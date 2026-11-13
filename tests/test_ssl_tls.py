import ssl
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

from scanner.checks import ssl_tls
from scanner.checks.ssl_tls import check_ssl_tls
from scanner.finding import Severity


def _not_after(days: int) -> str:
    d = datetime.now(timezone.utc) + timedelta(days=days, hours=1)
    return d.strftime("%b %d %H:%M:%S %Y GMT")


@contextmanager
def fake_tls(version="TLSv1.3", cert=None, supported=("TLSv1.2", "TLSv1.3"), wrap_error=None):
    """Patches the socket/TLS layers so check_ssl_tls never touches the network."""
    tls = MagicMock()
    tls.version.return_value = version
    tls.getpeercert.return_value = {"notAfter": _not_after(90)} if cert is None else cert
    wrapped = MagicMock()
    wrapped.__enter__.return_value = tls
    ctx = MagicMock()
    if wrap_error:
        ctx.wrap_socket.side_effect = wrap_error
    else:
        ctx.wrap_socket.return_value = wrapped
    sock = MagicMock()
    with patch.object(ssl_tls.socket, "create_connection", return_value=sock), \
         patch.object(ssl_tls.ssl, "create_default_context", return_value=ctx), \
         patch.object(ssl_tls, "supported_protocols", return_value=list(supported)):
        yield


def by_sev(findings):
    return {f.severity for f in findings}


def test_http_target_is_skipped():
    f = check_ssl_tls("http://ex.com")
    assert len(f) == 1 and f[0].severity is Severity.INFO


def test_healthy_site_has_only_info():
    with fake_tls():
        findings = check_ssl_tls("https://ex.com")
    assert by_sev(findings) == {Severity.INFO}
    assert any("Valid certificate" in f.title for f in findings)


def test_invalid_certificate_is_high():
    with fake_tls(wrap_error=ssl.SSLCertVerificationError("hostname mismatch")):
        f = check_ssl_tls("https://ex.com")
    assert f[0].severity is Severity.HIGH and "Invalid TLS certificate" in f[0].title


def test_connection_failure_is_info_not_a_crash():
    with patch.object(ssl_tls.socket, "create_connection", side_effect=OSError("refused")):
        f = check_ssl_tls("https://ex.com")
    assert f[0].severity is Severity.INFO and "refused" in f[0].detail


def test_weak_negotiated_protocol_is_high():
    with fake_tls(version="TLSv1"):
        findings = check_ssl_tls("https://ex.com")
    assert any(f.severity is Severity.HIGH and "TLSv1" in f.title for f in findings)


def test_server_accepting_obsolete_protocols_is_medium():
    with fake_tls(supported=("TLSv1", "TLSv1.1", "TLSv1.2")):
        findings = check_ssl_tls("https://ex.com")
    weak = next(f for f in findings if f.severity is Severity.MEDIUM)
    assert "TLSv1" in weak.title and "TLSv1.1" in weak.title


def test_expired_and_expiring_certificates():
    with fake_tls(cert={"notAfter": _not_after(-3)}):
        assert any(f.severity is Severity.HIGH and "Expired" in f.title for f in check_ssl_tls("https://ex.com"))
    with fake_tls(cert={"notAfter": _not_after(5)}):
        assert any(f.severity is Severity.MEDIUM and "expiring" in f.title for f in check_ssl_tls("https://ex.com"))


def test_custom_port_is_used():
    with fake_tls():
        with patch.object(ssl_tls, "supported_protocols", return_value=["TLSv1.3"]) as sp:
            check_ssl_tls("https://ex.com:8443")
    assert sp.call_args.args[:2] == ("ex.com", 8443)


def test_supported_protocols_only_counts_the_probed_version():
    tls = MagicMock()
    tls.version.side_effect = ["TLSv1", "TLSv1.2", "TLSv1.2", "TLSv1.3"]  # downgrade on probe #2 must not count
    wrapped = MagicMock()
    wrapped.__enter__.return_value = tls
    ctx = MagicMock()
    ctx.wrap_socket.return_value = wrapped
    with patch.object(ssl_tls.ssl, "SSLContext", return_value=ctx), \
         patch.object(ssl_tls.socket, "create_connection", return_value=MagicMock()):
        assert ssl_tls.supported_protocols("ex.com", 443) == ["TLSv1", "TLSv1.2", "TLSv1.3"]
