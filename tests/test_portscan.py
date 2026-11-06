import asyncio

import pytest

from scanner.checks.portscan import PORT_TABLE, _probe_port, check_portscan, scan_ports
from scanner.finding import Severity
from scanner.http import HttpClient, ScanConfig, ScanContext
from scanner.scope import parse_scope


async def _tcp_echo_server(banner: bytes = b""):
    """Real loopback TCP server: accepts connections and optionally sends a banner."""
    async def handle(reader, writer):
        if banner:
            writer.write(banner)
            await writer.drain()
        await asyncio.sleep(0.05)
        writer.close()
    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


def run_check(ctx_config):
    async def main():
        async with HttpClient(ctx_config) as client:
            ctx = ScanContext("https://127.0.0.1", client, ctx_config)
            return await check_portscan(ctx)
    return asyncio.run(main())


def test_probe_open_port_with_banner():
    async def main():
        server, port = await _tcp_echo_server(b"SSH-2.0-OpenSSH_9.0\r\n")
        try:
            return await _probe_port("127.0.0.1", port, timeout=1)
        finally:
            server.close()
    banner = asyncio.run(main())
    assert banner == "SSH-2.0-OpenSSH_9.0"


def test_probe_closed_port_returns_none():
    async def main():
        # a port unlikely to be listening
        return await _probe_port("127.0.0.1", 1, timeout=0.3)
    assert asyncio.run(main()) is None


def test_probe_strips_non_printable_bytes():
    async def main():
        server, port = await _tcp_echo_server(b"\x00\x01OK\xff")
        try:
            return await _probe_port("127.0.0.1", port, timeout=1)
        finally:
            server.close()
    banner = asyncio.run(main())
    assert banner == "??OK?"


def test_scan_ports_finds_only_the_open_one():
    async def main():
        server, port = await _tcp_echo_server()
        try:
            closed = port + 1 if port < 65535 else port - 1
            return await scan_ports("127.0.0.1", [port, closed], rate=0, concurrency=5, timeout=0.5)
        finally:
            server.close()
    result = asyncio.run(main())
    assert list(result) == [list(result)[0]]  # only the open port


def test_check_portscan_end_to_end_classifies_by_table():
    async def main():
        server, port = await _tcp_echo_server()
        try:
            cfg = ScanConfig(rate=0, retries=0, ports=[port])
            async with HttpClient(cfg) as client:
                ctx = ScanContext(f"http://127.0.0.1:{port}", client, cfg)
                return await check_portscan(ctx)
        finally:
            server.close()
    findings = asyncio.run(main())
    by_rule = {f.rule: f for f in findings}
    assert any(r.startswith("portscan.port-") for r in by_rule)
    summary = by_rule["portscan.summary"]
    assert summary.severity is Severity.INFO and "1 of 1" in summary.title


def test_check_portscan_no_open_ports():
    cfg = ScanConfig(rate=0, retries=0, ports=[1])  # unlikely port
    findings = run_check(cfg)
    assert findings == [f for f in findings if f.rule == "portscan.none"]


def test_check_portscan_respects_custom_port_list():
    cfg = ScanConfig(rate=0, retries=0, ports=[1, 2, 3])
    findings = run_check(cfg)
    assert "3 ports tested" in findings[0].detail


@pytest.mark.parametrize("port,expected_severity", [(23, Severity.HIGH), (6379, Severity.HIGH),
                                                     (22, Severity.INFO), (3389, Severity.MEDIUM)])
def test_port_table_severities(port, expected_severity):
    _, severity, _ = PORT_TABLE[port]
    assert severity is expected_severity


def test_scope_blocks_portscan_even_though_it_uses_raw_sockets():
    async def main():
        server, port = await _tcp_echo_server()
        try:
            cfg = ScanConfig(rate=0, retries=0, ports=[port], scope=parse_scope("outro-host.test"))
            async with HttpClient(cfg) as client:
                ctx = ScanContext(f"http://127.0.0.1:{port}", client, cfg)
                return await check_portscan(ctx)
        finally:
            server.close()
    findings = asyncio.run(main())
    assert findings[0].rule == "portscan.out_of_scope"


def test_scope_allows_in_scope_host():
    async def main():
        server, port = await _tcp_echo_server()
        try:
            cfg = ScanConfig(rate=0, retries=0, ports=[port], scope=parse_scope("127.0.0.1"))
            async with HttpClient(cfg) as client:
                ctx = ScanContext(f"http://127.0.0.1:{port}", client, cfg)
                return await check_portscan(ctx)
        finally:
            server.close()
    findings = asyncio.run(main())
    assert any(f.rule.startswith("portscan.port-") for f in findings)



def test_portscan_is_registered_as_active_and_excluded_by_default():
    from scanner.core import REGISTRY, default_web_checks
    assert REGISTRY.get("portscan").active is True
    assert "portscan" not in default_web_checks(ScanConfig())
    assert "portscan" in default_web_checks(ScanConfig(allow_active=True))
