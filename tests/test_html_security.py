from scanner.checks.html_security import check_html_security
from scanner.checks.js_libs import check_js_libs, detect_libs
from scanner.finding import Severity

from .conftest import make_response

H = {"content-type": "text/html"}


def page(html, url="https://ex.com/"):
    return make_response(H, url=url, body=html)


def rules(findings):
    return {f.rule: f for f in findings}


def test_active_and_passive_mixed_content():
    r = rules(check_html_security(page(
        '<script src="http://cdn.x/a.js"></script><img src="http://ex.com/i.png">')))
    assert r["html.mixed-content-active"].severity is Severity.MEDIUM
    assert r["html.mixed-content-passive"].severity is Severity.LOW


def test_http_page_is_not_mixed_content():
    assert "html.mixed-content-active" not in rules(check_html_security(
        page('<script src="http://ex.com/a.js"></script>', url="http://ex.com/")))


def test_sri_missing_only_for_third_party():
    html = ('<script src="https://cdn.x/a.js"></script>'
            '<script src="https://cdn.x/ok.js" integrity="sha384-abc"></script>'
            '<script src="/local.js"></script>'
            '<link rel="stylesheet" href="https://fonts.x/s.css">')
    f = rules(check_html_security(page(html)))["html.no-sri"]
    assert "2 third-party" in f.title and "ok.js" not in f.evidence and "local.js" not in f.evidence


def test_password_form_over_http_is_high():
    html = '<form action="http://ex.com/login"><input type="password" name="p"></form>'
    assert rules(check_html_security(page(html)))["html.insecure-form"].severity is Severity.HIGH


def test_password_form_https_and_search_form_are_clean():
    html = ('<form action="/login"><input type="password"></form>'
            '<form action="http://ex.com/search"><input type="text"></form>')
    assert check_html_security(page(html)) == []


def test_non_html_and_broken_markup_are_safe():
    assert check_html_security(make_response({"content-type": "application/json"}, body="{}")) == []
    assert isinstance(check_html_security(page("<<<script src=>>><form")), list)


def test_detect_libs_from_url_shapes():
    assert ("jQuery", "3.3.1") in detect_libs("https://x/jquery-3.3.1.min.js")
    assert ("jQuery", "1.12.4") in detect_libs("https://cdnjs.cloudflare.com/ajax/libs/jquery/1.12.4/jquery.min.js")
    assert ("Lodash", "4.17.4") in detect_libs("https://x/lodash.js/4.17.4/lodash.min.js")
    assert ("Bootstrap", "3.3.7") in detect_libs("https://x/bootstrap@3.3.7/dist/js/bootstrap.min.js")
    assert detect_libs("https://x/app.js") == [] and detect_libs("https://x/jquery.min.js") == []


def test_vulnerable_and_fixed_versions():
    html = ('<script src="/js/jquery-3.3.1.min.js"></script>'
            '<script src="/js/bootstrap-4.6.0.min.js"></script>'      # fixed (>= 4.3.1)
            '<script src="/js/jquery-3.7.1.min.js"></script>'         # fixed
            '<script src="/js/handlebars-4.0.0.min.js"></script>')
    r = rules(check_js_libs(page(html)))
    assert r["js.jquery"].metadata["version"] == "3.3.1" and r["js.jquery"].metadata["fixed_in"] == "3.5.0"
    assert r["js.handlebars"].severity is Severity.HIGH
    assert "js.bootstrap" not in r and len(check_js_libs(page(html))) == 2


def test_bootstrap_3_and_4_branches():
    assert check_js_libs(page('<script src="/bootstrap-3.3.7.js"></script>'))[0].metadata["fixed_in"] == "3.4.1"
    assert check_js_libs(page('<script src="/bootstrap-4.1.0.js"></script>'))[0].metadata["fixed_in"] == "4.3.1"
    assert check_js_libs(page('<script src="/bootstrap-5.3.0.js"></script>')) == []


def test_jquery_ui_and_other_lookalikes_are_not_mistaken_for_the_core_library():
    for url in ("https://cdnjs.cloudflare.com/ajax/libs/jqueryui/1.12.1/jquery-ui.min.js",
                "https://x/jquery-ui-1.12.1.min.js", "https://x/jquery.mobile-1.4.5.min.js",
                "https://x/ajax/libs/angular-material/1.1.0/a.js", "https://x/bootstrap-icons-1.5.0.js"):
        assert detect_libs(url) == [], url
    assert ("jQuery", "3.3.1") in detect_libs("https://cdnjs.cloudflare.com/ajax/libs/jquery/3.3.1/jquery.min.js")
