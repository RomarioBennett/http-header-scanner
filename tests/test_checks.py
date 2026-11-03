from headerscan.checks import (
    Context,
    check_clickjacking,
    check_cookies,
    check_cors,
    check_csp,
    check_disclosure,
    check_hsts,
    check_https,
    check_referrer,
    check_xcto,
    parse_csp,
)
from headerscan.models import Status

URL = "https://example.com/"


def ctx(headers=None, cookies=(), initial=URL, final=URL):
    return Context(
        headers={k.lower(): v for k, v in (headers or {}).items()},
        set_cookies=tuple(cookies),
        initial_url=initial,
        final_url=final,
    )


# ---- HTTPS / HSTS -------------------------------------------------------- #
def test_https_pass_and_fail():
    assert check_https(ctx()).status is Status.PASS
    http = "http://example.com/"
    assert check_https(ctx(initial=http, final=http)).status is Status.FAIL


def test_http_redirected_to_https_passes():
    f = check_https(ctx(initial="http://example.com/", final=URL))
    assert f.status is Status.PASS
    assert "redirected" in f.detail


def test_hsts_missing():
    assert check_hsts(ctx()).status is Status.FAIL


def test_hsts_good():
    h = {"Strict-Transport-Security": "max-age=31536000; includeSubDomains"}
    assert check_hsts(ctx(h)).status is Status.PASS


def test_hsts_max_age_zero_is_weak():
    f = check_hsts(ctx({"Strict-Transport-Security": "max-age=0"}))
    assert f.status is Status.WARN
    assert "disables" in f.detail


def test_hsts_short_max_age_is_weak():
    assert check_hsts(ctx({"Strict-Transport-Security": "max-age=300"})).status is Status.WARN


def test_hsts_over_http_is_ignored():
    http = "http://example.com/"
    f = check_hsts(
        ctx({"Strict-Transport-Security": "max-age=31536000"}, initial=http, final=http)
    )
    assert f.status is Status.WARN


# ---- CSP ----------------------------------------------------------------- #
def test_parse_csp_first_directive_wins():
    d = parse_csp("default-src 'self'; script-src a.com; script-src b.com")
    assert d["script-src"] == ["a.com"]


def test_csp_missing_and_report_only():
    assert check_csp(ctx()).status is Status.FAIL
    ro = ctx({"Content-Security-Policy-Report-Only": "default-src 'self'"})
    assert check_csp(ro).status is Status.WARN


def test_csp_strong():
    h = {"Content-Security-Policy": "default-src 'self'; object-src 'none'"}
    assert check_csp(ctx(h)).status is Status.PASS


def test_csp_unsafe_inline_flagged():
    h = {"Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'"}
    f = check_csp(ctx(h))
    assert f.status is Status.WARN and "unsafe-inline" in f.detail


def test_csp_unsafe_inline_ok_with_nonce():
    h = {"Content-Security-Policy": "default-src 'self'; script-src 'nonce-abc' 'unsafe-inline'"}
    assert check_csp(ctx(h)).status is Status.PASS


def test_csp_wildcard_and_eval_flagged():
    h = {"Content-Security-Policy": "default-src *; script-src * 'unsafe-eval'"}
    f = check_csp(ctx(h))
    assert f.status is Status.WARN
    assert "unsafe-eval" in f.detail and "any origin" in f.detail


def test_csp_without_script_or_default_src():
    f = check_csp(ctx({"Content-Security-Policy": "img-src 'self'"}))
    assert f.status is Status.WARN


# ---- Small header checks ------------------------------------------------- #
def test_xcto():
    assert check_xcto(ctx({"X-Content-Type-Options": "nosniff"})).status is Status.PASS
    assert check_xcto(ctx({"X-Content-Type-Options": "yes"})).status is Status.WARN
    assert check_xcto(ctx()).status is Status.FAIL


def test_clickjacking_via_xfo_or_csp():
    assert check_clickjacking(ctx({"X-Frame-Options": "DENY"})).status is Status.PASS
    csp = {"Content-Security-Policy": "frame-ancestors 'none'"}
    assert check_clickjacking(ctx(csp)).status is Status.PASS
    assert check_clickjacking(ctx({"X-Frame-Options": "ALLOW-FROM x"})).status is Status.WARN
    assert check_clickjacking(ctx()).status is Status.FAIL


def test_header_names_are_case_insensitive():
    assert check_xcto(ctx({"x-CONTENT-type-OPTIONS": "NoSniff"})).status is Status.PASS


def test_referrer_uses_last_token():
    assert check_referrer(ctx({"Referrer-Policy": "unsafe-url, no-referrer"})).status is Status.PASS
    assert check_referrer(ctx({"Referrer-Policy": "unsafe-url"})).status is Status.WARN


# ---- Cookies / CORS / disclosure ---------------------------------------- #
def test_cookies_none_is_info():
    assert check_cookies(ctx()).status is Status.INFO


def test_cookies_flags():
    good = ctx(cookies=["sid=abc; Secure; HttpOnly; SameSite=Lax"])
    assert check_cookies(good).status is Status.PASS
    bad = ctx(cookies=["sid=abc; Path=/"])
    f = check_cookies(bad)
    assert f.status is Status.WARN
    assert "Secure" in f.detail and "HttpOnly" in f.detail


def test_cookie_values_are_never_reported():
    f = check_cookies(ctx(cookies=["sid=SUPERSECRET; Path=/"]))
    assert "SUPERSECRET" not in f.detail
    assert "SUPERSECRET" not in (f.value or "")


def test_cors_wildcard_with_credentials_fails():
    h = {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"}
    assert check_cors(ctx(h)).status is Status.FAIL
    assert check_cors(ctx({"Access-Control-Allow-Origin": "*"})).status is Status.INFO


def test_disclosure():
    assert check_disclosure(ctx({"Server": "nginx"})).status is Status.PASS
    assert check_disclosure(ctx({"Server": "Apache/2.4.41"})).status is Status.WARN
    assert check_disclosure(ctx({"X-Powered-By": "PHP"})).status is Status.WARN
