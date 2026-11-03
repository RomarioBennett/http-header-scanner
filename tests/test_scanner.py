import httpx
import pytest

from headerscan import ScanError, scan
from headerscan.models import Status

SECURE = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "Content-Security-Policy": "default-src 'self'; object-src 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}


def transport(handler):
    return httpx.MockTransport(handler)


def test_fully_hardened_site_gets_a():
    t = transport(lambda req: httpx.Response(200, headers=SECURE))
    result = scan("https://secure.test", transport=t)
    assert result.grade == "A" and result.score == 100


def test_bare_site_gets_f():
    t = transport(lambda req: httpx.Response(200))
    result = scan("https://bare.test", transport=t)
    assert result.grade == "F"
    assert all(f.recommendation for f in result.findings if f.status is Status.FAIL)


def test_plain_http_site_is_penalised():
    t = transport(lambda req: httpx.Response(200, headers=SECURE))
    result = scan("http://insecure.test", transport=t)
    by_id = {f.id: f for f in result.findings}
    assert by_id["https"].status is Status.FAIL
    assert by_id["hsts"].status is Status.WARN
    assert result.grade != "A"


def test_redirect_chain_is_followed_and_recorded():
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.scheme == "http":
            return httpx.Response(301, headers={"Location": "https://site.test/"})
        return httpx.Response(200, headers=SECURE)

    result = scan("http://site.test", transport=transport(handler))
    assert result.final_url == "https://site.test/"
    assert len(result.redirects) == 2
    assert result.redirects[0].startswith("http://site.test")
    assert result.redirects[-1] == "https://site.test/"
    assert {f.id: f for f in result.findings}["https"].status is Status.PASS


def test_multiple_set_cookie_headers_are_preserved():
    headers = list(SECURE.items()) + [
        ("Set-Cookie", "a=1; Secure; HttpOnly; SameSite=Lax"),
        ("Set-Cookie", "b=2"),
    ]
    t = transport(lambda req: httpx.Response(200, headers=headers))
    cookies = {f.id: f for f in scan("https://c.test", transport=t).findings}["cookies"]
    assert cookies.status is Status.WARN
    assert "b: missing" in cookies.detail


def test_bare_hostname_defaults_to_https():
    seen = []

    def handler(req):
        seen.append(req.url.scheme)
        return httpx.Response(200)

    scan("example.com", transport=transport(handler))
    assert seen == ["https"]


@pytest.mark.parametrize("bad", ["", "   ", "ftp://example.com", "file:///etc/passwd"])
def test_invalid_urls_rejected(bad):
    with pytest.raises(ScanError):
        scan(bad)


def test_network_errors_become_scan_errors():
    def handler(req):
        raise httpx.ConnectError("boom", request=req)

    with pytest.raises(ScanError, match="ConnectError"):
        scan("https://down.test", transport=transport(handler))


def test_redirect_loop_becomes_scan_error():
    def handler(req):
        return httpx.Response(302, headers={"Location": str(req.url)})

    with pytest.raises(ScanError):
        scan("https://loop.test", transport=transport(handler), max_redirects=3)


def test_result_is_json_serialisable():
    import json

    t = transport(lambda req: httpx.Response(200, headers=SECURE))
    json.dumps(scan("https://secure.test", transport=t).to_dict())
