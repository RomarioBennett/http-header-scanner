"""Fetch a URL once and run every check against the response."""

from __future__ import annotations

from time import perf_counter
from urllib.parse import urlsplit

import httpx

from .checks import Context, run_checks
from .models import ScanResult

DEFAULT_USER_AGENT = "headerscan/1.0 (+security header scanner)"


class ScanError(Exception):
    """Raised for invalid input or a failed request."""


def normalize_url(raw: str) -> str:
    """Add https:// to bare hostnames and reject anything that isn't http(s)."""
    raw = raw.strip()
    if not raw:
        raise ScanError("Empty URL.")
    if "://" not in raw:
        raw = "https://" + raw
    parts = urlsplit(raw)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ScanError(f"Not a valid http(s) URL: {raw!r}")
    return raw


def scan(
    url: str,
    *,
    timeout: float = 10.0,
    verify: bool = True,
    max_redirects: int = 10,
    user_agent: str = DEFAULT_USER_AGENT,
    transport: httpx.BaseTransport | None = None,
) -> ScanResult:
    """Scan ``url`` and return a graded :class:`ScanResult`.

    ``transport`` lets tests inject ``httpx.MockTransport`` so no real
    network access is needed.
    """
    target = normalize_url(url)
    started = perf_counter()

    try:
        with httpx.Client(  # noqa: SIM117 - the stream depends on the client
            timeout=timeout,
            verify=verify,
            follow_redirects=True,
            max_redirects=max_redirects,
            headers={"User-Agent": user_agent},
            transport=transport,
        ) as client:
            # stream() reads headers only; we never download the body.
            with client.stream("GET", target) as response:
                headers: dict[str, str] = {}
                for name, value in response.headers.multi_items():
                    key = name.lower()
                    headers[key] = f"{headers[key]}, {value}" if key in headers else value
                cookies = tuple(response.headers.get_list("set-cookie"))
                final_url = str(response.url)
                redirects = [str(r.url) for r in response.history] + [final_url]
                status_code = response.status_code
    except httpx.HTTPError as exc:
        raise ScanError(f"{type(exc).__name__}: {exc}") from exc

    findings = run_checks(
        Context(
            headers=headers,
            set_cookies=cookies,
            initial_url=target,
            final_url=final_url,
        )
    )
    return ScanResult(
        url=target,
        final_url=final_url,
        status_code=status_code,
        redirects=redirects if len(redirects) > 1 else [],
        findings=findings,
        elapsed_ms=int((perf_counter() - started) * 1000),
    )
