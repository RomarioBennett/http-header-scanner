"""The individual security checks.

Every check is a pure function: ``Context -> Finding``. No network access
happens here, which makes each one trivial to unit test. To add a check,
write a function and append it to ``ALL_CHECKS`` at the bottom of the file.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlsplit

from .models import Finding, Severity, Status


@dataclass(frozen=True)
class Context:
    """What the checks get to look at."""

    headers: dict[str, str]  # lower-cased names, duplicate values joined by ", "
    set_cookies: tuple[str, ...]  # raw Set-Cookie lines (kept separate on purpose)
    initial_url: str
    final_url: str

    @property
    def is_https(self) -> bool:
        return urlsplit(self.final_url).scheme == "https"

    def get(self, name: str) -> str | None:
        return self.headers.get(name.lower())


@dataclass(frozen=True)
class CheckInfo:
    id: str
    title: str
    severity: Severity
    fix: str


def _finding(
    info: CheckInfo, status: Status, detail: str, value: str | None = None
) -> Finding:
    if value is not None and len(value) > 160:
        value = value[:157] + "..."
    return Finding(
        id=info.id,
        title=info.title,
        severity=info.severity,
        status=status,
        detail=detail,
        value=value,
        # Only suggest a fix when something is actually wrong.
        recommendation=info.fix if status in (Status.WARN, Status.FAIL) else None,
    )


def _missing(info: CheckInfo, header: str) -> Finding:
    return _finding(info, Status.FAIL, f"`{header}` header is not set.")


# --------------------------------------------------------------------------- #
# Transport
# --------------------------------------------------------------------------- #

HTTPS = CheckInfo(
    "https",
    "HTTPS",
    Severity.HIGH,
    "Serve the site over HTTPS and redirect all HTTP traffic to it.",
)


def check_https(ctx: Context) -> Finding:
    if ctx.is_https:
        if urlsplit(ctx.initial_url).scheme == "http":
            return _finding(HTTPS, Status.PASS, "HTTP request was redirected to HTTPS.")
        return _finding(HTTPS, Status.PASS, "Page is served over HTTPS.")
    return _finding(HTTPS, Status.FAIL, "Final response was served over plain HTTP.")


HSTS = CheckInfo(
    "hsts",
    "Strict-Transport-Security",
    Severity.HIGH,
    "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
)
HSTS_MIN_AGE = 15_552_000  # 180 days, the threshold Mozilla Observatory uses


def check_hsts(ctx: Context) -> Finding:
    value = ctx.get("strict-transport-security")
    if value is None:
        return _missing(HSTS, "Strict-Transport-Security")
    if not ctx.is_https:
        return _finding(
            HSTS,
            Status.WARN,
            "Sent over plain HTTP, where browsers ignore it (RFC 6797 §8.1).",
            value,
        )
    match = re.search(r"max-age\s*=\s*\"?(\d+)", value, re.IGNORECASE)
    if not match:
        return _finding(HSTS, Status.WARN, "No valid `max-age` directive.", value)
    max_age = int(match.group(1))
    if max_age == 0:
        return _finding(
            HSTS, Status.WARN, "`max-age=0` actively disables HSTS.", value
        )
    if max_age < HSTS_MIN_AGE:
        days = max_age // 86_400
        return _finding(
            HSTS,
            Status.WARN,
            f"`max-age` is only {days} days; at least 180 is recommended.",
            value,
        )
    note = "" if "includesubdomains" in value.lower() else " Consider includeSubDomains."
    return _finding(HSTS, Status.PASS, f"Long-lived HSTS policy.{note}", value)


# --------------------------------------------------------------------------- #
# Content Security Policy
# --------------------------------------------------------------------------- #

CSP = CheckInfo(
    "csp",
    "Content-Security-Policy",
    Severity.HIGH,
    "Add a CSP that avoids 'unsafe-inline'/'unsafe-eval' and wildcard sources, "
    "e.g. default-src 'self'; object-src 'none'; base-uri 'self'",
)


def parse_csp(value: str) -> dict[str, list[str]]:
    """Parse a CSP into {directive: [tokens]}. First occurrence wins (per spec)."""
    directives: dict[str, list[str]] = {}
    for part in value.split(";"):
        tokens = part.split()
        if tokens:
            directives.setdefault(tokens[0].lower(), tokens[1:])
    return directives


def _csp_issues(directives: dict[str, list[str]]) -> list[str]:
    issues: list[str] = []

    if "script-src" in directives:
        tokens = [t.lower() for t in directives["script-src"]]
        source = "script-src"
    elif "default-src" in directives:
        tokens = [t.lower() for t in directives["default-src"]]
        source = "default-src"
    else:
        return ["no script-src or default-src, so scripts are unrestricted"]

    has_nonce_or_hash = any(
        t.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for t in tokens
    )
    strict_dynamic = "'strict-dynamic'" in tokens

    # Modern browsers ignore 'unsafe-inline' when a nonce/hash is present.
    if "'unsafe-inline'" in tokens and not (has_nonce_or_hash or strict_dynamic):
        issues.append(f"{source} allows 'unsafe-inline'")
    if "'unsafe-eval'" in tokens:
        issues.append(f"{source} allows 'unsafe-eval'")
    if not strict_dynamic and any(t in ("*", "http:", "https:", "data:") for t in tokens):
        issues.append(f"{source} allows any origin or scheme (*, https:, data:)")
    if "object-src" not in directives and "default-src" not in directives:
        issues.append("no object-src or default-src (plugins unrestricted)")
    return issues


def check_csp(ctx: Context) -> Finding:
    value = ctx.get("content-security-policy")
    if value is None:
        if ctx.get("content-security-policy-report-only") is not None:
            return _finding(
                CSP,
                Status.WARN,
                "Only Content-Security-Policy-Report-Only is set; it reports but "
                "does not enforce.",
            )
        return _missing(CSP, "Content-Security-Policy")
    issues = _csp_issues(parse_csp(value))
    if issues:
        return _finding(CSP, Status.WARN, "; ".join(issues).capitalize() + ".", value)
    return _finding(CSP, Status.PASS, "Enforced policy with no obvious weaknesses.", value)


# --------------------------------------------------------------------------- #
# Simple header checks
# --------------------------------------------------------------------------- #

XCTO = CheckInfo(
    "x-content-type-options",
    "X-Content-Type-Options",
    Severity.MEDIUM,
    "Add: X-Content-Type-Options: nosniff",
)


def check_xcto(ctx: Context) -> Finding:
    value = ctx.get("x-content-type-options")
    if value is None:
        return _missing(XCTO, "X-Content-Type-Options")
    if value.strip().lower() == "nosniff":
        return _finding(XCTO, Status.PASS, "MIME sniffing is disabled.", value)
    return _finding(XCTO, Status.WARN, "Value should be exactly `nosniff`.", value)


CLICKJACK = CheckInfo(
    "clickjacking",
    "Clickjacking protection",
    Severity.MEDIUM,
    "Add: Content-Security-Policy: frame-ancestors 'none' "
    "(or X-Frame-Options: DENY)",
)


def check_clickjacking(ctx: Context) -> Finding:
    csp = ctx.get("content-security-policy")
    if csp and "frame-ancestors" in parse_csp(csp):
        return _finding(
            CLICKJACK, Status.PASS, "Protected by CSP `frame-ancestors`.", csp
        )
    xfo = ctx.get("x-frame-options")
    if xfo is None:
        return _finding(
            CLICKJACK,
            Status.FAIL,
            "Neither X-Frame-Options nor CSP `frame-ancestors` is set.",
        )
    if xfo.strip().upper() in ("DENY", "SAMEORIGIN"):
        return _finding(CLICKJACK, Status.PASS, "Protected by X-Frame-Options.", xfo)
    return _finding(
        CLICKJACK,
        Status.WARN,
        "Unrecognised or deprecated value (ALLOW-FROM is not supported).",
        xfo,
    )


REFERRER = CheckInfo(
    "referrer-policy",
    "Referrer-Policy",
    Severity.LOW,
    "Add: Referrer-Policy: strict-origin-when-cross-origin",
)
_REFERRER_GOOD = {
    "no-referrer",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
    "origin",
    "origin-when-cross-origin",
}
_REFERRER_LEAKY = {"unsafe-url", "no-referrer-when-downgrade"}


def check_referrer(ctx: Context) -> Finding:
    value = ctx.get("referrer-policy")
    if value is None:
        return _missing(REFERRER, "Referrer-Policy")
    tokens = [t.strip().lower() for t in value.split(",") if t.strip()]
    effective = tokens[-1] if tokens else ""  # browsers use the last valid token
    if effective in _REFERRER_GOOD:
        return _finding(REFERRER, Status.PASS, f"Policy is `{effective}`.", value)
    if effective in _REFERRER_LEAKY:
        return _finding(
            REFERRER, Status.WARN, f"`{effective}` can leak full URLs.", value
        )
    return _finding(REFERRER, Status.WARN, "Unrecognised policy value.", value)


PERMISSIONS = CheckInfo(
    "permissions-policy",
    "Permissions-Policy",
    Severity.LOW,
    "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()",
)


def check_permissions(ctx: Context) -> Finding:
    value = ctx.get("permissions-policy")
    if value is None:
        if ctx.get("feature-policy") is not None:
            return _finding(
                PERMISSIONS,
                Status.WARN,
                "Only the deprecated Feature-Policy header is set.",
                ctx.get("feature-policy"),
            )
        return _missing(PERMISSIONS, "Permissions-Policy")
    return _finding(PERMISSIONS, Status.PASS, "Browser features are restricted.", value)


COOP = CheckInfo(
    "coop",
    "Cross-Origin-Opener-Policy",
    Severity.LOW,
    "Add: Cross-Origin-Opener-Policy: same-origin",
)


def check_coop(ctx: Context) -> Finding:
    value = ctx.get("cross-origin-opener-policy")
    if value is None:
        return _missing(COOP, "Cross-Origin-Opener-Policy")
    if value.strip().lower() in (
        "same-origin",
        "same-origin-allow-popups",
        "noopener-allow-popups",
    ):
        return _finding(COOP, Status.PASS, "Browsing context is isolated.", value)
    return _finding(COOP, Status.WARN, "`unsafe-none` provides no isolation.", value)


CORP = CheckInfo(
    "corp",
    "Cross-Origin-Resource-Policy",
    Severity.LOW,
    "Add: Cross-Origin-Resource-Policy: same-origin (or same-site)",
)


def check_corp(ctx: Context) -> Finding:
    value = ctx.get("cross-origin-resource-policy")
    if value is None:
        return _missing(CORP, "Cross-Origin-Resource-Policy")
    if value.strip().lower() in ("same-origin", "same-site", "cross-origin"):
        return _finding(CORP, Status.PASS, "Resource sharing policy is set.", value)
    return _finding(CORP, Status.WARN, "Unrecognised value.", value)


# --------------------------------------------------------------------------- #
# Cookies, CORS, information disclosure
# --------------------------------------------------------------------------- #

COOKIES = CheckInfo(
    "cookies",
    "Cookie flags",
    Severity.MEDIUM,
    "Set cookies with Secure; HttpOnly; SameSite=Lax (or Strict). "
    "HttpOnly may be skipped only for cookies JavaScript must read.",
)


def check_cookies(ctx: Context) -> Finding:
    if not ctx.set_cookies:
        return _finding(COOKIES, Status.INFO, "No cookies were set on this response.")

    problems: list[str] = []
    for raw in ctx.set_cookies:
        parts = [p.strip() for p in raw.split(";")]
        name = parts[0].split("=", 1)[0].strip() or "(unnamed)"
        attrs = {p.split("=", 1)[0].strip().lower() for p in parts[1:]}
        missing = [
            label
            for label, key in (
                ("Secure", "secure"),
                ("HttpOnly", "httponly"),
                ("SameSite", "samesite"),
            )
            if key not in attrs
        ]
        if missing:
            problems.append(f"{name}: missing {', '.join(missing)}")

    names = ", ".join(
        (c.split(";", 1)[0].split("=", 1)[0].strip() or "(unnamed)")
        for c in ctx.set_cookies
    )
    # Cookie *values* are never reported, only names.
    if problems:
        return _finding(COOKIES, Status.WARN, "; ".join(problems) + ".", names)
    return _finding(COOKIES, Status.PASS, "All cookies set Secure, HttpOnly, SameSite.", names)


CORS = CheckInfo(
    "cors",
    "CORS configuration",
    Severity.HIGH,
    "Never combine a wildcard Access-Control-Allow-Origin with credentials; "
    "reflect only an allow-list of trusted origins.",
)


def check_cors(ctx: Context) -> Finding:
    origin = ctx.get("access-control-allow-origin")
    if origin is None:
        return _finding(CORS, Status.INFO, "No CORS headers on this response.")
    creds = (ctx.get("access-control-allow-credentials") or "").strip().lower()
    if origin.strip() == "*" and creds == "true":
        return _finding(
            CORS,
            Status.FAIL,
            "Wildcard origin combined with Allow-Credentials: true.",
            f"ACAO: {origin}; ACAC: {creds}",
        )
    if origin.strip() == "*":
        return _finding(
            CORS,
            Status.INFO,
            "Wildcard origin is fine for public, unauthenticated resources.",
            origin,
        )
    return _finding(CORS, Status.INFO, "Specific origin allowed.", origin)


DISCLOSURE = CheckInfo(
    "info-disclosure",
    "Technology disclosure",
    Severity.LOW,
    "Remove X-Powered-By and strip version numbers from the Server header.",
)
_VERSIONED = re.compile(r"/?\d+(\.\d+)+")


def check_disclosure(ctx: Context) -> Finding:
    leaks: list[str] = []
    server = ctx.get("server")
    if server and _VERSIONED.search(server):
        leaks.append(f"Server: {server}")
    for name in ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
        value = ctx.get(name)
        if value:
            leaks.append(f"{name.title()}: {value}")
    if leaks:
        return _finding(
            DISCLOSURE,
            Status.WARN,
            "Response reveals software details useful for fingerprinting.",
            "; ".join(leaks),
        )
    return _finding(DISCLOSURE, Status.PASS, "No version information disclosed.")


ALL_CHECKS: list[Callable[[Context], Finding]] = [
    check_https,
    check_hsts,
    check_csp,
    check_xcto,
    check_clickjacking,
    check_referrer,
    check_permissions,
    check_coop,
    check_corp,
    check_cookies,
    check_cors,
    check_disclosure,
]


def run_checks(ctx: Context) -> list[Finding]:
    return [check(ctx) for check in ALL_CHECKS]
