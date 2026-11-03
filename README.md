# http-header-scanner

[![CI](https://github.com/RomarioBennett/http-header-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR-USERNAME/http-header-scanner/actions)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

A command-line tool that makes **one GET request** to a URL, inspects the
HTTP response headers, and grades the site's security posture from **A to F**,
with concrete, copy-pasteable fixes for everything it finds.

Built to be easy to read, easy to extend, and safe to drop into a CI pipeline.

## Why headers matter

Browsers enforce a lot of security policy, but only if the server asks them to.
A missing `Content-Security-Policy` leaves the door open for XSS, a missing
`X-Frame-Options`/`frame-ancestors` allows clickjacking, and a weak
`Strict-Transport-Security` allows SSL-stripping on hostile networks.
This tool checks that those protections are present **and actually configured well**.

## What it checks


When your browser loads a website, the server sends back HTTP headers along with the page. Some of them are instructions to the browser about security, for example “only load scripts from my own domain” or “never let another site put me in an iframe.” If the server doesn’t send them, the browser falls back to permissive defaults, and attacks like cross-site scripting (XSS), clickjacking, and protocol downgrade become easier.

This makes one GET request to a URL, reads the response headers, checks them against security best practices, and gives you a grade from A to F with specific fixes. Developers and security teams use tools like this to audit sites.

| Check | Severity | What it catches |
|---|---|---|
| HTTPS | high | Pages served over plain HTTP; HTTP that doesn't redirect to HTTPS |
| `Strict-Transport-Security` | high | Missing, `max-age=0` (actively disabled), under 180 days, or sent over HTTP (ignored) |
| `Content-Security-Policy` | high | Missing, report-only, `'unsafe-inline'` / `'unsafe-eval'`, wildcard sources, no `script-src`/`default-src` |
| `X-Content-Type-Options` | medium | MIME-sniffing |
| Clickjacking | medium | No `X-Frame-Options` or CSP `frame-ancestors` |
| Cookie flags | medium | `Set-Cookie` missing `Secure`, `HttpOnly`, or `SameSite` |
| `Referrer-Policy` | low | Missing or leaky (`unsafe-url`) policy |
| `Permissions-Policy` | low | Powerful browser features left unrestricted |
| `Cross-Origin-Opener-Policy` / `-Resource-Policy` | low | Missing cross-origin isolation |
| Technology disclosure | low | `X-Powered-By`, versioned `Server` headers |
| CORS | high | Wildcard `Access-Control-Allow-Origin` combined with credentials |

Some design decisions worth noting:

- **Values are validated, not just detected.** `max-age=0` and a CSP full of
  `'unsafe-inline'` are flagged as *weak*, not *passing*.
- **CSP is parsed**, not pattern-matched, and understands that a nonce or hash
  makes browsers ignore `'unsafe-inline'`.
- **Weighted scoring.** high = 30 pts, medium = 15, low = 5. Pass earns full
  points, warn earns half, fail earns none. Informational findings (e.g. no
  cookies set) don't affect the score.
- **Redirects are followed** and the *final* URL is graded, since that's what
  users actually see. The redirect chain is shown.
- **Cookie values are never printed**, only names.
- **Untrusted output is escaped.** Header values come from the remote server,
  so they're escaped before being rendered, which prevents terminal-markup injection.
- **Headers only.** The response body is never downloaded.

## Install

```bash
git clone https://github.com/RomarioBennett/http-header-scanner.git
cd http-header-scanner
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Usage

```bash
headerscan https://example.com
headerscan example.com github.com            # https:// assumed; scan several at once
headerscan https://example.com --json        # machine-readable output
headerscan https://example.com --min-grade B # stricter CI gate
headerscan https://localhost:8443 --insecure # self-signed certificate
python -m headerscan https://example.com     # without installing the script
```

| Option | Description |
|---|---|
| `--json` | Print results as JSON |
| `--min-grade {A..F}` | Exit `1` if any grade is worse than this (default `C`) |
| `--timeout SECONDS` | Request timeout (default `10`) |
| `--insecure` | Skip TLS certificate verification |
| `--user-agent STR` | Override the User-Agent |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Every URL met `--min-grade` |
| `1` | At least one URL graded below `--min-grade` |
| `2` | At least one URL could not be scanned |

### Example output

Scanning a deliberately misconfigured local server:

```text
                                       http://127.0.0.1:8765 (HTTP 200)
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Check                        ┃ Status ┃ Sev.   ┃ Details                                                   ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ HTTPS                        │ FAIL   │ high   │ Final response was served over plain HTTP.                │
│ Strict-Transport-Security    │ FAIL   │ high   │ `Strict-Transport-Security` header is not set.            │
│ Content-Security-Policy      │ WARN   │ high   │ Script-src allows 'unsafe-inline'.                        │
│ X-Content-Type-Options       │ PASS   │ medium │ MIME sniffing is disabled.                                │
│ Clickjacking protection      │ FAIL   │ medium │ Neither X-Frame-Options nor CSP `frame-ancestors` is set. │
│ Cookie flags                 │ WARN   │ medium │ sid: missing Secure, HttpOnly, SameSite.                  │
│ Technology disclosure        │ WARN   │ low    │ Response reveals software details useful for fingerprint… │
│ ...                          │        │        │                                                           │
╰──────────────────────────────┴────────┴────────┴───────────────────────────────────────────────────────────╯
╭────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ Grade F   Score 25/100   (80 ms)                                                                           │
╰────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
Recommendations
  • HTTPS: Serve the site over HTTPS and redirect all HTTP traffic to it.
  • Strict-Transport-Security: Add: Strict-Transport-Security: max-age=31536000; includeSubDomains
  ...
```

### Use in CI

```yaml
- run: pip install git+https://github.com/RomarioBennett/http-header-scanner
- run: headerscan https://staging.example.com --min-grade B
```

### Use as a library

```python
from headerscan import scan

result = scan("https://example.com")
print(result.grade, result.score)
for f in result.findings:
    print(f.status.value, f.title, f.detail)
```

## Architecture

```
src/headerscan/
├── models.py    # Finding, ScanResult, scoring + grade logic (pure data)
├── checks.py    # one pure function per check: Context -> Finding (no I/O)
├── scanner.py   # the only module that touches the network (httpx)
├── report.py    # Rich terminal rendering
└── cli.py       # argparse, JSON output, exit codes
```

The key idea is **separating I/O from logic**. Every check is a pure function
over a `Context`, so the whole rule set is unit-tested without any network.
The scanner accepts an injectable `httpx` transport, so the integration tests
use `httpx.MockTransport` rather than live sites.

### Adding a check

1. Write `def check_something(ctx: Context) -> Finding` in `checks.py`.
2. Append it to `ALL_CHECKS`.
3. Add tests in `tests/test_checks.py`.

## Development

```bash
pytest          # 42 tests, no network required
ruff check .
```

## Limitations & roadmap

- Checks one URL's response; it does not crawl the site.
- CSP analysis targets the most common weaknesses; it is not a full CSP evaluator.
- Does not inspect TLS versions or certificates.


## Responsible use

This tool sends a single ordinary GET request, but only scan sites you own or
have permission to test.

## Credits

Inspired by the weighted-rubric approach of
[Mozilla Observatory](https://developer.mozilla.org/en-US/observatory) and the
foundations-tier project in
[CarterPerez-dev/Cybersecurity-Projects](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/foundations/http-headers-scanner).
This is an independent implementation.

## License

MIT
