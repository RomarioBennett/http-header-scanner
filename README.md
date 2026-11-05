# http-header-scanner

[![CI](https://github.com/RomarioBennett/http-header-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/RomarioBennett/http-header-scanner/actions)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

**This tool, when given a URL tells you how well that site protects its visitors, as a grade from A to F, and shows you exactly how to fix any problems.**

```bash
headerscan https://example.com
```

## What is this for?

Every time you open a website, the server sends back the page plus some hidden
instructions called **HTTP headers**. Some of these headers are security rules
for your browser, like "don't let other sites embed this page" or "only talk to
me over HTTPS."

If a site forgets to send those rules, browsers fall back to relaxed defaults,
and attackers can take advantage of that.

This tool checks whether a site sends the right rules **and** whether they are
set up properly (a rule that's turned off or too loose doesn't count).

### Quick example of what can go wrong

| Missing or weak header | What an attacker could do |
|---|---|
| `Content-Security-Policy` | Inject malicious scripts into the page (XSS) |
| `X-Frame-Options` | Trick users into clicking a hidden page inside a frame (clickjacking) |
| `Strict-Transport-Security` | Force a visitor onto an unencrypted connection on public Wi-Fi |

## Install

You need Python 3.10 or newer.

```bash
git clone https://github.com/RomarioBennett/http-header-scanner.git
cd http-header-scanner
python -m venv .venv
source .venv/bin/activate        # on Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

After this, `headerscan` is a command you can run from anywhere inside that
virtual environment.

## How to use it

Scan one site:

```bash
headerscan https://example.com
```

Other things you can do:

```bash
headerscan example.com github.com             # scan several sites (https:// is added for you)
headerscan https://example.com --json         # output for other programs to read
headerscan https://example.com --min-grade B  # fail unless the site scores B or better
headerscan https://localhost:8443 --insecure  # allow a self-signed certificate (testing only)
python -m headerscan https://example.com      # run it without installing the command
```

### Options

| Option | What it does |
|---|---|
| `--json` | Prints results as JSON instead of a table |
| `--min-grade A-F` | Sets the lowest grade you'll accept (default: `C`) |
| `--timeout SECONDS` | How long to wait for the site (default: 10) |
| `--insecure` | Skips certificate checking, for test servers only |
| `--user-agent TEXT` | Changes the name the scanner introduces itself with |

### What the exit code means

When the scan finishes, the program ends with a number. Automation tools (like
CI pipelines) use it to decide if a build should pass.

| Code | Meaning |
|---|---|
| `0` | Success: every site met your minimum grade |
| `1` | A site scored below your minimum grade |
| `2` | A site couldn't be scanned (wrong address, timeout, etc.) |

## What it checks

Each check is worth points based on how serious it is:
**high = 30 points, medium = 15, low = 5.**

- **PASS** earns all the points
- **WARN** (present but weak) earns half
- **FAIL** (missing or broken) earns none
- **INFO** is shown for your knowledge but isn't scored

Your score is the points earned divided by the points possible. That percentage
becomes the grade: **90+ is A, 80+ is B, 70+ is C, 60+ is D, below 60 is F.**

| Check | Severity | Purpose |
|---|---|---|
| HTTPS | high | Is the site encrypted? Does plain HTTP redirect to HTTPS? |
| `Strict-Transport-Security` | high | Does the site tell browsers to always use HTTPS, and for long enough? |
| `Content-Security-Policy` | high | Does the site limit which scripts can run, without loopholes? |
| `X-Content-Type-Options` | medium | Stops browsers from guessing file types |
| Clickjacking protection | medium | Stops other sites from putting this one in a hidden frame |
| Cookie flags | medium | Are cookies marked `Secure`, `HttpOnly` and `SameSite`? |
| `Referrer-Policy` | low | Controls how much of your URL is shared with other sites |
| `Permissions-Policy` | low | Limits access to things like the camera and location |
| Cross-Origin policies | low | Keeps the page isolated from other sites |
| Technology disclosure | low | Is the server revealing its software and version number? |
| CORS | high | Is the site dangerously letting any website make requests with a user's login? |

## Example output

This is a scan of a deliberately badly configured test server:

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

Read it top to bottom: each row is one check, then your grade, then a list of
fixes.

## Use it in your own projects

### In a CI pipeline (GitHub Actions)

This fails the build if your staging site drops below a B:

```yaml
- run: pip install git+https://github.com/RomarioBennett/http-header-scanner
- run: headerscan https://staging.example.com --min-grade B
```

### As a Python library

```python
from headerscan import scan

result = scan("https://example.com")
print(result.grade, result.score)

for f in result.findings:
    print(f.status.value, f.title, f.detail)
```

## How the code is organized

```
src/headerscan/
├── cli.py       # reads what you typed and sets the exit code
├── scanner.py   # visits the website and collects its headers
├── checks.py    # the security rules (one small function per rule)
├── models.py    # the data shapes and the scoring/grade math
└── report.py    # prints the colorful results table
```

The flow when you run a scan:

```
you type a command → cli.py → scanner.py fetches the site → checks.py judges it
                                                  → models.py scores it → report.py prints it
```

**The main design idea:** only `scanner.py` talks to the internet. Everything
else is plain logic. That means the rules can be tested instantly with fake
data, with no real websites involved.

### Adding your own check

1. Write a function in `checks.py` that takes the response info and returns a result.
2. Add it to the `ALL_CHECKS` list.
3. Write a test for it in `tests/test_checks.py`.

## Built-in safety choices

- **Only one request, headers only.** The page content is never downloaded.
- **Cookie values are never shown**, only their names, so secrets can't leak into your terminal or logs.
- **Server output is treated as untrusted.** Text from a website is sanitized before printing so a malicious site can't mess with your terminal.
- **Redirects are followed.** The final page is what gets graded, since that's what visitors actually see.

## Running the tests

```bash
pytest          # 42 tests, no internet needed
ruff check .    # code style check
```

## Limitations

**Limitations**
- Checks one page at a time; it doesn't crawl the whole site.
- The Content-Security-Policy check catches the most common mistakes but isn't a full analyzer.
- Doesn't inspect TLS versions or certificates.



## Responsible use

This tool sends one ordinary request, but only scan websites you own or have
permission to test.

## Credits

Inspired by the weighted grading approach of
[Mozilla Observatory](https://developer.mozilla.org/en-US/observatory) and the
foundations project in
[CarterPerez-dev/Cybersecurity-Projects](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/foundations/http-headers-scanner).
This is an independent implementation.

## License

MIT
