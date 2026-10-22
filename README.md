# Security headers checker

![tests](https://github.com/twistedsol/security-headers-checker/actions/workflows/tests.yml/badge.svg)

A small Python tool that reads the HTTP response headers of a website and flags security protections that are missing or set weakly. It uses the standard library only, so there is nothing to install. It makes one normal page request and does nothing else to the site.

## Run it

Check a live site:

```bash
python3 headers_checker.py https://example.com
```

On Windows, use `py -3.13 headers_checker.py https://example.com`.

Or check a saved copy of headers, with no internet needed:

```bash
python3 headers_checker.py --file sample_headers/02_static_host_hsts_only.txt
```

Example output:

```
== sample_headers/02_static_host_hsts_only.txt (https://blog.example.test/)
[MEDIUM] Page can be shown inside another site's frame (clickjacking)
  Neither X-Frame-Options nor a CSP frame-ancestors rule is set.
  fix: Send X-Frame-Options: DENY, or CSP frame-ancestors 'none'.

[MEDIUM] Content-Security-Policy is missing (csp-missing)
  The browser has no rule about which scripts and resources may load.
  fix: Start with a policy such as: default-src 'self'

[LOW] X-Content-Type-Options: nosniff is missing (nosniff-missing)
  Browsers may guess a file's type and run it as something else.
  fix: Send: X-Content-Type-Options: nosniff

[LOW] Permissions-Policy is missing (permissions-policy-missing)
  Browser features like camera and location are not restricted.
  fix: Send: Permissions-Policy: camera=(), microphone=(), geolocation=()

[LOW] Referrer-Policy is missing (referrer-policy-missing)
  Full page addresses may be sent to other sites when users click away.
  fix: Send: Referrer-Policy: strict-origin-when-cross-origin

Checked 1 target(s): 5 finding(s) (2 medium, 3 low)
```

The files in `sample_headers/` are made-up headers: an old unprotected server, a static host that only sets one header, and a well configured site.

## What it checks

| Rule | Severity | What it catches |
| --- | --- | --- |
| not-https | high | The page is served over plain HTTP |
| hsts-missing | high | No Strict-Transport-Security on an HTTPS page |
| hsts-weak | medium | Strict-Transport-Security lifetime under 6 months |
| csp-missing | medium | No Content-Security-Policy |
| csp-unsafe | medium | A policy that allows `'unsafe-inline'` or `'unsafe-eval'` |
| clickjacking | medium | No X-Frame-Options and no CSP frame-ancestors rule |
| cookie-no-secure | medium | A cookie without the Secure flag (HTTPS pages) |
| cookie-no-httponly | medium | A cookie without the HttpOnly flag |
| cookie-no-samesite | low | A cookie without a SameSite setting |
| nosniff-missing | low | X-Content-Type-Options: nosniff is missing |
| referrer-policy-missing | low | No Referrer-Policy |
| permissions-policy-missing | low | No Permissions-Policy |
| server-version | low | The Server header shows a software version |
| x-powered-by | low | The X-Powered-By header reveals the technology |
| cors-wildcard | low | Access-Control-Allow-Origin is * |

Cookie values are never printed. Only the cookie name is shown.

## Options

```bash
python3 headers_checker.py https://example.com --format json         # machine-readable output
python3 headers_checker.py https://example.com --min-severity medium  # hide low findings
python3 headers_checker.py https://example.com --fail-on medium       # fail on medium and above
```

Exit codes: `0` nothing at or above the fail level, `1` something found, `2` the site or file could not be read.

## Test it

```bash
python3 -m unittest -v
```

47 tests cover each rule, case-insensitive header names, repeated headers, the command-line options and exit codes, and the sample files. A few tests start a tiny web server on the same computer to test the real request code, so they need no internet.

## How I built it

This is part of a 30-day challenge to learn cloud security by building in public. It follows the [log detector](https://github.com/twistedsol/log-detector), the [misconfiguration scan](https://github.com/twistedsol/misconfig-scan), the [IAM policy checker](https://github.com/twistedsol/iam-policy-checker) and the [secrets scanner](https://github.com/twistedsol/secrets-scanner). I wrote the code together with Claude. No cloud account is needed.

## What I learned

- Not every finding can be fixed on every host. GitHub Pages does not let you set response headers, so my own site will always show a few.
- A checker that reads headers cannot see a CSP set with a meta tag inside the HTML, so it can say "missing" when something is partly in place.
- A good checker avoids false alarms. HSTS and the cookie Secure flag only matter on https, so I skip those checks on http pages.
-
- ## Limits

- It reads headers from one page request. Other pages on the same site can send different headers.
- It checks that a header exists and a few obvious weak values. It does not judge whether a full Content-Security-Policy is well designed.
- Some hosts, such as static site hosts, do not let you set your own response headers. A missing header there may not be fixable without moving the site behind a service that can add headers.
- It only makes a normal request, so it cannot see problems that need a login or a special request to show up.

## Next ideas

- Follow redirects step by step and report each hop
- Check several pages from a list
- Output a markdown report
