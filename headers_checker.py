#!/usr/bin/env python3
"""Security headers checker.

Reads the HTTP response headers of a website (or a saved copy of them) and
flags protections that are missing or set weakly.
Standard library only. Only a normal page request is made, nothing is attacked.

Usage:
    python3 headers_checker.py https://example.com
    python3 headers_checker.py --file sample_headers/01_bare_server.txt
    python3 headers_checker.py https://example.com --format json --min-severity medium
"""

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from urllib.parse import urlparse

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# Six months, a common minimum for Strict-Transport-Security.
MIN_HSTS_SECONDS = 15_552_000


@dataclass(frozen=True)
class Finding:
    target: str
    rule_id: str
    severity: str
    title: str
    detail: str
    advice: str


class Headers:
    """Response headers. Names are case-insensitive; a name may repeat."""

    def __init__(self, pairs):
        self._items = [(name.strip().lower(), value.strip()) for name, value in pairs]

    def get(self, name):
        name = name.lower()
        for key, value in self._items:
            if key == name:
                return value
        return None

    def get_all(self, name):
        name = name.lower()
        return [value for key, value in self._items if key == name]

    def has(self, name):
        return self.get(name) is not None


def parse_raw_headers(text):
    """Turn a saved header dump into (url, Headers).

    The first line may be a status line (HTTP/1.1 200 OK). An optional comment
    line `# url: https://example.com/` says which address the headers came from.
    Without it, https is assumed.
    """
    url = "https://example.test/"
    pairs = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("#"):
            match = re.match(r"#\s*url:\s*(\S+)", line, re.IGNORECASE)
            if match:
                url = match.group(1)
            continue
        if line.upper().startswith("HTTP/"):
            continue
        if ":" in line:
            name, _, value = line.partition(":")
            pairs.append((name, value))
    return url, Headers(pairs)


def fetch_headers(url, timeout=10):
    """Request the page and return (final_url, Headers). Redirects are followed."""
    request = urllib.request.Request(
        url, headers={"User-Agent": "headers-checker/1.0 (learning project)"}
    )
    try:
        response = urllib.request.urlopen(request, timeout=timeout)
    except urllib.error.HTTPError as error:  # 404 etc. still carry headers
        response = error
    with response:
        pairs = list(response.headers.items())
        final_url = response.geturl() if hasattr(response, "geturl") else url
    return final_url, Headers(pairs)


def hsts_max_age(value):
    match = re.search(r"max-age\s*=\s*\"?(\d+)", value, re.IGNORECASE)
    return int(match.group(1)) if match else None


def csp_directives(value):
    result = {}
    for part in value.split(";"):
        part = part.strip()
        if part:
            name, *sources = part.split()
            result[name.lower()] = sources
    return result


def check_headers(url, headers, label=None):
    target = label or url
    findings = []

    def add(rule_id, severity, title, detail, advice):
        findings.append(Finding(target, rule_id, severity, title, detail, advice))

    is_https = urlparse(url).scheme.lower() == "https"

    if not is_https:
        add("not-https", "high", "Page is not served over HTTPS",
            "Anyone on the network path can read or change what is sent.",
            "Serve the site over HTTPS and redirect plain HTTP to it.")

    # --- Strict-Transport-Security ---
    hsts = headers.get("strict-transport-security")
    if is_https:
        if hsts is None:
            add("hsts-missing", "high", "Strict-Transport-Security is missing",
                "Browsers are not told to always use HTTPS for this site.",
                "Send: Strict-Transport-Security: max-age=31536000; includeSubDomains")
        else:
            age = hsts_max_age(hsts)
            if age is None or age < MIN_HSTS_SECONDS:
                add("hsts-weak", "medium", "Strict-Transport-Security lifetime is too short",
                    f"Value is: {hsts}",
                    "Use a max-age of at least 15552000 (6 months); 31536000 (1 year) is common.")

    # --- Content-Security-Policy ---
    csp = headers.get("content-security-policy")
    directives = csp_directives(csp) if csp else {}
    if csp is None:
        add("csp-missing", "medium", "Content-Security-Policy is missing",
            "The browser has no rule about which scripts and resources may load.",
            "Start with a policy such as: default-src 'self'")
    elif any(
        "'unsafe-inline'" in sources or "'unsafe-eval'" in sources
        for sources in directives.values()
    ):
        add("csp-unsafe", "medium", "Content-Security-Policy allows unsafe-inline or unsafe-eval",
            f"Value is: {csp}",
            "Remove 'unsafe-inline' and 'unsafe-eval'; use nonces or hashes for needed scripts.")

    # --- Clickjacking protection ---
    has_frame_rule = headers.has("x-frame-options") or "frame-ancestors" in directives
    if not has_frame_rule:
        add("clickjacking", "medium", "Page can be shown inside another site's frame",
            "Neither X-Frame-Options nor a CSP frame-ancestors rule is set.",
            "Send X-Frame-Options: DENY, or CSP frame-ancestors 'none'.")

    # --- X-Content-Type-Options ---
    nosniff = headers.get("x-content-type-options")
    if nosniff is None or nosniff.lower() != "nosniff":
        add("nosniff-missing", "low", "X-Content-Type-Options: nosniff is missing",
            "Browsers may guess a file's type and run it as something else.",
            "Send: X-Content-Type-Options: nosniff")

    # --- Referrer-Policy / Permissions-Policy ---
    if not headers.has("referrer-policy"):
        add("referrer-policy-missing", "low", "Referrer-Policy is missing",
            "Full page addresses may be sent to other sites when users click away.",
            "Send: Referrer-Policy: strict-origin-when-cross-origin")
    if not headers.has("permissions-policy"):
        add("permissions-policy-missing", "low", "Permissions-Policy is missing",
            "Browser features like camera and location are not restricted.",
            "Send: Permissions-Policy: camera=(), microphone=(), geolocation=()")

    # --- Information leaks ---
    server = headers.get("server")
    if server and re.search(r"\d", server):
        add("server-version", "low", "Server header shows a software version",
            f"Value is: {server}",
            "Hide the version so attackers cannot match it to known bugs.")
    powered = headers.get("x-powered-by")
    if powered:
        add("x-powered-by", "low", "X-Powered-By header reveals the technology",
            f"Value is: {powered}",
            "Remove the X-Powered-By header.")

    # --- Cookies ---
    for cookie in headers.get_all("set-cookie"):
        name = cookie.split("=", 1)[0].strip()
        flags = {part.strip().lower().split("=")[0] for part in cookie.split(";")[1:]}
        if is_https and "secure" not in flags:
            add("cookie-no-secure", "medium", f"Cookie '{name}' has no Secure flag",
                "It can be sent over plain HTTP.", "Add the Secure flag.")
        if "httponly" not in flags:
            add("cookie-no-httponly", "medium", f"Cookie '{name}' has no HttpOnly flag",
                "Scripts on the page can read it.", "Add the HttpOnly flag.")
        if "samesite" not in flags:
            add("cookie-no-samesite", "low", f"Cookie '{name}' has no SameSite setting",
                "It is sent with requests from other sites.", "Add SameSite=Lax or Strict.")

    # --- Cross-origin sharing ---
    if (headers.get("access-control-allow-origin") or "").strip() == "*":
        add("cors-wildcard", "low", "Any website may read this response (CORS *)",
            "Access-Control-Allow-Origin is set to *.",
            "Allow only the sites that need it, unless the content is fully public.")

    return findings


def sort_findings(findings):
    return sorted(findings, key=lambda f: (f.target, -SEVERITY_ORDER[f.severity], f.rule_id))


def format_text(findings, targets_checked):
    lines = []
    current = None
    for f in findings:
        if f.target != current:
            current = f.target
            lines.append(f"== {f.target}")
        lines.append(f"[{f.severity.upper()}] {f.title} ({f.rule_id})")
        lines.append(f"  {f.detail}")
        lines.append(f"  fix: {f.advice}")
        lines.append("")
    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    summary = ", ".join(
        f"{counts[s]} {s}" for s in ("critical", "high", "medium", "low") if s in counts
    )
    lines.append(
        f"Checked {targets_checked} target(s): {len(findings)} finding(s)"
        + (f" ({summary})" if summary else "")
    )
    return "\n".join(lines)


def build_parser():
    parser = argparse.ArgumentParser(description="Check a website's security headers.")
    parser.add_argument("urls", nargs="*", help="web addresses to check")
    parser.add_argument("--file", action="append", default=[],
                        help="a saved header dump to check instead of a live site")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--min-severity", choices=tuple(SEVERITY_ORDER), default="low",
                        help="hide findings below this level (default: low)")
    parser.add_argument("--fail-on", choices=tuple(SEVERITY_ORDER), default="high",
                        help="exit with code 1 if a finding is at or above this level (default: high)")
    parser.add_argument("--timeout", type=int, default=10, help="seconds to wait (default: 10)")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    if not args.urls and not args.file:
        print("error: give at least one web address or --file", file=sys.stderr)
        return 2

    all_findings = []
    checked = 0
    try:
        for path in args.file:
            with open(path, encoding="utf-8") as handle:
                url, headers = parse_raw_headers(handle.read())
            all_findings.extend(check_headers(url, headers, label=f"{path} ({url})"))
            checked += 1
        for url in args.urls:
            if "://" not in url:
                url = "https://" + url
            final_url, headers = fetch_headers(url, args.timeout)
            all_findings.extend(check_headers(final_url, headers))
            checked += 1
    except (OSError, ValueError) as error:  # URLError is an OSError
        print(f"error: could not read {error}", file=sys.stderr)
        return 2

    all_findings = sort_findings(all_findings)
    minimum = SEVERITY_ORDER[args.min_severity]
    shown = [f for f in all_findings if SEVERITY_ORDER[f.severity] >= minimum]

    if args.format == "json":
        print(json.dumps([asdict(f) for f in shown], indent=2))
    else:
        print(format_text(shown, checked))

    threshold = SEVERITY_ORDER[args.fail_on]
    if any(SEVERITY_ORDER[f.severity] >= threshold for f in all_findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
