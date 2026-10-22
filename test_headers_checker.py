import contextlib
import http.server
import io
import json
import tempfile
import threading
import unittest
from pathlib import Path

import headers_checker as hc

GOOD = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=()",
}


def headers(**overrides):
    """GOOD headers with changes. A value of None removes that header."""
    merged = {k.replace("_", "-"): v for k, v in GOOD.items()}
    for key, value in overrides.items():
        name = key.replace("_", "-")
        # match existing names case-insensitively
        for existing in list(merged):
            if existing.lower() == name.lower():
                del merged[existing]
        if value is not None:
            merged[name] = value
    return hc.Headers(list(merged.items()))


def ids(url, hdrs):
    return sorted(f.rule_id for f in hc.check_headers(url, hdrs))


HTTPS = "https://example.test/"


class CleanSiteTests(unittest.TestCase):
    def test_well_configured_site_has_no_findings(self):
        self.assertEqual(ids(HTTPS, headers()), [])

    def test_header_names_are_case_insensitive(self):
        h = hc.Headers([("strict-transport-security", "max-age=31536000"),
                        ("CONTENT-SECURITY-POLICY", "default-src 'self'; frame-ancestors 'none'"),
                        ("x-content-type-options", "NOSNIFF"),
                        ("REFERRER-POLICY", "no-referrer"),
                        ("Permissions-Policy", "camera=()")])
        self.assertEqual(ids(HTTPS, h), [])


class TransportTests(unittest.TestCase):
    def test_http_is_flagged(self):
        self.assertIn("not-https", ids("http://example.test/", headers()))

    def test_hsts_not_required_over_http(self):
        found = ids("http://example.test/", headers(Strict_Transport_Security=None))
        self.assertNotIn("hsts-missing", found)

    def test_hsts_missing(self):
        self.assertEqual(ids(HTTPS, headers(Strict_Transport_Security=None)), ["hsts-missing"])

    def test_hsts_short_lifetime(self):
        self.assertEqual(ids(HTTPS, headers(Strict_Transport_Security="max-age=300")), ["hsts-weak"])

    def test_hsts_without_max_age(self):
        self.assertEqual(ids(HTTPS, headers(Strict_Transport_Security="includeSubDomains")), ["hsts-weak"])

    def test_hsts_six_months_is_accepted(self):
        self.assertEqual(ids(HTTPS, headers(Strict_Transport_Security="max-age=15552000")), [])


class PolicyTests(unittest.TestCase):
    def test_csp_missing(self):
        found = ids(HTTPS, headers(Content_Security_Policy=None))
        self.assertIn("csp-missing", found)

    def test_csp_unsafe_inline(self):
        h = headers(Content_Security_Policy="script-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
        self.assertEqual(ids(HTTPS, h), ["csp-unsafe"])

    def test_csp_unsafe_eval(self):
        h = headers(Content_Security_Policy="default-src 'unsafe-eval'; frame-ancestors 'none'")
        self.assertEqual(ids(HTTPS, h), ["csp-unsafe"])

    def test_clickjacking_when_no_frame_rule(self):
        h = headers(Content_Security_Policy="default-src 'self'")
        self.assertEqual(ids(HTTPS, h), ["clickjacking"])

    def test_x_frame_options_counts_as_frame_rule(self):
        h = headers(Content_Security_Policy="default-src 'self'", X_Frame_Options="DENY")
        self.assertEqual(ids(HTTPS, h), [])

    def test_nosniff_missing(self):
        self.assertEqual(ids(HTTPS, headers(X_Content_Type_Options=None)), ["nosniff-missing"])

    def test_nosniff_wrong_value(self):
        self.assertEqual(ids(HTTPS, headers(X_Content_Type_Options="sniff")), ["nosniff-missing"])

    def test_referrer_policy_missing(self):
        self.assertEqual(ids(HTTPS, headers(Referrer_Policy=None)), ["referrer-policy-missing"])

    def test_permissions_policy_missing(self):
        self.assertEqual(ids(HTTPS, headers(Permissions_Policy=None)), ["permissions-policy-missing"])


class LeakTests(unittest.TestCase):
    def extra(self, **more):
        base = headers()
        return hc.Headers(base._items + [(k.replace("_", "-"), v) for k, v in more.items()])

    def test_server_version_leak(self):
        self.assertEqual(ids(HTTPS, self.extra(Server="Apache/2.4.41")), ["server-version"])

    def test_server_without_version_is_fine(self):
        self.assertEqual(ids(HTTPS, self.extra(Server="nginx")), [])

    def test_x_powered_by(self):
        self.assertEqual(ids(HTTPS, self.extra(X_Powered_By="PHP/7.4")), ["x-powered-by"])

    def test_cors_wildcard(self):
        self.assertEqual(ids(HTTPS, self.extra(Access_Control_Allow_Origin="*")), ["cors-wildcard"])

    def test_cors_specific_origin_is_fine(self):
        h = self.extra(Access_Control_Allow_Origin="https://a.example")
        self.assertEqual(ids(HTTPS, h), [])


class CookieTests(unittest.TestCase):
    def with_cookie(self, cookie):
        return hc.Headers(headers()._items + [("set-cookie", cookie)])

    def test_safe_cookie(self):
        h = self.with_cookie("id=1; Path=/; Secure; HttpOnly; SameSite=Lax")
        self.assertEqual(ids(HTTPS, h), [])

    def test_plain_cookie_over_https(self):
        h = self.with_cookie("id=1; Path=/")
        self.assertEqual(ids(HTTPS, h),
                         ["cookie-no-httponly", "cookie-no-samesite", "cookie-no-secure"])

    def test_secure_flag_not_asked_over_http(self):
        h = self.with_cookie("id=1; HttpOnly; SameSite=Lax")
        self.assertNotIn("cookie-no-secure", ids("http://example.test/", h))

    def test_every_cookie_is_checked(self):
        h = hc.Headers(headers()._items + [("set-cookie", "a=1; Secure; HttpOnly; SameSite=Lax"),
                                           ("set-cookie", "b=2; Secure; SameSite=Lax")])
        findings = hc.check_headers(HTTPS, h)
        self.assertEqual([f.rule_id for f in findings], ["cookie-no-httponly"])
        self.assertIn("'b'", findings[0].title)

    def test_cookie_value_is_not_in_the_report(self):
        h = self.with_cookie("sessionid=supersecretvalue; Path=/")
        text = hc.format_text(hc.check_headers(HTTPS, h), 1)
        self.assertNotIn("supersecretvalue", text)


class ParsingTests(unittest.TestCase):
    def test_status_line_and_comments_are_skipped(self):
        url, h = hc.parse_raw_headers("# url: http://a.test/\nHTTP/1.1 200 OK\nServer: nginx\n")
        self.assertEqual(url, "http://a.test/")
        self.assertEqual(h.get("server"), "nginx")

    def test_default_url_is_https(self):
        url, _ = hc.parse_raw_headers("Server: nginx")
        self.assertTrue(url.startswith("https://"))

    def test_repeated_header_names_are_kept(self):
        _, h = hc.parse_raw_headers("Set-Cookie: a=1\nSet-Cookie: b=2")
        self.assertEqual(h.get_all("set-cookie"), ["a=1", "b=2"])

    def test_value_with_colons(self):
        _, h = hc.parse_raw_headers("Link: <https://a.test/x>; rel=preload")
        self.assertEqual(h.get("link"), "<https://a.test/x>; rel=preload")

    def test_hsts_max_age_parsing(self):
        self.assertEqual(hc.hsts_max_age("max-age=100; includeSubDomains"), 100)
        self.assertIsNone(hc.hsts_max_age("includeSubDomains"))

    def test_csp_directives(self):
        d = hc.csp_directives("default-src 'self'; img-src *")
        self.assertEqual(d["img-src"], ["*"])


class OutputTests(unittest.TestCase):
    def test_sorted_most_severe_first(self):
        found = hc.sort_findings(hc.check_headers("http://example.test/", hc.Headers([])))
        self.assertEqual(found[0].severity, "high")

    def test_summary_line(self):
        found = hc.check_headers(HTTPS, headers(Strict_Transport_Security=None))
        self.assertIn("1 finding(s) (1 high)", hc.format_text(found, 1))

    def test_clean_summary(self):
        self.assertIn("0 finding(s)", hc.format_text([], 1))


class CommandLineTests(unittest.TestCase):
    def run_main(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = hc.main([str(a) for a in args])
        return code, out.getvalue(), err.getvalue()

    def test_no_arguments_exits_2(self):
        self.assertEqual(self.run_main()[0], 2)

    def test_missing_file_exits_2(self):
        code, _, err = self.run_main("--file", "nope.txt")
        self.assertEqual(code, 2)
        self.assertIn("error", err)

    def test_bare_server_sample_exits_1(self):
        self.assertEqual(self.run_main("--file", "sample_headers/01_bare_server.txt")[0], 1)

    def test_good_sample_exits_0(self):
        code, out, _ = self.run_main("--file", "sample_headers/03_well_configured.txt")
        self.assertEqual(code, 0)
        self.assertIn("0 finding(s)", out)

    def test_medium_only_exits_0_by_default_and_1_with_fail_on_medium(self):
        sample = "sample_headers/02_static_host_hsts_only.txt"
        self.assertEqual(self.run_main("--file", sample)[0], 0)
        self.assertEqual(self.run_main("--file", sample, "--fail-on", "medium")[0], 1)

    def test_json_output_and_min_severity(self):
        _, out, _ = self.run_main("--file", "sample_headers/01_bare_server.txt",
                                  "--format", "json", "--min-severity", "high")
        data = json.loads(out)
        self.assertEqual([d["rule_id"] for d in data], ["not-https"])

    def test_sample_finding_counts(self):
        counts = {}
        for name in ("01_bare_server", "02_static_host_hsts_only", "03_well_configured"):
            url, h = hc.parse_raw_headers(Path(f"sample_headers/{name}.txt").read_text())
            counts[name] = len(hc.check_headers(url, h))
        self.assertEqual(counts, {"01_bare_server": 11, "02_static_host_hsts_only": 5,
                                  "03_well_configured": 0})


class LiveFetchTests(unittest.TestCase):
    """Starts a tiny web server on this computer. No internet is used."""

    @classmethod
    def setUpClass(cls):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(404 if self.path == "/missing" else 200)
                self.send_header("X-Test", "hello")
                self.send_header("Set-Cookie", "a=1")
                self.end_headers()
                self.wfile.write(b"hi")

            def log_message(self, *args):
                pass

        cls.server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_fetch_reads_headers(self):
        url, h = hc.fetch_headers(f"http://127.0.0.1:{self.port}/")
        self.assertEqual(h.get("x-test"), "hello")
        self.assertTrue(url.startswith("http://127.0.0.1"))

    def test_error_pages_still_give_headers(self):
        _, h = hc.fetch_headers(f"http://127.0.0.1:{self.port}/missing")
        self.assertEqual(h.get("x-test"), "hello")

    def test_main_checks_a_live_address(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = hc.main([f"http://127.0.0.1:{self.port}/"])
        self.assertEqual(code, 1)
        self.assertIn("not-https", out.getvalue())

    def test_unreachable_address_exits_2(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            code = hc.main(["http://127.0.0.1:9/", "--timeout", "2"])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
