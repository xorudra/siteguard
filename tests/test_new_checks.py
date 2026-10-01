#!/usr/bin/env python3
"""Mocked tests for SiteGuard's 12 newer checks (12-23).

No real network: scanner._check_url, _get, _safe_get, the TRACE call and
the TLS socket layer are all faked, so every pass/fail/skipped branch can
be exercised deterministically.
"""
import socket
import ssl
import unittest
from unittest.mock import MagicMock, patch

import scanner

HOST = "example.test"
DEDUCT = scanner.DEDUCT

CHECK_NAMES = {
    12: "File-type guessing blocked (nosniff)",
    13: "Link-click data leak controlled (Referrer-Policy)",
    14: "Browser feature restrictions (Permissions-Policy)",
    15: "Login/session cookies locked down",
    16: "Cross-site data sharing locked down (CORS)",
    17: "Outdated encryption versions disabled",
    18: "Security contact file (security.txt)",
    19: "Risky TRACE method disabled",
    20: "Extra technology names hidden",
    21: "Cross-origin isolation (COOP/COEP)",
    22: "HSTS covers all subdomains",
    23: "robots.txt hides sensitive paths",
}

GOOD_HEADERS = {
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=(), microphone=()",
    "cross-origin-opener-policy": "same-origin",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
}
GOOD_COOKIES = ["sess=abc; Path=/; Secure; HttpOnly; SameSite=Lax"]


class FakeHeaders(dict):
    def getlist(self, name):
        val = self.get(name.lower())
        if val is None:
            return []
        return val if isinstance(val, list) else [val]


class FakeResponse:
    def __init__(self, status_code=200, headers=None, text="",
                 set_cookies=()):
        self.status_code = status_code
        self.headers = FakeHeaders(
            {k.lower(): v for k, v in (headers or {}).items()})
        self.text = text
        self.raw = self
        if set_cookies:
            self.headers["set-cookie"] = list(set_cookies)


def run_scan(base_headers=None, set_cookies=GOOD_COOKIES,
             security_txt=200, robots_txt=200, robots_body="",
             trace_status=405, tls_behavior="rejected",
             fail_urls=(), base_raises=False):
    """Run scan() with everything faked. tls_behavior: accepted|rejected|network-fail."""
    headers = dict(GOOD_HEADERS if base_headers is None else base_headers)

    def router(url, *a, **k):
        for suffix in fail_urls:
            if url.endswith(suffix):
                raise ConnectionError("mocked network failure")
        if url == f"https://{HOST}/":
            if base_raises:
                raise ConnectionError("mocked network failure")
            return FakeResponse(200, headers, set_cookies=set_cookies)
        if url == f"http://{HOST}/":
            return FakeResponse(301, {"location": f"https://{HOST}/"})
        if url.endswith("/.git/HEAD") or url.endswith("/.env"):
            return FakeResponse(404)
        if url.endswith("/wp-login.php"):
            return FakeResponse(404)
        if url.endswith("/.well-known/security.txt"):
            return FakeResponse(security_txt)
        if url.endswith("/robots.txt"):
            return FakeResponse(robots_txt, text=robots_body)
        return FakeResponse(404)

    # --- TLS fakes ---
    fake_sock_cm = MagicMock()
    fake_sock_cm.__enter__.return_value = MagicMock()
    if tls_behavior == "network-fail":
        fake_create = MagicMock(side_effect=socket.timeout("mocked timeout"))
    else:
        fake_create = MagicMock(return_value=fake_sock_cm)
    fake_ctx = MagicMock()
    fake_ss = MagicMock()
    if tls_behavior == "accepted":
        fake_ss.version.return_value = "TLSv1"
        wrap_cm = MagicMock()
        wrap_cm.__enter__.return_value = fake_ss
        fake_ctx.wrap_socket.return_value = wrap_cm
    else:  # rejected: server actively refuses the old-protocol handshake
        fake_ctx.wrap_socket.side_effect = ssl.SSLError("mocked handshake failure")
    fake_ssl_ctx_cls = MagicMock(return_value=fake_ctx)

    with patch.object(scanner, "_check_url", lambda url: url), \
         patch.object(scanner, "_get", side_effect=router), \
         patch.object(scanner, "_safe_get", side_effect=router), \
         patch.object(scanner.requests, "request",
                      return_value=FakeResponse(trace_status)), \
         patch.object(scanner.socket, "create_connection", fake_create), \
         patch.object(scanner.ssl, "SSLContext", fake_ssl_ctx_cls), \
         patch.object(scanner.ssl, "create_default_context",
                      side_effect=Exception("mocked: skip cert check")):
        return scanner.scan(HOST)


def check_status(result, name):
    return next(c["status"] for c in result["checks"] if c["name"] == name)


def has_finding(result, key):
    return any(f["key"] == key for f in result["findings"])


class NewChecksTest(unittest.TestCase):
    def test_total_check_count_is_23(self):
        result = run_scan()
        self.assertEqual(len(result["checks"]), 23)

    def test_finding_keys_unique(self):
        # worst case: everything fails at once
        bad = dict(GOOD_HEADERS)
        del bad["x-content-type-options"]
        del bad["referrer-policy"]
        del bad["permissions-policy"]
        del bad["cross-origin-opener-policy"]
        bad["strict-transport-security"] = "max-age=31536000"
        bad["access-control-allow-origin"] = "*"
        bad["access-control-allow-credentials"] = "true"
        bad["x-aspnet-version"] = "4.0.30319"
        result = run_scan(
            base_headers=bad,
            set_cookies=["sess=abc; Path=/"],
            security_txt=404,
            robots_body="User-agent: *\nDisallow: /admin/\n",
            trace_status=200,
            tls_behavior="accepted",
        )
        keys = [f["key"] for f in result["findings"]]
        self.assertEqual(len(keys), len(set(keys)),
                         f"duplicate keys: {keys}")

    def test_all_severities_supported(self):
        result = run_scan(base_headers={}, set_cookies=["s=1"],
                          security_txt=404, trace_status=200,
                          tls_behavior="accepted",
                          robots_body="Disallow: /backup/\n")
        for f in result["findings"]:
            self.assertIn(f["severity"], DEDUCT,
                          f"unsupported severity on {f['key']}")

    # 12. nosniff
    def test_12_nosniff(self):
        h = dict(GOOD_HEADERS); del h["x-content-type-options"]
        r = run_scan(base_headers=h)
        self.assertEqual(check_status(r, CHECK_NAMES[12]), "failed")
        self.assertTrue(has_finding(r, "nosniff-missing"))
        r = run_scan()
        self.assertEqual(check_status(r, CHECK_NAMES[12]), "passed")

    # 13. referrer-policy
    def test_13_referrer_policy(self):
        for bad in ({}, {"referrer-policy": "unsafe-url"}):
            h = dict(GOOD_HEADERS); h.pop("referrer-policy", None); h.update(bad)
            r = run_scan(base_headers=h)
            self.assertEqual(check_status(r, CHECK_NAMES[13]), "failed")
            self.assertTrue(has_finding(r, "referrer-policy-insecure"))
        r = run_scan()
        self.assertEqual(check_status(r, CHECK_NAMES[13]), "passed")

    # 14. permissions-policy
    def test_14_permissions_policy(self):
        h = dict(GOOD_HEADERS); del h["permissions-policy"]
        r = run_scan(base_headers=h)
        self.assertEqual(check_status(r, CHECK_NAMES[14]), "info")
        self.assertTrue(has_finding(r, "permissions-policy-missing"))
        r = run_scan()
        self.assertEqual(check_status(r, CHECK_NAMES[14]), "passed")

    # 15. cookie flags
    def test_15_cookie_flags(self):
        r = run_scan(set_cookies=["sess=abc; Path=/"])
        self.assertEqual(check_status(r, CHECK_NAMES[15]), "failed")
        self.assertTrue(has_finding(r, "cookie-flags-missing"))
        f = next(f for f in r["findings"] if f["key"] == "cookie-flags-missing")
        self.assertEqual(f["severity"], "medium")
        r = run_scan()
        self.assertEqual(check_status(r, CHECK_NAMES[15]), "passed")
        r = run_scan(base_raises=True)  # no HTTPS -> skipped
        self.assertEqual(check_status(r, CHECK_NAMES[15]), "skipped")

    # 16. CORS
    def test_16_cors(self):
        h = dict(GOOD_HEADERS)
        h["access-control-allow-origin"] = "*"
        h["access-control-allow-credentials"] = "true"
        r = run_scan(base_headers=h)
        self.assertEqual(check_status(r, CHECK_NAMES[16]), "failed")
        self.assertTrue(has_finding(r, "cors-wildcard-credentials"))
        f = next(f for f in r["findings"] if f["key"] == "cors-wildcard-credentials")
        self.assertEqual(f["severity"], "high")
        r = run_scan()
        self.assertEqual(check_status(r, CHECK_NAMES[16]), "passed")

    # 17. old TLS — tri-state
    def test_17_tls(self):
        r = run_scan(tls_behavior="accepted")
        self.assertEqual(check_status(r, CHECK_NAMES[17]), "failed")
        self.assertTrue(has_finding(r, "tls-old-version"))
        r = run_scan(tls_behavior="rejected")
        self.assertEqual(check_status(r, CHECK_NAMES[17]), "passed")
        self.assertFalse(has_finding(r, "tls-old-version"))
        r = run_scan(tls_behavior="network-fail")
        self.assertEqual(check_status(r, CHECK_NAMES[17]), "skipped",
                         "inconclusive TLS probes must be skipped, not passed")

    # 18. security.txt
    def test_18_security_txt(self):
        r = run_scan(security_txt=404)
        self.assertEqual(check_status(r, CHECK_NAMES[18]), "info")
        self.assertTrue(has_finding(r, "security-txt-missing"))
        r = run_scan(security_txt=200)
        self.assertEqual(check_status(r, CHECK_NAMES[18]), "passed")
        r = run_scan(fail_urls=("/.well-known/security.txt",))
        self.assertEqual(check_status(r, CHECK_NAMES[18]), "skipped")

    # 19. TRACE
    def test_19_trace(self):
        r = run_scan(trace_status=200)
        self.assertEqual(check_status(r, CHECK_NAMES[19]), "failed")
        self.assertTrue(has_finding(r, "http-trace-enabled"))
        r = run_scan(trace_status=405)
        self.assertEqual(check_status(r, CHECK_NAMES[19]), "passed")

    # 20. tech headers
    def test_20_tech_headers(self):
        h = dict(GOOD_HEADERS); h["x-aspnet-version"] = "4.0.30319"
        r = run_scan(base_headers=h)
        self.assertEqual(check_status(r, CHECK_NAMES[20]), "failed")
        self.assertTrue(has_finding(r, "tech-version-headers"))
        r = run_scan()
        self.assertEqual(check_status(r, CHECK_NAMES[20]), "passed")

    # 21. COOP/COEP
    def test_21_coop_coep(self):
        h = dict(GOOD_HEADERS); del h["cross-origin-opener-policy"]
        r = run_scan(base_headers=h)
        self.assertEqual(check_status(r, CHECK_NAMES[21]), "info")
        self.assertTrue(has_finding(r, "cross-origin-policy-missing"))
        r = run_scan()
        self.assertEqual(check_status(r, CHECK_NAMES[21]), "passed")

    # 22. HSTS includeSubDomains
    def test_22_hsts_subdomains(self):
        h = dict(GOOD_HEADERS); h["strict-transport-security"] = "max-age=31536000"
        r = run_scan(base_headers=h)
        self.assertEqual(check_status(r, CHECK_NAMES[22]), "failed")
        self.assertTrue(has_finding(r, "hsts-weak"))
        r = run_scan()
        self.assertEqual(check_status(r, CHECK_NAMES[22]), "passed")
        h = dict(GOOD_HEADERS); del h["strict-transport-security"]
        r = run_scan(base_headers=h)
        self.assertEqual(check_status(r, CHECK_NAMES[22]), "skipped")

    # 23. robots.txt
    def test_23_robots(self):
        r = run_scan(robots_txt=200,
                     robots_body="User-agent: *\nDisallow: /admin/\n")
        self.assertEqual(check_status(r, CHECK_NAMES[23]), "info")
        self.assertTrue(has_finding(r, "robots-disclosure"))
        r = run_scan(robots_txt=200,
                     robots_body="User-agent: *\nDisallow: /public/\n")
        self.assertEqual(check_status(r, CHECK_NAMES[23]), "passed")
        r = run_scan(robots_txt=404)
        self.assertEqual(check_status(r, CHECK_NAMES[23]), "passed")
        r = run_scan(fail_urls=("/robots.txt",))
        self.assertEqual(check_status(r, CHECK_NAMES[23]), "skipped")


if __name__ == "__main__":
    unittest.main(verbosity=2)
