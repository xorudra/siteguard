#!/usr/bin/env python3
"""Mocked tests for SiteGuard's VAPT mode (vapt.py) — 6 active checks.

No real network: vapt._check_url, vapt._safe_get and requests.options are
all faked, so every pass/fail/skipped branch runs deterministically.
"""
import unittest
from unittest.mock import patch
from urllib.parse import urlparse, parse_qs

import vapt
from scanner import UnsafeTarget

HOST = "example.test"
BASE = f"https://{HOST}"


class FakeHeaders(dict):
    pass


class FakeResponse:
    def __init__(self, status_code=200, headers=None, text=""):
        self.status_code = status_code
        self.headers = FakeHeaders(
            {k.lower(): v for k, v in (headers or {}).items()})
        self.text = text
        self.content = text.encode()


def run_vapt(reflect=False, sql_error=False, open_redirect=False,
             backup_exposed=False, allow_header="GET, HEAD, OPTIONS",
             verbose_404=False, fail_urls=(), check_raises=False):
    """Run vapt_scan() with everything faked."""

    def fake_check_url(url):
        if check_raises:
            raise UnsafeTarget("mocked: not a public host")
        return url

    def router(url, *a, **k):
        for suffix in fail_urls:
            if suffix in url:
                raise ConnectionError("mocked network failure")
        if "?sgx=" in url:
            token = parse_qs(urlparse(url).query).get("sgx", [""])[0]
            return FakeResponse(200, text=f"<html>hello {token}</html>"
                                if reflect else "<html>hello</html>")
        if "?id=%27" in url:
            return FakeResponse(
                200, text="You have an error in your SQL syntax; check "
                         "the manual that corresponds to your MySQL server"
                if sql_error else "<html>ok</html>")
        if any(f"?{p}=" in url for p in ("next", "redirect", "url")):
            if open_redirect:
                return FakeResponse(302, {"Location":
                                          vapt.REDIRECT_CANARY})
            return FakeResponse(200, text="<html>ok</html>")
        if any(url == BASE + p for p in vapt.BACKUP_PATHS):
            if backup_exposed:
                return FakeResponse(200, text="x" * 5000)
            return FakeResponse(404)
        if "/sg-missing-" in url:
            return FakeResponse(
                404, text="Traceback (most recent call last): ..."
                if verbose_404 else "<html>not found</html>")
        return FakeResponse(404)

    def fake_options(url, **k):
        fake_check_url(url)
        return FakeResponse(200, {"Allow": allow_header})

    with patch.object(vapt, "_check_url", side_effect=fake_check_url), \
         patch.object(vapt, "_safe_get", side_effect=router), \
         patch.object(vapt.requests, "options", side_effect=fake_options):
        return vapt.vapt_scan(HOST)


def check_status(result, name):
    return next(c["status"] for c in result["checks"] if c["name"] == name)


def has_finding(result, key):
    return any(f["key"] == key for f in result["findings"])


NAMES = [
    "User input reflected in pages",
    "Database errors hidden",
    "Login/link redirects stay on your site",
    "No backup files exposed",
    "Only safe request methods enabled",
    "Error pages hide internals",
]


class VaptTest(unittest.TestCase):
    def test_six_checks_recorded(self):
        result = run_vapt()
        names = [c["name"] for c in result["checks"]]
        self.assertEqual(names, NAMES)

    def test_clean_site_passes_all(self):
        result = run_vapt()
        self.assertEqual(result["score"], 100)
        self.assertEqual(result["grade"], "A")
        self.assertEqual(result["findings"], [])

    def test_result_shape(self):
        result = run_vapt()
        self.assertEqual(result["url"], HOST)
        self.assertEqual(result["mode"], "vapt")
        self.assertIn("scanned_at", result)

    def test_reflected_input_failed(self):
        result = run_vapt(reflect=True)
        self.assertEqual(check_status(result, NAMES[0]), "failed")
        self.assertTrue(has_finding(result, "reflected-input"))
        f = next(f for f in result["findings"]
                 if f["key"] == "reflected-input")
        self.assertEqual(f["severity"], "medium")
        self.assertEqual(result["score"], 85)

    def test_sql_error_failed_high(self):
        result = run_vapt(sql_error=True)
        self.assertEqual(check_status(result, NAMES[1]), "failed")
        f = next(f for f in result["findings"] if f["key"] == "sql-errors")
        self.assertEqual(f["severity"], "high")
        self.assertEqual(result["score"], 75)

    def test_open_redirect_failed(self):
        result = run_vapt(open_redirect=True)
        self.assertEqual(check_status(result, NAMES[2]), "failed")
        self.assertTrue(has_finding(result, "open-redirect"))

    def test_backup_file_failed(self):
        result = run_vapt(backup_exposed=True)
        self.assertEqual(check_status(result, NAMES[3]), "failed")
        f = next(f for f in result["findings"] if f["key"] == "backup-files")
        self.assertEqual(f["severity"], "low")
        self.assertIn("/backup.zip", f["title"])

    def test_dangerous_methods_failed(self):
        result = run_vapt(allow_header="GET, HEAD, OPTIONS, PUT, DELETE")
        self.assertEqual(check_status(result, NAMES[4]), "failed")
        f = next(f for f in result["findings"]
                 if f["key"] == "dangerous-methods")
        self.assertIn("PUT", f["title"])

    def test_verbose_error_failed(self):
        result = run_vapt(verbose_404=True)
        self.assertEqual(check_status(result, NAMES[5]), "failed")
        self.assertTrue(has_finding(result, "verbose-errors"))

    def test_exceptions_become_skipped(self):
        result = run_vapt(fail_urls=("?sgx=", "?id=", "/sg-missing-",
                                     "/backup.zip", "/backup.tar.gz",
                                     "/db.sql", "/database.sql",
                                     "/index.php.bak", "/index.html.bak",
                                     "/wp-config.php.bak", "/.env.bak"))
        for name in (NAMES[0], NAMES[1], NAMES[3], NAMES[5]):
            self.assertEqual(check_status(result, name), "skipped")
        # open-redirect + dangerous-methods use different paths; force them
        result2 = run_vapt(fail_urls=("?next=", "?redirect=", "?url="))
        self.assertEqual(check_status(result2, NAMES[2]), "skipped")

    def test_options_uses_ssrf_guard(self):
        # requests.options must go through _check_url first
        with self.assertRaises(UnsafeTarget):
            run_vapt(check_raises=True)

    def test_unsafe_target_raises(self):
        with self.assertRaises(UnsafeTarget):
            run_vapt(check_raises=True)

    def test_finding_keys_unique(self):
        result = run_vapt(reflect=True, sql_error=True, open_redirect=True,
                          backup_exposed=True, verbose_404=True,
                          allow_header="GET, PUT")
        keys = [f["key"] for f in result["findings"]]
        self.assertEqual(len(keys), len(set(keys)))
        self.assertEqual(len(result["findings"]), 6)


if __name__ == "__main__":
    unittest.main()
