#!/usr/bin/env python3
"""Mocked tests for SiteGuard's reel-risk checks (scanner.py #29-33).

The reel (adilet.fndr, 2026): a vibe-coded app can cost $100k with zero
users — open Supabase database (no RLS), TCPA texts without consent,
ADA/alt-text lawsuits, and a bandwidth bill from uncached files.
No real network: scanner._check_url and scanner._get are faked.
"""
import base64
import json
import unittest
from unittest.mock import patch

import scanner

HOST = "example.test"
PROJ = "https://xyzproj.supabase.co"


def make_jwt(role):
    def b64(obj):
        return base64.urlsafe_b64encode(
            json.dumps(obj).encode()).decode().rstrip("=")
    return f"{b64({'alg': 'HS256', 'typ': 'JWT'})}.{b64({'role': role})}.sig"


ANON = make_jwt("anon")
SERVICE = make_jwt("service_role")


class FakeResponse:
    def __init__(self, status_code=200, headers=None, text=""):
        self.status_code = status_code
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}
        self.text = text
        self.content = text.encode()


def run_scan(homepage_html, exact=None, substrings=None):
    """routes: exact URL -> resp, plus ordered (needle, resp) substrings."""
    exact = exact or {}
    substrings = substrings or []

    def fake_check_url(url):
        return url

    def fake_get(url, headers=None):
        if url in exact:
            resp = exact[url]
            if isinstance(resp, Exception):
                raise resp
            return resp
        for needle, resp in substrings:
            if needle in url:
                if isinstance(resp, Exception):
                    raise resp
                return resp
        return FakeResponse(404, text="not found")

    with patch.object(scanner, "_check_url", fake_check_url), \
         patch.object(scanner, "_get", fake_get):
        with patch.object(scanner.requests, "request",
                          side_effect=ConnectionError("offline")):
            return scanner.scan(HOST)


def homepage(html):
    return {f"https://{HOST}/": FakeResponse(200, text=html)}


def status_of(report, name):
    for c in report["checks"]:
        if c["name"] == name:
            return c["status"]
    return None


def finding(report, key):
    for f in report["findings"]:
        if f["key"] == key:
            return f
    return None


class TestSupabaseKeys(unittest.TestCase):
    def test_service_role_key_failed(self):
        html = f'<script>const k="{SERVICE}"; const u="{PROJ}"</script>'
        report = run_scan("", exact=homepage(html))
        self.assertEqual(
            status_of(report, "Backend admin keys not leaked in page source"),
            "failed")
        f = finding(report, "supabase-service-key")
        self.assertIsNotNone(f)
        self.assertEqual(f["severity"], "high")

    def test_anon_key_only_passes(self):
        html = f'<script>const k="{ANON}"; const u="{PROJ}"</script>'
        report = run_scan("", exact=homepage(html), substrings=[
            ("/rest/v1/", FakeResponse(401, text="unauthorized")),
        ])
        self.assertEqual(
            status_of(report, "Backend admin keys not leaked in page source"),
            "passed")
        self.assertIsNone(finding(report, "supabase-service-key"))

    def test_no_backend_passes(self):
        report = run_scan("", exact=homepage("<p>hello</p>"))
        self.assertEqual(
            status_of(report, "Backend admin keys not leaked in page source"),
            "passed")
        self.assertEqual(
            status_of(report, "Database not readable by the public (RLS)"),
            "skipped")


class TestRlsProbe(unittest.TestCase):
    def _routes(self, users_resp):
        spec = json.dumps({"paths": {"/": {}, "/users": {},
                                     "/rpc/do_thing": {}}})
        return [
            ("/rest/v1/users?", users_resp),
            ("/rest/v1/", FakeResponse(200, text=spec)),
        ]

    def test_open_users_table_failed_high(self):
        html = f'<script>const k="{ANON}"; const u="{PROJ}"</script>'
        rows = json.dumps([{"id": 1, "email": "a@b.test", "name": "Test"}])
        report = run_scan("", exact=homepage(html),
                          substrings=self._routes(FakeResponse(200, text=rows)))
        self.assertEqual(
            status_of(report, "Database not readable by the public (RLS)"),
            "failed")
        f = finding(report, "supabase-data-open")
        self.assertIsNotNone(f)
        self.assertEqual(f["severity"], "high")
        # Row VALUES must never leak into the report — table/columns only.
        self.assertNotIn("a@b.test", json.dumps(report))

    def test_locked_table_passes(self):
        html = f'<script>const k="{ANON}"; const u="{PROJ}"</script>'
        report = run_scan("", exact=homepage(html), substrings=self._routes(
            FakeResponse(200, text="[]")))
        self.assertEqual(
            status_of(report, "Database not readable by the public (RLS)"),
            "passed")
        self.assertIsNone(finding(report, "supabase-data-open"))


class TestAltText(unittest.TestCase):
    def test_missing_alt_failed(self):
        html = '<img src="/a.png"><img src="/b.png" alt="Bee">'
        report = run_scan("", exact=homepage(html))
        self.assertEqual(
            status_of(report, "Images have text descriptions (alt text)"),
            "failed")
        f = finding(report, "img-alt-missing")
        self.assertIsNotNone(f)
        self.assertIn("1 of 2", f["title"])

    def test_all_alt_passed(self):
        html = '<img src="/a.png" alt="A"><img src="/b.png" alt="">'
        report = run_scan("", exact=homepage(html))
        self.assertEqual(
            status_of(report, "Images have text descriptions (alt text)"),
            "passed")


class TestCaching(unittest.TestCase):
    def test_no_cache_headers_failed(self):
        html = '<link href="/style.css"><img src="/a.png" alt="A">'
        report = run_scan("", exact=homepage(html))
        self.assertEqual(
            status_of(report,
                      "Files cached, not re-downloaded every visit"),
            "failed")
        self.assertIsNotNone(finding(report, "no-cache-headers"))

    def test_cache_headers_passed(self):
        html = '<link href="/style.css">'
        cached = FakeResponse(
            200, headers={"Cache-Control": "public, max-age=31536000"},
            text="x")
        report = run_scan("", exact=homepage(html),
                          substrings=[("/style.css", cached)])
        self.assertEqual(
            status_of(report,
                      "Files cached, not re-downloaded every visit"),
            "passed")

    def test_no_assets_skipped(self):
        report = run_scan("", exact=homepage("<p>hello</p>"))
        self.assertEqual(
            status_of(report,
                      "Files cached, not re-downloaded every visit"),
            "skipped")


class TestSmsConsent(unittest.TestCase):
    def test_phone_no_consent_info(self):
        html = '<form><input type="tel" name="phone"></form>'
        report = run_scan("", exact=homepage(html))
        self.assertEqual(
            status_of(report, "Text-message signup asks for consent"),
            "info")
        f = finding(report, "sms-consent-risk")
        self.assertIsNotNone(f)
        self.assertEqual(f["severity"], "info")

    def test_phone_with_checkbox_passed(self):
        html = ('<form><input type="tel" name="phone">'
                '<input type="checkbox"> I agree</form>')
        report = run_scan("", exact=homepage(html))
        self.assertEqual(
            status_of(report, "Text-message signup asks for consent"),
            "passed")

    def test_no_phone_field_passed(self):
        report = run_scan("", exact=homepage("<p>hello</p>"))
        self.assertEqual(
            status_of(report, "Text-message signup asks for consent"),
            "passed")


if __name__ == "__main__":
    unittest.main()
