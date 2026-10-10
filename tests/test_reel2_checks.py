#!/usr/bin/env python3
"""Mocked tests for SiteGuard's legal-basics checks (scanner.py #34-39).

Reel 2 (duck.tate, 2026): getting sued over a vibe-coded app — missing
privacy/terms pages, copy-paste template placeholders, thin terms,
trackers with no cookie consent, and an unsecured backend (Supabase
storage here; the database half is covered by test_reel_checks.py).
No real network: scanner._check_url and scanner._get are faked.
"""
import base64
import json
import unittest
from unittest.mock import patch

import scanner

HOST = "example.test"
PROJ = "https://xyzproj.supabase.co"

GOOD_PRIVACY = (
    "Privacy Policy. This privacy policy explains what we collect. "
    "We share data with third parties only as needed: our service "
    "providers for hosting, payments and analytics receive the data "
    "required to run the service. We keep data for one year and you "
    "can request deletion at any time by emailing us. " * 2)
GOOD_TERMS = (
    "Terms of Service. Billing and subscription payments are charged "
    "monthly. Our limitation of liability applies to the maximum "
    "extent permitted. We may terminate accounts that break the "
    "rules. These terms are governed by governing law of India. "
    "All intellectual property in the service belongs to us. " * 2)


def make_jwt(role):
    def b64(obj):
        return base64.urlsafe_b64encode(
            json.dumps(obj).encode()).decode().rstrip("=")
    return f"{b64({'alg': 'HS256', 'typ': 'JWT'})}.{b64({'role': role})}.sig"


ANON = make_jwt("anon")


class FakeResponse:
    def __init__(self, status_code=200, headers=None, text=""):
        self.status_code = status_code
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}
        self.text = text
        self.content = text.encode()


def run_scan(homepage_html, exact=None, substrings=None):
    routes = {f"https://{HOST}/": FakeResponse(200, text=homepage_html)}
    routes.update(exact or {})
    substrings = substrings or []

    def fake_check_url(url):
        return url

    def fake_get(url, headers=None):
        if url in routes:
            resp = routes[url]
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
         patch.object(scanner, "_get", fake_get), \
         patch.object(scanner, "_request",
                      side_effect=ConnectionError("offline")):
        return scanner.scan(HOST)


def legal(privacy=None, terms=None):
    routes = {}
    if privacy is not None:
        routes[f"https://{HOST}/privacy"] = FakeResponse(200, text=privacy)
    if terms is not None:
        routes[f"https://{HOST}/terms"] = FakeResponse(200, text=terms)
    return routes


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


class TestLegalExistence(unittest.TestCase):
    def test_no_legal_pages_failed(self):
        report = run_scan("<p>hello</p>")
        self.assertEqual(status_of(report, "Privacy policy page exists"),
                         "failed")
        self.assertEqual(status_of(report, "Terms page exists"), "failed")
        self.assertIsNotNone(finding(report, "privacy-missing"))
        self.assertIsNotNone(finding(report, "terms-missing"))
        self.assertEqual(
            status_of(report, "Legal pages customised and complete"),
            "skipped")
        self.assertEqual(
            status_of(report, "Privacy policy names who receives data"),
            "skipped")

    def test_good_legal_pages_pass(self):
        report = run_scan("<p>hello</p>",
                          exact=legal(GOOD_PRIVACY, GOOD_TERMS))
        self.assertEqual(status_of(report, "Privacy policy page exists"),
                         "passed")
        self.assertEqual(status_of(report, "Terms page exists"), "passed")
        self.assertEqual(
            status_of(report, "Legal pages customised and complete"),
            "passed")
        self.assertEqual(
            status_of(report, "Privacy policy names who receives data"),
            "passed")


class TestLegalQuality(unittest.TestCase):
    def test_placeholder_failed(self):
        terms = GOOD_TERMS + " Operated by [Company Name], registered."
        report = run_scan("<p>hello</p>",
                          exact=legal(GOOD_PRIVACY, terms))
        self.assertEqual(
            status_of(report, "Legal pages customised and complete"),
            "failed")
        f = finding(report, "legal-placeholder")
        self.assertIsNotNone(f)
        self.assertEqual(f["severity"], "medium")

    def test_thin_terms_failed(self):
        thin = ("Terms. You may use the site. We can terminate your "
                "account at any time. That is everything. " * 4)
        report = run_scan("<p>hello</p>",
                          exact=legal(GOOD_PRIVACY, thin))
        self.assertEqual(
            status_of(report, "Legal pages customised and complete"),
            "failed")
        self.assertIsNotNone(finding(report, "terms-thin"))

    def test_privacy_silent_on_processors_info(self):
        silent = ("Privacy Policy. This privacy policy explains what "
                  "we collect. We collect your email when you sign up "
                  "and keep it for your account. You can ask us to "
                  "delete it by writing to us any time you like. " * 2)
        report = run_scan("<p>hello</p>",
                          exact=legal(silent, GOOD_TERMS))
        self.assertEqual(
            status_of(report, "Privacy policy names who receives data"),
            "failed")
        f = finding(report, "privacy-no-processors")
        self.assertIsNotNone(f)
        self.assertEqual(f["severity"], "info")


class TestCookieConsent(unittest.TestCase):
    def test_tracker_no_consent_failed(self):
        html = ('<script src="https://www.googletagmanager.com/gtag/js'
                '?id=G-ABCDEFGH12"></script><p>hi</p>')
        report = run_scan(html)
        self.assertEqual(
            status_of(report, "Cookie consent shown when trackers run"),
            "failed")
        f = finding(report, "cookie-consent-missing")
        self.assertIsNotNone(f)
        self.assertIn("Google Analytics", f["title"])

    def test_tracker_with_consent_passed(self):
        html = ('<script src="https://www.googletagmanager.com/gtag/js'
                '?id=G-ABCDEFGH12"></script>'
                '<div>We use cookies to improve the site. '
                '<button>Accept</button></div>')
        report = run_scan(html)
        self.assertEqual(
            status_of(report, "Cookie consent shown when trackers run"),
            "passed")

    def test_no_tracker_passed(self):
        report = run_scan("<p>hello</p>")
        self.assertEqual(
            status_of(report, "Cookie consent shown when trackers run"),
            "passed")


class TestStorageBuckets(unittest.TestCase):
    def _html(self):
        return f'<script>const k="{ANON}"; const u="{PROJ}"</script>'

    def test_public_bucket_info(self):
        buckets = json.dumps([{"name": "avatars", "public": True},
                              {"name": "docs", "public": False}])
        report = run_scan(self._html(), substrings=[
            ("/storage/v1/bucket", FakeResponse(200, text=buckets)),
            ("/rest/v1/", FakeResponse(401, text="no")),
        ])
        self.assertEqual(
            status_of(report, "Cloud storage buckets not public"),
            "info")
        f = finding(report, "supabase-public-bucket")
        self.assertIsNotNone(f)
        self.assertIn("avatars", f["title"])
        self.assertNotIn("docs", f["title"])

    def test_private_buckets_passed(self):
        buckets = json.dumps([{"name": "docs", "public": False}])
        report = run_scan(self._html(), substrings=[
            ("/storage/v1/bucket", FakeResponse(200, text=buckets)),
            ("/rest/v1/", FakeResponse(401, text="no")),
        ])
        self.assertEqual(
            status_of(report, "Cloud storage buckets not public"),
            "passed")

    def test_no_supabase_skipped(self):
        report = run_scan("<p>hello</p>")
        self.assertEqual(
            status_of(report, "Cloud storage buckets not public"),
            "skipped")


if __name__ == "__main__":
    unittest.main()
