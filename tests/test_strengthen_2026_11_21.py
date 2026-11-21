"""Strengthening batch (2026-11-21): SPF + DMARC email checks, mixed
content, and the 'na' (doesn't apply) status that replaced 'skipped'
for checks whose precondition is absent on the scanned site.

Harness mirrors test_new_checks: scanner._get/_safe_get are replaced
with a fake keyed by URL. The DoH endpoint is just another URL to the
fake, so DNS answers are fully scripted here.
"""
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import scanner


class FakeHeaders(dict):
    def getlist(self, name):
        val = self.get(name.lower())
        if val is None:
            return []
        return val if isinstance(val, list) else [val]


class FakeResponse:
    def __init__(self, status_code=200, headers=None, text=""):
        self.status_code = status_code
        self.headers = FakeHeaders(
            {k.lower(): v for k, v in (headers or {}).items()})
        self.text = text
        self.content = text.encode()
        self.url = ""


GOOD_HEADERS = {
    "x-frame-options": "SAMEORIGIN",
    "content-security-policy": "default-src 'self'",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=()",
    "cross-origin-opener-policy": "same-origin",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
}

HOST = "shop.test"


def doh_json(records):
    return json.dumps({
        "Status": 0,
        "Answer": [{"name": "x", "type": 16, "data": f'"{r}"'}
                   for r in records],
    })


def run_scan(spf=None, dmarc=None, doh_down=False, page_html="<p>hi</p>"):
    """spf/dmarc: list of TXT strings, or None for 'no records'."""

    def fake_get(url, headers=None):
        if url.startswith("https://cloudflare-dns.com/"):
            if doh_down:
                return FakeResponse(503)
            if "_dmarc." in url:
                return FakeResponse(200, text=doh_json(dmarc or []))
            return FakeResponse(200, text=doh_json(spf or []))
        if url == f"https://{HOST}/":
            return FakeResponse(200, GOOD_HEADERS, text=page_html)
        if url == f"http://{HOST}/":
            return FakeResponse(301, {"location": f"https://{HOST}/"})
        return FakeResponse(404)

    with patch.object(scanner, "_get", fake_get), \
            patch.object(scanner, "_safe_get", fake_get), \
            patch.object(scanner, "_is_public_host", return_value=True), \
            patch.object(scanner, "_open_validated",
                         side_effect=ConnectionError("no tls in tests")):
        return scanner.scan(HOST)


def status_of(report, name):
    return next(c["status"] for c in report["checks"] if c["name"] == name)


class TestEmailChecks(unittest.TestCase):
    def test_spf_and_dmarc_pass(self):
        r = run_scan(spf=["v=spf1 include:_spf.google.com -all"],
                     dmarc=["v=DMARC1; p=reject; rua=mailto:d@shop.test"])
        self.assertEqual(status_of(r, "Email sender rules set (SPF)"),
                         "passed")
        self.assertEqual(status_of(r, "Fake-email policy set (DMARC)"),
                         "passed")

    def test_missing_records_fail(self):
        r = run_scan()
        self.assertEqual(status_of(r, "Email sender rules set (SPF)"),
                         "failed")
        self.assertEqual(status_of(r, "Fake-email policy set (DMARC)"),
                         "failed")
        keys = {f["key"] for f in r["findings"]}
        self.assertIn("spf-missing", keys)
        self.assertIn("dmarc-missing", keys)

    def test_spf_plus_all_fails_medium(self):
        r = run_scan(spf=["v=spf1 +all"])
        self.assertEqual(status_of(r, "Email sender rules set (SPF)"),
                         "failed")
        f = next(f for f in r["findings"] if f["key"] == "spf-open")
        self.assertEqual(f["severity"], "medium")

    def test_dmarc_p_none_is_weak(self):
        r = run_scan(dmarc=["v=DMARC1; p=none"])
        self.assertEqual(status_of(r, "Fake-email policy set (DMARC)"),
                         "failed")
        self.assertIn("dmarc-weak", {f["key"] for f in r["findings"]})

    def test_doh_down_means_skipped_not_failed(self):
        r = run_scan(doh_down=True)
        self.assertEqual(status_of(r, "Email sender rules set (SPF)"),
                         "skipped")
        self.assertEqual(status_of(r, "Fake-email policy set (DMARC)"),
                         "skipped")


class TestMixedContent(unittest.TestCase):
    def test_mixed_content_fails(self):
        r = run_scan(page_html='<img src="http://cdn.x/a.png">')
        self.assertEqual(status_of(r, "Page parts all load securely"),
                         "failed")
        self.assertIn("mixed-content",
                      {f["key"] for f in r["findings"]})

    def test_clean_page_passes(self):
        r = run_scan(page_html='<img src="https://cdn.x/a.png">')
        self.assertEqual(status_of(r, "Page parts all load securely"),
                         "passed")


class TestMailDomain(unittest.TestCase):
    def test_derivations(self):
        self.assertEqual(scanner._mail_domain("example.com"), "example.com")
        self.assertEqual(scanner._mail_domain("www.example.com"),
                         "example.com")
        self.assertEqual(scanner._mail_domain("app.shop.co.in"),
                         "shop.co.in")
        self.assertEqual(scanner._mail_domain("a.b.example.com"),
                         "example.com")


if __name__ == "__main__":
    unittest.main()
