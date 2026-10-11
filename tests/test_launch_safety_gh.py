#!/usr/bin/env python3
"""Tests for the Launch Safety Standard sections G/H wave (2026-10-11).

- H39 useful 404/405 page instead of Flask's default error text.
- H39 form errors preserve the user's valid input (scan + VAPT URL)
      instead of making them retype it.

App-level tests skip cleanly when Flask is not installed (the scanner
test environment has no Flask; production installs requirements.txt).
"""
import unittest

try:
    import app as sg_app
    _HAVE_APP = True
except Exception:
    _HAVE_APP = False


@unittest.skipUnless(_HAVE_APP, "Flask not installed in this environment")
class TestAppGH39(unittest.TestCase):
    def setUp(self):
        self.client = sg_app.app.test_client()

    def tearDown(self):
        sg_app._hits.clear()

    # --- H39: useful error pages ---
    def test_missing_page_gets_branded_404(self):
        r = self.client.get("/no-such-page")
        self.assertEqual(r.status_code, 404)
        body = r.get_data(as_text=True)
        self.assertIn("That page isn't here", body)
        self.assertIn('href="/"', body)

    def test_wrong_method_gets_same_useful_page(self):
        r = self.client.get("/scan")  # /scan is POST-only
        self.assertEqual(r.status_code, 405)
        self.assertIn("That page isn't here", r.get_data(as_text=True))

    # --- H39: input preserved on form errors ---
    def test_scan_error_preserves_long_url(self):
        long_url = "x" * 300
        r = self.client.post("/scan", data={"url": long_url})
        self.assertEqual(r.status_code, 200)
        body = r.get_data(as_text=True)
        self.assertIn("too long", body)
        self.assertIn(f'value="{long_url}"', body)

    def test_vapt_consent_error_preserves_url(self):
        r = self.client.post("/vapt", data={"url": "example.com"})
        self.assertEqual(r.status_code, 200)
        body = r.get_data(as_text=True)
        self.assertIn("permission box", body)
        self.assertIn('value="example.com"', body)

    def test_rate_limit_page_preserves_url(self):
        headers = {"X-Forwarded-For": "7.7.7.7"}
        for _ in range(sg_app.RATE_LIMIT):
            self.client.post("/scan", data={}, headers=headers)
        r = self.client.post("/scan", data={"url": "example.org"},
                             headers=headers)
        self.assertEqual(r.status_code, 429)
        self.assertIn('value="example.org"', r.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
