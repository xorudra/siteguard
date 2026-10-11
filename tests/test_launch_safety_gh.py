#!/usr/bin/env python3
"""Tests for the Launch Safety Standard sections G/H wave (2026-10-11).

- H39 useful 404/405 page instead of Flask's default error text.
- H39 form errors preserve the user's valid input (scan + VAPT URL)
      instead of making them retype it.
- G33 public GET pages carry explicit Cache-Control TTLs; POST and
      error responses are never marked publicly cacheable.
- H41 favicon served (SVG, long cache) and linked from every page;
      canonical + Open Graph basics on the indexable pages.

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


@unittest.skipUnless(_HAVE_APP, "Flask not installed in this environment")
class TestAppG33(unittest.TestCase):
    def setUp(self):
        self.client = sg_app.app.test_client()

    def tearDown(self):
        sg_app._hits.clear()

    def test_index_has_short_public_cache(self):
        r = self.client.get("/")
        self.assertEqual(r.status_code, 200)
        cc = r.headers.get("Cache-Control", "")
        self.assertIn("public", cc)
        self.assertIn("max-age=300", cc)

    def test_legal_pages_have_longer_public_cache(self):
        for path in ("/privacy", "/terms"):
            r = self.client.get(path)
            cc = r.headers.get("Cache-Control", "")
            self.assertIn("public", cc, path)
            self.assertIn("max-age=3600", cc, path)

    def test_post_responses_are_not_publicly_cached(self):
        r = self.client.post("/scan", data={})
        self.assertNotIn("public", r.headers.get("Cache-Control", ""))

    def test_error_pages_are_not_cached(self):
        r = self.client.get("/no-such-page")
        self.assertNotIn("public", r.headers.get("Cache-Control", ""))


@unittest.skipUnless(_HAVE_APP, "Flask not installed in this environment")
class TestAppH41(unittest.TestCase):
    def setUp(self):
        self.client = sg_app.app.test_client()

    def tearDown(self):
        sg_app._hits.clear()

    def test_favicon_svg_served_with_long_cache(self):
        r = self.client.get("/favicon.svg")
        self.assertEqual(r.status_code, 200)
        self.assertIn("image/svg+xml", r.headers.get("Content-Type", ""))
        self.assertIn("max-age=604800",
                      r.headers.get("Cache-Control", ""))
        self.assertIn(b"<svg", r.data)

    def test_favicon_ico_path_also_served(self):
        r = self.client.get("/favicon.ico")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"<svg", r.data)

    def test_pages_link_the_favicon(self):
        for path in ("/", "/privacy", "/terms", "/no-such-page"):
            body = self.client.get(path).get_data(as_text=True)
            self.assertIn('rel="icon"', body, path)
            self.assertIn("/favicon.svg", body, path)

    def test_index_has_canonical_and_og(self):
        body = self.client.get("/").get_data(as_text=True)
        self.assertIn('rel="canonical"', body)
        self.assertIn("https://siteguard-vf9c.onrender.com/", body)
        self.assertIn('property="og:title"', body)
        self.assertIn('property="og:description"', body)

    def test_legal_pages_have_canonical(self):
        body = self.client.get("/privacy").get_data(as_text=True)
        self.assertIn("https://siteguard-vf9c.onrender.com/privacy", body)
        body = self.client.get("/terms").get_data(as_text=True)
        self.assertIn("https://siteguard-vf9c.onrender.com/terms", body)


if __name__ == "__main__":
    unittest.main()
