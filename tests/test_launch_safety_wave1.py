#!/usr/bin/env python3
"""Tests for the Launch Safety Standard wave-1 fixes (2026-10-10):

- A5  connection pinning: resolve once, connect to the validated IP —
      a hostname that re-resolves to a private IP is never fetched there.
- C21 response bodies are read under a hard byte cap.
- A10 the rate limiter keys on the LAST X-Forwarded-For hop (the old
      first-hop keying was client-spoofable) and also covers /poc/pdf.
- A2  POST routes reject cross-site Origin/Referer headers.
- F27/F31 /privacy and /terms pages exist and are linked in footers.
- D22 --faint text colour meets WCAG AA contrast (>= 4.5:1) on --bg.

App-level tests skip cleanly when Flask is not installed (the scanner
test environment has no Flask; production installs requirements.txt).
"""
import os
import re
import socket
import unittest
from unittest.mock import patch

import scanner
from scanner import UnsafeTarget

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

PUBLIC_IP = "93.184.216.34"
PRIVATE_IP = "10.0.0.5"


def _gai_entry(ip):
    return (socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443))


class _FakeResp:
    def __init__(self, body=b"ok", status=200, headers=()):
        self._body = body
        self.status = status
        self._headers = list(headers)
        self._pos = 0

    def read(self, n=-1):
        if self._pos >= len(self._body):
            return b""
        if n is None or n < 0:
            n = len(self._body) - self._pos
        chunk = self._body[self._pos:self._pos + n]
        self._pos += len(chunk)
        return chunk

    def getheaders(self):
        return list(self._headers)


class _FakeConn:
    """Records what the pinned transport would have dialled."""
    instances = []
    resp = None

    def __init__(self, host, port=None, timeout=None,
                 _sg_ip=None, _sg_sni=None, **kwargs):
        self.host, self.port = host, port
        self.ip, self.sni = _sg_ip, _sg_sni
        _FakeConn.instances.append(self)

    def request(self, method, path, headers=None):
        self.method, self.path, self.headers = method, path, headers

    def getresponse(self):
        return _FakeConn.resp or _FakeResp()

    def close(self):
        pass


class TestPinning(unittest.TestCase):
    def setUp(self):
        _FakeConn.instances = []
        _FakeConn.resp = None

    def _patch_conns(self):
        return (patch.object(scanner, "_PinnedHTTPConnection", _FakeConn),
                patch.object(scanner, "_PinnedHTTPSConnection", _FakeConn))

    def test_rebinding_hostname_is_never_fetched_at_private_ip(self):
        # DNS answers a public IP at validation time, then flips to a
        # private IP — the classic rebinding sequence. The pinned
        # transport resolves ONCE, so the second answer is never used.
        calls = []

        def fake_gai(host, port=None, *a, **k):
            calls.append(host)
            ip = PUBLIC_IP if len(calls) == 1 else PRIVATE_IP
            return [_gai_entry(ip)]

        p1, p2 = self._patch_conns()
        with patch.object(scanner.socket, "getaddrinfo", fake_gai), p1, p2:
            r = scanner._request("GET", "http://rebind.test/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(calls), 1)  # resolved exactly once
        self.assertEqual(len(_FakeConn.instances), 1)
        conn = _FakeConn.instances[0]
        self.assertEqual(conn.ip, PUBLIC_IP)  # pinned to validated IP
        self.assertNotEqual(conn.ip, PRIVATE_IP)
        self.assertEqual(conn.headers["Host"], "rebind.test")

    def test_mixed_public_and_private_resolution_rejected(self):
        def fake_gai(host, port=None, *a, **k):
            return [_gai_entry(PUBLIC_IP), _gai_entry(PRIVATE_IP)]

        with patch.object(scanner.socket, "getaddrinfo", fake_gai):
            self.assertFalse(scanner._is_public_host("mixed.test"))
            with self.assertRaises(UnsafeTarget):
                scanner._resolve_public("mixed.test")
            with self.assertRaises(UnsafeTarget):
                scanner._check_url("https://mixed.test/")

    def test_body_byte_cap(self):
        def fake_gai(host, port=None, *a, **k):
            return [_gai_entry(PUBLIC_IP)]

        _FakeConn.resp = _FakeResp(body=b"x" * 100_000)
        p1, p2 = self._patch_conns()
        with patch.object(scanner.socket, "getaddrinfo", fake_gai), p1, p2, \
                patch.object(scanner, "MAX_BODY_BYTES", 1000):
            r = scanner._request("GET", "http://big.test/")
        self.assertEqual(len(r.content), 1000)

    def test_redirect_to_private_host_rejected(self):
        # Per-hop pinning: a public site redirecting to a private host
        # must fail on the second hop, not be fetched.
        def fake_gai(host, port=None, *a, **k):
            ip = PUBLIC_IP if host == "good.test" else PRIVATE_IP
            return [_gai_entry(ip)]

        _FakeConn.resp = _FakeResp(
            status=302, headers=[("Location", "http://evil.test/")])
        p1, p2 = self._patch_conns()
        with patch.object(scanner.socket, "getaddrinfo", fake_gai), p1, p2:
            with self.assertRaises(UnsafeTarget):
                scanner._safe_get("http://good.test/")
        self.assertEqual(len(_FakeConn.instances), 1)  # only hop 1 fetched


def _luminance(hex_color):
    r, g, b = (int(hex_color[i:i + 2], 16) / 255 for i in (1, 3, 5))
    f = lambda c: c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
    r, g, b = f(r), f(g), f(b)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


class TestContrast(unittest.TestCase):
    def test_faint_meets_wcag_aa_on_page_background(self):
        bg = _luminance("#0a0d12")
        for tpl in ("index.html", "report.html", "legal.html"):
            with open(os.path.join(ROOT, "templates", tpl)) as fh:
                css = fh.read()
            m = re.search(r"--faint:\s*(#[0-9a-fA-F]{6})", css)
            self.assertIsNotNone(m, tpl)
            ratio = (_luminance(m.group(1)) + 0.05) / (bg + 0.05)
            self.assertGreaterEqual(
                ratio, 4.5, f"{tpl}: --faint {m.group(1)} is {ratio:.2f}:1")


try:
    import app as sg_app
    _HAVE_APP = True
except Exception:  # Flask not installed in this environment
    sg_app = None
    _HAVE_APP = False


@unittest.skipUnless(_HAVE_APP, "Flask not installed in this environment")
class TestAppWave1(unittest.TestCase):
    def setUp(self):
        sg_app._hits.clear()
        self.client = sg_app.app.test_client()

    def tearDown(self):
        sg_app._hits.clear()

    # --- A10: rate-limit keying ---
    def test_client_ip_uses_last_xff_hop(self):
        with sg_app.app.test_request_context(
                headers={"X-Forwarded-For": "1.1.1.1, 2.2.2.2, 3.3.3.3"}):
            self.assertEqual(sg_app._client_ip(), "3.3.3.3")
        with sg_app.app.test_request_context(
                headers={"X-Forwarded-For": "8.8.8.8"}):
            self.assertEqual(sg_app._client_ip(), "8.8.8.8")
        with sg_app.app.test_request_context(
                environ_base={"REMOTE_ADDR": "127.0.0.1"}):
            self.assertEqual(sg_app._client_ip(), "127.0.0.1")

    def test_rotating_fake_first_hop_does_not_dodge_limit(self):
        # Same real visitor (last hop 5.5.5.5), ever-changing fake first
        # hop: under the old keying each post got a fresh bucket.
        for i in range(sg_app.RATE_LIMIT):
            r = self.client.post(
                "/scan", data={},
                headers={"X-Forwarded-For": f"9.9.9.{i}, 5.5.5.5"})
            self.assertEqual(r.status_code, 200)
        r = self.client.post(
            "/scan", data={},
            headers={"X-Forwarded-For": "9.9.9.99, 5.5.5.5"})
        self.assertEqual(r.status_code, 429)

    def test_no_xff_falls_back_to_remote_addr(self):
        for _ in range(sg_app.RATE_LIMIT):
            r = self.client.post("/scan", data={})
            self.assertEqual(r.status_code, 200)
        r = self.client.post("/scan", data={})
        self.assertEqual(r.status_code, 429)

    def test_poc_and_pdf_are_rate_limited(self):
        for _ in range(sg_app.RATE_LIMIT):
            r = self.client.post("/poc", data={})
            self.assertEqual(r.status_code, 200)
        r = self.client.post("/poc", data={})
        self.assertEqual(r.status_code, 429)

        sg_app._hits.clear()
        for _ in range(sg_app.RATE_LIMIT):
            r = self.client.post("/poc/pdf", data={})
            self.assertNotEqual(r.status_code, 429)
        r = self.client.post("/poc/pdf", data={})
        self.assertEqual(r.status_code, 429)

    # --- A2: origin check ---
    def test_foreign_origin_rejected(self):
        r = self.client.post("/scan", data={},
                             headers={"Origin": "https://evil.example"})
        self.assertEqual(r.status_code, 403)
        r = self.client.post("/poc", data={},
                             headers={"Origin": "https://evil.example"})
        self.assertEqual(r.status_code, 403)

    def test_foreign_referer_rejected(self):
        r = self.client.post("/scan", data={},
                             headers={"Referer": "https://evil.example/x"})
        self.assertEqual(r.status_code, 403)

    def test_same_host_and_absent_origin_pass(self):
        r = self.client.post("/scan", data={},
                             headers={"Origin": "http://localhost"})
        self.assertEqual(r.status_code, 200)
        r = self.client.post("/scan", data={})  # curl-style: no headers
        self.assertEqual(r.status_code, 200)
        r = self.client.get("/", headers={"Origin": "https://evil.example"})
        self.assertEqual(r.status_code, 200)  # guard applies to POST only

    # --- F27/F31: legal pages ---
    def test_privacy_and_terms_pages(self):
        r = self.client.get("/privacy")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"Privacy Policy", r.data)
        self.assertIn(b"in memory", r.data)
        r = self.client.get("/terms")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"Terms of Use", r.data)
        self.assertIn(b"permission", r.data)

    def test_footer_links_to_legal_pages(self):
        r = self.client.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b'href="/privacy"', r.data)
        self.assertIn(b'href="/terms"', r.data)


if __name__ == "__main__":
    unittest.main()
