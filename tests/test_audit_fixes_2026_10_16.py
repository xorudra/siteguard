#!/usr/bin/env python3
"""Regression tests for the 2026-10-16 security-audit fixes.

Each test answers one needs_validation lead from
security-audits-2026-10-16/siteguard/run-1 with a bounded, no-network
check (the audit's own validation plans, implemented):

- cert/TLS probes dialled a fresh, unvalidated DNS answer
  (_open_validated now resolve-validate-pins like the HTTP transport).
- no port allowlist: a redirect or page URL could steer the scanner
  to arbitrary TCP ports on public hosts.
- no overall scan deadline: per-recv timeouts chained indefinitely.
- _pdf_sanitize let CR/LF and C0 controls reach the "Final" PDF.
- _hits keys were never evicted (unbounded retained memory).
- no MAX_CONTENT_LENGTH: urlencoded bodies parsed without a cap.
- local launch bound 0.0.0.0 (unauthenticated endpoints on the LAN).
- rate-limit identity trusted XFF with no edge in local mode —
  XFF now counts only with SITEGUARD_TRUST_PROXY=1.
- requirements.txt floated on >= bounds; now exactly pinned.
"""
import os
import re
import socket
import time
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


def _patch_conns():
    return (patch.object(scanner, "_PinnedHTTPConnection", _FakeConn),
            patch.object(scanner, "_PinnedHTTPSConnection", _FakeConn))


def _public_gai(host, port=None, *a, **k):
    return [_gai_entry(PUBLIC_IP)]


class TestValidatedDial(unittest.TestCase):
    """The raw TLS probes use the same resolve-validate-pin discipline
    as the HTTP transport: a DNS answer that flips to a private IP
    after validation is never dialled."""

    def test_rebinding_answer_is_never_dialled(self):
        calls = []
        dialled = []

        def fake_gai(host, port=None, *a, **k):
            calls.append(host)
            ip = PUBLIC_IP if len(calls) == 1 else PRIVATE_IP
            return [_gai_entry(ip)]

        def fake_connect(addr, *a, **k):
            dialled.append(addr)
            return object()

        with patch.object(scanner.socket, "getaddrinfo", fake_gai), \
                patch.object(scanner.socket, "create_connection",
                             fake_connect):
            scanner._open_validated("rebind.test")
        self.assertEqual(len(calls), 1)  # resolved exactly once
        self.assertEqual(dialled, [(PUBLIC_IP, 443)])

    def test_private_only_resolution_rejected(self):
        def fake_gai(host, port=None, *a, **k):
            return [_gai_entry(PRIVATE_IP)]

        with patch.object(scanner.socket, "getaddrinfo", fake_gai):
            with self.assertRaises(UnsafeTarget):
                scanner._open_validated("internal.test")


class TestPortAllowlist(unittest.TestCase):
    def setUp(self):
        _FakeConn.instances = []
        _FakeConn.resp = None

    def test_check_url_rejects_non_default_ports(self):
        with patch.object(scanner.socket, "getaddrinfo", _public_gai):
            for url in ("http://good.test:2375/", "https://good.test:22/",
                        "http://good.test:99999/"):
                with self.assertRaises(UnsafeTarget, msg=url):
                    scanner._check_url(url)
            for url in ("http://good.test/", "http://good.test:80/",
                        "https://good.test/", "https://good.test:443/"):
                self.assertEqual(scanner._check_url(url), url)

    def test_pinned_fetch_refuses_alternate_port_before_dialling(self):
        p1, p2 = _patch_conns()
        with patch.object(scanner.socket, "getaddrinfo", _public_gai), \
                p1, p2:
            with self.assertRaises(UnsafeTarget):
                scanner._request("GET", "http://good.test:2375/")
        self.assertEqual(_FakeConn.instances, [])

    def test_redirect_to_alternate_port_rejected(self):
        # The audit's validation plan, verbatim scenario: hop 1 answers
        # 302 to a public host on port 2375; the fetch must stop there.
        _FakeConn.resp = _FakeResp(
            status=302,
            headers=[("Location", "http://victim.test:2375/probe?x=1")])
        p1, p2 = _patch_conns()
        with patch.object(scanner.socket, "getaddrinfo", _public_gai), \
                p1, p2:
            with self.assertRaises(UnsafeTarget):
                scanner._safe_get("http://good.test/")
        self.assertEqual(len(_FakeConn.instances), 1)  # only hop 1 ran


class TestScanDeadline(unittest.TestCase):
    def setUp(self):
        _FakeConn.instances = []
        _FakeConn.resp = None
        self.addCleanup(scanner._disarm_deadline)

    def test_expired_deadline_stops_fetches(self):
        scanner._scan_state.deadline = time.monotonic() - 1
        p1, p2 = _patch_conns()
        with patch.object(scanner.socket, "getaddrinfo", _public_gai), \
                p1, p2:
            with self.assertRaises(scanner._DeadlineExceeded):
                scanner._request("GET", "http://good.test/")
        self.assertEqual(_FakeConn.instances, [])

    def test_live_deadline_lets_fetches_through(self):
        scanner._scan_state.deadline = time.monotonic() + 60
        p1, p2 = _patch_conns()
        with patch.object(scanner.socket, "getaddrinfo", _public_gai), \
                p1, p2:
            r = scanner._request("GET", "http://good.test/")
        self.assertEqual(r.status_code, 200)


class TestRequirementsPinned(unittest.TestCase):
    def test_every_requirement_is_an_exact_pin(self):
        with open(os.path.join(ROOT, "requirements.txt")) as fh:
            lines = [ln.strip() for ln in fh
                     if ln.strip() and not ln.startswith("#")]
        self.assertTrue(lines)
        for ln in lines:
            self.assertRegex(ln, r"^[A-Za-z0-9_.-]+==\S+$", ln)


try:
    import app as sg_app
    _HAVE_APP = True
except Exception:  # Flask not installed in this environment
    sg_app = None
    _HAVE_APP = False


@unittest.skipUnless(_HAVE_APP, "Flask not installed in this environment")
class TestAppAuditFixes(unittest.TestCase):
    def setUp(self):
        sg_app._hits.clear()
        self.client = sg_app.app.test_client()

    def tearDown(self):
        sg_app._hits.clear()

    # --- PDF control characters ---
    def test_pdf_sanitize_strips_control_characters(self):
        out = sg_app._pdf_sanitize(
            "Alice\r\nReport status: Draft\x00\x1f\x7f")
        self.assertTrue(
            all(0x20 <= ord(c) and ord(c) != 0x7F for c in out), repr(out))
        self.assertIn("Alice", out)
        self.assertIn("Report status: Draft", out)

    # --- _hits eviction ---
    def test_rate_ok_sweeps_fully_expired_identities(self):
        old = time.time() - sg_app.RATE_WINDOW - 5
        sg_app._hits["gone.test"] = [old]
        sg_app._hits["fresh.test"] = [time.time()]
        self.assertTrue(sg_app._rate_ok("fresh.test"))
        self.assertNotIn("gone.test", sg_app._hits)
        self.assertIn("fresh.test", sg_app._hits)

    # --- request-body cap ---
    def test_oversize_post_gets_clean_413(self):
        r = self.client.post("/scan", data={"url": "x" * 70_000})
        self.assertEqual(r.status_code, 413)
        self.assertIn("too big", r.get_data(as_text=True))

    def test_body_cap_is_configured(self):
        self.assertEqual(sg_app.app.config["MAX_CONTENT_LENGTH"],
                         64 * 1024)

    # --- XFF trust flag ---
    def test_xff_ignored_unless_proxy_trusted(self):
        ctx = dict(headers={"X-Forwarded-For": "1.2.3.4, 5.6.7.8"},
                   environ_base={"REMOTE_ADDR": "10.9.8.7"})
        with patch.object(sg_app, "TRUST_PROXY", False):
            with sg_app.app.test_request_context(**ctx):
                self.assertEqual(sg_app._client_ip(), "10.9.8.7")
        with patch.object(sg_app, "TRUST_PROXY", True):
            with sg_app.app.test_request_context(**ctx):
                self.assertEqual(sg_app._client_ip(), "5.6.7.8")

    def test_rotating_xff_mints_no_budgets_by_default(self):
        # Local mode (no trusted edge): the limiter keys on the real
        # connection address, so forged XFF values buy nothing.
        with patch.object(sg_app, "TRUST_PROXY", False):
            for i in range(sg_app.RATE_LIMIT):
                r = self.client.post(
                    "/scan", data={},
                    headers={"X-Forwarded-For": f"198.51.100.{i}"})
                self.assertEqual(r.status_code, 200)
            r = self.client.post(
                "/scan", data={},
                headers={"X-Forwarded-For": "198.51.100.99"})
            self.assertEqual(r.status_code, 429)

    # --- local launch bind ---
    def test_local_launch_binds_loopback_unless_opted_in(self):
        with open(os.path.join(ROOT, "app.py")) as fh:
            main_block = fh.read().split('if __name__', 1)[1]
        self.assertIn("127.0.0.1", main_block)
        self.assertIn("SITEGUARD_LAN", main_block)


if __name__ == "__main__":
    unittest.main()
