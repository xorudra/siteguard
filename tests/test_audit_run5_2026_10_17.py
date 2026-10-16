#!/usr/bin/env python3
"""Regression tests for the 2026-10-17 run-5 measurement fixes.

Run-5 performed the two bounded measurements the earlier runs had
left as needs_validation blockers (loopback mock targets only):

- Header-phase deadline: a target dripping response headers at
  9 s/byte held _pinned_once for 162 s against the armed 90 s scan
  deadline — past the 120 s gunicorn worker kill — because the
  deadline was consulted only before the fetch and between body
  chunks, never during connect/getresponse. The fetch socket is now
  wrapped (_DeadlineSocket): every recv re-checks the deadline and
  runs with a timeout shrunk to the remaining budget.
- Worker starvation: two concurrent slow /vapt scans held both sync
  workers for ~103 s each and an unrelated GET / waited 98 s. Scan
  routes now take a cross-process slot (_ScanGate, flock files) with
  a default of one concurrent scan service-wide, so a worker always
  stays free for pages; a scan that cannot get a slot gets an honest
  429 + Retry-After instead of queueing invisibly.
"""
import os
import socket
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

import scanner

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def _resolve_loopback(host):
    # Validation sees the address the harness pins to; the pinned
    # transport then dials it — the loopback fixture server.
    import ipaddress
    return [ipaddress.ip_address("127.0.0.1")]


class _FixtureHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path.startswith("/drip"):
            raw = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n"
            try:
                for byte in raw:
                    self.connection.sendall(bytes([byte]))
                    time.sleep(0.3)
                self.connection.sendall(b"ok")
            except (BrokenPipeError, ConnectionResetError):
                pass
        else:
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
        self.close_connection = True


try:
    _server = ThreadingHTTPServer(("127.0.0.1", 80), _FixtureHandler)
    _server_thread = threading.Thread(target=_server.serve_forever,
                                      daemon=True)
    _server_thread.start()
    _HAVE_SERVER = True
except OSError:
    _server = None
    _HAVE_SERVER = False


def tearDownModule():
    if _server is not None:
        _server.shutdown()
        _server.server_close()


@unittest.skipUnless(_HAVE_SERVER, "cannot bind loopback port 80")
class TestHeaderPhaseDeadline(unittest.TestCase):
    def test_header_drip_is_stopped_at_the_deadline(self):
        with patch.object(scanner, "_resolve_public", _resolve_loopback), \
                patch.object(scanner, "SCAN_DEADLINE", 2):
            scanner._arm_deadline()
            t0 = time.monotonic()
            try:
                with self.assertRaises(scanner._DeadlineExceeded):
                    scanner._pinned_once("GET", "http://drip.test/drip")
            finally:
                elapsed = time.monotonic() - t0
                scanner._disarm_deadline()
        # Unfixed, the drip runs ~11 s (38 header bytes x 0.3 s); the
        # deadline must cut it at ~2 s.
        self.assertGreaterEqual(elapsed, 1.8)
        self.assertLess(elapsed, 6)

    def test_fast_fetch_still_completes_under_deadline(self):
        with patch.object(scanner, "_resolve_public", _resolve_loopback):
            scanner._arm_deadline()
            try:
                resp = scanner._pinned_once("GET", "http://drip.test/fast")
            finally:
                scanner._disarm_deadline()
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.content, b"ok")


try:
    import app as sg_app
    _HAVE_APP = True
except Exception:  # Flask not installed in this environment
    sg_app = None
    _HAVE_APP = False


@unittest.skipUnless(_HAVE_APP, "Flask not installed in this environment")
class TestScanGate(unittest.TestCase):
    def setUp(self):
        sg_app._hits.clear()
        self.client = sg_app.app.test_client()

    def tearDown(self):
        sg_app._hits.clear()

    def test_gate_hands_out_bounded_slots(self):
        gate = sg_app._ScanGate(1)
        token = gate.acquire()
        self.assertIsNotNone(token)
        self.assertIsNone(gate.acquire())
        gate.release(token)
        token2 = gate.acquire()
        self.assertIsNotNone(token2)
        gate.release(token2)

    def test_scan_route_is_busy_when_all_slots_held(self):
        token = sg_app._scan_gate.acquire()
        self.assertIsNotNone(token)
        try:
            r = self.client.post("/scan", data={"url": "http://x.test/"})
        finally:
            sg_app._scan_gate.release(token)
        self.assertEqual(r.status_code, 429)
        self.assertIn(b"busy", r.data)
        self.assertEqual(r.headers.get("Retry-After"), "30")

    def test_scan_route_not_busy_when_slot_free(self):
        def _boom(host, port, **kw):
            raise socket.gaierror("no dns in tests")
        with patch.object(scanner.socket, "getaddrinfo", _boom):
            r = self.client.post("/scan", data={"url": "http://x.test/"})
        self.assertEqual(r.status_code, 200)
        self.assertNotIn(b"scanner is busy", r.data)


if __name__ == "__main__":
    unittest.main()
