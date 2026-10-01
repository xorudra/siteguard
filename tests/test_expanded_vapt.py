#!/usr/bin/env python3
"""Mocked tests for SiteGuard's 3 new VAPT active tests (vapt.py).

No real network: vapt._check_url, vapt._safe_get and vapt.requests.get
are all faked, so every pass/fail/skipped branch runs deterministically.
"""
import unittest
from unittest.mock import patch

import vapt

HOST = "example.test"
BASE = f"https://{HOST}"


class FakeResponse:
    def __init__(self, status_code=200, text=""):
        self.status_code = status_code
        self.text = text
        self.headers = {}


def run_vapt(safe_get_hook, requests_get_hook=None):
    """Run vapt_scan() with network faked."""
    def fake_check_url(url):
        return url

    def fake_safe_get(url, *a, **k):
        return safe_get_hook(url)

    patches = [
        patch.object(vapt, "_check_url", fake_check_url),
        patch.object(vapt, "_safe_get", fake_safe_get),
    ]
    if requests_get_hook is not None:
        patches.append(patch.object(vapt.requests, "get", requests_get_hook))
    for p in patches:
        p.start()
    try:
        return vapt.vapt_scan(HOST)
    finally:
        for p in patches:
            p.stop()


def status_of(report, name):
    for c in report["checks"]:
        if c["name"] == name:
            return c["status"]
    return None


def safe_get_router(routes):
    def hook(url):
        for suffix, resp in routes.items():
            if suffix in url:
                if isinstance(resp, Exception):
                    raise resp
                return resp
        return FakeResponse(404, "<html>not found</html>")
    return hook


class TestExpandedVapt(unittest.TestCase):
    # 7. Path traversal probe
    def test_path_traversal_failed(self):
        routes = {"etc%2fpasswd": FakeResponse(200, "root:x:0:0:root:/root:/bin/bash\n")}
        report = run_vapt(safe_get_router(routes))
        self.assertEqual(status_of(report, "Path traversal probe"), "failed")

    def test_path_traversal_passed(self):
        routes = {"etc%2fpasswd": FakeResponse(200, "<html>no file here</html>")}
        report = run_vapt(safe_get_router(routes))
        self.assertEqual(status_of(report, "Path traversal probe"), "passed")

    # 8. Template injection probe (SSTI)
    def test_ssti_failed(self):
        routes = {"sgname=": FakeResponse(200, "<html>hello 49</html>")}
        report = run_vapt(safe_get_router(routes))
        self.assertEqual(status_of(report, "Template injection probe (SSTI)"), "failed")

    def test_ssti_passed_raw(self):
        # Template syntax echoed back raw (not evaluated) -> not vulnerable.
        routes = {"sgname=": FakeResponse(200, "<html>hello {{7*7}}</html>")}
        report = run_vapt(safe_get_router(routes))
        self.assertEqual(status_of(report, "Template injection probe (SSTI)"), "passed")

    def test_ssti_passed_no_reflection(self):
        routes = {"sgname=": FakeResponse(200, "<html>hello</html>")}
        report = run_vapt(safe_get_router(routes))
        self.assertEqual(status_of(report, "Template injection probe (SSTI)"), "passed")

    # 9. Host header injection
    def test_host_header_failed(self):
        def requests_get(url, headers=None, timeout=None, **kwargs):
            assert headers.get("Host") == "evil-sg-probe.com"
            return FakeResponse(200, "<html>welcome evil-sg-probe.com</html>")

        report = run_vapt(safe_get_router({}), requests_get)
        self.assertEqual(status_of(report, "Host header injection"), "failed")

    def test_host_header_passed(self):
        def requests_get(url, headers=None, timeout=None, **kwargs):
            return FakeResponse(200, "<html>welcome example.test</html>")

        report = run_vapt(safe_get_router({}), requests_get)
        self.assertEqual(status_of(report, "Host header injection"), "passed")

    # Skipped branches
    def test_path_traversal_skipped(self):
        routes = {"etc%2fpasswd": ConnectionError("mocked network failure")}
        report = run_vapt(safe_get_router(routes))
        self.assertEqual(status_of(report, "Path traversal probe"), "skipped")

    def test_ssti_skipped(self):
        routes = {"sgname=": ConnectionError("mocked network failure")}
        report = run_vapt(safe_get_router(routes))
        self.assertEqual(status_of(report, "Template injection probe (SSTI)"), "skipped")


if __name__ == "__main__":
    unittest.main()
