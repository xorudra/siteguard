#!/usr/bin/env python3
"""Mocked tests for SiteGuard's 3 new passive checks (scanner.py #26-28).

No real network: scanner._check_url and scanner._get are faked, so every
pass/fail/skipped branch runs deterministically.
"""
import unittest
from unittest.mock import patch

import scanner

HOST = "example.test"


class FakeHeaders(dict):
    pass


class FakeResponse:
    def __init__(self, status_code=200, headers=None, text=""):
        self.status_code = status_code
        self.headers = FakeHeaders(
            {k.lower(): v for k, v in (headers or {}).items()})
        self.text = text


def run_scan(routes):
    def fake_check_url(url):
        return url

    def fake_get(url):
        for suffix, resp in routes.items():
            if url.endswith(suffix):
                if isinstance(resp, Exception):
                    raise resp
                return resp
        return FakeResponse(404, text="not found")

    with patch.object(scanner, "_check_url", fake_check_url), \
         patch.object(scanner, "_get", fake_get):
        return scanner.scan(HOST)


def status_of(report, name):
    for c in report["checks"]:
        if c["name"] == name:
            return c["status"]
    return None
    def test_debug_phpinfo_failed(self):
        routes = {"/phpinfo.php": FakeResponse(200, text="PHP Version 8.1\nphpinfo() output")}
        report = run_scan(routes)
        self.assertEqual(status_of(report, "Debug page exposed (phpinfo.php)"), "failed")

    def test_debug_phpinfo_passed(self):
        routes = {"/phpinfo.php": FakeResponse(200, text="hello world")}
        report = run_scan(routes)
        self.assertEqual(status_of(report, "Debug page exposed (phpinfo.php)"), "passed")

    # 29. Server status page exposed
    def test_server_status_failed(self):
        routes = {"/server-status": FakeResponse(200, text="Apache Status Page\nserver-status info")}
        report = run_scan(routes)
        self.assertEqual(status_of(report, "Server status page exposed"), "failed")

    def test_server_status_passed(self):
        routes = {"/server-status": FakeResponse(200, text="just a page")}
        report = run_scan(routes)
    # 31. Mac junk file exposed (.DS_Store)
    def test_ds_store_failed(self):
        routes = {"/.DS_Store": FakeResponse(200, text="x" * 120)}
        report = run_scan(routes)
        self.assertEqual(status_of(report, "Mac junk file exposed (.DS_Store)"), "failed")

    def test_ds_store_passed(self):
        routes = {"/.DS_Store": FakeResponse(200, text="short")}
        report = run_scan(routes)
        self.assertEqual(status_of(report, "Mac junk file exposed (.DS_Store)"), "passed")

    # Network exception -> skipped
    def test_network_exception_skipped(self):
        routes = {"/phpinfo.php": ConnectionError("network down")}
        report = run_scan(routes)
        self.assertEqual(status_of(report, "Debug page exposed (phpinfo.php)"), "skipped")


if __name__ == "__main__":
    unittest.main()
