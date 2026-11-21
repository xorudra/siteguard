#!/usr/bin/env python3
"""The SiteGuard -> ZeroSweep funnel (owner decision 2026-11-21):
every free-scan report ends with a deep-scan box whose link carries
the scanned target and score into ZeroSweep."""
import unittest

from flask import render_template

import app as appmod


def fake_report(url="example.com", score=50):
    return {
        "url": url,
        "scanned_at": "2026-11-21 07:30 IST",
        "score": score,
        "grade": "F",
        "findings": [],
        "checks": [{"name": "HTTPS enforced", "status": "passed"}],
        "skipped": 0,
    }


class TestFunnel(unittest.TestCase):
    def render(self, report):
        with appmod.app.test_request_context("/scan"):
            return render_template(
                "report.html", r=report,
                sev_color=appmod.SEV_COLOR, sev_label=appmod.SEV_LABEL,
                grade_color=appmod.GRADE_COLOR[report["grade"]],
                poc_payload=appmod._sign_report(report),
                owasp=appmod.owasp_coverage(report))

    def test_report_links_to_zerosweep(self):
        html = self.render(fake_report())
        self.assertIn("Deep scan · Invite only", html)
        self.assertIn(
            'href="https://zerosweep.dpdns.org/">Get the deep scan', html)

    def test_no_carryover_claim(self):
        # The ZeroSweep home page stays as it was (owner, 2026-11-21):
        # nothing there reads referral params, so the report must not
        # promise the target is carried over.
        html = self.render(fake_report())
        self.assertNotIn("from=siteguard", html)
        self.assertNotIn("carried over", html)


PARTNER = "https://zerosweep.dpdns.org"


def api_report(url="example.com"):
    r = fake_report(url)
    r["complete"] = True
    r["findings"] = [{
        "severity": "high", "key": "db.public-access",
        "title": "Database readable by the public",
        "meaning": "m", "fix": "f",
    }]
    r["checks"] = [
        {"name": "HTTPS enforced", "status": "passed"},
        {"name": "Database access", "status": "failed"},
        {"name": "HSTS", "status": "skipped"},
    ]
    r["skipped"] = 1
    r["complete"] = False
    return r


class TestPartnerScanApi(unittest.TestCase):
    """The funnel scan path (2026-11-21): ZeroSweep's home page posts
    scans here cross-site. The CSRF guard names that one origin, on the
    scan endpoints only; /api/scan answers JSON for the result card."""

    def setUp(self):
        self.client = appmod.app.test_client()
        appmod._reset_rate_state()
        self._real_scan = appmod.scan
        appmod.scan = lambda url: api_report(url)

    def tearDown(self):
        appmod.scan = self._real_scan

    def test_partner_origin_may_post_scan(self):
        # The origin guard still lets the partner through; /scan itself
        # is retired (410) — the partner flow is /api/scan now.
        r = self.client.post("/scan", data={"url": "example.com"},
                             headers={"Origin": PARTNER})
        self.assertEqual(r.status_code, 410)

    def test_partner_origin_still_blocked_elsewhere(self):
        r = self.client.post("/vapt", data={"url": "example.com"},
                             headers={"Origin": PARTNER})
        self.assertEqual(r.status_code, 403)

    def test_api_scan_json_and_cors(self):
        r = self.client.post("/api/scan", data={"url": "example.com"},
                             headers={"Origin": PARTNER})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(
            r.headers.get("Access-Control-Allow-Origin"), PARTNER)
        body = r.get_json()
        self.assertEqual(body["score"], 50)
        self.assertEqual(body["grade"], "F")
        self.assertEqual(body["passed"], 1)
        self.assertEqual(body["failed"], 1)
        self.assertEqual(body["skipped"], 1)
        self.assertEqual(body["total"], 3)
        self.assertFalse(body["complete"])
        self.assertEqual(body["findings"][0]["label"], "Fix now")

    def test_api_scan_no_cors_for_other_origins(self):
        r = self.client.post("/api/scan", data={"url": "example.com"})
        self.assertEqual(r.status_code, 200)
        self.assertIsNone(r.headers.get("Access-Control-Allow-Origin"))

    def test_api_scan_evil_origin_rejected(self):
        r = self.client.post("/api/scan", data={"url": "example.com"},
                             headers={"Origin": "https://evil.example"})
        self.assertEqual(r.status_code, 403)

    def test_api_scan_empty_url(self):
        r = self.client.post("/api/scan", data={"url": ""})
        self.assertEqual(r.status_code, 400)
        self.assertIn("error", r.get_json())


if __name__ == "__main__":
    unittest.main()
