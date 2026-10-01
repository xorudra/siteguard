#!/usr/bin/env python3
"""Mocked tests for VAPT full-scan mode: passive scan (25 checks) + 6 active
tests merged into one report.

No real network: app.scan and app.vapt_scan are faked, so the merge logic,
score math, grade thresholds and OWASP coverage run deterministically.
"""
import unittest
from unittest.mock import patch

from app import _merge_reports
from owasp import owasp_coverage


def _mk_report(names, findings):
    return {"url": "example.test",
            "scanned_at": "2026-10-02 00:00 UTC",
            "score": 100, "grade": "A",
            "findings": findings,
            "checks": [{"name": n, "status": "passed"} for n in names]}


# Real check names, one per testable OWASP category (from owasp.CHECK_MAP).
PASSIVE_NAMES = [
    "Secure connection (HTTPS)",            # A02
    "Private code folder (.git) not public",  # A01
    "Clickjacking protection",              # A05
    "Outdated tech versions visible",       # A06
    "WordPress login page",                 # A07
] + [f"Passive filler {i}" for i in range(20)]  # 25 total

VAPT_NAMES = [
    "User input reflected in pages",        # A03
    "Database errors hidden",               # A03
    "Login/link redirects stay on your site",  # A01
    "No backup files exposed",              # A01
    "Only safe request methods enabled",    # A05
    "Error pages hide internals",           # A05
]  # 6 total


class TestMergeReports(unittest.TestCase):
    def test_check_count(self):
        r = _merge_reports(_mk_report(PASSIVE_NAMES, []),
                           _mk_report(VAPT_NAMES, []))
        self.assertEqual(len(r["checks"]), 31)
        self.assertEqual(r["mode"], "vapt")
        self.assertEqual(r["url"], "example.test")

    def test_score_and_grade(self):
        findings = [{"severity": "high"}, {"severity": "medium"}]
        r = _merge_reports(_mk_report(PASSIVE_NAMES, findings),
                           _mk_report(VAPT_NAMES, []))
        # 100 - 25 - 15 = 60 -> D on passive thresholds (D >= 60)
        self.assertEqual(r["score"], 60)
        self.assertEqual(r["grade"], "D")

    def test_score_floors_at_zero(self):
        findings = [{"severity": "high"}] * 10
        r = _merge_reports(_mk_report(PASSIVE_NAMES, findings),
                           _mk_report(VAPT_NAMES, []))
        self.assertEqual(r["score"], 0)
        self.assertEqual(r["grade"], "F")

    def test_findings_sorted_by_severity(self):
        findings = [{"severity": "info"}, {"severity": "high"},
                    {"severity": "low"}, {"severity": "medium"}]
        r = _merge_reports(_mk_report(PASSIVE_NAMES, []),
                           _mk_report(VAPT_NAMES, findings))
        self.assertEqual([f["severity"] for f in r["findings"]],
                         ["high", "medium", "low", "info"])

    def test_owasp_no_not_in_scan(self):
        r = _merge_reports(_mk_report(PASSIVE_NAMES, []),
                           _mk_report(VAPT_NAMES, []))
        rows = {row["id"]: row["status"] for row in owasp_coverage(r)}
        for cat in ("A01", "A02", "A03", "A05", "A06", "A07"):
            self.assertEqual(rows[cat], "covered", cat)
        for cat in ("A04", "A08", "A09", "A10"):
            self.assertEqual(rows[cat], "not-testable", cat)
        self.assertNotIn("not-in-scan", rows.values())


class TestVaptRouteWiring(unittest.TestCase):
    def test_do_vapt_runs_both_scans(self):
        import app as appmod
        passive = _mk_report(PASSIVE_NAMES, [{"severity": "low"}])
        active = _mk_report(VAPT_NAMES, [{"severity": "medium"}])
        with patch.object(appmod, "scan", return_value=passive), \
             patch.object(appmod, "vapt_scan", return_value=active):
            client = appmod.app.test_client()
            resp = client.post("/vapt", data={"url": "example.test",
                                              "consent": "on"})
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)
        self.assertIn("See all 31 checks", html)
        # 100 - 5 - 15 = 80 -> B
        self.assertIn("full scan: 25 passive checks + 6 active", html)

    def test_do_vapt_requires_consent(self):
        import app as appmod
        client = appmod.app.test_client()
        resp = client.post("/vapt", data={"url": "example.test"})
        self.assertEqual(resp.status_code, 200)
        self.assertIn("permission box", resp.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
