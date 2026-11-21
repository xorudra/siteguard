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
        self.assertIn("Want the deep scan?", html)
        self.assertIn(
            'href="https://zerosweep.dpdns.org/">Get the deep scan', html)

    def test_no_carryover_claim(self):
        # The ZeroSweep home page stays as it was (owner, 2026-11-21):
        # nothing there reads referral params, so the report must not
        # promise the target is carried over.
        html = self.render(fake_report())
        self.assertNotIn("from=siteguard", html)
        self.assertNotIn("carried over", html)


if __name__ == "__main__":
    unittest.main()
