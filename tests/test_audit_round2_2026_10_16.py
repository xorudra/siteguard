#!/usr/bin/env python3
"""Regression tests for the 2026-10-16 run-2 audit fixes (second round).

Each test answers one surviving needs_validation lead from
security-audits-2026-10-16/siteguard/run-2 with a bounded, no-network
check:

- the scan deadline was one process-global shared by concurrent scans
  (now thread-local), and /vapt stacked two independent 90s budgets
  (now one shared per-request budget via vapt_scan's deadline cap).
- partially-tested scans rendered as perfect "Final" reports (reports
  now carry skipped/complete; verdict, stats, OWASP table, PoC page
  and PDF disclose incompleteness; OWASP "covered" requires a check
  that actually ran).
- the local-mode CSRF guard compared two attacker-controlled values
  under DNS rebinding (no-edge mode now requires a local Host).
- run.bat installed unpinned packages (now -r requirements.txt);
  requirements.txt floated transitives (now the full closure is
  pinned); render.yaml omitted SITEGUARD_TRUST_PROXY (now set).
"""
import os
import socket
import threading
import time
import unittest
import zlib
from unittest.mock import patch

import scanner
import vapt
from owasp import owasp_coverage

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PUBLIC_IP = "93.184.216.34"


def _public_gai(host, port, *a, **k):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (PUBLIC_IP, port))]


class TestThreadLocalDeadline(unittest.TestCase):
    def tearDown(self):
        scanner._disarm_deadline()

    def test_deadline_is_confined_to_the_arming_thread(self):
        scanner._arm_deadline(until=time.monotonic() - 1)  # expired here
        with self.assertRaises(scanner._DeadlineExceeded):
            scanner._check_deadline()
        errors = []

        def other_thread():
            try:
                scanner._check_deadline()
            except Exception as e:  # noqa: BLE001 - recorded for assert
                errors.append(e)

        t = threading.Thread(target=other_thread)
        t.start()
        t.join()
        self.assertEqual(errors, [])

    def test_arm_until_caps_the_budget(self):
        cap = time.monotonic() + 5
        scanner._arm_deadline(until=cap)
        self.assertLessEqual(scanner._scan_state.deadline, cap)
        self.assertGreater(scanner._scan_state.deadline,
                           time.monotonic())

    def test_vapt_scan_honours_a_shared_past_deadline(self):
        # An already-expired shared budget (as do_vapt passes when the
        # passive phase consumed it) degrades every probe to skipped
        # instead of arming a fresh 90s.
        with patch.object(scanner.socket, "getaddrinfo", _public_gai):
            r = vapt.vapt_scan("good.test",
                               deadline=time.monotonic() - 1)
        self.assertGreater(r["skipped"], 0)
        self.assertFalse(r["complete"])


class TestCompletenessFields(unittest.TestCase):
    def _report(self, checks):
        return {"url": "x.test", "scanned_at": "2026-10-16 00:00 UTC",
                "score": 100, "grade": "A", "findings": [],
                "checks": checks}

    def test_owasp_all_skipped_category_is_not_tested(self):
        rows = owasp_coverage(self._report(
            [{"name": "Security certificate valid", "status": "skipped"}]))
        a02 = [r for r in rows if r["id"] == "A02"][0]
        self.assertEqual(a02["status"], "not-tested")

    def test_owasp_mixed_category_is_covered(self):
        rows = owasp_coverage(self._report([
            {"name": "Security certificate valid", "status": "skipped"},
            {"name": "Secure connection (HTTPS)", "status": "passed"}]))
        a02 = [r for r in rows if r["id"] == "A02"][0]
        self.assertEqual(a02["status"], "covered")


class TestSupplyChainFiles(unittest.TestCase):
    def test_transitive_closure_is_pinned(self):
        with open(os.path.join(ROOT, "requirements.txt")) as fh:
            text = fh.read()
        for pkg in ("Werkzeug==", "Jinja2==", "MarkupSafe==",
                    "itsdangerous==", "click==", "blinker==",
                    "urllib3==", "certifi==", "idna==",
                    "charset-normalizer==", "pillow==", "fonttools==",
                    "defusedxml=="):
            self.assertIn(pkg, text)

    def test_run_bat_installs_from_requirements(self):
        with open(os.path.join(ROOT, "run.bat")) as fh:
            text = fh.read()
        self.assertIn("-r requirements.txt", text)
        self.assertNotIn("install --quiet flask requests", text)

    def test_render_yaml_sets_trust_proxy(self):
        with open(os.path.join(ROOT, "render.yaml")) as fh:
            text = fh.read()
        self.assertIn("SITEGUARD_TRUST_PROXY", text)


try:
    import app as sg_app
    _HAVE_APP = True
except Exception:  # Flask not installed in this environment
    sg_app = None
    _HAVE_APP = False


def _partial_report():
    return {"url": "victim.test",
            "scanned_at": "2026-10-16 00:00 UTC",
            "score": 95, "grade": "A",
            "findings": [{"key": "https-not-enforced", "severity": "low",
                          "title": "HTTPS not enforced",
                          "what_it_means": "x", "how_to_fix": "y"}],
            "checks": [
                {"name": "Security certificate valid", "status": "passed"},
                {"name": "Exposed .git directory", "status": "skipped"},
                {"name": "Exposed .env file", "status": "skipped"}],
            "skipped": 2, "complete": False}


@unittest.skipUnless(_HAVE_APP, "Flask not installed in this environment")
class TestReportHonesty(unittest.TestCase):
    def setUp(self):
        sg_app._hits.clear()
        self.client = sg_app.app.test_client()
        self._saved_trust = sg_app.TRUST_PROXY
        sg_app.TRUST_PROXY = False

    def tearDown(self):
        sg_app._hits.clear()
        sg_app.TRUST_PROXY = self._saved_trust

    def test_merge_reports_carries_completeness(self):
        passive = {"url": "x.test", "scanned_at": "t", "findings": [],
                   "checks": [{"name": "a", "status": "passed"},
                              {"name": "b", "status": "skipped"}]}
        active = {"findings": [],
                  "checks": [{"name": "c", "status": "passed"}]}
        merged = sg_app._merge_reports(passive, active)
        self.assertEqual(merged["skipped"], 1)
        self.assertFalse(merged["complete"])

    def test_report_page_discloses_partial_scan(self):
        with patch.object(sg_app, "scan",
                          return_value=_partial_report()):
            r = self.client.post("/scan", data={"url": "victim.test"})
        html = r.get_data(as_text=True)
        self.assertIn("partial scan", html)
        self.assertIn("Skipped", html)
        self.assertNotIn("passed every check", html)
        self.assertIn("(skipped)", html)

    def test_poc_page_marks_partial(self):
        payload = sg_app._sign_report(_partial_report())
        r = self.client.post("/poc", data={"payload": payload,
                                           "name": "Rudra"})
        html = r.get_data(as_text=True)
        self.assertIn("Final (partial scan)", html)
        self.assertIn("Partial scan:", html)

    # --- run-3 confirmed residual: the grade element itself ---
    def test_grade_elements_carry_the_partial_qualifier(self):
        with patch.object(sg_app, "scan",
                          return_value=_partial_report()):
            r = self.client.post("/scan", data={"url": "victim.test"})
        html = r.get_data(as_text=True)
        # The ring's accessible name and visible caption are qualified.
        self.assertIn("partial scan, 2 checks skipped", html)
        self.assertIn('<div class="gp">partial</div>', html)
        # The PoC cover's grade line is qualified too.
        payload = sg_app._sign_report(_partial_report())
        r = self.client.post("/poc", data={"payload": payload,
                                           "name": "Rudra"})
        self.assertIn("&middot; partial scan",
                      r.get_data(as_text=True))

    def test_grade_elements_unqualified_when_complete(self):
        report = _partial_report()
        report["skipped"] = 0
        report["complete"] = True
        report["checks"] = [
            {"name": "Security certificate valid", "status": "passed"}]
        with patch.object(sg_app, "scan", return_value=report):
            r = self.client.post("/scan", data={"url": "victim.test"})
        html = r.get_data(as_text=True)
        self.assertNotIn("partial scan", html)
        self.assertNotIn('class="gp"', html)

    def test_poc_pdf_marks_partial(self):
        report = _partial_report()
        data = sg_app._build_poc_pdf(report, "Rudra",
                                     sg_app._poc_details(report))
        text = data.decode("latin-1", "replace")
        # fpdf compresses its streams; inflate any that decode.
        import re
        for m in re.finditer(rb"stream\r?\n(.*?)endstream", data, re.S):
            try:
                text += zlib.decompress(m.group(1)).decode(
                    "latin-1", "replace")
            except Exception:
                pass
        self.assertIn("partial scan", text)

    def test_old_payload_backfills_completeness(self):
        report = _partial_report()
        del report["skipped"], report["complete"]
        payload = sg_app._sign_report(report)
        loaded = sg_app._load_report(payload)
        self.assertEqual(loaded["skipped"], 2)
        self.assertFalse(loaded["complete"])

    # --- local-mode Host gate (DNS-rebinding shape) ---
    def test_rebinding_host_is_rejected_in_no_edge_mode(self):
        r = self.client.post("/scan", data={"url": "example.com"},
                             headers={"Host": "attacker.example:5050"})
        self.assertEqual(r.status_code, 403)

    def test_ip_literal_and_localhost_hosts_are_allowed(self):
        for host in ("127.0.0.1:5050", "localhost:5050", "[::1]:5050"):
            r = self.client.post("/scan", data={"url": ""},
                                 headers={"Host": host})
            self.assertNotEqual(r.status_code, 403, host)


if __name__ == "__main__":
    unittest.main()
