#!/usr/bin/env python3
"""Regression tests for the 2026-10-17 owner ruling: the scan rate
limit is a TRUE flat 10/hour/IP service-wide.

Before this fix, hit counts lived in one in-process dict per gunicorn
worker, so the effective limit was 10 x workers (~30 with the current
3-worker production shape) while the docs promised 10. Counts now
sync through one flock-guarded state file (app._RATE_STATE_FILE), so
every worker process on the host counts together — the same pattern
_ScanGate already uses for scan slots.

The cross-process test drives the limiter from a real child process
pointed at one state file: 6 hits there + 4 here are allowed, the
11th combined hit is refused. A parent-process memory cannot produce
that result — only the shared file can. The fallback test proves the
limiter degrades to in-process counting (same limit) when the state
file cannot be opened, instead of failing requests.
"""
import ast
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

try:
    import app as sg_app
    _HAVE_APP = True
except Exception:  # Flask not installed in this environment
    sg_app = None
    _HAVE_APP = False

_CHILD = (
    "import sys; sys.path.insert(0, {root!r});"
    "import app;"
    "print([app._rate_ok('203.0.113.7') for _ in range(6)])"
)


@unittest.skipUnless(_HAVE_APP, "Flask not installed in this environment")
@unittest.skipUnless(_HAVE_APP and sg_app.fcntl is not None,
                     "shared state file needs fcntl (POSIX)")
class TestSharedRateLimit(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.state = os.path.join(self._tmp.name, "rate-hits.json")
        self._patch = patch.object(sg_app, "_RATE_STATE_FILE", self.state)
        self._patch.start()
        sg_app._hits.clear()

    def tearDown(self):
        sg_app._hits.clear()
        self._patch.stop()
        self._tmp.cleanup()

    def test_two_processes_count_together(self):
        env = dict(os.environ, SITEGUARD_RATE_STATE_FILE=self.state)
        out = subprocess.run(
            [sys.executable, "-c", _CHILD.format(root=ROOT)],
            capture_output=True, text=True, env=env, cwd=ROOT,
            timeout=120)
        self.assertEqual(out.returncode, 0, out.stderr)
        child = ast.literal_eval(out.stdout.strip().splitlines()[-1])
        self.assertEqual(child, [True] * 6)
        # This process's own memory starts empty (simulate a second
        # worker): dict.clear bypasses _Hits.clear's file reset, so
        # only the shared file can carry the child's 6 hits.
        dict.clear(sg_app._hits)
        mine = [sg_app._rate_ok("203.0.113.7") for _ in range(4)]
        self.assertEqual(mine, [True] * 4)
        # 6 (child) + 4 (here) = 10 allowed; the 11th combined hit
        # must be refused even though THIS process only made 5.
        self.assertFalse(sg_app._rate_ok("203.0.113.7"))

    def test_state_file_records_all_workers_hits(self):
        for _ in range(3):
            self.assertTrue(sg_app._rate_ok("198.51.100.23"))
        with open(self.state) as fh:
            state = json.load(fh)
        self.assertEqual(len(state["198.51.100.23"]), 3)


@unittest.skipUnless(_HAVE_APP, "Flask not installed in this environment")
class TestRateLimitFallback(unittest.TestCase):
    def setUp(self):
        self._patch = patch.object(
            sg_app, "_RATE_STATE_FILE",
            os.path.join(tempfile.gettempdir(),
                         "siteguard-no-such-dir", "rate-hits.json"))
        self._patch.start()
        sg_app._hits.clear()

    def tearDown(self):
        sg_app._hits.clear()
        self._patch.stop()

    def test_unusable_state_file_degrades_to_in_process(self):
        # os.open on a path in a missing directory raises OSError;
        # the limiter must keep working (in-process) at the same cap.
        for _ in range(sg_app.RATE_LIMIT):
            self.assertTrue(sg_app._rate_ok("192.0.2.9"))
        self.assertFalse(sg_app._rate_ok("192.0.2.9"))


if __name__ == "__main__":
    unittest.main()
