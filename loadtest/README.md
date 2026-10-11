# Load testing (Launch Safety Standard G34)

Script: `siteguard-load.js` (k6). **Local or staging only — never
production.**

```bash
# boot the app the way render.yaml does
gunicorn app:app --bind 127.0.0.1:5050 --workers 2 --timeout 120
k6 run loadtest/siteguard-load.js

# or against staging
BASE_URL=https://siteguard-staging.onrender.com k6 run loadtest/siteguard-load.js
```

## Profile

| Scenario | Shape | What it hits |
|---|---|---|
| `pages` | ramp 0 → 25 → 50 VUs, hold, down (~2 min) | GET `/`, `/privacy`, `/terms`, `/favicon.svg` |
| `scan_probe` | 1 VU for 2 min | POST `/scan` for example.com |

Thresholds: page failures < 1%, page p95 < 800 ms, scan real-error
rate < 5%. HTTP 429 from `/scan` counts as an *expected* response —
it is the rate limiter working, not an error.

The scan endpoint is deliberately **not** bulk-tested: it is limited
to 10 scans/hour per IP by design (C21 anti-runaway control), so bulk
scan traffic would measure the limiter, not the app.

## Results — 2026-10-11, local instance (gunicorn, 2 workers, this VM)

Raw summary: `results-2026-10-11.json`. Two runs were made; the
first exposed the limiter behaviour, the second (identical profile,
429 counted as expected) passed every threshold.

- Pages: **4,202 requests, 0 failures**, avg 8 ms, **p95 30 ms**,
  max 135 ms at 50 VUs. The public pages are nowhere near a breaking
  point at this scale.
- Scan probe: 60 POSTs in 2 min. The first **20 succeeded** and the
  remaining **40 were answered 429** — exactly the designed limit
  (10/hour/IP × 2 gunicorn workers, each holding its own in-memory
  limiter). Page traffic was completely unaffected while scans were
  being throttled (0 page failures in both runs).
- **What breaks first:** the scan rate limiter — by design, and it
  degrades politely (fast 429 + a friendly page) instead of letting
  scan load hurt the public pages. The next ceiling after that is
  worker concurrency: see `docs/SCALE-READINESS.md`.
