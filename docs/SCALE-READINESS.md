# Scale readiness (Launch Safety Standard G35)

Recorded 2026-10-11. SiteGuard is a scanner, not a data product —
this shapes every answer below.

## Stateless?

**Yes.** The app keeps no session and no file state that matters:

- Scan reports are never stored server-side. The report travels to
  the browser as a *signed* payload (itsdangerous, keyed by
  `SECRET_KEY`) and comes back with the PoC form — any worker on any
  instance can verify it. This is why `SECRET_KEY` is a stable
  generated env var in `render.yaml`: without it, each worker would
  sign with its own random key and PoC requests would fail randomly
  across workers.
- The per-IP scan rate limiter (`app.py: _hits`) keeps its hit
  timestamps in one small flock-guarded state file shared by every
  worker on the host, so the documented 10 scans/hour/IP is a flat
  service-wide limit, not 10 x workers (owner ruling 2026-10-17).
  It is a safety control, not user state: losing the file just
  resets the hour window.

## Database / connection pooler

**Not applicable — there is no database.** No SQL store, no ORM, no
connection pool. Scans run in memory against the target site and the
result is rendered and discarded. (G32 indexes: likewise N/A.)

## Current plan limits (known, written down)

- Render **free** web service (`render.yaml: plan: free`): 512 MB
  RAM, shared CPU, spins down after ~15 min idle (cold start on the
  next visit), monthly free instance-hours/bandwidth shared across
  the account's free services.
- App-level: gunicorn **2 sync workers**, 120 s timeout. Scans are
  capped at 10/hour per IP; scanner response bodies are read under a
  hard 5 MB cap (C21).

## What breaks first at 10x traffic

1. **Scan concurrency.** Each scan holds a sync worker for its whole
   duration (seconds to ~30 s for a slow target). With 2 workers,
   2 concurrent scans queue every other request behind them. The
   10/hour/IP limiter keeps *abuse* out, but a genuine crowd of
   distinct IPs scanning at once is the first real ceiling.
   Fix when it matters: more workers/instances, or move scans to a
   queue + background worker. Not before — free tier, no crowd yet.
2. **Rate-limiter accuracy.** Per-worker in-memory buckets make the
   effective limit 10 × worker-count per IP, and a restart or
   spin-down resets the window. Acceptable for an anti-abuse control;
   a shared store (Redis) is the upgrade if it ever needs to be exact.
3. **Free-tier sleep.** A viral link landing on a spun-down service
   pays one ~30–50 s cold start, then the instance stays warm while
   traffic continues. Mitigated socially by the UptimeRobot
   keep-alive already in place.
4. **Outbound fetch load.** Every scan makes a few dozen small
   requests to the *target* — our bandwidth stays trivial (the whole
   4,262-request load test moved ~42 MB, almost all of it page HTML).

Load-test evidence: `loadtest/README.md`.
