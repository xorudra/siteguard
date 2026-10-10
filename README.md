# SiteGuard — website security scanner

**Try it live:** https://siteguard-vf9c.onrender.com — enter any website,
get a safety score. No signup needed.

Enter a URL, get a safety score (0-100, grade A-F) and a list of problems
explained in simple words: what it means + how to fix it. Every finding can
be turned into a personalized Proof of Concept report — just enter your name
on the results page. Every report also maps your results against the
OWASP Top 10, honestly marking what can and can't be tested from outside.

## Roadmap
- More checks, continuously — the goal is to catch every bug a site has.

## VAPT mode (live)
A second, opt-in scan mode at the bottom of the homepage. 6 active,
non-destructive tests: reflected input, database error leaks, open
redirects, leftover backup files, risky HTTP methods, verbose error pages.
Detection only — nothing is written, deleted, or brute-forced. Requires
ticking a permission box (only test sites you own or may test), and reuses
the same SSRF guard, redirect validation, and 10 scans/hour/IP limit as the
passive scan. Implemented in `vapt.py` (`vapt_scan()`), tested in
`tests/test_vapt.py` (13 mocked tests).

## Try it on your own computer (Windows)
1. Download this repo: click the green **Code** button above, then **Download ZIP**. Unzip it anywhere.
2. Double-click **`run.bat`**. Your browser opens by itself. Done.

(If Python is missing, `run.bat` opens the Microsoft Store for you —
install Python from there, then double-click `run.bat` again.)

## Run it (terminal)
```
pip install -r requirements.txt
python app.py
```
Then open http://127.0.0.1:5050 in a browser.

## Deploy it (Render, free)
Push this folder to GitHub, then New -> Web Service on render.com pointing
at the repo. `render.yaml` sets the build/start commands automatically.

## How it works
`scanner.py` runs 39 HTTP-level checks (HTTPS, HSTS, security headers,
certificate expiry, exposed .git/.env, server version leaks, WordPress
login, cookie flags, CORS, old TLS versions, TRACE method, technology
headers, security.txt, robots.txt and more) — plus the launch-risk checks
added 2026-10-10: leaked Supabase service-role keys in page source, a
public-database (RLS) read test using only the site's own public anon key
(read-only, 1 row per table, values never stored), images missing alt
text (ADA risk), static files served with no caching headers (bandwidth
bill risk), and phone-number forms with no visible consent step (TCPA
risk, info-only). VAPT mode adds 9 active tests on top (42 total).

Launch-risk batch 2 (2026-10-10, from a second reel on getting sued over
a vibe-coded app): privacy policy page exists, terms page exists, legal
pages customised & complete (template-placeholder detection — `[Company
Name]`, `{{...}}`, lorem ipsum — plus a terms-completeness check for
billing/liability/termination/governing-law/IP clauses), privacy policy
names who receives data (processors, incl. AI providers), cookie consent
present when trackers run, and Supabase storage buckets not left public
(bucket names only, never files). Now 39 passive checks, 48 total with
VAPT. Third-party code licence provenance can't be verified from
outside a website, so it is deliberately not faked as a check. Each finding has a severity (high/medium/low/info) and a
simple explanation of what it means and how to fix it. Score starts at 100, deductions per severity.

`app.py` is a small Flask app: form on `/`, report on `/scan`.

## Safety (added for public launch)
- **SSRF guard**: only public websites can be scanned. Private IPs,
  localhost, link-local (incl. cloud metadata 169.254.169.254) are rejected,
  and every redirect hop is re-checked.
- **Rate limiting**: 10 scans/hour per IP, in-memory.
- **Security headers** on our own pages (nosniff, no framing, no referrer).
- Scan errors never leak internal details to the visitor.
