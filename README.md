# SiteGuard — plain-English website security scanner

Enter a URL, get a safety score (0-100, grade A-F) and a list of problems
explained in simple words: what it means + how to fix it.

## Try it on your own computer (Windows, no tech skills needed)
1. Download this repo: click the green **Code** button above, then **Download ZIP**. Unzip it anywhere.
2. Double-click **`run.bat`**.
3. Open **http://localhost:5050** in your browser. Done.

(If it says Python is missing, install it free from [python.org](https://www.python.org/downloads/) —
tick **"Add python.exe to PATH"** during install — then double-click `run.bat` again.)

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
`scanner.py` runs 11 HTTP-level checks (HTTPS, HSTS, security headers,
certificate expiry, exposed .git/.env, server version leaks, WordPress
login). Each finding has a severity (high/medium/low/info) and a
plain-English explanation. Score starts at 100, deductions per severity.

`app.py` is a small Flask app: form on `/`, report on `/scan`.

## Safety (added for public launch)
- **SSRF guard**: only public websites can be scanned. Private IPs,
  localhost, link-local (incl. cloud metadata 169.254.169.254) are rejected,
  and every redirect hop is re-checked.
- **Rate limiting**: 10 scans/hour per IP, in-memory.
- **Security headers** on our own pages (nosniff, no framing, no referrer).
- Scan errors never leak internal details to the visitor.

## Business model (current decision: NO subscriptions for now)
Plan was one-time paid reports (~Rs.499). Payment wiring (Razorpay) comes
later, only if the product proves worthy. See NEEDS_FROM_RUDRA.md.
