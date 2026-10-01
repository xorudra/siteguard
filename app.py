#!/usr/bin/env python3
"""SiteGuard web app — enter a URL, get a website security report."""
import os
import secrets
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, render_template, request
from itsdangerous import BadSignature, URLSafeSerializer
from scanner import scan, UnsafeTarget

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
_poc_signer = URLSafeSerializer(app.secret_key, salt="siteguard-poc")

SEV_COLOR = {"high": "#d33", "medium": "#e80", "low": "#2a7", "info": "#68c"}
SEV_LABEL = {"high": "Fix now", "medium": "Should fix",
             "low": "Nice to fix", "info": "Just so you know"}
GRADE_COLOR = {"A": "#22a06b", "B": "#65a30d", "C": "#ca8a04",
               "D": "#ea580c", "F": "#dc2626"}

# --- PoC payload: the scan report is signed into a hidden form field, so /poc
# works no matter which gunicorn worker handles the POST (no shared memory).
def _sign_report(report):
    return _poc_signer.dumps(report)


def _load_report(payload):
    try:
        report = _poc_signer.loads(payload)
    except BadSignature:
        return None
    if not isinstance(report, dict):
        return None
    for key in ("url", "score", "grade", "findings", "checks", "scanned_at"):
        if key not in report:
            return None
    if not isinstance(report["findings"], list):
        return None
    return report


# --- PoC details per finding key: impact, reproduction steps, observed evidence.
# Pure static data — generating a PoC needs no AI and no tokens. TARGET in
# repro steps is replaced with the scanned host.
POC_DETAILS = {
    "https": {
        "impact": "Without HTTPS, everything visitors type — passwords, card "
                  "numbers, messages — travels as readable text. Anyone on the "
                  "same network (cafe WiFi, office network) can read or change it.",
        "repro": ["Open https://TARGET in a browser — the connection fails or "
                  "the address bar shows 'Not secure' instead of a padlock."],
        "evidence": "The scanner could not establish an HTTPS connection to the site.",
    },
    "http-redirect": {
        "impact": "Visitors who type the address without https:// land on an "
                  "unprotected page. An attacker on the network can intercept "
                  "that first request and steal logins (SSL stripping).",
        "repro": ["Run: curl -sI http://TARGET",
                  "A safe site answers 301/302 redirecting to https://. "
                  "This one served a normal page over plain HTTP."],
        "evidence": "A plain-HTTP request did not redirect to HTTPS.",
    },
    "hsts": {
        "impact": "Without this rule, a first-time visitor can be silently "
                  "downgraded to the insecure version of the site by an attacker "
                  "on the network — even though HTTPS exists.",
        "repro": ["Run: curl -sI https://TARGET | grep -i strict-transport-security",
                  "No output means the header is missing."],
        "evidence": "Response headers did not include Strict-Transport-Security.",
    },
    "clickjacking": {
        "impact": "Other sites can embed this site invisibly in a frame and trick "
                  "visitors into clicking buttons they cannot see (for example, "
                  "'Delete account').",
        "repro": ["Run: curl -sI https://TARGET | grep -iE 'x-frame-options|content-security-policy'",
                  "No output means there is no framing protection.",
                  "Demo: putting <iframe src='https://TARGET'></iframe> on any "
                  "page loads this site inside it."],
        "evidence": "The response had neither X-Frame-Options nor a "
                    "Content-Security-Policy framing rule.",
    },
    "csp": {
        "impact": "If an attacker ever manages to inject a script into a page "
                  "(through a comment box, for example), nothing stops it from "
                  "running and stealing visitor data.",
        "repro": ["Run: curl -sI https://TARGET | grep -i content-security-policy",
                  "No output means the header is missing."],
        "evidence": "Response headers did not include Content-Security-Policy.",
    },
    "server-version": {
        "impact": "The exact server version is public. Attackers search for known "
                  "holes in that exact version instead of guessing.",
        "repro": ["Run: curl -sI https://TARGET | grep -i '^server:'",
                  "The version number is printed in the response."],
        "evidence": "The Server response header exposed a version number.",
    },
    "x-powered-by": {
        "impact": "Reveals the exact technology stack, giving attackers a head "
                  "start on which exploits to try.",
        "repro": ["Run: curl -sI https://TARGET | grep -i x-powered-by"],
        "evidence": "The X-Powered-By header was present in the response.",
    },
    "cert-expired": {
        "impact": "Browsers show a full-page security warning. Most visitors "
                  "leave immediately and never come back.",
        "repro": ["Run: echo | openssl s_client -connect TARGET:443 2>/dev/null "
                  "| openssl x509 -noout -dates",
                  "The 'notAfter' date is in the past."],
        "evidence": "The TLS certificate's expiry date has passed.",
    },
    "cert-expiring": {
        "impact": "When it lapses, browsers will block visitors with a security "
                  "warning until it is renewed.",
        "repro": ["Run: echo | openssl s_client -connect TARGET:443 2>/dev/null "
                  "| openssl x509 -noout -dates",
                  "The 'notAfter' date is within 30 days."],
        "evidence": "The TLS certificate expires within 30 days.",
    },
    "git": {
        "impact": "Anyone can download the site's private source code — often "
                  "containing passwords and API keys developers left inside.",
        "repro": ["Run: curl -s https://TARGET/.git/HEAD",
                  "If it prints 'ref: refs/heads/...', the code folder is public."],
        "evidence": "/.git/HEAD was publicly readable and contained a git ref.",
    },
    "env": {
        "impact": "Database passwords, API keys and app secrets are readable by "
                  "anyone — a full compromise of every connected service.",
        "repro": ["Run: curl -s https://TARGET/.env",
                  "If it prints values like DB_PASSWORD or SECRET, they are exposed."],
        "evidence": "/.env was publicly readable and contained secret-looking values.",
    },
    "wp-login": {
        "impact": "Not a vulnerability by itself — but it tells attackers exactly "
                  "where to try stolen passwords and bot attacks.",
        "repro": ["Open https://TARGET/wp-login.php in a browser — the login form loads."],
        "evidence": "/wp-login.php returned HTTP 200.",
    },
}

# --- simple in-memory rate limiting: 10 scans / hour per IP ---
RATE_LIMIT = 10
RATE_WINDOW = 3600
_hits = {}


def _rate_ok(ip):
    now = time.time()
    recent = [t for t in _hits.get(ip, []) if now - t < RATE_WINDOW]
    if len(recent) >= RATE_LIMIT:
        _hits[ip] = recent
        return False
    recent.append(now)
    _hits[ip] = recent
    return True


@app.after_request
def _security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    # HSTS: tell browsers to only ever use HTTPS for this site (1 year).
    resp.headers["Strict-Transport-Security"] = \
        "max-age=31536000; includeSubDomains"
    # CSP: our pages use only same-origin + inline styles/scripts, nothing
    # external — lock everything else down.
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "form-action 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'"
    )
    return resp


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def do_scan():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "?")
    ip = ip.split(",")[0].strip()
    if not _rate_ok(ip):
        return render_template(
            "index.html",
            error="Too many scans from you lately — please wait a bit and try again."), 429

    url = (request.form.get("url") or "").strip()
    if not url:
        return render_template("index.html",
                               error="Please enter a website address.")
    if len(url) > 253:
        return render_template("index.html",
                               error="That address looks too long to be real.")

    try:
        report = scan(url)
    except UnsafeTarget as e:
        return render_template("index.html", error=str(e))
    except Exception:
        return render_template(
            "index.html",
            error="Could not scan that site — check the address and try again.")
    return render_template("report.html", r=report,
                           sev_color=SEV_COLOR, sev_label=SEV_LABEL,
                           grade_color=GRADE_COLOR[report["grade"]],
                           poc_payload=_sign_report(report))


@app.route("/poc", methods=["POST"])
def make_poc():
    name = (request.form.get("name") or "").strip()[:80]
    report = _load_report(request.form.get("payload", ""))

    def _report_page(r, payload, poc_error=None):
        return render_template("report.html", r=r,
                               sev_color=SEV_COLOR, sev_label=SEV_LABEL,
                               grade_color=GRADE_COLOR[r["grade"]],
                               poc_payload=payload, poc_error=poc_error)

    if not report:
        return render_template(
            "index.html",
            error="That report expired or was changed — please scan the site again.")
    payload = request.form.get("payload", "")
    if not name:
        return _report_page(report, payload,
                            "Please enter your name for the PoC report.")
    if not report["findings"]:
        return _report_page(report, payload)

    details = []
    for f in report["findings"]:
        d = POC_DETAILS.get(f.get("key", ""), {})
        host = report["url"]
        details.append({
            "finding": f,
            "impact": d.get("impact", ""),
            "repro": [s.replace("TARGET", host) for s in d.get("repro", [])],
            "evidence": d.get("evidence", ""),
        })
    return render_template("poc.html", r=report, name=name, details=details,
                           sev_color=SEV_COLOR, sev_label=SEV_LABEL)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5050))
    app.run(host="0.0.0.0", port=port)
