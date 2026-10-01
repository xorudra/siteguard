#!/usr/bin/env python3
"""SiteGuard web app — enter a URL, get a website security report."""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, render_template, request
from scanner import scan, UnsafeTarget

app = Flask(__name__)

SEV_COLOR = {"high": "#d33", "medium": "#e80", "low": "#2a7", "info": "#68c"}
SEV_LABEL = {"high": "Fix now", "medium": "Should fix",
             "low": "Nice to fix", "info": "Just so you know"}
GRADE_COLOR = {"A": "#22a06b", "B": "#65a30d", "C": "#ca8a04",
               "D": "#ea580c", "F": "#dc2626"}

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
                           grade_color=GRADE_COLOR[report["grade"]])


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5050))
    app.run(host="0.0.0.0", port=port)
