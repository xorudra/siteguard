#!/usr/bin/env python3
"""SiteGuard web app — enter a URL, get a website security report."""
import os
import secrets
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, Response, render_template, request
from itsdangerous import BadSignature, URLSafeSerializer
from scanner import DEDUCT, scan, UnsafeTarget
from vapt import vapt_scan
from owasp import owasp_coverage

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

# --- Server-generated PoC PDF: plain text document with NO embedded fonts.
# The browser's "Save as PDF" always embeds font subsets; generating the PDF
# here with PDF core fonts (Helvetica) keeps it fully editable anywhere.
try:
    from fpdf import FPDF
    _HAVE_FPDF = True
except ImportError:
    _HAVE_FPDF = False


def _pdf_sanitize(s):
    """Core PDF fonts are latin-1 only — map stray unicode to safe text."""
    s = str(s or "")
    s = (s.replace("\u2014", "-").replace("\u2013", "-")
          .replace("\u201c", '"').replace("\u201d", '"')
          .replace("\u2018", "'").replace("\u2019", "'")
          .replace("\u2026", "...").replace("\u00a0", " "))
    return s.encode("latin-1", "replace").decode("latin-1")


class _PocPDF(FPDF):
    def footer(self):
        self.set_y(-15)
        self.set_font("helvetica", "", 8)
        self.set_text_color(140, 140, 140)
        self.cell(0, 8, f"Page {self.page_no()}/{{nb}}", align="C")


# --- Reference links per finding key (OWASP / CWE) for the PoC report.
REFERENCES = {
    "https": "OWASP Transport Layer Protection Cheat Sheet; https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html",
    "http-redirect": "OWASP HTTP Strict Transport Security Cheat Sheet; https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html",
    "hsts": "OWASP HTTP Strict Transport Security Cheat Sheet; https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html",
    "clickjacking": "OWASP Clickjacking Defense Cheat Sheet; https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html",
    "csp": "OWASP Content Security Policy Cheat Sheet; https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
    "server-version": "CWE-200 Exposure of Sensitive Information; https://cwe.mitre.org/data/definitions/200.html",
    "x-powered-by": "CWE-200 Exposure of Sensitive Information; https://cwe.mitre.org/data/definitions/200.html",
    "cert-expired": "OWASP Certificate and Public Key Pinning; https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning",
    "cert-expiring": "OWASP Certificate and Public Key Pinning; https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning",
    "git": "CWE-538 File and Directory Information Exposure; https://cwe.mitre.org/data/definitions/538.html",
    "env": "CWE-538 File and Directory Information Exposure; https://cwe.mitre.org/data/definitions/538.html",
    "wp-login": "OWASP WordPress Security Implementation Guideline; https://owasp.org/www-project-wordpress-security-implementation-guideline/",
    "nosniff-missing": "OWASP Secure Headers Project; https://owasp.org/www-project-secure-headers/",
    "referrer-policy-insecure": "OWASP Secure Headers Project; https://owasp.org/www-project-secure-headers/",
    "permissions-policy-missing": "OWASP Secure Headers Project; https://owasp.org/www-project-secure-headers/",
    "cookie-flags-missing": "OWASP Session Management Cheat Sheet; https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
    "cors-wildcard-credentials": "CWE-942 Permissive Cross-domain Policy with Untrusted Domains; https://cwe.mitre.org/data/definitions/942.html",
    "tls-old-version": "OWASP Transport Layer Protection Cheat Sheet; https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html",
    "security-txt-missing": "security.txt — a method for web security policies; https://securitytxt.org/",
    "http-trace-enabled": "CWE-749 Exposed Dangerous Method or Function; https://cwe.mitre.org/data/definitions/749.html",
    "tech-version-headers": "CWE-200 Exposure of Sensitive Information; https://cwe.mitre.org/data/definitions/200.html",
    "cross-origin-policy-missing": "OWASP Secure Headers Project; https://owasp.org/www-project-secure-headers/",
    "hsts-weak": "OWASP HTTP Strict Transport Security Cheat Sheet; https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html",
    "robots-disclosure": "CWE-538 File and Directory Information Exposure; https://cwe.mitre.org/data/definitions/538.html",
}


def _poc_details(report):
    details = []
    for f in report["findings"]:
        d = POC_DETAILS.get(f.get("key", ""), {})
        host = report["url"]
        details.append({
            "finding": f,
            "impact": d.get("impact", ""),
            "repro": [s.replace("TARGET", host) for s in d.get("repro", [])],
            "evidence": d.get("evidence", ""),
            "reference": REFERENCES.get(f.get("key", ""), ""),
        })
    return details


def _build_poc_pdf(report, name, details):
    ink, muted = (20, 25, 35), (110, 118, 130)
    pdf = _PocPDF(format="A4")
    pdf.alias_nb_pages("{nb}")
    pdf.set_auto_page_break(True, margin=22)
    pdf.set_margins(20, 18, 20)
    pdf.add_page()

    def _field(label, body):
        if not body:
            return
        pdf.set_font("helvetica", "B", 9)
        pdf.set_text_color(*muted)
        pdf.cell(0, 6, _pdf_sanitize(label.upper()),
                 new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("helvetica", "", 10)
        pdf.set_text_color(*ink)
        pdf.multi_cell(0, 5.5, _pdf_sanitize(body),
                       new_x="LMARGIN", new_y="NEXT", align="L")
        pdf.ln(2)

    def _section_head(text):
        if pdf.get_y() > 245:
            pdf.add_page()
        pdf.set_font("helvetica", "B", 13)
        pdf.set_text_color(*ink)
        pdf.cell(0, 9, _pdf_sanitize(text), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)

    # ---- report header ----
    pdf.set_font("helvetica", "B", 9)
    pdf.set_text_color(*muted)
    pdf.cell(0, 6, "VAPT ASSESSMENT & PROOF OF CONCEPT REPORT",
             new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("helvetica", "B", 20)
    pdf.set_text_color(*ink)
    pdf.multi_cell(0, 9, _pdf_sanitize(report["url"]),
                   new_x="LMARGIN", new_y="NEXT", align="L")
    pdf.ln(4)
    pdf.set_font("helvetica", "", 10)
    for label, val in (("Prepared by", name), ("Target", report["url"]),
                       ("Assessment date", report["scanned_at"]),
                       ("Report status", "Final"),
                       ("Generated by", "SiteGuard (no AI used)")):
        pdf.set_text_color(*muted)
        pdf.cell(36, 6, _pdf_sanitize(label))
        pdf.set_text_color(*ink)
        pdf.cell(0, 6, _pdf_sanitize(val), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)
    pdf.set_draw_color(*ink)
    pdf.set_line_width(0.8)
    pdf.line(20, pdf.get_y(), 190, pdf.get_y())
    pdf.ln(8)

    # ---- 1. executive summary ----
    _section_head("1. Executive Summary")
    for i, d in enumerate(details, 1):
        f = d["finding"]
        pdf.set_font("helvetica", "", 10)
        pdf.set_text_color(*ink)
        pdf.multi_cell(0, 6, _pdf_sanitize(
            f"{i:02d}. {f.get('title', '')} "
            f"[{f.get('severity', '').upper()}] - Confirmed"),
            new_x="LMARGIN", new_y="NEXT", align="L")
    pdf.ln(4)

    # ---- 2. finding details ----
    _section_head("2. Finding Details")
    for i, d in enumerate(details, 1):
        f = d["finding"]
        if pdf.get_y() > 230:
            pdf.add_page()
        pdf.set_font("helvetica", "B", 12)
        pdf.set_text_color(*ink)
        pdf.cell(0, 8, _pdf_sanitize(f"Finding {i:02d}"),
                 new_x="LMARGIN", new_y="NEXT")
        pdf.ln(1)
        _field("Name", name)
        _field("Vulnerability Name", f.get("title", ""))
        _field("Severity", f.get("severity", "").upper())
        _field("Description", f.get("what_it_means", ""))
        _field("Observation", d.get("evidence", ""))
        if d.get("repro"):
            _field("Steps to reproduce",
                   "\n".join(f"{j + 1}. {s}"
                             for j, s in enumerate(d["repro"])))
        _field("Impact", d.get("impact", ""))
        _field("Recommendation", f.get("how_to_fix", ""))
        _field("Reference", d.get("reference", ""))
        pdf.ln(4)

    # ---- 3. security controls verified ----
    passed = [c for c in report.get("checks", [])
              if c.get("status") == "passed"]
    if passed:
        _section_head("3. Security Controls Verified")
        pdf.set_font("helvetica", "", 10)
        pdf.set_text_color(*ink)
        pdf.multi_cell(0, 5.5, _pdf_sanitize(
            "The following controls were inspected and verified to be "
            "correctly configured. They are effective defenses, not "
            "vulnerabilities."), new_x="LMARGIN", new_y="NEXT", align="L")
        pdf.ln(2)
        for c in passed:
            pdf.cell(0, 6, _pdf_sanitize(f"PASS - {c.get('name', '')}"),
                     new_x="LMARGIN", new_y="NEXT", align="L")
        pdf.ln(4)

    pdf.set_font("helvetica", "", 9)
    pdf.set_text_color(*muted)
    pdf.multi_cell(0, 5, _pdf_sanitize(
        "This Proof of Concept was generated from an automated, non-intrusive "
        "scan of publicly visible information only. It is provided for "
        "authorized security testing and remediation purposes. Do not use "
        "these techniques against systems you do not own or have explicit "
        "permission to test."), new_x="LMARGIN", new_y="NEXT", align="L")
    return bytes(pdf.output())

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
                           poc_payload=_sign_report(report),
                           owasp=owasp_coverage(report))


def _merge_reports(passive, active):
    """VAPT mode: merge the passive scan and the active tests into one report.

    Score uses scanner.DEDUCT over all findings; grade uses the passive
    thresholds (A>=90, B>=80, C>=70, D>=60, else F). Pure function so it
    can be unit-tested without network or Flask context.
    """
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    findings = sorted(passive["findings"] + active["findings"],
                      key=lambda f: order[f["severity"]])
    score = max(0, 100 - sum(DEDUCT[f["severity"]] for f in findings))
    grade = ("A" if score >= 90 else "B" if score >= 80 else "C"
             if score >= 70 else "D" if score >= 60 else "F")
    return {"url": passive["url"],
            "scanned_at": passive["scanned_at"],
            "mode": "vapt",
            "score": score,
            "grade": grade,
            "findings": findings,
            "checks": passive["checks"] + active["checks"]}


@app.route("/vapt", methods=["POST"])
def do_vapt():
    """VAPT mode: 6 active (non-destructive) vulnerability tests.

    Requires the consent checkbox — only scan sites you own or have
    permission to test. Same rate limit and SSRF guard as passive scans.
    """
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
    if not request.form.get("consent"):
        return render_template(
            "index.html",
            error="Please tick the permission box — VAPT tests may only run "
                  "against sites you own or have permission to test.")

    try:
        # VAPT mode = full passive scan + 6 active tests, merged into one
        # report. Both scans raise UnsafeTarget for non-public targets.
        passive = scan(url)
        active = vapt_scan(url)
    except UnsafeTarget as e:
        return render_template("index.html", error=str(e))
    except Exception:
        return render_template(
            "index.html",
            error="Could not scan that site — check the address and try again.")
    report = _merge_reports(passive, active)
    return render_template("report.html", r=report,
                           sev_color=SEV_COLOR, sev_label=SEV_LABEL,
                           grade_color=GRADE_COLOR[report["grade"]],
                           poc_payload=_sign_report(report),
                           mode="vapt",
                           owasp=owasp_coverage(report))


@app.route("/poc", methods=["POST"])
def make_poc():
    name = (request.form.get("name") or "").strip()[:80]
    report = _load_report(request.form.get("payload", ""))

    def _report_page(r, payload, poc_error=None):
        return render_template("report.html", r=r,
                               sev_color=SEV_COLOR, sev_label=SEV_LABEL,
                               grade_color=GRADE_COLOR[r["grade"]],
                               poc_payload=payload, poc_error=poc_error,
                               mode=r.get("mode"),
                               owasp=owasp_coverage(r))

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

    details = _poc_details(report)
    return render_template("poc.html", r=report, name=name, details=details,
                           payload=payload,
                           sev_color=SEV_COLOR, sev_label=SEV_LABEL,
                           grade_color=GRADE_COLOR[report["grade"]])


@app.route("/poc/pdf", methods=["POST"])
def poc_pdf():
    """Downloadable PoC PDF generated server-side with no embedded fonts."""
    if not _HAVE_FPDF:
        return "PDF download is temporarily unavailable.", 503
    name = (request.form.get("name") or "").strip()[:80]
    report = _load_report(request.form.get("payload", ""))
    if not report or not name or not report["findings"]:
        return render_template(
            "index.html",
            error="That report expired or was changed — please scan the site again.")
    data = _build_poc_pdf(report, name, _poc_details(report))
    return Response(data, mimetype="application/pdf", headers={
        "Content-Disposition": "attachment; filename=siteguard-poc.pdf"})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5050))
    app.run(host="0.0.0.0", port=port)
