#!/usr/bin/env python3
"""SiteGuard web app — enter a URL, get a website security report."""
import ipaddress
import os
import secrets
import sys
import time
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, Response, render_template, request
from itsdangerous import BadSignature, URLSafeSerializer
from scanner import DEDUCT, scan, UnsafeTarget
from vapt import vapt_scan
from owasp import owasp_coverage

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
# Cap request bodies (2026-10-16 audit fix): the forms carry a URL plus a
# signed report payload, so 64 KiB is generous headroom — and without a
# cap Werkzeug buffers a whole urlencoded body in memory before any
# route-level check (URL length, consent, signature) gets to run.
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024
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
    # Backfill completeness for payloads signed before the field existed
    # (2026-10-16 run-2 fix): derive it from the check list so an old
    # payload renders with the same honesty rules as a fresh report.
    if "skipped" not in report:
        report["skipped"] = sum(
            1 for c in report["checks"] if c.get("status") == "skipped")
    if "complete" not in report:
        report["complete"] = report["skipped"] == 0
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
    "supabase-service-key": {
        "impact": "The service_role key bypasses all Row Level Security. Anyone "
                  "who views the page source can read, modify or delete the "
                  "entire database — user accounts, orders, everything.",
        "repro": ["Open the site's page source / bundled JS and search for "
                  "'supabase.co' and 'service_role'.",
                  "The admin key is shipped to every visitor's browser."],
        "evidence": "A JWT decoding to role=service_role was found in the "
                    "public page source.",
    },
    "supabase-data-open": {
        "impact": "Private table data (emails, names, order details) is "
                  "readable by anyone on the internet with no login — the "
                  "exact exposure behind CVE-2025-48757, found in about 1 "
                  "in 10 AI-built apps scanned in 2025.",
        "repro": ["Take the public anon key from the site's page source.",
                  "Run: curl 'https://<project>.supabase.co/rest/v1/<table>"
                  "?select=*&limit=1' -H 'apikey: <anon key>'",
                  "Real rows come back instead of a permission error."],
        "evidence": "A read-only request using only the site's public anon "
                    "key returned rows from a table. No row values were "
                    "stored in this report.",
    },
    "img-alt-missing": {
        "impact": "Blind and low-vision visitors using screen readers get "
                  "nothing from these images. Missing alt text is a standard "
                  "claim in ADA accessibility lawsuits, which hit thousands "
                  "of small sites every year.",
        "repro": ["Run: curl -s https://TARGET | grep -o '<img[^>]*>'",
                  "Tags without an alt= attribute are the problem images."],
        "evidence": "One or more <img> tags on the homepage have no alt "
                    "attribute at all.",
    },
    "no-cache-headers": {
        "impact": "Every visit re-downloads every file in full. A bot, a "
                  "hotlink or one viral link can quietly run up a bandwidth "
                  "bill in the tens of thousands of dollars on metered "
                  "hosting — with no users to show for it.",
        "repro": ["Run: curl -sI https://TARGET/<a static file>",
                  "No Cache-Control, Expires or ETag header is returned."],
        "evidence": "None of the homepage's static files carried any "
                    "caching headers.",
    },
    "sms-consent-risk": {
        "impact": "In the US, marketing texts sent without prior express "
                  "written consent carry $500 per message in statutory "
                  "damages under the TCPA — a 10,000-number launch list "
                  "is a $5M claim on paper.",
        "repro": ["Open https://TARGET and find the phone-number form.",
                  "There is no consent checkbox, wording or terms next to it."],
        "evidence": "A phone-number input was found with no visible consent "
                    "signals on the page. Backend consent records cannot be "
                    "verified from outside.",
    },
    "privacy-missing": {
        "impact": "Collecting any personal data without a privacy policy "
                  "breaches GDPR / DPDP / CCPA duties and is a standard "
                  "app-store rejection reason — and the first thing a "
                  "lawyer's demand letter cites.",
        "repro": ["Run: curl -sI https://TARGET/privacy and "
                  "https://TARGET/privacy-policy",
                  "Both return 404 — no privacy policy exists."],
        "evidence": "No page at /privacy, /privacy-policy or /privacy.html.",
    },
    "terms-missing": {
        "impact": "No agreed terms means no billing rules, no acceptable-use "
                  "rules and no limitation of liability between a dispute "
                  "and the owner's personal assets.",
        "repro": ["Run: curl -sI https://TARGET/terms and "
                  "https://TARGET/terms-of-service",
                  "Both return 404 — no terms page exists."],
        "evidence": "No page at /terms, /terms-of-service, /terms.html "
                    "or /tos.",
    },
    "legal-placeholder": {
        "impact": "A legal document naming '[Company Name]' protects a "
                  "company that doesn't exist. It signals the pages were "
                  "never reviewed — by the owner or a lawyer.",
        "repro": ["Open the site's privacy/terms page and search for "
                  "'[', '{{' or 'lorem ipsum'.",
                  "Template placeholders are still in the published text."],
        "evidence": "Placeholder patterns were found in the legal pages.",
    },
    "terms-thin": {
        "impact": "When a payment dispute or abuse case arrives, the "
                  "missing clauses (billing, liability, termination, "
                  "governing law) are exactly the ones that decide who "
                  "pays.",
        "repro": ["Read https://TARGET/terms and compare against a "
                  "complete template's section list."],
        "evidence": "Three or more key clause groups are absent from "
                    "the terms text.",
    },
    "privacy-no-processors": {
        "impact": "Regulators (and app-store reviewers) ask who receives "
                  "the data first. A policy that omits processors — "
                  "especially AI APIs receiving user content — reads as "
                  "concealment, not simplicity.",
        "repro": ["Read https://TARGET/privacy and search for 'third', "
                  "'provider', 'processor', 'share', 'analytics'.",
                  "None of them appear."],
        "evidence": "The privacy policy contains no third-party / "
                    "processor / sharing language.",
    },
    "cookie-consent-missing": {
        "impact": "Loading trackers before consent breaches EU/UK "
                  "ePrivacy rules; regulators have fined far smaller "
                  "sites, and ad platforms can restrict accounts over it.",
        "repro": ["Open https://TARGET with browser dev tools > Network.",
                  "Tracker requests (analytics/pixel) fire immediately; "
                  "no consent banner appears first."],
        "evidence": "Tracker code was found in the page source with no "
                    "cookie-consent mechanism alongside it.",
    },
    "supabase-public-bucket": {
        "impact": "Public buckets serve files to anyone with the URL — "
                  "fine for images, a data breach if user uploads or "
                  "documents ever land in one.",
        "repro": ["Run: curl 'https://<project>.supabase.co/storage/v1/"
                  "bucket' -H 'apikey: <public anon key>'",
                  "One or more buckets are marked public: true."],
        "evidence": "The storage API listed public buckets using only "
                    "the site's public anon key. Bucket names only — "
                    "no files were listed or read.",
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
    """Core PDF fonts are latin-1 only — map stray unicode to safe text.

    Control characters (CR, LF, the other C0 controls, DEL, C1) are
    flattened to spaces first: the visitor-supplied name and target-
    controlled finding titles flow into cell()/multi_cell() of a
    document labelled "Report status: Final", and an embedded newline
    would let a crafted name forge extra rendered lines in that
    trusted report."""
    s = str(s or "")
    s = "".join(ch if 0x20 <= ord(ch) < 0x7F or ord(ch) >= 0xA0 else " "
                for ch in s)
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
    "supabase-service-key": "Supabase — Row Level Security & API keys; https://supabase.com/docs/guides/database/postgres/row-level-security",
    "supabase-data-open": "CVE-2025-48757 — Missing RLS in Supabase applications; https://nvd.nist.gov/vuln/detail/CVE-2025-48757",
    "img-alt-missing": "WCAG 2.1 — Non-text Content (1.1.1); https://www.w3.org/WAI/WCAG21/Understanding/non-text-content.html",
    "no-cache-headers": "MDN — HTTP caching & Cache-Control; https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Caching",
    "sms-consent-risk": "FCC — TCPA rules for text messaging consent; https://www.fcc.gov/consumers/guides/stop-unwanted-robocalls-and-texts",
    "privacy-missing": "GDPR Art. 13/14 — information to be provided to data subjects; https://gdpr-info.eu/art-13-gdpr/",
    "terms-missing": "General Legal — CC0 legal templates for startups (GitHub); https://github.com/General-Legal/legal-templates",
    "legal-placeholder": "General Legal — CC0 legal templates for startups (GitHub); https://github.com/General-Legal/legal-templates",
    "terms-thin": "General Legal — CC0 legal templates for startups (GitHub); https://github.com/General-Legal/legal-templates",
    "privacy-no-processors": "GDPR Art. 13/14 — information to be provided to data subjects; https://gdpr-info.eu/art-13-gdpr/",
    "cookie-consent-missing": "ePrivacy Directive & GDPR consent for cookies/trackers; https://gdpr-info.eu/art-7-gdpr/",
    "supabase-public-bucket": "Supabase — Storage access control; https://supabase.com/docs/guides/storage/security/access-control",
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
    # Completeness honesty (2026-10-16 run-2 fix): a partial scan must
    # not label itself an unqualified "Final" assessment.
    _complete = report.get("complete", True)
    _status = "Final" if _complete else "Final (partial scan)"
    for label, val in (("Prepared by", name), ("Target", report["url"]),
                       ("Assessment date", report["scanned_at"]),
                       ("Report status", _status),
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
        if not report.get("complete", True):
            pdf.multi_cell(0, 5.5, _pdf_sanitize(
                f"Partial scan: {report.get('skipped', 0)} of "
                f"{len(report.get('checks', []))} checks could not be "
                "completed and are not listed here."),
                new_x="LMARGIN", new_y="NEXT", align="L")
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

# X-Forwarded-For is trusted ONLY when the deployment sets
# SITEGUARD_TRUST_PROXY=1 to state that a real edge sits in front and
# appends the address it observed (the hosted service behind Caddy
# sets it). Default off: with no edge — local mode has none at all —
# the header is purely client-authored and must not mint rate-limit
# identities.
TRUST_PROXY = os.environ.get("SITEGUARD_TRUST_PROXY") == "1"


def _rate_ok(ip):
    now = time.time()
    # Lazy sweep: forget identities whose hits have all aged out, so
    # _hits cannot grow forever with one-visit addresses.
    for key in [k for k, ts in _hits.items()
                if not ts or now - ts[-1] >= RATE_WINDOW]:
        del _hits[key]
    recent = [t for t in _hits.get(ip, []) if now - t < RATE_WINDOW]
    if len(recent) >= RATE_LIMIT:
        _hits[ip] = recent
        return False
    recent.append(now)
    _hits[ip] = recent
    return True


def _client_ip():
    """Rate-limit identity. With SITEGUARD_TRUST_PROXY=1 (hosted, behind
    a trusted edge): the LAST X-Forwarded-For hop — the address the edge
    actually observed. Earlier hops are client-supplied and spoofable:
    keying on the first hop used to let anyone rotate a fake address and
    scan without limit. Without the flag, XFF is ignored entirely and
    identity is the connection's remote_addr."""
    if TRUST_PROXY:
        hops = [h.strip() for h in
                request.headers.get("X-Forwarded-For", "").split(",")
                if h.strip()]
        if hops:
            return hops[-1]
    return request.remote_addr or "?"


def _origin_ok():
    """CSRF guard for form posts (Launch Safety Standard A2): when a
    browser sends an Origin (or Referer) header, it must name THIS
    host. Non-browser clients send neither and pass — the check only
    stops cross-site browser form submissions."""
    origin = (request.headers.get("Origin")
              or request.headers.get("Referer"))
    if not origin:
        return True
    return urlparse(origin).netloc == request.host


def _host_is_local():
    """True when the request's Host is a loopback name or an IP literal.

    In no-edge mode (TRUST_PROXY off — the local launch and any direct
    bind) a DNS-rebinding page makes the browser send the attacker's
    hostname as Host, and _origin_ok then compares two attacker-chosen
    values. Requiring an IP-literal or localhost Host in that mode
    closes the shape: a rebound name is neither. Hosted mode sits
    behind the edge and is not gated here.
    """
    h = request.host or ""
    if h.startswith("["):
        name = h[1:].split("]")[0]
    else:
        name = h.split(":")[0]
    if name == "localhost":
        return True
    try:
        ipaddress.ip_address(name)
        return True
    except ValueError:
        return False


@app.before_request
def _csrf_guard():
    if (request.method == "POST" and not TRUST_PROXY
            and not _host_is_local()):
        return render_template(
            "index.html", url=(request.form.get("url") or ""),
            error="That request didn't come from this site — please "
                  "start again from the homepage."), 403
    if request.method == "POST" and not _origin_ok():
        return render_template(
            "index.html", url=(request.form.get("url") or ""),
            error="That request didn't come from this site — please "
                  "start again from the homepage."), 403
    return None


@app.errorhandler(404)
@app.errorhandler(405)
def _not_found(_e):
    """Useful error page (Launch Safety Standard H39): a missing page
    or a wrong-method hit gets the branded page with a way back to the
    scanner, not Flask's default plain-text error."""
    return render_template("404.html", code=_e.code or 404), _e.code or 404


@app.errorhandler(413)
def _too_large(_e):
    """Oversized request body (MAX_CONTENT_LENGTH): same branded page
    with a plain reason, not Flask's default plain-text error."""
    return render_template(
        "index.html",
        error="That request was too big — please start again "
              "from the homepage."), 413


def _rate_or_429():
    """Shared limiter gate for the POST routes. Returns a 429 response
    when the caller is over the limit, else None."""
    if _rate_ok(_client_ip()):
        return None
    return render_template(
        "index.html", url=(request.form.get("url") or ""),
        error="Too many scans from you lately — please wait a bit "
              "and try again."), 429


# --- G33 caching: the only cacheable responses are the public GET
# pages (identical for every visitor). Everything else — POST results,
# error pages — is per-request and never marked publicly cacheable.
_PUBLIC_CACHE = {"/": 300, "/privacy": 3600, "/terms": 3600}


@app.after_request
def _security_headers(resp):
    if (request.method == "GET" and resp.status_code == 200
            and request.path in _PUBLIC_CACHE
            and "Cache-Control" not in resp.headers):
        resp.headers["Cache-Control"] = (
            f"public, max-age={_PUBLIC_CACHE[request.path]}")
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


# --- H41 discovery basics: the brand shield as a real favicon asset.
_FAVICON_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" '
    'fill="none" stroke="#4da3ff" stroke-width="1.9" '
    'stroke-linecap="round" stroke-linejoin="round">'
    '<rect width="24" height="24" rx="5" fill="#0a0d12" stroke="none"/>'
    '<path d="M12 3.5l6.5 2.4v4.9c0 4-2.8 7-6.5 8.7-3.7-1.7-6.5-4.7-6.5-8.7'
    'V5.9L12 3.5z"/><path d="M9.2 12l2 2 3.8-3.8"/></svg>')


@app.route("/favicon.svg", methods=["GET"])
@app.route("/favicon.ico", methods=["GET"])
def favicon():
    return Response(_FAVICON_SVG, mimetype="image/svg+xml", headers={
        "Cache-Control": "public, max-age=604800"})


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/privacy", methods=["GET"])
def privacy():
    return render_template("legal.html", page="privacy")


@app.route("/terms", methods=["GET"])
def terms():
    return render_template("legal.html", page="terms")


@app.route("/scan", methods=["POST"])
def do_scan():
    limited = _rate_or_429()
    if limited is not None:
        return limited

    url = (request.form.get("url") or "").strip()
    if not url:
        return render_template("index.html",
                               error="Please enter a website address.")
    if len(url) > 253:
        return render_template("index.html", url=url,
                               error="That address looks too long to be real.")

    try:
        report = scan(url)
    except UnsafeTarget as e:
        return render_template("index.html", url=url, error=str(e))
    except Exception:
        return render_template(
            "index.html", url=url,
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
    checks = passive["checks"] + active["checks"]
    skipped = sum(1 for c in checks if c["status"] == "skipped")
    return {"url": passive["url"],
            "scanned_at": passive["scanned_at"],
            "mode": "vapt",
            "score": score,
            "grade": grade,
            "findings": findings,
            "checks": checks,
            "skipped": skipped,
            "complete": skipped == 0}


@app.route("/vapt", methods=["POST"])
def do_vapt():
    """VAPT mode: 6 active (non-destructive) vulnerability tests.

    Requires the consent checkbox — only scan sites you own or have
    permission to test. Same rate limit and SSRF guard as passive scans.
    """
    limited = _rate_or_429()
    if limited is not None:
        return limited

    url = (request.form.get("url") or "").strip()
    if not url:
        return render_template("index.html",
                               error="Please enter a website address.")
    if len(url) > 253:
        return render_template("index.html", url=url,
                               error="That address looks too long to be real.")
    if not request.form.get("consent"):
        return render_template(
            "index.html", url=url,
            error="Please tick the permission box — VAPT tests may only run "
                  "against sites you own or have permission to test.")

    try:
        # VAPT mode = full passive scan + 6 active tests, merged into one
        # report. Both scans raise UnsafeTarget for non-public targets.
        # The two phases share one overall budget (2026-10-16 run-2
        # fix): the active phase's deadline is capped at 100s from the
        # request start, inside the 120s worker timeout, instead of
        # arming a second independent 90s budget.
        started = time.monotonic()
        passive = scan(url)
        active = vapt_scan(url, deadline=started + 100)
    except UnsafeTarget as e:
        return render_template("index.html", url=url, error=str(e))
    except Exception:
        return render_template(
            "index.html", url=url,
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
    limited = _rate_or_429()
    if limited is not None:
        return limited
    name = (request.form.get("name") or "").strip()[:80]
    report = _load_report(request.form.get("payload", ""))

    def _report_page(r, payload, poc_error=None, poc_name=""):
        return render_template("report.html", r=r,
                               sev_color=SEV_COLOR, sev_label=SEV_LABEL,
                               grade_color=GRADE_COLOR[r["grade"]],
                               poc_payload=payload, poc_error=poc_error,
                               poc_name=poc_name,
                               mode=r.get("mode"),
                               owasp=owasp_coverage(r))

    if not report:
        return render_template(
            "index.html",
            error="That report expired or was changed — please scan the site again.")
    payload = request.form.get("payload", "")
    if not name:
        return _report_page(report, payload,
                            "Please enter your name for the PoC report.",
                            poc_name=name)
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
    limited = _rate_or_429()
    if limited is not None:
        return limited
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
    # Local mode serves the operator's own browser only: bind loopback.
    # The scan/VAPT endpoints are unauthenticated, so exposing them to
    # the LAN is an explicit opt-in (SITEGUARD_LAN=1), never the default.
    host = ("0.0.0.0" if os.environ.get("SITEGUARD_LAN") == "1"
            else "127.0.0.1")
    if host == "0.0.0.0":
        # Loud, every launch (2026-10-16 run-2 fix): an inherited
        # SITEGUARD_LAN=1 must never widen the bind silently.
        print("=" * 60)
        print("WARNING: SiteGuard is listening on ALL network interfaces")
        print(f"(SITEGUARD_LAN=1, port {port}). Anyone on your network can")
        print("run scans from this machine and its IP address — the scan")
        print("endpoints have no login. Unset SITEGUARD_LAN to go back to")
        print("this-computer-only mode.")
        print("=" * 60)
    app.run(host=host, port=port)
