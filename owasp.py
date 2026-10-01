#!/usr/bin/env python3
"""OWASP Top 10 (2021) mapping for SiteGuard.

Every check SiteGuard runs is tagged with the OWASP category it belongs
to. Categories that cannot be tested from outside (no credentials, no
exploitation) are marked honestly instead of faked.

owasp_coverage(report) -> list of 10 dicts, one per category:
    {"id", "title", "note", "status", "checks"}
status is one of:
    "covered"      - at least one mapped check ran in this scan
    "not-in-scan"  - testable, but this scan mode doesn't cover it
    "not-testable" - cannot be checked from outside; see note
"""
CATEGORIES = [
    {"id": "A01", "title": "Broken Access Control",
     "testable": True,
     "note": "We probe for directly reachable sensitive paths and files "
             "(.git, .env, backups, admin pages, open redirects). We can't "
             "test logged-in access rules — that needs an account."},
    {"id": "A02", "title": "Cryptographic Failures",
     "testable": True,
     "note": "We check TLS end to end: certificate health, old protocol "
             "versions rejected, HSTS enforcement, secure cookie flags."},
    {"id": "A03", "title": "Injection",
     "testable": True,
     "note": "VAPT mode probes for reflected input and database error "
             "leaks. Detection only — we never attempt exploitation."},
    {"id": "A04", "title": "Insecure Design",
     "testable": False,
     "note": "Design flaws need threat modelling and code review — they "
             "can't be found by probing a live site from outside."},
    {"id": "A05", "title": "Security Misconfiguration",
     "testable": True,
     "note": "Most of our checks live here: security headers, risky HTTP "
             "methods, verbose error pages, version leaks, security.txt, "
             "CORS."},
    {"id": "A06", "title": "Vulnerable and Outdated Components",
     "testable": True,
     "note": "We flag visible version numbers so you can check them against "
             "vulnerability databases. We don't track which versions are "
             "vulnerable ourselves."},
    {"id": "A07", "title": "Identification and Authentication Failures",
     "testable": True,
     "note": "From outside we can only spot exposed login pages. Real "
             "authentication testing needs credentials we won't ask for."},
    {"id": "A08", "title": "Software and Data Integrity Failures",
     "testable": False,
     "note": "Update pipelines and code integrity can't be verified by "
             "probing a live site from outside."},
    {"id": "A09", "title": "Security Logging and Monitoring Failures",
     "testable": False,
     "note": "Logging and monitoring are internal — invisible from outside."},
    {"id": "A10", "title": "Server-Side Request Forgery",
     "testable": False,
     "note": "Can't be tested safely from outside. (Our own scanner is "
             "SSRF-guarded so it can't be abused to probe internal "
             "networks.)"},
]

# SiteGuard check name -> OWASP category id.
CHECK_MAP = {
    # --- passive scan ---
    "Secure connection (HTTPS)": "A02",
    "Insecure page redirects to secure version": "A02",
    "Always-use-secure-connection rule (HSTS)": "A02",
    "Clickjacking protection": "A05",
    "Script-loading rules (CSP)": "A05",
    "Server software version hidden": "A05",
    "Technology name hidden (X-Powered-By)": "A05",
    "Security certificate valid": "A02",
    "Private code folder (.git) not public": "A01",
    "Secret keys file (.env) not public": "A01",
    "WordPress login page": "A07",
    "File-type guessing blocked (nosniff)": "A05",
    "Link-click data leak controlled (Referrer-Policy)": "A05",
    "Browser feature restrictions (Permissions-Policy)": "A05",
    "Login/session cookies locked down": "A02",
    "Cross-site data sharing locked down (CORS)": "A01",
    "Outdated encryption versions disabled": "A02",
    "Security contact file (security.txt)": "A05",
    "Risky TRACE method disabled": "A05",
    "Extra technology names hidden": "A05",
    "Cross-origin isolation (COOP/COEP)": "A05",
    "HSTS covers all subdomains": "A02",
    "robots.txt hides sensitive paths": "A01",
    "Sensitive admin paths hidden": "A01",
    "Outdated tech versions visible": "A06",
    # --- VAPT mode ---
    "User input reflected in pages": "A03",
    "Database errors hidden": "A03",
    "Login/link redirects stay on your site": "A01",
    "No backup files exposed": "A01",
    "Only safe request methods enabled": "A05",
    "Error pages hide internals": "A05",
}


def owasp_coverage(report):
    """Build the 10-row OWASP coverage table for a scan report."""
    by_cat = {}
    for check in report.get("checks", []):
        cat = CHECK_MAP.get(check["name"])
        if cat:
            by_cat.setdefault(cat, []).append(
                {"name": check["name"], "status": check["status"]})
    rows = []
    for cat in CATEGORIES:
        checks = by_cat.get(cat["id"], [])
        if checks:
            status = "covered"
        elif cat["testable"]:
            status = "not-in-scan"
        else:
            status = "not-testable"
        rows.append({"id": cat["id"], "title": cat["title"],
                     "note": cat["note"], "status": status,
                     "checks": checks})
    return rows
