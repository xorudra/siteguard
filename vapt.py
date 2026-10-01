#!/usr/bin/env python3
"""SiteGuard VAPT mode — active (but non-destructive) vulnerability tests.

vapt_scan(url) -> dict with score, grade, findings, checks.

Detection only: no payloads that write, delete, authenticate, brute-force,
or deny service. Every probe stays on the target domain.

Safety is imported from scanner.py — never re-implemented here — so the
SSRF guard (public IPs only), per-hop redirect re-validation, and the
5-redirect cap apply to every VAPT probe exactly as they do to passive scans.
"""
import random
import re
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

from scanner import (
    DEDUCT,
    TIMEOUT,
    UA,
    UnsafeTarget,  # noqa: F401  (re-exported so app.py can catch it)
    _check_url,
    _finding,
    _safe_get,
)

_rng = random.SystemRandom()


def _canary(n=16):
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(_rng.choice(alphabet) for _ in range(n))


SQL_ERROR_SIGS = [
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_",
    r"valid MySQL result",
    r"MySqlClient\.",
    r"Unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"ORA-\d{5}",
    r"Oracle error",
    r"Oracle.*Driver",
    r"SQLServer JDBC Driver",
    r"SqlException",
    r"sqlite3?\.OperationalError",
    r"SQLite/JDBCDriver",
    r"SQLite\.Exception",
    r"psycopg2",
    r"pg_query\(\)",
    r"PostgreSQL.*ERROR",
    r"Warning.*\Wpg_",
    r"Microsoft OLE DB Provider",
    r"Microsoft JET Database",
    r"Access Database Engine",
    r"DB2 SQL error",
    r"JDBC",
]

TRACE_MARKERS = [
    r"Traceback \(most recent call last\)",
    r"\bat java\.",
    r"\.php on line \d+",
    r"System\.Web\.",
    r"NullReferenceException",
    r"Stack trace:",
]

# Backup / stale-copy paths probed on the SAME host (never another domain).
BACKUP_PATHS = [
    "/backup.zip",
    "/backup.tar.gz",
    "/db.sql",
    "/database.sql",
    "/index.php.bak",
    "/index.html.bak",
    "/wp-config.php.bak",
    "/.env.bak",
]

REDIRECT_PARAMS = ["next", "redirect", "url"]
REDIRECT_CANARY = "https://example.com/sg-probe"


def vapt_scan(raw_url):
    url = raw_url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    host = urlparse(url).hostname or url
    _check_url(f"https://{host}/")  # reject non-public targets up front
    base = f"https://{host}"

    score = 100
    findings = []
    checks = []

    def _record(name, status):
        # status: "passed", "failed", "skipped" or "info"
        checks.append({"name": name, "status": status})

    def _deduct(severity):
        nonlocal score
        score = max(0, score - DEDUCT[severity])

    # 1. Reflected input — canary token echoed back into the page?
    #    (XSS prerequisite; reported as medium, needs human verification.)
    try:
        token = "sgx" + _canary()
        r = _safe_get(f"{base}/?sgx={token}")
        if token in r.text:
            _record("User input reflected in pages", "failed")
            _deduct("medium")
            findings.append(_finding(
                "medium", "reflected-input",
                "Your site echoes visitor input back into pages",
                "Text typed into your site's address (or forms) shows up "
                "in the page itself. Attackers can abuse this to run "
                "malicious scripts in other visitors' browsers (cross-site "
                "scripting). This check only proves the echo — a human "
                "should confirm whether it is exploitable.",
                "Make sure anything visitors type is escaped before it is "
                "shown back, and set a Content-Security-Policy header."))
        else:
            _record("User input reflected in pages", "passed")
    except Exception:
        _record("User input reflected in pages", "skipped")

    # 2. Database error disclosure — single quote probe.
    try:
        r = _safe_get(f"{base}/?id=%27")
        hit = any(re.search(pat, r.text, re.IGNORECASE)
                  for pat in SQL_ERROR_SIGS)
        if hit:
            _record("Database errors hidden", "failed")
            _deduct("high")
            findings.append(_finding(
                "high", "sql-errors",
                "Your site leaks database error details",
                "A tiny typo in the address made your site print a raw "
                "database error. Those messages reveal your database type "
                "and structure — exactly what attackers need to plan a "
                "deeper injection attack.",
                "Turn off detailed errors on the live site (show visitors "
                "a generic error page) and log the real errors privately. "
                "Use parameterized queries everywhere."))
        else:
            _record("Database errors hidden", "passed")
    except Exception:
        _record("Database errors hidden", "skipped")

    # 3. Open redirect — ?next=https://example.com style params.
    try:
        vulnerable = False
        for param in REDIRECT_PARAMS:
            r = _safe_get(f"{base}/?{param}={REDIRECT_CANARY}", follow=False)
            hdrs = {k.lower(): v for k, v in r.headers.items()}
            loc = hdrs.get("location", "")
            if (r.status_code in (301, 302, 303, 307, 308)
                    and "example.com" in loc):
                vulnerable = True
                break
        if vulnerable:
            _record("Login/link redirects stay on your site", "failed")
            _deduct("medium")
            findings.append(_finding(
                "medium", "open-redirect",
                "Your site can redirect visitors to any address",
                "A link on your site (login, 'continue', language switch…) "
                "sent our test visitor to an external address we chose. "
                "Attackers use this for phishing: victim clicks YOUR link, "
                "lands on THEIR fake page.",
                "Only allow redirects to addresses on your own domain — "
                "reject anything starting with http:// or https:// that "
                "isn't yours."))
        else:
            _record("Login/link redirects stay on your site", "passed")
    except Exception:
        _record("Login/link redirects stay on your site", "skipped")

    # 4. Backup / stale files exposed on the same host.
    try:
        exposed = None
        for path in BACKUP_PATHS:
            r = _safe_get(base + path, follow=False)
            if r.status_code == 200 and len(r.content) > 100:
                exposed = path
                break
        if exposed:
            _record("No backup files exposed", "failed")
            _deduct("low")
            findings.append(_finding(
                "low", "backup-files",
                f"Leftover backup file is downloadable ({exposed})",
                "An old copy of site files is sitting on your server where "
                "anyone can download it. Backups often contain passwords, "
                "old code with known bugs, or customer data.",
                "Delete backup/old files from the live server (keep them "
                "offline), and block direct downloads of .bak/.old/.sql/ "
                ".zip in your server settings."))
        else:
            _record("No backup files exposed", "passed")
    except Exception:
        _record("No backup files exposed", "skipped")

    # 5. Dangerous HTTP methods enabled (OPTIONS probe).
    try:
        _check_url(base + "/")
        r = requests.options(base + "/", headers=UA, timeout=TIMEOUT)
        allow = {k.lower(): v for k, v in r.headers.items()}.get("allow", "")
        dangerous = [m for m in ("PUT", "DELETE", "TRACE")
                     if m in allow.upper()]
        if dangerous:
            _record("Only safe request methods enabled", "failed")
            _deduct("medium")
            findings.append(_finding(
                "medium", "dangerous-methods",
                f"Risky request methods enabled ({', '.join(dangerous)})",
                "Your server says it accepts methods like "
                f"{', '.join(dangerous)}. Those let visitors upload, "
                "overwrite, or debug the site — far more than reading "
                "pages needs.",
                "Ask your host to allow only GET, HEAD, POST (and OPTIONS) "
                "on the live site."))
        else:
            _record("Only safe request methods enabled", "passed")
    except Exception:
        _record("Only safe request methods enabled", "skipped")

    # 6. Verbose error pages — stack traces on 404s.
    try:
        r = _safe_get(f"{base}/sg-missing-{_canary(8)}")
        hit = any(re.search(pat, r.text) for pat in TRACE_MARKERS)
        if r.status_code == 404 and hit:
            _record("Error pages hide internals", "failed")
            _deduct("low")
            findings.append(_finding(
                "low", "verbose-errors",
                "Error pages reveal server internals",
                "Your 'page not found' screen prints technical details "
                "(code traces, file paths). That tells attackers which "
                "software and versions you run.",
                "Show visitors a plain, friendly error page on the live "
                "site and write the technical details to a private log."))
        else:
            _record("Error pages hide internals", "passed")
    except Exception:
        _record("Error pages hide internals", "skipped")

    grade = ("A" if score >= 90 else "B" if score >= 75
             else "C" if score >= 60 else "D" if score >= 40 else "F")
    return {"url": host,
            "scanned_at": datetime.now(timezone.utc).strftime(
                "%Y-%m-%d %H:%M UTC"),
            "score": score, "grade": grade,
            "findings": findings, "checks": checks,
            "mode": "vapt"}
