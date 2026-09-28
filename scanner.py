#!/usr/bin/env python3
"""SiteGuard scanner engine — plain-English website security checks.

scan(url) -> dict with score, grade, and findings. Every finding carries
a plain-English explanation: what it means and how to fix it.
Only scans the domain the user asked for. HTTP-level checks only.
"""
import ipaddress
import re
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

TIMEOUT = 10
UA = {"User-Agent": "SiteGuard/1.0 (security check; contact: hello@siteguard)"}
MAX_REDIRECTS = 5

DEDUCT = {"high": 25, "medium": 15, "low": 5, "info": 0}


def _finding(severity, title, meaning, fix):
    return {"severity": severity, "title": title,
            "what_it_means": meaning, "how_to_fix": fix}


class UnsafeTarget(ValueError):
    """Raised when a scan target is not a public website."""


def _is_public_host(host):
    """True only if the host resolves exclusively to public IPs.

    Blocks private networks, loopback, link-local (incl. cloud metadata
    169.254.169.254), and other non-routable addresses — SSRF guard.
    """
    if not host or len(host) > 253:
        return False
    try:
        infos = socket.getaddrinfo(host, 443)
    except socket.gaierror:
        return False
    if not infos:
        return False
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            return False
        if not ip.is_global:
            return False
    return True


def _check_url(url):
    """Validate one URL before we fetch it. Returns normalized URL."""
    parts = urlparse(url)
    if parts.scheme not in ("http", "https"):
        raise UnsafeTarget("Only http:// and https:// addresses can be scanned.")
    host = parts.hostname
    if not _is_public_host(host):
        raise UnsafeTarget(
            "That address isn't a public website — only real, public "
            "sites can be scanned.")
    return url


def _safe_get(url, max_redirects=MAX_REDIRECTS, follow=True):
    """GET with optional manual redirect-following; every hop is re-validated.

    requests' automatic redirect-following would let a hostile site bounce
    us onto an internal address, so we follow redirects ourselves.
    """
    for _ in range(max_redirects + 1):
        _check_url(url)
        r = requests.get(url, headers=UA, timeout=TIMEOUT,
                         allow_redirects=False)
        if not follow:
            return r
        if r.status_code in (301, 302, 303, 307, 308):
            loc = r.headers.get("Location")
            if not loc:
                return r
            url = requests.compat.urljoin(url, loc)
            continue
        return r
    raise UnsafeTarget("Too many redirects — giving up on that address.")


def _get(url):
    return _safe_get(url)


def scan(raw_url):
    url = raw_url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    host = urlparse(url).hostname or url
    _check_url(f"https://{host}/")  # reject non-public targets up front
    findings = []

    # 1. Does HTTPS work at all?
    https_ok = True
    try:
        r = _get(f"https://{host}/")
        base = r
    except Exception:
        https_ok = False
        findings.append(_finding(
            "high", "No secure connection (HTTPS)",
            "Your site has no padlock in the browser. Visitor data "
            "(passwords, forms, payments) can be seen or changed by "
            "attackers on the network.",
            "Turn on HTTPS in your hosting settings — most hosts offer "
            "a free certificate (Let's Encrypt) in one click."))
        base = None

    # 2. Does plain http:// redirect to https:// ?
    if https_ok:
        try:
            r = _safe_get(f"http://{host}/", follow=False)
            loc = r.headers.get("Location", "")
            if not (r.status_code in (301, 302, 307, 308)
                    and loc.startswith("https://")):
                findings.append(_finding(
                    "medium", "Insecure address still works",
                    "People who type your address without https://, or "
                    "follow old links, get an unprotected page instead of "
                    "being sent to the safe version.",
                    "Turn on 'Force HTTPS' / 'Always use HTTPS' in your "
                    "hosting or Cloudflare settings."))
        except Exception:
            pass

    headers = {k.lower(): v for k, v in base.headers.items()} if base else {}

    # 3. HSTS — tells browsers to never use http again
    if https_ok and "strict-transport-security" not in headers:
        findings.append(_finding(
            "medium", "Missing 'always use secure connection' rule",
            "Even with HTTPS on, a first-time visitor can still be tricked "
            "onto the insecure version of your site.",
            "Ask your host to add the HSTS header, or enable it in "
            "Cloudflare (SSL/TLS -> Edge Certificates -> HTTP Strict "
            "Transport Security)."))

    # 4. Clickjacking protection
    if "x-frame-options" not in headers and "content-security-policy" not in headers:
        findings.append(_finding(
            "low", "Your site can be embedded inside other sites",
            "Attackers can invisibly layer your site inside theirs and "
            "trick visitors into clicking things they didn't mean to.",
            "Ask your developer or host to add the header "
            "'X-Frame-Options: SAMEORIGIN'."))

    # 5. Content-Security-Policy
    if "content-security-policy" not in headers:
        findings.append(_finding(
            "low", "No script-loading rules set",
            "Without these rules it's easier for attackers to sneak "
            "malicious scripts onto your pages.",
            "This one needs a developer — ask them to add a "
            "Content-Security-Policy header."))

    # 6. Server version exposed
    server = headers.get("server", "")
    if server and re.search(r"\d+\.\d+", server):
        findings.append(_finding(
            "low", f"Server software version is visible ({server})",
            "Your site tells everyone exactly which software version it "
            "runs. Attackers use this to look up known weaknesses.",
            "Ask your host to hide the version number (turn off "
            "'ServerTokens' / 'server signature')."))

    # 7. X-Powered-By exposed
    if "x-powered-by" in headers:
        findings.append(_finding(
            "low", f"Technology name is visible ({headers['x-powered-by']})",
            "Same idea as above — free clues for attackers about what "
            "to attack.",
            "Ask your host or developer to remove the X-Powered-By header."))

    # 8. Certificate expiry
    if https_ok:
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=TIMEOUT) as s:
                with ctx.wrap_socket(s, server_hostname=host) as ss:
                    cert = ss.getpeercert()
            exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
            exp = exp.replace(tzinfo=timezone.utc)
            days = (exp - datetime.now(timezone.utc)).days
            if days < 0:
                findings.append(_finding(
                    "high", "Security certificate has expired",
                    "Browsers show a scary warning page to every visitor. "
                    "Most people leave immediately.",
                    "Renew the certificate in your hosting panel right away."))
            elif days < 30:
                findings.append(_finding(
                    "medium", f"Security certificate expires in {days} days",
                    "If it lapses, visitors will see a warning page and "
                    "leave.",
                    "Set your certificate to auto-renew, or renew it in "
                    "your hosting panel now."))
        except Exception:
            pass

    # 9. Exposed .git folder — source code leak
    try:
        r = _get(f"https://{host}/.git/HEAD")
        if r.status_code == 200 and "ref:" in r.text:
            findings.append(_finding(
                "high", "Your website's private code folder is public",
                "Anyone can download your site's source code — including "
                "passwords or keys a developer may have left inside.",
                "Block public access to the .git folder on your server "
                "immediately, and change any passwords/keys in the code."))
    except Exception:
        pass

    # 10. Exposed .env file — secrets leak
    try:
        r = _get(f"https://{host}/.env")
        if r.status_code == 200 and ("APP_KEY" in r.text or "DB_" in r.text
                                     or "SECRET" in r.text):
            findings.append(_finding(
                "high", "A file with secret keys is public",
                "Your .env file — which usually holds database passwords "
                "and API keys — can be read by anyone.",
                "Block public access to .env right away and change every "
                "password and key listed inside it."))
    except Exception:
        pass

    # 11. WordPress login reachable (informational)
    try:
        r = _safe_get(f"https://{host}/wp-login.php", follow=False)
        if r.status_code == 200:
            findings.append(_finding(
                "info", "WordPress login page found",
                "Not a problem by itself — just means attackers know "
                "where to try passwords.",
                "Use a strong admin password and turn on two-factor login "
                "in WordPress."))
    except Exception:
        pass

    score = max(0, 100 - sum(DEDUCT[f["severity"]] for f in findings))
    grade = ("A" if score >= 90 else "B" if score >= 80 else "C"
             if score >= 70 else "D" if score >= 60 else "F")
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    findings.sort(key=lambda f: order[f["severity"]])

    return {
        "url": host,
        "scanned_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "score": score,
        "grade": grade,
        "findings": findings,
    }


if __name__ == "__main__":
    import json
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    print(json.dumps(scan(target), indent=2))
