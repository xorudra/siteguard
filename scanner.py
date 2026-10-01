#!/usr/bin/env python3
"""SiteGuard scanner engine — website security checks.

scan(url) -> dict with score, grade, and findings. Every finding carries
a simple explanation: what it means and how to fix it.
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


def _finding(severity, key, title, meaning, fix):
    return {"severity": severity, "key": key, "title": title,
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
    checks = []

    def _record(name, status):
        # status: "passed", "failed", "skipped" or "info"
        checks.append({"name": name, "status": status})

    # 1. Does HTTPS work at all?
    https_ok = True
    try:
        r = _get(f"https://{host}/")
        base = r
    except Exception:
        https_ok = False
        findings.append(_finding(
            "high", "https", "No secure connection (HTTPS)",
            "Your site has no padlock in the browser. Visitor data "
            "(passwords, forms, payments) can be seen or changed by "
            "attackers on the network.",
            "Turn on HTTPS in your hosting settings — most hosts offer "
            "a free certificate (Let's Encrypt) in one click."))
        base = None
    _record("Secure connection (HTTPS)", "passed" if https_ok else "failed")

    # 2. Does plain http:// redirect to https:// ?
    if https_ok:
        redir_ok = True
        try:
            r = _safe_get(f"http://{host}/", follow=False)
            loc = r.headers.get("Location", "")
            if not (r.status_code in (301, 302, 307, 308)
                    and loc.startswith("https://")):
                redir_ok = False
                findings.append(_finding(
                    "medium", "http-redirect", "Insecure address still works",
                    "People who type your address without https://, or "
                    "follow old links, get an unprotected page instead of "
                    "being sent to the safe version.",
                    "Turn on 'Force HTTPS' / 'Always use HTTPS' in your "
                    "hosting or Cloudflare settings."))
        except Exception:
            pass
        _record("Insecure page redirects to secure version",
                "passed" if redir_ok else "failed")
    else:
        _record("Insecure page redirects to secure version", "skipped")

    headers = {k.lower(): v for k, v in base.headers.items()} if base else {}

    # 3. HSTS — tells browsers to never use http again
    if not https_ok:
        _record("Always-use-secure-connection rule (HSTS)", "skipped")
    elif "strict-transport-security" not in headers:
        _record("Always-use-secure-connection rule (HSTS)", "failed")
        findings.append(_finding(
            "medium", "hsts", "Missing 'always use secure connection' rule",
            "Even with HTTPS on, a first-time visitor can still be tricked "
            "onto the insecure version of your site.",
            "Ask your host to add the HSTS header, or enable it in "
            "Cloudflare (SSL/TLS -> Edge Certificates -> HTTP Strict "
            "Transport Security)."))
    else:
        _record("Always-use-secure-connection rule (HSTS)", "passed")

    # 4. Clickjacking protection
    if "x-frame-options" not in headers and "content-security-policy" not in headers:
        _record("Clickjacking protection", "failed")
        findings.append(_finding(
            "low", "clickjacking", "Your site can be embedded inside other sites",
            "Attackers can invisibly layer your site inside theirs and "
            "trick visitors into clicking things they didn't mean to.",
            "Ask your developer or host to add the header "
            "'X-Frame-Options: SAMEORIGIN'."))
    else:
        _record("Clickjacking protection", "passed")

    # 5. Content-Security-Policy
    if "content-security-policy" not in headers:
        _record("Script-loading rules (CSP)", "failed")
        findings.append(_finding(
            "low", "csp", "No script-loading rules set",
            "Without these rules it's easier for attackers to sneak "
            "malicious scripts onto your pages.",
            "This one needs a developer — ask them to add a "
            "Content-Security-Policy header."))
    else:
        _record("Script-loading rules (CSP)", "passed")

    # 6. Server version exposed
    server = headers.get("server", "")
    if server and re.search(r"\d+\.\d+", server):
        _record("Server software version hidden", "failed")
        findings.append(_finding(
            "low", "server-version", f"Server software version is visible ({server})",
            "Your site tells everyone exactly which software version it "
            "runs. Attackers use this to look up known weaknesses.",
            "Ask your host to hide the version number (turn off "
            "'ServerTokens' / 'server signature')."))
    else:
        _record("Server software version hidden", "passed")

    # 7. X-Powered-By exposed
    if "x-powered-by" in headers:
        _record("Technology name hidden (X-Powered-By)", "failed")
        findings.append(_finding(
            "low", "x-powered-by", f"Technology name is visible ({headers['x-powered-by']})",
            "Same idea as above — free clues for attackers about what "
            "to attack.",
            "Ask your host or developer to remove the X-Powered-By header."))
    else:
        _record("Technology name hidden (X-Powered-By)", "passed")

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
                _record("Security certificate valid", "failed")
                findings.append(_finding(
                    "high", "cert-expired", "Security certificate has expired",
                    "Browsers show a scary warning page to every visitor. "
                    "Most people leave immediately.",
                    "Renew the certificate in your hosting panel right away."))
            elif days < 30:
                _record("Security certificate valid", "failed")
                findings.append(_finding(
                    "medium", "cert-expiring", f"Security certificate expires in {days} days",
                    "If it lapses, visitors will see a warning page and "
                    "leave.",
                    "Set your certificate to auto-renew, or renew it in "
                    "your hosting panel now."))
            else:
                _record("Security certificate valid", "passed")
        except Exception:
            _record("Security certificate valid", "skipped")
    else:
        _record("Security certificate valid", "skipped")

    # 9. Exposed .git folder — source code leak
    try:
        r = _get(f"https://{host}/.git/HEAD")
        if r.status_code == 200 and "ref:" in r.text:
            _record("Private code folder (.git) not public", "failed")
            findings.append(_finding(
                "high", "git", "Your website's private code folder is public",
                "Anyone can download your site's source code — including "
                "passwords or keys a developer may have left inside.",
                "Block public access to the .git folder on your server "
                "immediately, and change any passwords/keys in the code."))
        else:
            _record("Private code folder (.git) not public", "passed")
    except Exception:
        _record("Private code folder (.git) not public", "skipped")

    # 10. Exposed .env file — secrets leak
    try:
        r = _get(f"https://{host}/.env")
        if r.status_code == 200 and ("APP_KEY" in r.text or "DB_" in r.text
                                     or "SECRET" in r.text):
            _record("Secret keys file (.env) not public", "failed")
            findings.append(_finding(
                "high", "env", "A file with secret keys is public",
                "Your .env file — which usually holds database passwords "
                "and API keys — can be read by anyone.",
                "Block public access to .env right away and change every "
                "password and key listed inside it."))
        else:
            _record("Secret keys file (.env) not public", "passed")
    except Exception:
        _record("Secret keys file (.env) not public", "skipped")

    # 11. WordPress login reachable (informational)
    try:
        r = _safe_get(f"https://{host}/wp-login.php", follow=False)
        if r.status_code == 200:
            _record("WordPress login page", "info")
            findings.append(_finding(
                "info", "wp-login", "WordPress login page found",
                "Not a problem by itself — just means attackers know "
                "where to try passwords.",
                "Use a strong admin password and turn on two-factor login "
                "in WordPress."))
        else:
            _record("WordPress login page", "passed")
    except Exception:
        _record("WordPress login page", "skipped")

    # 12. nosniff — blocks browsers from guessing file types
    try:
        if headers.get('x-content-type-options', '').lower() != 'nosniff':
            _record("File-type guessing blocked (nosniff)", "failed")
            findings.append(_finding(
                "low", "nosniff-missing", "Browser file-type guessing not blocked",
                "Browsers may guess what your files are. Attackers abuse "
                "this to disguise malicious scripts as harmless files.",
                "Ask your host or developer to add the header "
                "'X-Content-Type-Options: nosniff'."))
        else:
            _record("File-type guessing blocked (nosniff)", "passed")
    except Exception:
        _record("File-type guessing blocked (nosniff)", "skipped")

    # 13. Referrer-Policy — controls what link clicks leak
    try:
        _rp = headers.get('referrer-policy', '').lower()
        if not _rp or _rp == 'unsafe-url':
            _record("Link-click data leak controlled (Referrer-Policy)", "failed")
            findings.append(_finding(
                "low", "referrer-policy-insecure", "Link clicks may leak private page addresses",
                "When visitors click links on your site, the full address "
                "of the page they came from can be sent along — sometimes "
                "including private details in the address.",
                "Ask your developer to add the header 'Referrer-Policy: "
                "strict-origin-when-cross-origin'."))
        else:
            _record("Link-click data leak controlled (Referrer-Policy)", "passed")
    except Exception:
        _record("Link-click data leak controlled (Referrer-Policy)", "skipped")

    # 14. Permissions-Policy — restricts browser features
    try:
        if 'permissions-policy' not in headers and 'feature-policy' not in headers:
            _record("Browser feature restrictions (Permissions-Policy)", "info")
            findings.append(_finding(
                "info", "permissions-policy-missing", "Browser features not restricted",
                "Your site doesn't say which browser features (camera, "
                "microphone, location) pages may use. Mostly hardening, "
                "not an emergency.",
                "A developer can add a 'Permissions-Policy' header listing "
                "only the features the site needs."))
        else:
            _record("Browser feature restrictions (Permissions-Policy)", "passed")
    except Exception:
        _record("Browser feature restrictions (Permissions-Policy)", "skipped")

    # 15. Cookie flags — Secure / HttpOnly / SameSite
    try:
        if https_ok and base is not None:
            _cookies = base.raw.headers.getlist('Set-Cookie')
            _bad_cookie = False
            for _c in _cookies:
                _cl = _c.lower()
                if 'secure' not in _cl or 'httponly' not in _cl or 'samesite' not in _cl:
                    _bad_cookie = True
                    break
            if _bad_cookie:
                _record("Login/session cookies locked down", "failed")
                findings.append(_finding(
                    "medium", "cookie-flags-missing", "Site cookies missing safety locks",
                    "The cookies your site sets (used for logins and "
                    "sessions) are missing safety locks, making them easier "
                    "to steal on insecure networks or via scripts.",
                    "Ask your developer to set Secure, HttpOnly and "
                    "SameSite on all cookies."))
            else:
                _record("Login/session cookies locked down", "passed")
        else:
            _record("Login/session cookies locked down", "skipped")
    except Exception:
        _record("Login/session cookies locked down", "skipped")

    # 16. CORS wildcard + credentials — dangerous combo
    try:
        if (headers.get('access-control-allow-origin') == '*'
                and headers.get('access-control-allow-credentials') == 'true'):
            _record("Cross-site data sharing locked down (CORS)", "failed")
            findings.append(_finding(
                "high", "cors-wildcard-credentials", "Any website can read your site's private data",
                "Your site tells browsers that ANY other website may read "
                "its responses, including logged-in user data. Attackers "
                "can exploit this to steal information.",
                "A developer must fix this urgently: never combine "
                "'Access-Control-Allow-Origin: *' with "
                "'Access-Control-Allow-Credentials: true'."))
        else:
            _record("Cross-site data sharing locked down (CORS)", "passed")
    except Exception:
        _record("Cross-site data sharing locked down (CORS)", "skipped")

    # 17. Old TLS versions still accepted
    try:
        if https_ok:
            _old_tls = False
            _tls_tested = False
            for _ver, _name in ((ssl.PROTOCOL_TLSv1, 'TLSv1'),
                                (ssl.PROTOCOL_TLSv1_1, 'TLSv1.1')):
                try:
                    _ctx = ssl.SSLContext(_ver)
                    _ctx.verify_mode = ssl.CERT_NONE
                    with socket.create_connection((host, 443), timeout=TIMEOUT) as _s:
                        with _ctx.wrap_socket(_s, server_hostname=host) as _ss:
                            _tls_tested = True
                            if _ss.version() in ('TLSv1', 'TLSv1.1'):
                                _old_tls = True
                                break
                except ssl.SSLError:
                    # The server actively rejected the old-protocol
                    # handshake: a definitive "not accepted" answer.
                    _tls_tested = True
                    continue
                except Exception:
                    # Network-level failure (timeout, reset): inconclusive,
                    # try the next version.
                    continue
            if _old_tls:
                _record("Outdated encryption versions disabled", "failed")
                findings.append(_finding(
                    "medium", "tls-old-version", "Outdated encryption (TLS 1.0/1.1) still accepted",
                    "Your server still talks the old, broken versions of "
                    "encryption. Attackers can force connections down to "
                    "these and snoop on traffic.",
                    "Ask your host to disable TLS 1.0 and 1.1, keeping "
                    "only TLS 1.2 and 1.3."))
            elif _tls_tested:
                _record("Outdated encryption versions disabled", "passed")
            else:
                # Neither legacy probe got a definitive answer
                # (network errors, not rejections): don't claim "passed".
                _record("Outdated encryption versions disabled", "skipped")
        else:
            _record("Outdated encryption versions disabled", "skipped")
    except Exception:
        _record("Outdated encryption versions disabled", "skipped")

    # 18. security.txt — contact point for researchers
    try:
        _r = _get(f"https://{host}/.well-known/security.txt")
        if _r.status_code == 404:
            _record("Security contact file (security.txt)", "info")
            findings.append(_finding(
                "info", "security-txt-missing", "No security contact file",
                "Not a vulnerability — but security researchers who find "
                "a problem on your site have no clear way to tell you.",
                "Add a small 'security.txt' file at "
                "/.well-known/security.txt with a contact email."))
        else:
            _record("Security contact file (security.txt)", "passed")
    except Exception:
        _record("Security contact file (security.txt)", "skipped")

    # 19. HTTP TRACE method enabled
    try:
        _check_url(f"https://{host}/")
        _r = requests.request("TRACE", f"https://{host}/", headers=UA,
                              timeout=TIMEOUT, allow_redirects=False)
        if _r.status_code in (200, 204):
            _record("Risky TRACE method disabled", "failed")
            findings.append(_finding(
                "low", "http-trace-enabled", "Risky TRACE method is enabled",
                "Your server answers TRACE requests, an old debugging "
                "method attackers can abuse to steal cookie data.",
                "Ask your host to disable the TRACE method."))
        else:
            _record("Risky TRACE method disabled", "passed")
    except Exception:
        _record("Risky TRACE method disabled", "skipped")

    # 20. Extra technology version headers
    try:
        _leaked = [h for h in ('x-aspnet-version', 'x-aspnetmvc-version', 'x-generator')
                   if h in headers]
        if _leaked:
            _record("Extra technology names hidden", "failed")
            findings.append(_finding(
                "low", "tech-version-headers",
                f"Technology details visible ({', '.join(_leaked)})",
                "Your site's responses name the exact technology it runs "
                "on — free clues for attackers picking what to attack.",
                "Ask your developer or host to remove these headers."))
        else:
            _record("Extra technology names hidden", "passed")
    except Exception:
        _record("Extra technology names hidden", "skipped")

    # 21. Cross-origin isolation policies
    try:
        if ('cross-origin-opener-policy' not in headers
                and 'cross-origin-embedder-policy' not in headers):
            _record("Cross-origin isolation (COOP/COEP)", "info")
            findings.append(_finding(
                "info", "cross-origin-policy-missing", "Cross-origin isolation not set",
                "Hardening only — these headers keep other sites from "
                "interacting with your pages in sneaky ways.",
                "A developer can add 'Cross-Origin-Opener-Policy' and "
                "'Cross-Origin-Embedder-Policy' headers."))
        else:
            _record("Cross-origin isolation (COOP/COEP)", "passed")
    except Exception:
        _record("Cross-origin isolation (COOP/COEP)", "skipped")

    # 22. HSTS missing includeSubDomains
    try:
        if 'strict-transport-security' in headers:
            if 'includesubdomains' not in headers['strict-transport-security'].lower():
                _record("HSTS covers all subdomains", "failed")
                findings.append(_finding(
                    "low", "hsts-weak", "Secure-connection rule skips subdomains",
                    "Your always-use-HTTPS rule doesn't cover subdomains "
                    "(like blog.yoursite.com), leaving them open to the "
                    "trick it protects against.",
                    "Add 'includeSubDomains' to the HSTS header."))
            else:
                _record("HSTS covers all subdomains", "passed")
        else:
            _record("HSTS covers all subdomains", "skipped")
    except Exception:
        _record("HSTS covers all subdomains", "skipped")

    # 23. robots.txt reveals sensitive paths
    try:
        _r = _safe_get(f"https://{host}/robots.txt", follow=False)
        if _r.status_code == 200:
            _sensitive = ['admin', 'backup', 'config', '.sql', '.bak', '.git', 'wp-admin']
            _disallows = [l for l in _r.text.lower().splitlines()
                          if l.strip().startswith('disallow:')]
            if any(s in l for l in _disallows for s in _sensitive):
                _record("robots.txt hides sensitive paths", "info")
                findings.append(_finding(
                    "info", "robots-disclosure", "robots.txt points at sensitive areas",
                    "Your robots.txt lists private areas (admin pages, "
                    "backups). Attackers read this file first to pick targets.",
                    "Don't list sensitive paths in robots.txt — block them "
                    "server-side instead."))
            else:
                _record("robots.txt hides sensitive paths", "passed")
        else:
            _record("robots.txt hides sensitive paths", "passed")
    except Exception:
        _record("robots.txt hides sensitive paths", "skipped")

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
        "checks": checks,
    }


if __name__ == "__main__":
    import json
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    print(json.dumps(scan(target), indent=2))
