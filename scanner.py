#!/usr/bin/env python3
"""SiteGuard scanner engine — website security checks.

scan(url) -> dict with score, grade, and findings. Every finding carries
a simple explanation: what it means and how to fix it.
Only scans the domain the user asked for. HTTP-level checks only.
"""
import base64
import http.client
import ipaddress
import json
import re
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

TIMEOUT = 10
UA = {"User-Agent": "SiteGuard/1.0 (security check; contact: hello@siteguard)"}
MAX_REDIRECTS = 5
# Hard cap on any downloaded body (Launch Safety Standard C21): a hostile
# target can serve an endless page; the checks never need more than this
# (script analysis already truncates at 1M chars).
MAX_BODY_BYTES = 5 * 1024 * 1024

DEDUCT = {"high": 25, "medium": 15, "low": 5, "info": 0}


def _finding(severity, key, title, meaning, fix):
    return {"severity": severity, "key": key, "title": title,
            "what_it_means": meaning, "how_to_fix": fix}


class UnsafeTarget(ValueError):
    """Raised when a scan target is not a public website."""


def _resolve_public(host):
    """Resolve a host ONCE and return its IPs — only if EVERY resolved
    address is a public (global) IP.

    Blocks private networks, loopback, link-local (incl. cloud metadata
    169.254.169.254), and other non-routable addresses — SSRF guard.
    Raises UnsafeTarget for anything that is not a public website.
    """
    if not host or len(host) > 253:
        raise UnsafeTarget(
            "That address isn't a public website — only real, public "
            "sites can be scanned.")
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError):
        raise UnsafeTarget(
            "That address isn't a public website — only real, public "
            "sites can be scanned.")
    ips = []
    for info in infos or []:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            raise UnsafeTarget(
                "That address isn't a public website — only real, public "
                "sites can be scanned.")
        if not ip.is_global:
            raise UnsafeTarget(
                "That address isn't a public website — only real, public "
                "sites can be scanned.")
        if ip not in ips:
            ips.append(ip)
    if not ips:
        raise UnsafeTarget(
            "That address isn't a public website — only real, public "
            "sites can be scanned.")
    return ips


def _is_public_host(host):
    """True only if the host resolves exclusively to public IPs."""
    try:
        _resolve_public(host)
        return True
    except UnsafeTarget:
        return False


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


class _CaseInsensitiveHeaders:
    """Minimal case-insensitive header mapping with the requests
    semantics the checks rely on: .get() returns the last value,
    .getlist() returns every value (Set-Cookie), .items() lists pairs."""

    def __init__(self, pairs=()):
        self._pairs = [(str(k), str(v)) for k, v in pairs]

    def get(self, name, default=None):
        lname = name.lower()
        for k, v in reversed(self._pairs):
            if k.lower() == lname:
                return v
        return default

    def getlist(self, name):
        lname = name.lower()
        return [v for k, v in self._pairs if k.lower() == lname]

    def __contains__(self, name):
        return self.get(name) is not None

    def __getitem__(self, name):
        value = self.get(name)
        if value is None:
            raise KeyError(name)
        return value

    def items(self):
        return list(self._pairs)

    def __repr__(self):
        return repr(dict(self._pairs))


class _RawShim:
    """Stands in for requests' .raw — the checks only use
    .raw.headers.getlist('Set-Cookie')."""

    def __init__(self, headers):
        self.headers = headers


class _PinnedResponse:
    """Thin stand-in for a requests.Response, exposing exactly what the
    checks use: status_code, headers, text, content, url (and .raw)."""

    def __init__(self, status_code, headers, body, url):
        self.status_code = status_code
        self.headers = headers
        self.content = body
        self.url = url
        self.raw = _RawShim(headers)

    @property
    def text(self):
        return self.content.decode("utf-8", "replace")


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """HTTP connection that dials a pre-validated IP — never DNS."""

    def __init__(self, *args, _sg_ip=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._sg_ip = _sg_ip

    def connect(self):
        self.sock = socket.create_connection(
            (self._sg_ip, self.port), self.timeout, self.source_address)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if self._tunnel_host:
            self._tunnel()


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS variant: TCP goes to the validated IP, while TLS SNI and
    certificate hostname verification keep the original hostname."""

    def __init__(self, *args, _sg_ip=None, _sg_sni=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._sg_ip = _sg_ip
        self._sg_sni = _sg_sni

    def connect(self):
        raw = socket.create_connection(
            (self._sg_ip, self.port), self.timeout, self.source_address)
        raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if self._tunnel_host:
            self.sock = raw
            self._tunnel()
            raw = self.sock
        context = self._context or ssl.create_default_context()
        self.sock = context.wrap_socket(raw, server_hostname=self._sg_sni)


def _pinned_once(method, url, headers=None):
    """One HTTP request with the connection PINNED to a validated IP
    (resolve-validate-pin, Launch Safety Standard A5).

    The host is resolved exactly once here, every resolved address must
    be global, and the socket connects to one of those very addresses —
    there is no second DNS lookup at connect time for a rebinding
    attacker to poison. The Host header and TLS SNI keep the original
    hostname. The body is read under the MAX_BODY_BYTES hard cap (C21).
    """
    parts = urlparse(url)
    if parts.scheme not in ("http", "https"):
        raise UnsafeTarget("Only http:// and https:// addresses can be scanned.")
    host = parts.hostname
    ips = _resolve_public(host)
    try:
        port = parts.port
    except ValueError:
        port = None
    default_port = 443 if parts.scheme == "https" else 80
    host_header = host if port in (None, default_port) else f"{host}:{port}"
    hdrs = {"Host": host_header, "Connection": "close"}
    if headers:
        hdrs.update(headers)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    ip = str(ips[0])
    if parts.scheme == "https":
        conn = _PinnedHTTPSConnection(host, port or default_port,
                                      timeout=TIMEOUT,
                                      _sg_ip=ip, _sg_sni=host)
    else:
        conn = _PinnedHTTPConnection(host, port or default_port,
                                     timeout=TIMEOUT, _sg_ip=ip)
    try:
        conn.request(method, path, headers=hdrs)
        resp = conn.getresponse()
        body = b""
        while len(body) < MAX_BODY_BYTES:
            chunk = resp.read(min(65536, MAX_BODY_BYTES - len(body)))
            if not chunk:
                break
            body += chunk
        return _PinnedResponse(resp.status,
                               _CaseInsensitiveHeaders(resp.getheaders()),
                               body, url)
    finally:
        conn.close()


def _request(method, url, headers=None):
    """A single pinned request with no redirect following (TRACE and
    OPTIONS probes). Validation happens inside _pinned_once."""
    hdrs = dict(UA)
    if headers:
        hdrs.update(headers)
    return _pinned_once(method, url, hdrs)


def _safe_get(url, max_redirects=MAX_REDIRECTS, follow=True, headers=None):
    """GET with optional manual redirect-following; every hop is
    re-validated and pinned.

    Automatic redirect-following would let a hostile site bounce us onto
    an internal address, so we follow redirects ourselves; each hop goes
    through _check_url and gets its own resolve-validate-pin fetch.
    """
    hdrs = dict(UA)
    if headers:
        hdrs.update(headers)
    for _ in range(max_redirects + 1):
        _check_url(url)
        r = _pinned_once("GET", url, hdrs)
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


def _get(url, headers=None):
    return _safe_get(url, headers=headers)


def _jwt_role(token):
    """Read the 'role' claim out of a JWT payload (no verification — the
    payload is public to anyone who can see the token, which is the point)."""
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload.encode()))
        return str(data.get("role", ""))
    except Exception:
        return ""


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
        _r = _request("TRACE", f"https://{host}/", headers=UA)
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

    # 24. Sensitive admin/debug paths directly reachable (OWASP A01)
    try:
        _admin_paths = ["/server-status", "/server-info", "/phpinfo.php",
                        "/.DS_Store"]
        _exposed = []
        for _p in _admin_paths:
            _r = _safe_get(f"https://{host}{_p}", follow=False)
            if _r.status_code == 200 and len(_r.content) > 200:
                _exposed.append(_p)
        if _exposed:
            _record("Sensitive admin paths hidden", "failed")
            findings.append(_finding(
                "medium", "admin-paths",
                "Admin/debug page reachable: " + ", ".join(_exposed),
                "Debug or server-status pages are publicly reachable. They "
                "leak internals and sometimes allow deeper access.",
                "Disable or password-protect these pages "
                "(/server-status, /server-info, phpinfo)."))
        else:
            _record("Sensitive admin paths hidden", "passed")
    except Exception:
        _record("Sensitive admin paths hidden", "skipped")

    # 25. Visible technology versions (OWASP A06)
    try:
        _html = (base.text if base is not None else "")
        _versions = []
        _m = re.search(
            r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)',
            _html, re.I)
        if _m:
            _versions.append("generator: " + _m.group(1).strip()[:60])
        for _lib, _pat in (("jQuery", r"jquery[/-](\d+\.\d+[\.\d]*)"),
                           ("Bootstrap", r"bootstrap[/-](\d+\.\d+[\.\d]*)"),
                           ("WordPress", r"wp-(?:content|includes)/"),
                           ("PHP", r"\.php[?\"']")):
            if re.search(_pat, _html, re.I):
                _versions.append(_lib)
        _versions = sorted(set(_versions))
        if _versions:
            _record("Outdated tech versions visible", "info")
            findings.append(_finding(
                "info", "tech-versions",
                "Technology fingerprints visible: " + ", ".join(_versions),
                "Your pages reveal which software they run on. Attackers "
                "match these against known vulnerabilities.",
                "Remove generator tags and version strings; then check the "
                "versions you run against a vulnerability database."))
        else:
            _record("Outdated tech versions visible", "passed")
    except Exception:
        _record("Outdated tech versions visible", "skipped")

    # 26. Debug page exposed (phpinfo.php)
    try:
        _r = _get(f"https://{host}/phpinfo.php")
        if _r.status_code == 200 and 'phpinfo()' in _r.text.lower():
            _record("Debug page exposed (phpinfo.php)", "failed")
            findings.append(_finding(
                "medium", "phpinfo-exposed",
                "PHP debug page is publicly accessible",
                "A debug page shows attackers your exact server setup, which "
                "helps them pick an attack.",
                "Delete phpinfo.php or block it in your server settings."))
        else:
            _record("Debug page exposed (phpinfo.php)", "passed")
    except Exception:
        _record("Debug page exposed (phpinfo.php)", "skipped")

    # 27. Server status page exposed
    try:
        _r = _get(f"https://{host}/server-status")
        if (_r.status_code == 200
                and ('apache status' in _r.text.lower()
                     or 'server-status' in _r.text.lower())):
            _record("Server status page exposed", "failed")
            findings.append(_finding(
                "medium", "server-status",
                "Server status page is publicly accessible",
                "A live status page shows attackers how busy your server is "
                "and what it is running.",
                "Turn off the server-status page in your web server settings."))
        else:
            _record("Server status page exposed", "passed")
    except Exception:
        _record("Server status page exposed", "skipped")
    # 28. Mac junk file exposed (.DS_Store)
    try:
        _r = _get(f"https://{host}/.DS_Store")
        if _r.status_code == 200 and len(_r.text) > 100:
            _record("Mac junk file exposed (.DS_Store)", "failed")
            findings.append(_finding(
                "low", "ds-store",
                ".DS_Store file is publicly accessible",
                "A leftover Mac system file can reveal the names of files "
                "and folders on your server.",
                "Delete .DS_Store files from your website's folders."))
        else:
            _record("Mac junk file exposed (.DS_Store)", "passed")
    except Exception:
        _record("Mac junk file exposed (.DS_Store)", "skipped")

    # --- Reel risks (2026-10-10): the four ways a vibe-coded app can cost
    # its owner real money before it has a single user. Checks 29-33.

    # Page source pool: homepage HTML + up to 3 same-host script files,
    # because bundled JS is where backend keys actually live.
    _src = (base.text if base is not None else "") or ""
    try:
        _fetched = 0
        for _s in re.findall(r'<script[^>]+src=["\']([^"\']+)', _src, re.I):
            if _fetched >= 3 or len(_src) > 1_000_000:
                break
            _u = requests.compat.urljoin(f"https://{host}/", _s)
            if urlparse(_u).hostname != host:
                continue
            _fetched += 1
            try:
                _r = _get(_u)
                if _r.status_code == 200:
                    _src += "\n" + (_r.text or "")
            except Exception:
                continue
    except Exception:
        pass

    _sb_urls = sorted(set(re.findall(
        r"https://[a-z0-9-]+\.supabase\.co", _src)))
    _sb_anon = ""
    _sb_service = False
    for _t in re.findall(
            r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", _src):
        _role = _jwt_role(_t)
        if _role == "service_role":
            _sb_service = True
        elif _role == "anon" and not _sb_anon:
            _sb_anon = _t
    if not _sb_service:
        _sb_service = bool(re.search(
            r"service_role[\"']?\s*[:=]\s*[\"']eyJ", _src))

    # 29. Supabase service-role (admin) key leaked in page source — this
    # key bypasses every database protection the service offers.
    if _sb_service:
        _record("Backend admin keys not leaked in page source", "failed")
        findings.append(_finding(
            "high", "supabase-service-key",
            "Database admin key is public in your site's code",
            "Your site's code contains a Supabase 'service_role' key. "
            "That key ignores all database access rules — anyone who "
            "views your page source can read, change or delete your "
            "entire database.",
            "Remove the service_role key from the website code right "
            "away and rotate it in Supabase (Project Settings -> API). "
            "Browsers must only ever use the 'anon' key, with Row Level "
            "Security turned on."))
    else:
        _record("Backend admin keys not leaked in page source", "passed")

    # 30. Public database readable — Row Level Security test. Uses ONLY
    # the public anon key the site itself hands to every visitor, reads
    # at most 1 row per table (3 tables max), and never records row
    # values — only table and column names.
    if _sb_urls and _sb_anon:
        try:
            _proj = _sb_urls[0]
            _hdr = {"apikey": _sb_anon,
                    "Authorization": f"Bearer {_sb_anon}"}
            _tables = []
            _r = _get(f"{_proj}/rest/v1/", headers=_hdr)
            if _r.status_code == 200:
                _spec = json.loads(_r.text)
                for _p in (_spec.get("paths") or {}):
                    if _p != "/" and not _p.startswith("/rpc"):
                        _tables.append(_p.lstrip("/"))
            _sens_cols = {"email", "name", "full_name", "phone", "address",
                          "password", "user_id", "first_name", "last_name",
                          "dob", "date_of_birth"}
            _open_tables, _sens_tables = [], []
            for _t in _tables[:3]:
                try:
                    _rr = _get(f"{_proj}/rest/v1/{_t}?select=*&limit=1",
                               headers=_hdr)
                except Exception:
                    continue
                if _rr.status_code != 200:
                    continue
                try:
                    _rows = json.loads(_rr.text)
                except Exception:
                    continue
                if (isinstance(_rows, list) and _rows
                        and isinstance(_rows[0], dict)):
                    _open_tables.append(_t)
                    if _sens_cols & {k.lower() for k in _rows[0]}:
                        _sens_tables.append(_t)
            if _open_tables:
                _record("Database not readable by the public (RLS)",
                        "failed")
                _worst = _sens_tables or _open_tables
                findings.append(_finding(
                    "high" if _sens_tables else "medium",
                    "supabase-data-open",
                    "Your database can be read by anyone "
                    f"(table: {_worst[0]})",
                    "Using only the public key your own website gives "
                    "every visitor, this scan read real rows from your "
                    "database table '" + _worst[0] + "'. Row Level "
                    "Security is off or missing, so the same request "
                    "works for anyone on the internet — a scan of 1,645 "
                    "AI-built apps found about 1 in 10 readable this "
                    "way (CVE-2025-48757). No row values were stored "
                    "in this report.",
                    "In Supabase: turn ON Row Level Security for every "
                    "table (Table Editor -> RLS) and add policies that "
                    "only let users see their own rows. Then test by "
                    "opening your database API with just the anon key."))
            else:
                _record("Database not readable by the public (RLS)",
                        "passed")
        except Exception:
            _record("Database not readable by the public (RLS)", "skipped")
    else:
        _record("Database not readable by the public (RLS)", "skipped")

    # 31. Images missing alt text — the accessibility gap behind ADA
    # lawsuits against small sites.
    try:
        _html = (base.text if base is not None else "") or ""
        _imgs = re.findall(r"<img\b[^>]*>", _html, re.I)
        _noalt = [t for t in _imgs if not re.search(r"\balt\s*=", t, re.I)]
        if _noalt:
            _record("Images have text descriptions (alt text)", "failed")
            findings.append(_finding(
                "medium", "img-alt-missing",
                f"{len(_noalt)} of {len(_imgs)} images have no text "
                "description",
                "Images without alt text are invisible to screen "
                "readers used by blind visitors. Missing basics like "
                "this are behind thousands of accessibility (ADA) "
                "lawsuits every year — including against companies "
                "with no revenue yet.",
                "Add a short alt='...' description to every meaningful "
                "image (alt='' is fine for purely decorative ones). "
                "Most site builders and AI tools can add these in bulk."))
        else:
            _record("Images have text descriptions (alt text)", "passed")
    except Exception:
        _record("Images have text descriptions (alt text)", "skipped")

    # 32. No caching on static files — every visit (or bot) re-downloads
    # everything; this is how a $73k bandwidth bill happens.
    try:
        _html = (base.text if base is not None else "") or ""
        _assets = []
        for _m in re.findall(
                r"(?:src|href)=[\"']([^\"']+\.(?:css|js|png|jpe?g|webp|"
                r"svg|gif)(?:\?[^\"']*)?)[\"']", _html, re.I):
            _u = requests.compat.urljoin(f"https://{host}/", _m)
            if urlparse(_u).hostname == host and _u not in _assets:
                _assets.append(_u)
            if len(_assets) >= 5:
                break
        if not _assets:
            _record("Files cached, not re-downloaded every visit",
                    "skipped")
        else:
            _checked, _uncached, _big_uncached = 0, [], []
            for _u in _assets:
                try:
                    _r = _get(_u)
                except Exception:
                    continue
                _checked += 1
                _h = {k.lower(): v for k, v in _r.headers.items()}
                _cc = _h.get("cache-control", "").lower()
                _cached = ("max-age" in _cc or "immutable" in _cc
                           or "public" in _cc or "expires" in _h
                           or "etag" in _h)
                if not _cached:
                    _uncached.append(_u)
                    try:
                        _size = int(_h.get("content-length", "0"))
                    except ValueError:
                        _size = 0
                    if _size >= 1_000_000:
                        _big_uncached.append(_u)
            if _checked == 0:
                _record("Files cached, not re-downloaded every visit",
                        "skipped")
            elif _uncached and (len(_uncached) == _checked
                                or _big_uncached):
                _record("Files cached, not re-downloaded every visit",
                        "failed")
                findings.append(_finding(
                    "low", "no-cache-headers",
                    "Your files are re-downloaded on every single visit",
                    "None of your site's files tell browsers or CDNs to "
                    "cache them, so every visit — human or bot — pulls "
                    "them again in full. One repeatedly-hit file with "
                    "no caching, compression or spend alerts is how "
                    "sites end up with surprise bandwidth bills in the "
                    "tens of thousands of dollars.",
                    "Serve static files (images, CSS, JS) with a "
                    "Cache-Control header (e.g. 'public, max-age=31536000, "
                    "immutable' for versioned files), put a CDN like "
                    "Cloudflare in front, turn on hotlink protection, "
                    "and set a bandwidth/spend alert with your host."))
            else:
                _record("Files cached, not re-downloaded every visit",
                        "passed")
    except Exception:
        _record("Files cached, not re-downloaded every visit", "skipped")

    # 33. Phone/SMS signup with no visible consent — TCPA risk. Info
    # only: consent records can't be proven from outside, so flag the
    # risk, never accuse.
    try:
        _html = ((base.text if base is not None else "") or "")
        _low = _html.lower()
        _phone_field = bool(
            re.search(r"type=[\"']tel[\"']", _low)
            or re.search(r"<input[^>]+(?:name|id)=[\"'][^\"']*"
                         r"(phone|mobile|sms)", _low))
        if not _phone_field:
            _record("Text-message signup asks for consent", "passed")
        else:
            _consent = (
                any(w in _low for w in (
                    "consent", "message and data rates",
                    "agree to receive", "terms and conditions"))
                or "type=\"checkbox\"" in _low
                or "type='checkbox'" in _low)
            if _consent:
                _record("Text-message signup asks for consent", "passed")
            else:
                _record("Text-message signup asks for consent", "info")
                findings.append(_finding(
                    "info", "sms-consent-risk",
                    "Phone number collected with no visible consent step",
                    "Your site collects phone numbers but shows no "
                    "consent wording, checkbox or terms next to the "
                    "form. In the US, marketing texts without prior "
                    "written consent carry statutory damages of $500 "
                    "per message (TCPA) — 10,000 launch texts can "
                    "become a $5M claim on paper. This scan can't see "
                    "your backend records, so treat this as a prompt "
                    "to check, not a verdict.",
                    "Add an unticked consent checkbox with clear "
                    "wording ('I agree to receive marketing texts...'), "
                    "keep a record of each consent (who, when, the "
                    "exact wording), and never text numbers collected "
                    "without it."))
    except Exception:
        _record("Text-message signup asks for consent", "skipped")

    # --- Reel risks, part 2 (2026-10-10): the legal basics. Getting sued
    # over a vibe-coded app usually starts with missing/copy-paste legal
    # pages, not with a hacker. Checks 34-39.

    def _fetch_legal(paths, must_mention=None):
        """First candidate path that answers 200 with a real page wins."""
        for _p in paths:
            try:
                _r = _get(f"https://{host}{_p}")
            except Exception:
                continue
            _text = (_r.text or "")
            if _r.status_code == 200 and len(_text) > 200:
                if must_mention and must_mention not in _text.lower():
                    continue
                return _text[:200_000]
        return ""

    _privacy_text = _fetch_legal(
        ["/privacy", "/privacy-policy", "/privacy.html"], "privacy")
    _terms_text = _fetch_legal(
        ["/terms", "/terms-of-service", "/terms.html", "/tos"])

    # 34. Privacy policy page exists
    if _privacy_text:
        _record("Privacy policy page exists", "passed")
    else:
        _record("Privacy policy page exists", "failed")
        findings.append(_finding(
            "medium", "privacy-missing", "No privacy policy page found",
            "No page at /privacy or /privacy-policy. The moment your "
            "site collects anything — emails, accounts, analytics — "
            "privacy laws (GDPR, India's DPDP Act, California's CCPA) "
            "require you to say what you collect and why. Missing "
            "legal pages are the most common reason small apps get "
            "sued or pulled from app stores.",
            "Add a /privacy page that names what data you collect, "
            "who you share it with (hosting, payments, analytics, AI "
            "providers), how long you keep it, and how users can ask "
            "for deletion. Free attorney-drafted templates exist "
            "(e.g. the CC0 'legal-templates' repo on GitHub) — but "
            "fill in every placeholder with YOUR details."))

    # 35. Terms page exists
    if _terms_text:
        _record("Terms page exists", "passed")
    else:
        _record("Terms page exists", "failed")
        findings.append(_finding(
            "medium", "terms-missing", "No terms page found",
            "No page at /terms or /terms-of-service. Without terms "
            "you have no agreed rules for accounts, payments or "
            "acceptable use — and no liability limit standing "
            "between a user dispute and your own pocket.",
            "Add a /terms page covering subscriptions and billing "
            "(if you charge), user content, acceptable use, "
            "intellectual property, disclaimers, limitation of "
            "liability, termination and governing law."))

    # 36. Legal pages actually customised + complete — template
    # placeholders ([Company Name], lorem ipsum, {{...}}) are the
    # copy-paste tell, and a 3-line terms page protects nobody.
    _legal_all = (_privacy_text + "\n" + _terms_text)
    if not _legal_all.strip():
        _record("Legal pages customised and complete", "skipped")
    else:
        _ph = (re.search(r"\[(?:company|insert|your|name|date|address|"
                         r"email|website)[^\]]*\]", _legal_all, re.I)
               or re.search(r"lorem ipsum", _legal_all, re.I)
               or re.search(r"\{\{[^}]+\}\}", _legal_all)
               or re.search(r"\bXYZ (?:Company|Inc|LLC)\b", _legal_all)
               or re.search(r"\[COMPANY[^\]]*\]", _legal_all))
        if _ph:
            _record("Legal pages customised and complete", "failed")
            findings.append(_finding(
                "medium", "legal-placeholder",
                "Your legal pages still contain template placeholders",
                "Your privacy/terms pages still say things like "
                "'[Company Name]' or contain template filler. That "
                "means the document was copy-pasted and never "
                "customised — a court (and an app-store reviewer) "
                "treats it as decoration, not protection.",
                "Search your legal pages for '[' brackets, '{{ }}' "
                "markers and filler text, and replace every one with "
                "your real business name, address and details."))
        elif _terms_text:
            _tl = _terms_text.lower()
            _groups = {
                "billing/subscriptions": ("billing", "subscription",
                                          "payment", "price"),
                "liability limit": ("limitation of liability", "liable",
                                    "liability"),
                "termination": ("terminat",),
                "governing law": ("governing law", "jurisdiction"),
                "intellectual property": ("intellectual property",),
            }
            _missing = [g for g, words in _groups.items()
                        if not any(w in _tl for w in words)]
            if len(_missing) >= 3:
                _record("Legal pages customised and complete", "failed")
                findings.append(_finding(
                    "low", "terms-thin",
                    "Terms page is missing key protections: "
                    + ", ".join(_missing),
                    "Your terms page exists but skips the clauses "
                    "that actually protect you when something goes "
                    "wrong — billing disputes, liability and how the "
                    "agreement ends.",
                    "Add the missing sections. Attorney-drafted free "
                    "templates (CC0) cover all of them — customise "
                    "every placeholder to your business."))
            else:
                _record("Legal pages customised and complete", "passed")
        else:
            _record("Legal pages customised and complete", "passed")

    # 37. Privacy policy says who receives the data — the processors
    # (hosting, payments, analytics, AI providers). Silence here is
    # what regulators ask about first.
    if not _privacy_text:
        _record("Privacy policy names who receives data", "skipped")
    else:
        _pl = _privacy_text.lower()
        if any(w in _pl for w in ("third part", "service provider",
                                  "processor", "we share", "shared with",
                                  "analytics", "advertising partner")):
            _record("Privacy policy names who receives data", "passed")
        else:
            _record("Privacy policy names who receives data", "failed")
            findings.append(_finding(
                "info", "privacy-no-processors",
                "Privacy policy never says who receives user data",
                "Your privacy policy doesn't mention third parties, "
                "service providers or processors at all. In reality "
                "your host, payment provider, analytics and any AI "
                "APIs you call all receive user data — a policy that "
                "hides that is worse than one that lists them.",
                "List every service that receives user data (hosting, "
                "payments like Stripe, analytics, AI providers) and "
                "what each receives. If you send user content to AI "
                "APIs, say so — and whether it's used for training."))

    # 38. Trackers present but no cookie-consent signal — the classic
    # GDPR/ePrivacy fine starter.
    try:
        _trackers = [name for name, pat in (
            ("Google Analytics", r"googletagmanager\.com|google-analytics"
             r"|gtag\(|G-[A-Z0-9]{8,}"),
            ("Meta/Facebook pixel", r"connect\.facebook\.net|fbq\("),
            ("Hotjar", r"hotjar\.com|hjBootstrap"),
            ("Microsoft Clarity", r"clarity\.ms"),
            ("Mixpanel", r"mixpanel\.com"),
            ("Segment", r"cdn\.segment\.com"),
        ) if re.search(pat, _src, re.I)]
        if not _trackers:
            _record("Cookie consent shown when trackers run", "passed")
        else:
            _low_src = _src.lower()
            _consent_ui = (
                any(w in _low_src for w in (
                    "cookiebot", "onetrust", "termly", "cookie-consent",
                    "cookieconsent", "gdpr-consent", "consent-banner"))
                or ("cookie" in _low_src
                    and ("accept" in _low_src or "consent" in _low_src)))
            if _consent_ui:
                _record("Cookie consent shown when trackers run",
                        "passed")
            else:
                _record("Cookie consent shown when trackers run",
                        "failed")
                findings.append(_finding(
                    "low", "cookie-consent-missing",
                    "Tracking runs with no cookie consent: "
                    + ", ".join(_trackers),
                    "Your site loads trackers (" + ", ".join(_trackers)
                    + ") but shows no cookie-consent banner or settings. "
                    "In the EU/UK that's an ePrivacy/GDPR violation "
                    "before you've made a single sale — and 'the AI "
                    "built it that way' is not a defence.",
                    "Add a cookie-consent banner that blocks trackers "
                    "until the visitor accepts (free tools: Termly, "
                    "Cookiebot free tier, or the vanilla-cookieconsent "
                    "library), and list the trackers in your privacy "
                    "policy."))
    except Exception:
        _record("Cookie consent shown when trackers run", "skipped")

    # 39. Supabase storage buckets left public — the database reel's
    # other half. Public buckets are sometimes intentional (site
    # images), so this is info: name them, warn what's at stake.
    if _sb_urls and _sb_anon:
        try:
            _r = _get(f"{_sb_urls[0]}/storage/v1/bucket",
                      headers={"apikey": _sb_anon,
                               "Authorization": f"Bearer {_sb_anon}"})
            _buckets = []
            if _r.status_code == 200:
                _data = json.loads(_r.text)
                if isinstance(_data, list):
                    _buckets = [str(b.get("name")) for b in _data
                                if isinstance(b, dict) and b.get("public")]
            if _buckets:
                _record("Cloud storage buckets not public", "info")
                findings.append(_finding(
                    "info", "supabase-public-bucket",
                    "Public file-storage buckets: "
                    + ", ".join(_buckets[:3]),
                    "These Supabase storage buckets are set to public — "
                    "anyone with a file's address can open it without "
                    "logging in. That's fine for site images and "
                    "avatars; it's a breach waiting to happen for "
                    "uploads, documents or anything user-specific. "
                    "This scan lists bucket names only, never files.",
                    "In Supabase Storage, set buckets that hold user "
                    "files to private and serve them through signed "
                    "URLs. Keep public only what you'd happily post "
                    "on your homepage."))
            else:
                _record("Cloud storage buckets not public", "passed")
        except Exception:
            _record("Cloud storage buckets not public", "skipped")
    else:
        _record("Cloud storage buckets not public", "skipped")

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
