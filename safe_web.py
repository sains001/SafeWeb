#!/usr/bin/env python3
"""
SafeWebAudit - pemindai keamanan web dasar non-eksploitatif.

Gunakan hanya pada website yang Anda miliki atau punya izin tertulis untuk diuji.
Tool ini melakukan request ringan dan tidak mencoba mengeksploitasi celah.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from html.parser import HTMLParser
from http.cookiejar import CookieJar
from typing import Iterable


DEFAULT_TIMEOUT = 10
USER_AGENT = "SafeWebAudit/1.0 (+authorized security check)"

SECURITY_HEADERS = {
    "strict-transport-security": "HSTS membantu memaksa browser memakai HTTPS.",
    "content-security-policy": "CSP membantu membatasi sumber script/content.",
    "x-frame-options": "X-Frame-Options membantu mencegah clickjacking.",
    "x-content-type-options": "X-Content-Type-Options mencegah MIME sniffing.",
    "referrer-policy": "Referrer-Policy mengurangi kebocoran URL/referrer.",
    "permissions-policy": "Permissions-Policy membatasi akses fitur browser.",
}

SENSITIVE_PATHS = [
    "/.env",
    "/.git/HEAD",
    "/backup.zip",
    "/backup.tar.gz",
    "/database.sql",
    "/phpinfo.php",
    "/server-status",
    "/wp-config.php.bak",
]


@dataclass
class Finding:
    severity: str
    title: str
    detail: str
    evidence: str = ""


@dataclass
class ScanResult:
    target: str
    final_url: str = ""
    status: int | None = None
    findings: list[Finding] = field(default_factory=list)
    info: dict[str, object] = field(default_factory=dict)

    def add(self, severity: str, title: str, detail: str, evidence: str = "") -> None:
        self.findings.append(Finding(severity, title, detail, evidence))


class PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict[str, object]] = []
        self.scripts: list[str] = []
        self.links: list[str] = []
        self.current_form: dict[str, object] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_dict = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            self.current_form = {
                "method": attrs_dict.get("method", "get").lower(),
                "action": attrs_dict.get("action", ""),
                "inputs": [],
            }
            self.forms.append(self.current_form)
        elif tag == "input" and self.current_form is not None:
            self.current_form["inputs"].append(attrs_dict)
        elif tag == "script" and attrs_dict.get("src"):
            self.scripts.append(attrs_dict["src"])
        elif tag in {"img", "iframe", "link"}:
            src = attrs_dict.get("src") or attrs_dict.get("href")
            if src:
                self.links.append(src)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self.current_form = None


class HeaderCapturingRedirect(urllib.request.HTTPRedirectHandler):
    def http_error_301(self, req, fp, code, msg, headers):
        return super().http_error_301(req, fp, code, msg, headers)

    http_error_302 = http_error_303 = http_error_307 = http_error_308 = http_error_301


def normalize_url(raw: str) -> str:
    parsed = urllib.parse.urlparse(raw if "://" in raw else f"https://{raw}")
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Skema URL harus http atau https.")
    if not parsed.netloc:
        raise ValueError("URL target tidak valid.")
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", parsed.query, ""))


def build_opener(cookie_jar: CookieJar) -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(cookie_jar),
        HeaderCapturingRedirect,
    )


def request(
    opener: urllib.request.OpenerDirector,
    url: str,
    method: str = "GET",
    timeout: int = DEFAULT_TIMEOUT,
) -> tuple[int, str, dict[str, str], bytes]:
    req = urllib.request.Request(
        url,
        method=method,
        headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml,*/*"},
    )
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read(1_000_000)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            return resp.status, resp.geturl(), headers, body
    except urllib.error.HTTPError as exc:
        body = exc.read(200_000)
        headers = {k.lower(): v for k, v in exc.headers.items()}
        return exc.code, exc.geturl(), headers, body


def check_security_headers(result: ScanResult, headers: dict[str, str], scheme: str) -> None:
    for header, reason in SECURITY_HEADERS.items():
        if header not in headers:
            severity = "medium" if header in {"content-security-policy", "strict-transport-security"} else "low"
            if header == "strict-transport-security" and scheme != "https":
                continue
            result.add(severity, f"Header hilang: {header}", reason)

    csp = headers.get("content-security-policy", "")
    if csp and ("'unsafe-inline'" in csp or "*" in csp):
        result.add("low", "CSP terlalu longgar", "CSP ditemukan, tetapi masih memakai wildcard atau unsafe-inline.", csp)

    server = headers.get("server")
    powered_by = headers.get("x-powered-by")
    if server:
        result.add("info", "Server header terbuka", "Pertimbangkan menyamarkan detail versi server bila terlalu spesifik.", server)
    if powered_by:
        result.add("low", "X-Powered-By terbuka", "Header ini dapat membocorkan teknologi backend.", powered_by)


def check_cookies(result: ScanResult, cookie_jar: CookieJar, https: bool) -> None:
    for cookie in cookie_jar:
        missing = []
        if https and not cookie.secure:
            missing.append("Secure")
        rest = {k.lower(): v for k, v in cookie._rest.items()}
        if "httponly" not in rest:
            missing.append("HttpOnly")
        if "samesite" not in rest:
            missing.append("SameSite")
        if missing:
            result.add(
                "medium",
                f"Cookie tanpa flag penting: {cookie.name}",
                "Cookie session/auth sebaiknya memakai flag proteksi sesuai konteks.",
                ", ".join(missing),
            )


def check_forms(result: ScanResult, html: bytes, base_url: str) -> None:
    parser = PageParser()
    try:
        parser.feed(html.decode("utf-8", errors="ignore"))
    except Exception as exc:
        result.add("info", "HTML parser gagal membaca sebagian halaman", str(exc))
        return

    result.info["forms"] = len(parser.forms)
    result.info["external_scripts"] = len([s for s in parser.scripts if is_external(base_url, s)])

    for form in parser.forms:
        method = str(form.get("method", "get")).lower()
        inputs = form.get("inputs", [])
        input_names = {str(i.get("name", "")).lower() for i in inputs if isinstance(i, dict)}
        has_csrf = any("csrf" in name or "token" in name for name in input_names)
        if method == "post" and not has_csrf:
            result.add(
                "medium",
                "Form POST tanpa token CSRF yang terdeteksi",
                "Tidak terlihat input bernama csrf/token. Verifikasi manual karena framework bisa memakai mekanisme lain.",
                str(form.get("action", "")),
            )

    insecure_assets = [u for u in parser.scripts + parser.links if str(u).startswith("http://")]
    if urllib.parse.urlparse(base_url).scheme == "https" and insecure_assets:
        result.add(
            "medium",
            "Mixed content terdeteksi",
            "Halaman HTTPS memuat asset melalui HTTP.",
            ", ".join(insecure_assets[:5]),
        )


def is_external(base_url: str, maybe_url: str) -> bool:
    parsed_base = urllib.parse.urlparse(base_url)
    parsed = urllib.parse.urlparse(urllib.parse.urljoin(base_url, maybe_url))
    return bool(parsed.netloc and parsed.netloc != parsed_base.netloc)


def check_tls(result: ScanResult, url: str, timeout: int) -> None:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https":
        result.add("high", "Website tidak memakai HTTPS", "Gunakan HTTPS untuk melindungi data dan session pengguna.")
        return

    hostname = parsed.hostname
    if not hostname:
        return
    port = parsed.port or 443
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                result.info["tls_version"] = ssock.version()
                not_after = cert.get("notAfter")
                if not_after:
                    expires = dt.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days_left = (expires - dt.datetime.utcnow()).days
                    result.info["certificate_expires"] = expires.isoformat() + "Z"
                    if days_left < 0:
                        result.add("high", "Sertifikat TLS sudah kedaluwarsa", "Perbarui sertifikat TLS.", not_after)
                    elif days_left <= 30:
                        result.add("medium", "Sertifikat TLS hampir kedaluwarsa", f"Sisa sekitar {days_left} hari.", not_after)
    except Exception as exc:
        result.add("medium", "Pemeriksaan TLS gagal", "Verifikasi konfigurasi TLS secara manual.", str(exc))


def check_options(result: ScanResult, opener: urllib.request.OpenerDirector, url: str, timeout: int) -> None:
    try:
        status, _, headers, _ = request(opener, url, "OPTIONS", timeout)
    except Exception as exc:
        result.add("info", "OPTIONS tidak dapat diperiksa", str(exc))
        return

    allow = headers.get("allow", "")
    result.info["options_status"] = status
    if allow:
        result.info["allowed_methods"] = allow
        risky = {"PUT", "DELETE", "TRACE", "CONNECT"}
        found = sorted(m for m in risky if m in allow.upper())
        if found:
            result.add("high", "HTTP method berisiko diizinkan", "Nonaktifkan method yang tidak diperlukan.", ", ".join(found))


def check_sensitive_paths(
    result: ScanResult,
    opener: urllib.request.OpenerDirector,
    base_url: str,
    timeout: int,
    enabled: bool,
) -> None:
    if not enabled:
        return
    parsed = urllib.parse.urlparse(base_url)
    origin = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))
    exposed = []
    for path in SENSITIVE_PATHS:
        url = urllib.parse.urljoin(origin, path)
        try:
            status, _, headers, body = request(opener, url, "GET", timeout)
        except Exception:
            continue
        content_type = headers.get("content-type", "")
        if status == 200 and "text/html" not in content_type.lower() and len(body) > 0:
            exposed.append(f"{path} ({status}, {content_type or 'unknown type'})")
        elif status == 200 and path in {"/.env", "/.git/HEAD", "/database.sql"}:
            exposed.append(f"{path} ({status})")
    if exposed:
        result.add("high", "Kemungkinan file sensitif terekspos", "Batasi akses file konfigurasi, backup, dan metadata.", ", ".join(exposed))


def score(findings: Iterable[Finding]) -> str:
    weights = {"high": 30, "medium": 12, "low": 4, "info": 0}
    value = 100 - sum(weights.get(f.severity, 0) for f in findings)
    value = max(0, min(100, value))
    if value >= 85:
        label = "baik"
    elif value >= 65:
        label = "perlu perbaikan"
    else:
        label = "berisiko"
    return f"{value}/100 ({label})"


def scan(target: str, timeout: int, check_paths: bool) -> ScanResult:
    url = normalize_url(target)
    cookie_jar = CookieJar()
    opener = build_opener(cookie_jar)
    result = ScanResult(target=url)

    status, final_url, headers, body = request(opener, url, "GET", timeout)
    result.final_url = final_url
    result.status = status
    result.info["content_type"] = headers.get("content-type", "")
    result.info["body_sample_bytes"] = len(body)

    parsed_final = urllib.parse.urlparse(final_url)
    if status >= 500:
        result.add("medium", "Server mengembalikan error 5xx", "Periksa log aplikasi/server.", str(status))
    elif status >= 400:
        result.add("info", "Halaman mengembalikan status 4xx", "Scan header tetap diproses, tetapi hasil halaman bisa terbatas.", str(status))

    check_tls(result, final_url, timeout)
    check_security_headers(result, headers, parsed_final.scheme)
    check_cookies(result, cookie_jar, parsed_final.scheme == "https")
    check_forms(result, body, final_url)
    check_options(result, opener, final_url, timeout)
    check_sensitive_paths(result, opener, final_url, timeout, check_paths)
    return result


def print_text(result: ScanResult) -> None:
    print(f"Target       : {result.target}")
    print(f"Final URL    : {result.final_url}")
    print(f"HTTP Status  : {result.status}")
    print(f"Skor         : {score(result.findings)}")
    print()

    if result.info:
        print("Info:")
        for key, value in result.info.items():
            print(f"  - {key}: {value}")
        print()

    if not result.findings:
        print("Tidak ada temuan dari pemeriksaan dasar ini.")
        return

    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    for item in sorted(result.findings, key=lambda f: order.get(f.severity, 9)):
        print(f"[{item.severity.upper()}] {item.title}")
        print(f"  {item.detail}")
        if item.evidence:
            print(f"  Bukti: {item.evidence}")
        print()


def as_json(result: ScanResult) -> str:
    return json.dumps(
        {
            "target": result.target,
            "final_url": result.final_url,
            "status": result.status,
            "score": score(result.findings),
            "info": result.info,
            "findings": [finding.__dict__ for finding in result.findings],
        },
        indent=2,
        ensure_ascii=False,
    )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Pemindai keamanan web dasar non-eksploitatif untuk target yang diizinkan."
    )
    parser.add_argument("target", help="URL/domain target, contoh: https://example.com")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Timeout request dalam detik.")
    parser.add_argument("--json", action="store_true", help="Output dalam format JSON.")
    parser.add_argument(
        "--check-paths",
        action="store_true",
        help="Cek beberapa path file umum yang sering salah terekspos. Gunakan hanya dengan izin.",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        result = scan(args.target, args.timeout, args.check_paths)
    except ValueError as exc:
        print(f"Input salah: {exc}", file=sys.stderr)
        return 2
    except (urllib.error.URLError, TimeoutError, socket.timeout) as exc:
        print(f"Gagal mengakses target: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Dibatalkan.", file=sys.stderr)
        return 130

    if args.json:
        print(as_json(result))
    else:
        print_text(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
