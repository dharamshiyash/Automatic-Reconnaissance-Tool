"""
recon.modules.http_recon — Enhanced HTTP header analysis module.

Analyzes security headers, cookies, compression, caching, redirect chains,
robots.txt, sitemap.xml, CORS configuration, and allowed HTTP methods.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

import requests

from recon.logger import get_logger, log_duration
from recon.utils import ensure_scheme

logger = get_logger(__name__)

# Security headers to check
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
]


@dataclass
class CookieInfo:
    """Analysis of a single cookie."""

    name: str
    secure: bool = False
    httponly: bool = False
    samesite: Optional[str] = None
    path: Optional[str] = None
    domain: Optional[str] = None


@dataclass
class RedirectHop:
    """A single hop in a redirect chain."""

    url: str
    status_code: int


@dataclass
class HttpResult:
    """Structured HTTP analysis result."""

    # Raw headers
    headers: dict[str, str] = field(default_factory=dict)
    status_code: Optional[int] = None
    final_url: Optional[str] = None

    # Server info
    server: Optional[str] = None
    x_powered_by: Optional[str] = None
    content_type: Optional[str] = None
    content_length: Optional[int] = None
    content_encoding: Optional[str] = None

    # Security headers analysis
    security_headers: dict[str, Optional[str]] = field(default_factory=dict)
    missing_security_headers: list[str] = field(default_factory=list)

    # Cookies
    cookies: list[CookieInfo] = field(default_factory=list)

    # Redirect chain
    redirect_chain: list[RedirectHop] = field(default_factory=list)

    # robots.txt & sitemap
    robots_txt: Optional[str] = None
    robots_found: bool = False
    sitemap_url: Optional[str] = None
    sitemap_found: bool = False

    # CORS
    cors_origin: Optional[str] = None
    cors_methods: Optional[str] = None
    cors_headers: Optional[str] = None

    # Allowed methods
    allowed_methods: list[str] = field(default_factory=list)

    # Cache
    cache_control: Optional[str] = None
    pragma: Optional[str] = None
    etag: Optional[str] = None

    error: Optional[str] = None
    success: bool = False


def _check_redirect_chain(url: str, timeout: int) -> list[RedirectHop]:
    """Trace the redirect chain for a URL."""
    chain: list[RedirectHop] = []
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True)
        for r in resp.history:
            chain.append(RedirectHop(url=r.url, status_code=r.status_code))
        chain.append(RedirectHop(url=resp.url, status_code=resp.status_code))
    except Exception as exc:
        logger.debug("Redirect chain tracing failed: %s", exc)
    return chain


def _check_robots(base_url: str, timeout: int) -> tuple[Optional[str], bool]:
    """Fetch robots.txt content."""
    try:
        resp = requests.get(
            f"{base_url.rstrip('/')}/robots.txt",
            timeout=timeout,
            allow_redirects=True,
        )
        if resp.status_code == 200 and "html" not in resp.headers.get("Content-Type", "").lower():
            return resp.text[:5000], True
        return None, False
    except Exception:
        return None, False


def _check_sitemap(base_url: str, timeout: int) -> tuple[Optional[str], bool]:
    """Check if sitemap.xml exists."""
    try:
        resp = requests.head(
            f"{base_url.rstrip('/')}/sitemap.xml",
            timeout=timeout,
            allow_redirects=True,
        )
        if resp.status_code == 200:
            return f"{base_url.rstrip('/')}/sitemap.xml", True
        return None, False
    except Exception:
        return None, False


def _check_cors(url: str, timeout: int) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """Check CORS configuration."""
    try:
        resp = requests.options(
            url,
            headers={"Origin": "https://evil.com", "Access-Control-Request-Method": "GET"},
            timeout=timeout,
        )
        return (
            resp.headers.get("Access-Control-Allow-Origin"),
            resp.headers.get("Access-Control-Allow-Methods"),
            resp.headers.get("Access-Control-Allow-Headers"),
        )
    except Exception:
        return None, None, None


def _check_methods(url: str, timeout: int) -> list[str]:
    """Discover allowed HTTP methods."""
    try:
        resp = requests.options(url, timeout=timeout)
        allow = resp.headers.get("Allow", "")
        if allow:
            return [m.strip() for m in allow.split(",")]
    except Exception:
        pass
    return []


def run(target: str, timeout: int = 10) -> HttpResult:
    """Perform comprehensive HTTP header analysis.

    Args:
        target: URL or domain string.
        timeout: HTTP request timeout in seconds.

    Returns:
        HttpResult with headers, security analysis, cookies, and more.
    """
    url = ensure_scheme(target)
    result = HttpResult()

    with log_duration(logger, f"HTTP analysis for {url}"):
        # ── Primary request ───────────────────────────────────────────
        try:
            resp = requests.head(url, timeout=timeout, allow_redirects=True)
            if not resp.headers or resp.status_code >= 400:
                resp = requests.get(url, timeout=timeout, allow_redirects=True)
        except Exception as exc:
            logger.error("HTTP request failed for %s: %s", url, exc)
            result.error = str(exc)
            return result

        result.success = True
        result.headers = dict(resp.headers)
        result.status_code = resp.status_code
        result.final_url = resp.url

        # Server info
        result.server = resp.headers.get("Server")
        result.x_powered_by = resp.headers.get("X-Powered-By")
        result.content_type = resp.headers.get("Content-Type")
        result.content_encoding = resp.headers.get("Content-Encoding")
        cl = resp.headers.get("Content-Length")
        result.content_length = int(cl) if cl and cl.isdigit() else None

        # Cache
        result.cache_control = resp.headers.get("Cache-Control")
        result.pragma = resp.headers.get("Pragma")
        result.etag = resp.headers.get("ETag")

        # ── Security headers ──────────────────────────────────────────
        for header in SECURITY_HEADERS:
            value = resp.headers.get(header)
            result.security_headers[header] = value
            if value is None:
                result.missing_security_headers.append(header)

        # ── Cookie analysis ───────────────────────────────────────────
        for cookie in resp.cookies:
            ci = CookieInfo(name=cookie.name)
            ci.secure = cookie.secure
            ci.path = cookie.path
            ci.domain = cookie.domain
            # httponly and samesite are stored in _rest dict
            rest = getattr(cookie, "_rest", {})
            ci.httponly = "httponly" in {k.lower() for k in rest}
            samesite_vals = [v for k, v in rest.items() if k.lower() == "samesite"]
            ci.samesite = samesite_vals[0] if samesite_vals else None
            result.cookies.append(ci)

        # ── Redirect chain ────────────────────────────────────────────
        result.redirect_chain = _check_redirect_chain(url, timeout)

        # ── robots.txt ────────────────────────────────────────────────
        base = f"{resp.url.split('://')[0]}://{resp.url.split('://')[1].split('/')[0]}"
        result.robots_txt, result.robots_found = _check_robots(base, timeout)

        # ── Sitemap ───────────────────────────────────────────────────
        result.sitemap_url, result.sitemap_found = _check_sitemap(base, timeout)

        # ── CORS ──────────────────────────────────────────────────────
        result.cors_origin, result.cors_methods, result.cors_headers = _check_cors(
            url, timeout
        )

        # ── Allowed Methods ───────────────────────────────────────────
        result.allowed_methods = _check_methods(url, timeout)

    return result
