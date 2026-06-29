"""
recon.modules.tech_recon — Technology detection module.

Combines BuiltWith library detection with Wappalyzer-style pattern matching
against HTTP headers and HTML content to identify: frameworks, CMS, CDN,
web servers, analytics, JS libraries, and programming languages.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional

import requests

from recon.logger import get_logger, log_duration
from recon.utils import clean_domain, ensure_scheme

logger = get_logger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Wappalyzer-style signature patterns
# ──────────────────────────────────────────────────────────────────────────────
# (category, technology_name, detection_source, pattern)
TECH_SIGNATURES: list[tuple[str, str, str, str]] = [
    # Frameworks
    ("Framework", "React", "html", r"react(?:\.min)?\.js|__NEXT_DATA__|reactroot"),
    ("Framework", "Angular", "html", r"ng-version=|angular(?:\.min)?\.js"),
    ("Framework", "Vue.js", "html", r"vue(?:\.min)?\.js|__vue__|v-cloak"),
    ("Framework", "jQuery", "html", r"jquery(?:\.min)?\.js"),
    ("Framework", "Bootstrap", "html", r"bootstrap(?:\.min)?\.(?:js|css)"),
    ("Framework", "Tailwind CSS", "html", r"tailwindcss|tailwind\.min\.css"),
    ("Framework", "Next.js", "html", r"_next/static|__NEXT_DATA__"),
    ("Framework", "Nuxt.js", "html", r"__nuxt|_nuxt/"),
    ("Framework", "Svelte", "html", r"svelte(?:\.min)?\.js|__svelte"),
    ("Framework", "Gatsby", "html", r"gatsby-"),

    # CMS
    ("CMS", "WordPress", "html", r"wp-content/|wp-includes/|wordpress"),
    ("CMS", "Drupal", "html", r"drupal\.js|sites/all/|Drupal\.settings"),
    ("CMS", "Joomla", "html", r"/media/jui/|joomla"),
    ("CMS", "Shopify", "html", r"cdn\.shopify\.com|shopify"),
    ("CMS", "Squarespace", "html", r"squarespace\.com|static\.squarespace"),
    ("CMS", "Wix", "html", r"wix\.com|wixsite"),
    ("CMS", "Ghost", "html", r"ghost\.(?:io|org)|ghost-"),

    # Web Servers (from headers)
    ("Server", "Nginx", "header_server", r"nginx"),
    ("Server", "Apache", "header_server", r"apache"),
    ("Server", "IIS", "header_server", r"microsoft-iis"),
    ("Server", "LiteSpeed", "header_server", r"litespeed"),
    ("Server", "Caddy", "header_server", r"caddy"),
    ("Server", "Cloudflare", "header_server", r"cloudflare"),

    # CDN
    ("CDN", "Cloudflare", "headers", r"cf-ray|cf-cache-status|cloudflare"),
    ("CDN", "Akamai", "headers", r"x-akamai|akamai"),
    ("CDN", "Fastly", "headers", r"x-fastly|fastly"),
    ("CDN", "AWS CloudFront", "headers", r"x-amz-cf-|cloudfront"),
    ("CDN", "Varnish", "headers", r"x-varnish|via.*varnish"),

    # Analytics
    ("Analytics", "Google Analytics", "html", r"google-analytics\.com|gtag|UA-\d+"),
    ("Analytics", "Google Tag Manager", "html", r"googletagmanager\.com|GTM-"),
    ("Analytics", "Facebook Pixel", "html", r"connect\.facebook\.net|fbq\("),
    ("Analytics", "Hotjar", "html", r"hotjar\.com|hj\.js"),
    ("Analytics", "Matomo", "html", r"matomo\.js|piwik\.js"),

    # Programming Languages (from headers)
    ("Language", "PHP", "headers", r"x-powered-by.*php"),
    ("Language", "ASP.NET", "headers", r"x-powered-by.*asp\.net|x-aspnet"),
    ("Language", "Java", "headers", r"x-powered-by.*(?:servlet|jsp|java)"),
    ("Language", "Python", "headers", r"x-powered-by.*(?:python|django|flask|gunicorn)"),
    ("Language", "Ruby", "headers", r"x-powered-by.*(?:phusion|ruby)"),
    ("Language", "Node.js", "headers", r"x-powered-by.*express"),

    # Security
    ("Security", "reCAPTCHA", "html", r"recaptcha|google\.com/recaptcha"),
    ("Security", "hCaptcha", "html", r"hcaptcha\.com"),
]


@dataclass
class TechDetection:
    """A single detected technology."""

    category: str
    name: str
    source: str  # e.g., "header", "html", "builtwith"
    version: Optional[str] = None


@dataclass
class TechResult:
    """Structured technology detection result."""

    technologies: list[TechDetection] = field(default_factory=list)
    builtwith_raw: Optional[dict[str, Any]] = None
    categories: dict[str, list[str]] = field(default_factory=dict)
    error: Optional[str] = None
    success: bool = False

    def has_tech(self, name: str) -> bool:
        """Check if a specific technology was detected."""
        return any(t.name.lower() == name.lower() for t in self.technologies)

    def get_by_category(self, category: str) -> list[TechDetection]:
        """Get all technologies in a specific category."""
        return [t for t in self.technologies if t.category.lower() == category.lower()]


def _detect_builtwith(domain: str) -> dict[str, Any]:
    """Run BuiltWith detection."""
    try:
        import builtwith
        tech = builtwith.parse(f"http://{domain}")
        return tech or {}
    except Exception as exc:
        logger.debug("BuiltWith detection failed: %s", exc)
        return {}


def _detect_from_patterns(
    html: str,
    headers: dict[str, str],
    server: str,
) -> list[TechDetection]:
    """Detect technologies using signature patterns."""
    detected: list[TechDetection] = []
    seen: set[str] = set()

    for category, name, source, pattern in TECH_SIGNATURES:
        if name in seen:
            continue

        text = ""
        if source == "html":
            text = html
        elif source == "header_server":
            text = server
        elif source == "headers":
            text = " ".join(f"{k}: {v}" for k, v in headers.items())

        if text and re.search(pattern, text, re.IGNORECASE):
            detected.append(TechDetection(
                category=category,
                name=name,
                source=source.replace("_", " "),
            ))
            seen.add(name)

    return detected


def run(target: str, timeout: int = 10) -> TechResult:
    """Detect technologies used by the target.

    Combines BuiltWith library analysis with Wappalyzer-style
    pattern matching against HTTP headers and HTML content.

    Args:
        target: URL or domain string.
        timeout: HTTP request timeout in seconds.

    Returns:
        TechResult with detected technologies grouped by category.
    """
    domain = clean_domain(target)
    url = ensure_scheme(target)
    result = TechResult()

    with log_duration(logger, f"Technology detection for {domain}"):
        # ── Fetch page HTML and headers ───────────────────────────────
        html = ""
        headers: dict[str, str] = {}
        server = ""
        try:
            resp = requests.get(url, timeout=timeout, allow_redirects=True)
            html = resp.text
            headers = dict(resp.headers)
            server = headers.get("Server", "")
        except Exception as exc:
            logger.warning("Could not fetch page for tech detection: %s", exc)

        # ── BuiltWith detection ───────────────────────────────────────
        bw = _detect_builtwith(domain)
        result.builtwith_raw = bw
        for category, techs in bw.items():
            for tech_name in techs:
                result.technologies.append(TechDetection(
                    category=category,
                    name=tech_name,
                    source="builtwith",
                ))

        # ── Pattern-based detection ───────────────────────────────────
        pattern_results = _detect_from_patterns(html, headers, server)
        # Merge avoiding duplicates
        existing_names = {t.name.lower() for t in result.technologies}
        for tech in pattern_results:
            if tech.name.lower() not in existing_names:
                result.technologies.append(tech)
                existing_names.add(tech.name.lower())

        # ── Build category index ──────────────────────────────────────
        for tech in result.technologies:
            result.categories.setdefault(tech.category, []).append(tech.name)

        result.success = bool(result.technologies)
        if not result.success:
            result.error = "No technologies detected"

    return result
