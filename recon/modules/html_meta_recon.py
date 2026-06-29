"""
recon.modules.html_meta_recon — HTML metadata extraction module.

Fetches the target page and extracts title, meta tags, Open Graph data,
and other HTML-embedded metadata.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

import requests
from bs4 import BeautifulSoup

from recon.logger import get_logger, log_duration
from recon.utils import ensure_scheme

logger = get_logger(__name__)


@dataclass
class HtmlMetaResult:
    """Structured HTML metadata result."""

    title: Optional[str] = None
    description: Optional[str] = None
    keywords: Optional[str] = None
    author: Optional[str] = None
    generator: Optional[str] = None
    viewport: Optional[str] = None
    canonical: Optional[str] = None
    favicon: Optional[str] = None
    og_tags: dict[str, str] = field(default_factory=dict)
    twitter_tags: dict[str, str] = field(default_factory=dict)
    meta_tags: list[dict[str, str]] = field(default_factory=list)
    meta_count: int = 0
    status_code: Optional[int] = None
    error: Optional[str] = None
    success: bool = False


def run(target: str, timeout: int = 10) -> HtmlMetaResult:
    """Fetch the target page and extract HTML metadata.

    Args:
        target: URL or domain string.
        timeout: HTTP request timeout in seconds.

    Returns:
        HtmlMetaResult with extracted metadata.
    """
    url = ensure_scheme(target)
    result = HtmlMetaResult()

    with log_duration(logger, f"HTML metadata extraction for {url}"):
        try:
            resp = requests.get(url, timeout=timeout, allow_redirects=True)
            result.status_code = resp.status_code
        except Exception as exc:
            logger.error("HTML fetch failed for %s: %s", url, exc)
            result.error = str(exc)
            return result

        if resp.status_code != 200:
            result.error = f"HTTP status {resp.status_code}"
            return result

        try:
            soup = BeautifulSoup(resp.text, "html.parser")
        except Exception as exc:
            result.error = f"HTML parse error: {exc}"
            return result

        result.success = True

        # Title
        if soup.title and soup.title.string:
            result.title = soup.title.string.strip()

        # All meta tags
        for meta in soup.find_all("meta"):
            attrs = {k: v for k, v in meta.attrs.items()}
            result.meta_tags.append(attrs)

            name = (attrs.get("name") or attrs.get("property") or "").lower()
            content = attrs.get("content", "")

            # Standard meta tags
            if name == "description":
                result.description = content
            elif name == "keywords":
                result.keywords = content
            elif name == "author":
                result.author = content
            elif name == "generator":
                result.generator = content
            elif name == "viewport":
                result.viewport = content

            # Open Graph
            prop = attrs.get("property", "").lower()
            if prop.startswith("og:"):
                result.og_tags[prop] = content

            # Twitter Card
            if name.startswith("twitter:"):
                result.twitter_tags[name] = content

        result.meta_count = len(result.meta_tags)

        # Canonical URL
        canonical = soup.find("link", rel="canonical")
        if canonical:
            result.canonical = canonical.get("href")

        # Favicon
        favicon = soup.find("link", rel=lambda r: r and "icon" in r if isinstance(r, list) else r == "icon")
        if favicon:
            result.favicon = favicon.get("href")

    return result
