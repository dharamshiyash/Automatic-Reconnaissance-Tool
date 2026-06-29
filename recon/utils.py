"""
recon.utils — Shared utility functions.

Common operations used across multiple modules:
  - Domain cleaning / URL parsing
  - Input validation
  - Timestamp generation
  - Safe filename creation
"""

from __future__ import annotations

import datetime
import re
from urllib.parse import urlparse


def clean_domain(target: str) -> str:
    """Extract the bare domain (hostname) from a URL or domain string.

    Examples:
        >>> clean_domain("https://www.example.com/path?q=1")
        'www.example.com'
        >>> clean_domain("http://example.com")
        'example.com'
        >>> clean_domain("example.com")
        'example.com'
    """
    target = target.strip()
    if "://" not in target:
        target = "http://" + target
    parsed = urlparse(target)
    hostname = parsed.hostname or parsed.path.split("/")[0]
    return hostname.lower() if hostname else target.lower()


def ensure_scheme(url: str, default_scheme: str = "http") -> str:
    """Ensure a URL has a scheme prefix.

    Args:
        url: Raw URL or domain string.
        default_scheme: Scheme to add if missing (default ``http``).

    Returns:
        URL with scheme prefix.
    """
    url = url.strip()
    if not url:
        return url
    if "://" not in url:
        return f"{default_scheme}://{url}"
    return url


def timestamp_str() -> str:
    """Return a filesystem-safe timestamp string: ``YYYYMMDD_HHMMSS``."""
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")


def timestamp_iso() -> str:
    """Return an ISO-8601 formatted timestamp string."""
    return datetime.datetime.now().isoformat(timespec="seconds")


def safe_filename(target: str) -> str:
    """Convert a URL/domain into a filesystem-safe filename component.

    Replaces ``://``, ``/``, ``:``, and other problematic characters
    with underscores.

    Examples:
        >>> safe_filename("https://www.example.com/path")
        'https_www.example.com_path'
    """
    name = target.replace("://", "_").replace("/", "_").replace(":", "_")
    # Remove any remaining unsafe characters
    name = re.sub(r'[<>"|?*\\]', "", name)
    # Collapse multiple underscores
    name = re.sub(r"_+", "_", name)
    return name.strip("_")


def validate_target(target: str) -> tuple[bool, str]:
    """Validate a user-supplied target string.

    Returns:
        Tuple of (is_valid, error_message).  ``error_message`` is empty
        when ``is_valid`` is ``True``.
    """
    target = target.strip()
    if not target:
        return False, "Target cannot be empty."

    domain = clean_domain(target)
    if not domain:
        return False, "Could not extract a domain from the target."

    # Basic domain pattern check
    domain_pattern = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*"
        r"[a-zA-Z]{2,}$"
    )
    if not domain_pattern.match(domain):
        # Allow IP addresses too
        ip_pattern = re.compile(
            r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
        )
        if not ip_pattern.match(domain):
            return False, f"Invalid domain or IP: {domain}"

    return True, ""


def format_duration(seconds: float) -> str:
    """Format a duration in seconds to a human-readable string.

    Examples:
        >>> format_duration(65.3)
        '1m 5s'
        >>> format_duration(3.7)
        '3.7s'
    """
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes = int(seconds // 60)
    secs = seconds % 60
    return f"{minutes}m {secs:.0f}s"
