"""
recon.modules.geo_recon — Geo-IP location module.

Resolves an IP address or domain to its geographic location using
the ip-api.com free API.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass
from typing import Optional

import requests

from recon.logger import get_logger, log_duration
from recon.utils import clean_domain

logger = get_logger(__name__)


@dataclass
class GeoResult:
    """Structured geo-IP lookup result."""

    ip: Optional[str] = None
    city: Optional[str] = None
    region: Optional[str] = None
    country: Optional[str] = None
    country_code: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    isp: Optional[str] = None
    org: Optional[str] = None
    as_number: Optional[str] = None
    timezone: Optional[str] = None
    error: Optional[str] = None
    success: bool = False


def resolve_ip(target: str) -> tuple[Optional[str], Optional[str]]:
    """Resolve domain to IP address.

    Args:
        target: URL or domain string.

    Returns:
        Tuple of (ip_address, error_message).
    """
    domain = clean_domain(target)
    try:
        ip = socket.gethostbyname(domain)
        logger.info("Resolved %s → %s", domain, ip)
        return ip, None
    except socket.gaierror as exc:
        logger.error("DNS resolution failed for %s: %s", domain, exc)
        return None, str(exc)


def run(target: str, timeout: int = 8) -> GeoResult:
    """Perform geo-IP lookup on the target.

    Args:
        target: URL, domain, or IP address.
        timeout: HTTP request timeout in seconds.

    Returns:
        GeoResult with location data.
    """
    result = GeoResult()

    # Resolve domain to IP if needed
    domain = clean_domain(target)
    ip, err = resolve_ip(target)
    if not ip:
        result.error = err
        return result

    result.ip = ip

    with log_duration(logger, f"Geo-IP lookup for {ip}"):
        try:
            resp = requests.get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": "status,message,country,countryCode,region,"
                        "regionName,city,lat,lon,timezone,isp,org,as,query"},
                timeout=timeout,
            )
            data = resp.json()
        except Exception as exc:
            logger.error("Geo-IP API request failed: %s", exc)
            result.error = str(exc)
            return result

        if data.get("status") != "success":
            result.error = data.get("message", "Geo info not available")
            return result

        result.success = True
        result.city = data.get("city")
        result.region = data.get("regionName")
        result.country = data.get("country")
        result.country_code = data.get("countryCode")
        result.latitude = data.get("lat")
        result.longitude = data.get("lon")
        result.isp = data.get("isp")
        result.org = data.get("org")
        result.as_number = data.get("as")
        result.timezone = data.get("timezone")

    return result
