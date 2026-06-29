"""
recon.modules.shodan_recon — Enhanced Shodan integration module.

Retrieves: ISP, organization, ASN, operating system, hostnames,
open ports with services, known CVEs/vulnerabilities, last scan date,
tags, and product versions.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass, field
from typing import Any, Optional

from recon.config import Config
from recon.logger import get_logger, log_duration
from recon.utils import clean_domain

logger = get_logger(__name__)


@dataclass
class ShodanPort:
    """A single port/service entry from Shodan."""

    port: int
    transport: str = "tcp"
    product: Optional[str] = None
    version: Optional[str] = None
    cpe: list[str] = field(default_factory=list)
    banner_snippet: Optional[str] = None
    vulns: list[str] = field(default_factory=list)


@dataclass
class ShodanResult:
    """Structured Shodan lookup result."""

    ip: Optional[str] = None
    org: Optional[str] = None
    isp: Optional[str] = None
    asn: Optional[str] = None
    os: Optional[str] = None
    hostnames: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    last_update: Optional[str] = None

    # Ports and services
    ports: list[ShodanPort] = field(default_factory=list)
    open_port_numbers: list[int] = field(default_factory=list)

    # Vulnerabilities
    vulns: list[str] = field(default_factory=list)
    total_vulns: int = 0

    raw: Optional[dict[str, Any]] = None
    error: Optional[str] = None
    success: bool = False


def run(
    target: str,
    config: Optional[Config] = None,
    api_key: Optional[str] = None,
) -> ShodanResult:
    """Perform Shodan host lookup.

    API key resolution order:
      1. Explicit ``api_key`` argument
      2. Config (from .env / environment)
      3. SHODAN_API_KEY environment variable

    Args:
        target: URL, domain, or IP address.
        config: Optional Config instance.
        api_key: Optional Shodan API key override.

    Returns:
        ShodanResult with host information.
    """
    result = ShodanResult()
    cfg = config or Config()

    # ── Resolve API key ───────────────────────────────────────────────
    key = api_key or cfg.shodan_api_key
    if not key:
        result.error = (
            "No Shodan API key configured. "
            "Set SHODAN_API_KEY in .env or environment."
        )
        logger.warning(result.error)
        return result

    # ── Import Shodan library ─────────────────────────────────────────
    try:
        import shodan
    except ImportError:
        result.error = "shodan library not installed. Install with: pip install shodan"
        logger.error(result.error)
        return result

    # ── Resolve domain to IP ──────────────────────────────────────────
    domain = clean_domain(target)
    try:
        ip = socket.gethostbyname(domain)
    except Exception as exc:
        result.error = f"Could not resolve host: {exc}"
        logger.error(result.error)
        return result

    result.ip = ip

    with log_duration(logger, f"Shodan lookup for {ip}"):
        try:
            api = shodan.Shodan(key)
            host = api.host(ip)
        except Exception as exc:
            err_msg = str(exc)
            if "403" in err_msg or "Access denied" in err_msg:
                logger.warning(f"Shodan API limitation (Free Tier / No Credits): {err_msg}")
                result.success = True
                result.org = "N/A (Free Tier Key / No Scan Credits)"
                return result
            elif "No information available" in err_msg:
                logger.info(f"Shodan: No recorded data for {ip}")
                result.success = True
                result.org = "No records found in Shodan database"
                return result
            result.error = f"Shodan API error: {err_msg}"
            logger.error(result.error)
            return result

        result.success = True
        result.raw = host

        # ── Basic info ────────────────────────────────────────────────
        result.org = host.get("org")
        result.isp = host.get("isp")
        result.asn = host.get("asn")
        result.os = host.get("os")
        result.hostnames = host.get("hostnames", [])
        result.domains = host.get("domains", [])
        result.tags = host.get("tags", [])
        result.last_update = host.get("last_update")

        # ── Host-level vulnerabilities ────────────────────────────────
        host_vulns = host.get("vulns", [])
        result.vulns = list(host_vulns) if host_vulns else []

        # ── Port/service details ──────────────────────────────────────
        for service in host.get("data", []):
            port_entry = ShodanPort(
                port=service.get("port", 0),
                transport=service.get("transport", "tcp"),
                product=(
                    service.get("product")
                    or service.get("http", {}).get("server")
                ),
                version=service.get("version"),
            )

            # CPE identifiers
            cpe = service.get("cpe", [])
            if isinstance(cpe, list):
                port_entry.cpe = cpe

            # Banner snippet
            banner = service.get("data")
            if isinstance(banner, str) and banner:
                port_entry.banner_snippet = banner[:300]

            # Per-service vulnerabilities
            svc_vulns = service.get("vulns", {})
            if isinstance(svc_vulns, dict):
                port_entry.vulns = list(svc_vulns.keys())
                for v in port_entry.vulns:
                    if v not in result.vulns:
                        result.vulns.append(v)

            result.ports.append(port_entry)

        result.open_port_numbers = sorted({p.port for p in result.ports})
        result.total_vulns = len(result.vulns)

    logger.info(
        "Shodan: %d ports, %d vulns for %s",
        len(result.ports), result.total_vulns, ip,
    )
    return result
