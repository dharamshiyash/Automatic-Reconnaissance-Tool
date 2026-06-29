"""
recon.modules.subdomain_recon — Enhanced subdomain enumeration module.

Merges results from multiple sources:
  - Sublist3r (if installed)
  - crt.sh certificate transparency logs
Deduplicates, sorts, and provides statistics.
"""

from __future__ import annotations

import subprocess
import os
from dataclasses import dataclass, field
from typing import Optional

import requests

from recon.config import Config
from recon.logger import get_logger, log_duration
from recon.utils import clean_domain, timestamp_str

logger = get_logger(__name__)


@dataclass
class SubdomainResult:
    """Structured subdomain enumeration result."""

    subdomains: list[str] = field(default_factory=list)
    total_count: int = 0

    # Source breakdown
    from_sublist3r: list[str] = field(default_factory=list)
    from_crtsh: list[str] = field(default_factory=list)

    sources_used: list[str] = field(default_factory=list)
    error: Optional[str] = None
    success: bool = False


def _enum_crtsh(domain: str, timeout: int = 30) -> list[str]:
    """Query crt.sh certificate transparency logs for subdomains."""
    subdomains: set[str] = set()
    try:
        resp = requests.get(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            timeout=timeout,
            headers={"User-Agent": "ReconTool/2.0"},
        )
        if resp.status_code == 200:
            data = resp.json()
            for entry in data:
                name_value = entry.get("name_value", "")
                for name in name_value.split("\n"):
                    name = name.strip().lower()
                    if name and "*" not in name and name.endswith(domain):
                        subdomains.add(name)
            logger.info("crt.sh found %d unique subdomains", len(subdomains))
    except Exception as exc:
        logger.warning("crt.sh query failed: %s", exc)
    return sorted(subdomains)


def _enum_sublist3r(
    domain: str,
    output_dir: str,
    timeout: int = 300,
) -> list[str]:
    """Run Sublist3r for subdomain enumeration."""
    subdomains: list[str] = []
    outpath = os.path.join(output_dir, f"{domain}_sublist3r_{timestamp_str()}.txt")

    try:
        result = subprocess.run(
            ["sublist3r", "-d", domain, "-o", outpath],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if os.path.exists(outpath):
            with open(outpath, "r") as fh:
                subdomains = [line.strip().lower() for line in fh if line.strip()]
            logger.info("Sublist3r found %d subdomains", len(subdomains))
        return subdomains
    except FileNotFoundError:
        logger.info("Sublist3r not installed — skipping")
        return []
    except subprocess.TimeoutExpired:
        logger.warning("Sublist3r timed out after %ds", timeout)
        return []
    except Exception as exc:
        logger.warning("Sublist3r failed: %s", exc)
        return []


def run(
    target: str,
    config: Optional[Config] = None,
    timeout: int = 300,
) -> SubdomainResult:
    """Enumerate subdomains using multiple sources.

    Args:
        target: URL or domain string.
        config: Optional Config for directory settings.
        timeout: Sublist3r timeout in seconds.

    Returns:
        SubdomainResult with merged, deduplicated, sorted results.
    """
    cfg = config or Config()
    domain = clean_domain(target)
    result = SubdomainResult()

    with log_duration(logger, f"Subdomain enumeration for {domain}"):
        # ── crt.sh (passive, fast) ────────────────────────────────────
        crtsh_subs = _enum_crtsh(domain)
        result.from_crtsh = crtsh_subs
        if crtsh_subs:
            result.sources_used.append("crt.sh")

        # ── Sublist3r (active, slower) ────────────────────────────────
        sublist3r_subs = _enum_sublist3r(
            domain, str(cfg.documents_dir), timeout=timeout
        )
        result.from_sublist3r = sublist3r_subs
        if sublist3r_subs:
            result.sources_used.append("Sublist3r")

        # ── Merge & deduplicate ───────────────────────────────────────
        all_subs: set[str] = set()
        all_subs.update(crtsh_subs)
        all_subs.update(sublist3r_subs)

        result.subdomains = sorted(all_subs)
        result.total_count = len(result.subdomains)
        result.success = True

    logger.info(
        "Subdomain enumeration complete: %d unique from %d sources",
        result.total_count,
        len(result.sources_used),
    )
    return result
