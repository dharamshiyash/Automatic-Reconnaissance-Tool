"""
recon.modules.dns_recon — Enhanced DNS reconnaissance module.

Collects comprehensive DNS records including:
A, AAAA, MX, TXT, NS, SOA, CAA, CNAME, PTR (reverse DNS),
SPF, DMARC, DNSSEC status, and TTL values.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

import dns.resolver
import dns.reversename
import dns.rdatatype
import dns.dnssec
import dns.name

from recon.logger import get_logger, log_duration
from recon.modules.geo_recon import resolve_ip
from recon.utils import clean_domain

logger = get_logger(__name__)


@dataclass
class DnsRecord:
    """A single DNS record entry."""

    record_type: str
    values: list[str] = field(default_factory=list)
    ttl: Optional[int] = None


@dataclass
class DnsResult:
    """Structured DNS lookup result with all record types."""

    records: dict[str, DnsRecord] = field(default_factory=dict)

    # Parsed convenience fields
    spf: Optional[str] = None
    dmarc: Optional[str] = None
    has_dnssec: Optional[bool] = None
    reverse_dns: Optional[str] = None

    error: Optional[str] = None
    success: bool = False

    def get_values(self, record_type: str) -> list[str]:
        """Get values for a specific record type."""
        rec = self.records.get(record_type)
        return rec.values if rec else []


def _query_record(
    resolver: dns.resolver.Resolver,
    domain: str,
    rdtype: str,
) -> DnsRecord:
    """Query a single DNS record type, returning a DnsRecord."""
    record = DnsRecord(record_type=rdtype)
    try:
        answers = resolver.resolve(domain, rdtype, raise_on_no_answer=False)
        if answers.rrset is not None:
            record.values = [str(rr).strip() for rr in answers]
            record.ttl = answers.rrset.ttl
    except dns.resolver.NoAnswer:
        pass
    except dns.resolver.NXDOMAIN:
        pass
    except dns.resolver.NoNameservers:
        pass
    except Exception as exc:
        logger.debug("DNS %s query for %s failed: %s", rdtype, domain, exc)
    return record


def run(target: str, timeout: int = 5) -> DnsResult:
    """Perform comprehensive DNS reconnaissance on the target.

    Args:
        target: URL or domain string.
        timeout: DNS query timeout in seconds.

    Returns:
        DnsResult with all collected DNS records.
    """
    domain = clean_domain(target)
    result = DnsResult()

    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    with log_duration(logger, f"DNS enumeration for {domain}"):
        # ── Standard record types ─────────────────────────────────────
        record_types = ["A", "AAAA", "MX", "TXT", "NS", "SOA", "CAA", "CNAME"]
        for rdtype in record_types:
            rec = _query_record(resolver, domain, rdtype)
            result.records[rdtype] = rec
            if rec.values:
                logger.debug("DNS %s: %s", rdtype, rec.values)

        result.success = True

        # ── SPF (from TXT records) ────────────────────────────────────
        txt_records = result.get_values("TXT")
        for txt in txt_records:
            txt_lower = txt.lower().strip('"')
            if txt_lower.startswith("v=spf1"):
                result.spf = txt.strip('"')
                break

        # ── DMARC (query _dmarc subdomain) ────────────────────────────
        dmarc_rec = _query_record(resolver, f"_dmarc.{domain}", "TXT")
        result.records["DMARC"] = dmarc_rec
        for txt in dmarc_rec.values:
            txt_lower = txt.lower().strip('"')
            if "v=dmarc1" in txt_lower:
                result.dmarc = txt.strip('"')
                break

        # ── Reverse DNS (PTR) ─────────────────────────────────────────
        ip, _ = resolve_ip(target)
        if ip:
            try:
                rev_name = dns.reversename.from_address(ip)
                answers = resolver.resolve(rev_name, "PTR")
                ptrs = [str(rr).rstrip(".") for rr in answers]
                result.records["PTR"] = DnsRecord(
                    record_type="PTR",
                    values=ptrs,
                    ttl=answers.rrset.ttl if answers.rrset else None,
                )
                result.reverse_dns = ptrs[0] if ptrs else None
            except Exception as exc:
                logger.debug("Reverse DNS failed for %s: %s", ip, exc)
                result.records["PTR"] = DnsRecord(record_type="PTR")

        # ── DNSSEC check ──────────────────────────────────────────────
        try:
            answers = resolver.resolve(domain, "DNSKEY")
            result.has_dnssec = bool(answers.rrset)
        except Exception:
            result.has_dnssec = False

    return result
