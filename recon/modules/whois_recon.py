"""
recon.modules.whois_recon — WHOIS lookup module.

Retrieves domain registration information including registrar,
creation/expiration dates, name servers, and contact details.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

import whois

from recon.logger import get_logger, log_duration
from recon.utils import clean_domain

logger = get_logger(__name__)


@dataclass
class WhoisResult:
    """Structured WHOIS lookup result."""

    domain_name: Optional[str] = None
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    updated_date: Optional[str] = None
    name_servers: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    registrant: Optional[str] = None
    registrant_country: Optional[str] = None
    dnssec: Optional[str] = None
    status: list[str] = field(default_factory=list)
    raw: Optional[dict[str, Any]] = None
    error: Optional[str] = None
    success: bool = False


def run(target: str) -> WhoisResult:
    """Perform a WHOIS lookup on the target domain.

    Args:
        target: URL or domain string to look up.

    Returns:
        WhoisResult with structured registration data.
    """
    domain = clean_domain(target)
    result = WhoisResult()

    with log_duration(logger, f"WHOIS lookup for {domain}"):
        try:
            w = whois.whois(domain)
        except Exception as exc:
            logger.error("WHOIS lookup failed for %s: %s", domain, exc)
            result.error = str(exc)
            return result

        result.success = True
        result.raw = dict(w) if hasattr(w, "__iter__") else {}

        # Domain name — may be a list or string
        dn = getattr(w, "domain_name", None)
        if isinstance(dn, list):
            result.domain_name = dn[0] if dn else None
        else:
            result.domain_name = dn

        result.registrar = getattr(w, "registrar", None)

        # Dates — may be a list or single value
        cd = getattr(w, "creation_date", None)
        result.creation_date = str(cd[0] if isinstance(cd, list) else cd) if cd else None

        ed = getattr(w, "expiration_date", None)
        result.expiration_date = str(ed[0] if isinstance(ed, list) else ed) if ed else None

        ud = getattr(w, "updated_date", None)
        result.updated_date = str(ud[0] if isinstance(ud, list) else ud) if ud else None

        # Name servers
        ns = getattr(w, "name_servers", None)
        if isinstance(ns, list):
            result.name_servers = [str(s).lower() for s in ns]
        elif ns:
            result.name_servers = [str(ns).lower()]

        # Emails
        em = getattr(w, "emails", None)
        if isinstance(em, list):
            result.emails = em
        elif em:
            result.emails = [em]

        # Registrant
        result.registrant = getattr(w, "org", None) or getattr(w, "name", None)
        result.registrant_country = getattr(w, "country", None)

        # DNSSEC
        result.dnssec = getattr(w, "dnssec", None)

        # Status
        st = getattr(w, "status", None)
        if isinstance(st, list):
            result.status = st
        elif st:
            result.status = [st]

    return result
