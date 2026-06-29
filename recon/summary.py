"""
recon.summary — Executive summary generator.

Produces a human-readable narrative summary of scan results using
template-based text generation. Uses ONLY collected evidence —
never fabricates or infers data.
"""

from __future__ import annotations

from typing import Any, Optional


def generate(scan_results: dict[str, Any], score: Any = None) -> str:
    """Generate an executive summary from scan results.

    Args:
        scan_results: Dictionary mapping module name → result dataclass.
        score: Optional SecurityScore instance.

    Returns:
        Multi-paragraph human-readable summary string.
    """
    paragraphs: list[str] = []

    # ── Infrastructure paragraph ──────────────────────────────────────
    geo = scan_results.get("geo")
    ssl_res = scan_results.get("ssl")
    http = scan_results.get("http")

    infra_parts: list[str] = []
    target_domain = ""

    if geo and getattr(geo, "success", False):
        target_domain = f"The target resolves to {geo.ip}"
        if geo.city and geo.country:
            target_domain += f", geolocated in {geo.city}, {geo.country}"
        if geo.isp:
            target_domain += f" (ISP: {geo.isp})"
        target_domain += "."
        infra_parts.append(target_domain)
    elif geo and getattr(geo, "ip", None):
        infra_parts.append(f"The target resolves to {geo.ip}.")

    if http and getattr(http, "success", False):
        server = getattr(http, "server", None)
        if server:
            infra_parts.append(f"The web server identifies as {server}.")

    if infra_parts:
        paragraphs.append(" ".join(infra_parts))

    # ── SSL/TLS paragraph ─────────────────────────────────────────────
    ssl_parts: list[str] = []
    if ssl_res and getattr(ssl_res, "success", False):
        tls = getattr(ssl_res, "tls_version", "unknown")
        issuer = getattr(ssl_res, "issuer", "unknown")
        days = getattr(ssl_res, "days_until_expiry", None)

        ssl_parts.append(
            f"The SSL certificate is issued by {issuer} using {tls}."
        )

        if getattr(ssl_res, "is_expired", False):
            ssl_parts.append("WARNING: The certificate has expired.")
        elif days is not None:
            if days < 30:
                ssl_parts.append(
                    f"The certificate expires in {days} days and should be renewed soon."
                )
            else:
                ssl_parts.append(
                    f"The certificate is valid for {days} more days."
                )

        grade = getattr(ssl_res, "grade", "N/A")
        ssl_parts.append(f"Certificate grade: {grade}.")

        if getattr(ssl_res, "has_weak_cipher", False):
            ssl_parts.append(
                "A weak cipher suite was detected in the TLS configuration."
            )
    elif ssl_res:
        ssl_parts.append(
            f"SSL/TLS analysis was unsuccessful: {getattr(ssl_res, 'error', 'unknown error')}."
        )

    if ssl_parts:
        paragraphs.append(" ".join(ssl_parts))

    # ── Security headers paragraph ────────────────────────────────────
    if http and getattr(http, "success", False):
        missing = getattr(http, "missing_security_headers", [])
        total_headers = len(getattr(http, "security_headers", {}))
        present = total_headers - len(missing)

        if not missing:
            paragraphs.append(
                "Security headers are fully configured. "
                "All recommended headers are present."
            )
        elif len(missing) <= 2:
            paragraphs.append(
                f"Security headers are mostly configured correctly "
                f"({present}/{total_headers} present), although "
                + " and ".join(missing) + " "
                + ("is" if len(missing) == 1 else "are") + " absent."
            )
        else:
            paragraphs.append(
                f"Security header configuration requires attention. "
                f"Only {present} of {total_headers} recommended headers are present. "
                f"Missing: {', '.join(missing[:5])}."
            )

    # ── DNS paragraph ─────────────────────────────────────────────────
    dns_res = scan_results.get("dns")
    if dns_res and getattr(dns_res, "success", False):
        dns_parts: list[str] = []
        spf = getattr(dns_res, "spf", None)
        dmarc = getattr(dns_res, "dmarc", None)
        dnssec = getattr(dns_res, "has_dnssec", False)

        email_sec: list[str] = []
        if spf:
            email_sec.append("SPF")
        if dmarc:
            email_sec.append("DMARC")

        if email_sec:
            dns_parts.append(
                f"Email security records are partially configured "
                f"({', '.join(email_sec)} present)."
            )
        else:
            dns_parts.append(
                "No email security records (SPF, DMARC) were found, "
                "leaving the domain vulnerable to email spoofing."
            )

        if dnssec:
            dns_parts.append("DNSSEC is enabled.")
        else:
            dns_parts.append("DNSSEC is not enabled.")

        if dns_parts:
            paragraphs.append(" ".join(dns_parts))

    # ── Admin & subdomain paragraph ───────────────────────────────────
    recon_parts: list[str] = []

    admin = scan_results.get("admin")
    if admin and getattr(admin, "success", False):
        accessible = getattr(admin, "accessible", [])
        auth_required = getattr(admin, "auth_required", [])
        if accessible:
            recon_parts.append(
                f"{len(accessible)} admin endpoint(s) returned accessible responses."
            )
        elif auth_required:
            recon_parts.append(
                "Administrative endpoints were found but require authentication."
            )
        else:
            recon_parts.append(
                "No publicly accessible admin panels were discovered."
            )

    subdomains = scan_results.get("subdomains")
    if subdomains and getattr(subdomains, "success", False):
        count = getattr(subdomains, "total_count", 0)
        if count > 0:
            recon_parts.append(
                f"{count} subdomain(s) were enumerated through passive reconnaissance."
            )

    if recon_parts:
        paragraphs.append(" ".join(recon_parts))

    # ── Shodan paragraph ──────────────────────────────────────────────
    shodan = scan_results.get("shodan")
    if shodan and getattr(shodan, "success", False):
        ports = getattr(shodan, "open_port_numbers", [])
        vulns = getattr(shodan, "vulns", [])
        shodan_parts: list[str] = []

        if ports:
            shodan_parts.append(
                f"Shodan reports {len(ports)} open port(s): {', '.join(str(p) for p in ports[:10])}."
            )
        if vulns:
            shodan_parts.append(
                f"{len(vulns)} known CVE(s) are associated with the host."
            )
        else:
            shodan_parts.append(
                "No known vulnerabilities were reported by Shodan."
            )

        if shodan_parts:
            paragraphs.append(" ".join(shodan_parts))

    # ── Risk assessment paragraph ─────────────────────────────────────
    if score:
        risk = getattr(score, "risk_level", "Unknown")
        grade = getattr(score, "grade", "N/A")
        score_val = getattr(score, "score", 0)
        num_findings = len(getattr(score, "findings", []))

        paragraphs.append(
            f"Overall security score: {score_val}/100 (Grade: {grade}). "
            f"Risk level: {risk}. "
            f"The assessment identified {num_findings} finding(s) across all modules."
        )

    # ── Fallback ──────────────────────────────────────────────────────
    if not paragraphs:
        return "Insufficient data was collected to generate an executive summary."

    return "\n\n".join(paragraphs)
