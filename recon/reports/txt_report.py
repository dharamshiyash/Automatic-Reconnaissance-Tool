"""
recon.reports.txt_report — Enhanced text report generator.

Produces a well-formatted, structured plain-text report from scan results.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from recon.config import Config
from recon.utils import safe_filename, timestamp_str


def generate(scan: Any, config: Optional[Config] = None) -> str:
    """Generate a formatted text report and save to disk.

    Args:
        scan: ScanResult from the engine.
        config: Optional Config for output directory.

    Returns:
        Path to the saved report file.
    """
    cfg = config or Config()
    lines: list[str] = []

    def section(title: str) -> None:
        lines.append("")
        lines.append("=" * 70)
        lines.append(f"  {title}")
        lines.append("=" * 70)

    def subsection(title: str) -> None:
        lines.append("")
        lines.append(f"--- {title} ---")

    # ── Header ────────────────────────────────────────────────────────
    lines.append("╔" + "═" * 68 + "╗")
    lines.append("║" + "RECONNAISSANCE REPORT".center(68) + "║")
    lines.append("╚" + "═" * 68 + "╝")
    lines.append("")
    lines.append(f"  Target:     {scan.target}")
    lines.append(f"  Scan Start: {scan.start_time}")
    lines.append(f"  Scan End:   {scan.end_time}")
    lines.append(f"  Duration:   {scan.total_duration:.1f}s")

    # ── Security Score ────────────────────────────────────────────────
    if scan.score:
        section("SECURITY ASSESSMENT")
        lines.append(f"  Score:      {scan.score.score}/100")
        lines.append(f"  Grade:      {scan.score.grade}")
        lines.append(f"  Risk Level: {scan.score.risk_level}")
        lines.append(f"  Findings:   {len(scan.score.findings)}")
        if scan.score.findings:
            lines.append("")
            for f in scan.score.findings:
                lines.append(f"  [{f.severity:>13}] {f.title}")
                lines.append(f"                  {f.description}")

    # ── Executive Summary ─────────────────────────────────────────────
    if scan.summary:
        section("EXECUTIVE SUMMARY")
        for para in scan.summary.split("\n\n"):
            lines.append(f"  {para}")
            lines.append("")

    # ── Geo-IP ────────────────────────────────────────────────────────
    geo = scan.results.get("geo")
    if geo and getattr(geo, "success", False):
        section("NETWORK INFORMATION")
        lines.append(f"  IP Address: {geo.ip}")
        lines.append(f"  Location:   {geo.city}, {geo.region}, {geo.country}")
        lines.append(f"  ISP:        {geo.isp}")
        lines.append(f"  Org:        {geo.org}")
        lines.append(f"  ASN:        {geo.as_number}")

    # ── WHOIS ─────────────────────────────────────────────────────────
    w = scan.results.get("whois")
    if w and getattr(w, "success", False):
        section("WHOIS INFORMATION")
        lines.append(f"  Domain:     {w.domain_name}")
        lines.append(f"  Registrar:  {w.registrar}")
        lines.append(f"  Created:    {w.creation_date}")
        lines.append(f"  Expires:    {w.expiration_date}")
        lines.append(f"  Name Servers: {', '.join(w.name_servers)}")
        if w.emails:
            lines.append(f"  Emails:     {', '.join(w.emails)}")

    # ── DNS ───────────────────────────────────────────────────────────
    dns = scan.results.get("dns")
    if dns and getattr(dns, "success", False):
        section("DNS RECORDS")
        for rtype, rec in dns.records.items():
            vals = rec.values if rec.values else ["None"]
            ttl_str = f" (TTL: {rec.ttl})" if rec.ttl else ""
            lines.append(f"  {rtype:>8}: {', '.join(vals)}{ttl_str}")
        lines.append(f"  SPF:        {dns.spf or 'Not found'}")
        lines.append(f"  DMARC:      {dns.dmarc or 'Not found'}")
        lines.append(f"  DNSSEC:     {'Yes' if dns.has_dnssec else 'No'}")
        lines.append(f"  Rev DNS:    {dns.reverse_dns or 'N/A'}")

    # ── HTTP ──────────────────────────────────────────────────────────
    http = scan.results.get("http")
    if http and getattr(http, "success", False):
        section("HTTP ANALYSIS")
        lines.append(f"  Server:     {http.server}")
        lines.append(f"  Status:     {http.status_code}")
        lines.append(f"  Final URL:  {http.final_url}")

        subsection("Security Headers")
        for header, value in http.security_headers.items():
            status = "✓" if value else "✗"
            lines.append(f"  {status} {header}: {value or 'MISSING'}")

        if http.cookies:
            subsection("Cookies")
            for c in http.cookies:
                flags = []
                if c.secure:
                    flags.append("Secure")
                if c.httponly:
                    flags.append("HttpOnly")
                if c.samesite:
                    flags.append(f"SameSite={c.samesite}")
                lines.append(f"  {c.name}: {', '.join(flags) or 'No security flags'}")

        if http.robots_found:
            subsection("robots.txt")
            if http.robots_txt:
                for line in http.robots_txt.split("\n")[:20]:
                    lines.append(f"  {line}")

    # ── SSL ───────────────────────────────────────────────────────────
    ssl_r = scan.results.get("ssl")
    if ssl_r and getattr(ssl_r, "success", False):
        section("SSL/TLS CERTIFICATE")
        lines.append(f"  Subject:    {ssl_r.subject}")
        lines.append(f"  Issuer:     {ssl_r.issuer}")
        lines.append(f"  TLS Ver:    {ssl_r.tls_version}")
        lines.append(f"  Cipher:     {ssl_r.cipher_suite}")
        lines.append(f"  Grade:      {ssl_r.grade}")
        lines.append(f"  Valid:      {ssl_r.not_before} – {ssl_r.not_after}")
        lines.append(f"  Expires In: {ssl_r.days_until_expiry} days")
        lines.append(f"  Sig Algo:   {ssl_r.signature_algorithm or 'N/A'}")
        if ssl_r.san:
            lines.append(f"  SAN:        {', '.join(ssl_r.san[:10])}")

    # ── Technology ────────────────────────────────────────────────────
    tech = scan.results.get("tech")
    if tech and getattr(tech, "success", False):
        section("TECHNOLOGY STACK")
        for category, techs in tech.categories.items():
            lines.append(f"  {category}: {', '.join(techs)}")

    # ── Admin Panels ──────────────────────────────────────────────────
    admin = scan.results.get("admin")
    if admin and getattr(admin, "success", False):
        section("ADMIN PANEL DISCOVERY")
        lines.append(f"  Paths Scanned: {admin.paths_scanned}")
        for finding in admin.findings[:30]:
            lines.append(f"  [{finding.classification:>15}] {finding.url} ({finding.status_code})")

    # ── Subdomains ────────────────────────────────────────────────────
    subs = scan.results.get("subdomains")
    if subs and getattr(subs, "success", False) and subs.subdomains:
        section("SUBDOMAIN ENUMERATION")
        lines.append(f"  Total Found: {subs.total_count}")
        lines.append(f"  Sources:     {', '.join(subs.sources_used)}")
        for s in subs.subdomains[:50]:
            lines.append(f"  • {s}")
        if subs.total_count > 50:
            lines.append(f"  ... and {subs.total_count - 50} more")

    # ── Shodan ────────────────────────────────────────────────────────
    shodan = scan.results.get("shodan")
    if shodan and getattr(shodan, "success", False):
        section("SHODAN INTELLIGENCE")
        lines.append(f"  IP:         {shodan.ip}")
        lines.append(f"  Org:        {shodan.org}")
        lines.append(f"  ISP:        {shodan.isp}")
        lines.append(f"  ASN:        {shodan.asn}")
        lines.append(f"  OS:         {shodan.os}")
        lines.append(f"  Last Scan:  {shodan.last_update}")
        if shodan.hostnames:
            lines.append(f"  Hostnames:  {', '.join(shodan.hostnames)}")
        if shodan.ports:
            subsection("Open Ports")
            for p in shodan.ports:
                product = p.product or "unknown"
                version = f" v{p.version}" if p.version else ""
                lines.append(f"  {p.port}/{p.transport}: {product}{version}")
        if shodan.vulns:
            subsection("Known CVEs")
            for v in shodan.vulns[:20]:
                lines.append(f"  • {v}")

    # ── Footer ────────────────────────────────────────────────────────
    lines.append("")
    lines.append("=" * 70)
    lines.append("  End of Report")
    lines.append("=" * 70)

    content = "\n".join(lines)

    # Save to file
    filename = cfg.documents_dir / f"{safe_filename(scan.target)}_report_{timestamp_str()}.txt"
    filename.parent.mkdir(parents=True, exist_ok=True)
    with open(filename, "w", encoding="utf-8") as fh:
        fh.write(content)

    return str(filename)
