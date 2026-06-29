"""
recon.scoring — Security Score Engine.

Analyzes all collected reconnaissance data and produces:
  - A numeric security score (0–100)
  - A letter grade (A+ through F)
  - A risk level (Critical / High / Medium / Low / Informational)
  - A detailed list of findings with severity

Uses only collected evidence — never fabricates or infers data.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class Finding:
    """A single security finding with severity."""

    title: str
    description: str
    severity: str  # Critical, High, Medium, Low, Informational
    points_deducted: int = 0
    category: str = "General"


@dataclass
class SecurityScore:
    """Complete security score assessment."""

    score: int = 100
    grade: str = "A+"
    risk_level: str = "Low"
    findings: list[Finding] = field(default_factory=list)
    total_checks: int = 0
    passed_checks: int = 0
    failed_checks: int = 0


# ──────────────────────────────────────────────────────────────────────────────
# Grade / risk mapping
# ──────────────────────────────────────────────────────────────────────────────
def _score_to_grade(score: int) -> str:
    if score >= 95:
        return "A+"
    elif score >= 88:
        return "A"
    elif score >= 80:
        return "B"
    elif score >= 70:
        return "C"
    elif score >= 55:
        return "D"
    else:
        return "F"


def _score_to_risk(score: int, findings: list[Finding] = None) -> str:
    has_critical = any(f.severity == "Critical" for f in (findings or []))
    has_high = any(f.severity == "High" for f in (findings or []))
    
    if has_critical or score < 45:
        return "Critical"
    elif has_high or score < 65:
        return "High"
    elif score < 80:
        return "Medium"
    else:
        return "Low"


# ──────────────────────────────────────────────────────────────────────────────
# Scoring rules
# ──────────────────────────────────────────────────────────────────────────────
def calculate(scan_results: dict[str, Any]) -> SecurityScore:
    """Calculate the security score from all scan results.

    Args:
        scan_results: Dictionary of module name → result dataclass.

    Returns:
        SecurityScore with grade, risk level, and detailed findings.
    """
    ss = SecurityScore()
    findings: list[Finding] = []

    # ── HTTP Security Headers ─────────────────────────────────────────
    http = scan_results.get("http")
    if http and getattr(http, "success", False):
        missing = getattr(http, "missing_security_headers", [])

        header_scores = {
            "Strict-Transport-Security": (
                "Missing HSTS Header",
                "The server does not set Strict-Transport-Security, "
                "allowing downgrade attacks.",
                "Medium", 5,
            ),
            "Content-Security-Policy": (
                "Missing Content Security Policy",
                "No CSP header found. This increases XSS risk.",
                "Medium", 4,
            ),
            "X-Content-Type-Options": (
                "Missing X-Content-Type-Options",
                "Without nosniff, browsers may MIME-sniff responses.",
                "Low", 2,
            ),
            "X-Frame-Options": (
                "Missing X-Frame-Options",
                "The site may be vulnerable to clickjacking.",
                "Low", 2,
            ),
            "Referrer-Policy": (
                "Missing Referrer-Policy",
                "Referrer information may leak to third parties.",
                "Informational", 1,
            ),
            "Permissions-Policy": (
                "Missing Permissions-Policy",
                "Browser features are not explicitly restricted.",
                "Informational", 1,
            ),
            "X-XSS-Protection": (
                "Missing X-XSS-Protection",
                "Legacy XSS filter is not configured.",
                "Informational", 1,
            ),
        }

        for header_name, (title, desc, sev, pts) in header_scores.items():
            ss.total_checks += 1
            if header_name in missing:
                findings.append(Finding(
                    title=title, description=desc,
                    severity=sev, points_deducted=pts,
                    category="HTTP Security Headers",
                ))
                ss.failed_checks += 1
            else:
                ss.passed_checks += 1

        # Insecure cookies
        for cookie in getattr(http, "cookies", []):
            ss.total_checks += 1
            if not getattr(cookie, "secure", True):
                findings.append(Finding(
                    title=f"Insecure Cookie: {cookie.name}",
                    description="Cookie lacks the Secure flag and may be sent over HTTP.",
                    severity="Low", points_deducted=1,
                    category="Cookies",
                ))
                ss.failed_checks += 1
            else:
                ss.passed_checks += 1

        # CORS wildcard
        cors = getattr(http, "cors_origin", None)
        ss.total_checks += 1
        if cors == "*":
            findings.append(Finding(
                title="Permissive CORS Configuration",
                description="Access-Control-Allow-Origin is set to *, "
                            "allowing any origin to read responses.",
                severity="Medium", points_deducted=5,
                category="CORS",
            ))
            ss.failed_checks += 1
        else:
            ss.passed_checks += 1

    # ── SSL / TLS ─────────────────────────────────────────────────────
    ssl_res = scan_results.get("ssl")
    if ssl_res:
        ss.total_checks += 1
        if not getattr(ssl_res, "success", False):
            findings.append(Finding(
                title="No SSL/TLS Support",
                description="The server does not support HTTPS.",
                severity="Critical", points_deducted=20,
                category="SSL/TLS",
            ))
            ss.failed_checks += 1
        else:
            ss.passed_checks += 1

            # Expired cert
            ss.total_checks += 1
            if getattr(ssl_res, "is_expired", False):
                findings.append(Finding(
                    title="Expired SSL Certificate",
                    description="The SSL certificate has expired.",
                    severity="Critical", points_deducted=25,
                    category="SSL/TLS",
                ))
                ss.failed_checks += 1
            else:
                ss.passed_checks += 1

            # Self-signed
            ss.total_checks += 1
            if getattr(ssl_res, "is_self_signed", False):
                findings.append(Finding(
                    title="Self-Signed Certificate",
                    description="The certificate is self-signed and won't be trusted by browsers.",
                    severity="High", points_deducted=15,
                    category="SSL/TLS",
                ))
                ss.failed_checks += 1
            else:
                ss.passed_checks += 1

            # Weak cipher
            ss.total_checks += 1
            if getattr(ssl_res, "has_weak_cipher", False):
                findings.append(Finding(
                    title="Weak TLS Cipher Suite",
                    description=getattr(ssl_res, "weak_cipher_reason", "Weak cipher detected"),
                    severity="High", points_deducted=15,
                    category="SSL/TLS",
                ))
                ss.failed_checks += 1
            else:
                ss.passed_checks += 1

            # Expiring soon
            days = getattr(ssl_res, "days_until_expiry", None)
            if days is not None:
                ss.total_checks += 1
                if 0 < days < 30:
                    findings.append(Finding(
                        title="Certificate Expiring Soon",
                        description=f"The SSL certificate expires in {days} days.",
                        severity="Medium", points_deducted=8,
                        category="SSL/TLS",
                    ))
                    ss.failed_checks += 1
                else:
                    ss.passed_checks += 1

            # Old TLS version
            tls = getattr(ssl_res, "tls_version", "") or ""
            ss.total_checks += 1
            if "TLSv1.1" in tls or ("TLSv1" in tls and "TLSv1.2" not in tls and "TLSv1.3" not in tls):
                findings.append(Finding(
                    title="Outdated TLS Version",
                    description=f"Server uses {tls}, which is deprecated.",
                    severity="High", points_deducted=12,
                    category="SSL/TLS",
                ))
                ss.failed_checks += 1
            else:
                ss.passed_checks += 1

    # ── DNS ───────────────────────────────────────────────────────────
    dns_res = scan_results.get("dns")
    if dns_res and getattr(dns_res, "success", False):
        # SPF
        ss.total_checks += 1
        if not getattr(dns_res, "spf", None):
            findings.append(Finding(
                title="No SPF Record",
                description="No SPF record found. Email spoofing may be possible.",
                severity="Medium", points_deducted=3,
                category="DNS / Email Security",
            ))
            ss.failed_checks += 1
        else:
            ss.passed_checks += 1

        # DMARC
        ss.total_checks += 1
        if not getattr(dns_res, "dmarc", None):
            findings.append(Finding(
                title="No DMARC Record",
                description="No DMARC policy found. Email authentication is incomplete.",
                severity="Medium", points_deducted=3,
                category="DNS / Email Security",
            ))
            ss.failed_checks += 1
        else:
            ss.passed_checks += 1

        # CAA
        ss.total_checks += 1
        caa_values = dns_res.get_values("CAA") if hasattr(dns_res, "get_values") else []
        if not caa_values:
            findings.append(Finding(
                title="No CAA Record",
                description="No CAA record limits which CAs can issue certificates.",
                severity="Informational", points_deducted=1,
                category="DNS / Email Security",
            ))
            ss.failed_checks += 1
        else:
            ss.passed_checks += 1

        # DNSSEC
        ss.total_checks += 1
        if not getattr(dns_res, "has_dnssec", False):
            findings.append(Finding(
                title="DNSSEC Not Enabled",
                description="DNS responses are not cryptographically signed.",
                severity="Informational", points_deducted=1,
                category="DNS / Email Security",
            ))
            ss.failed_checks += 1
        else:
            ss.passed_checks += 1

    # ── Admin Panels ──────────────────────────────────────────────────
    admin = scan_results.get("admin")
    if admin and getattr(admin, "success", False):
        accessible = getattr(admin, "accessible", [])
        ss.total_checks += 1
        if accessible:
            findings.append(Finding(
                title="Exposed Admin Panel(s)",
                description=f"{len(accessible)} admin endpoint(s) returned 200 OK: "
                            + ", ".join(accessible[:5]),
                severity="High", points_deducted=12,
                category="Admin Exposure",
            ))
            ss.failed_checks += 1
        else:
            ss.passed_checks += 1

    # ── Shodan ────────────────────────────────────────────────────────
    shodan = scan_results.get("shodan")
    if shodan and getattr(shodan, "success", False):
        # Known CVEs
        vulns = getattr(shodan, "vulns", [])
        ss.total_checks += 1
        if vulns:
            findings.append(Finding(
                title=f"{len(vulns)} Known CVE(s) Detected",
                description="Shodan reports known vulnerabilities: "
                            + ", ".join(vulns[:10]),
                severity="Critical" if len(vulns) > 5 else "High",
                points_deducted=min(len(vulns) * 3, 20),
                category="Vulnerabilities",
            ))
            ss.failed_checks += 1
        else:
            ss.passed_checks += 1

        # Dangerous ports
        dangerous_ports = {21, 23, 25, 445, 1433, 3306, 3389, 5432, 5900, 6379, 27017}
        open_ports = set(getattr(shodan, "open_port_numbers", []))
        exposed = open_ports & dangerous_ports
        ss.total_checks += 1
        if exposed:
            findings.append(Finding(
                title="Dangerous Ports Exposed",
                description=f"Potentially dangerous ports are publicly accessible: "
                            + ", ".join(str(p) for p in sorted(exposed)),
                severity="High", points_deducted=min(len(exposed) * 5, 15),
                category="Network Exposure",
            ))
            ss.failed_checks += 1
        else:
            ss.passed_checks += 1

    # ── Calculate final score ─────────────────────────────────────────
    total_deducted = sum(f.points_deducted for f in findings)
    ss.score = max(0, 100 - total_deducted)
    ss.grade = _score_to_grade(ss.score)
    ss.risk_level = _score_to_risk(ss.score)
    ss.findings = sorted(findings, key=lambda f: f.points_deducted, reverse=True)

    return ss
