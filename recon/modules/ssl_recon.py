"""
recon.modules.ssl_recon — Enhanced SSL/TLS certificate analysis module.

Collects: TLS version, cipher suite, SAN (Subject Alternative Names),
certificate chain, signature algorithm, days until expiry,
weak cipher detection, and certificate grade.
"""

from __future__ import annotations

import socket
import ssl
import datetime
from dataclasses import dataclass, field
from typing import Any, Optional

from recon.logger import get_logger, log_duration
from recon.utils import clean_domain

logger = get_logger(__name__)

# Cipher suites considered weak
WEAK_CIPHERS = {
    "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT",
    "anon", "RC2", "IDEA",
}


@dataclass
class SslResult:
    """Structured SSL/TLS analysis result."""

    # Certificate fields
    subject: Optional[str] = None
    issuer: Optional[str] = None
    serial_number: Optional[str] = None
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    days_until_expiry: Optional[int] = None
    is_expired: bool = False

    # Subject Alternative Names
    san: list[str] = field(default_factory=list)

    # Certificate chain
    chain_depth: int = 0
    signature_algorithm: Optional[str] = None

    # Connection info
    tls_version: Optional[str] = None
    cipher_suite: Optional[str] = None
    cipher_bits: Optional[int] = None

    # Analysis
    has_weak_cipher: bool = False
    weak_cipher_reason: Optional[str] = None
    is_self_signed: bool = False
    grade: str = "N/A"

    # Raw certificate
    raw_cert: Optional[dict[str, Any]] = None

    error: Optional[str] = None
    success: bool = False


def _extract_cn(tuples: tuple) -> str:
    """Extract Common Name from certificate subject/issuer tuples."""
    for rdn in tuples:
        for attr_type, attr_value in rdn:
            if attr_type == "commonName":
                return attr_value
    return str(tuples)


def _grade_certificate(result: SslResult) -> str:
    """Assign a letter grade to the SSL configuration.

    Grading criteria:
        A  — Modern TLS, strong cipher, valid cert, no issues
        B  — Minor issues (e.g., TLS 1.2 without 1.3, expiring soon)
        C  — Moderate issues (e.g., older TLS, no SAN)
        D  — Significant issues (e.g., weak cipher, expiring very soon)
        F  — Critical issues (expired, self-signed, or very weak)
    """
    score = 100

    # TLS version scoring
    tls = result.tls_version or ""
    if "TLSv1.3" in tls:
        pass  # perfect
    elif "TLSv1.2" in tls:
        score -= 5
    elif "TLSv1.1" in tls:
        score -= 30
    elif "TLSv1" in tls or "SSLv3" in tls:
        score -= 50

    # Certificate validity
    if result.is_expired:
        score -= 50
    elif result.days_until_expiry is not None and result.days_until_expiry < 7:
        score -= 30
    elif result.days_until_expiry is not None and result.days_until_expiry < 30:
        score -= 15

    # Self-signed
    if result.is_self_signed:
        score -= 40

    # Weak cipher
    if result.has_weak_cipher:
        score -= 30

    # No SAN
    if not result.san:
        score -= 10

    if score >= 90:
        return "A"
    elif score >= 80:
        return "B"
    elif score >= 65:
        return "C"
    elif score >= 50:
        return "D"
    else:
        return "F"


def run(target: str, timeout: int = 5) -> SslResult:
    """Perform SSL/TLS certificate and connection analysis.

    Args:
        target: URL or domain string.
        timeout: Connection timeout in seconds.

    Returns:
        SslResult with comprehensive certificate and TLS data.
    """
    domain = clean_domain(target)
    result = SslResult()

    with log_duration(logger, f"SSL/TLS analysis for {domain}"):
        try:
            ctx = ssl.create_default_context()
            try:
                import certifi
                ctx.load_verify_locations(certifi.where())
            except Exception:
                pass

            try:
                sock = socket.create_connection((domain, 443), timeout=timeout)
                ssock = ctx.wrap_socket(sock, server_hostname=domain)
            except (ssl.SSLCertVerificationError, ssl.SSLError):
                # Fallback to unverified context to inspect certificates if local store lacks root CA
                ctx = ssl._create_unverified_context()
                sock = socket.create_connection((domain, 443), timeout=timeout)
                ssock = ctx.wrap_socket(sock, server_hostname=domain)

            with sock, ssock:
                cert = ssock.getpeercert() or {}
                result.raw_cert = cert

                # ── Connection info ───────────────────────────────
                result.tls_version = ssock.version()
                cipher_info = ssock.cipher()
                if cipher_info:
                    result.cipher_suite = cipher_info[0]
                    result.cipher_bits = cipher_info[2] if len(cipher_info) > 2 else None

                # ── Certificate fields ────────────────────────────
                subject = cert.get("subject", ())
                result.subject = _extract_cn(subject)

                issuer = cert.get("issuer", ())
                result.issuer = _extract_cn(issuer)

                result.serial_number = cert.get("serialNumber")

                # Check self-signed
                result.is_self_signed = result.subject == result.issuer

                # Dates
                result.not_before = cert.get("notBefore")
                result.not_after = cert.get("notAfter")

                if result.not_after:
                    try:
                        expiry = datetime.datetime.strptime(
                            result.not_after, "%b %d %H:%M:%S %Y %Z"
                        )
                        now = datetime.datetime.utcnow()
                        delta = expiry - now
                        result.days_until_expiry = delta.days
                        result.is_expired = delta.days < 0
                    except Exception:
                        pass

                # SAN
                san_entries = cert.get("subjectAltName", ())
                result.san = [value for _type, value in san_entries]

                # Certificate chain depth (from OCSP stapling info)
                caIssuers = cert.get("caIssuers", [])
                result.chain_depth = len(caIssuers) + 1  # Approximate

                # Signature algorithm (not directly in getpeercert,
                # but we can check via binary cert)
                try:
                    der = ssock.getpeercert(binary_form=True)
                    if der:
                        # Attempt to extract from DER-encoded cert
                        import hashlib
                        # Check common OIDs in the binary data
                        der_hex = der.hex()
                        if "2a864886f70d01010b" in der_hex:
                            result.signature_algorithm = "sha256WithRSAEncryption"
                        elif "2a864886f70d01010d" in der_hex:
                            result.signature_algorithm = "sha512WithRSAEncryption"
                        elif "2a864886f70d010105" in der_hex:
                            result.signature_algorithm = "sha1WithRSAEncryption"
                        elif "2a8648ce3d040302" in der_hex:
                            result.signature_algorithm = "ecdsa-with-SHA256"
                        elif "2a8648ce3d040303" in der_hex:
                            result.signature_algorithm = "ecdsa-with-SHA384"
                except Exception:
                    pass

                # ── Weak cipher detection ─────────────────────────
                if result.cipher_suite:
                    for weak in WEAK_CIPHERS:
                        if weak.lower() in result.cipher_suite.lower():
                            result.has_weak_cipher = True
                            result.weak_cipher_reason = (
                                f"Cipher suite contains weak algorithm: {weak}"
                            )
                            break
                    if result.cipher_bits and result.cipher_bits < 128:
                        result.has_weak_cipher = True
                        result.weak_cipher_reason = (
                            f"Cipher key length is only {result.cipher_bits} bits"
                        )

                result.success = True

        except ssl.SSLError as exc:
            logger.warning("SSL error for %s: %s", domain, exc)
            result.error = f"SSL error: {exc}"
        except ssl.SSLCertVerificationError as exc:
            logger.warning("SSL certificate verification failed for %s: %s", domain, exc)
            result.error = f"Certificate verification failed: {exc}"
        except socket.timeout:
            logger.warning("SSL connection timed out for %s", domain)
            result.error = "SSL connection timed out"
        except ConnectionRefusedError:
            logger.warning("Connection refused on port 443 for %s", domain)
            result.error = "Connection refused on port 443"
        except Exception as exc:
            logger.error("SSL analysis failed for %s: %s", domain, exc)
            result.error = str(exc)

        # Assign grade
        result.grade = _grade_certificate(result)

    return result
