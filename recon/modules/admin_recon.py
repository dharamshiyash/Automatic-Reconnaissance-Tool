"""
recon.modules.admin_recon — Admin panel discovery module.

Scans for common admin panel paths using a configurable wordlist.
Classifies results by response type: Accessible, Redirected,
Forbidden, Auth Required, Not Found, and detects false positives.
"""

from __future__ import annotations

import concurrent.futures
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import requests

from recon.config import Config
from recon.logger import get_logger, log_duration
from recon.utils import ensure_scheme

logger = get_logger(__name__)

# Default paths if no wordlist file is found
DEFAULT_PATHS = [
    "/admin", "/administrator", "/wp-admin", "/login", "/admin.php",
    "/manage", "/panel", "/cpanel", "/dashboard", "/wp-login.php",
    "/admin/login", "/user/login", "/signin", "/auth", "/admin/",
    "/manager", "/console", "/webadmin", "/siteadmin", "/moderator",
    "/controlpanel", "/admin/dashboard", "/admin/index", "/cms",
    "/backend", "/secure", "/portal", "/admin/login.php",
    "/admin/admin", "/admin/controlpanel", "/adminpanel",
    "/admin/cp", "/admin/account", "/admin/admin-login",
    "/adminLogin", "/admin_area", "/admin1", "/admin2",
    "/phpmyadmin", "/pma", "/adminer", "/dbadmin",
    "/.env", "/.git", "/.htaccess", "/.htpasswd",
    "/server-status", "/server-info", "/xmlrpc.php",
    "/api", "/api/v1", "/api/v2", "/graphql",
    "/swagger", "/swagger-ui", "/docs", "/redoc",
    "/robots.txt", "/sitemap.xml", "/wp-json",
    "/config", "/configuration", "/setup", "/install",
    "/debug", "/trace", "/test", "/status", "/health",
    "/backup", "/dump", "/export", "/download",
]


@dataclass
class AdminFinding:
    """A single admin panel discovery finding."""

    url: str
    status_code: int
    classification: str  # Accessible, Redirected, Forbidden, Auth Required, Not Found
    content_length: Optional[int] = None
    redirect_url: Optional[str] = None
    is_false_positive: bool = False


@dataclass
class AdminResult:
    """Structured admin panel discovery result."""

    findings: list[AdminFinding] = field(default_factory=list)
    paths_scanned: int = 0
    accessible: list[str] = field(default_factory=list)
    redirected: list[str] = field(default_factory=list)
    forbidden: list[str] = field(default_factory=list)
    auth_required: list[str] = field(default_factory=list)
    error: Optional[str] = None
    success: bool = False


def _load_wordlist(config: Config) -> list[str]:
    """Load admin paths from wordlist file, falling back to defaults."""
    wordlist_path = config.wordlists_dir / "admin_paths.txt"
    if wordlist_path.is_file():
        try:
            with open(wordlist_path, "r", encoding="utf-8") as fh:
                paths = [
                    line.strip()
                    for line in fh
                    if line.strip() and not line.startswith("#")
                ]
                if paths:
                    logger.info("Loaded %d admin paths from wordlist", len(paths))
                    return paths
        except Exception as exc:
            logger.warning("Failed to read wordlist: %s", exc)

    logger.debug("Using default admin paths (%d entries)", len(DEFAULT_PATHS))
    return DEFAULT_PATHS


def _check_path(
    base_url: str,
    path: str,
    timeout: int,
    baseline_length: Optional[int],
) -> Optional[AdminFinding]:
    """Check a single path and classify the response."""
    url = base_url.rstrip("/") + path
    try:
        resp = requests.get(
            url,
            timeout=timeout,
            allow_redirects=False,
            headers={"User-Agent": "Mozilla/5.0 (compatible; ReconTool/2.0)"},
        )
    except Exception:
        return None

    sc = resp.status_code
    cl = len(resp.content)

    # Skip obvious 404s
    if sc == 404:
        return None

    # Classify
    if sc == 200:
        classification = "Accessible"
    elif sc in (301, 302, 303, 307, 308):
        classification = "Redirected"
    elif sc == 403:
        classification = "Forbidden"
    elif sc == 401:
        classification = "Auth Required"
    else:
        return None

    finding = AdminFinding(
        url=url,
        status_code=sc,
        classification=classification,
        content_length=cl,
    )

    # Redirect target
    if sc in (301, 302, 303, 307, 308):
        finding.redirect_url = resp.headers.get("Location")

    # False positive detection: if the 200 response has the same
    # content length as a known 404 page, it's likely a soft 404
    if sc == 200 and baseline_length and abs(cl - baseline_length) < 50:
        finding.is_false_positive = True

    return finding


def run(
    target: str,
    config: Optional[Config] = None,
    timeout: int = 6,
    max_workers: int = 10,
) -> AdminResult:
    """Discover admin panels and sensitive paths.

    Args:
        target: URL or domain string.
        config: Optional Config instance for wordlist loading.
        timeout: HTTP request timeout per path.
        max_workers: Concurrent request threads.

    Returns:
        AdminResult with classified findings.
    """
    cfg = config or Config()
    base_url = ensure_scheme(target)
    result = AdminResult()
    paths = _load_wordlist(cfg)
    result.paths_scanned = len(paths)

    with log_duration(logger, f"Admin panel scan for {base_url} ({len(paths)} paths)"):
        # ── Establish baseline (false positive detection) ─────────────
        baseline_length: Optional[int] = None
        try:
            resp_404 = requests.get(
                f"{base_url.rstrip('/')}/this-path-definitely-does-not-exist-12345",
                timeout=timeout,
                allow_redirects=False,
            )
            if resp_404.status_code == 200:
                baseline_length = len(resp_404.content)
                logger.debug("Baseline 404 content length: %d", baseline_length)
        except Exception:
            pass

        # ── Concurrent path scanning ─────────────────────────────────
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(_check_path, base_url, path, timeout, baseline_length): path
                for path in paths
            }
            for future in concurrent.futures.as_completed(futures):
                finding = future.result()
                if finding and not finding.is_false_positive:
                    result.findings.append(finding)

                    # Categorize
                    if finding.classification == "Accessible":
                        result.accessible.append(finding.url)
                    elif finding.classification == "Redirected":
                        result.redirected.append(finding.url)
                    elif finding.classification == "Forbidden":
                        result.forbidden.append(finding.url)
                    elif finding.classification == "Auth Required":
                        result.auth_required.append(finding.url)

        result.success = True

    logger.info(
        "Admin scan complete: %d accessible, %d auth, %d forbidden, %d redirected",
        len(result.accessible),
        len(result.auth_required),
        len(result.forbidden),
        len(result.redirected),
    )
    return result
