"""
recon.config — Centralized configuration management.

Loads configuration from environment variables and .env files.
No secrets are stored in source code.

Usage:
    from recon.config import Config
    cfg = Config()
    print(cfg.smtp_server)
    print(cfg.shodan_api_key)
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


def _load_dotenv(env_path: Path) -> None:
    """Load .env file into os.environ if it exists.

    Lightweight implementation that avoids requiring python-dotenv
    as a hard dependency.
    """
    if not env_path.is_file():
        return
    with open(env_path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            # Remove surrounding quotes if present
            os.environ[key] = value


# ---------------------------------------------------------------------------
# Resolve project root (directory containing this package)
# ---------------------------------------------------------------------------
_PACKAGE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = _PACKAGE_DIR.parent

# Load .env from project root
_load_dotenv(PROJECT_ROOT / ".env")


@dataclass
class Config:
    """Application configuration loaded from environment variables.

    Precedence: explicit argument > environment variable > default value.
    """

    # ── SMTP ──────────────────────────────────────────────────────────
    smtp_server: str = field(
        default_factory=lambda: os.environ.get("RECON_SMTP_SERVER", "smtp.gmail.com")
    )
    smtp_port: int = field(
        default_factory=lambda: int(os.environ.get("RECON_SMTP_PORT", "587"))
    )
    smtp_user: str = field(
        default_factory=lambda: os.environ.get("RECON_SMTP_USER", "")
    )
    smtp_pass: str = field(
        default_factory=lambda: os.environ.get("RECON_SMTP_PASS", "")
    )
    smtp_use_tls: bool = field(
        default_factory=lambda: os.environ.get("RECON_SMTP_USE_TLS", "yes").lower()
        in ("yes", "true", "1")
    )

    # ── API Keys ──────────────────────────────────────────────────────
    shodan_api_key: str = field(
        default_factory=lambda: os.environ.get("SHODAN_API_KEY", "")
    )

    # ── Directories ───────────────────────────────────────────────────
    project_root: Path = field(default_factory=lambda: PROJECT_ROOT)
    screenshots_dir: Path = field(
        default_factory=lambda: Path(
            os.environ.get(
                "RECON_SCREENSHOTS_DIR",
                str(PROJECT_ROOT / "output" / "screenshots"),
            )
        )
    )
    documents_dir: Path = field(
        default_factory=lambda: Path(
            os.environ.get(
                "RECON_DOCUMENTS_DIR",
                str(PROJECT_ROOT / "reports"),
            )
        )
    )
    logs_dir: Path = field(
        default_factory=lambda: Path(
            os.environ.get(
                "RECON_LOGS_DIR",
                str(PROJECT_ROOT / "logs"),
            )
        )
    )
    wordlists_dir: Path = field(
        default_factory=lambda: Path(
            os.environ.get(
                "RECON_WORDLISTS_DIR",
                str(PROJECT_ROOT / "config" / "wordlists"),
            )
        )
    )

    # ── Timeouts ──────────────────────────────────────────────────────
    dns_timeout: int = field(
        default_factory=lambda: int(os.environ.get("RECON_DNS_TIMEOUT", "5"))
    )
    http_timeout: int = field(
        default_factory=lambda: int(os.environ.get("RECON_HTTP_TIMEOUT", "10"))
    )
    ssl_timeout: int = field(
        default_factory=lambda: int(os.environ.get("RECON_SSL_TIMEOUT", "5"))
    )
    screenshot_timeout: int = field(
        default_factory=lambda: int(os.environ.get("RECON_SCREENSHOT_TIMEOUT", "20"))
    )
    subdomain_timeout: int = field(
        default_factory=lambda: int(os.environ.get("RECON_SUBDOMAIN_TIMEOUT", "300"))
    )

    # ── Concurrency ───────────────────────────────────────────────────
    max_workers: int = field(
        default_factory=lambda: int(os.environ.get("RECON_MAX_WORKERS", "8"))
    )
    admin_scan_workers: int = field(
        default_factory=lambda: int(os.environ.get("RECON_ADMIN_SCAN_WORKERS", "10"))
    )

    # ── Assets ────────────────────────────────────────────────────────
    logo_path: Path = field(
        default_factory=lambda: PROJECT_ROOT / "assets" / "logo" / "ST.png"
    )
    bg_image_path: Path = field(
        default_factory=lambda: PROJECT_ROOT / "assets" / "logo" / "reconnaissance.jpeg"
    )

    def __post_init__(self) -> None:
        """Ensure output directories exist."""
        for directory in (
            self.screenshots_dir,
            self.documents_dir,
            self.logs_dir,
        ):
            directory.mkdir(parents=True, exist_ok=True)

    # ── Legacy compatibility ──────────────────────────────────────────
    def to_smtp_dict(self) -> dict[str, str]:
        """Return SMTP config as a dict for backward compatibility."""
        return {
            "smtp_server": self.smtp_server,
            "smtp_port": str(self.smtp_port),
            "smtp_user": self.smtp_user,
            "smtp_pass": self.smtp_pass,
            "use_tls": "yes" if self.smtp_use_tls else "no",
        }

    @classmethod
    def from_legacy_file(cls, filepath: str | Path) -> "Config":
        """Load config from the legacy smtp_config.txt format.

        This preserves backward compatibility with the original config
        file while encouraging migration to .env.
        """
        filepath = Path(filepath)
        if not filepath.is_file():
            return cls()

        kv: dict[str, str] = {}
        with open(filepath, "r", encoding="utf-8") as fh:
            for line in fh:
                if "=" in line:
                    key, _, value = line.strip().partition("=")
                    kv[key.strip()] = value.strip()

        return cls(
            smtp_server=kv.get("smtp_server", os.environ.get("RECON_SMTP_SERVER", "smtp.gmail.com")),
            smtp_port=int(kv.get("smtp_port", os.environ.get("RECON_SMTP_PORT", "587"))),
            smtp_user=kv.get("smtp_user", os.environ.get("RECON_SMTP_USER", "")),
            smtp_pass=kv.get("smtp_pass", os.environ.get("RECON_SMTP_PASS", "")),
            smtp_use_tls=kv.get("use_tls", "yes").lower() in ("yes", "true", "1"),
            shodan_api_key=kv.get(
                "shodan_api_key",
                os.environ.get("SHODAN_API_KEY", ""),
            ),
        )

    @classmethod
    def reload(cls) -> "Config":
        """Reload .env file and return a fresh Config instance."""
        _load_dotenv(PROJECT_ROOT / ".env")
        return cls()
