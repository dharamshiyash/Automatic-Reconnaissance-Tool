"""
recon.engine — Reconnaissance orchestration engine.

Manages concurrent execution of recon modules with:
  - Dependency-aware scheduling
  - ThreadPoolExecutor for parallel independent modules
  - Progress callbacks for GUI updates
  - Module status tracking (pending/running/success/failed)
"""

from __future__ import annotations

import time
import concurrent.futures
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional

from recon.config import Config
from recon.logger import get_logger, log_duration, setup_logging
from recon.utils import timestamp_iso

logger = get_logger(__name__)


class ModuleStatus(Enum):
    """Status of a recon module."""

    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class ModuleInfo:
    """Tracking info for a single module."""

    name: str
    display_name: str
    status: ModuleStatus = ModuleStatus.PENDING
    duration: float = 0.0
    error: Optional[str] = None
    result: Any = None


@dataclass
class ScanResult:
    """Complete scan result container."""

    target: str = ""
    start_time: str = ""
    end_time: str = ""
    total_duration: float = 0.0
    modules: dict[str, ModuleInfo] = field(default_factory=dict)
    results: dict[str, Any] = field(default_factory=dict)
    score: Any = None
    summary: str = ""


# Type for progress callback: (module_name, status, progress_pct)
ProgressCallback = Callable[[str, ModuleStatus, float], None]


class ReconEngine:
    """Orchestrates reconnaissance modules with concurrent execution.

    Usage::

        engine = ReconEngine(config)
        engine.on_progress = my_callback  # optional
        scan = engine.run("https://example.com")
    """

    def __init__(self, config: Optional[Config] = None) -> None:
        self.config = config or Config()
        self.on_progress: Optional[ProgressCallback] = None
        self._modules: dict[str, ModuleInfo] = {}

        setup_logging(self.config)

    def _notify(self, name: str, status: ModuleStatus, pct: float) -> None:
        """Fire progress callback if set."""
        if self.on_progress:
            try:
                self.on_progress(name, status, pct)
            except Exception:
                pass

    def _run_module(
        self,
        name: str,
        display_name: str,
        func: Callable,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        """Execute a single module with tracking."""
        info = ModuleInfo(name=name, display_name=display_name)
        self._modules[name] = info

        info.status = ModuleStatus.RUNNING
        self._notify(name, ModuleStatus.RUNNING, 0)

        start = time.perf_counter()
        try:
            result = func(*args, **kwargs)
            info.duration = time.perf_counter() - start

            # Check if module reports success
            success = getattr(result, "success", True)
            if success:
                info.status = ModuleStatus.SUCCESS
            else:
                info.status = ModuleStatus.FAILED
                info.error = getattr(result, "error", None)

            info.result = result
            self._notify(name, info.status, 100)
            return result

        except Exception as exc:
            info.duration = time.perf_counter() - start
            info.status = ModuleStatus.FAILED
            info.error = str(exc)
            self._notify(name, ModuleStatus.FAILED, 100)
            logger.error("Module %s failed: %s", name, exc)
            return None

    def run(self, target: str) -> ScanResult:
        """Execute full reconnaissance scan on the target.

        Runs modules concurrently where possible, respecting
        dependencies (e.g., IP resolution before GeoIP).

        Args:
            target: URL or domain to scan.

        Returns:
            ScanResult with all module results, score, and summary.
        """
        scan = ScanResult(target=target, start_time=timestamp_iso())
        total_start = time.perf_counter()
        total_modules = 11  # Total module count for progress tracking
        completed = 0

        logger.info("=" * 60)
        logger.info("Starting reconnaissance on: %s", target)
        logger.info("=" * 60)

        from recon.modules import (
            whois_recon,
            dns_recon,
            http_recon,
            ssl_recon,
            geo_recon,
            tech_recon,
            admin_recon,
            subdomain_recon,
            shodan_recon,
            screenshot_recon,
            html_meta_recon,
        )
        from recon import scoring, summary

        # ── Phase 1: Independent modules (concurrent) ────────────────
        phase1_modules = {
            "whois": ("WHOIS Lookup", whois_recon.run, (target,), {}),
            "dns": ("DNS Analysis", dns_recon.run, (target, self.config.dns_timeout), {}),
            "http": ("HTTP Analysis", http_recon.run, (target, self.config.http_timeout), {}),
            "ssl": ("SSL/TLS Analysis", ssl_recon.run, (target, self.config.ssl_timeout), {}),
            "geo": ("Geo-IP Lookup", geo_recon.run, (target,), {}),
            "html_meta": ("HTML Metadata", html_meta_recon.run, (target,), {}),
            "tech": ("Technology Detection", tech_recon.run, (target,), {}),
        }

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.config.max_workers
        ) as executor:
            futures = {}
            for name, (display, func, args, kwargs) in phase1_modules.items():
                future = executor.submit(
                    self._run_module, name, display, func, *args, **kwargs
                )
                futures[future] = name

            for future in concurrent.futures.as_completed(futures):
                name = futures[future]
                result = future.result()
                if result is not None:
                    scan.results[name] = result
                completed += 1
                pct = (completed / total_modules) * 100
                self._notify(name, ModuleStatus.SUCCESS, pct)

        # ── Phase 2: Modules that benefit from phase 1 results ───────
        # Admin scan (concurrent paths)
        admin_result = self._run_module(
            "admin", "Admin Panel Discovery",
            admin_recon.run, target, self.config,
            self.config.http_timeout, self.config.admin_scan_workers,
        )
        if admin_result:
            scan.results["admin"] = admin_result
        completed += 1

        # Subdomain enumeration
        sub_result = self._run_module(
            "subdomains", "Subdomain Enumeration",
            subdomain_recon.run, target, self.config, self.config.subdomain_timeout,
        )
        if sub_result:
            scan.results["subdomains"] = sub_result
        completed += 1

        # Shodan (requires IP, but handles resolution internally)
        shodan_result = self._run_module(
            "shodan", "Shodan Intelligence",
            shodan_recon.run, target, self.config,
        )
        if shodan_result:
            scan.results["shodan"] = shodan_result
        completed += 1

        # Screenshot (slowest, run last)
        screenshot_result = self._run_module(
            "screenshot", "Screenshot Capture",
            screenshot_recon.run, target, self.config, self.config.screenshot_timeout,
        )
        if screenshot_result:
            scan.results["screenshot"] = screenshot_result
        completed += 1

        # ── Phase 3: Analysis (depends on all results) ────────────────
        logger.info("Calculating security score...")
        scan.score = scoring.calculate(scan.results)
        logger.info(
            "Security Score: %d/100 (Grade: %s, Risk: %s)",
            scan.score.score, scan.score.grade, scan.score.risk_level,
        )

        logger.info("Generating executive summary...")
        scan.summary = summary.generate(scan.results, scan.score)

        # ── Finalize ──────────────────────────────────────────────────
        scan.end_time = timestamp_iso()
        scan.total_duration = time.perf_counter() - total_start
        scan.modules = dict(self._modules)

        logger.info("=" * 60)
        logger.info(
            "Reconnaissance complete in %.1fs — Score: %d (%s)",
            scan.total_duration, scan.score.score, scan.score.grade,
        )
        logger.info("=" * 60)

        return scan
