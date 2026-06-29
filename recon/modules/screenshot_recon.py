"""
recon.modules.screenshot_recon — Enhanced screenshot capture module.

Captures three viewport variants:
  - Desktop (1280×800)
  - Mobile  (375×812, iPhone viewport)
  - Full-page (scroll-stitched, desktop width)

Stores screenshots in target-specific subdirectories.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from recon.config import Config
from recon.logger import get_logger, log_duration
from recon.utils import clean_domain, ensure_scheme, safe_filename, timestamp_str

logger = get_logger(__name__)


@dataclass
class ScreenshotResult:
    """Structured screenshot capture result."""

    desktop_path: Optional[str] = None
    mobile_path: Optional[str] = None
    fullpage_path: Optional[str] = None

    desktop_ok: bool = False
    mobile_ok: bool = False
    fullpage_ok: bool = False

    error: Optional[str] = None
    success: bool = False


def _capture(
    url: str,
    output_path: str,
    width: int,
    height: int,
    fullpage: bool = False,
    timeout: int = 20,
) -> tuple[Optional[str], Optional[str]]:
    """Capture a single screenshot using headless Chrome.

    Returns:
        Tuple of (saved_path, error_message).
    """
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        from selenium.webdriver.chrome.service import Service
        from webdriver_manager.chrome import ChromeDriverManager
    except ImportError as exc:
        return None, f"Missing dependency: {exc}"

    try:
        options = Options()
        options.add_argument("--headless=new")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-gpu")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument(f"--window-size={width},{height}")

        if width <= 500:
            # Mobile user agent
            options.add_argument(
                '--user-agent=Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) '
                'AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1'
            )

        driver = webdriver.Chrome(
            service=Service(ChromeDriverManager().install()),
            options=options,
        )
        driver.set_page_load_timeout(timeout)
        driver.get(url)
        driver.implicitly_wait(2)

        if fullpage:
            # Get full page height and resize
            total_height = driver.execute_script(
                "return Math.max("
                "  document.body.scrollHeight, "
                "  document.body.offsetHeight, "
                "  document.documentElement.clientHeight, "
                "  document.documentElement.scrollHeight, "
                "  document.documentElement.offsetHeight"
                ")"
            )
            # Cap at 10000px to prevent memory issues
            total_height = min(total_height, 10000)
            driver.set_window_size(width, total_height)
            driver.implicitly_wait(1)

        driver.save_screenshot(output_path)
        driver.quit()
        return output_path, None

    except Exception as exc:
        return None, str(exc)


def run(
    target: str,
    config: Optional[Config] = None,
    timeout: int = 20,
) -> ScreenshotResult:
    """Capture desktop, mobile, and full-page screenshots.

    Args:
        target: URL or domain string.
        config: Optional Config instance.
        timeout: Page load timeout in seconds.

    Returns:
        ScreenshotResult with paths to captured screenshots.
    """
    cfg = config or Config()
    url = ensure_scheme(target)
    domain = clean_domain(target)
    result = ScreenshotResult()

    # Create target-specific screenshot directory
    ts = timestamp_str()
    target_dir = cfg.screenshots_dir / safe_filename(domain)
    target_dir.mkdir(parents=True, exist_ok=True)

    with log_duration(logger, f"Screenshot capture for {url}"):
        # ── Desktop screenshot ────────────────────────────────────────
        desktop_path = str(target_dir / f"desktop_{ts}.png")
        path, err = _capture(url, desktop_path, 1280, 800, timeout=timeout)
        if path:
            result.desktop_path = path
            result.desktop_ok = True
            logger.info("Desktop screenshot saved: %s", path)
        else:
            logger.warning("Desktop screenshot failed: %s", err)

        # ── Mobile screenshot ─────────────────────────────────────────
        mobile_path = str(target_dir / f"mobile_{ts}.png")
        path, err = _capture(url, mobile_path, 375, 812, timeout=timeout)
        if path:
            result.mobile_path = path
            result.mobile_ok = True
            logger.info("Mobile screenshot saved: %s", path)
        else:
            logger.warning("Mobile screenshot failed: %s", err)

        # ── Full-page screenshot ──────────────────────────────────────
        fullpage_path = str(target_dir / f"fullpage_{ts}.png")
        path, err = _capture(
            url, fullpage_path, 1280, 800, fullpage=True, timeout=timeout
        )
        if path:
            result.fullpage_path = path
            result.fullpage_ok = True
            logger.info("Full-page screenshot saved: %s", path)
        else:
            logger.warning("Full-page screenshot failed: %s", err)

        result.success = result.desktop_ok or result.mobile_ok or result.fullpage_ok
        if not result.success:
            result.error = "All screenshot captures failed"

    return result
