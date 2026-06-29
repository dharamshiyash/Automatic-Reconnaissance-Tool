"""
recon.logger — Structured logging for the reconnaissance framework.

Provides:
  - Rotating file logs: recon.log, errors.log, debug.log
  - Console output with color-coded levels
  - Module execution duration tracking
  - Per-module loggers via get_logger(__name__)

Usage:
    from recon.logger import get_logger
    logger = get_logger(__name__)
    logger.info("Starting DNS scan...")
"""

from __future__ import annotations

import logging
import time
from contextlib import contextmanager
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Generator

from recon.config import Config


# ---------------------------------------------------------------------------
# ANSI color codes for console output
# ---------------------------------------------------------------------------
class _Colors:
    RESET = "\033[0m"
    GREY = "\033[38;5;240m"
    CYAN = "\033[36m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    RED = "\033[31m"
    BOLD_RED = "\033[1;31m"


class _ColorFormatter(logging.Formatter):
    """Console formatter with color-coded log levels."""

    _LEVEL_COLORS = {
        logging.DEBUG: _Colors.GREY,
        logging.INFO: _Colors.CYAN,
        logging.WARNING: _Colors.YELLOW,
        logging.ERROR: _Colors.RED,
        logging.CRITICAL: _Colors.BOLD_RED,
    }

    def __init__(self, fmt: str | None = None, datefmt: str | None = None) -> None:
        super().__init__(fmt=fmt, datefmt=datefmt)

    def format(self, record: logging.LogRecord) -> str:
        color = self._LEVEL_COLORS.get(record.levelno, _Colors.RESET)
        record.levelname = f"{color}{record.levelname:<8}{_Colors.RESET}"
        record.msg = f"{_Colors.GREEN}{record.msg}{_Colors.RESET}"
        return super().format(record)


# ---------------------------------------------------------------------------
# Singleton flag — only configure once
# ---------------------------------------------------------------------------
_configured = False


def setup_logging(config: Config | None = None) -> None:
    """Initialize the logging subsystem.

    Creates rotating file handlers for recon.log, errors.log, debug.log
    and a color-coded console handler.  Safe to call multiple times — only
    the first invocation takes effect.
    """
    global _configured
    if _configured:
        return
    _configured = True

    cfg = config or Config()
    logs_dir = cfg.logs_dir
    logs_dir.mkdir(parents=True, exist_ok=True)

    root = logging.getLogger("recon")
    root.setLevel(logging.DEBUG)
    root.propagate = False

    file_fmt = logging.Formatter(
        fmt="%(asctime)s │ %(levelname)-8s │ %(name)-28s │ %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    console_fmt = _ColorFormatter(
        fmt="%(asctime)s │ %(levelname)s │ %(message)s",
        datefmt="%H:%M:%S",
    )

    # ── Main log (INFO+) ──────────────────────────────────────────────
    main_handler = RotatingFileHandler(
        logs_dir / "recon.log",
        maxBytes=5 * 1024 * 1024,  # 5 MB
        backupCount=3,
        encoding="utf-8",
    )
    main_handler.setLevel(logging.INFO)
    main_handler.setFormatter(file_fmt)
    root.addHandler(main_handler)

    # ── Error log (WARNING+) ──────────────────────────────────────────
    error_handler = RotatingFileHandler(
        logs_dir / "errors.log",
        maxBytes=2 * 1024 * 1024,
        backupCount=3,
        encoding="utf-8",
    )
    error_handler.setLevel(logging.WARNING)
    error_handler.setFormatter(file_fmt)
    root.addHandler(error_handler)

    # ── Debug log (everything) ────────────────────────────────────────
    debug_handler = RotatingFileHandler(
        logs_dir / "debug.log",
        maxBytes=10 * 1024 * 1024,
        backupCount=2,
        encoding="utf-8",
    )
    debug_handler.setLevel(logging.DEBUG)
    debug_handler.setFormatter(file_fmt)
    root.addHandler(debug_handler)

    # ── Console (INFO+) ──────────────────────────────────────────────
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(console_fmt)
    root.addHandler(console_handler)

    root.info("Logging initialized — logs at %s", logs_dir)


def get_logger(name: str) -> logging.Logger:
    """Get a logger within the ``recon`` namespace.

    Args:
        name: Typically ``__name__`` from the calling module.

    Returns:
        A configured :class:`logging.Logger` instance.
    """
    # Ensure logging is set up even if caller forgets
    setup_logging()
    return logging.getLogger(name)


@contextmanager
def log_duration(logger: logging.Logger, task: str) -> Generator[None, None, None]:
    """Context manager that logs the duration of a task.

    Usage::

        with log_duration(logger, "DNS lookup"):
            result = perform_dns_lookup()
    """
    start = time.perf_counter()
    logger.info("▶ %s — started", task)
    try:
        yield
    except Exception:
        elapsed = time.perf_counter() - start
        logger.error("✗ %s — failed after %.2fs", task, elapsed)
        raise
    else:
        elapsed = time.perf_counter() - start
        logger.info("✓ %s — completed in %.2fs", task, elapsed)
