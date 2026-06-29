"""
recon.gui.theme — Dark cybersecurity GUI theme definition.

Provides a consistent color palette, fonts, and styling constants
for the Tkinter interface.
"""

from __future__ import annotations


class Theme:
    """Dark cybersecurity color palette and typography."""

    # ── Background & Surfaces ─────────────────────────────────────────
    BG = "#0a0e17"
    SURFACE = "#131926"
    SURFACE_2 = "#1a2236"
    SURFACE_3 = "#212d45"

    # ── Accent Colors ─────────────────────────────────────────────────
    ACCENT = "#00e5ff"
    ACCENT_DIM = "#006978"

    # ── Status Colors ─────────────────────────────────────────────────
    SUCCESS = "#00e676"
    ERROR = "#ff1744"
    WARNING = "#ffc400"
    INFO = "#448aff"
    PENDING = "#555555"

    # ── Text ──────────────────────────────────────────────────────────
    TEXT = "#e0e0e0"
    TEXT_MUTED = "#969696"
    TEXT_DIM = "#555555"

    # ── Borders ───────────────────────────────────────────────────────
    BORDER = "#1e2940"

    # ── Button Colors ─────────────────────────────────────────────────
    BTN_PRIMARY_BG = "#00e5ff"
    BTN_PRIMARY_FG = "#000000"
    BTN_DANGER_BG = "#ff1744"
    BTN_DANGER_FG = "#000000"
    BTN_SECONDARY_BG = "#1e2940"
    BTN_SECONDARY_FG = "#000000"

    # ── Fonts ─────────────────────────────────────────────────────────
    FONT_FAMILY = "Helvetica"
    FONT_MONO = "Consolas"
    FONT_TITLE = (FONT_FAMILY, 22, "bold")
    FONT_HEADING = (FONT_FAMILY, 14, "bold")
    FONT_BODY = (FONT_FAMILY, 11)
    FONT_SMALL = (FONT_FAMILY, 10)
    FONT_TINY = (FONT_FAMILY, 9)
    FONT_CODE = (FONT_MONO, 11)
    FONT_CODE_SMALL = (FONT_MONO, 10)

    # ── Spacing ───────────────────────────────────────────────────────
    PAD_X = 16
    PAD_Y = 12
    BORDER_RADIUS = 8

    # ── Module status indicators ──────────────────────────────────────
    STATUS_COLORS = {
        "pending": PENDING,
        "running": WARNING,
        "success": SUCCESS,
        "failed": ERROR,
        "skipped": TEXT_DIM,
    }

    STATUS_ICONS = {
        "pending": "○",
        "running": "◉",
        "success": "●",
        "failed": "●",
        "skipped": "○",
    }

    # ── Grade colors ──────────────────────────────────────────────────
    GRADE_COLORS = {
        "A+": SUCCESS,
        "A": "#00c853",
        "B": "#76ff03",
        "C": WARNING,
        "D": "#ff6d00",
        "F": ERROR,
    }
