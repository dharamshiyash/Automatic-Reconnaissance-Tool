"""
recon.gui.dashboard — Structured results dashboard.

Replaces plain text output with organized, color-coded sections
for each reconnaissance module result.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Any, Optional

from recon.gui.theme import Theme


class DashboardPanel(tk.Frame):
    """Scrollable dashboard panel with structured result sections."""

    def __init__(self, parent: tk.Widget) -> None:
        super().__init__(parent, bg=Theme.BG)

        # Scrollable canvas
        self._canvas = tk.Canvas(self, bg=Theme.BG, highlightthickness=0)
        self._scrollbar = ttk.Scrollbar(self, orient="vertical", command=self._canvas.yview)
        self._inner = tk.Frame(self._canvas, bg=Theme.BG)

        self._inner.bind("<Configure>", lambda e: self._canvas.configure(
            scrollregion=self._canvas.bbox("all")
        ))
        self._canvas_window = self._canvas.create_window((0, 0), window=self._inner, anchor="nw")

        self._canvas.configure(yscrollcommand=self._scrollbar.set)
        self._canvas.pack(side="left", fill="both", expand=True)
        self._scrollbar.pack(side="right", fill="y")

        # Respond to resize
        self._canvas.bind("<Configure>", self._on_canvas_resize)

        # Mouse wheel scrolling
        self._canvas.bind_all("<MouseWheel>", self._on_mousewheel)

        self._sections: list[tk.Frame] = []

    def _on_canvas_resize(self, event: Any) -> None:
        self._canvas.itemconfig(self._canvas_window, width=event.width)

    def _on_mousewheel(self, event: Any) -> None:
        self._canvas.yview_scroll(-1 * (event.delta // 120), "units")

    def clear(self) -> None:
        """Remove all sections."""
        for widget in self._inner.winfo_children():
            widget.destroy()
        self._sections.clear()

    def add_score_card(self, score: int, grade: str, risk: str) -> None:
        """Add the security score card at the top."""
        card = tk.Frame(self._inner, bg=Theme.SURFACE, pady=16, padx=20)
        card.pack(fill="x", padx=12, pady=(12, 6))

        # Grade
        color = Theme.GRADE_COLORS.get(grade, Theme.TEXT)
        tk.Label(
            card,
            text=grade,
            font=("Helvetica", 42, "bold"),
            fg=color,
            bg=Theme.SURFACE,
        ).pack(side="left", padx=(10, 20))

        # Score info
        info = tk.Frame(card, bg=Theme.SURFACE)
        info.pack(side="left", fill="x", expand=True)

        tk.Label(
            info,
            text=f"Security Score: {score}/100",
            font=("Helvetica", 16, "bold"),
            fg=Theme.TEXT,
            bg=Theme.SURFACE,
        ).pack(anchor="w")

        risk_color = {
            "Critical": Theme.ERROR,
            "High": "#ff6d00",
            "Medium": Theme.WARNING,
            "Low": Theme.SUCCESS,
        }.get(risk, Theme.TEXT)

        tk.Label(
            info,
            text=f"Risk Level: {risk}",
            font=("Helvetica", 12),
            fg=risk_color,
            bg=Theme.SURFACE,
        ).pack(anchor="w", pady=(4, 0))

    def add_section(
        self,
        title: str,
        content: list[tuple[str, str]],
        status: str = "success",
    ) -> None:
        """Add a collapsible section with key-value pairs.

        Args:
            title: Section title.
            content: List of (key, value) tuples to display.
            status: Status for color-coding: success, error, warning.
        """
        status_color = {
            "success": Theme.SUCCESS,
            "error": Theme.ERROR,
            "warning": Theme.WARNING,
        }.get(status, Theme.TEXT_MUTED)

        section = tk.Frame(self._inner, bg=Theme.SURFACE)
        section.pack(fill="x", padx=12, pady=4)
        self._sections.append(section)

        # Header
        header = tk.Frame(section, bg=Theme.SURFACE_2, padx=12, pady=8)
        header.pack(fill="x")

        # Status indicator
        tk.Label(
            header,
            text="●",
            font=("Helvetica", 10),
            fg=status_color,
            bg=Theme.SURFACE_2,
        ).pack(side="left", padx=(0, 8))

        tk.Label(
            header,
            text=title,
            font=Theme.FONT_HEADING,
            fg=Theme.ACCENT,
            bg=Theme.SURFACE_2,
        ).pack(side="left")

        # Content area
        body = tk.Frame(section, bg=Theme.SURFACE, padx=16, pady=8)
        body.pack(fill="x")

        for key, value in content:
            row = tk.Frame(body, bg=Theme.SURFACE)
            row.pack(fill="x", pady=1)

            tk.Label(
                row,
                text=f"{key}:",
                font=Theme.FONT_SMALL,
                fg=Theme.TEXT_MUTED,
                bg=Theme.SURFACE,
                width=20,
                anchor="w",
            ).pack(side="left")

            tk.Label(
                row,
                text=str(value)[:200],
                font=Theme.FONT_CODE_SMALL,
                fg=Theme.TEXT,
                bg=Theme.SURFACE,
                anchor="w",
                wraplength=500,
                justify="left",
            ).pack(side="left", fill="x", expand=True)

    def add_table_section(
        self,
        title: str,
        headers: list[str],
        rows: list[list[str]],
        status: str = "success",
    ) -> None:
        """Add a section with tabular data."""
        status_color = Theme.STATUS_COLORS.get(status, Theme.TEXT_MUTED)

        section = tk.Frame(self._inner, bg=Theme.SURFACE)
        section.pack(fill="x", padx=12, pady=4)

        # Header
        header_frame = tk.Frame(section, bg=Theme.SURFACE_2, padx=12, pady=8)
        header_frame.pack(fill="x")

        tk.Label(
            header_frame,
            text="●",
            font=("Helvetica", 10),
            fg=status_color,
            bg=Theme.SURFACE_2,
        ).pack(side="left", padx=(0, 8))

        tk.Label(
            header_frame,
            text=title,
            font=Theme.FONT_HEADING,
            fg=Theme.ACCENT,
            bg=Theme.SURFACE_2,
        ).pack(side="left")

        # Table
        body = tk.Frame(section, bg=Theme.SURFACE, padx=8, pady=8)
        body.pack(fill="x")

        # Header row
        hrow = tk.Frame(body, bg=Theme.SURFACE_3)
        hrow.pack(fill="x")
        for h in headers:
            tk.Label(
                hrow,
                text=h,
                font=("Helvetica", 10, "bold"),
                fg=Theme.ACCENT,
                bg=Theme.SURFACE_3,
                padx=8,
                pady=4,
            ).pack(side="left", expand=True, fill="x")

        # Data rows
        for i, row in enumerate(rows[:25]):
            bg = Theme.SURFACE if i % 2 == 0 else Theme.SURFACE_2
            rframe = tk.Frame(body, bg=bg)
            rframe.pack(fill="x")
            for cell in row:
                tk.Label(
                    rframe,
                    text=str(cell)[:60],
                    font=Theme.FONT_CODE_SMALL,
                    fg=Theme.TEXT,
                    bg=bg,
                    padx=8,
                    pady=2,
                    anchor="w",
                ).pack(side="left", expand=True, fill="x")

    def add_summary(self, text: str) -> None:
        """Add the executive summary section."""
        section = tk.Frame(self._inner, bg=Theme.SURFACE)
        section.pack(fill="x", padx=12, pady=4)

        header = tk.Frame(section, bg=Theme.SURFACE_2, padx=12, pady=8)
        header.pack(fill="x")

        tk.Label(
            header,
            text="📝",
            font=("Helvetica", 12),
            bg=Theme.SURFACE_2,
        ).pack(side="left", padx=(0, 8))

        tk.Label(
            header,
            text="Executive Summary",
            font=Theme.FONT_HEADING,
            fg=Theme.ACCENT,
            bg=Theme.SURFACE_2,
        ).pack(side="left")

        body = tk.Frame(section, bg=Theme.SURFACE, padx=16, pady=12)
        body.pack(fill="x")

        lbl = tk.Label(
            body,
            text=text,
            font=Theme.FONT_BODY,
            fg=Theme.TEXT,
            bg=Theme.SURFACE,
            wraplength=700,
            justify="left",
            anchor="nw",
        )
        lbl.pack(fill="x")
