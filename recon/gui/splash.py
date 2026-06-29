"""
recon.gui.splash — Professional splash screen.

Displays a loading screen with the project name, version,
and an animated progress indicator. Auto-closes when ready.
"""

from __future__ import annotations

import tkinter as tk
from recon import __version__
from recon.gui.theme import Theme


class SplashScreen:
    """Professional splash screen with animated loading."""

    def __init__(self, duration_ms: int = 2500) -> None:
        self.duration = duration_ms
        self.root = tk.Tk()
        self.root.overrideredirect(True)  # No title bar
        self.root.configure(bg=Theme.BG)

        # Center on screen
        w, h = 500, 320
        sx = (self.root.winfo_screenwidth() - w) // 2
        sy = (self.root.winfo_screenheight() - h) // 2
        self.root.geometry(f"{w}x{h}+{sx}+{sy}")

        # Transparent on macOS
        try:
            self.root.attributes("-alpha", 0.97)
        except Exception:
            pass

        # Content
        frame = tk.Frame(self.root, bg=Theme.BG)
        frame.pack(expand=True, fill="both", padx=2, pady=2)

        # Border effect
        inner = tk.Frame(frame, bg=Theme.BG)
        inner.pack(expand=True, fill="both", padx=1, pady=1)

        # Shield icon
        tk.Label(
            inner,
            text="🛡️",
            font=("Helvetica", 48),
            bg=Theme.BG,
        ).pack(pady=(30, 5))

        # Title
        tk.Label(
            inner,
            text="AUTOMATIC RECON TOOL",
            font=("Helvetica", 20, "bold"),
            fg=Theme.ACCENT,
            bg=Theme.BG,
        ).pack(pady=(0, 2))

        # Subtitle
        tk.Label(
            inner,
            text="Cybersecurity Reconnaissance Framework",
            font=("Helvetica", 11),
            fg=Theme.TEXT_MUTED,
            bg=Theme.BG,
        ).pack(pady=(0, 5))

        # Version
        tk.Label(
            inner,
            text=f"v{__version__}",
            font=("Helvetica", 10),
            fg=Theme.TEXT_DIM,
            bg=Theme.BG,
        ).pack()

        # Progress bar container
        bar_frame = tk.Frame(inner, bg=Theme.SURFACE, height=4)
        bar_frame.pack(fill="x", padx=80, pady=(25, 0))
        bar_frame.pack_propagate(False)

        self._bar = tk.Frame(bar_frame, bg=Theme.ACCENT, width=0)
        self._bar.pack(side="left", fill="y")

        # Loading text
        self._loading_var = tk.StringVar(value="Initializing modules...")
        tk.Label(
            inner,
            textvariable=self._loading_var,
            font=("Helvetica", 9),
            fg=Theme.TEXT_DIM,
            bg=Theme.BG,
        ).pack(pady=(8, 0))

        # Author
        tk.Label(
            inner,
            text="By Yash Dharamshi",
            font=("Helvetica", 9, "italic"),
            fg=Theme.TEXT_DIM,
            bg=Theme.BG,
        ).pack(side="bottom", pady=(0, 15))

        # Animate
        self._animate_step = 0
        self._total_steps = 30
        self._animate()

    def _animate(self) -> None:
        """Animate the progress bar."""
        if self._animate_step >= self._total_steps:
            self.root.destroy()
            return

        pct = self._animate_step / self._total_steps
        bar_width = int(340 * pct)
        self._bar.configure(width=bar_width)

        # Update loading text
        messages = [
            "Initializing modules...",
            "Loading configuration...",
            "Preparing scanner engine...",
            "Starting GUI...",
            "Ready",
        ]
        idx = min(int(pct * len(messages)), len(messages) - 1)
        self._loading_var.set(messages[idx])

        self._animate_step += 1
        delay = self.duration // self._total_steps
        self.root.after(delay, self._animate)

    def show(self) -> None:
        """Display the splash screen (blocks until animation completes)."""
        self.root.mainloop()
