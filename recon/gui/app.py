"""
recon.gui.app — Professional Tkinter GUI for the Automatic Recon Tool.

Features:
  - Modern dark cybersecurity theme
  - Module execution tracker (sidebar)
  - Progress bar with percentage
  - Status bar with timestamps
  - Tabbed view: Dashboard / Raw Output
  - Responsive resizing
  - Animated module status indicators
"""

from __future__ import annotations

import threading
import webbrowser
from tkinter import (
    Tk, Label, Entry, Button, Frame, Text, Scrollbar, Toplevel, StringVar,
    END, DISABLED, NORMAL, LEFT, RIGHT, TOP, BOTTOM, BOTH, X, Y,
    messagebox, ttk,
)
from typing import Any, Optional

from recon import __version__
from recon.config import Config
from recon.engine import ModuleStatus, ReconEngine, ScanResult
from recon.gui.dashboard import DashboardPanel
from recon.gui.theme import Theme
from recon.reports import txt_report, pdf_report, html_report, json_report, email_report
from recon.utils import validate_target, timestamp_iso, format_duration


# Module display info
MODULE_DISPLAY = {
    "whois": "WHOIS Lookup",
    "dns": "DNS Analysis",
    "http": "HTTP Headers",
    "ssl": "SSL/TLS Cert",
    "geo": "Geo-IP Lookup",
    "html_meta": "HTML Metadata",
    "tech": "Tech Detection",
    "admin": "Admin Discovery",
    "subdomains": "Subdomains",
    "shodan": "Shodan Intel",
    "screenshot": "Screenshots",
}


class ReconGUI:
    """Professional reconnaissance tool GUI."""

    def __init__(self, root: Tk) -> None:
        self.root = root
        self.config = Config()
        self.engine: Optional[ReconEngine] = None
        self.scan_result: Optional[ScanResult] = None

        # ── Window setup ──────────────────────────────────────────────
        root.title(f"Automatic Recon Tool v{__version__}")
        root.geometry("1200x750")
        root.minsize(1000, 650)
        root.configure(bg=Theme.BG)

        try:
            root.attributes("-alpha", 0.98)
        except Exception:
            pass

        self._module_labels: dict[str, Label] = {}
        self._module_status_labels: dict[str, Label] = {}

        self._build_ui()

    def _build_ui(self) -> None:
        """Construct the complete GUI layout."""
        # ── Background Image ──────────────────────────────────────────
        try:
            from PIL import Image, ImageTk, ImageEnhance
            if self.config.bg_image_path.exists():
                bg_img = Image.open(self.config.bg_image_path)
                bg_img = bg_img.resize((1600, 1000), Image.Resampling.LANCZOS)
                bg_img = ImageEnhance.Brightness(bg_img).enhance(0.55)
                self._bg_photo = ImageTk.PhotoImage(bg_img)
                bg_label = Label(self.root, image=self._bg_photo, bd=0)
                bg_label.place(x=0, y=0, relwidth=1, relheight=1)
        except Exception as exc:
            logger.warning(f"Could not load background image: {exc}")

        # ── Top Bar ───────────────────────────────────────────────────
        top_bar = Frame(self.root, bg=Theme.SURFACE, height=60)
        top_bar.pack(fill=X, padx=25, pady=(20, 10))
        top_bar.pack_propagate(False)

        # Title
        Label(
            top_bar,
            text="🛡️  AUTOMATIC RECON TOOL",
            font=("Helvetica", 18, "bold"),
            fg=Theme.ACCENT,
            bg=Theme.SURFACE,
        ).pack(side=LEFT, padx=20, pady=12)

        Label(
            top_bar,
            text=f"v{__version__}",
            font=("Helvetica", 10),
            fg=Theme.TEXT_DIM,
            bg=Theme.SURFACE,
        ).pack(side=LEFT, pady=12)

        # Top-right buttons
        btn_frame = Frame(top_bar, bg=Theme.SURFACE)
        btn_frame.pack(side=RIGHT, padx=16)

        Button(
            btn_frame, text="⚙ Settings", command=self._open_settings,
            bg=Theme.SURFACE_2, fg=Theme.BTN_SECONDARY_FG, font=Theme.FONT_SMALL,
            relief="flat", padx=12, pady=4, cursor="hand2",
        ).pack(side=LEFT, padx=4)

        Button(
            btn_frame, text="ℹ About", command=self._open_about,
            bg=Theme.SURFACE_2, fg=Theme.BTN_SECONDARY_FG, font=Theme.FONT_SMALL,
            relief="flat", padx=12, pady=4, cursor="hand2",
        ).pack(side=LEFT, padx=4)

        # ── Input Bar ────────────────────────────────────────────────
        input_bar = Frame(self.root, bg=Theme.SURFACE_2)
        input_bar.pack(fill=X, padx=25, pady=(0, 15))

        Label(
            input_bar, text="Target:", font=Theme.FONT_BODY,
            fg=Theme.TEXT_MUTED, bg=Theme.SURFACE_2,
        ).pack(side=LEFT, padx=(20, 8), pady=10)

        self.target_entry = Entry(
            input_bar, font=Theme.FONT_CODE, width=40,
            bg=Theme.BG, fg=Theme.TEXT, insertbackground=Theme.ACCENT,
            relief="flat", highlightthickness=1,
            highlightbackground=Theme.BORDER,
            highlightcolor=Theme.ACCENT,
        )
        self.target_entry.pack(side=LEFT, padx=4, pady=10, ipady=4)
        self.target_entry.insert(0, "http://")
        self.target_entry.bind("<Return>", lambda e: self._start_scan())

        Label(
            input_bar, text="Email:", font=Theme.FONT_BODY,
            fg=Theme.TEXT_MUTED, bg=Theme.SURFACE_2,
        ).pack(side=LEFT, padx=(16, 8), pady=10)

        self.email_entry = Entry(
            input_bar, font=Theme.FONT_CODE, width=28,
            bg=Theme.BG, fg=Theme.TEXT, insertbackground=Theme.ACCENT,
            relief="flat", highlightthickness=1,
            highlightbackground=Theme.BORDER,
            highlightcolor=Theme.ACCENT,
        )
        self.email_entry.pack(side=LEFT, padx=4, pady=10, ipady=4)
        self.email_entry.bind("<Return>", lambda e: self._start_scan())

        # Buttons
        self.btn_start = Button(
            input_bar, text="▶ Start Scan", command=self._start_scan,
            bg=Theme.BTN_PRIMARY_BG, fg=Theme.BTN_PRIMARY_FG,
            font=("Helvetica", 11, "bold"), relief="flat",
            padx=16, pady=4, cursor="hand2",
        )
        self.btn_start.pack(side=LEFT, padx=(16, 4), pady=10)

        Button(
            input_bar, text="✕ Clear", command=self._clear_output,
            bg=Theme.BTN_DANGER_BG, fg=Theme.BTN_DANGER_FG,
            font=Theme.FONT_SMALL, relief="flat",
            padx=12, pady=4, cursor="hand2",
        ).pack(side=LEFT, padx=4, pady=10)

        # ── Status Bar ────────────────────────────────────────────────
        status_bar = Frame(self.root, bg=Theme.SURFACE, height=32)
        status_bar.pack(side=BOTTOM, fill=X, padx=25, pady=(0, 20))
        status_bar.pack_propagate(False)

        self._status_var = StringVar(value="Ready — Enter a target and click Start Scan")
        Label(
            status_bar,
            textvariable=self._status_var,
            font=Theme.FONT_TINY,
            fg=Theme.TEXT_MUTED,
            bg=Theme.SURFACE,
        ).pack(side=LEFT, padx=12)

        self._time_var = StringVar(value="")
        Label(
            status_bar,
            textvariable=self._time_var,
            font=Theme.FONT_TINY,
            fg=Theme.TEXT_DIM,
            bg=Theme.SURFACE,
        ).pack(side=RIGHT, padx=12)

        # ── Left Sidebar (Module Tracker) ─────────────────────────────
        sidebar = Frame(self.root, bg=Theme.SURFACE, width=220)
        sidebar.pack(side=LEFT, fill=Y, padx=(25, 12), pady=(0, 10))
        sidebar.pack_propagate(False)

        Label(
            sidebar, text="MODULE STATUS",
            font=("Helvetica", 10, "bold"),
            fg=Theme.ACCENT, bg=Theme.SURFACE,
            pady=10,
        ).pack(fill=X, padx=12)

        # Separator
        Frame(sidebar, bg=Theme.BORDER, height=1).pack(fill=X, padx=12)

        # Module entries
        for mod_key, mod_name in MODULE_DISPLAY.items():
            row = Frame(sidebar, bg=Theme.SURFACE, pady=3)
            row.pack(fill=X, padx=12)

            status_lbl = Label(
                row, text=Theme.STATUS_ICONS["pending"],
                font=("Helvetica", 10),
                fg=Theme.STATUS_COLORS["pending"],
                bg=Theme.SURFACE,
            )
            status_lbl.pack(side=LEFT, padx=(0, 8))
            self._module_status_labels[mod_key] = status_lbl

            name_lbl = Label(
                row, text=mod_name,
                font=Theme.FONT_SMALL,
                fg=Theme.TEXT_MUTED,
                bg=Theme.SURFACE,
                anchor="w",
            )
            name_lbl.pack(side=LEFT, fill=X, expand=True)
            self._module_labels[mod_key] = name_lbl

        # Spacer
        Frame(sidebar, bg=Theme.SURFACE).pack(fill=BOTH, expand=True)

        # Sidebar footer — progress
        self._progress_frame = Frame(sidebar, bg=Theme.SURFACE)
        self._progress_frame.pack(fill=X, padx=12, pady=(0, 8))

        self._progress_var = StringVar(value="Ready")
        Label(
            self._progress_frame,
            textvariable=self._progress_var,
            font=Theme.FONT_TINY,
            fg=Theme.TEXT_DIM,
            bg=Theme.SURFACE,
        ).pack(fill=X)

        # Progress bar
        style = ttk.Style()
        style.theme_use("default")
        style.configure(
            "Recon.Horizontal.TProgressbar",
            troughcolor=Theme.SURFACE_2,
            background=Theme.ACCENT,
            thickness=6,
        )
        self._progress_bar = ttk.Progressbar(
            self._progress_frame,
            style="Recon.Horizontal.TProgressbar",
            mode="determinate",
            maximum=100,
        )
        self._progress_bar.pack(fill=X, pady=(4, 0))

        # ── Right Content Area (Tabs) ─────────────────────────────────
        content = Frame(self.root, bg=Theme.SURFACE)
        content.pack(side=LEFT, fill=BOTH, expand=True, padx=(0, 25), pady=(0, 10))

        # Tab control
        style.configure("TNotebook", background=Theme.SURFACE, borderwidth=0)
        style.configure(
            "TNotebook.Tab",
            background=Theme.SURFACE,
            foreground=Theme.TEXT,
            padding=[12, 6],
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", Theme.SURFACE_2)],
            foreground=[("selected", Theme.ACCENT)],
        )

        self._tabs = ttk.Notebook(content, style="TNotebook")
        self._tabs.pack(fill=BOTH, expand=True, padx=4, pady=4)

        # Dashboard tab
        self._dashboard = DashboardPanel(self._tabs)
        self._tabs.add(self._dashboard, text="  📊 Dashboard  ")

        # Raw output tab
        raw_frame = Frame(self._tabs, bg=Theme.BG)
        self._tabs.add(raw_frame, text="  📝 Raw Output  ")

        self._output = Text(
            raw_frame,
            bg="#0d1117",
            fg=Theme.TEXT,
            insertbackground=Theme.ACCENT,
            font=Theme.FONT_CODE,
            wrap="word",
            relief="flat",
            padx=12,
            pady=8,
        )
        self._output.pack(side=LEFT, fill=BOTH, expand=True)

        scroll = Scrollbar(raw_frame, command=self._output.yview)
        scroll.pack(side=RIGHT, fill=Y)
        self._output.configure(yscrollcommand=scroll.set, state=DISABLED)

    # ── Output helpers ────────────────────────────────────────────────
    def _append(self, text: str) -> None:
        """Append text to raw output (thread-safe)."""
        def _do() -> None:
            self._output.configure(state=NORMAL)
            self._output.insert(END, text + "\n")
            self._output.see(END)
            self._output.configure(state=DISABLED)
        self.root.after(0, _do)

    def _clear_output(self) -> None:
        self._output.configure(state=NORMAL)
        self._output.delete("1.0", END)
        self._output.configure(state=DISABLED)
        self._dashboard.clear()
        self._reset_module_status()
        self._progress_bar["value"] = 0
        self._progress_var.set("Ready")
        self._status_var.set("Output cleared")

    def _reset_module_status(self) -> None:
        for key in MODULE_DISPLAY:
            self._update_module_status(key, ModuleStatus.PENDING, 0)

    def _update_module_status(
        self, name: str, status: ModuleStatus, pct: float
    ) -> None:
        """Update module tracker and progress bar (thread-safe)."""
        def _do() -> None:
            status_key = status.value
            if name in self._module_status_labels:
                self._module_status_labels[name].configure(
                    text=Theme.STATUS_ICONS.get(status_key, "○"),
                    fg=Theme.STATUS_COLORS.get(status_key, Theme.TEXT_DIM),
                )
            if name in self._module_labels:
                fg = Theme.TEXT if status_key == "success" else (
                    Theme.ERROR if status_key == "failed" else (
                        Theme.WARNING if status_key == "running" else Theme.TEXT_MUTED
                    )
                )
                self._module_labels[name].configure(fg=fg)

            self._progress_bar["value"] = min(pct, 100)
            self._progress_var.set(f"{pct:.0f}%")
        self.root.after(0, _do)

    # ── Scan execution ────────────────────────────────────────────────
    def _start_scan(self) -> None:
        target = self.target_entry.get().strip()
        valid, err = validate_target(target)
        if not valid:
            messagebox.showwarning("Invalid Target", err)
            return

        self._clear_output()
        self.btn_start.configure(state=DISABLED, text="⏳ Scanning...")
        self._status_var.set(f"Scanning {target}...")
        self._time_var.set(f"Started: {timestamp_iso()}")

        t = threading.Thread(target=self._run_scan, args=(target,), daemon=True)
        t.start()

    def _run_scan(self, target: str) -> None:
        """Execute scan in background thread."""
        try:
            self.config = Config.reload()
            self.engine = ReconEngine(self.config)
            self.engine.on_progress = self._update_module_status

            self._append(f"{'=' * 60}")
            self._append(f"  Starting reconnaissance on: {target}")
            self._append(f"  Time: {timestamp_iso()}")
            self._append(f"{'=' * 60}")
            self._append("")

            scan = self.engine.run(target)
            self.scan_result = scan

            # ── Populate dashboard ────────────────────────────────────
            self.root.after(0, lambda: self._populate_dashboard(scan))

            # ── Raw output ────────────────────────────────────────────
            self._append_scan_results(scan)

            # ── Generate reports ──────────────────────────────────────
            self._append("\n=== REPORT GENERATION ===")
            print("\n=== REPORT GENERATION ===")

            txt_path = txt_report.generate(scan, self.config)
            self._append(f"[✓] Text report:  {txt_path}")
            print(f"[✓] Text report:  {txt_path}")

            pdf_path = pdf_report.generate(scan, self.config)
            self._append(f"[✓] PDF report:   {pdf_path}")
            print(f"[✓] PDF report:   {pdf_path}")

            html_path = html_report.generate(scan, self.config)
            self._append(f"[✓] HTML report:  {html_path}")
            print(f"[✓] HTML report:  {html_path}")

            json_path = json_report.generate(scan, self.config)
            self._append(f"[✓] JSON report:  {json_path}")
            print(f"[✓] JSON report:  {json_path}")

            # ── Email ─────────────────────────────────────────────────
            recipient = self.email_entry.get().strip()
            mail_status = ""
            if recipient:
                self._append(f"\nSending report to {recipient}...")
                print(f"\n[*] Sending report to {recipient}...")
                ok, err = email_report.send(
                    recipient=recipient,
                    subject=f"Recon Report for {target}",
                    body=scan.summary[:2000] if scan.summary else "See attached report.",
                    attachments=[pdf_path, html_path],
                    config=self.config,
                )
                if ok:
                    msg = f"Mail sent successfully to {recipient}"
                    self._append(f"[✓] {msg}")
                    print(f"[✓] {msg}")
                    mail_status = f"📧 Mail Sent"
                else:
                    msg = f"Problem sending mail: {err}"
                    self._append(f"[✗] {msg}")
                    print(f"[✗] {msg}")
                    mail_status = f"❌ Mail Problem: {err}"
            else:
                self._append("[i] No email recipient — skipping email")
                print("[i] No email recipient — skipping email")

            # Open HTML report
            self._append(f"\n[✓] Scan complete in {format_duration(scan.total_duration)}")
            self._append(f"[✓] Security Score: {scan.score.score}/100 ({scan.score.grade})")

            status_text = f"Scan complete — Score: {scan.score.score}/100 ({scan.score.grade})"
            if mail_status:
                status_text += f" — {mail_status}"
            status_text += f" ({format_duration(scan.total_duration)})"
            print(f"\n[+] {status_text}\n")

            self.root.after(0, lambda st=status_text: self._status_var.set(st))

        except Exception as exc:
            import traceback
            err_msg = f"Error during scan: {exc}"
            print(f"\n[✗] {err_msg}")
            traceback.print_exc()
            self._append(f"\n[✗] Error: {exc}")
            self._append(traceback.format_exc())
            self.root.after(0, lambda em=err_msg: self._status_var.set(em[:85]))

        finally:
            self.root.after(0, lambda: self.btn_start.configure(
                state=NORMAL, text="▶ Start Scan"
            ))

    def _append_scan_results(self, scan: ScanResult) -> None:
        """Append structured raw output for all modules."""
        results = scan.results

        # Geo-IP
        geo = results.get("geo")
        if geo and getattr(geo, "success", False):
            self._append(f"[✓] IP: {geo.ip} | Location: {geo.city}, {geo.country} | ISP: {geo.isp}")

        # WHOIS
        w = results.get("whois")
        if w and getattr(w, "success", False):
            self._append(f"[✓] WHOIS: {w.domain_name} | Registrar: {w.registrar} | Expires: {w.expiration_date}")

        # DNS
        dns = results.get("dns")
        if dns and getattr(dns, "success", False):
            for rtype, rec in dns.records.items():
                if rec.values:
                    self._append(f"[✓] DNS {rtype}: {', '.join(rec.values)}")
            self._append(f"[i] SPF: {dns.spf or 'Not found'} | DMARC: {dns.dmarc or 'Not found'}")

        # HTTP
        http = results.get("http")
        if http and getattr(http, "success", False):
            self._append(f"[✓] Server: {http.server} | Status: {http.status_code}")
            missing = http.missing_security_headers
            if missing:
                self._append(f"[!] Missing headers: {', '.join(missing)}")

        # SSL
        ssl_r = results.get("ssl")
        if ssl_r and getattr(ssl_r, "success", False):
            self._append(f"[✓] SSL: {ssl_r.subject} | TLS: {ssl_r.tls_version} | Grade: {ssl_r.grade} | Expires: {ssl_r.days_until_expiry}d")

        # Tech
        tech = results.get("tech")
        if tech and getattr(tech, "success", False):
            for cat, techs in tech.categories.items():
                self._append(f"[✓] {cat}: {', '.join(techs)}")

        # Admin
        admin = results.get("admin")
        if admin and getattr(admin, "success", False):
            for f in admin.findings[:10]:
                self._append(f"[{'!' if f.classification == 'Accessible' else '+'}] {f.classification}: {f.url}")

        # Subdomains
        subs = results.get("subdomains")
        if subs and getattr(subs, "success", False):
            self._append(f"[✓] Subdomains: {subs.total_count} found via {', '.join(subs.sources_used)}")

        # Shodan
        shodan = results.get("shodan")
        if shodan and getattr(shodan, "success", False):
            self._append(f"[✓] Shodan: {len(shodan.ports)} ports, {len(shodan.vulns)} CVEs | Org: {shodan.org}")
        elif shodan:
            self._append(f"[!] Shodan: {getattr(shodan, 'error', 'Failed')}")

        # Screenshot
        ss = results.get("screenshot")
        if ss and getattr(ss, "success", False):
            self._append(f"[✓] Screenshots captured: desktop={ss.desktop_ok}, mobile={ss.mobile_ok}, fullpage={ss.fullpage_ok}")

    def _populate_dashboard(self, scan: ScanResult) -> None:
        """Fill the dashboard with structured results."""
        self._dashboard.clear()

        # Score card
        if scan.score:
            self._dashboard.add_score_card(
                scan.score.score, scan.score.grade, scan.score.risk_level
            )

        # Executive summary
        if scan.summary:
            self._dashboard.add_summary(scan.summary)

        # Network info
        geo = scan.results.get("geo")
        if geo and getattr(geo, "success", False):
            self._dashboard.add_section("Network Information", [
                ("IP Address", geo.ip),
                ("Location", f"{geo.city}, {geo.region}, {geo.country}"),
                ("ISP", geo.isp),
                ("Organization", geo.org),
                ("ASN", geo.as_number),
            ])

        # DNS
        dns = scan.results.get("dns")
        if dns and getattr(dns, "success", False):
            dns_items = []
            for rtype, rec in dns.records.items():
                if rec.values:
                    dns_items.append((rtype, ", ".join(rec.values)))
            dns_items.append(("SPF", dns.spf or "Not found"))
            dns_items.append(("DMARC", dns.dmarc or "Not found"))
            dns_items.append(("DNSSEC", "Yes" if dns.has_dnssec else "No"))
            self._dashboard.add_section("DNS Records", dns_items)

        # HTTP
        http = scan.results.get("http")
        if http and getattr(http, "success", False):
            headers_data = []
            for h, v in http.security_headers.items():
                status = "✓" if v else "✗ MISSING"
                headers_data.append((h, status))
            status_str = "warning" if http.missing_security_headers else "success"
            self._dashboard.add_section("HTTP Security Headers", headers_data, status=status_str)

        # SSL
        ssl_r = scan.results.get("ssl")
        if ssl_r and getattr(ssl_r, "success", False):
            self._dashboard.add_section("SSL/TLS Certificate", [
                ("Subject", ssl_r.subject),
                ("Issuer", ssl_r.issuer),
                ("TLS Version", ssl_r.tls_version),
                ("Cipher", ssl_r.cipher_suite),
                ("Grade", ssl_r.grade),
                ("Days Left", str(ssl_r.days_until_expiry)),
            ])

        # Tech
        tech = scan.results.get("tech")
        if tech and getattr(tech, "success", False):
            tech_items = [(cat, ", ".join(techs)) for cat, techs in tech.categories.items()]
            self._dashboard.add_section("Technology Stack", tech_items)

        # Admin findings
        admin = scan.results.get("admin")
        if admin and getattr(admin, "success", False) and admin.findings:
            admin_rows = [[f.classification, f.url, str(f.status_code)] for f in admin.findings[:15]]
            status_str = "warning" if admin.accessible else "success"
            self._dashboard.add_table_section(
                "Admin Panel Discovery",
                ["Status", "URL", "Code"],
                admin_rows,
                status=status_str,
            )

        # Findings
        if scan.score and scan.score.findings:
            finding_rows = [[f.severity, f.title, str(f.points_deducted)] for f in scan.score.findings]
            self._dashboard.add_table_section(
                "Security Findings",
                ["Severity", "Finding", "Pts"],
                finding_rows,
                status="warning" if scan.score.score < 80 else "success",
            )

        # Switch to dashboard tab
        self._tabs.select(0)

    # ── Settings dialog ───────────────────────────────────────────────
    def _open_settings(self) -> None:
        top = Toplevel(self.root)
        top.title("Settings")
        top.geometry("520x340")
        top.configure(bg=Theme.SURFACE)
        top.resizable(False, False)

        Label(
            top, text="SMTP Configuration",
            font=Theme.FONT_HEADING, fg=Theme.ACCENT, bg=Theme.SURFACE,
        ).pack(anchor="w", padx=16, pady=(16, 8))

        fields = [
            ("SMTP Server", "smtp_server"),
            ("SMTP Port", "smtp_port"),
            ("SMTP User", "smtp_user"),
            ("SMTP Password", "smtp_pass"),
            ("Shodan API Key", "shodan_api_key"),
        ]

        entries: dict[str, Entry] = {}
        for label_text, key in fields:
            row = Frame(top, bg=Theme.SURFACE)
            row.pack(fill=X, padx=16, pady=2)

            Label(
                row, text=f"{label_text}:", font=Theme.FONT_SMALL,
                fg=Theme.TEXT_MUTED, bg=Theme.SURFACE, width=16, anchor="w",
            ).pack(side=LEFT)

            show = "*" if "pass" in key.lower() or "key" in key.lower() else ""
            e = Entry(
                row, font=Theme.FONT_CODE_SMALL, width=40,
                bg=Theme.BG, fg=Theme.TEXT, insertbackground=Theme.ACCENT,
                relief="flat", show=show,
            )
            e.pack(side=LEFT, padx=4, ipady=2)
            e.insert(0, str(getattr(self.config, key, "")))
            entries[key] = e

        def save() -> None:
            self.config.smtp_server = entries["smtp_server"].get().strip()
            self.config.smtp_port = int(entries["smtp_port"].get().strip() or "587")
            self.config.smtp_user = entries["smtp_user"].get().strip()
            self.config.smtp_pass = entries["smtp_pass"].get().strip()
            self.config.shodan_api_key = entries["shodan_api_key"].get().strip()
            messagebox.showinfo("Saved", "Settings saved for this session.")
            top.destroy()

        Button(
            top, text="Save", command=save,
            bg=Theme.BTN_PRIMARY_BG, fg=Theme.BTN_PRIMARY_FG,
            font=Theme.FONT_BODY, relief="flat", padx=20, cursor="hand2",
        ).pack(pady=16)

    def _open_about(self) -> None:
        top = Toplevel(self.root)
        top.title("About")
        top.geometry("400x260")
        top.configure(bg=Theme.SURFACE)
        top.resizable(False, False)

        Label(
            top, text="🛡️ Automatic Recon Tool",
            font=("Helvetica", 16, "bold"),
            fg=Theme.ACCENT, bg=Theme.SURFACE,
        ).pack(pady=(20, 4))

        Label(
            top, text=f"Version {__version__}",
            font=Theme.FONT_BODY, fg=Theme.TEXT_MUTED, bg=Theme.SURFACE,
        ).pack()

        Label(
            top, text="Cybersecurity Reconnaissance Framework",
            font=Theme.FONT_BODY, fg=Theme.TEXT, bg=Theme.SURFACE,
        ).pack(pady=(8, 4))

        Label(
            top, text="Developed by Yash Dharamshi",
            font=Theme.FONT_SMALL, fg=Theme.TEXT_MUTED, bg=Theme.SURFACE,
        ).pack(pady=(12, 2))

        Label(
            top, text="Supraja Technologies Internship",
            font=Theme.FONT_SMALL, fg=Theme.TEXT_DIM, bg=Theme.SURFACE,
        ).pack()

        Button(
            top, text="Close", command=top.destroy,
            bg=Theme.SURFACE_2, fg=Theme.BTN_SECONDARY_FG,
            font=Theme.FONT_SMALL, relief="flat", padx=16, cursor="hand2",
        ).pack(pady=16)


def main() -> None:
    """Launch the application with splash screen."""
    # Show splash
    from recon.gui.splash import SplashScreen
    splash = SplashScreen(duration_ms=2000)
    splash.show()

    # Launch main GUI
    root = Tk()
    app = ReconGUI(root)
    root.mainloop()
