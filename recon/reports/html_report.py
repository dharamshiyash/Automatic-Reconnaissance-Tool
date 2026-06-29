"""
recon.reports.html_report — Interactive HTML report generator.

Produces a self-contained HTML file with:
  - Dark cybersecurity theme
  - Sidebar navigation
  - Collapsible sections
  - Search functionality
  - Score gauge chart (SVG)
  - Copy-to-clipboard buttons
  - Responsive layout
  - Embedded screenshots (base64)
"""

from __future__ import annotations

import base64
import html
import os
from typing import Any, Optional

from recon import __version__
from recon.config import Config
from recon.utils import safe_filename, timestamp_str


def _b64_image(path: str) -> str:
    """Convert image file to base64 data URI."""
    if not path or not os.path.exists(path):
        return ""
    try:
        with open(path, "rb") as fh:
            data = base64.b64encode(fh.read()).decode("ascii")
        ext = path.rsplit(".", 1)[-1].lower()
        mime = {"png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg"}.get(ext, "image/png")
        return f"data:{mime};base64,{data}"
    except Exception:
        return ""


def _esc(text: Any) -> str:
    """HTML-escape text safely."""
    return html.escape(str(text)) if text else "N/A"


def _score_color(score: int) -> str:
    if score >= 90:
        return "#00e676"
    elif score >= 75:
        return "#ffc400"
    elif score >= 55:
        return "#ff6d00"
    else:
        return "#ff1744"


def _severity_color(severity: str) -> str:
    return {
        "Critical": "#ff1744",
        "High": "#ff6d00",
        "Medium": "#ffc400",
        "Low": "#00e5ff",
        "Informational": "#969696",
    }.get(severity, "#969696")


def generate(scan: Any, config: Optional[Config] = None) -> str:
    """Generate an interactive HTML report.

    Args:
        scan: ScanResult from the engine.
        config: Optional Config for output directory.

    Returns:
        Path to the saved HTML file.
    """
    cfg = config or Config()

    score_val = scan.score.score if scan.score else 0
    grade = scan.score.grade if scan.score else "N/A"
    risk = scan.score.risk_level if scan.score else "Unknown"
    sc = _score_color(score_val)

    # Build sections HTML
    sections = []

    # ── Executive Summary ─────────────────────────────────────────────
    if scan.summary:
        paras = "".join(f"<p>{_esc(p)}</p>" for p in scan.summary.split("\n\n"))
        sections.append(("executive-summary", "Executive Summary", f'<div class="summary-text">{paras}</div>'))

    # ── Security Findings ─────────────────────────────────────────────
    if scan.score and scan.score.findings:
        rows = ""
        for f in scan.score.findings:
            sc_color = _severity_color(f.severity)
            rows += f"""<tr>
                <td><span class="badge" style="background:{sc_color}">{_esc(f.severity)}</span></td>
                <td>{_esc(f.title)}</td>
                <td>{_esc(f.description)}</td>
                <td>{_esc(f.category)}</td>
                <td>{f.points_deducted}</td>
            </tr>"""
        sections.append(("findings", "Security Findings", f"""
            <table class="data-table"><thead><tr>
                <th>Severity</th><th>Finding</th><th>Description</th><th>Category</th><th>Pts</th>
            </tr></thead><tbody>{rows}</tbody></table>"""))

    # ── Network Info ──────────────────────────────────────────────────
    geo = scan.results.get("geo")
    if geo and getattr(geo, "success", False):
        sections.append(("network", "Network Information", f"""
            <div class="kv-grid">
                <div class="kv"><span class="k">IP Address</span><span class="v copy-target">{_esc(geo.ip)}</span></div>
                <div class="kv"><span class="k">Location</span><span class="v">{_esc(geo.city)}, {_esc(geo.region)}, {_esc(geo.country)}</span></div>
                <div class="kv"><span class="k">ISP</span><span class="v">{_esc(geo.isp)}</span></div>
                <div class="kv"><span class="k">Organization</span><span class="v">{_esc(geo.org)}</span></div>
                <div class="kv"><span class="k">ASN</span><span class="v">{_esc(geo.as_number)}</span></div>
                <div class="kv"><span class="k">Timezone</span><span class="v">{_esc(geo.timezone)}</span></div>
            </div>"""))

    # ── WHOIS ─────────────────────────────────────────────────────────
    w = scan.results.get("whois")
    if w and getattr(w, "success", False):
        ns = ", ".join(w.name_servers) if w.name_servers else "N/A"
        emails = ", ".join(w.emails) if w.emails else "N/A"
        sections.append(("whois", "WHOIS Information", f"""
            <div class="kv-grid">
                <div class="kv"><span class="k">Domain</span><span class="v">{_esc(w.domain_name)}</span></div>
                <div class="kv"><span class="k">Registrar</span><span class="v">{_esc(w.registrar)}</span></div>
                <div class="kv"><span class="k">Created</span><span class="v">{_esc(w.creation_date)}</span></div>
                <div class="kv"><span class="k">Expires</span><span class="v">{_esc(w.expiration_date)}</span></div>
                <div class="kv"><span class="k">Name Servers</span><span class="v">{_esc(ns)}</span></div>
                <div class="kv"><span class="k">Emails</span><span class="v">{_esc(emails)}</span></div>
            </div>"""))

    # ── DNS ───────────────────────────────────────────────────────────
    dns = scan.results.get("dns")
    if dns and getattr(dns, "success", False):
        dns_rows = ""
        for rtype, rec in dns.records.items():
            vals = ", ".join(rec.values) if rec.values else "None"
            ttl = str(rec.ttl) if rec.ttl else "-"
            dns_rows += f"<tr><td><code>{_esc(rtype)}</code></td><td>{_esc(vals)}</td><td>{ttl}</td></tr>"
        sections.append(("dns", "DNS Records", f"""
            <table class="data-table"><thead><tr><th>Type</th><th>Values</th><th>TTL</th></tr></thead>
            <tbody>{dns_rows}</tbody></table>
            <div class="kv-grid" style="margin-top:12px">
                <div class="kv"><span class="k">SPF</span><span class="v">{_esc(dns.spf or 'Not found')}</span></div>
                <div class="kv"><span class="k">DMARC</span><span class="v">{_esc(dns.dmarc or 'Not found')}</span></div>
                <div class="kv"><span class="k">DNSSEC</span><span class="v">{'✓ Enabled' if dns.has_dnssec else '✗ Not enabled'}</span></div>
                <div class="kv"><span class="k">Reverse DNS</span><span class="v">{_esc(dns.reverse_dns or 'N/A')}</span></div>
            </div>"""))

    # ── HTTP Headers ──────────────────────────────────────────────────
    http_res = scan.results.get("http")
    if http_res and getattr(http_res, "success", False):
        header_rows = ""
        for h_name, value in http_res.security_headers.items():
            status_cls = "pass" if value else "fail"
            status_text = "✓" if value else "✗ MISSING"
            header_rows += f"""<tr class="{status_cls}">
                <td>{_esc(h_name)}</td><td>{status_text}</td><td>{_esc(value or '-')}</td></tr>"""
        sections.append(("http", "HTTP Security Headers", f"""
            <div class="kv-grid" style="margin-bottom:12px">
                <div class="kv"><span class="k">Server</span><span class="v">{_esc(http_res.server)}</span></div>
                <div class="kv"><span class="k">Status</span><span class="v">{http_res.status_code}</span></div>
            </div>
            <table class="data-table"><thead><tr><th>Header</th><th>Status</th><th>Value</th></tr></thead>
            <tbody>{header_rows}</tbody></table>"""))

    # ── SSL/TLS ───────────────────────────────────────────────────────
    ssl_r = scan.results.get("ssl")
    if ssl_r and getattr(ssl_r, "success", False):
        san = ", ".join(ssl_r.san[:5]) if ssl_r.san else "N/A"
        sections.append(("ssl", "SSL/TLS Certificate", f"""
            <div class="kv-grid">
                <div class="kv"><span class="k">Subject</span><span class="v">{_esc(ssl_r.subject)}</span></div>
                <div class="kv"><span class="k">Issuer</span><span class="v">{_esc(ssl_r.issuer)}</span></div>
                <div class="kv"><span class="k">TLS Version</span><span class="v">{_esc(ssl_r.tls_version)}</span></div>
                <div class="kv"><span class="k">Cipher</span><span class="v">{_esc(ssl_r.cipher_suite)}</span></div>
                <div class="kv"><span class="k">Grade</span><span class="v" style="font-size:1.5em;font-weight:700">{_esc(ssl_r.grade)}</span></div>
                <div class="kv"><span class="k">Valid Until</span><span class="v">{_esc(ssl_r.not_after)}</span></div>
                <div class="kv"><span class="k">Days Left</span><span class="v">{ssl_r.days_until_expiry}</span></div>
                <div class="kv"><span class="k">Signature</span><span class="v">{_esc(ssl_r.signature_algorithm or 'N/A')}</span></div>
                <div class="kv"><span class="k">SAN</span><span class="v">{_esc(san)}</span></div>
            </div>"""))

    # ── Technology ────────────────────────────────────────────────────
    tech = scan.results.get("tech")
    if tech and getattr(tech, "success", False):
        tech_html = '<div class="tech-grid">'
        for cat, techs in tech.categories.items():
            tags = "".join(f'<span class="tech-tag">{_esc(t)}</span>' for t in techs)
            tech_html += f'<div class="tech-cat"><h4>{_esc(cat)}</h4>{tags}</div>'
        tech_html += '</div>'
        sections.append(("tech", "Technology Stack", tech_html))

    # ── Admin Panels ──────────────────────────────────────────────────
    admin = scan.results.get("admin")
    if admin and getattr(admin, "success", False) and admin.findings:
        admin_rows = ""
        for f in admin.findings[:30]:
            cls = {"Accessible": "fail", "Auth Required": "warn", "Forbidden": "warn"}.get(f.classification, "")
            admin_rows += f'<tr class="{cls}"><td>{_esc(f.classification)}</td><td><a href="{_esc(f.url)}" target="_blank">{_esc(f.url)}</a></td><td>{f.status_code}</td></tr>'
        sections.append(("admin", "Admin Panel Discovery", f"""
            <p>Scanned {admin.paths_scanned} paths</p>
            <table class="data-table"><thead><tr><th>Status</th><th>URL</th><th>Code</th></tr></thead>
            <tbody>{admin_rows}</tbody></table>"""))

    # ── Subdomains ────────────────────────────────────────────────────
    subs = scan.results.get("subdomains")
    if subs and getattr(subs, "success", False) and subs.subdomains:
        sub_list = "".join(f"<li>{_esc(s)}</li>" for s in subs.subdomains[:50])
        extra = f"<p>...and {subs.total_count - 50} more</p>" if subs.total_count > 50 else ""
        sections.append(("subdomains", "Subdomains", f"""
            <p>Total: {subs.total_count} | Sources: {', '.join(subs.sources_used)}</p>
            <ul class="sub-list">{sub_list}</ul>{extra}"""))

    # ── Shodan ────────────────────────────────────────────────────────
    shodan = scan.results.get("shodan")
    if shodan and getattr(shodan, "success", False):
        port_rows = ""
        for p in shodan.ports[:20]:
            port_rows += f"<tr><td>{p.port}</td><td>{p.transport}</td><td>{_esc(p.product or '-')}</td><td>{_esc(p.version or '-')}</td></tr>"
        vuln_tags = "".join(f'<span class="vuln-tag">{_esc(v)}</span>' for v in shodan.vulns[:15])
        sections.append(("shodan", "Shodan Intelligence", f"""
            <div class="kv-grid">
                <div class="kv"><span class="k">IP</span><span class="v">{_esc(shodan.ip)}</span></div>
                <div class="kv"><span class="k">Org</span><span class="v">{_esc(shodan.org)}</span></div>
                <div class="kv"><span class="k">ISP</span><span class="v">{_esc(shodan.isp)}</span></div>
                <div class="kv"><span class="k">ASN</span><span class="v">{_esc(shodan.asn)}</span></div>
            </div>
            <h4 style="margin-top:12px">Open Ports</h4>
            <table class="data-table"><thead><tr><th>Port</th><th>Proto</th><th>Product</th><th>Version</th></tr></thead>
            <tbody>{port_rows}</tbody></table>
            {'<h4 style="margin-top:12px">Known CVEs</h4><div class="vuln-list">' + vuln_tags + '</div>' if vuln_tags else ''}
            """))

    # ── Screenshots ───────────────────────────────────────────────────
    screenshot = scan.results.get("screenshot")
    if screenshot and getattr(screenshot, "success", False):
        imgs = ""
        for label, path in [
            ("Desktop", getattr(screenshot, "desktop_path", None)),
            ("Mobile", getattr(screenshot, "mobile_path", None)),
            ("Full Page", getattr(screenshot, "fullpage_path", None)),
        ]:
            b64 = _b64_image(path) if path else ""
            if b64:
                imgs += f'<div class="screenshot"><h4>{label}</h4><img src="{b64}" alt="{label} screenshot" loading="lazy"></div>'
        if imgs:
            sections.append(("screenshots", "Screenshots", f'<div class="screenshot-grid">{imgs}</div>'))

    # ── Build nav and sections HTML ───────────────────────────────────
    nav_items = ""
    content_sections = ""
    for sec_id, sec_title, sec_body in sections:
        nav_items += f'<a href="#{sec_id}" class="nav-item">{_esc(sec_title)}</a>\n'
        content_sections += f"""
        <section id="{sec_id}" class="section">
            <div class="section-header" onclick="this.parentElement.classList.toggle('collapsed')">
                <h2>{_esc(sec_title)}</h2>
                <span class="chevron">▼</span>
            </div>
            <div class="section-body">{sec_body}</div>
        </section>\n"""

    # ── Score gauge SVG ───────────────────────────────────────────────
    pct = score_val / 100
    dash_offset = 283 * (1 - pct)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Recon Report — {_esc(scan.target)}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
:root{{
    --bg:#0a0e17;--surface:#131926;--surface2:#1a2236;
    --accent:#00e5ff;--success:#00e676;--error:#ff1744;--warn:#ffc400;
    --text:#e0e0e0;--muted:#969696;--border:#1e2940;
}}
body{{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text);display:flex;min-height:100vh}}
a{{color:var(--accent);text-decoration:none}}a:hover{{text-decoration:underline}}

/* Sidebar */
.sidebar{{width:260px;background:var(--surface);border-right:1px solid var(--border);padding:20px 0;position:fixed;height:100vh;overflow-y:auto;z-index:10}}
.sidebar-header{{padding:16px 20px;border-bottom:1px solid var(--border)}}
.sidebar-header h1{{font-size:14px;color:var(--accent);letter-spacing:2px;text-transform:uppercase}}
.sidebar-header .target{{font-size:12px;color:var(--muted);margin-top:4px;word-break:break-all}}
.nav-item{{display:block;padding:10px 20px;color:var(--text);font-size:13px;transition:all .2s}}
.nav-item:hover{{background:var(--surface2);color:var(--accent);text-decoration:none}}

/* Search */
.search-box{{padding:12px 20px}}
.search-box input{{width:100%;padding:8px 12px;background:var(--bg);border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:13px;outline:none}}
.search-box input:focus{{border-color:var(--accent)}}

/* Main */
.main{{margin-left:260px;flex:1;padding:30px}}

/* Score card */
.score-card{{background:var(--surface);border-radius:12px;padding:24px;display:flex;align-items:center;gap:24px;margin-bottom:24px;border:1px solid var(--border)}}
.score-gauge svg{{width:120px;height:120px}}
.score-gauge .bg{{fill:none;stroke:var(--border);stroke-width:8}}
.score-gauge .fg{{fill:none;stroke:{sc};stroke-width:8;stroke-linecap:round;stroke-dasharray:283;stroke-dashoffset:{dash_offset:.1f};transform:rotate(-90deg);transform-origin:center;transition:stroke-dashoffset 1s ease}}
.score-gauge text{{fill:var(--text);font-weight:700}}
.score-info h2{{font-size:28px;color:{sc}}}
.score-info .meta{{color:var(--muted);font-size:13px;margin-top:4px}}

/* Sections */
.section{{background:var(--surface);border-radius:10px;margin-bottom:16px;border:1px solid var(--border);overflow:hidden}}
.section-header{{display:flex;justify-content:space-between;align-items:center;padding:16px 20px;cursor:pointer;user-select:none}}
.section-header h2{{font-size:16px;color:var(--accent)}}
.chevron{{color:var(--muted);transition:transform .3s}}
.section.collapsed .section-body{{display:none}}
.section.collapsed .chevron{{transform:rotate(-90deg)}}
.section-body{{padding:0 20px 20px}}

/* Tables */
.data-table{{width:100%;border-collapse:collapse;font-size:13px}}
.data-table th{{text-align:left;padding:8px 10px;background:var(--surface2);color:var(--accent);font-weight:600;border-bottom:1px solid var(--border)}}
.data-table td{{padding:7px 10px;border-bottom:1px solid var(--border)}}
.data-table tr:hover{{background:rgba(0,229,255,0.03)}}
.data-table tr.fail td{{border-left:3px solid var(--error)}}
.data-table tr.warn td{{border-left:3px solid var(--warn)}}
.data-table tr.pass td{{border-left:3px solid var(--success)}}

/* KV grid */
.kv-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:8px}}
.kv{{display:flex;gap:8px;padding:6px 0}}
.k{{color:var(--muted);font-size:13px;min-width:110px;flex-shrink:0}}
.v{{color:var(--text);font-size:13px;word-break:break-all}}

/* Tech tags */
.tech-grid{{display:flex;flex-wrap:wrap;gap:16px}}
.tech-cat h4{{color:var(--muted);font-size:12px;margin-bottom:6px;text-transform:uppercase;letter-spacing:1px}}
.tech-tag{{display:inline-block;padding:4px 10px;background:var(--surface2);border:1px solid var(--border);border-radius:4px;font-size:12px;margin:2px}}

/* Badge */
.badge{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;color:#fff}}

/* Vuln */
.vuln-tag{{display:inline-block;padding:3px 8px;background:rgba(255,23,68,0.15);border:1px solid var(--error);border-radius:4px;font-size:12px;margin:2px;color:var(--error)}}

/* Subdomains */
.sub-list{{columns:2;list-style:none;font-size:13px}}.sub-list li{{padding:3px 0}}

/* Screenshots */
.screenshot-grid{{display:flex;flex-wrap:wrap;gap:16px}}
.screenshot img{{max-width:100%;border-radius:6px;border:1px solid var(--border);cursor:pointer}}
.screenshot img:hover{{opacity:.9}}
.screenshot h4{{color:var(--muted);font-size:12px;margin-bottom:6px}}

/* Summary */
.summary-text p{{line-height:1.7;margin-bottom:12px}}

/* Responsive */
@media(max-width:768px){{
    .sidebar{{display:none}}
    .main{{margin-left:0}}
    .score-card{{flex-direction:column;text-align:center}}
    .kv-grid{{grid-template-columns:1fr}}
    .sub-list{{columns:1}}
}}
</style>
</head>
<body>
<nav class="sidebar">
    <div class="sidebar-header">
        <h1>⛏ Recon Report</h1>
        <div class="target">{_esc(scan.target)}</div>
    </div>
    <div class="search-box">
        <input type="text" id="search" placeholder="Search report..." oninput="filterSections(this.value)">
    </div>
    <a href="#score-card" class="nav-item">Security Score</a>
    {nav_items}
</nav>

<main class="main">
    <div class="score-card" id="score-card">
        <div class="score-gauge">
            <svg viewBox="0 0 100 100">
                <circle class="bg" cx="50" cy="50" r="45"/>
                <circle class="fg" cx="50" cy="50" r="45"/>
                <text x="50" y="45" text-anchor="middle" font-size="22">{score_val}</text>
                <text x="50" y="62" text-anchor="middle" font-size="10" fill="var(--muted)">/100</text>
            </svg>
        </div>
        <div class="score-info">
            <h2>Grade: {_esc(grade)}</h2>
            <div class="meta">Risk Level: {_esc(risk)} • {scan.score.total_checks if scan.score else 0} checks performed</div>
            <div class="meta">Scan: {_esc(scan.start_time)} • Duration: {scan.total_duration:.1f}s</div>
        </div>
    </div>

    {content_sections}

    <footer style="text-align:center;padding:24px;color:var(--muted);font-size:12px">
        Generated by Automatic Recon Tool v{__version__} • CONFIDENTIAL
    </footer>
</main>

<script>
function filterSections(q) {{
    q = q.toLowerCase();
    document.querySelectorAll('.section').forEach(s => {{
        const text = s.textContent.toLowerCase();
        s.style.display = text.includes(q) ? '' : 'none';
    }});
}}
document.querySelectorAll('.copy-target').forEach(el => {{
    el.style.cursor = 'pointer';
    el.title = 'Click to copy';
    el.addEventListener('click', () => {{
        navigator.clipboard.writeText(el.textContent);
        const orig = el.textContent;
        el.textContent = 'Copied!';
        setTimeout(() => el.textContent = orig, 1000);
    }});
}});
</script>
</body>
</html>"""

    # Save
    filename = cfg.documents_dir / f"{safe_filename(scan.target)}_report_{timestamp_str()}.html"
    filename.parent.mkdir(parents=True, exist_ok=True)
    with open(filename, "w", encoding="utf-8") as fh:
        fh.write(html_content)

    return str(filename)
