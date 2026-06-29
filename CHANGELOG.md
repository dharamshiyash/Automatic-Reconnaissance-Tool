# Changelog

All notable changes to this project will be documented in this file.

## [2.0.0] — 2026-06-28

### 🚀 Major Upgrade — Professional Reconnaissance Framework

#### Architecture
- **Modular package structure**: Split monolithic 787-line file into 25+ focused modules
- **`recon/` package** with subpackages: `modules/`, `reports/`, `gui/`
- **Concurrent execution engine** using `ThreadPoolExecutor` for parallel scans
- **Centralized configuration** via `.env` files — no hardcoded secrets

#### New Features
- **Security Score Engine**: 0–100 scoring with A+ to F grades across ~30 security checks
- **Executive AI Summary**: Template-based narrative report from collected evidence
- **Interactive HTML Report**: Dark-themed, searchable, with SVG score gauge and sidebar navigation
- **JSON Export**: Machine-readable output for automation pipelines
- **Professional PDF Report**: Cover page, score badge, color-coded tables, embedded screenshots, recommendations
- **Enhanced DNS**: A/AAAA/MX/TXT/NS/SOA/CAA/PTR/SPF/DMARC/DNSSEC with TTL tracking
- **Enhanced HTTP**: Security headers analysis, cookie inspection, CORS, robots.txt, sitemap, redirect chain
- **Enhanced SSL**: TLS version, cipher suite, SAN, chain depth, weak cipher detection, certificate grading
- **Enhanced Tech Detection**: Wappalyzer-style pattern matching (50+ signatures) + BuiltWith
- **Enhanced Admin Discovery**: Configurable 200-path wordlist, concurrent scanning, response classification, false positive detection
- **Enhanced Subdomains**: crt.sh passive enumeration merged with Sublist3r
- **Enhanced Shodan**: ISP, ASN, hostnames, tags, CVE extraction, product versions
- **Enhanced Screenshots**: Desktop (1280×800), Mobile (375×812), Full-page (scroll-stitched)
- **Structured Logging**: Rotating file logs (recon.log, errors.log, debug.log) with duration tracking

#### GUI Redesign
- Modern dark cybersecurity theme with consistent styling
- Module execution tracker sidebar (green/red/yellow/grey indicators)
- Progress bar with percentage
- Tabbed view: Dashboard + Raw Output
- Professional splash screen with animated loading
- Responsive resizing (minimum 1000×650)
- Settings dialog for SMTP and API keys

#### Code Quality
- PEP-8 compliant with type hints throughout
- Comprehensive docstrings on all modules and functions
- Dataclass-based structured results (no more raw dicts/tuples)
- Eliminated duplicated domain-parsing logic via `clean_domain()` utility
- Input validation on all user-facing inputs

#### Security
- Removed hardcoded SMTP credentials and API keys from source code
- Configuration via `.env` files (git-ignored)
- Input validation and graceful error handling
- SMTP password and API keys masked in Settings UI

#### GitHub Quality
- Professional README with badges, architecture diagram, and feature list
- `requirements.txt` with pinned dependencies
- MIT License
- `.gitignore` for secrets, cache, and runtime output
- `CHANGELOG.md`, `SECURITY.md`, `CONTRIBUTING.md`

## [1.0.0] — 2025-10-26

### Initial Release
- WHOIS, DNS, HTTP headers, SSL, GeoIP, Admin panel discovery
- HTML metadata extraction, BuiltWith tech detection
- Selenium screenshot capture
- Subdomain enumeration (Sublist3r)
- Shodan integration
- PDF and TXT report generation
- Email report sending
- Tkinter GUI with background image
