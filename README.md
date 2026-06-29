<div align="center">

# 🛡️ AUTOMATIC RECONNAISSANCE TOOL
### Professional Passive & Active OSINT Cybersecurity Framework

<p align="center">
  <img src="assets/logo/logo.png" alt="Automatic Reconnaissance Logo" height="100">
</p>

[![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB.svg?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-00e5ff.svg?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-macOS%20%7C%20Linux%20%7C%20Windows-4EAA25.svg?style=for-the-badge&logo=linux&logoColor=white)](https://github.com/dharamshiyash/Automatic-Reconnaissance-Tool)
[![Stars](https://img.shields.io/github/stars/dharamshiyash/Automatic-Reconnaissance-Tool.svg?style=for-the-badge&color=ff69b4)](https://github.com/dharamshiyash/Automatic-Reconnaissance-Tool/stargazers)
[![Issues](https://img.shields.io/github/issues/dharamshiyash/Automatic-Reconnaissance-Tool.svg?style=for-the-badge&color=orange)](https://github.com/dharamshiyash/Automatic-Reconnaissance-Tool/issues)

**An enterprise-grade, concurrent cybersecurity reconnaissance framework designed for automated passive information gathering, posture evaluation, vulnerability profiling, and professional reporting.**

[Key Features](#-features) • [Architecture](#-architecture) • [Screenshots](#-screenshots) • [Installation](#-installation) • [Usage](#-usage) • [Tech Stack](#-tech-stack)

</div>

---

## 📖 Overview

In modern cybersecurity engineering, effective penetration testing and proactive defense begin with comprehensive **reconnaissance**. Security engineers often spend countless manual hours running fragmented tools (WHOIS lookups, DNS enumeration, SSL grading, Shodan queries, web scraping, and directory fuzzing) and assembling the raw data into cohesive reports.

The **Automatic Reconnaissance Tool** bridges this gap by unifying 11+ specialized reconnaissance modules into a single concurrent orchestration engine. Equipped with an intuitive graphical user interface (GUI) and multi-format automated reporting capabilities, it empowers security professionals, ethical hackers, and defensive engineers to evaluate organizational exposure rapidly and accurately.

### 🎯 Cybersecurity Use Cases
- **External Attack Surface Management (EASM):** Continuously discover and map domain assets, exposed admin panels, and forgotten subdomains.
- **Vulnerability Profiling & Shodan Enrichment:** Rapidly cross-reference target IP addresses against Shodan intelligence to uncover open ports, running services, and known CVEs.
- **Automated Compliance & Posture Grading:** Evaluate TLS cipher suites, security headers (HSTS, CSP, CORS), and DNS configurations (SPF, DMARC, DNSSEC) against industry benchmarks with an automated 0–100 scoring engine.
- **Executive Reporting:** Automatically synthesize technical findings into executive summaries delivered in PDF, HTML, JSON, and plain-text formats, with optional automated SMTP email dispatch.

---

## ✨ Features

| Status | Reconnaissance Module | Description & Capabilities |
| :---: | :--- | :--- |
| ✅ | **WHOIS Lookup** | Extracts domain registration details, registrar metadata, creation/expiration dates, and authoritative name servers. |
| ✅ | **DNS Analysis** | Deep enumeration across A, AAAA, MX, TXT, NS, SOA, CAA, and PTR records with SPF, DMARC, DNSSEC, and TTL tracking. |
| ✅ | **SSL Inspection** | Analyzes certificate chains, TLS versions, cipher strengths, SANs, and flags weak ciphers or self-signed certificates. |
| ✅ | **HTTP Header Analysis** | Inspects security headers (HSTS, CSP, X-Frame-Options), cookie flags, CORS policies, robots.txt, and sitemaps. |
| ✅ | **Admin Panel Discovery** | Multi-threaded directory scanner evaluating 200+ high-probability administrative paths with false-positive detection. |
| ✅ | **Technology Detection** | Fingerprints CMS platforms, web servers, frontend frameworks, and JavaScript libraries via 50+ Wappalyzer signatures & BuiltWith. |
| ✅ | **Screenshot Capture** | Headless automated browser capture providing desktop (1280×800), mobile (iPhone form-factor), and full-page scroll snapshots. |
| ✅ | **Subdomain Enumeration** | Passive OSINT discovery combining Certificate Transparency (`crt.sh`) logs with Sublist3r multi-source enumeration. |
| ✅ | **Shodan Integration** | Queries Shodan intelligence for ISP metadata, ASNs, open ports, banners, software product versions, and assigned CVEs. |
| ✅ | **PDF Report Generation** | Generates executive publication-ready PDF reports featuring cover pages, score badges, data tables, and embedded screenshots. |
| ✅ | **HTML Interactive Report** | Modern dark-themed interactive HTML dashboard with search filtering, collapsible cards, and SVG score gauges. |
| ✅ | **Email Report Delivery** | Built-in SMTP delivery agent that automatically emails encrypted or standard PDF reconnaissance reports upon completion. |
| ✅ | **Professional GUI** | Responsive Tkinter dark-mode interface featuring progress bars, live execution tracking, and tabbed dashboard views. |

---

## 🏗️ Architecture Diagram

The application uses a clean decoupled architecture separating the GUI view, concurrent execution engine, analytical scoring, and report generation pipelines:

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                                PRESENTATION LAYER                                │
│                     Tkinter GUI (app.py, dashboard.py, theme.py)                 │
└────────────────────────────────────────┬─────────────────────────────────────────┘
                                         │ User Input (Target URL & Email)
                                         ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│                              ORCHESTRATION LAYER                                 │
│                      Concurrent Engine (engine.py, ThreadPoolExecutor)           │
├────────────────────────────────────────┬─────────────────────────────────────────┤
│    PHASE 1: Concurrent I/O Scans       │     PHASE 2: Heavy & Sequential Scans   │
│  ├── WHOIS Lookup Module               │   ├── Admin Panel Directory Scanner     │
│  ├── DNS & TXT Record Enumerator       │   ├── Subdomain OSINT Enumerator        │
│  ├── SSL/TLS Certificate Inspector     │   ├── Shodan Intelligence Analyzer      │
│  ├── HTTP Security Header Scanner      │   └── Headless Selenium Screenshot Capt │
│  ├── GeoIP & AS Routing Lookup         │                                         │
│  └── Technology Fingerprinter          │                                         │
└────────────────────────────────────────┬─────────────────────────────────────────┘
                                         │ Structured Dataclass Results
                                         ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│                                 ANALYSIS LAYER                                   │
│           Security Scoring Engine (0–100 Grade) & Executive AI Summary Generator │
└────────────────────────────────────────┬─────────────────────────────────────────┘
                                         │ Compiled Scan Summary
                                         ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│                               REPORTING LAYER                                    │
│   ├── PDF Report Generator ──────► reports/<target>_report_<timestamp>.pdf       │
│   ├── HTML Interactive Dashboard ► reports/<target>_report_<timestamp>.html      │
│   ├── JSON Machine Export ───────► reports/<target>_report_<timestamp>.json      │
│   ├── TXT Formatted Log ─────────► reports/<target>_report_<timestamp>.txt       │
│   └── SMTP Email Dispatcher ─────► Sends PDF Report directly to Client Inbox     │
└──────────────────────────────────────────────────────────────────────────────────┘
```

---

## 📸 Screenshots

### 1. Graphical User Interface (GUI) & Progress Tracking
The modern dark-themed interface tracks module execution in real time with intuitive visual status indicators.
<p align="center">
  <img src="assets/screenshots/gui_progress_demo.png" alt="GUI Progress Window" width="80%">
</p>

### 2. Automated Visual Reconnaissance Capture
Automated headless browser capture captures desktop, mobile, and full-page layout evidence automatically.
<p align="center">
  <img src="assets/screenshots/report_demo.png" alt="Generated Screenshot Preview" width="80%">
</p>

### 3. Generated Report Pipeline
Reports are seamlessly compiled into structured deliverables ready for executive distribution or audit documentation.
```
reports/
├── https_www.target.com_report_20260629_120000.pdf   (Executive PDF Report)
├── https_www.target.com_report_20260629_120000.html  (Interactive HTML Dashboard)
├── https_www.target.com_report_20260629_120000.json  (Machine-readable Export)
└── https_www.target.com_report_20260629_120000.txt   (Plain-text Log Summary)
```

---

## ⚡ Installation

Follow these steps to set up the tool in your local development or testing environment:

### 1. Clone the Repository
```bash
git clone https://github.com/dharamshiyash/Automatic-Reconnaissance-Tool.git
cd Automatic-Reconnaissance-Tool
```

### 2. Create & Activate a Virtual Environment (Recommended)
```bash
# macOS / Linux
python3 -m venv venv
source venv/bin/activate

# Windows
python -m venv venv
venv\Scripts\activate
```

### 3. Install Required Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Configure Environment Variables
Copy the configuration template and insert your API keys and SMTP delivery credentials:
```bash
cp .env.example .env
```

Edit the `.env` file with your preferred text editor:
```env
RECON_SMTP_SERVER=smtp.gmail.com
RECON_SMTP_PORT=587
RECON_SMTP_USER=your_email@gmail.com
RECON_SMTP_PASS=your_16_char_app_password
RECON_SMTP_USE_TLS=yes

SHODAN_API_KEY=your_shodan_api_key_here
```

---

## 🎮 Usage

### Launching the Graphical Application
To run the full interactive GUI framework with animated splash screen and real-time dashboard:
```bash
python automatic_recon_gui.py
```

### Step-by-Step Execution Guide:
1. **Target Input:** Enter the target URL or domain name (e.g., `https://example.com` or `testphp.vulnweb.com`) in the main target field.
2. **Email Recipient (Optional):** Enter an email address if you wish the completed PDF assessment report to be dispatched automatically via SMTP upon scan completion.
3. **Execute Scan:** Click the **Start Scan** button.
4. **Live Monitoring:** Observe the sidebar indicators as threads execute concurrently (Green = Success, Red = Issue/Vulnerability found, Yellow = Warning/Skip).
5. **Review Dashboard:** Once finalized, switch between the **Dashboard** and **Raw Output** tabs to explore detailed DNS records, SSL ciphers, and discovered administrative paths.
6. **Access Reports:** Retrieve your finalized PDF, HTML, JSON, and TXT deliverables from the `reports/` directory.

---

## 💻 Tech Stack

The project leverages industry-standard Python libraries and security frameworks:

* **Language:** Python 3.9+
* **GUI Framework:** Tkinter (Custom Dark Mode UI Design)
* **Concurrent Engine:** Python `concurrent.futures.ThreadPoolExecutor`
* **HTTP & Web Scraping:** `requests`, `BeautifulSoup4` (`bs4`)
* **Browser Automation:** `selenium`, `webdriver-manager` (Headless Chromium screenshot generation)
* **PDF Engine:** `fpdf2` (Custom styling, headers, footers, and table rendering)
* **DNS Enumeration:** `dnspython`
* **WHOIS Lookups:** `python-whois`
* **Technology Fingerprinting:** `builtwith` + Custom Regex Signatures
* **Threat Intelligence:** `shodan` API Client
* **Subdomain Discovery:** `Sublist3r` integration & Certificate Transparency (`crt.sh`) REST API

---

## 🛣️ Future Improvements (Roadmap)

We are continuously working to expand the capabilities of the framework. Planned future upgrades include:

- [ ] **Headless CLI Mode:** Add terminal flag arguments (`--target`, `--output`, `--silent`) for automated CI/CD security pipelines.
- [ ] **Nmap Port Scanning Integration:** Incorporate `python-nmap` for active SYN/TCP port scanning and service banner grabbing.
- [ ] **Vulnerability & CVE Mapping:** Cross-reference discovered software versions against NIST NVD / VulnDB APIs automatically.
- [ ] **Docker Containerization:** Provide an official lightweight `Dockerfile` and `docker-compose.yml` for isolated container execution.
- [ ] **REST API Server Integration:** Implement a FastAPI backend enabling remote execution and multi-user team dashboarding.
- [ ] **Custom Wordlist Support:** Allow dynamic runtime loading of user-specified fuzzing dictionaries and subdomain wordlists.

---

## ⚖️ License & Credits

This project is open-source software licensed under the **MIT License**. See the [LICENSE](LICENSE) file for complete terms and details.

### Credits & Acknowledgments
- Developed as part of an intensive **Cybersecurity Internship** at **Supraja Technologies**.
- Built to provide security teams and engineers with a unified, professional reconnaissance alternative to fragmented command-line utilities.

---

## 👨‍💻 Author

**Yash Dharamshi**
* **GitHub:** [@dharamshiyash](https://github.com/dharamshiyash)
* **Repository:** [Automatic-Reconnaissance-Tool](https://github.com/dharamshiyash/Automatic-Reconnaissance-Tool)

---
<p align="center">
  <b>⭐ If you find this project useful for your cybersecurity engineering workflows, please consider giving it a star on GitHub! ⭐</b>
</p>
