# Architecture

## System Overview

The Automatic Recon Tool follows a layered architecture:

```
┌─────────────────────────────────────────┐
│              GUI Layer                  │
│   (app.py, theme.py, dashboard.py)      │
├─────────────────────────────────────────┤
│           Orchestration Layer           │
│          (engine.py)                    │
│   ThreadPoolExecutor + Callbacks        │
├─────────────────────────────────────────┤
│          Analysis Layer                 │
│   (scoring.py, summary.py)              │
├──────────┬──────────────────────────────┤
│  Modules │        Reports              │
│          │                              │
│  whois   │  pdf_report.py              │
│  dns     │  html_report.py             │
│  http    │  json_report.py             │
│  ssl     │  txt_report.py              │
│  geo     │  email_report.py            │
│  tech    │                              │
│  admin   │                              │
│  subdomain│                             │
│  shodan  │                              │
│  screenshot│                            │
│  html_meta│                             │
├──────────┴──────────────────────────────┤
│          Foundation Layer               │
│   (config.py, logger.py, utils.py)      │
└─────────────────────────────────────────┘
```

## Execution Flow

```
User → GUI → Engine.run(target)
                  │
                  ├─ Phase 1 (concurrent): WHOIS, DNS, HTTP, SSL, GeoIP, HTML Meta, Tech
                  │
                  ├─ Phase 2 (sequential): Admin Discovery, Subdomains, Shodan, Screenshots
                  │
                  ├─ Phase 3 (analysis): Security Score → Executive Summary
                  │
                  └─ Reports: PDF, HTML, JSON, TXT → Email (optional)
```

## Module Interface

Every module follows the same pattern:

```python
@dataclass
class ModuleResult:
    """Structured result with success flag and error."""
    error: Optional[str] = None
    success: bool = False

def run(target: str, ...) -> ModuleResult:
    """Execute the module and return structured results."""
```

## Data Flow

1. **Config** loads from `.env` → environment → defaults
2. **Engine** creates `ThreadPoolExecutor`, schedules modules
3. Each **Module** returns a typed dataclass
4. **Scoring** engine analyzes all results → `SecurityScore`
5. **Summary** generator creates narrative text
6. **Reports** serialize everything to PDF/HTML/JSON/TXT
7. **GUI** displays results via Dashboard + Raw Output tabs
