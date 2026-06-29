"""
Recon Modules Package.

Each module implements a specific reconnaissance technique and returns
structured results as dataclass instances.
"""

MODULE_REGISTRY: list[str] = [
    "whois_recon",
    "dns_recon",
    "http_recon",
    "ssl_recon",
    "geo_recon",
    "tech_recon",
    "admin_recon",
    "subdomain_recon",
    "shodan_recon",
    "screenshot_recon",
    "html_meta_recon",
]
