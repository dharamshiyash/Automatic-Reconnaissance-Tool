"""
recon.reports.json_report — JSON report generator.

Produces a structured, machine-readable JSON export of all scan results
for automation pipelines and data analysis.
"""

from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, Optional

from recon import __version__
from recon.config import Config
from recon.utils import safe_filename, timestamp_str


def _serialize(obj: Any) -> Any:
    """Custom serializer for dataclass and non-serializable types."""
    if is_dataclass(obj) and not isinstance(obj, type):
        return asdict(obj)
    if isinstance(obj, Path):
        return str(obj)
    if hasattr(obj, "__dict__"):
        return {k: v for k, v in obj.__dict__.items() if not k.startswith("_")}
    return str(obj)


def generate(scan: Any, config: Optional[Config] = None) -> str:
    """Generate a JSON report and save to disk.

    Args:
        scan: ScanResult from the engine.
        config: Optional Config for output directory.

    Returns:
        Path to the saved report file.
    """
    cfg = config or Config()

    report: dict[str, Any] = {
        "meta": {
            "tool": "Automatic Recon Tool",
            "version": __version__,
            "target": scan.target,
            "scan_start": scan.start_time,
            "scan_end": scan.end_time,
            "duration_seconds": round(scan.total_duration, 2),
        },
        "score": None,
        "summary": scan.summary,
        "modules": {},
    }

    # Score
    if scan.score:
        report["score"] = {
            "value": scan.score.score,
            "grade": scan.score.grade,
            "risk_level": scan.score.risk_level,
            "total_checks": scan.score.total_checks,
            "passed_checks": scan.score.passed_checks,
            "failed_checks": scan.score.failed_checks,
            "findings": [
                {
                    "title": f.title,
                    "description": f.description,
                    "severity": f.severity,
                    "category": f.category,
                    "points_deducted": f.points_deducted,
                }
                for f in scan.score.findings
            ],
        }

    # Module results
    for name, result in scan.results.items():
        try:
            if is_dataclass(result) and not isinstance(result, type):
                module_data = asdict(result)
            elif hasattr(result, "__dict__"):
                module_data = {
                    k: v
                    for k, v in result.__dict__.items()
                    if not k.startswith("_")
                }
            else:
                module_data = str(result)

            # Remove raw/heavy data to keep JSON manageable
            if isinstance(module_data, dict):
                module_data.pop("raw", None)
                module_data.pop("raw_cert", None)
                module_data.pop("builtwith_raw", None)

            report["modules"][name] = module_data
        except Exception as exc:
            report["modules"][name] = {"error": f"Serialization failed: {exc}"}

    # Module execution info
    report["execution"] = {}
    for name, info in scan.modules.items():
        report["execution"][name] = {
            "display_name": info.display_name,
            "status": info.status.value,
            "duration_seconds": round(info.duration, 2),
            "error": info.error,
        }

    # Save
    filename = cfg.documents_dir / f"{safe_filename(scan.target)}_report_{timestamp_str()}.json"
    filename.parent.mkdir(parents=True, exist_ok=True)
    with open(filename, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, default=_serialize, ensure_ascii=False)

    return str(filename)
