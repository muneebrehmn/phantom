"""
phantom/report/json_export.py

Exports scan results as a structured JSON file.

The JSON format is designed to be:
  - Machine-readable for downstream tooling (SIEM, vulnerability trackers)
  - Human-readable with consistent indentation
  - Complete enough to reproduce findings without re-running the scan

The schema mirrors the Markdown report structure but in a form that CI/CD
pipelines and scripts can parse without understanding Markdown.

Schema overview:
    {
      "meta": { scan metadata },
      "summary": { finding counts by severity },
      "findings": [ { finding objects } ],
      "surfaces": [ { surface objects } ]
    }
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from phantom.core.config import PhantomConfig
from phantom.core.logger import get_logger
from phantom.core.state import SessionState
from phantom.report.cvss import score_finding

log = get_logger(__name__)


class JsonExporter:
    """
    Writes scan results to a structured JSON file.

    Usage:
        exporter = JsonExporter(config, state)
        path = exporter.export(output_dir)
    """

    def __init__(self, config: PhantomConfig, state: SessionState) -> None:
        self.config = config
        self.state = state

    def export(self, output_dir: Path) -> Path:
        """
        Render the full JSON report and write it to output_dir/phantom_report.json.
        Returns the Path of the written file.
        """
        data = self._build_dict()
        output_path = output_dir / "phantom_report.json"

        with open(output_path, "w", encoding="utf-8") as fh:
            # indent=2 keeps the file human-readable in a text editor
            json.dump(data, fh, indent=2, ensure_ascii=False)

        log.debug("JSON report: %d findings, %d surfaces", len(data["findings"]), len(data["surfaces"]))
        return output_path

    # ------------------------------------------------------------------
    # Document builder
    # ------------------------------------------------------------------

    def _build_dict(self) -> dict:
        """Assemble the complete JSON document as a Python dict."""
        summary = self.state.summary()
        findings = self.state.findings_by_severity()

        # Attach CVSSv3.1 scores before serialising so the fields are
        # populated in to_dict() output (cvss_vector, cvss_base_score, cvss_severity)
        for f in findings:
            cvss = score_finding(f.payload_category)
            f.cvss_vector     = cvss.vector_string
            f.cvss_base_score = cvss.base_score
            f.cvss_severity   = cvss.severity_label

        return {
            "meta": {
                "tool": "Phantom",
                "version": "0.1",
                "standard": "NIST SP 800-115 / PTES / CVSSv3.1",
                "generated_at": datetime.now().isoformat(timespec="seconds"),
                "target": self.config.target_url,
                "scan_config": {
                    "max_depth": self.config.max_depth,
                    "max_pages": self.config.max_pages,
                    "concurrency_limit": self.config.concurrency_limit,
                    "rate_limit_rps": self.config.rate_limit_rps,
                    "fingerprint_latency_samples": self.config.fingerprint_latency_samples,
                },
            },
            "summary": {
                **summary,
                "max_cvss_base_score": max((f.cvss_base_score for f in findings), default=0.0),
                "cvss_severity": (
                    max(
                        findings,
                        key=lambda f: f.cvss_base_score,
                        default=None,
                    ).cvss_severity
                    if findings else "None"
                ),
            },
            "findings": [f.to_dict() for f in findings],
            "surfaces": self._serialize_surfaces(),
        }

    def _serialize_surfaces(self) -> list:
        """
        Serialize all discovered surfaces to a list of dicts.

        We use getattr with defaults throughout because ClassifiedSurface
        objects may have varying attributes depending on the classifier version.
        """
        result = []
        for url, surface in self.state.surfaces.items():
            fp = getattr(surface, "fingerprint", None)
            entry = {
                "url": url,
                "surface_type": getattr(surface, "surface_type", "unknown"),
                "attack_vectors": getattr(surface, "attack_vectors", []),
                "fingerprint": {
                    "confidence": getattr(fp, "confidence", None),
                    "label": getattr(fp, "label", None),
                    "is_streaming": getattr(fp, "is_streaming", None),
                    "latency_mean_ms": getattr(fp, "latency_mean_ms", None),
                    "latency_std_ms": getattr(fp, "latency_std_ms", None),
                    "matched_url_patterns": getattr(fp, "matched_url_patterns", []),
                    "matched_json_keys": getattr(fp, "matched_json_keys", []),
                    "evidence": getattr(fp, "evidence", []),
                } if fp else None,
            }
            result.append(entry)
        return result