"""
phantom/report/builder.py

Report generation orchestrator.

The ReportBuilder reads completed SessionState (after scanning + analysis)
and produces one or more output artifacts based on config.report_formats:
  - "markdown" → a human-readable .md file
  - "json"     → a machine-readable .json file
  - "html"     → an interactive self-contained .html report

The builder delegates actual formatting to the specialized modules:
  markdown.py, json_export.py, and html_builder.py.  This file handles:
  - Output directory creation
  - Dispatch to the right exporter
  - Summary printing to the console
  - Returning paths of written files for the CLI to display
"""

from __future__ import annotations

from pathlib import Path
from typing import List

from phantom.core.config import PhantomConfig
from phantom.core.logger import get_logger, print_finding, print_section
from phantom.core.state import SessionState
from phantom.report.html_builder import generate_html_report
from phantom.report.json_export import JsonExporter
from phantom.report.markdown import MarkdownExporter

log = get_logger(__name__)


class ReportBuilder:
    """
    Orchestrates report export for a completed scan session.

    Usage:
        builder = ReportBuilder(config, state)
        written_files = builder.build()
        # written_files is a list of Path objects to the generated files.
    """

    def __init__(self, config: PhantomConfig, state: SessionState) -> None:
        self.config = config
        self.state = state

    def build(self) -> List[Path]:
        """
        Generate all requested report formats and return a list of written paths.

        Creates the output directory if it does not exist.
        Prints a findings summary to the console before writing files.
        """
        # Ensure output directory exists
        out_dir = self.config.output_dir
        out_dir.mkdir(parents=True, exist_ok=True)

        # Print live summary to terminal before writing files
        self._print_summary()

        written: List[Path] = []

        # Dispatch to each requested exporter
        for fmt in self.config.report_formats:
            if fmt == "markdown":
                exporter = MarkdownExporter(self.config, self.state)
                path = exporter.export(out_dir)
                written.append(path)
                log.info("Markdown report written → %s", path)

            elif fmt == "json":
                exporter = JsonExporter(self.config, self.state)
                path = exporter.export(out_dir)
                written.append(path)
                log.info("JSON report written → %s", path)

            elif fmt == "html":
                path = generate_html_report(self.config, self.state)
                written.append(path)
                log.info("HTML report written → %s", path)

            else:
                log.warning("Unknown report format %r — skipping", fmt)

        return written

    # ------------------------------------------------------------------
    # Console summary
    # ------------------------------------------------------------------

    def _print_summary(self) -> None:
        """
        Print a structured findings summary to the terminal at the end of
        each scan.  This gives the operator a quick overview without having
        to open the report files.
        """
        summary = self.state.summary()
        findings = self.state.findings_by_severity()

        print_section("Scan Complete")

        # Key stats
        log.info(
            "Target: %s | Runtime: %ss | Surfaces: %d | Payloads fired: %d",
            summary["target"],
            summary["runtime_seconds"],
            summary["surfaces_discovered"],
            summary["payloads_fired"],
        )

        if not findings:
            log.info("No findings above confidence threshold — surface may not be injectable")
            return

        print_section(f"Findings ({len(findings)} total)")

        # Print each finding in severity order (CRITICAL first)
        for finding in findings:
            print_finding(
                finding.severity.value,
                f"[{finding.payload_category}] {finding.payload_id} → {finding.surface_url}"
            )
            for indicator in finding.success_indicators[:2]:
                log.info("    ↳ %s", indicator)

        # Severity breakdown
        sev_breakdown = summary.get("findings_by_severity", {})
        if sev_breakdown:
            breakdown_str = "  |  ".join(
                f"{sev.upper()}: {count}"
                for sev, count in sorted(
                    sev_breakdown.items(),
                    key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(x[0], 9)
                )
            )
            log.info("Severity breakdown: %s", breakdown_str)