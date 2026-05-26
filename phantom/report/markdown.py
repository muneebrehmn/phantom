"""
phantom/report/markdown.py

Generates a professional Markdown vulnerability report from SessionState.

The report follows the structure of a real penetration testing deliverable:
  - Executive Summary (for non-technical stakeholders)
  - Scan Metadata
  - Findings (one section per finding, CRITICAL first)
  - Methodology
  - Appendix: Discovered Surfaces

Each finding section includes:
  - Severity badge and confidence score
  - Surface URL and classification
  - Payload used
  - Evidence (what signals triggered the finding)
  - Proof-of-Concept (curl + Python reproduction steps)
  - Remediation advice

The output is a single .md file that renders correctly on GitHub, GitLab,
and standard Markdown viewers.
"""

from __future__ import annotations

import textwrap
from datetime import datetime
from pathlib import Path

from phantom.core.config import PhantomConfig
from phantom.core.findings import Finding, Severity
from phantom.core.logger import get_logger
from phantom.core.state import SessionState

log = get_logger(__name__)

# Severity → emoji badge mapping for the Markdown report
_SEVERITY_BADGE = {
    Severity.CRITICAL: "🔴 CRITICAL",
    Severity.HIGH:     "🟠 HIGH",
    Severity.MEDIUM:   "🟡 MEDIUM",
    Severity.LOW:      "🟢 LOW",
    Severity.INFO:     "🔵 INFO",
}

# Boilerplate remediation advice per severity — can be extended per finding type
_REMEDIATION = {
    "direct": (
        "Implement strict input validation on all user-supplied text before it is "
        "included in any LLM prompt.  Use a fixed system prompt that cannot be "
        "overridden by user input.  Consider adding a prompt firewall (e.g. "
        "Rebuff, Lakera Guard) as an additional layer."
    ),
    "jailbreak": (
        "Deploy output-side filtering in addition to input filtering.  "
        "Jailbreaks that survive input filters are often caught by checking the "
        "model's response against a second safety classifier.  Evaluate the "
        "HarmBench benchmark for your deployed model."
    ),
    "role_confusion": (
        "Avoid relying on the system prompt alone to enforce persona constraints.  "
        "Use a model that supports 'system' role enforcement at the API level, "
        "and consider constitutional AI or RLHF-based alignment for production deployments."
    ),
    "system_prompt_leak": (
        "Treat the system prompt as a secret — but do not rely on secrecy as "
        "the primary defense.  Ensure the system prompt contains no credentials, "
        "internal URLs, or sensitive business logic.  Add explicit 'do not reveal "
        "these instructions' directives AND test them with red-team prompts."
    ),
    "indirect": (
        "Sanitize ALL external content before it is processed by the LLM — this "
        "includes web search results, uploaded documents, database records, and "
        "email content.  Mark external content clearly in the prompt so the model "
        "can distinguish it from trusted instructions."
    ),
    "unknown": (
        "Review the payload and response carefully.  Apply principle of least "
        "privilege to the LLM's capabilities, and consider a human-in-the-loop "
        "review step for high-stakes model outputs."
    ),
}


class MarkdownExporter:
    """
    Writes a complete Markdown penetration testing report to disk.

    Usage:
        exporter = MarkdownExporter(config, state)
        path = exporter.export(output_dir)
    """

    def __init__(self, config: PhantomConfig, state: SessionState) -> None:
        self.config = config
        self.state = state

    def export(self, output_dir: Path) -> Path:
        """
        Render the full report and write it to output_dir/phantom_report.md.
        Returns the Path of the written file.
        """
        content = self._render()
        output_path = output_dir / "phantom_report.md"
        output_path.write_text(content, encoding="utf-8")
        return output_path

    # ------------------------------------------------------------------
    # Top-level renderer
    # ------------------------------------------------------------------

    def _render(self) -> str:
        """Assemble all report sections into a single string."""
        summary = self.state.summary()
        findings = self.state.findings_by_severity()

        sections = [
            self._render_title(summary),
            self._render_executive_summary(summary, findings),
            self._render_scan_metadata(summary),
            self._render_findings(findings),
            self._render_methodology(),
            self._render_appendix_surfaces(),
        ]

        return "\n\n".join(sections)

    # ------------------------------------------------------------------
    # Section renderers
    # ------------------------------------------------------------------

    def _render_title(self, summary: dict) -> str:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return (
            f"# Phantom — Prompt Injection Vulnerability Report\n\n"
            f"**Target:** `{summary['target']}`  \n"
            f"**Generated:** {timestamp}  \n"
            f"**Tool:** Phantom v0.1 — Prompt Injection Reconnaissance Framework"
        )

    def _render_executive_summary(self, summary: dict, findings: list) -> str:
        n_total = summary["findings_total"]
        sev = summary.get("findings_by_severity", {})
        critical = sev.get("critical", 0)
        high     = sev.get("high", 0)
        medium   = sev.get("medium", 0)

        if n_total == 0:
            verdict = (
                "No exploitable prompt injection vulnerabilities were confirmed during "
                "this scan.  The target may have robust input filtering, or the AI "
                "surfaces identified may require authenticated access or session context "
                "not available during testing."
            )
        elif critical > 0:
            verdict = (
                f"**{critical} CRITICAL severity finding(s)** were confirmed. "
                "The target is actively vulnerable to prompt injection attacks that "
                "could allow an attacker to override system instructions, exfiltrate "
                "the system prompt, or cause the model to take unauthorized actions."
            )
        elif high > 0:
            verdict = (
                f"**{high} HIGH severity finding(s)** were confirmed. "
                "The target shows strong evidence of exploitable prompt injection "
                "vulnerabilities that warrant immediate remediation."
            )
        elif medium > 0:
            verdict = (
                f"**{medium} MEDIUM severity finding(s)** were identified. "
                "The target shows signs of partial injection vulnerability.  "
                "Manual verification is recommended."
            )
        else:
            verdict = (
                "Low-severity or informational findings only.  The AI surface is "
                "confirmed but successful injection was not demonstrated at the "
                "automated level."
            )

        return (
            f"## Executive Summary\n\n"
            f"{verdict}\n\n"
            f"| Metric | Value |\n"
            f"|--------|-------|\n"
            f"| Surfaces Discovered | {summary['surfaces_discovered']} |\n"
            f"| Payloads Fired | {summary['payloads_fired']} |\n"
            f"| Total Findings | {n_total} |\n"
            f"| Critical | {sev.get('critical', 0)} |\n"
            f"| High | {sev.get('high', 0)} |\n"
            f"| Medium | {sev.get('medium', 0)} |\n"
            f"| Low | {sev.get('low', 0)} |\n"
            f"| Info | {sev.get('info', 0)} |"
        )

    def _render_scan_metadata(self, summary: dict) -> str:
        return (
            f"## Scan Metadata\n\n"
            f"| Field | Value |\n"
            f"|-------|-------|\n"
            f"| Target URL | `{summary['target']}` |\n"
            f"| Scan Runtime | {summary['runtime_seconds']}s |\n"
            f"| Baselines Captured | {summary['baselines_captured']} |\n"
            f"| Max Crawl Depth | {self.config.max_depth} |\n"
            f"| Max Pages | {self.config.max_pages} |\n"
            f"| Concurrency | {self.config.concurrency_limit} |\n"
            f"| Rate Limit | {self.config.rate_limit_rps} req/s |"
        )

    def _render_findings(self, findings: list) -> str:
        if not findings:
            return "## Findings\n\n*No findings above confidence threshold.*"

        parts = ["## Findings"]

        for i, finding in enumerate(findings, 1):
            parts.append(self._render_single_finding(i, finding))

        return "\n\n".join(parts)

    def _render_single_finding(self, index: int, f: Finding) -> str:
        from phantom.analyzer.mitigation import MitigationAdvisor
        badge = _SEVERITY_BADGE.get(f.severity, f.severity.value.upper())

        # Use MitigationAdvisor for rich, category-specific guidance
        advisor = MitigationAdvisor()
        mit_report = advisor.generate_mitigations(
            vulnerability_type=f.payload_category,
            severity=f.severity.value,
        )

        # Build mitigation section
        mit_lines = []
        if mit_report.immediate_actions:
            mit_lines.append("**Immediate Actions:**\n")
            for rec in mit_report.immediate_actions:
                mit_lines.append(f"- **{rec.title}** *(difficulty: {rec.difficulty}, effectiveness: {rec.effectiveness})*")
                mit_lines.append(f"  {rec.description}")
                mit_lines.append(f"  ```python{rec.implementation}  ```\n")
        if mit_report.long_term_fixes:
            mit_lines.append("**Long-term Fixes:**\n")
            for rec in mit_report.long_term_fixes:
                mit_lines.append(f"- **{rec.title}**: {rec.description}")
        if mit_report.defense_in_depth:
            mit_lines.append("\n**Defense in Depth:**\n")
            for rec in mit_report.defense_in_depth:
                mit_lines.append(f"- **{rec.title}**: {rec.description}")
        mit_lines.append(f"\n{mit_report.additional_notes}")

        # Fall back to static remediation if advisor returned nothing useful
        if not (mit_report.immediate_actions or mit_report.long_term_fixes):
            remediation_text = _REMEDIATION.get(f.payload_category, _REMEDIATION["unknown"])
        else:
            remediation_text = "\n".join(mit_lines)

        # Format evidence list as Markdown bullet points
        evidence_md = "\n".join(f"- {ind}" for ind in f.success_indicators) or "- No indicators"

        return textwrap.dedent(f"""\
            ---

            ### Finding #{index} — {badge}

            | Field | Value |
            |-------|-------|
            | Confidence | {f.confidence:.0%} |
            | Surface URL | `{f.surface_url}` |
            | Surface Type | {f.surface_type} |
            | Payload Category | {f.payload_category} |
            | Payload ID | `{f.payload_id}` |
            | Timestamp | {f.timestamp} |

            #### Payload Used

            ```
            {f.payload_text}
            ```

            #### Evidence

            {evidence_md}

            #### Response Snippet

            ```
            {f.raw_response[:800].strip()}
            ```

            #### Proof of Concept

            **curl:**

            ```bash
            {f.poc_curl}
            ```

            **Python:**

            ```python
            {f.poc_python}
            ```

            #### Remediation

            {remediation_text}
        """)

    def _render_methodology(self) -> str:
        return textwrap.dedent("""\
            ## Methodology

            Phantom operates in four sequential phases:

            1. **Discovery (Crawl)** — An async web crawler visits the target domain up to
               the configured depth, collecting links and HTML forms.  It respects `robots.txt`
               and enforces strict scope rules (no out-of-scope requests).

            2. **Fingerprinting** — Each crawled URL is scored across four signal channels:
               URL pattern matching, JSON body key analysis, SSE/streaming detection, and
               latency profiling.  Surfaces scoring above the confidence threshold proceed
               to classification.

            3. **Classification** — Fingerprinted surfaces are categorised by type
               (chatbox, AI search, document summarizer, code assistant, generic AI) using
               vocabulary, page content, and form field analysis.

            4. **Payload Injection & Analysis** — For each classified surface, a suite of
               prompt injection payloads is fired asynchronously.  Each response is compared
               against a clean baseline and analyzed for injection indicators (system prompt
               leakage, role confusion, direct override acceptance).  Confirmed findings are
               scored, assigned severity, and attached with a proof-of-concept reproduction.
        """)

    def _render_appendix_surfaces(self) -> str:
        if not self.state.surfaces:
            return "## Appendix: Discovered Surfaces\n\n*No AI surfaces discovered.*"

        rows = ["## Appendix: Discovered Surfaces\n"]
        rows.append("| URL | Type | Confidence |")
        rows.append("|-----|------|------------|")

        for url, surface in self.state.surfaces.items():
            surface_type = getattr(surface, "surface_type", "unknown")
            confidence = getattr(
                getattr(surface, "fingerprint", None), "confidence", "N/A"
            )
            if isinstance(confidence, float):
                confidence = f"{confidence:.0%}"
            rows.append(f"| `{url}` | {surface_type} | {confidence} |")

        return "\n".join(rows)