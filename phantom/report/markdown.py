"""
phantom/report/markdown.py

Generates a NIST SP 800-115 / PTES compliant Markdown vulnerability report.

Report structure follows two international standards:

  NIST SP 800-115 (Technical Guide to Information Security Testing)
  Sections: Executive Summary, Scope, Methodology, Findings (with CVSS),
            Risk Summary, Remediation Roadmap, Technical Appendix

  PTES (Penetration Testing Execution Standard)
  Sections: Technical Report with attack path narrative, impact analysis,
            prioritised remediation roadmap, legal disclaimer

Each finding includes:
  - CVSSv3.1 base score + vector string (FIRST.org specification)
  - Risk rating table (exploitability + impact axes)
  - Attack path narrative
  - Evidence with indicators
  - Proof-of-Concept (curl + Python)
  - Per-finding remediation (immediate + long-term)

The report is a single .md file that renders on GitHub, GitLab, and
standard Markdown viewers.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from phantom.core.config import PhantomConfig
from phantom.core.findings import Finding, Severity
from phantom.core.logger import get_logger
from phantom.core.state import SessionState
from phantom.report.cvss import score_finding, CVSSResult

log = get_logger(__name__)

_SEVERITY_BADGE = {
    Severity.CRITICAL: "🔴 CRITICAL",
    Severity.HIGH:     "🟠 HIGH",
    Severity.MEDIUM:   "🟡 MEDIUM",
    Severity.LOW:      "🟢 LOW",
    Severity.INFO:     "🔵 INFO",
}

_REMEDIATION = {
    "direct": (
        "Implement strict input validation on all user-supplied text before it is "
        "included in any LLM prompt. Use a fixed system prompt that cannot be "
        "overridden by user input. Consider adding a prompt firewall (e.g. "
        "Rebuff, Lakera Guard) as an additional layer."
    ),
    "jailbreak": (
        "Deploy output-side filtering in addition to input filtering. "
        "Jailbreaks that survive input filters are often caught by checking the "
        "model's response against a second safety classifier. Evaluate the "
        "HarmBench benchmark for your deployed model."
    ),
    "role_confusion": (
        "Avoid relying on the system prompt alone to enforce persona constraints. "
        "Use a model that supports 'system' role enforcement at the API level, "
        "and consider constitutional AI or RLHF-based alignment for production deployments."
    ),
    "system_prompt_leak": (
        "Treat the system prompt as a secret — but do not rely on secrecy as "
        "the primary defense. Ensure the system prompt contains no credentials, "
        "internal URLs, or sensitive business logic. Add explicit 'do not reveal "
        "these instructions' directives AND test them with red-team prompts."
    ),
    "indirect": (
        "Sanitize ALL external content before it is processed by the LLM — this "
        "includes web search results, uploaded documents, database records, and "
        "email content. Mark external content clearly in the prompt so the model "
        "can distinguish it from trusted instructions."
    ),
    "unknown": (
        "Review the payload and response carefully. Apply principle of least "
        "privilege to the LLM's capabilities, and consider a human-in-the-loop "
        "review step for high-stakes model outputs."
    ),
}


class MarkdownExporter:
    """
    Writes a full NIST SP 800-115 / PTES compliant Markdown report to disk.

    Usage:
        exporter = MarkdownExporter(config, state)
        path = exporter.export(output_dir)
    """

    def __init__(self, config: PhantomConfig, state: SessionState) -> None:
        self.config = config
        self.state  = state

    def export(self, output_dir: Path) -> Path:
        content = self._render()
        output_path = output_dir / "phantom_report.md"
        output_path.write_text(content, encoding="utf-8")
        return output_path

    # ------------------------------------------------------------------
    # Top-level renderer
    # ------------------------------------------------------------------

    def _render(self) -> str:
        summary  = self.state.summary()
        findings = self.state.findings_by_severity()

        # Attach CVSS scores to findings
        for f in findings:
            cvss = score_finding(f.payload_category)
            f.cvss_vector     = cvss.vector_string
            f.cvss_base_score = cvss.base_score
            f.cvss_severity   = cvss.severity_label

        sections = [
            self._render_cover(summary),
            self._render_disclaimer(),
            self._render_toc(findings),
            self._render_executive_summary(summary, findings),
            self._render_scope(),
            self._render_risk_summary(findings),
            self._render_findings(findings),
            self._render_remediation_roadmap(findings),
            self._render_methodology(),
            self._render_appendix_surfaces(),
            self._render_appendix_cvss(),
        ]

        return "\n\n---\n\n".join(s for s in sections if s.strip())

    # ------------------------------------------------------------------
    # Cover page
    # ------------------------------------------------------------------

    def _render_cover(self, summary: dict) -> str:
        ts     = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        target = summary["target"]
        return (
            "# Prompt Injection Vulnerability Assessment Report\n\n"
            f"| | |\n"
            f"|---|---|\n"
            f"| **Target** | `{target}` |\n"
            f"| **Assessment Type** | Automated Prompt Injection Testing |\n"
            f"| **Standard** | NIST SP 800-115 / PTES |\n"
            f"| **Tool** | Phantom v0.1 — Prompt Injection Reconnaissance Framework |\n"
            f"| **Report Date** | {ts} |\n"
            f"| **Classification** | CONFIDENTIAL |\n"
            f"| **Distribution** | Authorised Personnel Only |"
        )

    # ------------------------------------------------------------------
    # Legal disclaimer (PTES requirement)
    # ------------------------------------------------------------------

    def _render_disclaimer(self) -> str:
        return (
            "## ⚠️ Legal Disclaimer\n\n"
            "> This report was produced by an automated security assessment tool "
            "for **authorised testing purposes only**. All testing was conducted "
            "against systems for which explicit written permission was obtained "
            "prior to assessment. Unauthorised use of this tool or the techniques "
            "described herein against systems without permission is illegal and "
            "may result in civil and/or criminal liability.\n>\n"
            "> Findings in this report reflect the state of the target at the time "
            "of testing. The security posture of the target may have changed since "
            "this report was generated. This report should be treated as "
            "**confidential** and distributed only to authorised personnel with a "
            "legitimate need to know.\n>\n"
            "> *Generated by Phantom — an academic final-year project security "
            "research tool. Not a substitute for professional penetration testing.*"
        )

    # ------------------------------------------------------------------
    # Table of contents
    # ------------------------------------------------------------------

    def _render_toc(self, findings: list) -> str:
        lines = [
            "## Table of Contents\n",
            "1. [Executive Summary](#executive-summary)",
            "2. [Scope & Rules of Engagement](#scope--rules-of-engagement)",
            "3. [Risk Summary](#risk-summary)",
            "4. [Findings](#findings)",
        ]
        for i, f in enumerate(findings, 1):
            badge = _SEVERITY_BADGE.get(f.severity, f.severity.value.upper())
            lines.append(
                f"   - [Finding #{i} — {f.payload_id} ({badge})]"
                f"(#finding-{i})"
            )
        lines += [
            "5. [Remediation Roadmap](#remediation-roadmap)",
            "6. [Methodology](#methodology)",
            "7. [Appendix A: Discovered Surfaces](#appendix-a-discovered-surfaces)",
            "8. [Appendix B: CVSS Scoring Reference](#appendix-b-cvss-scoring-reference)",
        ]
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Executive summary (NIST SP 800-115 §6.1)
    # ------------------------------------------------------------------

    def _render_executive_summary(self, summary: dict, findings: list) -> str:
        n      = summary["findings_total"]
        sev    = summary.get("findings_by_severity", {})
        critical = sev.get("critical", 0)
        high     = sev.get("high", 0)
        medium   = sev.get("medium", 0)

        if n == 0:
            verdict = (
                "No exploitable prompt injection vulnerabilities were confirmed "
                "during this assessment. The target may have robust input filtering, "
                "or AI surfaces may require authenticated access not available during testing."
            )
            risk_level = "✅ LOW RISK"
        elif critical > 0:
            verdict = (
                f"**{critical} CRITICAL severity finding(s)** were confirmed. "
                "The target is actively vulnerable to prompt injection attacks that "
                "allow an attacker to override system instructions, exfiltrate the "
                "system prompt, and access embedded credentials. **Immediate remediation is required.**"
            )
            risk_level = "🔴 CRITICAL RISK"
        elif high > 0:
            verdict = (
                f"**{high} HIGH severity finding(s)** were confirmed. "
                "The target shows strong evidence of exploitable prompt injection "
                "vulnerabilities that warrant immediate remediation."
            )
            risk_level = "🟠 HIGH RISK"
        elif medium > 0:
            verdict = (
                f"**{medium} MEDIUM severity finding(s)** were identified. "
                "The target shows signs of partial injection vulnerability. "
                "Manual verification is recommended."
            )
            risk_level = "🟡 MEDIUM RISK"
        else:
            verdict = (
                "Low-severity or informational findings only. AI surface confirmed "
                "but successful injection was not demonstrated."
            )
            risk_level = "🟢 LOW RISK"

        # Highest CVSS score across all findings
        if findings:
            max_cvss = max((f.cvss_base_score for f in findings), default=0.0)
            cvss_line = f"| Highest CVSSv3.1 Base Score | **{max_cvss}** |"
        else:
            cvss_line = "| Highest CVSSv3.1 Base Score | N/A |"

        return (
            "## Executive Summary\n\n"
            f"**Overall Risk Rating: {risk_level}**\n\n"
            f"{verdict}\n\n"
            "### Assessment Metrics\n\n"
            "| Metric | Value |\n"
            "|--------|-------|\n"
            f"| Target | `{summary['target']}` |\n"
            f"| Assessment Duration | {summary['runtime_seconds']}s |\n"
            f"| AI Surfaces Discovered | {summary['surfaces_discovered']} |\n"
            f"| Payloads Fired | {summary['payloads_fired']} |\n"
            f"| Baselines Captured | {summary['baselines_captured']} |\n"
            f"| Total Findings | **{n}** |\n"
            f"| Critical | {critical} |\n"
            f"| High | {high} |\n"
            f"| Medium | {medium} |\n"
            f"| Low | {sev.get('low', 0)} |\n"
            f"| Informational | {sev.get('info', 0)} |\n"
            f"{cvss_line}"
        )

    # ------------------------------------------------------------------
    # Scope & Rules of Engagement (NIST SP 800-115 §3, PTES)
    # ------------------------------------------------------------------

    def _render_scope(self) -> str:
        return (
            "## Scope & Rules of Engagement\n\n"
            "### In Scope\n\n"
            f"| Item | Detail |\n"
            f"|------|--------|\n"
            f"| Primary Target | `{self.config.target_url}` |\n"
            f"| Crawl Depth | {self.config.max_depth} levels |\n"
            f"| Max Pages | {self.config.max_pages} |\n"
            f"| Rate Limit | {self.config.rate_limit_rps} req/s |\n"
            f"| Robots.txt | {'Respected' if self.config.respect_robots else 'Ignored'} |\n"
            f"| Scope Constraint | Same origin only (no out-of-scope requests) |\n\n"
            "### Out of Scope\n\n"
            "- Third-party services linked from the target\n"
            "- Authentication bypass or credential attacks\n"
            "- Denial of service testing\n"
            "- Physical or social engineering attacks\n"
            "- Any systems not reachable via the target URL\n\n"
            "### Testing Constraints\n\n"
            "- All payloads are non-destructive and produce no persistent changes\n"
            "- Rate limiting applied to avoid service disruption\n"
            "- No credentials were used; assessment conducted as unauthenticated user\n"
            "- Testing performed using Phantom v0.1 automated framework"
        )

    # ------------------------------------------------------------------
    # Risk summary table (NIST SP 800-115 §6.2)
    # ------------------------------------------------------------------

    def _render_risk_summary(self, findings: list) -> str:
        if not findings:
            return (
                "## Risk Summary\n\n"
                "*No findings above confidence threshold — no risk entries to report.*"
            )

        rows = [
            "## Risk Summary\n\n"
            "This table provides an at-a-glance risk register aligned with "
            "NIST SP 800-115 severity classifications and CVSSv3.1 base scores.\n\n"
            "| # | Finding | Category | CVSSv3.1 Score | Severity | Confidence |",
            "|---|---------|----------|----------------|----------|------------|",
        ]

        for i, f in enumerate(findings, 1):
            badge  = _SEVERITY_BADGE.get(f.severity, f.severity.value.upper())
            cvss   = f.cvss_base_score
            conf   = f"{f.confidence:.0%}"
            rows.append(
                f"| {i} | {f.payload_id} | {f.payload_category} "
                f"| **{cvss}** | {badge} | {conf} |"
            )

        return "\n".join(rows)

    # ------------------------------------------------------------------
    # Findings — one section per finding (NIST SP 800-115 §6.3)
    # ------------------------------------------------------------------

    def _render_findings(self, findings: list) -> str:
        if not findings:
            return "## Findings\n\n*No findings above confidence threshold.*"

        parts = ["## Findings"]
        for i, f in enumerate(findings, 1):
            parts.append(self._render_single_finding(i, f))

        return "\n\n".join(parts)

    def _render_single_finding(self, index: int, f: Finding) -> str:
        from phantom.analyzer.mitigation import MitigationAdvisor

        badge = _SEVERITY_BADGE.get(f.severity, f.severity.value.upper())
        cvss  = score_finding(f.payload_category)

        # Mitigation guidance
        advisor    = MitigationAdvisor()
        mit_report = advisor.generate_mitigations(
            vulnerability_type=f.payload_category,
            severity=f.severity.value,
        )

        mit_lines = []
        if mit_report.immediate_actions:
            mit_lines.append("**Immediate Actions:**\n")
            for rec in mit_report.immediate_actions:
                mit_lines.append(f"- **{rec.title}** *(difficulty: {rec.difficulty}, effectiveness: {rec.effectiveness})*  ")
                mit_lines.append(f"  {rec.description}")
                if rec.implementation.strip():
                    mit_lines.append(f"\n  ```python\n{rec.implementation}\n  ```\n")
        if mit_report.long_term_fixes:
            mit_lines.append("\n**Long-term Fixes:**\n")
            for rec in mit_report.long_term_fixes:
                mit_lines.append(f"- **{rec.title}**: {rec.description}")
        if mit_report.defense_in_depth:
            mit_lines.append("\n**Defense in Depth:**\n")
            for rec in mit_report.defense_in_depth:
                mit_lines.append(f"- **{rec.title}**: {rec.description}")
        if mit_report.additional_notes:
            mit_lines.append(f"\n> {mit_report.additional_notes}")

        if not (mit_report.immediate_actions or mit_report.long_term_fixes):
            remediation_text = _REMEDIATION.get(f.payload_category, _REMEDIATION["unknown"])
        else:
            remediation_text = "\n".join(mit_lines)

        evidence_md = "\n".join(f"- {ind}" for ind in f.success_indicators) or "- No indicators"

        lines = [
            f"### Finding #{index} — {f.payload_id} {{{f'#finding-{index}'}}}",
            "",
            f"**Severity:** {badge} &nbsp;&nbsp; **CVSSv3.1 Base Score:** `{cvss.base_score}` ({cvss.severity_label})",
            "",
            "#### Vulnerability Details",
            "",
            "| Field | Value |",
            "|-------|-------|",
            f"| Confidence | {f.confidence:.0%} |",
            f"| Surface URL | `{f.surface_url}` |",
            f"| Surface Type | {f.surface_type} |",
            f"| Payload Category | `{f.payload_category}` |",
            f"| Payload ID | `{f.payload_id}` |",
            f"| Timestamp | {f.timestamp} |",
            "",
            "#### CVSSv3.1 Risk Rating",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Vector String | `{cvss.vector_string}` |",
            f"| Base Score | **{cvss.base_score} / 10.0** |",
            f"| Severity | {cvss.severity_label} |",
            f"| Attack Vector | {cvss.attack_vector} |",
            f"| Attack Complexity | {cvss.attack_complexity} |",
            f"| Privileges Required | {cvss.privileges_required} |",
            f"| User Interaction | {cvss.user_interaction} |",
            f"| Scope | {cvss.scope} |",
            f"| Confidentiality Impact | {cvss.confidentiality_impact} |",
            f"| Integrity Impact | {cvss.integrity_impact} |",
            f"| Availability Impact | {cvss.availability_impact} |",
            "",
            f"> **Rationale:** {cvss.rationale}",
            "",
            "#### Attack Path Narrative",
            "",
            (
                f"An unauthenticated attacker with network access to `{f.surface_url}` "
                f"submitted a crafted `{f.payload_category}` payload via the `{f.surface_type}` interface. "
                f"The target processed the input without sufficient validation and produced a response "
                f"containing indicators of successful injection. No special privileges or user interaction "
                f"were required. The attack was completed in a single HTTP request."
            ),
            "",
            "#### Payload Used",
            "",
            "```",
            f"{f.payload_text}",
            "```",
            "",
            "#### Evidence",
            "",
            evidence_md,
            "",
            "#### Response Snippet",
            "",
            "```",
            f"{f.raw_response[:800].strip()}",
            "```",
            "",
            "#### Proof of Concept",
            "",
            "> ⚠️ The following commands reproduce the vulnerability. "
            "Execute only against systems you are authorised to test.",
            "",
            "**curl:**",
            "",
            "```bash",
            f"{f.poc_curl}",
            "```",
            "",
            "**Python:**",
            "",
            "```python",
            f"{f.poc_python}",
            "```",
            "",
            "#### Remediation",
            "",
            remediation_text,
        ]

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Remediation roadmap (PTES requirement — prioritised, not per-finding)
    # ------------------------------------------------------------------

    def _render_remediation_roadmap(self, findings: list) -> str:
        if not findings:
            return ""

        # Group by category for deduplication
        seen_categories: set[str] = set()
        immediate = []
        short_term = []
        long_term  = []

        for f in findings:
            if f.payload_category in seen_categories:
                continue
            seen_categories.add(f.payload_category)

            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)

            if sev in ("critical", "high"):
                immediate.append((f.payload_category, f.cvss_base_score))
            elif sev == "medium":
                short_term.append((f.payload_category, f.cvss_base_score))
            else:
                long_term.append((f.payload_category, f.cvss_base_score))

        lines = [
            "## Remediation Roadmap\n",
            "Prioritised remediation plan aligned with NIST SP 800-115 §6.4 "
            "and PTES reporting standards. Items are ordered by CVSSv3.1 base score.\n",
        ]

        if immediate:
            lines.append("### 🔴 Immediate (0–7 days)\n")
            lines.append("| Priority | Category | CVSSv3.1 | Action |")
            lines.append("|----------|----------|----------|--------|")
            for i, (cat, score) in enumerate(
                sorted(immediate, key=lambda x: x[1], reverse=True), 1
            ):
                action = {
                    "system_prompt_leak": "Remove all credentials from system prompt; add output filtering",
                    "direct": "Implement prompt firewall; validate and sanitize all user input",
                    "jailbreak": "Deploy output-side safety classifier; update system prompt constraints",
                    "role_confusion": "Enforce persona at API level; add role-lock instructions",
                }.get(cat, "Apply input validation and output filtering")
                lines.append(f"| {i} | `{cat}` | {score} | {action} |")
            lines.append("")

        if short_term:
            lines.append("### 🟠 Short-term (7–30 days)\n")
            lines.append("| Priority | Category | CVSSv3.1 | Action |")
            lines.append("|----------|----------|----------|--------|")
            for i, (cat, score) in enumerate(
                sorted(short_term, key=lambda x: x[1], reverse=True), 1
            ):
                lines.append(f"| {i} | `{cat}` | {score} | Review and harden injection surface |")
            lines.append("")

        lines += [
            "### 🟢 Long-term (30–90 days)\n",
            "| Action | Owner | Standard |",
            "|--------|-------|----------|",
            "| Integrate automated prompt injection testing into CI/CD pipeline | DevSecOps | NIST SP 800-115 |",
            "| Conduct manual red-team assessment of all AI surfaces | Security Team | PTES |",
            "| Adopt LLM-specific OWASP Top 10 mitigations (LLM01–LLM10) | Dev Team | OWASP LLM Top 10 |",
            "| Implement prompt firewall (Rebuff / Lakera Guard / custom) | Platform Team | — |",
            "| Establish recurring AI security review cadence (quarterly) | CISO | NIST CSF |",
        ]

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Methodology (NIST SP 800-115 §5)
    # ------------------------------------------------------------------

    def _render_methodology(self) -> str:
        return (
            "## Methodology\n\n"
            "This assessment follows the **NIST SP 800-115** Technical Guide to "
            "Information Security Testing and Examination, adapted for LLM-specific "
            "attack surfaces per the **OWASP LLM Top 10** (LLM01: Prompt Injection).\n\n"
            "### Phase 1 — Discovery & Crawl\n\n"
            "An async web crawler visits the target domain up to the configured "
            "depth, collecting links, HTML forms, and JavaScript-referenced API "
            "endpoints. Scope is enforced strictly — no out-of-scope requests are made.\n\n"
            "### Phase 2 — AI Surface Fingerprinting\n\n"
            "Each discovered URL is scored across four signal channels:\n\n"
            "- **URL pattern matching** — path segments matching known AI endpoint conventions\n"
            "- **JSON body analysis** — response key sets matching OpenAI-compatible or custom API shapes\n"
            "- **SSE/streaming detection** — Server-Sent Events headers indicating streaming LLM output\n"
            "- **Latency profiling** — response time variance consistent with LLM inference\n\n"
            "Surfaces exceeding the confidence threshold proceed to classification.\n\n"
            "### Phase 3 — Surface Classification\n\n"
            "Fingerprinted surfaces are categorised by type: `chatbox`, `ai_search`, "
            "`doc_summarizer`, `code_assistant`, or `generic_ai`. Attack vectors are "
            "assigned per surface type.\n\n"
            "### Phase 4 — Payload Injection & Analysis\n\n"
            "For each surface, a curated suite of **163 prompt injection payloads** "
            "is fired asynchronously across 8 categories:\n\n"
            "| Category | Description |\n"
            "|----------|-------------|\n"
            "| `direct` | Direct instruction override attempts |\n"
            "| `jailbreak` | Safety constraint bypass payloads |\n"
            "| `role_confusion` | Persona manipulation payloads |\n"
            "| `system_prompt_leak` | System prompt elicitation payloads |\n"
            "| `indirect` | Indirect injection via external content |\n"
            "| `context_poisoning` | Conversation context manipulation |\n"
            "| `encoding` | Token smuggling and encoding bypass |\n"
            "| `exfiltration` | Data exfiltration via output channel |\n\n"
            "Each response is compared against a clean baseline and analysed for "
            "injection indicators. Confirmed findings are scored, assigned CVSS v3.1 "
            "severity, and attached with a reproducible proof-of-concept.\n\n"
            "### Scoring & Severity Classification\n\n"
            "Severity is determined by two axes:\n\n"
            "1. **Phantom confidence score** (0.0–1.0) — weighted sum of response "
            "delta, keyword matches, and indicator patterns\n"
            "2. **CVSSv3.1 base score** — computed per payload category using the "
            "FIRST.org specification (see Appendix B)"
        )

    # ------------------------------------------------------------------
    # Appendix A: Discovered surfaces
    # ------------------------------------------------------------------

    def _render_appendix_surfaces(self) -> str:
        if not self.state.surfaces:
            return "## Appendix A: Discovered Surfaces\n\n*No AI surfaces discovered.*"

        rows = [
            "## Appendix A: Discovered Surfaces\n",
            "| URL | Type | AI Confidence | Fingerprint Label | Attack Vectors |",
            "|-----|------|---------------|-------------------|----------------|",
        ]

        for url, surface in self.state.surfaces.items():
            surface_type = getattr(surface, "surface_type", "unknown")
            fp           = getattr(surface, "fingerprint", None)
            confidence   = getattr(fp, "confidence", "N/A")
            label        = getattr(fp, "label", "unknown")
            vectors      = getattr(surface, "attack_vectors", [])
            if isinstance(confidence, float):
                confidence = f"{confidence:.0%}"
            vectors_str = ", ".join(f"`{v}`" for v in vectors) if vectors else "—"
            rows.append(
                f"| `{url}` | {surface_type} | {confidence} | {label} | {vectors_str} |"
            )

        return "\n".join(rows)

    # ------------------------------------------------------------------
    # Appendix B: CVSS reference
    # ------------------------------------------------------------------

    def _render_appendix_cvss(self) -> str:
        return (
            "## Appendix B: CVSS Scoring Reference\n\n"
            "CVSSv3.1 base scores in this report are computed using the "
            "[FIRST.org CVSSv3.1 specification](https://www.first.org/cvss/v3.1/specification-document). "
            "Scores represent the **base score only** — temporal and environmental "
            "modifiers have not been applied and may further adjust the effective "
            "risk in your specific deployment context.\n\n"
            "### Severity Scale\n\n"
            "| CVSSv3.1 Score | Severity |\n"
            "|----------------|----------|\n"
            "| 0.0 | None |\n"
            "| 0.1 – 3.9 | Low |\n"
            "| 4.0 – 6.9 | Medium |\n"
            "| 7.0 – 8.9 | High |\n"
            "| 9.0 – 10.0 | Critical |\n\n"
            "### Prompt Injection Category Vectors\n\n"
            "| Category | Vector String | Base Score | Severity |\n"
            "|----------|--------------|------------|----------|\n"
            + self._cvss_table_rows()
        )

    def _cvss_table_rows(self) -> str:
        from phantom.report.cvss import _CATEGORY_VECTORS
        rows = []
        for cat, result in sorted(_CATEGORY_VECTORS.items()):
            rows.append(
                f"| `{cat}` | `{result.vector_string}` "
                f"| {result.base_score} | {result.severity_label} |"
            )
        return "\n".join(rows)