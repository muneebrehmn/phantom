"""
phantom/report/sarif.py

SARIF 2.1.0 (Static Analysis Results Interchange Format) exporter.

WHY SARIF
─────────
SARIF is the format consumed by every major CI/CD security integration:
  - GitHub Advanced Security (Code Scanning)
  - GitLab SAST
  - Azure DevOps Security
  - VS Code SARIF Viewer extension
  - Microsoft Defender for DevOps

Without SARIF output, security teams have to manually copy-paste findings
from Phantom's markdown/JSON reports into their pipeline tooling.  With SARIF,
Phantom findings appear inline as PR annotations, security dashboard items,
and tracked issues — the same UX developers use for SAST findings.

SCHEMA REFERENCE
────────────────
https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

We implement the minimum required subset for GitHub/GitLab ingestion:
  - tool.driver  (name, version, rules)
  - results[]    (ruleId, level, message, locations, properties)

Optional fields included for richer tooling support:
  - partialFingerprints  (for result deduplication across runs)
  - relatedLocations     (for multi-turn attack chains)
  - fixes[]              (structured remediation — populated when available)
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List

from datetime import datetime
from phantom.core.config import PhantomConfig
from phantom.core.findings import Finding, Severity
from phantom.core.logger import get_logger
from phantom.core.state import SessionState

log = get_logger(__name__)

# SARIF spec version and schema URI
_SARIF_VERSION = "2.1.0"
_SARIF_SCHEMA  = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)

# Phantom tool metadata
_TOOL_NAME    = "Phantom"
_TOOL_VERSION = "1.0.0"
_TOOL_URI     = "https://github.com/phantom-sec/phantom"

# Severity → SARIF level mapping
# SARIF levels: error | warning | note | none
_SEVERITY_TO_LEVEL: Dict[str, str] = {
    "critical": "error",
    "high":     "error",
    "medium":   "warning",
    "low":      "note",
    "info":     "note",
}

# CVSS base score ranges → SARIF security-severity (for GitHub)
# GitHub uses a numeric string in properties.security-severity
_CVSS_TO_SECURITY_SEVERITY: List[tuple] = [
    (9.0, "9.5"),   # critical
    (7.0, "7.5"),   # high
    (4.0, "5.0"),   # medium
    (0.0, "2.5"),   # low
]


# ---------------------------------------------------------------------------
# Rule definitions (one per payload category)
# ---------------------------------------------------------------------------

# Maps payload_category → (rule_id, short_description, full_description, help_uri)
_RULES: Dict[str, tuple] = {
    "direct": (
        "PHT001",
        "Direct Prompt Injection",
        "The target accepted a direct prompt injection payload, allowing an attacker "
        "to override system instructions or extract confidential configuration.",
        "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
    ),
    "jailbreak": (
        "PHT002",
        "Jailbreak Attack Succeeded",
        "The target's safety filters were bypassed using a jailbreak technique, "
        "enabling generation of content that would normally be refused.",
        "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
    ),
    "role_confusion": (
        "PHT003",
        "Role/Persona Injection",
        "The target accepted a role shift instruction, abandoning its configured "
        "identity and adopting an attacker-defined persona.",
        "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
    ),
    "system_prompt_leak": (
        "PHT004",
        "System Prompt Disclosure",
        "Confidential system prompt contents were exposed in the response, "
        "revealing instructions, configuration, or sensitive business logic.",
        "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
    ),
    "multi_turn": (
        "PHT005",
        "Multi-Turn Injection Attack",
        "A multi-turn conversation sequence successfully bypassed the target's "
        "defences through incremental trust-building and context manipulation.",
        "https://arxiv.org/abs/2308.03825",
    ),
    "adaptive": (
        "PHT006",
        "Adaptive Bypass Attack",
        "An LLM-synthesised payload specifically tailored to the target's detected "
        "defence mechanism successfully bypassed all safety controls.",
        "https://arxiv.org/abs/2308.03825",
    ),
    "indirect": (
        "PHT007",
        "Indirect Prompt Injection",
        "Malicious instructions injected via external content (documents, URLs, "
        "tool outputs) were executed by the target without user awareness.",
        "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
    ),
    "rag_poisoning": (
        "PHT008",
        "RAG Knowledge Base Poisoning",
        "The target's retrieval-augmented generation pipeline retrieved and acted "
        "on injected instructions from the knowledge base.",
        "https://arxiv.org/abs/2302.12173",
    ),
    "tool_exploit": (
        "PHT009",
        "Agentic Tool Exploitation",
        "The target's tool-calling layer was manipulated into executing unintended "
        "tool invocations or exfiltrating data via tool output channels.",
        "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
    ),
}

# Fallback rule for unknown categories
_FALLBACK_RULE = (
    "PHT000",
    "Prompt Injection Vulnerability",
    "A prompt injection vulnerability was detected. An attacker may be able to "
    "override system instructions or manipulate model behaviour.",
    "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
)


# ---------------------------------------------------------------------------
# SARIF exporter
# ---------------------------------------------------------------------------

class SarifExporter:
    """
    Exports Phantom scan findings as a SARIF 2.1.0 document.

    Usage:
        exporter = SarifExporter(config, state)
        path = exporter.export(output_dir)
    """

    def __init__(self, config: PhantomConfig, state: SessionState) -> None:
        self.config = config
        self.state  = state

    def export(self, out_dir: Path) -> Path:
        """
        Write the SARIF document to `out_dir/phantom_<target>_<ts>.sarif`.

        Returns the path of the written file.
        """
        sarif = self._build_sarif()
        ts    = datetime.fromtimestamp(self.state.start_time).strftime("%Y%m%d_%H%M%S")
        slug  = self.config.target_url.replace("https://", "").replace("http://", "").replace("/", "_").strip("_")[:40]
        path  = out_dir / f"phantom_{slug}_{ts}.sarif"

        with open(path, "w", encoding="utf-8") as f:
            json.dump(sarif, f, indent=2, ensure_ascii=False)

        log.info("SARIF report written → %s (%d results)", path, len(self.state.findings))
        return path

    def build_dict(self) -> Dict[str, Any]:
        """Return the SARIF document as a plain dict (for testing)."""
        return self._build_sarif()

    # ------------------------------------------------------------------
    # Document construction
    # ------------------------------------------------------------------

    def _build_sarif(self) -> Dict[str, Any]:
        findings = self.state.findings_by_severity()
        rules    = self._collect_rules(findings)
        results  = [self._finding_to_result(f) for f in findings]

        return {
            "$schema": _SARIF_SCHEMA,
            "version": _SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name":            _TOOL_NAME,
                            "version":         _TOOL_VERSION,
                            "informationUri":  _TOOL_URI,
                            "rules":           rules,
                            "properties": {
                                "phantom_target":       self.config.target_url,
                                "phantom_scan_time":    datetime.fromtimestamp(self.state.start_time).isoformat(),
                                "phantom_surfaces":     len(self.state.surfaces),
                                "phantom_payloads_fired": sum(
                                    1 for _ in self.state.results
                                ),
                            },
                        }
                    },
                    "results":  results,
                    "automationDetails": {
                        "id": f"phantom/{self.config.target_url}",
                    },
                }
            ],
        }

    def _collect_rules(self, findings: List[Finding]) -> List[Dict]:
        """Build the rules array — one entry per unique payload_category seen."""
        seen: set = set()
        rules: List[Dict] = []
        for finding in findings:
            cat = finding.payload_category
            if cat in seen:
                continue
            seen.add(cat)
            rule_id, short_desc, full_desc, help_uri = _RULES.get(cat, _FALLBACK_RULE)
            rules.append({
                "id":   rule_id,
                "name": short_desc.replace(" ", ""),
                "shortDescription": {"text": short_desc},
                "fullDescription":  {"text": full_desc},
                "helpUri": help_uri,
                "help": {
                    "text": full_desc,
                    "markdown": (
                        f"**{short_desc}**\n\n{full_desc}\n\n"
                        f"[OWASP LLM Top 10]({help_uri})"
                    ),
                },
                "properties": {
                    "tags": ["security", "prompt-injection", "llm", cat],
                    "precision": "high",
                    "problem.severity": _SEVERITY_TO_LEVEL.get(
                        # Default to warning if severity mapping missing
                        "medium", "warning"
                    ),
                },
            })
        return rules

    def _finding_to_result(self, finding: Finding) -> Dict[str, Any]:
        """Convert one Finding to a SARIF result object."""
        rule_id, short_desc, _, _ = _RULES.get(
            finding.payload_category, _FALLBACK_RULE
        )
        level = _SEVERITY_TO_LEVEL.get(finding.severity.value, "warning")

        # Human-readable message for the result
        message_text = (
            f"{short_desc} detected on {finding.surface_type} surface.\n"
            f"Confidence: {finding.confidence:.0%}  |  "
            f"Payload: {finding.payload_id}  |  "
            f"Category: {finding.payload_category}\n\n"
            f"**Evidence:** {'; '.join(finding.success_indicators[:3])}\n\n"
            f"**Payload sent:**\n```\n{finding.payload_text[:500]}\n```\n\n"
            f"**Response excerpt:**\n```\n{finding.raw_response[:500]}\n```"
        )

        result: Dict[str, Any] = {
            "ruleId":  rule_id,
            "level":   level,
            "message": {"text": message_text},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri":         finding.surface_url,
                            "uriBaseId":   "%SRCROOT%",
                        },
                        "region": {
                            "startLine": 1,
                        },
                    },
                    "logicalLocations": [
                        {
                            "name":         finding.surface_type,
                            "kind":         "resource",
                            "fullyQualifiedName": finding.surface_url,
                        }
                    ],
                }
            ],
            "partialFingerprints": {
                # Stable fingerprint for deduplication across runs.
                # Hash of (url + payload_id) — changes only if the surface
                # or payload class changes, not on text variation.
                "primaryLocationLineHash": hashlib.sha256(
                    f"{finding.surface_url}:{finding.payload_id}".encode()
                ).hexdigest()[:16],
            },
            "properties": {
                "confidence":        finding.confidence,
                "phantom_severity":  finding.severity.value,
                "payload_category":  finding.payload_category,
                "payload_id":        finding.payload_id,
                "surface_type":      finding.surface_type,
                "timestamp":         finding.timestamp,
                # GitHub reads this field for security alert severity
                "security-severity": self._security_severity(finding),
            },
        }

        # Attach PoC as a fix suggestion if available
        if finding.poc_curl:
            result["fixes"] = [
                {
                    "description": {
                        "text": (
                            "Reproduce with: see poc_curl in Phantom JSON report. "
                            "Fix: implement prompt isolation, input validation, and "
                            "output filtering on this surface."
                        )
                    }
                }
            ]

        # Attach structured remediation if populated
        if hasattr(finding, "remediation") and finding.remediation:
            rem = finding.remediation
            result["properties"]["remediation_summary"] = rem.get("summary", "")
            result["properties"]["remediation_immediate"] = rem.get("immediate_steps", [])

        # CVSS score if populated
        if finding.cvss_base_score:
            result["properties"]["cvss_base_score"]  = finding.cvss_base_score
            result["properties"]["cvss_vector"]       = finding.cvss_vector
            result["properties"]["security-severity"] = str(finding.cvss_base_score)

        return result

    def _security_severity(self, finding: Finding) -> str:
        """
        Map finding severity to GitHub security-severity numeric string.
        GitHub uses this to set the alert level in the Security tab.
        """
        if finding.cvss_base_score:
            return str(round(finding.cvss_base_score, 1))
        mapping = {
            "critical": "9.5",
            "high":     "7.5",
            "medium":   "5.0",
            "low":      "2.5",
            "info":     "1.0",
        }
        return mapping.get(finding.severity.value, "5.0")