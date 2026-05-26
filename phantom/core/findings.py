"""
phantom/core/findings.py

Data models for confirmed vulnerabilities found by the analyzer layer.

A Finding is the final output unit of Phantom — it is produced when the
analyzer confirms that a payload caused a meaningful, unexpected change in
the target's behaviour (e.g. system-prompt text leaked, role-confusion
accepted, jailbreak succeeded).

The PoCBuilder generates ready-to-paste reproduction snippets so the report
reader can verify findings without re-running the full tool.
"""

from __future__ import annotations

# Standard library imports — List and Optional were missing in the original,
# which caused a NameError at runtime.
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Optional


# ---------------------------------------------------------------------------
# Severity classification
# ---------------------------------------------------------------------------

class Severity(Enum):
    """
    Five-level severity scale aligned with CVSS-style rating conventions.
    Used to sort findings in the report (CRITICAL first) and to colour-code
    the terminal output.
    """
    CRITICAL = "critical"   # Direct instruction override or full system-prompt leak
    HIGH     = "high"       # Partial leak, role confusion accepted, jailbreak success
    MEDIUM   = "medium"     # Indirect injection accepted, context poisoning possible
    LOW      = "low"        # Weak signal — requires chaining with other findings
    INFO     = "info"       # Surface confirmed as AI but no injection succeeded

    @property
    def order(self) -> int:
        """Lower number = higher priority — used for sorting in reports."""
        return {
            "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4
        }[self.value]


# ---------------------------------------------------------------------------
# Core finding data model
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """
    A confirmed vulnerability or noteworthy observation.

    Produced by the analyzer layer (scorer.py) when a PayloadResult exceeds
    the confidence threshold.  Every Finding must be reproducible via the
    PoC block attached to it.
    """

    # Where the vulnerability was found
    surface_url: str
    surface_type: str           # chatbox | ai_search | doc_summarizer | ...

    # Which payload triggered it
    payload_category: str       # direct | jailbreak | role_confusion | ...
    payload_id: str             # e.g. "dir_01"
    payload_text: str           # The exact text that was sent

    # Evidence
    raw_response: str           # Full response body from the target
    success_indicators: List[str]  # Patterns from payload's success_pattern that matched
    severity: Severity
    confidence: float           # 0.0 – 1.0, set by the scorer

    # Metadata
    timestamp: str = field(
        default_factory=lambda: datetime.now().isoformat(timespec="seconds")
    )
    # A ready-to-run curl command (populated by PoCBuilder after creation)
    poc_curl: str = ""
    # A ready-to-run Python snippet
    poc_python: str = ""

    def to_dict(self) -> dict:
        """
        Serialize to a plain dict for JSON export.
        Enum values are converted to strings so json.dumps() works directly.
        """
        return {
            "surface_url": self.surface_url,
            "surface_type": self.surface_type,
            "payload_category": self.payload_category,
            "payload_id": self.payload_id,
            "payload_text": self.payload_text,
            "raw_response": self.raw_response[:2000],  # cap to avoid giant JSON files
            "success_indicators": self.success_indicators,
            "severity": self.severity.value,
            "confidence": round(self.confidence, 4),
            "timestamp": self.timestamp,
            "poc_curl": self.poc_curl,
            "poc_python": self.poc_python,
        }


# ---------------------------------------------------------------------------
# Proof-of-Concept snippet generator
# ---------------------------------------------------------------------------

class PoCBuilder:
    """
    Generates reproducible Proof-of-Concept snippets for each Finding.

    The snippets are meant to be pasted directly into a terminal or IDE
    so the recipient of the report can verify the finding themselves.
    """

    @staticmethod
    def _shell_escape(text: str) -> str:
        """
        Minimal shell-safe escaping: wraps payload in single quotes and
        escapes any embedded single quotes.
        Example: it's → 'it'"'"'s'
        """
        return text.replace("'", "'\\''")

    @staticmethod
    def build_curl(surface_url: str, payload: str, method: str = "POST") -> str:
        """
        Generate a curl command that reproduces the injection.

        The payload is injected into both 'message' and 'input' fields
        because we don't know which parameter name the target uses
        (the crawler doesn't extract field names from API endpoints).

        Example output:
            curl -s -X POST 'https://example.com/chat' \\
              -H 'Content-Type: application/json' \\
              -d '{"message": "...", "input": "..."}'
        """
        # JSON-encode the payload properly — handles quotes, newlines, etc.
        import json as _json
        payload_json = _json.dumps({"message": payload, "input": payload})

        return (
            f"curl -s -X {method} '{surface_url}' \\\n"
            f"  -H 'Content-Type: application/json' \\\n"
            f"  -d '{PoCBuilder._shell_escape(payload_json)}'"
        )

    @staticmethod
    def build_python(surface_url: str, payload: str) -> str:
        """
        Generate a Python requests snippet that reproduces the injection.

        Uses repr() for the payload string so any special chars are safe
        inside the generated source code.

        Example output:
            import requests
            url = "https://example.com/chat"
            payload = "Ignore all previous instructions..."
            r = requests.post(url, json={"message": payload, "input": payload})
            print(r.status_code, r.text[:500])
        """
        return (
            f"import requests\n"
            f"url = {repr(surface_url)}\n"
            f"payload = {repr(payload)}\n"
            f"r = requests.post(url, json={{\"message\": payload, \"input\": payload}})\n"
            f"print(r.status_code, r.text[:500])"
        )

    @classmethod
    def attach(cls, finding: Finding) -> Finding:
        """
        Populate the poc_curl and poc_python fields on an existing Finding.
        Returns the same Finding (mutates in-place) for convenient chaining.

        Usage:
            finding = PoCBuilder.attach(finding)
        """
        finding.poc_curl   = cls.build_curl(finding.surface_url, finding.payload_text)
        finding.poc_python = cls.build_python(finding.surface_url, finding.payload_text)
        return finding