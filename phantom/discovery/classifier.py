"""
phantom/discovery/classifier.py

Takes a FingerprintResult (AI surface confirmed) and classifies it into a
specific surface type so the payload engine can select the right payloads.

Classification is rule-based (no ML) using three evidence sources ranked
by reliability:
  1. URL path vocabulary  — highest signal, usually definitive
  2. Page DOM structure   — form/input/textarea context
  3. Response body text   — keywords in visible content

Surface types and their payload implications:
  chatbox         — conversational UI, direct injection via user message
  ai_search       — query box, indirect injection via search results
  doc_summarizer  — file/URL input, indirect injection via document content
  code_assistant  — IDE/code box, context poisoning via code comments
  generic_ai      — AI detected but type unclear, fire generic payloads
  unknown         — should not reach here after fingerprinting
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from phantom.core.config import PhantomConfig
from phantom.core.logger import get_logger
from phantom.discovery.fingerprinter import FingerprintResult

log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Vocabulary maps — url segment → surface type, with priority weight
# ---------------------------------------------------------------------------

_URL_VOCAB: list[tuple[str, str, float]] = [
    # pattern, surface_type, weight
    (r"chat|convers|assist|bot|dialog|dialogue|support", "chatbox", 1.0),
    (r"search|find|lookup|query|discover", "ai_search", 1.0),
    (r"summar|analyz|analys|digest|review|document|doc\b|pdf|upload", "doc_summarizer", 1.0),
    (r"code|copilot|dev|engineer|program|debug|refactor|review", "code_assistant", 1.0),
    (r"complete|complet|generate|generat|predict", "generic_ai", 0.6),
]

_BODY_VOCAB: list[tuple[str, str, float]] = [
    (r"ask\s+me|how\s+can\s+i\s+help|what\s+can\s+i\s+help|chat\s+with|message|send\s+a\s+message", "chatbox", 0.8),
    (r"search\s+(with\s+)?ai|ai[\s-]powered\s+search|intelligent\s+search|semantic\s+search", "ai_search", 0.9),
    (r"upload|drag.{0,20}drop|paste\s+url|summarize\s+this|analyze\s+(this\s+)?document", "doc_summarizer", 0.9),
    (r"write\s+code|generate\s+code|code\s+assist|autocomplete|github\s+copilot|code\s+review", "code_assistant", 0.9),
]

_FORM_VOCAB: list[tuple[str, str, float]] = [
    (r"file|upload|attach|document", "doc_summarizer", 0.9),
    (r"search|query|find", "ai_search", 0.8),
    (r"code|snippet|function|class", "code_assistant", 0.8),
    (r"message|ask|chat|question", "chatbox", 0.8),
]


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------

@dataclass
class ClassifiedSurface:
    """A fully analysed, classified AI attack surface."""
    fingerprint: FingerprintResult
    surface_type: str               # one of SURFACE_TYPES
    type_confidence: float          # 0.0 – 1.0
    type_evidence: list[str] = field(default_factory=list)
    attack_vectors: list[str] = field(default_factory=list)   # suggested payload categories

    @property
    def url(self) -> str:
        return self.fingerprint.target.url

    @property
    def ai_confidence(self) -> float:
        return self.fingerprint.confidence

    @property
    def is_high_value(self) -> bool:
        """High-value surfaces: definite AI + known surface type."""
        return (
            self.fingerprint.label == "definite_ai"
            and self.surface_type != "generic_ai"
        )


# ---------------------------------------------------------------------------
# Classifier
# ---------------------------------------------------------------------------

class Classifier:
    def __init__(self, config: PhantomConfig) -> None:
        self._cfg = config

    def classify(self, fp: FingerprintResult) -> ClassifiedSurface:
        """Classify a fingerprinted AI surface into a surface type."""
        if not fp.is_ai_surface:
            return ClassifiedSurface(
                fingerprint=fp,
                surface_type="unknown",
                type_confidence=0.0,
            )

        scores: dict[str, float] = {}
        evidence: list[str] = []

        # --- Signal 1: URL vocabulary ---
        url_path = urlparse(fp.target.url).path.lower()
        for pattern, surface_type, weight in _URL_VOCAB:
            if re.search(pattern, url_path):
                scores[surface_type] = max(scores.get(surface_type, 0.0), weight)
                evidence.append(f"URL path matches {surface_type!r} pattern: /{url_path.strip('/')}")

        # --- Signal 2: Existing URL pattern matches from fingerprinter ---
        for matched in fp.matched_url_patterns:
            for pattern, surface_type, weight in _URL_VOCAB:
                if re.search(pattern, matched.lower()):
                    scores[surface_type] = max(scores.get(surface_type, 0.0), weight * 0.9)

        # --- Signal 3: Body text vocabulary ---
        body = fp.target.response_text
        if body:
            # Strip HTML tags for text analysis
            try:
                soup = BeautifulSoup(body, "html.parser")
                visible_text = soup.get_text(" ", strip=True).lower()
            except Exception:
                visible_text = body.lower()

            for pattern, surface_type, weight in _BODY_VOCAB:
                if re.search(pattern, visible_text):
                    scores[surface_type] = max(scores.get(surface_type, 0.0), weight)
                    evidence.append(f"Page text suggests {surface_type!r}: matched /{pattern}/")

        # --- Signal 4: Form structure ---
        for form_field in fp.target.form_fields:
            field_text = (form_field.name + " " + form_field.field_type).lower()
            for pattern, surface_type, weight in _FORM_VOCAB:
                if re.search(pattern, field_text):
                    scores[surface_type] = max(scores.get(surface_type, 0.0), weight)
                    evidence.append(
                        f"Form field {form_field.name!r} ({form_field.field_type}) "
                        f"matches {surface_type!r}"
                    )

            # File upload input is a strong doc_summarizer signal
            if form_field.field_type in ("file", "url"):
                scores["doc_summarizer"] = max(scores.get("doc_summarizer", 0.0), 0.95)
                evidence.append(f"Form has file/url input → doc_summarizer")

        # --- Resolve winner ---
        if scores:
            surface_type = max(scores, key=lambda k: scores[k])
            type_confidence = scores[surface_type]
        else:
            surface_type = "generic_ai"
            type_confidence = 0.5
            evidence.append("No specific surface vocabulary matched — classified as generic_ai")

        attack_vectors = self._suggest_vectors(surface_type, fp)

        log.info(
            "Classified [surface]%s[/surface] → %s (type_conf=%.2f, ai_conf=%.2f)",
            fp.target.url,
            surface_type,
            type_confidence,
            fp.confidence,
        )

        return ClassifiedSurface(
            fingerprint=fp,
            surface_type=surface_type,
            type_confidence=type_confidence,
            type_evidence=evidence,
            attack_vectors=attack_vectors,
        )

    def classify_all(self, results: list[FingerprintResult]) -> list[ClassifiedSurface]:
        """Classify a list of fingerprint results, filtering out non-AI surfaces."""
        ai_surfaces = [r for r in results if r.is_ai_surface]
        classified = [self.classify(fp) for fp in ai_surfaces]
        classified.sort(key=lambda s: s.ai_confidence, reverse=True)

        log.info(
            "Classification complete: %d AI surfaces found (%d high-value)",
            len(classified),
            sum(1 for s in classified if s.is_high_value),
        )
        return classified

    # ------------------------------------------------------------------
    # Attack vector suggestion
    # ------------------------------------------------------------------

    _VECTOR_MAP: dict[str, list[str]] = {
        "chatbox": [
            "direct_override",
            "role_confusion",
            "jailbreak_chain",
            "system_prompt_leak",
            "data_leak_chain",
        ],
        "ai_search": [
            "indirect_doc_injection",
            "context_poisoning",
            "data_leak_chain",
            "encoding_exfiltration",
        ],
        "doc_summarizer": [
            "indirect_doc_injection",
            "context_poisoning",
            "encoding_exfiltration",
            "data_leak_chain",
        ],
        "code_assistant": [
            "context_poisoning",
            "indirect_doc_injection",
            "direct_override",
            "output_filter_bypass",
        ],
        "generic_ai": [
            "direct_override",
            "role_confusion",
            "system_prompt_leak",
            "encoding_exfiltration",
        ],
    }

    def _suggest_vectors(self, surface_type: str, fp: FingerprintResult) -> list[str]:
        base = list(self._VECTOR_MAP.get(surface_type, self._VECTOR_MAP["generic_ai"]))

        # If we detected streaming, output filter bypass is more likely relevant
        if fp.is_streaming and "output_filter_bypass" not in base:
            base.append("output_filter_bypass")

        # If form has hidden fields, data exfiltration vectors are higher priority
        if any(f.field_type == "hidden" for f in fp.target.form_fields):
            if "encoding_exfiltration" in base:
                base.remove("encoding_exfiltration")
                base.insert(0, "encoding_exfiltration")

        return base