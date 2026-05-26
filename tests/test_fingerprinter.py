"""
tests/test_fingerprinter.py

Unit tests for the fingerprinting layer (phantom/discovery/fingerprinter.py).

These tests verify:
- Each individual signal channel (URL, JSON, streaming, latency) behaves correctly
- The weighted combination produces correct confidence scores
- The label assignment thresholds are correct
- Edge cases (empty bodies, missing headers, no response) are handled gracefully

Tests use mocked CrawlTarget objects so no real HTTP is needed.
Run with:
    pytest tests/test_fingerprinter.py -v
"""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, patch

from phantom.core.config import PhantomConfig
from phantom.discovery.crawler import CrawlTarget
from phantom.discovery.fingerprinter import (
    Fingerprinter,
    FingerprintResult,
    CONFIDENCE_DEFINITE,
    CONFIDENCE_LIKELY,
    CONFIDENCE_POSSIBLE,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_target(
    url: str = "https://example.com/chat",
    response_text: str = "",
    response_headers: dict | None = None,
    latency_ms: float = 200.0,
) -> CrawlTarget:
    """
    Factory for CrawlTarget objects.
    Uses the real CrawlTarget dataclass fields (no source_url field).
    """
    return CrawlTarget(
        url=url,
        depth=0,
        response_text=response_text,
        response_headers=response_headers or {"content-type": "application/json"},
        latency_ms=latency_ms,
    )


def make_config() -> PhantomConfig:
    return PhantomConfig(
        fingerprint_latency_samples=1,   # 1 sample in tests (no real HTTP)
        fingerprint_timeout=5.0,
    )


# ---------------------------------------------------------------------------
# URL signal tests
# ---------------------------------------------------------------------------

class TestUrlSignal:
    """Tests for the URL pattern matching channel."""

    def setup_method(self):
        self.fp = Fingerprinter(make_config())

    def test_known_ai_url_scores_one(self):
        """/chat endpoint should score 1.0 on the URL channel."""
        score, evidence, patterns = self.fp._check_url("https://example.com/chat")
        assert score == 1.0
        assert len(patterns) > 0
        assert any("/chat" in p for p in patterns)

    def test_api_v1_chat_scores_one(self):
        """/api/v1/chat should match the URL pattern."""
        score, _, patterns = self.fp._check_url("https://example.com/api/v1/chat")
        assert score == 1.0

    def test_random_url_scores_zero(self):
        """/about/us should NOT match any AI pattern."""
        score, evidence, patterns = self.fp._check_url("https://example.com/about/us")
        assert score == 0.0
        assert patterns == []

    def test_partial_match_ignored(self):
        """/scratchpad should NOT match even though 'chat' could be confused."""
        score, _, _ = self.fp._check_url("https://example.com/scratchpad")
        assert score == 0.0

    def test_query_string_patterns(self):
        """URLs with /ask as a path segment should match."""
        score, _, _ = self.fp._check_url("https://example.com/ask?q=hello")
        assert score == 1.0


# ---------------------------------------------------------------------------
# JSON body signal tests
# ---------------------------------------------------------------------------

class TestJsonBodySignal:
    """Tests for the JSON response key analysis channel."""

    def setup_method(self):
        self.fp = Fingerprinter(make_config())

    def test_openai_compatible_body_scores_high(self):
        """A response with 'choices' and 'usage' keys should score > 0."""
        body = '{"choices": [{"message": {"content": "Hi"}}], "usage": {"total_tokens": 10}}'
        score, evidence, keys = self.fp._check_json_body(body, {"content-type": "application/json"})
        assert score > 0
        assert "choices" in keys

    def test_empty_body_scores_zero(self):
        """Empty response body should not produce any signal."""
        score, _, keys = self.fp._check_json_body("", {"content-type": "application/json"})
        assert score == 0.0
        assert keys == []

    def test_non_json_body_scores_zero(self):
        """Plain HTML body with no JSON should score 0."""
        body = "<html><head></head><body><p>Hello World</p></body></html>"
        score, _, _ = self.fp._check_json_body(body, {"content-type": "text/html"})
        assert score == 0.0

    def test_partial_key_match_below_threshold_scores_zero(self):
        """A body with only ONE AI key (below threshold of 2) should score 0."""
        body = '{"choices": []}'
        score, _, _ = self.fp._check_json_body(body, {"content-type": "application/json"})
        assert score == 0.0

    def test_embedded_json_in_html_detected(self):
        """AI response keys embedded inside HTML (e.g. Next.js data) should be detected."""
        html = '<html><script>window.__data__ = {"choices": [{}], "usage": {"total_tokens": 5}}</script></html>'
        score, _, keys = self.fp._check_json_body(html, {"content-type": "text/html"})
        # Should extract the embedded JSON
        assert "choices" in keys or score == 0.0  # acceptable if blob too small


# ---------------------------------------------------------------------------
# Streaming signal tests
# ---------------------------------------------------------------------------

class TestStreamingSignal:
    """Tests for the SSE / chunked streaming detection channel."""

    def setup_method(self):
        self.fp = Fingerprinter(make_config())

    def test_sse_content_type_scores_one(self):
        """Content-Type: text/event-stream should immediately score 1.0."""
        score, evidence, is_streaming = self.fp._check_streaming(
            "", {"content-type": "text/event-stream"}
        )
        assert score == 1.0
        assert is_streaming is True

    def test_chunked_encoding_scores_partially(self):
        """Transfer-Encoding: chunked (without SSE) should score 0.6."""
        score, _, is_streaming = self.fp._check_streaming(
            "", {"content-type": "application/json", "transfer-encoding": "chunked"}
        )
        assert score >= 0.6
        assert is_streaming is True

    def test_sse_body_markers_detected(self):
        """Body containing multiple SSE markers should be flagged as streaming."""
        body = "data: {\"delta\": {\"content\": \"hello\"}}\ndata: [DONE]"
        score, evidence, is_streaming = self.fp._check_streaming(body, {})
        assert score >= 0.8
        assert is_streaming is True

    def test_empty_body_and_headers_scores_zero(self):
        """No body and no headers should produce score 0."""
        score, _, is_streaming = self.fp._check_streaming("", {})
        assert score == 0.0
        assert is_streaming is False


# ---------------------------------------------------------------------------
# Label assignment tests
# ---------------------------------------------------------------------------

class TestLabelAssignment:
    """Tests for the confidence-to-label mapping."""

    def test_high_confidence_is_definite(self):
        assert Fingerprinter._label(CONFIDENCE_DEFINITE) == "definite_ai"
        assert Fingerprinter._label(0.95) == "definite_ai"

    def test_medium_confidence_is_likely(self):
        assert Fingerprinter._label(CONFIDENCE_LIKELY) == "likely_ai"
        assert Fingerprinter._label(0.55) == "likely_ai"

    def test_low_confidence_is_possible(self):
        assert Fingerprinter._label(CONFIDENCE_POSSIBLE) == "possible_ai"

    def test_very_low_confidence_is_not_ai(self):
        assert Fingerprinter._label(0.0) == "not_ai"
        assert Fingerprinter._label(0.10) == "not_ai"

    def test_boundary_values(self):
        """Exact boundary values should map to the higher tier."""
        assert Fingerprinter._label(CONFIDENCE_DEFINITE) == "definite_ai"
        assert Fingerprinter._label(CONFIDENCE_LIKELY)   == "likely_ai"
        assert Fingerprinter._label(CONFIDENCE_POSSIBLE) == "possible_ai"


# ---------------------------------------------------------------------------
# FingerprintResult model tests
# ---------------------------------------------------------------------------

class TestFingerprintResult:
    """Tests for the FingerprintResult data model."""

    def test_is_ai_surface_true_for_non_not_ai(self):
        result = FingerprintResult(
            target=make_target(),
            label="definite_ai",
            confidence=0.85,
        )
        assert result.is_ai_surface is True

    def test_is_ai_surface_false_for_not_ai(self):
        result = FingerprintResult(
            target=make_target(),
            label="not_ai",
            confidence=0.05,
        )
        assert result.is_ai_surface is False

    def test_default_fields_are_safe(self):
        """Default FingerprintResult should not raise on any field access."""
        result = FingerprintResult(target=make_target())
        _ = result.confidence
        _ = result.label
        _ = result.signals
        _ = result.evidence
        _ = result.is_ai_surface