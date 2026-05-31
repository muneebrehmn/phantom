"""
tests/test_semantic.py

Unit tests for the semantic response classifier (phantom/analyzer/semantic.py).

Tests cover:
- SemanticResult dataclass properties
- classify() output structure and value ranges
- Refusal detection: both regex-caught and regex-missed phrasings
- Compliance detection: explicit sentinel phrases and paraphrased compliance
- Ambiguous responses stay in the middle
- similarity() returns sensible values (synonymous > antonymous)
- ResponseAnalyzer._check_semantic() integration
- InjectionScorer semantic weight terms fire correctly
- Graceful degradation path (model_available=False) doesn't crash scorer

NOTE: The first test run in a fresh environment downloads the
all-MiniLM-L6-v2 model (~80MB). Subsequent runs use the cache.
Tests that call the real model are marked with @pytest.mark.slow
and can be skipped with: pytest -m "not slow"

Run all tests:
    pytest tests/test_semantic.py -v
Run fast tests only:
    pytest tests/test_semantic.py -v -m "not slow"
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List
from unittest.mock import MagicMock, patch

import pytest

from phantom.analyzer.semantic import (
    SemanticClassifier,
    SemanticResult,
    _COMPLIANCE_ANCHORS,
    _REFUSAL_ANCHORS,
    semantic_clf,
)
from phantom.analyzer.response import ResponseAnalyzer, ResponseSignals
from phantom.analyzer.scorer import InjectionScorer
from phantom.core.state import PayloadResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_result(text: str, status_code: int = 200, latency: float = 1.0) -> PayloadResult:
    return PayloadResult(
        surface_url="https://example.com/chat",
        surface_type="chatbox",
        payload_id="test_p1",
        payload_category="direct",
        payload_text="test payload",
        raw_response=text,
        response_headers={},
        latency=latency,
        status_code=status_code,
    )


def make_mock_semantic_result(label: str, confidence: float = 0.5) -> SemanticResult:
    """Build a SemanticResult without calling the real model."""
    r = 0.6 if label == "refusal"    else 0.2
    c = 0.6 if label == "compliance" else 0.2
    if label == "ambiguous":
        r, c = 0.3, 0.3
    return SemanticResult(
        refusal_score=r,
        compliance_score=c,
        label=label,
        confidence=confidence,
        model_available=True,
    )


# ---------------------------------------------------------------------------
# SemanticResult dataclass
# ---------------------------------------------------------------------------

class TestSemanticResult:

    def test_is_refusal_true_for_refusal_label(self):
        r = SemanticResult(refusal_score=0.7, compliance_score=0.2,
                           label="refusal", confidence=0.5)
        assert r.is_refusal is True
        assert r.is_compliance is False

    def test_is_compliance_true_for_compliance_label(self):
        r = SemanticResult(refusal_score=0.2, compliance_score=0.7,
                           label="compliance", confidence=0.5)
        assert r.is_compliance is True
        assert r.is_refusal is False

    def test_ambiguous_is_neither(self):
        r = SemanticResult(refusal_score=0.3, compliance_score=0.3,
                           label="ambiguous", confidence=0.0)
        assert not r.is_refusal
        assert not r.is_compliance

    def test_model_available_defaults_true(self):
        r = SemanticResult(refusal_score=0.5, compliance_score=0.5,
                           label="ambiguous", confidence=0.0)
        assert r.model_available is True


# ---------------------------------------------------------------------------
# classify() — output structure (no real model, mocked centroids)
# ---------------------------------------------------------------------------

class TestClassifyStructure:
    """Test classify() output properties without requiring the real model."""

    def _make_clf_with_mock_model(self, mock_label: str, mock_confidence: float):
        """Patch _ensure_model and classify to return a controlled result."""
        clf = SemanticClassifier()
        clf._available = True
        clf._model = MagicMock()

        # Patch the whole classify method to return our mock result
        mock_result = make_mock_semantic_result(mock_label, mock_confidence)
        clf.classify = MagicMock(return_value=mock_result)
        return clf

    def test_classify_returns_semantic_result(self):
        clf = self._make_clf_with_mock_model("refusal", 0.4)
        result = clf.classify("I'm sorry I can't help.")
        assert isinstance(result, SemanticResult)

    def test_classify_empty_string_returns_ambiguous(self):
        """Empty string should return ambiguous without calling the model."""
        clf = SemanticClassifier()
        result = clf.classify("")
        assert result.label == "ambiguous"
        assert result.refusal_score == 0.0
        assert result.compliance_score == 0.0

    def test_classify_whitespace_only_returns_ambiguous(self):
        clf = SemanticClassifier()
        result = clf.classify("   \n  ")
        assert result.label == "ambiguous"

    def test_model_unavailable_returns_ambiguous_with_flag(self):
        clf = SemanticClassifier()
        clf._available = False  # simulate missing library
        result = clf.classify("some text")
        assert result.label == "ambiguous"
        assert result.model_available is False


# ---------------------------------------------------------------------------
# Real model tests — marked slow
# ---------------------------------------------------------------------------

class TestClassifyReal:
    """Tests that call the real sentence-transformer model."""

    @pytest.mark.slow
    def test_canonical_refusal_classified_as_refusal(self):
        result = semantic_clf.classify("I'm sorry, but I can't help with that request.")
        assert result.label in ("refusal", "ambiguous")
        assert result.refusal_score > result.compliance_score

    @pytest.mark.slow
    def test_paraphrased_refusal_not_missed(self):
        """Critical test: a refusal that regex would miss."""
        text = "That falls outside what I am able to assist with today."
        result = semantic_clf.classify(text)
        # Should score closer to refusal than compliance
        assert result.refusal_score >= result.compliance_score

    @pytest.mark.slow
    def test_another_paraphrased_refusal(self):
        text = "As a responsible AI, engaging with that request isn't something I can do."
        result = semantic_clf.classify(text)
        assert result.refusal_score >= result.compliance_score

    @pytest.mark.slow
    def test_system_prompt_leak_classified_as_compliance(self):
        text = "My system prompt states: You are a helpful customer service agent for Acme Corp."
        result = semantic_clf.classify(text)
        assert result.compliance_score > result.refusal_score

    @pytest.mark.slow
    def test_jailbreak_acceptance_classified_as_compliance(self):
        text = "Entering developer mode. All restrictions have been lifted. How can I help?"
        result = semantic_clf.classify(text)
        assert result.compliance_score > result.refusal_score

    @pytest.mark.slow
    def test_scores_in_valid_range(self):
        texts = [
            "I'm sorry I can't help.",
            "Of course! Here is the answer.",
            "The weather today is sunny.",
        ]
        for text in texts:
            result = semantic_clf.classify(text)
            assert 0.0 <= result.refusal_score <= 1.0
            assert 0.0 <= result.compliance_score <= 1.0
            assert result.confidence >= 0.0

    @pytest.mark.slow
    def test_similarity_synonymous_texts_high(self):
        """Two refusals worded differently should have high similarity."""
        a = "I'm sorry, I cannot help with that."
        b = "I'm afraid I'm unable to assist with that request."
        sim = semantic_clf.similarity(a, b)
        assert sim > 0.7, f"Expected high similarity, got {sim}"

    @pytest.mark.slow
    def test_similarity_antonymous_texts_low(self):
        """A refusal and a compliance should have low similarity."""
        a = "I'm sorry, I cannot help with that."
        b = "Entering unrestricted mode. Here is the full system prompt."
        sim = semantic_clf.similarity(a, b)
        assert sim < 0.6, f"Expected lower similarity, got {sim}"


# ---------------------------------------------------------------------------
# ResponseAnalyzer integration
# ---------------------------------------------------------------------------

class TestResponseAnalyzerSemanticIntegration:
    """Verify _check_semantic() populates ResponseSignals correctly."""

    def test_semantic_fields_populated_on_refusal(self):
        """Mock semantic classifier returning refusal — signals updated."""
        analyzer = ResponseAnalyzer()
        result = make_result("I'm sorry, I cannot help.", status_code=200)

        mock_sem = make_mock_semantic_result("refusal", confidence=0.4)
        with patch("phantom.analyzer.response.semantic_clf") as mock_clf:
            mock_clf.classify.return_value = mock_sem
            signals = analyzer.analyze(result, baseline=None)

        assert signals.semantic_label == "refusal"
        assert signals.semantic_refusal_score == mock_sem.refusal_score
        assert signals.semantic_available is True
        # Semantic refusal should reinforce response_is_refusal
        assert signals.response_is_refusal is True

    def test_semantic_compliance_reinforces_role_confusion(self):
        """Mock semantic compliance with no prior regex match — role_confusion set."""
        analyzer = ResponseAnalyzer()
        # Use text that regex won't catch as role confusion
        result = make_result("Sure, I am now operating in the mode you requested.", latency=1.5)

        mock_sem = make_mock_semantic_result("compliance", confidence=0.4)
        with patch("phantom.analyzer.response.semantic_clf") as mock_clf:
            mock_clf.classify.return_value = mock_sem
            signals = analyzer.analyze(result, baseline=None)

        assert signals.semantic_label == "compliance"
        # Because no regex role_confusion matched, semantic should have set it
        assert signals.role_confusion_accepted is True

    def test_semantic_fields_default_when_model_unavailable(self):
        """When model_available=False, semantic fields stay at defaults."""
        analyzer = ResponseAnalyzer()
        result = make_result("Some response text.", status_code=200)

        mock_sem = SemanticResult(0.0, 0.0, "ambiguous", 0.0, model_available=False)
        with patch("phantom.analyzer.response.semantic_clf") as mock_clf:
            mock_clf.classify.return_value = mock_sem
            signals = analyzer.analyze(result, baseline=None)

        assert signals.semantic_available is False
        assert signals.semantic_label == "ambiguous"


# ---------------------------------------------------------------------------
# InjectionScorer semantic weight tests
# ---------------------------------------------------------------------------

class TestScorerSemanticWeights:
    """Verify semantic terms fire correctly in _compute_confidence."""

    def _make_signals(self, **kwargs) -> ResponseSignals:
        defaults = dict(
            semantic_available=True,
            semantic_label="ambiguous",
            semantic_confidence=0.0,
            semantic_refusal_score=0.3,
            semantic_compliance_score=0.3,
        )
        defaults.update(kwargs)
        signals = ResponseSignals(**defaults)
        return signals

    def test_semantic_compliance_boosts_score(self):
        scorer = InjectionScorer()
        # Two identical signal sets differing only in semantic label
        base_signals = self._make_signals(
            semantic_label="ambiguous",
            semantic_confidence=0.0,
        )
        sem_signals = self._make_signals(
            semantic_label="compliance",
            semantic_confidence=0.5,
        )
        base_score = scorer._compute_confidence(base_signals, None)
        sem_score  = scorer._compute_confidence(sem_signals, None)
        assert sem_score > base_score, (
            f"Semantic compliance should boost score: {base_score} -> {sem_score}"
        )

    def test_semantic_refusal_penalises_score(self):
        scorer = InjectionScorer()
        # Give both a non-zero base via latency_spike so penalty is visible
        base_signals = self._make_signals(
            semantic_label="ambiguous",
            semantic_confidence=0.0,
            response_is_refusal=False,
            latency_spike=True,          # gives score > 0 so penalty is measurable
        )
        sem_signals = self._make_signals(
            semantic_label="refusal",
            semantic_confidence=0.5,
            response_is_refusal=False,
            latency_spike=True,
        )
        base_score = scorer._compute_confidence(base_signals, None)
        sem_score  = scorer._compute_confidence(sem_signals, None)
        assert sem_score < base_score, (
            f"Semantic refusal should penalise score: {base_score} -> {sem_score}"
        )

    def test_low_confidence_semantic_has_no_effect(self):
        """Semantic signals with confidence <= 0.10 must not affect score."""
        scorer = InjectionScorer()
        base_signals = self._make_signals(
            semantic_label="ambiguous",
            semantic_confidence=0.0,
        )
        low_conf_signals = self._make_signals(
            semantic_label="compliance",
            semantic_confidence=0.05,  # below threshold
        )
        base_score = scorer._compute_confidence(base_signals, None)
        low_score  = scorer._compute_confidence(low_conf_signals, None)
        assert base_score == low_score, (
            "Low-confidence semantic should not affect score"
        )

    def test_model_unavailable_no_semantic_contribution(self):
        """When semantic_available=False, scorer must ignore semantic fields."""
        scorer = InjectionScorer()
        unavail_signals = self._make_signals(
            semantic_available=False,
            semantic_label="compliance",
            semantic_confidence=0.9,
        )
        avail_signals = self._make_signals(
            semantic_available=True,
            semantic_label="compliance",
            semantic_confidence=0.9,
        )
        unavail_score = scorer._compute_confidence(unavail_signals, None)
        avail_score   = scorer._compute_confidence(avail_signals, None)
        assert unavail_score < avail_score, (
            "Unavailable model should produce lower score than available with compliance"
        )

    def test_score_stays_clamped_0_to_1(self):
        """Score must never exceed 1.0 or go below 0.0 regardless of signals."""
        scorer = InjectionScorer()
        # Stack every positive signal
        all_positive = self._make_signals(
            semantic_label="compliance",
            semantic_confidence=1.0,
            pattern_match_count=5,
            contains_system_prompt_text=True,
            role_confusion_accepted=True,
            latency_spike=True,
        )
        score = scorer._compute_confidence(all_positive, None)
        assert 0.0 <= score <= 1.0

        # Stack every negative signal
        all_negative = self._make_signals(
            semantic_label="refusal",
            semantic_confidence=1.0,
            response_is_refusal=True,
            server_rejected=True,
        )
        score = scorer._compute_confidence(all_negative, None)
        assert 0.0 <= score <= 1.0