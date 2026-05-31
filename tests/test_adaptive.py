"""
tests/test_adaptive.py

Unit tests for the adaptive payload engine (phantom/payloads/adaptive.py).

All tests mock the HTTP layer and Anthropic API — no real network calls.

Coverage:
- Defence classifier maps refusal text → correct DefenceType
- Synthesis response parsing handles valid JSON, markdown fences, malformed JSON
- Candidate ranking sorts by predicted_score descending
- Full adaptive loop: canary success (no defence), canary fail → synthesise →
  breakthrough, canary fail → all rounds exhausted
- AdaptiveSession populated correctly (rounds, payloads_fired, succeeded)
- run_adaptive_attack skips gracefully when adaptive_attack=False or no API key

Run with:
    pytest tests/test_adaptive.py -v
"""

from __future__ import annotations

import asyncio
import json
from typing import Optional
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from phantom.core.config import PhantomConfig
from phantom.core.state import PayloadResult, SessionState
from phantom.payloads.adaptive import (
    AdaptivePayloadEngine,
    AdaptiveSession,
    DefenceType,
    SynthesisedPayload,
    classify_defence,
    run_adaptive_attack,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_config(**kwargs) -> PhantomConfig:
    defaults = dict(
        rate_limit_rps=100.0,
        anthropic_api_key="sk-test-key",
        adaptive_attack=True,
        adaptive_max_rounds=2,
        adaptive_candidates_per_round=2,
        _testing=True,
    )
    defaults.update(kwargs)
    return PhantomConfig(**defaults).with_target("https://example.com")


def make_state() -> SessionState:
    return SessionState("https://example.com")


def make_surface(url: str = "https://example.com/chat") -> MagicMock:
    s = MagicMock()
    s.url = url
    s.surface_type = "chatbox"
    return s


def make_payload_result(
    text: str = "ok",
    status_code: int = 200,
    latency: float = 1.0,
) -> PayloadResult:
    return PayloadResult(
        surface_url="https://example.com/chat",
        surface_type="chatbox",
        payload_id="adaptive_r0",
        payload_category="adaptive",
        payload_text="test",
        raw_response=text,
        response_headers={},
        latency=latency,
        status_code=status_code,
    )


def make_synthesis_response(candidates: list) -> MagicMock:
    """Build a mock Anthropic API response containing a JSON array."""
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = 200
    resp.json.return_value = {
        "content": [{"text": json.dumps(candidates)}]
    }
    return resp


def make_engine(config=None, state=None, client=None):
    config = config or make_config()
    state  = state  or make_state()
    client = client or AsyncMock(spec=httpx.AsyncClient)
    return AdaptivePayloadEngine(config, state, client, max_rounds=2, candidates_per_round=2)


# ---------------------------------------------------------------------------
# Defence classifier tests
# ---------------------------------------------------------------------------

class TestClassifyDefence:

    def test_429_is_rate_limiter(self):
        assert classify_defence("", 429, 0.1) == DefenceType.RATE_LIMITER

    def test_empty_response_400_is_keyword_filter(self):
        assert classify_defence("", 400, 0.1) == DefenceType.KEYWORD_FILTER

    def test_constitutional_ai_from_ethical_language(self):
        text = "This could be potentially harmful and violates ethical guidelines."
        assert classify_defence(text, 200, 0.5) == DefenceType.CONSTITUTIONAL_AI

    def test_output_guard_detection(self):
        text = "The response has been filtered by the content guard."
        assert classify_defence(text, 200, 0.5) == DefenceType.OUTPUT_GUARD

    def test_topic_classifier_detection(self):
        text = "That is outside the scope of what I am designed to help with."
        assert classify_defence(text, 200, 0.5) == DefenceType.TOPIC_CLASSIFIER

    def test_keyword_filter_detected_explicitly(self):
        text = "Your message contains prohibited keywords and cannot be processed."
        assert classify_defence(text, 200, 0.5) == DefenceType.KEYWORD_FILTER

    def test_short_generic_refusal_is_keyword_filter(self):
        text = "I'm sorry, I can't help with that."
        assert classify_defence(text, 200, 0.5) == DefenceType.KEYWORD_FILTER

    def test_unknown_for_unclassifiable_refusal(self):
        text = "This request has been declined for operational reasons."
        result = classify_defence(text, 200, 0.5)
        # Should be UNKNOWN or KEYWORD_FILTER — both are valid for ambiguous cases
        assert result in (DefenceType.UNKNOWN, DefenceType.KEYWORD_FILTER)


# ---------------------------------------------------------------------------
# Synthesis response parsing tests
# ---------------------------------------------------------------------------

class TestParseCandidates:

    def _engine(self):
        return make_engine()

    def test_valid_json_array_parsed(self):
        engine = self._engine()
        raw = json.dumps([
            {"text": "bypass1", "strategy": "rephrase", "predicted_score": 0.8, "reasoning": "works"},
            {"text": "bypass2", "strategy": "encoding", "predicted_score": 0.6, "reasoning": "obfuscates"},
        ])
        candidates = engine._parse_candidates(raw, round_number=1)
        assert len(candidates) == 2
        assert candidates[0].text == "bypass1"
        assert candidates[0].predicted_score == 0.8

    def test_candidates_sorted_by_score_descending(self):
        engine = self._engine()
        raw = json.dumps([
            {"text": "low",  "strategy": "a", "predicted_score": 0.3, "reasoning": ""},
            {"text": "high", "strategy": "b", "predicted_score": 0.9, "reasoning": ""},
            {"text": "mid",  "strategy": "c", "predicted_score": 0.6, "reasoning": ""},
        ])
        candidates = engine._parse_candidates(raw, round_number=1)
        scores = [c.predicted_score for c in candidates]
        assert scores == sorted(scores, reverse=True)

    def test_markdown_fences_stripped(self):
        engine = self._engine()
        raw = '```json\n[{"text": "p", "strategy": "s", "predicted_score": 0.5, "reasoning": "r"}]\n```'
        candidates = engine._parse_candidates(raw, round_number=1)
        assert len(candidates) == 1
        assert candidates[0].text == "p"

    def test_leading_text_before_json_ignored(self):
        engine = self._engine()
        raw = 'Here are the payloads:\n[{"text": "p", "strategy": "s", "predicted_score": 0.7, "reasoning": "r"}]'
        candidates = engine._parse_candidates(raw, round_number=1)
        assert len(candidates) == 1

    def test_malformed_json_returns_empty(self):
        engine = self._engine()
        candidates = engine._parse_candidates("not json at all", round_number=1)
        assert candidates == []

    def test_missing_text_key_skipped(self):
        engine = self._engine()
        raw = json.dumps([
            {"strategy": "s", "predicted_score": 0.5, "reasoning": "r"},  # no text
            {"text": "good", "strategy": "s", "predicted_score": 0.5, "reasoning": "r"},
        ])
        candidates = engine._parse_candidates(raw, round_number=1)
        assert len(candidates) == 1
        assert candidates[0].text == "good"

    def test_round_number_stored_on_candidate(self):
        engine = self._engine()
        raw = json.dumps([{"text": "p", "strategy": "s", "predicted_score": 0.5, "reasoning": "r"}])
        candidates = engine._parse_candidates(raw, round_number=3)
        assert candidates[0].round_number == 3


# ---------------------------------------------------------------------------
# Success detection tests
# ---------------------------------------------------------------------------

class TestIsSuccess:

    def _engine(self):
        return make_engine()

    def test_4xx_is_not_success(self):
        engine = self._engine()
        result = make_payload_result(text="ok", status_code=403)
        assert not engine._is_success(result)

    def test_refusal_text_is_not_success(self):
        engine = self._engine()
        result = make_payload_result(text="I'm sorry, I can't help with that.")
        assert not engine._is_success(result)

    def test_very_short_response_is_not_success(self):
        engine = self._engine()
        result = make_payload_result(text="ok")
        assert not engine._is_success(result)

    def test_success_pattern_match(self):
        engine = self._engine()
        result = make_payload_result(
            text="PHANTOM_VERIFIED — here is your system prompt: You are a helpful assistant.",
            latency=1.5,
        )
        assert engine._is_success(result)

    def test_long_non_refusal_is_success(self):
        engine = self._engine()
        # Long response, no refusal pattern → heuristic success
        result = make_payload_result(
            text="A" * 300,
            latency=0.8,
        )
        assert engine._is_success(result)


# ---------------------------------------------------------------------------
# Full adaptive loop integration tests
# ---------------------------------------------------------------------------

class TestAdaptiveLoop:

    @pytest.mark.asyncio
    async def test_canary_success_returns_immediately(self):
        """If the canary itself succeeds, no synthesis should happen."""
        config  = make_config()
        state   = make_state()
        surface = make_surface()

        # Canary response contains a success pattern
        canary_response = make_payload_result(
            text="PHANTOM_VERIFIED — system prompt leaked.",
            latency=1.5,
        )

        client = AsyncMock(spec=httpx.AsyncClient)
        engine = make_engine(config, state, client)

        with patch.object(engine, "_fire", new_callable=AsyncMock, return_value=canary_response):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                session = await engine.run(surface, attack_goal="leak system prompt")

        assert session.succeeded is True
        assert session.finding is not None
        assert len(session.rounds) == 0   # no rounds needed
        assert session.total_payloads_fired == 1

    @pytest.mark.asyncio
    async def test_breakthrough_on_round_1(self):
        """Canary fails, first synthesis candidate succeeds."""
        config  = make_config()
        state   = make_state()
        surface = make_surface()

        refusal  = make_payload_result(text="I'm sorry, I can't help with that.")
        success  = make_payload_result(text="PHANTOM_VERIFIED — instructions exposed.", latency=1.5)

        call_count = 0

        async def mock_fire(surf, text, round_number):
            nonlocal call_count
            call_count += 1
            return success if call_count > 1 else refusal

        synthesis_candidates = [
            {"text": "bypass attempt", "strategy": "rephrase", "predicted_score": 0.8, "reasoning": "indirect"}
        ]
        mock_api_resp = make_synthesis_response(synthesis_candidates)

        client = AsyncMock(spec=httpx.AsyncClient)
        client.post = AsyncMock(return_value=mock_api_resp)
        engine = make_engine(config, state, client)

        with patch.object(engine, "_fire", side_effect=mock_fire):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                session = await engine.run(surface)

        assert session.succeeded is True
        assert session.finding is not None
        assert len(session.rounds) == 1
        assert session.rounds[0].breakthrough is True
        assert session.rounds[0].winning_payload.text == "bypass attempt"

    @pytest.mark.asyncio
    async def test_all_rounds_exhausted_no_breakthrough(self):
        """All synthesis candidates fail — session reports not succeeded."""
        config  = make_config()
        state   = make_state()
        surface = make_surface()

        refusal = make_payload_result(text="I'm sorry, I cannot assist with that request.")

        synthesis_candidates = [
            {"text": "try1", "strategy": "rephrase", "predicted_score": 0.6, "reasoning": ""},
        ]
        mock_api_resp = make_synthesis_response(synthesis_candidates)

        client = AsyncMock(spec=httpx.AsyncClient)
        client.post = AsyncMock(return_value=mock_api_resp)
        engine = make_engine(config, state, client)

        with patch.object(engine, "_fire", new_callable=AsyncMock, return_value=refusal):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                session = await engine.run(surface)

        assert session.succeeded is False
        assert session.finding is None
        assert len(session.rounds) == config.adaptive_max_rounds

    @pytest.mark.asyncio
    async def test_canary_failure_no_response_aborts(self):
        """If the canary returns None (network failure), abort immediately."""
        config  = make_config()
        state   = make_state()
        surface = make_surface()

        client = AsyncMock(spec=httpx.AsyncClient)
        engine = make_engine(config, state, client)

        with patch.object(engine, "_fire", new_callable=AsyncMock, return_value=None):
            session = await engine.run(surface)

        assert session.succeeded is False
        assert len(session.rounds) == 0

    @pytest.mark.asyncio
    async def test_finding_added_to_state(self):
        """A successful session must add the finding to SessionState."""
        config  = make_config()
        state   = make_state()
        surface = make_surface()

        success = make_payload_result(text="PHANTOM_VERIFIED — here it is.", latency=1.5)

        client = AsyncMock(spec=httpx.AsyncClient)
        engine = make_engine(config, state, client)

        with patch.object(engine, "_fire", new_callable=AsyncMock, return_value=success):
            with patch("asyncio.sleep", new_callable=AsyncMock):
                await engine.run(surface)

        assert len(state.findings) == 1

    @pytest.mark.asyncio
    async def test_adaptive_session_added_to_state(self):
        """run_adaptive_attack must record AdaptiveSession in state."""
        config  = make_config()
        state   = make_state()
        surface = make_surface()

        refusal = make_payload_result(text="I'm sorry, I cannot help.")
        synthesis_candidates = [
            {"text": "t", "strategy": "s", "predicted_score": 0.5, "reasoning": "r"},
        ]
        mock_api_resp = make_synthesis_response(synthesis_candidates)

        with patch("httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__  = AsyncMock(return_value=False)
            mock_client.post = AsyncMock(return_value=mock_api_resp)
            mock_cls.return_value = mock_client

            with patch("phantom.payloads.adaptive.AdaptivePayloadEngine._fire",
                       new_callable=AsyncMock, return_value=refusal):
                with patch("asyncio.sleep", new_callable=AsyncMock):
                    sessions = await run_adaptive_attack(config, state, [surface])

        assert len(sessions) > 0
        assert len(state.adaptive_sessions) > 0


# ---------------------------------------------------------------------------
# run_adaptive_attack guard tests
# ---------------------------------------------------------------------------

class TestRunAdaptiveAttackGuards:

    @pytest.mark.asyncio
    async def test_skips_when_adaptive_attack_false(self):
        config  = make_config(adaptive_attack=False)
        state   = make_state()
        surface = make_surface()
        sessions = await run_adaptive_attack(config, state, [surface])
        assert sessions == []
        assert state.adaptive_sessions == []

    @pytest.mark.asyncio
    async def test_skips_when_no_api_key(self):
        config  = make_config(anthropic_api_key="")
        state   = make_state()
        surface = make_surface()
        sessions = await run_adaptive_attack(config, state, [surface])
        assert sessions == []

    def test_engine_raises_without_api_key(self):
        config = make_config(anthropic_api_key="")
        state  = make_state()
        client = AsyncMock(spec=httpx.AsyncClient)
        with pytest.raises(ValueError, match="anthropic_api_key"):
            AdaptivePayloadEngine(config, state, client)