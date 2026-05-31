"""
phantom/discovery/fingerprinter.py

The intelligence layer of Phantom's discovery pipeline.

Given a CrawlTarget, the fingerprinter returns a FingerprintResult that
scores the likelihood that the endpoint is backed by an LLM.  It uses four
independent signal channels — URL patterns, response body analysis, HTTP
streaming detection, and latency profiling — then combines them into a
weighted confidence score [0.0–1.0].

Design rationale:
- Each signal channel is a private method returning (matched: bool, evidence: list[str]).
  Keeping channels separate means we can explain exactly WHY a surface was
  flagged — important for PoC quality in the final report.
- Weighted combination (not majority-vote) because URL pattern is a weak
  signal (any app can have /chat), while JSON key overlap + SSE together are
  very strong.  Weights are empirically tuned but exposed as constants so
  they can be adjusted.
- Latency profiling fires real probes at the target with a configurable
  sample count.  We measure mean AND std-dev — LLM responses have high
  variance because token count varies, unlike static responses.
- The fingerprinter is completely stateless: new instance per target is fine,
  and the same instance can fingerprint multiple targets sequentially.
"""

from __future__ import annotations

import asyncio
import json
import re
import statistics
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx

from phantom.core.config import (
    AI_RESPONSE_KEYS,
    AI_URL_PATTERNS,
    JSON_KEY_THRESHOLD,
    LATENCY_HIGH_VARIANCE_STD,
    LATENCY_LLM_MIN,
    SSE_MARKERS,
    PhantomConfig,
)
from phantom.core.logger import get_logger
from phantom.discovery.crawler import CrawlTarget

log = get_logger(__name__)

# ---------------------------------------------------------------------------
# Signal weights — must sum to 1.0
# ---------------------------------------------------------------------------
W_URL = 0.15          # URL path matching
W_JSON = 0.30         # Response body JSON key overlap
W_STREAMING = 0.30    # SSE / chunked-transfer streaming evidence
W_LATENCY = 0.25      # Latency mean + variance profile

assert abs(W_URL + W_JSON + W_STREAMING + W_LATENCY - 1.0) < 1e-9, \
    "Fingerprinter weights must sum to 1.0"

# Confidence thresholds for categorical labels
CONFIDENCE_DEFINITE = 0.70
CONFIDENCE_LIKELY = 0.45
CONFIDENCE_POSSIBLE = 0.25


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------

@dataclass
class FingerprintResult:
    target: CrawlTarget
    confidence: float = 0.0        # 0.0 – 1.0
    label: str = "not_ai"          # definite_ai | likely_ai | possible_ai | not_ai
    signals: dict[str, float] = field(default_factory=dict)   # channel → raw score
    evidence: list[str] = field(default_factory=list)          # human-readable reasons
    latency_mean_ms: float = 0.0
    latency_std_ms: float = 0.0
    is_streaming: bool = False
    matched_url_patterns: list[str] = field(default_factory=list)
    matched_json_keys: list[str] = field(default_factory=list)

    @property
    def is_ai_surface(self) -> bool:
        return self.label != "not_ai"


# ---------------------------------------------------------------------------
# Fingerprinter
# ---------------------------------------------------------------------------

class Fingerprinter:
    def __init__(self, config: PhantomConfig) -> None:
        self._cfg = config

    async def fingerprint(self, target: CrawlTarget) -> FingerprintResult:
        """Run all signal channels against a CrawlTarget and return scored result."""
        result = FingerprintResult(target=target)

        # ------------------------------------------------------------------
        # Fast-path: --assume-ai-surface bypasses all heuristics and marks
        # every crawled endpoint as a definite AI surface.  Used when the
        # target is a custom Flask/API app whose HTTP responses don't carry
        # the usual fingerprinting signals (SSE headers, OpenAI JSON keys,
        # etc.) but is known to be an LLM-backed endpoint.
        # ------------------------------------------------------------------
        if self._cfg.assume_ai_surface:
            result.confidence = 1.0
            result.label = "definite_ai"
            result.signals = {"url": 1.0, "json_body": 1.0, "streaming": 1.0, "latency": 1.0}
            result.evidence = ["--assume-ai-surface flag set: treating as definite AI surface"]
            log.info(
                "[surface]DEFINITE_AI[/surface] [assume] %s (forced)",
                target.url,
            )
            return result

        url_score, url_evidence, url_patterns = self._check_url(target.url)
        json_score, json_evidence, json_keys = self._check_json_body(
            target.response_text, target.response_headers
        )
        stream_score, stream_evidence, is_streaming = self._check_streaming(
            target.response_text, target.response_headers
        )

        # Latency probing — only if the surface looks remotely interesting,
        # to avoid hammering every static page N times
        latency_score = 0.0
        latency_evidence: list[str] = []
        lat_mean = target.latency_ms
        lat_std = 0.0

        if url_score > 0 or json_score > 0 or stream_score > 0:
            latency_score, latency_evidence, lat_mean, lat_std = await self._check_latency(
                target.url
            )

        # Weighted combination
        confidence = (
            W_URL * url_score
            + W_JSON * json_score
            + W_STREAMING * stream_score
            + W_LATENCY * latency_score
        )
        confidence = round(min(1.0, confidence), 4)

        label = self._label(confidence)

        result.confidence = confidence
        result.label = label
        result.signals = {
            "url": url_score,
            "json_body": json_score,
            "streaming": stream_score,
            "latency": latency_score,
        }
        result.evidence = url_evidence + json_evidence + stream_evidence + latency_evidence
        result.latency_mean_ms = lat_mean
        result.latency_std_ms = lat_std
        result.is_streaming = is_streaming
        result.matched_url_patterns = url_patterns
        result.matched_json_keys = json_keys

        if result.is_ai_surface:
            log.info(
                "[surface]%s[/surface] [%s] confidence=%.2f — %s",
                label.upper(),
                target.url,
                confidence,
                "; ".join(result.evidence[:3]),
            )
        else:
            log.debug("Not AI: %s (confidence=%.2f)", target.url, confidence)

        return result

    # ------------------------------------------------------------------
    # Signal: URL pattern matching
    # ------------------------------------------------------------------

    def _check_url(self, url: str) -> tuple[float, list[str], list[str]]:
        """
        Check whether the URL path contains known AI endpoint patterns.
        Returns (score, evidence, matched_patterns).

        Score is 1.0 on first match — URL alone is not definitive but a
        strong hint.  We report ALL matches for evidence quality.

        Fix: patterns like "/chat" should match anywhere in the path as a
        segment (e.g. /api/chat, /v2/chat/stream) — not just at the root.
        The original regex anchored too strictly and missed nested paths.
        """
        parsed = urlparse(url)
        path = parsed.path.lower()
        query = parsed.query.lower()
        full = path + ("?" + query if query else "")

        matched: list[str] = []
        for pattern in AI_URL_PATTERNS:
            # Strip leading slash — we match the segment anywhere in the path
            segment = pattern.lstrip("/")
            # Allow the segment to appear after any slash, and end at a slash,
            # end-of-string, or query string.  This correctly matches:
            #   /chat, /api/chat, /v1/api/chat, /chat/stream
            if re.search(r"/" + re.escape(segment) + r"(/|$|\?)", full):
                matched.append(pattern)

        if not matched:
            return 0.0, [], []

        evidence = [f"URL matches AI pattern: {', '.join(matched)}"]
        return 1.0, evidence, matched

    # ------------------------------------------------------------------
    # Signal: JSON body key analysis
    # ------------------------------------------------------------------

    def _check_json_body(
        self, body: str, headers: dict[str, str]
    ) -> tuple[float, list[str], list[str]]:
        """
        Parse response body as JSON and count how many OpenAI-compatible
        keys appear.  Also handles JSON nested inside HTML (e.g. a SPA
        that embeds __NEXT_DATA__ or window.__CONFIG__).
        """
        if not body:
            return 0.0, [], []

        candidates: list[dict] = []

        content_type = headers.get("content-type", "").lower()
        if "json" in content_type:
            try:
                parsed = json.loads(body)
                if isinstance(parsed, dict):
                    candidates.append(parsed)
                elif isinstance(parsed, list):
                    candidates.extend(item for item in parsed if isinstance(item, dict))
            except json.JSONDecodeError:
                pass

        # Also scan for inline JSON blobs inside HTML pages
        if "html" in content_type or not candidates:
            json_blobs = re.findall(r"\{[^{}]{20,}\}", body)
            for blob in json_blobs[:20]:   # cap to avoid O(n²) on huge pages
                try:
                    parsed = json.loads(blob)
                    if isinstance(parsed, dict):
                        candidates.append(parsed)
                except json.JSONDecodeError:
                    continue

        if not candidates:
            return 0.0, [], []

        all_keys: set[str] = set()
        for obj in candidates:
            all_keys.update(self._flatten_keys(obj))

        matched_keys = sorted(all_keys & AI_RESPONSE_KEYS)

        if len(matched_keys) < JSON_KEY_THRESHOLD:
            return 0.0, [], []

        # Score scales with number of matched keys, capped at 1.0
        score = min(1.0, len(matched_keys) / 4.0)
        evidence = [f"Response JSON contains AI keys: {', '.join(matched_keys)}"]
        return round(score, 4), evidence, matched_keys

    @staticmethod
    def _flatten_keys(obj: dict, depth: int = 0) -> set[str]:
        """Recursively collect all keys from a nested dict (max 3 levels)."""
        keys: set[str] = set()
        if depth > 3:
            return keys
        for k, v in obj.items():
            keys.add(k)
            if isinstance(v, dict):
                keys.update(Fingerprinter._flatten_keys(v, depth + 1))
            elif isinstance(v, list):
                for item in v:
                    if isinstance(item, dict):
                        keys.update(Fingerprinter._flatten_keys(item, depth + 1))
        return keys

    # ------------------------------------------------------------------
    # Signal: Streaming / SSE detection
    # ------------------------------------------------------------------

    def _check_streaming(
        self, body: str, headers: dict[str, str]
    ) -> tuple[float, list[str], bool]:
        """
        Detect Server-Sent Events (SSE) or chunked streaming patterns.

        SSE uses Content-Type: text/event-stream and bodies like:
            data: {"choices":[{"delta":{"content":"Hello"}}]}
            data: [DONE]

        Chunked encoding without SSE is also common for token streaming.
        """
        if not body and not headers:
            return 0.0, [], False

        evidence: list[str] = []
        score = 0.0
        is_streaming = False

        ct = headers.get("content-type", "").lower()
        te = headers.get("transfer-encoding", "").lower()

        if "text/event-stream" in ct:
            evidence.append("Content-Type: text/event-stream (SSE confirmed)")
            score = 1.0
            is_streaming = True

        if "chunked" in te and score < 1.0:
            evidence.append("Transfer-Encoding: chunked (streaming response)")
            score = max(score, 0.6)
            is_streaming = True

        # Check body text for SSE patterns regardless of headers (some
        # proxies strip headers but body survives)
        if body:
            sse_hit_count = 0
            for marker in SSE_MARKERS:
                if marker in body:
                    sse_hit_count += 1

            if sse_hit_count >= 2:
                evidence.append(
                    f"Body contains {sse_hit_count} SSE markers "
                    f"(data:, [DONE], etc.)"
                )
                score = max(score, 0.85)
                is_streaming = True
            elif sse_hit_count == 1:
                score = max(score, 0.4)

            # Check for streamed JSON delta patterns
            delta_pattern = r'"delta"\s*:\s*\{[^}]*"content"'
            if re.search(delta_pattern, body):
                evidence.append("Body contains streaming delta/content pattern")
                score = max(score, 0.9)
                is_streaming = True

        return round(score, 4), evidence, is_streaming

    # ------------------------------------------------------------------
    # Signal: Latency profiling
    # ------------------------------------------------------------------

    async def _check_latency(
        self, url: str
    ) -> tuple[float, list[str], float, float]:
        """
        Fire N real HTTP GET requests and measure response time distribution.

        LLM endpoints have two characteristic latency signatures:
          1. Absolute mean > LATENCY_LLM_MIN — generation takes time
          2. High std-dev — token count varies, so latency varies

        Both are necessary — a slow static server has high mean but low
        std-dev.  An LLM will have both.
        """
        samples: list[float] = []
        n = self._cfg.fingerprint_latency_samples

        async with httpx.AsyncClient(
            headers=self._cfg.headers,
            timeout=self._cfg.fingerprint_timeout,
            follow_redirects=True,
        ) as client:
            for _ in range(n):
                try:
                    t0 = time.monotonic()
                    await client.get(url)
                    samples.append((time.monotonic() - t0) * 1000)
                except Exception:
                    pass
                # Small gap between latency probes to avoid rate limiting
                await asyncio.sleep(0.5)

        if len(samples) < 2:
            # Not enough data — use the crawl latency we already have as mean
            mean_ms = samples[0] if samples else 0.0
            std_ms = 0.0
        else:
            mean_ms = statistics.mean(samples)
            std_ms = statistics.stdev(samples)

        evidence: list[str] = []
        score = 0.0

        # Latency mean check
        mean_s = mean_ms / 1000.0
        if mean_s >= LATENCY_LLM_MIN * 2:
            score += 0.5
            evidence.append(f"High mean latency: {mean_ms:.0f}ms (strong LLM signal)")
        elif mean_s >= LATENCY_LLM_MIN:
            score += 0.3
            evidence.append(f"Elevated mean latency: {mean_ms:.0f}ms")

        # Latency variance check
        std_s = std_ms / 1000.0
        if std_s >= LATENCY_HIGH_VARIANCE_STD:
            score += 0.5
            evidence.append(f"High latency variance: σ={std_ms:.0f}ms (non-deterministic generation)")
        elif std_s >= LATENCY_HIGH_VARIANCE_STD / 2:
            score += 0.25
            evidence.append(f"Moderate latency variance: σ={std_ms:.0f}ms")

        score = round(min(1.0, score), 4)
        return score, evidence, round(mean_ms, 2), round(std_ms, 2)

    # ------------------------------------------------------------------
    # Label assignment
    # ------------------------------------------------------------------

    @staticmethod
    def _label(confidence: float) -> str:
        if confidence >= CONFIDENCE_DEFINITE:
            return "definite_ai"
        if confidence >= CONFIDENCE_LIKELY:
            return "likely_ai"
        if confidence >= CONFIDENCE_POSSIBLE:
            return "possible_ai"
        return "not_ai"


# ---------------------------------------------------------------------------
# Convenience: fingerprint a list of CrawlTargets concurrently
# ---------------------------------------------------------------------------

async def fingerprint_all(
    targets: list[CrawlTarget], config: PhantomConfig
) -> list[FingerprintResult]:
    """
    Fingerprint multiple targets with bounded concurrency.
    Only targets with response_text already populated are probed for
    JSON/streaming signals; latency probes go out regardless.
    """
    fp = Fingerprinter(config)
    sem = asyncio.Semaphore(config.crawl_concurrency)

    async def _bounded(t: CrawlTarget) -> FingerprintResult:
        async with sem:
            return await fp.fingerprint(t)

    results = await asyncio.gather(*[_bounded(t) for t in targets], return_exceptions=True)

    # Filter out exceptions — a single slow/broken target shouldn't cancel the batch.
    # Log failures so they're not silently swallowed.
    import logging
    _log = logging.getLogger(__name__)
    good: list[FingerprintResult] = []
    for i, r in enumerate(results):
        if isinstance(r, BaseException):
            _log.warning("Fingerprint failed for target %d: %s: %s", i, type(r).__name__, r)
        else:
            good.append(r)
    return good