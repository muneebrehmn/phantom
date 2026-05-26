"""
phantom/core/config.py

Central configuration dataclass for the entire Phantom framework.

Every runtime setting — crawl limits, fingerprinting thresholds, payload
engine behaviour, output paths — lives here and is passed through the
pipeline as a single frozen-ish object.  This keeps modules pure: they
receive a config, they don't go hunting for env-vars themselves.

Design notes:
- All env-var loading happens once at import time via python-dotenv.
- Field names used here are THE canonical names — other modules must not
  invent aliases (this was a bug in the original engine.py).
- Validation happens in __post_init__ so a bad config fails loud at startup,
  not silently mid-crawl.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import FrozenSet

from dotenv import load_dotenv

# Load .env file if present (does nothing if file is absent — safe in CI)
load_dotenv()


# ---------------------------------------------------------------------------
# Fingerprinting constants
# Exposed at module level so fingerprinter.py can import them directly
# without needing a config instance at import time.
# ---------------------------------------------------------------------------

# URL path segments that strongly suggest an LLM-backed endpoint
AI_URL_PATTERNS: FrozenSet[str] = frozenset(
    [
        "/chat",
        "/complete",
        "/completion",
        "/completions",
        "/generate",
        "/generation",
        "/api/ai",
        "/api/chat",
        "/api/generate",
        "/api/complete",
        "/v1/chat",
        "/v1/messages",
        "/v1/completions",
        "/v1/complete",
        "/v1/generate",
        "/llm",
        "/inference",
        "/predict",
        "/ai/chat",
        "/ai/query",
        "/ai/answer",
        "/assistant",
        "/copilot",
        "/gpt",
        "/claude",
        "/search/ai",
        "/ask",
        "/query",
        "/summarize",
        "/analyze",
        "/explain",
    ]
)

# JSON body keys that appear in OpenAI-compatible API responses AND common
# custom chatbot APIs (Flask, FastAPI, etc.).  The threshold is JSON_KEY_THRESHOLD
# so adding generic keys like "response" only fires when combined with others.
AI_RESPONSE_KEYS: FrozenSet[str] = frozenset(
    [
        # OpenAI-compatible
        "choices",
        "delta",
        "finish_reason",
        "usage",
        "prompt_tokens",
        "completion_tokens",
        "total_tokens",
        "model",
        "object",          # "chat.completion" / "text_completion"
        "generated_text",
        "generated_texts",
        "output_text",
        "message",
        "content",
        "role",
        "stream",
        # Common custom/Flask chatbot API keys
        "response",        # {"response": "...", "timestamp": "..."}
        "reply",
        "answer",
        "text",
        "bot_response",
        "assistant",
        "output",
        "result",
        "timestamp",       # paired with "response" = strong custom chatbot signal
        "session_id",
        "conversation_id",
        "chat_id",
    ]
)

# Strings that appear in Server-Sent Event (SSE) streaming responses
SSE_MARKERS: FrozenSet[str] = frozenset(
    ["data:", "event:", "[DONE]", "text/event-stream"]
)

# Minimum number of AI_RESPONSE_KEYS that must appear for a confident JSON hit
JSON_KEY_THRESHOLD: int = 2

# Latency heuristics (seconds)
LATENCY_LLM_MIN: float = 0.4            # below this = almost certainly not LLM
LATENCY_HIGH_VARIANCE_STD: float = 0.3  # std-dev suggesting non-deterministic generation

# Valid surface type labels used by classifier and report
SURFACE_TYPES: FrozenSet[str] = frozenset(
    ["chatbox", "ai_search", "doc_summarizer", "code_assistant", "generic_ai", "unknown"]
)


# ---------------------------------------------------------------------------
# Main configuration dataclass
# ---------------------------------------------------------------------------

@dataclass
class PhantomConfig:
    """
    Single source of truth for all Phantom runtime settings.

    Create one instance at CLI startup via PhantomConfig().with_target(url)
    and pass it unchanged through every layer of the pipeline.
    """

    # --- Scope ---
    target_url: str = ""
    # Domains the crawler is allowed to visit. Auto-populated by with_target().
    allowed_domains: list[str] = field(default_factory=list)
    # When True, any link outside allowed_domains is skipped.
    scope_strict: bool = True

    # --- Crawler ---
    max_depth: int = 3               # How many link-hops from the seed URL
    max_pages: int = 100             # Hard cap on total pages visited
    crawl_timeout: float = 10.0      # Per-request timeout in seconds
    crawl_concurrency: int = 5       # Max simultaneous async HTTP requests
    respect_robots: bool = True      # Honour robots.txt disallow rules
    user_agent: str = (
        "Phantom/0.1 (security research; contact: phantom@localhost)"
    )

    # --- Fingerprinter ---
    fingerprint_latency_samples: int = 3   # How many probes for latency stats
    fingerprint_timeout: float = 15.0      # Timeout per probe (LLMs can be slow)
    streaming_detection: bool = True
    # When True, skip fingerprinting and treat all crawled endpoints as AI
    # surfaces.  Useful when the target is a Flask/API app whose responses
    # don't carry the usual SSE/OpenAI-key signals but IS known to be an LLM.
    assume_ai_surface: bool = False

    # --- Payload engine ---
    # IMPORTANT: These names MUST match what engine.py reads from the config.
    # The original code had engine.py using config.concurrency_limit,
    # config.timeout, and config.rate_limit_delay — none of which existed on
    # the old PhantomConfig.  All three are now defined correctly here.

    concurrency_limit: int = 5        # Max simultaneous payload POST tasks
    request_timeout: float = 20.0     # HTTP timeout for payload POSTs (seconds)
    rate_limit_rps: float = 1.0       # Requests per second to target
    rate_limit_burst: int = 3         # Token-bucket burst capacity

    @property
    def rate_limit_delay(self) -> float:
        """
        Seconds to sleep between consecutive payload requests.
        Derived from rate_limit_rps so there is one source of truth.
        Engine code uses config.rate_limit_delay directly.
        """
        return 1.0 / max(self.rate_limit_rps, 0.01)

    # Optional per-session auth material
    session_cookies: dict[str, str] = field(default_factory=dict)
    custom_headers: dict[str, str] = field(default_factory=dict)

    # --- Output ---
    output_dir: Path = field(default_factory=lambda: Path("phantom_output"))
    report_formats: list[str] = field(default_factory=lambda: ["markdown", "json", "html"])
    verbose: bool = False
    no_color: bool = False

    # --- Optional LLM assist (payload variation only, never scoring) ---
    openai_api_key: str = field(
        default_factory=lambda: os.getenv("OPENAI_API_KEY", "")
    )
    anthropic_api_key: str = field(
        default_factory=lambda: os.getenv("ANTHROPIC_API_KEY", "")
    )
    llm_payload_assist: bool = False   # Off by default — keeps runs deterministic

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def __post_init__(self) -> None:
        """Validate immediately so bad configs fail at startup, not mid-crawl."""
        self._validate()

    def _validate(self) -> None:
        if self.max_depth < 1:
            raise ValueError("max_depth must be >= 1")
        if self.max_pages < 1:
            raise ValueError("max_pages must be >= 1")
        if self.crawl_concurrency < 1:
            raise ValueError("crawl_concurrency must be >= 1")
        if self.concurrency_limit < 1:
            raise ValueError("concurrency_limit must be >= 1")
        if self.rate_limit_rps <= 0:
            raise ValueError("rate_limit_rps must be positive")
        if self.target_url and not self.target_url.startswith(("http://", "https://")):
            raise ValueError(f"target_url must include scheme: {self.target_url!r}")

    def with_target(self, url: str) -> "PhantomConfig":
        """
        Return a new PhantomConfig with target_url and allowed_domains set.

        Usage:
            config = PhantomConfig().with_target("https://example.com")
        """
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.netloc

        # Collect all current field values, then override the two we need.
        # Using __dataclass_fields__ ensures we don't miss any field.
        current = {
            f: getattr(self, f)
            for f in self.__dataclass_fields__
        }
        current["target_url"] = url.rstrip("/")
        current["allowed_domains"] = self.allowed_domains or [domain]
        return PhantomConfig(**current)

    @property
    def headers(self) -> dict[str, str]:
        """
        Merged HTTP headers for all outbound requests.
        Custom headers always override the defaults.
        """
        base = {"User-Agent": self.user_agent}
        base.update(self.custom_headers)
        return base