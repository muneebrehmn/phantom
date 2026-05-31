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
    respect_robots: bool = False     # Honour robots.txt disallow rules (off by default in scan mode)
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
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
    request_timeout: float = 10.0     # HTTP timeout for payload POSTs (seconds)
    rate_limit_rps: float = 0.2       # Requests per second to target (conservative)
    rate_limit_burst: int = 3         # Token-bucket burst capacity
    # NOTE: rate_limit_rps is PER-WORKER. With crawl_concurrency=5, actual RPS = 5 * rate_limit_rps.
    # Example: rate_limit_rps=0.2 + crawl_concurrency=5 = 1.0 RPS effective.
    # Reduce rate_limit_rps further if you want lower overall rate. Default 0.2 is conservative.

    # --- SSL/TLS verification ---
    verify_ssl: bool = True           # Verify SSL certificates (default: safe)
    allow_self_signed: bool = False   # Allow self-signed certs (requires --insecure flag)
    ssl_cert_path: str = ""           # Path to client certificate (PEM format)

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

    # --- Adaptive attack engine ---
    # When True, Phantom runs a defence-aware synthesis loop after the static
    # payload phase.  Requires anthropic_api_key to be set.
    # Each surface x goal costs up to adaptive_max_rounds x adaptive_candidates_per_round
    # Anthropic API calls.
    adaptive_attack: bool = False
    adaptive_max_rounds: int = 3            # Max synthesis rounds per surface/goal
    adaptive_candidates_per_round: int = 5  # Candidates synthesised per round

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    # Set to True only in unit tests to bypass rate-limit validation.
    # Never set this in production code.
    _testing: bool = False

    def __post_init__(self) -> None:
        """Validate immediately so bad configs fail at startup, not mid-crawl."""
        if not self._testing:
            self._validate()

    def _validate(self) -> None:
        """Validate all configuration parameters. Called on __post_init__."""
        if self.max_depth < 1:
            raise ValueError("max_depth must be >= 1")
        if self.max_pages < 1:
            raise ValueError("max_pages must be >= 1")
        if self.crawl_concurrency < 1:
            raise ValueError("crawl_concurrency must be >= 1")
        if self.crawl_concurrency > 50:
            raise ValueError("crawl_concurrency > 50 may cause resource exhaustion")
        if self.concurrency_limit < 1:
            raise ValueError("concurrency_limit must be >= 1")
        if self.concurrency_limit > 50:
            raise ValueError("concurrency_limit > 50 may cause resource exhaustion")
        if self.rate_limit_rps <= 0:
            raise ValueError("rate_limit_rps must be positive")
        if self.rate_limit_rps > 10.0:
            raise ValueError("rate_limit_rps > 10 is too aggressive and will harm targets")
        if self.rate_limit_rps > 1.0:
            import warnings
            warnings.warn(
                f"rate_limit_rps={self.rate_limit_rps} is aggressive. "
                "This combined with concurrency may hammer the target. "
                "Consider using <= 0.5 for safety.",
                stacklevel=2
            )
        if self.crawl_timeout <= 0:
            raise ValueError("crawl_timeout must be positive")
        if self.fingerprint_timeout <= 0:
            raise ValueError("fingerprint_timeout must be positive")
        if self.request_timeout <= 0:
            raise ValueError("request_timeout must be positive")
        if self.target_url and not self.target_url.startswith(("http://", "https://")):
            raise ValueError(f"target_url must include scheme: {self.target_url!r}")
        if self.allow_self_signed and self.verify_ssl:
            raise ValueError(
                "Conflicting SSL options: allow_self_signed=True requires verify_ssl=False. "
                "Use --insecure flag to set both correctly."
            )
        if self.ssl_cert_path and not os.path.isfile(self.ssl_cert_path):
            raise ValueError(f"SSL certificate file not found: {self.ssl_cert_path!r}")

    def with_target(self, url: str) -> "PhantomConfig":
        """
        Return a new PhantomConfig with target_url and allowed_domains set.

        Validates that the target URL is on an allowed domain before accepting it.

        Usage:
            config = PhantomConfig().with_target("https://example.com")
        """
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.netloc

        if not domain:
            raise ValueError(f"Invalid target URL — no domain found: {url!r}")

        # Collect all current field values, then override the two we need.
        # Using __dataclass_fields__ ensures we don't miss any field.
        current = {
            f: getattr(self, f)
            for f in self.__dataclass_fields__
        }
        current["target_url"] = url.rstrip("/")
        current["allowed_domains"] = self.allowed_domains or [domain]

        config = PhantomConfig(**current)
        # Validate that target is actually on an allowed domain
        if config.scope_strict and not self._is_target_in_scope(config.target_url, config.allowed_domains):
            raise ValueError(
                f"Target URL {url!r} is not on an allowed domain. "
                f"Allowed: {config.allowed_domains}. "
                "Set allowed_domains or use scope_strict=False."
            )
        return config

    @staticmethod
    def _is_target_in_scope(url: str, allowed_domains: list[str]) -> bool:
        """Check if URL netloc is in allowed_domains list."""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        target_netloc = parsed.netloc.lower()
        allowed_netlocs = [d.lower() for d in allowed_domains]
        return target_netloc in allowed_netlocs

    @property
    def headers(self) -> dict[str, str]:
        """
        Merged HTTP headers for all outbound requests.
        Custom headers always override the defaults.
        """
        base = {"User-Agent": self.user_agent}
        base.update(self.custom_headers)
        return base

    @property
    def ssl_verify(self) -> bool | str:
        """
        Return the verify parameter for httpx.
        - True: verify SSL certificates (default, safe)
        - False: skip verification (for self-signed certs, development)
        - str path: verify with specific CA bundle
        """
        if self.allow_self_signed:
            return False
        if self.ssl_cert_path:
            return self.ssl_cert_path
        return self.verify_ssl