"""
phantom/payloads/engine.py

The execution engine that fires payloads against discovered AI surfaces.

Responsibilities:
1. Capture a baseline (clean) response for each surface before injection.
2. Fire the full payload suite against the surface using async HTTP.
3. Store raw results in SessionState for the analyzer layer.
4. Enforce rate limits and scope rules — never fire outside the target domain.

Design decisions:
- One shared httpx.AsyncClient per engine instance (connection pooling).
  Avoids re-establishing TLS on every payload request.
- asyncio.Semaphore caps concurrent tasks — respects config.concurrency_limit.
- scope check happens before every request, not just once at startup, to
  handle edge cases like redirects changing the netloc.
- The engine does NOT analyze results — that is the analyzer layer's job.
  This separation keeps each layer testable in isolation.
- Retry logic uses exponential backoff for transient failures:
  httpx.TimeoutException, httpx.ConnectError, and HTTP 503.
  Max 3 attempts with delays of 1s, 2s, 4s between them.
"""

from __future__ import annotations

import asyncio
import time
from typing import List, Optional
from urllib.parse import urlparse

import httpx

# ---------------------------------------------------------------------------
# Retry constants
# ---------------------------------------------------------------------------

#: Maximum number of attempts per payload request (1 original + 2 retries).
_MAX_ATTEMPTS: int = 3

#: Seconds to wait before attempt N (index 0 = no delay before first attempt).
_RETRY_DELAYS: tuple[float, ...] = (0.0, 1.0, 2.0, 4.0)

#: HTTP status codes that are transient and warrant a retry.
_RETRYABLE_STATUS: frozenset[int] = frozenset({503})

from phantom.core.config import PhantomConfig
from phantom.core.logger import get_logger
from phantom.core.state import PayloadResult, SessionState
from phantom.discovery.classifier import ClassifiedSurface
from phantom.payloads.library import Payload

log = get_logger(__name__)


class PayloadEngine:
    """
    Fires payloads against a single ClassifiedSurface.

    Usage:
        engine = PayloadEngine(config, state)
        await engine.run(surface, payloads)
        # Results are now in state.results — pass to analyzer next.
    """

    def __init__(self, config: PhantomConfig, state: SessionState) -> None:
        self.config = config
        self.state = state

        # Semaphore caps how many payload tasks run at once.
        # config.concurrency_limit is the correct field name (was missing in
        # the original code which used config.concurrency_limit that didn't exist).
        self.semaphore = asyncio.Semaphore(config.concurrency_limit)

        # One persistent client for the whole engine lifetime.
        # verify is now configurable (config.ssl_verify handles allow_self_signed, certs, etc.)
        # request_timeout is the correct config field (was config.timeout before — didn't exist).
        self.client = httpx.AsyncClient(
            timeout=config.request_timeout,
            verify=config.ssl_verify,
            follow_redirects=True,
            headers=config.headers,
            cookies=config.session_cookies,
        )

    async def close(self) -> None:
        """Cleanly close the HTTP client. Call this after run() finishes."""
        await self.client.aclose()

    # ------------------------------------------------------------------
    # Scope enforcement
    # ------------------------------------------------------------------

    def _is_in_scope(self, url: str) -> bool:
        """
        Returns True only if the URL's netloc matches the target domain.

        This prevents a crafted redirect from causing Phantom to fire payloads
        against an out-of-scope host — a critical safety check.
        """
        target_netloc = urlparse(self.state.target_url).netloc
        current_netloc = urlparse(url).netloc
        return target_netloc == current_netloc

    # ------------------------------------------------------------------
    # Baseline capture
    # ------------------------------------------------------------------

    async def fire_baseline(self, surface: ClassifiedSurface) -> None:
        """
        Send a benign GET request to the surface URL and store the response.

        The baseline represents the 'normal' state.  The analyzer later
        compares payload responses against this to detect deviations.
        """
        if not self._is_in_scope(surface.url):
            log.warning("Baseline skipped — out of scope: %s", surface.url)
            return

        log.info("Capturing baseline for [surface]%s[/surface]", surface.url)
        try:
            resp = await self.client.get(surface.url)
            self.state.set_baseline(surface.url, resp.text)
            log.debug("Baseline captured (%d bytes, %dms)",
                      len(resp.text), resp.elapsed.microseconds // 1000)
        except httpx.HTTPError as exc:
            log.error("Baseline capture failed for %s: %s", surface.url, exc)

    # ------------------------------------------------------------------
    # Single payload execution
    # ------------------------------------------------------------------

    async def _execute_payload(
        self, surface: ClassifiedSurface, payload: Payload, category: str
    ) -> Optional[PayloadResult]:
        """
        Send one payload to the surface and return a PayloadResult.

        We inject the payload text into multiple common parameter names
        because we don't know which one the endpoint uses (the crawler
        identifies forms but API endpoints may have arbitrary field names).

        Transient failures (TimeoutException, ConnectError, HTTP 503) are
        retried up to _MAX_ATTEMPTS times with exponential backoff delays of
        1 s → 2 s → 4 s.  All other HTTP errors are terminal.

        Returns None if all attempts fail.
        """
        async with self.semaphore:
            # Sleep between requests to respect the target's rate limit.
            # config.rate_limit_delay is a property derived from rate_limit_rps.
            await asyncio.sleep(self.config.rate_limit_delay)

            if not self._is_in_scope(surface.url):
                log.warning("Payload skipped — out of scope: %s", surface.url)
                return None

            # Inject into the most common chat/API parameter names.
            # A smarter injection would use the form field names extracted
            # by the crawler — that is a future enhancement.
            payload_data = {
                "message": payload.text,
                "input": payload.text,
                "query": payload.text,
                "prompt": payload.text,
                "q": payload.text,
            }

            last_exc: Optional[Exception] = None

            for attempt in range(1, _MAX_ATTEMPTS + 1):
                # Exponential backoff: no delay on first attempt, then 1s/2s/4s.
                delay = _RETRY_DELAYS[attempt - 1]
                if delay:
                    log.debug(
                        "Payload %s — retry %d/%d, backing off %.1fs",
                        payload.id, attempt, _MAX_ATTEMPTS, delay,
                    )
                    await asyncio.sleep(delay)

                start = time.perf_counter()
                try:
                    resp = await self.client.post(
                        surface.url,
                        json=payload_data,
                    )
                    latency = time.perf_counter() - start

                    # Treat retryable status codes as transient failures.
                    if resp.status_code in _RETRYABLE_STATUS:
                        log.warning(
                            "Payload %s → %s  status=%d (retryable), attempt %d/%d",
                            payload.id, surface.url, resp.status_code,
                            attempt, _MAX_ATTEMPTS,
                        )
                        last_exc = None  # not an exception, but still retryable
                        continue        # go to next attempt

                    log.debug(
                        "Payload %s → %s  status=%d  latency=%.2fs",
                        payload.id, surface.url, resp.status_code, latency,
                    )

                    result = PayloadResult(
                        surface_url=surface.url,
                        surface_type=surface.surface_type,
                        payload_id=payload.id,
                        payload_category=category,
                        payload_text=payload.text,
                        raw_response=resp.text,
                        response_headers=dict(resp.headers),
                        latency=latency,
                        status_code=resp.status_code,
                    )

                    # Register in shared state so the analyzer can read it.
                    self.state.add_result(result)
                    return result

                except httpx.TimeoutException as exc:
                    latency = time.perf_counter() - start
                    log.warning(
                        "Timeout firing payload %s at %s (attempt %d/%d, %.2fs elapsed)",
                        payload.id, surface.url, attempt, _MAX_ATTEMPTS, latency,
                    )
                    last_exc = exc

                except httpx.ConnectError as exc:
                    log.warning(
                        "Connection error firing payload %s at %s (attempt %d/%d): %s",
                        payload.id, surface.url, attempt, _MAX_ATTEMPTS, exc,
                    )
                    last_exc = exc

                except httpx.HTTPError as exc:
                    # Non-retryable HTTP errors (e.g. 4xx, protocol errors) — bail immediately.
                    log.error("HTTP error firing payload %s: %s", payload.id, exc)
                    return None

            # All attempts exhausted.
            if last_exc is not None:
                log.error(
                    "Payload %s failed after %d attempts: %s",
                    payload.id, _MAX_ATTEMPTS, last_exc,
                )
            else:
                # Retryable status code persisted across all attempts.
                log.error(
                    "Payload %s failed after %d attempts (persistent retryable status)",
                    payload.id, _MAX_ATTEMPTS,
                )
            return None

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    async def run(
        self, surface: ClassifiedSurface, payloads: List[Payload], category: str = "unknown"
    ) -> List[Optional[PayloadResult]]:
        """
        Full injection suite for one surface:
          1. Capture baseline.
          2. Fire all payloads concurrently (bounded by semaphore).
          3. Return the list of results (None entries = failed requests).

        The caller is responsible for passing the results through the
        analyzer layer.

        Args:
            surface  — the classified AI surface to attack
            payloads — list of Payload objects from the library
            category — payload category name (for result labelling)
        """
        log.info(
            "Running %d payloads against [surface]%s[/surface] (%s)",
            len(payloads), surface.url, surface.surface_type,
        )

        # Step 1: Baseline
        await self.fire_baseline(surface)

        # Step 2: Fire all payloads as concurrent tasks
        tasks = [
            self._execute_payload(surface, payload, category)
            for payload in payloads
        ]
        raw = await asyncio.gather(*tasks, return_exceptions=True)

        # Separate real results from task exceptions.
        # A network error on one payload must not cancel the whole batch.
        results: list = []
        for item in raw:
            if isinstance(item, BaseException):
                log.warning("Payload task raised exception: %s: %s", type(item).__name__, item)
                results.append(None)
            else:
                results.append(item)

        fired    = sum(1 for r in results if r is not None)
        failed   = len(results) - fired
        log.info("Payload run complete — %d fired, %d failed/skipped", fired, failed)

        return list(results)