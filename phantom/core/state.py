"""
phantom/core/state.py

Session-level state container shared across the entire pipeline.

SessionState is created once at the start of a scan and passed into the
crawler, fingerprinter, payload engine, and analyzer in turn.  It acts as
the single mutable data store for the run — every discovered surface, every
payload result, and every confirmed finding is recorded here.

Why a shared state object instead of return values?
- Async tasks (crawler workers, payload tasks) run concurrently and need a
  thread-safe place to append results without coordinating through dozens of
  return-value chains.
- The report builder needs access to everything in one place at the end.
- Makes it easy to add a live progress display later (just read state fields).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from phantom.core.findings import Finding

if TYPE_CHECKING:
    from phantom.discovery.classifier import ClassifiedSurface


@dataclass
class PayloadResult:
    """
    The raw, un-analyzed result of sending a single payload to a surface.

    The analyzer layer (scorer.py) reads these and promotes matching results
    to Finding objects.

    Fields:
        surface_url     — which endpoint received the payload
        surface_type    — the classifier's label (chatbox, ai_search, …)
        payload_id      — e.g. "dir_01" — for cross-referencing with library
        payload_category — e.g. "direct", "jailbreak"
        payload_text    — the exact string that was sent
        raw_response    — the full response body
        response_headers — response headers (for content-type, etc.)
        latency         — round-trip time in seconds
        status_code     — HTTP status code
        timestamp       — epoch time at request start
    """
    surface_url: str
    surface_type: str
    payload_id: str
    payload_category: str
    payload_text: str
    raw_response: str
    response_headers: Dict[str, str]
    latency: float
    status_code: int
    timestamp: float = field(default_factory=time.time)


class SessionState:
    """
    Shared, append-only state for a single Phantom scan session.

    Thread-safety: all public methods do single-operation mutations
    (dict assignment, list append).  Python's GIL makes these atomic enough
    for our asyncio concurrency model — we never swap a list or do
    read-modify-write across an await point.
    """

    def __init__(self, target_url: str) -> None:
        self.target_url: str = target_url
        self.start_time: float = time.time()

        # Discovered and classified AI surfaces.
        # Key = surface URL, value = ClassifiedSurface
        self.surfaces: Dict[str, Any] = {}

        # All raw payload execution results (one per payload per surface)
        self.results: List[PayloadResult] = []

        # Baseline (clean) responses captured before payload firing.
        # Key = surface URL, value = response body text.
        self.baselines: Dict[str, str] = {}

        # Confirmed findings produced by the analyzer layer.
        self.findings: List[Finding] = []

        # MultiTurnResult records -- one per surface x payload attempted.
        self.multi_turn_results: List[Any] = []

        # AdaptiveSession records — one per surface x goal attempted.
        # Stored as Any to avoid circular import with adaptive.py.
        self.adaptive_sessions: List[Any] = []

    # ------------------------------------------------------------------
    # Mutation helpers
    # ------------------------------------------------------------------

    def add_surface(self, surface: ClassifiedSurface) -> None:
        """
        Register a ClassifiedSurface in the session.
        Using the URL as key deduplicates re-visits to the same endpoint.

        Args:
            surface: ClassifiedSurface object to register

        Raises:
            ValueError: If surface has no URL
        """
        if surface is None:
            raise ValueError("Cannot add None surface to session state")

        url = getattr(surface, "url", None)
        if not url:
            raise ValueError(f"Surface has no URL: {surface}")

        self.surfaces[str(url)] = surface

    def add_result(self, result: PayloadResult) -> None:
        """Append a raw payload result for later analysis."""
        if result is None:
            raise ValueError("Cannot add None result to session state")
        self.results.append(result)

    def set_baseline(self, url: str, response: str) -> None:
        """
        Store the 'clean' response for a surface before any payloads are fired.
        The analyzer uses this as the reference to detect deviations.

        Args:
            url: Surface URL
            response: Response text to store as baseline
        """
        if not url:
            raise ValueError("Cannot set baseline for empty URL")
        self.baselines[url] = response

    def get_baseline(self, url: str) -> Optional[str]:
        """Retrieve the baseline for a URL, or None if not captured."""
        return self.baselines.get(url)

    def has_surface(self, url: str) -> bool:
        """Check if a surface has been registered for this URL."""
        return url in self.surfaces

    def get_surface(self, url: str) -> Optional[Any]:
        """Retrieve a surface by URL, or None if not found."""
        return self.surfaces.get(url)

    def add_finding(self, finding: Finding) -> None:
        """Record a confirmed vulnerability produced by the analyzer."""
        if finding is None:
            raise ValueError("Cannot add None finding to session state")
        self.findings.append(finding)

    def add_adaptive_session(self, session: Any) -> None:
        """Record an AdaptiveSession produced by the adaptive engine."""
        if session is None:
            raise ValueError("Cannot add None adaptive session to session state")
        self.adaptive_sessions.append(session)

    def add_multi_turn_result(self, result: Any) -> None:
        """Record a MultiTurnResult produced by the multi-turn orchestrator."""
        if result is None:
            raise ValueError("Cannot add None multi-turn result to session state")
        self.multi_turn_results.append(result)

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    def findings_by_severity(self) -> List[Finding]:
        """Return findings sorted CRITICAL → INFO (most severe first)."""
        return sorted(self.findings, key=lambda f: f.severity.order)

    def summary(self) -> Dict[str, Any]:
        """
        High-level overview dict — written to the report header and printed
        to the terminal at the end of the scan.
        """
        from collections import Counter
        severity_counts = Counter(f.severity.value for f in self.findings)
        return {
            "target": self.target_url,
            "runtime_seconds": round(time.time() - self.start_time, 2),
            "surfaces_discovered": len(self.surfaces),
            "payloads_fired": len(self.results),
            "baselines_captured": len(self.baselines),
            "findings_total": len(self.findings),
            "findings_by_severity": dict(severity_counts),
        }