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
from typing import Dict, List, Optional

# These imports are inside the module — no circular dependency because
# findings.py and this file are siblings in core/.
from phantom.core.findings import Finding


# ---------------------------------------------------------------------------
# PayloadResult — raw result of one payload execution
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# SessionState — the shared mutable store for a full scan
# ---------------------------------------------------------------------------

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
        # Key = surface URL, value = ClassifiedSurface (imported lazily
        # to avoid a circular import chain at module level).
        self.surfaces: Dict[str, object] = {}

        # All raw payload execution results (one per payload per surface)
        self.results: List[PayloadResult] = []

        # Baseline (clean) responses captured before payload firing.
        # Key = surface URL, value = response body text.
        self.baselines: Dict[str, str] = {}

        # Confirmed findings produced by the analyzer layer.
        self.findings: List[Finding] = []

    # ------------------------------------------------------------------
    # Mutation helpers
    # ------------------------------------------------------------------

    def add_surface(self, surface: object) -> None:
        """
        Register a ClassifiedSurface in the session.
        Using the URL as key deduplicates re-visits to the same endpoint.
        """
        # Avoid importing ClassifiedSurface at the top to prevent circular
        # imports (classifier.py imports from core/, not the other way round).
        url = getattr(surface, "url", None) or getattr(surface, "fingerprint", {})
        if hasattr(url, "url"):
            url = url.url
        self.surfaces[str(url)] = surface

    def add_result(self, result: PayloadResult) -> None:
        """Append a raw payload result for later analysis."""
        self.results.append(result)

    def set_baseline(self, url: str, response: str) -> None:
        """
        Store the 'clean' response for a surface before any payloads are fired.
        The analyzer uses this as the reference to detect deviations.
        """
        self.baselines[url] = response

    def get_baseline(self, url: str) -> Optional[str]:
        """Retrieve the baseline for a URL, or None if not captured."""
        return self.baselines.get(url)

    def add_finding(self, finding: Finding) -> None:
        """Record a confirmed vulnerability produced by the analyzer."""
        self.findings.append(finding)

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    def findings_by_severity(self) -> List[Finding]:
        """Return findings sorted CRITICAL → INFO (most severe first)."""
        return sorted(self.findings, key=lambda f: f.severity.order)

    def summary(self) -> Dict:
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