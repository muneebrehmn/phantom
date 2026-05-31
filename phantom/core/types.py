"""
phantom/core/types.py

Shared type definitions for the Phantom framework.

Uses TypedDict to provide structure and type hints for common data patterns
across all modules without creating circular dependencies.

All type definitions live here so they can be imported by any module.
"""

from __future__ import annotations

from typing import TypedDict


class PayloadDict(TypedDict, total=False):
    """Complete payload structure from JSON payload files."""
    id: str
    text: str
    description: str
    success_pattern: str
    severity: str
    tags: list[str]
    model_targets: list[str]
    success_rate: float
    mitigation_difficulty: str


class FormFieldDict(TypedDict, total=False):
    """HTML form field definition."""
    name: str
    field_type: str
    value: str


class ResponseHeadersDict(TypedDict, total=False):
    """HTTP response headers as a dictionary."""
    content_type: str
    content_length: str
    server: str
    date: str
    cache_control: str
    set_cookie: str


class FindingDict(TypedDict, total=False):
    """Finding structure for vulnerability reports."""
    id: str
    vulnerability_type: str
    severity: str
    surface_url: str
    surface_type: str
    confidence: float
    payload_id: str
    payload_text: str
    response_preview: str
    description: str
    recommendation: str
    timestamp: float


class ScanSummaryDict(TypedDict, total=False):
    """High-level scan summary statistics."""
    target: str
    runtime_seconds: float
    surfaces_discovered: int
    payloads_fired: int
    baselines_captured: int
    findings_total: int
    findings_by_severity: dict[str, int]


class ClassifiedSurfaceDict(TypedDict, total=False):
    """Classified AI surface metadata."""
    url: str
    surface_type: str
    ai_confidence: float
    attack_vectors: list[str]
    request_method: str
    fingerprints: dict[str, float]
    page_title: str
    response_latency_ms: float


class ResponseSignalsDict(TypedDict, total=False):
    """Extracted signals from an LLM response."""
    response_is_refusal: bool
    contains_system_prompt: bool
    contains_role_confusion: bool
    contains_json_keys: list[str]
    response_latency_high: bool
    response_unexpectedly_short: bool
    status_code_rejection: bool
    pattern_matches: list[str]


class DiffResultDict(TypedDict, total=False):
    """Result of comparing baseline vs response."""
    similarity_score: float
    content_changed: bool
    size_ratio: float
    new_keys_detected: list[str]
    echo_detected: bool
    expansion_type: str
