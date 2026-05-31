"""
phantom/core/exceptions.py

Custom exception hierarchy for Phantom framework.

Enables specific exception handling throughout the pipeline and makes it easy
to distinguish Phantom errors from upstream library errors (httpx, json, etc.).

All Phantom exceptions inherit from PhantomException for catching at the top level.
Specific exceptions are raised in the modules where errors occur to enable
fine-grained error recovery and logging.
"""

from __future__ import annotations


class PhantomException(Exception):
    """Base exception for all Phantom framework errors."""

    pass


class ConfigurationError(PhantomException):
    """Configuration validation failed (bad values, conflicting settings)."""

    pass


class PayloadLoadError(PhantomException):
    """Failed to load or validate payload JSON file."""

    pass


class SurfaceClassificationError(PhantomException):
    """Surface fingerprinting or classification failed."""

    pass


class AnalysisError(PhantomException):
    """Response analysis or scoring failed."""

    pass


class CrawlerError(PhantomException):
    """URL crawling failed (network, parsing, etc.)."""

    pass


class EngineError(PhantomException):
    """Payload execution failed."""

    pass


class ReportError(PhantomException):
    """Report generation failed."""

    pass
