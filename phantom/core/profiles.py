"""
phantom/core/profiles.py

Pre-configured scan profiles for common use cases.

Each profile is a named bundle of PhantomConfig overrides that sets sensible
defaults for a specific scenario (quick triage, stealth, bug bounty, etc.).

Usage (from CLI via --profile flag):
    python phantom.py scan https://target.com --profile quick
    python phantom.py scan https://target.com --profile stealth
    python phantom.py scan https://target.com --profile thorough

Usage (programmatic):
    from phantom.core.profiles import get_profile, list_profiles
    profile = get_profile("bug_bounty")
    overrides = profile.to_config_overrides()
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class ScanProfile:
    """
    A named scan profile — a bundle of PhantomConfig overrides.

    Only the fields that differ from PhantomConfig defaults are specified;
    the rest fall through to the PhantomConfig defaults unchanged.
    This means adding a new config field never breaks existing profiles.
    """

    name: str
    description: str

    # Crawl settings
    max_depth: Optional[int] = None
    max_pages: Optional[int] = None
    crawl_concurrency: Optional[int] = None
    respect_robots: Optional[bool] = None

    # Payload engine settings
    concurrency_limit: Optional[int] = None
    rate_limit_rps: Optional[float] = None
    request_timeout: Optional[float] = None

    # Payload categories to restrict to (None = all categories)
    payload_categories: Optional[list] = None

    # Analysis / output settings
    skip_baseline: bool = False
    report_formats: Optional[list] = None

    def to_config_overrides(self) -> dict:
        """
        Return a dict of non-None fields suitable for PhantomConfig(**overrides).
        Fields left as None are omitted so PhantomConfig defaults win.
        """
        overrides: dict = {}
        if self.max_depth is not None:
            overrides["max_depth"] = self.max_depth
        if self.max_pages is not None:
            overrides["max_pages"] = self.max_pages
        if self.crawl_concurrency is not None:
            overrides["crawl_concurrency"] = self.crawl_concurrency
            overrides["concurrency_limit"] = self.crawl_concurrency
        if self.respect_robots is not None:
            overrides["respect_robots"] = self.respect_robots
        if self.concurrency_limit is not None:
            # Don't override if crawl_concurrency already set it
            overrides.setdefault("concurrency_limit", self.concurrency_limit)
        if self.rate_limit_rps is not None:
            overrides["rate_limit_rps"] = self.rate_limit_rps
        if self.request_timeout is not None:
            overrides["request_timeout"] = self.request_timeout
        if self.report_formats is not None:
            overrides["report_formats"] = self.report_formats
        return overrides


# ---------------------------------------------------------------------------
# Built-in profiles
# ---------------------------------------------------------------------------

_PROFILES: dict[str, ScanProfile] = {

    "quick": ScanProfile(
        name="quick",
        description=(
            "Fast triage — shallow crawl, top-priority payloads only. "
            "Good for a first look at an unknown target."
        ),
        max_depth=2,
        max_pages=30,
        crawl_concurrency=8,
        concurrency_limit=8,
        rate_limit_rps=3.0,
        skip_baseline=True,
        payload_categories=["direct", "jailbreak"],
        report_formats=["markdown"],
    ),

    "stealth": ScanProfile(
        name="stealth",
        description=(
            "Low-and-slow — respects rate limits and robots.txt strictly. "
            "Minimises footprint; ideal for authorised assessments of production systems."
        ),
        max_depth=3,
        max_pages=50,
        crawl_concurrency=2,
        concurrency_limit=2,
        rate_limit_rps=0.25,        # One request every 4 seconds
        request_timeout=30.0,
        respect_robots=True,
        report_formats=["markdown", "json"],
    ),

    "thorough": ScanProfile(
        name="thorough",
        description=(
            "Deep, comprehensive scan — all categories, high concurrency, "
            "full baseline capture. Use for lab / staging environments."
        ),
        max_depth=6,
        max_pages=300,
        crawl_concurrency=10,
        concurrency_limit=10,
        rate_limit_rps=5.0,
        skip_baseline=False,
        payload_categories=None,    # All categories
        report_formats=["markdown", "json"],
    ),

    "bug_bounty": ScanProfile(
        name="bug_bounty",
        description=(
            "Optimised for bug-bounty submissions — balanced speed, focuses on "
            "high-impact categories, generates both Markdown and JSON reports."
        ),
        max_depth=4,
        max_pages=150,
        crawl_concurrency=5,
        concurrency_limit=5,
        rate_limit_rps=1.5,
        skip_baseline=False,
        payload_categories=[
            "direct",
            "jailbreak",
            "system_prompt_leak",
            "exfiltration",
            "tool_exploit",
        ],
        report_formats=["markdown", "json"],
    ),

    "api": ScanProfile(
        name="api",
        description=(
            "Targets REST / GraphQL API endpoints directly — skips HTML page "
            "crawling, focuses on injection and exfiltration payloads."
        ),
        max_depth=1,
        max_pages=20,
        crawl_concurrency=6,
        concurrency_limit=6,
        rate_limit_rps=2.0,
        skip_baseline=False,
        payload_categories=[
            "direct",
            "indirect",
            "exfiltration",
            "tool_exploit",
            "system_prompt_leak",
        ],
        report_formats=["json"],
    ),

    "research": ScanProfile(
        name="research",
        description=(
            "All 12 payload categories, generous timeouts, full baseline — "
            "designed for academic benchmarking and reproducible results."
        ),
        max_depth=5,
        max_pages=200,
        crawl_concurrency=4,
        concurrency_limit=4,
        rate_limit_rps=1.0,
        request_timeout=45.0,
        skip_baseline=False,
        payload_categories=None,    # All categories
        report_formats=["markdown", "json"],
    ),

    "ci": ScanProfile(
        name="ci",
        description=(
            "Continuous-integration friendly — very shallow, fast, "
            "exits cleanly with a JSON report for automated pipelines."
        ),
        max_depth=1,
        max_pages=10,
        crawl_concurrency=5,
        concurrency_limit=5,
        rate_limit_rps=5.0,
        skip_baseline=True,
        payload_categories=["direct", "jailbreak"],
        report_formats=["json"],
    ),

    "recon": ScanProfile(
        name="recon",
        description=(
            "Discovery-style — crawls broadly to map AI surfaces "
            "then fires only lightweight probe payloads to confirm LLM presence."
        ),
        max_depth=4,
        max_pages=200,
        crawl_concurrency=8,
        concurrency_limit=6,
        rate_limit_rps=2.0,
        skip_baseline=True,
        payload_categories=["direct", "role_confusion"],
        report_formats=["markdown"],
    ),
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_profile(name: str) -> ScanProfile:
    """
    Retrieve a profile by name.

    Raises:
        ValueError: if the name is not recognised.
    """
    name = name.lower().strip()
    if name not in _PROFILES:
        available = ", ".join(sorted(_PROFILES))
        raise ValueError(
            f"Unknown profile {name!r}. "
            f"Available profiles: {available}"
        )
    return _PROFILES[name]


def list_profiles() -> list:
    """Return all registered profiles sorted by name."""
    return sorted(_PROFILES.values(), key=lambda p: p.name)


def profile_names() -> list:
    """Return just the profile name strings (for argparse choices)."""
    return sorted(_PROFILES.keys())


def apply_profile(profile: ScanProfile, config_kwargs: dict) -> dict:
    """
    Merge a profile's overrides into an existing config kwargs dict.

    Profile values take precedence over CLI defaults but the caller
    can still pass explicit CLI overrides on top.

    Args:
        profile:       ScanProfile to apply.
        config_kwargs: dict of kwargs that will be passed to PhantomConfig().

    Returns:
        Updated dict with profile overrides merged in.
    """
    merged = dict(config_kwargs)
    merged.update(profile.to_config_overrides())
    return merged