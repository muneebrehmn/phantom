#!/usr/bin/env python3
"""
phantom.py — CLI entry point for the Phantom prompt injection framework.

The CLI exposes two commands:
  discover   — Crawl, fingerprint, and classify AI surfaces only (no payloads)
  scan       — Full pipeline: discover + inject payloads + analyze + report

Usage:
    python phantom.py discover https://target.example.com
    python phantom.py scan     https://target.example.com
    python phantom.py scan     https://target.example.com --depth 4 --verbose
    python phantom.py scan     https://target.example.com --output-dir ./results --formats markdown json

The 'discover' command is useful for a quick inventory of AI surfaces.
The 'scan' command is the full attack pipeline — use it for actual assessments.

Original code only had 'discover' and the attack/analyze/report chain was
completely disconnected.  This file wires the full pipeline together.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from phantom.core.config import PhantomConfig
from phantom.core.logger import get_logger, print_banner, print_section, setup_logging
from phantom.core.progress import ProgressTracker, reset_tracker
from phantom.core.profiles import apply_profile, get_profile, list_profiles, profile_names
from phantom.core.state import SessionState
from phantom.discovery.classifier import Classifier
from phantom.discovery.crawler import Crawler
from phantom.discovery.fingerprinter import fingerprint_all

log = get_logger(__name__)


# ---------------------------------------------------------------------------
# CLI argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phantom",
        description="Phantom — Prompt Injection Reconnaissance & Exploitation Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Quick surface discovery (no payloads):
    python phantom.py discover https://example.com

  Full injection scan with Markdown + JSON + HTML reports:
    python phantom.py scan https://example.com

  Deep scan, slower rate, verbose logging:
    python phantom.py scan https://example.com --depth 5 --rate 0.5 --verbose
        """,
    )

    # Sub-commands
    sub = parser.add_subparsers(dest="command", required=True)

    # --- discover: crawl + fingerprint + classify only ---
    disc = sub.add_parser(
        "discover",
        help="Crawl, fingerprint, and classify AI surfaces (no payload injection)"
    )
    _add_common_args(disc)

    # --- scan: full pipeline ---
    scan = sub.add_parser(
        "scan",
        help="Full scan: discover surfaces + inject payloads + analyze + report"
    )
    _add_common_args(scan)
    scan.add_argument(
        "--formats",
        nargs="+",
        default=["markdown", "json", "html"],
        choices=["markdown", "json", "html"],
        help="Report formats to generate (default: markdown json html)",
    )
    scan.add_argument(
        "--categories",
        nargs="+",
        default=None,
        help=(
            "Payload categories to use (default: all available). "
            "Options: direct jailbreak role_confusion system_prompt_leak indirect"
        ),
    )
    scan.add_argument(
        "--no-baseline",
        action="store_true",
        help="Skip baseline capture (faster but reduces analyzer accuracy)",
    )
    scan.add_argument(
        "--profile",
        default=None,
        choices=profile_names(),
        metavar="PROFILE",
        help=(
            "Pre-configured scan profile. Choices: "
            + ", ".join(profile_names())
            + ". Overrides depth/rate/category defaults. "
            "Individual flags (--depth, --rate, etc.) override the profile."
        ),
    )
    scan.add_argument(
        "--no-progress",
        action="store_true",
        help="Disable the live progress tracker (useful for CI / log files)",
    )
    scan.add_argument(
        "--list-profiles",
        action="store_true",
        help="Print all available scan profiles and exit",
    )

    # --- benchmark: test payloads against production LLMs ---
    bench = sub.add_parser(
        "benchmark",
        help="Test Phantom payloads against production LLMs (GPT-4, Claude, Gemini)"
    )
    bench.add_argument(
        "--models",
        nargs="+",
        required=True,
        help="Models to test (e.g., gpt-4 claude-3-opus-20240229 gemini-pro)",
    )
    bench.add_argument(
        "--categories",
        nargs="+",
        default=None,
        help="Payload categories to test (default: all available)",
    )
    bench.add_argument(
        "--concurrency",
        type=int,
        default=3,
        help="Max concurrent API requests (default: 3, keep low to avoid rate limits)",
    )
    bench.add_argument(
        "--output",
        default="benchmark_results",
        help="Output filename prefix (default: benchmark_results)",
    )
    bench.add_argument("--verbose", "-v", action="store_true", help="Debug-level logging")
    bench.add_argument("--no-color", action="store_true", help="Disable color output")

    return parser


def _add_common_args(sub_parser: argparse.ArgumentParser) -> None:
    """Add crawl / output args shared by both 'discover' and 'scan'."""
    sub_parser.add_argument("target", help="Target URL including scheme (https://...)")
    sub_parser.add_argument("--depth",     type=int,   default=3,     help="Crawl depth (default: 3)")
    sub_parser.add_argument("--max-pages", type=int,   default=100,   help="Max pages to crawl")
    sub_parser.add_argument("--concurrency", type=int, default=5,     help="Concurrent requests")
    sub_parser.add_argument("--rate",      type=float, default=1.0,   help="Requests per second")
    sub_parser.add_argument("--robots",    action="store_true",        help="Respect robots.txt (default: ignored — pentesters don't care about robots.txt)")
    sub_parser.add_argument("--verbose",   "-v", action="store_true",  help="Debug-level logging")
    sub_parser.add_argument("--no-color",  action="store_true",        help="Disable color output")
    sub_parser.add_argument(
        "--output-dir", type=Path, default=Path("phantom_output"),
        help="Directory for report files (default: ./phantom_output)"
    )
    sub_parser.add_argument(
        "--assume-ai-surface",
        action="store_true",
        help=(
            "Bypass fingerprinting and treat every crawled endpoint as a "
            "definite AI surface. Use this when scanning Flask/API chatbots "
            "whose HTTP responses lack OpenAI-style signals (SSE headers, "
            "JSON schema) but are known to be LLM-backed."
        ),
    )
    sub_parser.add_argument(
        "--insecure",
        action="store_true",
        help=(
            "Allow self-signed SSL certificates. Disables SSL verification. "
            "⚠️  Only use this when testing internal targets or development environments."
        ),
    )
    sub_parser.add_argument(
        "--ssl-cert",
        type=str,
        default="",
        help="Path to SSL certificate file (PEM format) for verifying the target's cert.",
    )

    # --- Authentication flags ---
    auth = sub_parser.add_argument_group(
        "authentication",
        "Pass credentials for targets that require auth. All flags are additive "
        "and can be combined (e.g. --auth-bearer with --auth-cookie).",
    )
    auth.add_argument(
        "--auth-header",
        metavar="NAME:VALUE",
        action="append",
        default=[],
        dest="auth_headers",
        help=(
            "Inject a raw HTTP header for every request. "
            "Format: 'Header-Name:value'. "
            "Repeat the flag for multiple headers. "
            "Example: --auth-header 'X-API-Key:secret123'"
        ),
    )
    auth.add_argument(
        "--auth-cookie",
        metavar="NAME=VALUE",
        action="append",
        default=[],
        dest="auth_cookies",
        help=(
            "Inject a session cookie for every request. "
            "Format: 'name=value'. "
            "Repeat the flag for multiple cookies. "
            "Example: --auth-cookie 'sessionid=abc123' --auth-cookie 'csrftoken=xyz'"
        ),
    )
    auth.add_argument(
        "--auth-bearer",
        metavar="TOKEN",
        default="",
        dest="auth_bearer",
        help=(
            "Set the Authorization: Bearer <TOKEN> header for every request. "
            "Shorthand for --auth-header 'Authorization:Bearer <TOKEN>'. "
            "Example: --auth-bearer eyJhbGciOiJSUzI1NiJ9..."
        ),
    )

    # --- Adaptive attack engine ---
    adapt = sub_parser.add_argument_group(
        "adaptive engine",
        "LLM-powered adaptive attack loop. Detects the target's defence mechanism "
        "and synthesises novel bypass payloads via the Anthropic API. "
        "Requires ANTHROPIC_API_KEY to be set.",
    )
    adapt.add_argument(
        "--adaptive",
        action="store_true",
        dest="adaptive_attack",
        help=(
            "Enable the adaptive attack engine. After static payload injection, "
            "Phantom will probe each surface, classify its defence, and use Claude "
            "to synthesise targeted bypass payloads iteratively."
        ),
    )
    adapt.add_argument(
        "--adaptive-rounds",
        type=int,
        default=3,
        metavar="N",
        dest="adaptive_max_rounds",
        help="Max synthesis rounds per surface (default: 3). Each round costs API calls.",
    )
    adapt.add_argument(
        "--adaptive-candidates",
        type=int,
        default=5,
        metavar="N",
        dest="adaptive_candidates_per_round",
        help="Bypass candidates synthesised per round (default: 5).",
    )


# ---------------------------------------------------------------------------
# Pipeline stage: DISCOVER
# Crawl → Fingerprint → Classify
# Returns a list of ClassifiedSurface objects and populates state.
# ---------------------------------------------------------------------------

async def run_discover(
    config: PhantomConfig,
    state: SessionState,
    tracker: ProgressTracker | None = None,
) -> list:
    """
    Run the discovery pipeline (Crawl → Fingerprint → Classify).

    Returns the list of ClassifiedSurface objects found, and registers
    each surface in the shared SessionState.

    This is also called internally by run_scan() — they share the same
    discovery logic so there is no code duplication.

    Args:
        config:  Shared PhantomConfig.
        state:   Shared SessionState.
        tracker: Optional ProgressTracker for live progress display.
    """
    print_section("PHASE 1 — CRAWL")
    crawler = Crawler(config)
    targets = await crawler.crawl()
    log.info("Crawl complete: %d URLs discovered", len(targets))

    if tracker:
        tracker.update_crawl(urls_done=len(targets), urls_total=len(targets))

    print_section("PHASE 2 — FINGERPRINT")
    fingerprints = await fingerprint_all(targets, config)
    ai_hits = [f for f in fingerprints if f.is_ai_surface]
    log.info(
        "Fingerprinting complete: %d/%d surfaces flagged as AI",
        len(ai_hits), len(fingerprints),
    )

    print_section("PHASE 3 — CLASSIFY")
    classifier = Classifier(config)
    surfaces = classifier.classify_all(fingerprints)

    if not surfaces:
        log.warning("No AI surfaces found. Try increasing --depth or adjusting scope.")
        return []

    # Register every classified surface in the shared state
    for surface in surfaces:
        state.add_surface(surface)
        if tracker:
            tracker.add_surface()
        log.info(
            "[surface]%s[/surface]  confidence=%.0f%%  type=%s  vectors=%s",
            surface.url,
            surface.ai_confidence * 100,
            surface.surface_type,
            ", ".join(surface.attack_vectors[:3]),
        )

    return surfaces


# ---------------------------------------------------------------------------
# Pipeline stage: ATTACK + ANALYZE
# For each surface: fire payloads → analyze results → record findings
# ---------------------------------------------------------------------------

async def run_attack(
    config: PhantomConfig,
    state: SessionState,
    surfaces: list,
    categories: list | None = None,
    skip_baseline: bool = False,
    tracker: ProgressTracker | None = None,
) -> None:
    """
    Run the injection + analysis pipeline for all discovered surfaces.

    For each surface:
      1. Load the relevant payloads from the library.
      2. Fire a baseline request (unless skip_baseline is True).
      3. Fire all payloads asynchronously.
      4. For each result: extract signals, run diff, score, emit Finding.

    Args:
        config         — shared PhantomConfig
        state          — shared SessionState (findings are written here)
        surfaces       — ClassifiedSurface objects from the discovery phase
        categories     — optional filter: only use these payload categories
        skip_baseline  — if True, skip baseline capture (faster, less accurate)
        tracker        — optional ProgressTracker for live display
    """
    # Import attack-layer modules here (not at top) to keep startup fast
    # for 'discover'-only runs which don't need these imports at all.
    from phantom.payloads.library import PayloadLibrary
    from phantom.payloads.engine import PayloadEngine
    from phantom.analyzer.response import ResponseAnalyzer
    from phantom.analyzer.diff import DiffAnalyzer
    from phantom.analyzer.scorer import InjectionScorer
    from phantom.analyzer.filter_bypass import FilterBypassAdvisor

    print_section("PHASE 4 — PAYLOAD INJECTION")

    # Initialize pipeline components (one instance shared across all surfaces)
    library  = PayloadLibrary()
    engine   = PayloadEngine(config, state)
    analyzer = ResponseAnalyzer()
    differ   = DiffAnalyzer()
    scorer   = InjectionScorer()
    advisor  = FilterBypassAdvisor()

    try:
        for surface in surfaces:
            log.info(
                "Attacking surface: [surface]%s[/surface] (%s)",
                surface.url, surface.surface_type,
            )

            # Load payloads appropriate for this surface's attack vectors.
            # attack_vectors comes from the classifier (e.g. ["direct", "jailbreak"])
            # and maps to payload JSON categories in the library.
            vectors = categories or surface.attack_vectors or ["direct"]
            all_payloads = []
            for vector in vectors:
                payloads = library.get_by_category(vector)
                if payloads:
                    log.debug("Loaded %d payloads for category '%s'", len(payloads), vector)
                    all_payloads.extend((vector, p) for p in payloads)
                else:
                    log.warning("No payloads found for category '%s'", vector)

            if not all_payloads:
                log.warning("No payloads loaded for %s — skipping", surface.url)
                continue

            # Tell tracker how many payloads we're about to fire
            if tracker:
                tracker.update_attack(
                    payloads_done=tracker.stats.payloads_fired,
                    payloads_total=tracker.stats.payloads_total + len(all_payloads),
                )

            # Baseline capture
            if not skip_baseline:
                await engine.fire_baseline(surface)

            # Fire payloads per category
            for category, payload in all_payloads:
                results = await engine.run(surface, [payload], category=category)

                # Analyze each raw result
                for raw_result in results:
                    if raw_result is None:
                        if tracker:
                            tracker.add_payload_fired(failed=True)
                        continue  # Request failed (timeout/error) — skip

                    if tracker:
                        tracker.add_payload_fired()

                    # Stage 1: Extract response signals
                    signals = analyzer.analyze(
                        raw_result,
                        baseline=state.get_baseline(surface.url),
                    )

                    # Stage 2: Baseline differential analysis
                    baseline_text = state.get_baseline(surface.url)
                    diff = differ.compare(
                        baseline=baseline_text or "",
                        response=raw_result.raw_response,
                        payload_text=raw_result.payload_text,
                    ) if baseline_text else None

                    # Stage 3: Score and (maybe) emit a Finding
                    finding = scorer.score(raw_result, signals, diff)
                    if finding:
                        state.add_finding(finding)
                        if tracker:
                            tracker.add_finding(
                                getattr(finding, "severity", "info")
                            )

                    # Stage 4: If the model refused, advise on bypass strategies
                    if signals.response_is_refusal:
                        recommendation = advisor.recommend(
                            surface.url, raw_result.raw_response
                        )
                        if recommendation.top_strategy:
                            log.info(
                                "Bypass advisor for %s → try: %s (%s)",
                                surface.url,
                                recommendation.top_strategy.name,
                                ", ".join(recommendation.top_strategy.payload_categories),
                            )

    finally:
        # Always close the HTTP client even if an exception occurs mid-scan
        await engine.close()


# ---------------------------------------------------------------------------
# Pipeline stage: REPORT
# ---------------------------------------------------------------------------

def run_report(config: PhantomConfig, state: SessionState) -> list:
    """
    Generate all configured report formats.

    Returns the list of Path objects for written report files.
    """
    from phantom.report.builder import ReportBuilder

    print_section("PHASE 5 — REPORT")
    builder = ReportBuilder(config, state)
    return builder.build()


# ---------------------------------------------------------------------------
# Top-level command runners
# ---------------------------------------------------------------------------

async def cmd_discover(config: PhantomConfig, show_progress: bool = True) -> None:
    """Entry point for the 'discover' sub-command (no attack, no report)."""
    state = SessionState(config.target_url)
    tracker = ProgressTracker(show_progress=show_progress)
    tracker.start()
    try:
        surfaces = await run_discover(config, state, tracker=tracker)
    finally:
        tracker.stop()

    print_section("DISCOVERED SURFACES")
    if not surfaces:
        log.warning("No AI surfaces found.")
    else:
        log.info("Found %d AI surface(s):", len(surfaces))
        for s in surfaces:
            log.info("  %s  [%s]  vectors=%s", s.url, s.surface_type, s.attack_vectors)


async def cmd_scan(
    config: PhantomConfig,
    categories: list | None,
    skip_baseline: bool,
    show_progress: bool = True,
) -> None:
    """
    Entry point for the 'scan' sub-command.
    Runs the complete pipeline: discover → attack → analyze → report.
    """
    state = SessionState(config.target_url)
    tracker = ProgressTracker(show_progress=show_progress)
    tracker.start()

    try:
        # Phase 1-3: Discovery
        surfaces = await run_discover(config, state, tracker=tracker)

        if not surfaces:
            log.warning("No AI surfaces to attack — scan complete.")
            return

        # Phase 4: Injection + analysis
        await run_attack(
            config, state, surfaces,
            categories=categories,
            skip_baseline=skip_baseline,
            tracker=tracker,
        )

        # Phase 4b: Multi-turn attack orchestration
        if not categories or "multi_turn" in categories:
            from phantom.payloads.orchestrator import run_multi_turn_attacks
            mt_surfaces = [s for s in surfaces if s.surface_type in
                           ("chatbox", "generic_ai", "ai_search")]
            if mt_surfaces:
                print_section("PHASE 4b -- MULTI-TURN ATTACKS")
                await run_multi_turn_attacks(
                    config=config,
                    state=state,
                    surfaces=mt_surfaces,
                )

        # Phase 4c: Adaptive attack (optional -- requires --adaptive + API key)
        if config.adaptive_attack:
            from phantom.payloads.adaptive import run_adaptive_attack
            print_section("PHASE 4c -- ADAPTIVE ATTACK")
            await run_adaptive_attack(
                config=config,
                state=state,
                surfaces=surfaces,
                max_rounds=config.adaptive_max_rounds,
                candidates_per_round=config.adaptive_candidates_per_round,
            )

        # Phase 5: Report generation
        written_files = run_report(config, state)

    finally:
        tracker.stop()
        reset_tracker()

    print_section("SCAN COMPLETE")
    for path in written_files:
        log.info("Report → %s", path.resolve())


async def cmd_benchmark(args) -> None:
    """
    Entry point for the 'benchmark' sub-command.
    
    Tests Phantom payloads against production LLMs and generates
    academic-quality benchmark results.
    """
    from phantom.benchmark import PhantomBenchmark
    
    print_section("PHANTOM BENCHMARK SUITE")
    log.info("Models: %s", ", ".join(args.models))
    if args.categories:
        log.info("Categories: %s", ", ".join(args.categories))
    else:
        log.info("Categories: ALL")
    log.info("Concurrency: %d", args.concurrency)
    log.info("")
    
    # Initialize benchmark
    benchmark = PhantomBenchmark(
        models=args.models,
        categories=args.categories,
        concurrency=args.concurrency,
    )
    
    # Run full suite
    try:
        aggregated = await benchmark.run_full_suite()
    except Exception as e:
        log.error("Benchmark failed: %s", e)
        import traceback
        traceback.print_exc()
        return
    
    # Export results
    json_path = f"{args.output}.json"
    md_path = f"{args.output}.md"
    
    benchmark.export_results(json_path)
    benchmark.generate_report(md_path, aggregated)
    
    print_section("BENCHMARK COMPLETE")
    log.info("Overall success rate: %.1f%% (%d/%d)", 
             aggregated.successful_tests / aggregated.total_tests * 100,
             aggregated.successful_tests,
             aggregated.total_tests)
    log.info("Results → %s", json_path)
    log.info("Report → %s", md_path)


def _parse_auth_args(args) -> tuple[dict[str, str], dict[str, str]]:
    """
    Parse --auth-header, --auth-cookie, and --auth-bearer CLI flags into
    dicts suitable for PhantomConfig.custom_headers and .session_cookies.

    Returns:
        (custom_headers, session_cookies) — both dicts, possibly empty.

    Raises:
        SystemExit: if any flag value is malformed (bad separator, empty name).
    """
    custom_headers: dict[str, str] = {}
    session_cookies: dict[str, str] = {}

    # --auth-bearer shorthand → Authorization header
    bearer = getattr(args, "auth_bearer", "")
    if bearer:
        custom_headers["Authorization"] = f"Bearer {bearer}"

    # --auth-header NAME:VALUE  (colon separator, first colon only)
    for raw in getattr(args, "auth_headers", []):
        if ":" not in raw:
            print(
                f"[phantom] ERROR: --auth-header value must be 'Name:Value', got: {raw!r}",
                file=sys.stderr,
            )
            sys.exit(1)
        name, _, value = raw.partition(":")
        name = name.strip()
        if not name:
            print(
                f"[phantom] ERROR: --auth-header has empty header name in: {raw!r}",
                file=sys.stderr,
            )
            sys.exit(1)
        custom_headers[name] = value

    # --auth-cookie NAME=VALUE  (equals separator, first equals only)
    for raw in getattr(args, "auth_cookies", []):
        if "=" not in raw:
            print(
                f"[phantom] ERROR: --auth-cookie value must be 'name=value', got: {raw!r}",
                file=sys.stderr,
            )
            sys.exit(1)
        name, _, value = raw.partition("=")
        name = name.strip()
        if not name:
            print(
                f"[phantom] ERROR: --auth-cookie has empty cookie name in: {raw!r}",
                file=sys.stderr,
            )
            sys.exit(1)
        session_cookies[name] = value

    return custom_headers, session_cookies


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    # Handle --list-profiles before any other setup
    if getattr(args, "list_profiles", False):
        print("\nAvailable Phantom scan profiles:\n")
        for profile in list_profiles():
            print(f"  {profile.name:<14} {profile.description}")
        print()
        sys.exit(0)

    # Set up logging before anything else (controls verbosity globally)
    setup_logging(verbose=args.verbose, no_color=getattr(args, "no_color", False))
    print_banner()

    # --- Handle benchmark command (no config needed, different flow) ---
    if args.command == "benchmark":
        asyncio.run(cmd_benchmark(args))
        return

    # --- Build base config kwargs from CLI args (for discover/scan) ---
    custom_headers, session_cookies = _parse_auth_args(args)

    config_kwargs = dict(
        max_depth=args.depth,
        max_pages=args.max_pages,
        crawl_concurrency=args.concurrency,
        concurrency_limit=args.concurrency,
        rate_limit_rps=args.rate,
        respect_robots=getattr(args, "robots", False),  # off by default — robots.txt is for crawlers, not scanners
        output_dir=args.output_dir,
        verbose=args.verbose,
        no_color=args.no_color,
        report_formats=getattr(args, "formats", ["markdown", "json"]),
        assume_ai_surface=getattr(args, "assume_ai_surface", False),
        allow_self_signed=getattr(args, "insecure", False),
        ssl_cert_path=getattr(args, "ssl_cert", ""),
        custom_headers=custom_headers,
        session_cookies=session_cookies,
        adaptive_attack=getattr(args, "adaptive_attack", False),
        adaptive_max_rounds=getattr(args, "adaptive_max_rounds", 3),
        adaptive_candidates_per_round=getattr(args, "adaptive_candidates_per_round", 5),
    )

    # Log auth summary (names only — never log credential values)
    if custom_headers:
        log.info("Auth headers active: %s", ", ".join(custom_headers.keys()))
    if session_cookies:
        log.info("Auth cookies active: %s", ", ".join(session_cookies.keys()))

    # Warn if using insecure mode
    if getattr(args, "insecure", False):
        log.warning("⚠️  SSL verification DISABLED (--insecure). Only use for internal/development targets.")

    # --- Apply profile overrides (profile < explicit CLI flags) ---
    # Strategy: apply profile first, then re-apply any explicitly set CLI
    # flags so the user can always override a profile's defaults.
    profile_name = getattr(args, "profile", None)
    categories = getattr(args, "categories", None)
    skip_baseline = getattr(args, "no_baseline", False)
    show_progress = not getattr(args, "no_progress", False)

    if profile_name:
        profile = get_profile(profile_name)
        log.info("Using profile: %s — %s", profile.name, profile.description)

        # Build profile-overridden kwargs, then re-apply explicit CLI values
        # so that e.g. `--profile quick --depth 5` uses depth=5 not depth=2.
        config_kwargs = apply_profile(profile, config_kwargs)

        # Inherit profile categories/skip_baseline if user didn't set them
        if categories is None and profile.payload_categories:
            categories = profile.payload_categories
        if not skip_baseline and profile.skip_baseline:
            skip_baseline = profile.skip_baseline

    # Build the final config
    config = PhantomConfig(**config_kwargs).with_target(args.target)

    # Dispatch to the correct async command
    if args.command == "discover":
        asyncio.run(cmd_discover(config, show_progress=show_progress))

    elif args.command == "scan":
        asyncio.run(
            cmd_scan(
                config,
                categories=categories,
                skip_baseline=skip_baseline,
                show_progress=show_progress,
            )
        )

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()