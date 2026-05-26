"""
phantom/core/logger.py

Centralized logger for Phantom. Wraps Python's stdlib logging with a Rich
handler for styled console output and an optional plain-text file handler.

All modules get a child logger via `get_logger(__name__)` — the hierarchy
means you can silence discovery.* or enable debug for a single module
without touching anything else.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme

# ---------------------------------------------------------------------------
# Theme — keeps colors consistent with the rest of the Rich UI
# ---------------------------------------------------------------------------

PHANTOM_THEME = Theme(
    {
        "logging.level.debug": "dim cyan",
        "logging.level.info": "green",
        "logging.level.warning": "yellow",
        "logging.level.error": "bold red",
        "logging.level.critical": "bold white on red",
        # Phantom-specific markup tags used in log messages
        "finding": "bold magenta",
        "surface": "bold cyan",
        "payload": "bold yellow",
        "url": "underline blue",
        "score.critical": "bold red",
        "score.high": "red",
        "score.medium": "yellow",
        "score.low": "green",
        "score.info": "dim white",
    }
)

_console = Console(theme=PHANTOM_THEME, stderr=True)
_root_logger_name = "phantom"
_initialized = False


def setup_logging(
    verbose: bool = False,
    no_color: bool = False,
    log_file: Optional[Path] = None,
) -> None:
    """
    Call once at CLI startup. Idempotent — safe to call multiple times
    (subsequent calls are no-ops unless force=True is added later).
    """
    global _initialized, _console

    if _initialized:
        return

    if no_color:
        _console = Console(no_color=True, stderr=True)

    level = logging.DEBUG if verbose else logging.INFO

    root = logging.getLogger(_root_logger_name)
    root.setLevel(level)
    root.handlers.clear()

    # --- Rich console handler ---
    rich_handler = RichHandler(
        console=_console,
        show_time=True,
        show_path=verbose,           # show file:line only in verbose mode
        rich_tracebacks=True,
        tracebacks_show_locals=verbose,
        markup=True,                 # allow [bold red]...[/] in log messages
        log_time_format="[%H:%M:%S]",
    )
    rich_handler.setLevel(level)
    root.addHandler(rich_handler)

    # --- Optional plain-text file handler (no ANSI codes) ---
    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)  # always full detail in file
        file_handler.setFormatter(
            logging.Formatter(
                fmt="%(asctime)s [%(levelname)-8s] %(name)s: %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        root.addHandler(file_handler)

    # Silence noisy third-party loggers
    for noisy in ("httpx", "httpcore", "asyncio", "urllib3", "charset_normalizer"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    _initialized = True


def get_logger(name: str) -> logging.Logger:
    """
    Return a child logger under the phantom.* hierarchy.

    Usage:
        from phantom.core.logger import get_logger
        log = get_logger(__name__)
        log.info("Crawling [url]%s[/url]", target)
    """
    if not name.startswith(_root_logger_name):
        # Allow callers to pass __name__ directly; wrap if needed
        name = f"{_root_logger_name}.{name.lstrip('.')}"
    return logging.getLogger(name)


# ---------------------------------------------------------------------------
# Convenience wrappers used by the CLI for structured status output
# These are thin so callers don't import Rich directly.
# ---------------------------------------------------------------------------

def print_banner() -> None:
    _console.print(
        "\n[bold magenta]  ██████╗ ██╗  ██╗ █████╗ ███╗  ██╗████████╗ ██████╗ ███╗  ███╗[/]\n"
        "[bold magenta]  ██╔══██╗██║  ██║██╔══██╗████╗ ██║╚══██╔══╝██╔═══██╗████╗████║[/]\n"
        "[bold magenta]  ██████╔╝███████║███████║██╔██╗██║   ██║   ██║   ██║██╔████╔██║[/]\n"
        "[bold magenta]  ██╔═══╝ ██╔══██║██╔══██║██║╚████║   ██║   ██║   ██║██║╚██╔╝██║[/]\n"
        "[bold magenta]  ██║     ██║  ██║██║  ██║██║ ╚███║   ██║   ╚██████╔╝██║ ╚═╝ ██║[/]\n"
        "[bold magenta]  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝[/]\n"
        "[dim]  Prompt Injection Exploitation Framework  •  v0.1[/]\n"
    )


def print_section(title: str) -> None:
    _console.rule(f"[bold cyan]{title}[/]")


def print_finding(severity: str, message: str) -> None:
    tag = f"score.{severity.lower()}"
    _console.print(f"  [[{tag}]{severity.upper()}[/{tag}]] [finding]{message}[/finding]")


def print_surface(surface_type: str, url: str) -> None:
    _console.print(f"  [surface]{surface_type}[/surface] → [url]{url}[/url]")