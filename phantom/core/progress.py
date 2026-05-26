"""
phantom/core/progress.py

Live progress tracking and statistics display for Phantom scans.

Provides real-time feedback during long-running scans:
- Progress bars for crawling, fingerprinting, attacking
- Live counters for discovered surfaces, payloads fired, findings
- ETA calculations
- Colorful terminal output using rich library

This module integrates with the existing logger.py to provide enhanced
UX without breaking the current logging system.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskID,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.table import Table

console = Console()


@dataclass
class ScanStats:
    """
    Live statistics for a running scan.
    Updated by the pipeline as it progresses.
    """
    start_time: float = field(default_factory=time.time)
    
    # Discovery phase
    urls_crawled: int = 0
    urls_total: int = 0
    surfaces_discovered: int = 0
    
    # Attack phase
    payloads_fired: int = 0
    payloads_total: int = 0
    payloads_failed: int = 0
    
    # Analysis phase
    findings_total: int = 0
    findings_critical: int = 0
    findings_high: int = 0
    findings_medium: int = 0
    findings_low: int = 0
    findings_info: int = 0
    
    @property
    def elapsed_seconds(self) -> float:
        return time.time() - self.start_time
    
    @property
    def elapsed_formatted(self) -> str:
        seconds = int(self.elapsed_seconds)
        mins, secs = divmod(seconds, 60)
        hours, mins = divmod(mins, 60)
        if hours > 0:
            return f"{hours}h {mins}m {secs}s"
        elif mins > 0:
            return f"{mins}m {secs}s"
        else:
            return f"{secs}s"


class ProgressTracker:
    """
    Manages live progress display during scans.
    
    Usage:
        tracker = ProgressTracker()
        tracker.start()
        
        # Update as scan progresses
        tracker.update_crawl(urls_done=10, urls_total=50)
        tracker.add_surface()
        tracker.add_payload_fired()
        tracker.add_finding("critical")
        
        tracker.stop()
    """
    
    def __init__(self, show_progress: bool = True) -> None:
        self.show_progress = show_progress
        self.stats = ScanStats()
        
        # Progress bars
        self.progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(complete_style="green", finished_style="bold green"),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            console=console,
        )
        
        self.crawl_task: Optional[TaskID] = None
        self.attack_task: Optional[TaskID] = None
        
        self.live: Optional[Live] = None
    
    def start(self) -> None:
        """Initialize and display the live progress tracker."""
        if not self.show_progress:
            return
        
        self.stats.start_time = time.time()
        
        # Create live display
        self.live = Live(
            self._render_display(),
            console=console,
            refresh_per_second=2,
            transient=False,
        )
        self.live.start()
    
    def stop(self) -> None:
        """Stop the live display and print final summary."""
        if not self.show_progress or not self.live:
            return
        
        self.live.stop()
        
        # Print final summary
        self._print_final_summary()
    
    def update_crawl(self, urls_done: int, urls_total: int) -> None:
        """Update crawl progress."""
        self.stats.urls_crawled = urls_done
        self.stats.urls_total = urls_total
        
        if self.show_progress and self.live:
            self.live.update(self._render_display())
    
    def update_attack(self, payloads_done: int, payloads_total: int) -> None:
        """Update attack progress."""
        self.stats.payloads_fired = payloads_done
        self.stats.payloads_total = payloads_total
        
        if self.show_progress and self.live:
            self.live.update(self._render_display())
    
    def add_surface(self) -> None:
        """Increment discovered surfaces counter."""
        self.stats.surfaces_discovered += 1
        if self.show_progress and self.live:
            self.live.update(self._render_display())
    
    def add_payload_fired(self, failed: bool = False) -> None:
        """Increment payload counter."""
        self.stats.payloads_fired += 1
        if failed:
            self.stats.payloads_failed += 1
        if self.show_progress and self.live:
            self.live.update(self._render_display())
    
    def add_finding(self, severity) -> None:
        """Add a finding with the given severity (str or Severity enum)."""
        self.stats.findings_total += 1

        severity_lower = severity.value if hasattr(severity, "value") else str(severity)
        severity_lower = severity_lower.lower()
        if severity_lower == "critical":
            self.stats.findings_critical += 1
        elif severity_lower == "high":
            self.stats.findings_high += 1
        elif severity_lower == "medium":
            self.stats.findings_medium += 1
        elif severity_lower == "low":
            self.stats.findings_low += 1
        else:
            self.stats.findings_info += 1
        
        if self.show_progress and self.live:
            self.live.update(self._render_display())
    
    def _render_display(self) -> Panel:
        """Render the live display panel."""
        # Stats table
        table = Table.grid(padding=(0, 2))
        table.add_column(style="cyan", justify="right")
        table.add_column(style="white")
        
        # Discovery stats
        table.add_row("URLs Crawled:", f"{self.stats.urls_crawled}")
        table.add_row("Surfaces Found:", f"[green]{self.stats.surfaces_discovered}[/green]")
        table.add_row("", "")
        
        # Attack stats
        if self.stats.payloads_total > 0:
            success_rate = (
                (self.stats.payloads_fired - self.stats.payloads_failed) 
                / self.stats.payloads_fired * 100
                if self.stats.payloads_fired > 0 else 0
            )
            table.add_row(
                "Payloads Fired:",
                f"{self.stats.payloads_fired} ({success_rate:.0f}% success)"
            )
        
        # Findings stats
        if self.stats.findings_total > 0:
            table.add_row("", "")
            table.add_row("Findings:", f"[bold]{self.stats.findings_total}[/bold]")
            
            if self.stats.findings_critical > 0:
                table.add_row("  Critical:", f"[bold red]{self.stats.findings_critical}[/bold red]")
            if self.stats.findings_high > 0:
                table.add_row("  High:", f"[red]{self.stats.findings_high}[/red]")
            if self.stats.findings_medium > 0:
                table.add_row("  Medium:", f"[yellow]{self.stats.findings_medium}[/yellow]")
            if self.stats.findings_low > 0:
                table.add_row("  Low:", f"[green]{self.stats.findings_low}[/green]")
            if self.stats.findings_info > 0:
                table.add_row("  Info:", f"[blue]{self.stats.findings_info}[/blue]")
        
        table.add_row("", "")
        table.add_row("Elapsed Time:", self.stats.elapsed_formatted)
        
        return Panel(
            table,
            title="[bold cyan]Phantom Scan Progress[/bold cyan]",
            border_style="cyan",
        )
    
    def _print_final_summary(self) -> None:
        """Print final summary after scan completes."""
        console.print("\n")
        console.rule("[bold green]Scan Complete[/bold green]")
        
        # Summary table
        summary = Table(show_header=False, box=None, padding=(0, 2))
        summary.add_column(style="cyan bold", justify="right")
        summary.add_column(style="white")
        
        summary.add_row("Total Runtime:", self.stats.elapsed_formatted)
        summary.add_row("URLs Crawled:", str(self.stats.urls_crawled))
        summary.add_row("AI Surfaces:", str(self.stats.surfaces_discovered))
        summary.add_row("Payloads Fired:", str(self.stats.payloads_fired))
        
        if self.stats.findings_total > 0:
            summary.add_row("", "")
            summary.add_row(
                "Total Findings:",
                f"[bold]{self.stats.findings_total}[/bold]"
            )
            
            breakdown = []
            if self.stats.findings_critical > 0:
                breakdown.append(f"[bold red]{self.stats.findings_critical} CRITICAL[/bold red]")
            if self.stats.findings_high > 0:
                breakdown.append(f"[red]{self.stats.findings_high} HIGH[/red]")
            if self.stats.findings_medium > 0:
                breakdown.append(f"[yellow]{self.stats.findings_medium} MEDIUM[/yellow]")
            if self.stats.findings_low > 0:
                breakdown.append(f"[green]{self.stats.findings_low} LOW[/green]")
            
            if breakdown:
                summary.add_row("", " | ".join(breakdown))
        else:
            summary.add_row("", "")
            summary.add_row("Findings:", "[dim]No vulnerabilities detected[/dim]")
        
        console.print(summary)
        console.print()


# Global singleton instance
_global_tracker: Optional[ProgressTracker] = None


def get_tracker(create: bool = True) -> Optional[ProgressTracker]:
    """Get or create the global progress tracker."""
    global _global_tracker
    if _global_tracker is None and create:
        _global_tracker = ProgressTracker()
    return _global_tracker


def reset_tracker() -> None:
    """Reset the global tracker (for tests)."""
    global _global_tracker
    if _global_tracker and _global_tracker.live:
        _global_tracker.stop()
    _global_tracker = None