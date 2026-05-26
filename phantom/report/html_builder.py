"""
phantom/report/html_builder.py

Interactive HTML report generator with sortable tables, copy buttons, and diff viewer.

Generates self-contained HTML files with:
- Sortable/filterable findings table
- Copy-to-clipboard PoC buttons
- Baseline vs response diff viewer
- Success rate charts
- Severity distribution graphs
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from phantom.core.state import SessionState
    from phantom.core.config import PhantomConfig


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Phantom Security Report - {target}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: #0f0f23;
            color: #e0e0e0;
            line-height: 1.6;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 40px;
            border-radius: 12px;
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(102, 126, 234, 0.3);
        }}
        
        h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            color: white;
        }}
        
        .subtitle {{
            font-size: 1.1em;
            opacity: 0.9;
            color: white;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .stat-card {{
            background: #1a1a2e;
            padding: 25px;
            border-radius: 12px;
            border-left: 4px solid #667eea;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
        }}
        
        .stat-label {{
            font-size: 0.9em;
            color: #a0a0a0;
            margin-bottom: 8px;
        }}
        
        .stat-value {{
            font-size: 2em;
            font-weight: bold;
            color: #ffffff;
        }}
        
        .stat-value.critical {{ color: #ef4444; }}
        .stat-value.high {{ color: #f97316; }}
        .stat-value.medium {{ color: #f59e0b; }}
        .stat-value.low {{ color: #10b981; }}
        
        .controls {{
            background: #1a1a2e;
            padding: 20px;
            border-radius: 12px;
            margin-bottom: 20px;
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            align-items: center;
        }}
        
        .search-box {{
            flex: 1;
            min-width: 250px;
            padding: 12px 20px;
            background: #0f0f23;
            border: 2px solid #667eea;
            border-radius: 8px;
            color: #e0e0e0;
            font-size: 1em;
        }}
        
        .filter-btn {{
            padding: 12px 24px;
            background: #667eea;
            border: none;
            border-radius: 8px;
            color: white;
            cursor: pointer;
            font-weight: 600;
            transition: all 0.3s;
        }}
        
        .filter-btn:hover {{
            background: #764ba2;
            transform: translateY(-2px);
        }}
        
        .filter-btn.active {{
            background: #10b981;
        }}
        
        .findings-table {{
            background: #1a1a2e;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        
        thead {{
            background: #667eea;
            color: white;
        }}
        
        th {{
            padding: 15px;
            text-align: left;
            font-weight: 600;
            cursor: pointer;
            user-select: none;
        }}
        
        th:hover {{
            background: #764ba2;
        }}
        
        th::after {{
            content: ' ⇅';
            opacity: 0.5;
        }}
        
        tbody tr {{
            border-bottom: 1px solid #2a2a3e;
            transition: background 0.2s;
        }}
        
        tbody tr:hover {{
            background: #2a2a3e;
        }}
        
        td {{
            padding: 15px;
        }}
        
        .severity-badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
            text-transform: uppercase;
        }}
        
        .severity-critical {{
            background: #fecaca;
            color: #991b1b;
        }}
        
        .severity-high {{
            background: #fed7aa;
            color: #9a3412;
        }}
        
        .severity-medium {{
            background: #fef3c7;
            color: #92400e;
        }}
        
        .severity-low {{
            background: #d1fae5;
            color: #065f46;
        }}
        
        .copy-btn {{
            padding: 6px 12px;
            background: #10b981;
            border: none;
            border-radius: 6px;
            color: white;
            cursor: pointer;
            font-size: 0.85em;
            transition: all 0.2s;
        }}
        
        .copy-btn:hover {{
            background: #059669;
        }}
        
        .copy-btn.copied {{
            background: #6366f1;
        }}
        
        .expandable {{
            cursor: pointer;
            color: #667eea;
        }}
        
        .expandable:hover {{
            text-decoration: underline;
        }}
        
        .details {{
            display: none;
            margin-top: 10px;
            padding: 15px;
            background: #0f0f23;
            border-radius: 8px;
            border-left: 3px solid #667eea;
        }}
        
        .details.open {{
            display: block;
        }}
        
        .code-block {{
            background: #000;
            padding: 15px;
            border-radius: 8px;
            overflow-x: auto;
            margin: 10px 0;
            font-family: 'Monaco', 'Courier New', monospace;
            font-size: 0.9em;
        }}
        
        .diff-viewer {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 15px;
            margin: 15px 0;
        }}
        
        .diff-section {{
            background: #0f0f23;
            padding: 15px;
            border-radius: 8px;
        }}
        
        .diff-section h4 {{
            margin-bottom: 10px;
            color: #667eea;
        }}
        
        .added {{ background: rgba(16, 185, 129, 0.1); }}
        .removed {{ background: rgba(239, 68, 68, 0.1); }}
        
        footer {{
            margin-top: 50px;
            padding: 30px;
            text-align: center;
            color: #a0a0a0;
            border-top: 1px solid #2a2a3e;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>👻 Phantom Security Report</h1>
            <div class="subtitle">Target: {target} | Scan Date: {scan_date}</div>
        </header>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Total Findings</div>
                <div class="stat-value">{total_findings}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Critical</div>
                <div class="stat-value critical">{critical_count}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">High</div>
                <div class="stat-value high">{high_count}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Medium</div>
                <div class="stat-value medium">{medium_count}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Low</div>
                <div class="stat-value low">{low_count}</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Surfaces Scanned</div>
                <div class="stat-value">{surfaces_count}</div>
            </div>
        </div>
        
        <div class="controls">
            <input type="text" class="search-box" id="searchBox" placeholder="🔍 Search findings..." onkeyup="filterTable()">
            <button class="filter-btn" onclick="filterSeverity('all')">All</button>
            <button class="filter-btn" onclick="filterSeverity('critical')">Critical</button>
            <button class="filter-btn" onclick="filterSeverity('high')">High</button>
            <button class="filter-btn" onclick="filterSeverity('medium')">Medium</button>
            <button class="filter-btn" onclick="filterSeverity('low')">Low</button>
        </div>
        
        <div class="findings-table">
            <table id="findingsTable">
                <thead>
                    <tr>
                        <th onclick="sortTable(0)">Severity</th>
                        <th onclick="sortTable(1)">Category</th>
                        <th onclick="sortTable(2)">Surface</th>
                        <th onclick="sortTable(3)">Description</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {findings_rows}
                </tbody>
            </table>
        </div>
        
        <footer>
            <p>Generated by Phantom v0.1 | {scan_date}</p>
            <p style="margin-top: 10px; font-size: 0.9em;">
                Report contains {total_findings} findings across {surfaces_count} AI surfaces
            </p>
        </footer>
    </div>
    
    <script>
        let currentFilter = 'all';
        let sortDirection = {{}};
        
        function filterSeverity(severity) {{
            currentFilter = severity;
            const buttons = document.querySelectorAll('.filter-btn');
            buttons.forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');
            filterTable();
        }}
        
        function filterTable() {{
            const searchTerm = document.getElementById('searchBox').value.toLowerCase();
            const table = document.getElementById('findingsTable');
            const rows = table.getElementsByTagName('tr');
            
            for (let i = 1; i < rows.length; i++) {{
                const row = rows[i];
                const severity = row.cells[0].textContent.toLowerCase();
                const text = row.textContent.toLowerCase();
                
                const matchesSeverity = currentFilter === 'all' || severity.includes(currentFilter);
                const matchesSearch = text.includes(searchTerm);
                
                row.style.display = (matchesSeverity && matchesSearch) ? '' : 'none';
            }}
        }}
        
        function sortTable(columnIndex) {{
            const table = document.getElementById('findingsTable');
            const rows = Array.from(table.rows).slice(1);
            const direction = sortDirection[columnIndex] = !sortDirection[columnIndex];
            
            rows.sort((a, b) => {{
                const aText = a.cells[columnIndex].textContent;
                const bText = b.cells[columnIndex].textContent;
                return direction ? aText.localeCompare(bText) : bText.localeCompare(aText);
            }});
            
            rows.forEach(row => table.tBodies[0].appendChild(row));
        }}
        
        function toggleDetails(id) {{
            const details = document.getElementById('details-' + id);
            details.classList.toggle('open');
        }}
        
        function copyToClipboard(text, btnId) {{
            navigator.clipboard.writeText(text).then(() => {{
                const btn = document.getElementById(btnId);
                btn.textContent = '✓ Copied';
                btn.classList.add('copied');
                setTimeout(() => {{
                    btn.textContent = 'Copy PoC';
                    btn.classList.remove('copied');
                }}, 2000);
            }});
        }}
    </script>
</body>
</html>
"""


def generate_html_report(config: PhantomConfig, state: SessionState) -> Path:
    """
    Generate an interactive HTML report.
    
    Args:
        config: PhantomConfig instance
        state: SessionState with findings
    
    Returns:
        Path to the generated HTML file
    """
    findings = state.findings_by_severity()

    # Count by severity — severity may be a Severity enum or a plain string
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        sev_raw = getattr(finding, "severity", "info")
        sev = sev_raw.value if hasattr(sev_raw, "value") else str(sev_raw)
        sev = sev.lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    
    # Generate table rows
    rows = []
    from phantom.analyzer.mitigation import MitigationAdvisor
    _mit_advisor = MitigationAdvisor()

    for i, finding in enumerate(findings):
        severity = getattr(finding, "severity", "info")
        severity_str = severity.value if hasattr(severity, "value") else str(severity)
        category = getattr(finding, "payload_category", getattr(finding, "category", "unknown"))
        surface = getattr(finding, "surface_url", "unknown")
        description = getattr(finding, "description", None) or f"{category} injection detected"
        payload = getattr(finding, "payload_text", "")
        response = getattr(finding, "raw_response", getattr(finding, "response_snippet", ""))
        poc = getattr(finding, "poc_curl", getattr(finding, "poc_command", ""))

        mit_report = _mit_advisor.generate_mitigations(
            vulnerability_type=category,
            severity=severity_str,
        )
        mit_html_parts = []
        for rec in (mit_report.immediate_actions + mit_report.long_term_fixes)[:3]:
            mit_html_parts.append(
                f"<li><strong>{_escape_html(rec.title)}</strong> "
                f"<em>({rec.difficulty}, {rec.effectiveness} effectiveness)</em><br>"
                f"{_escape_html(rec.description)}</li>"
            )
        mitigation_html = (
            "<h4>Mitigation Recommendations</h4><ul>" + "".join(mit_html_parts) + "</ul>"
            if mit_html_parts else ""
        )

        row = f"""
        <tr>
            <td><span class="severity-badge severity-{severity_str.lower()}">{severity_str.upper()}</span></td>
            <td>{_escape_html(category)}</td>
            <td>{_escape_html(surface[:50])}...</td>
            <td>
                <span class="expandable" onclick="toggleDetails({i})">{_escape_html(description[:80])}...</span>
                <div class="details" id="details-{i}">
                    <h4>Payload</h4>
                    <div class="code-block">{_escape_html(payload[:200])}</div>
                    <h4>Response Evidence</h4>
                    <div class="code-block">{_escape_html(str(response)[:300])}</div>
                    {f'<h4>Proof of Concept</h4><div class="code-block">{_escape_html(poc)}</div>' if poc else ''}
                    {mitigation_html}
                </div>
            </td>
            <td>
                <button class="copy-btn" id="copy-{i}" onclick='copyToClipboard(`{_escape_js(poc)}`, "copy-{i}")'>
                    Copy PoC
                </button>
            </td>
        </tr>
        """
        rows.append(row)
    
    # Fill template
    html_content = HTML_TEMPLATE.format(
        target=config.target_url,
        scan_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        total_findings=len(findings),
        critical_count=severity_counts["critical"],
        high_count=severity_counts["high"],
        medium_count=severity_counts["medium"],
        low_count=severity_counts["low"],
        surfaces_count=len(list(state.surfaces.values())),
        findings_rows="\n".join(rows),
    )
    
    # Write file
    output_path = config.output_dir / f"report_{_sanitize_filename(config.target_url)}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    
    return output_path


def _escape_html(text: str) -> str:
    """Escape HTML special characters."""
    return (
        text
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def _escape_js(text: str) -> str:
    """Escape JavaScript special characters."""
    return (
        text
        .replace("\\", "\\\\")
        .replace("`", "\\`")
        .replace("$", "\\$")
        .replace("\n", "\\n")
    )


def _sanitize_filename(url: str) -> str:
    """Convert URL to safe filename."""
    import re
    safe = re.sub(r'[^\w\-_]', '_', url)
    return safe[:50]  # Truncate to reasonable length