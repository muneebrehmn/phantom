"""
phantom/report/html_builder.py

NIST SP 800-115 / PTES compliant interactive HTML report.

Mirrors the structure of the Markdown report but rendered as a
self-contained interactive HTML file:

  - Cover page with classification banner
  - Legal disclaimer
  - Executive summary with overall risk rating
  - CVSSv3.1 risk register table (sortable, filterable)
  - Per-finding expandable detail panels with:
      - CVSSv3.1 score + full vector breakdown
      - Attack path narrative
      - Payload, evidence, response snippet
      - Proof of concept (curl + Python) with copy button
      - Mitigation recommendations
  - Remediation roadmap (immediate / short / long term)
  - Methodology section
  - Appendix: discovered surfaces
  - Appendix: CVSS reference table

The file is fully self-contained (no external dependencies).
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from phantom.core.config import PhantomConfig
    from phantom.core.state import SessionState


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _escape_html(text: str) -> str:
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )

def _escape_js(text: str) -> str:
    return (
        str(text)
        .replace("\\", "\\\\")
        .replace("`", "\\`")
        .replace("$", "\\$")
        .replace("\n", "\\n")
        .replace("\r", "")
    )

def _sanitize_filename(url: str) -> str:
    return re.sub(r"[^\w\-_]", "_", url)[:50]

def _sev_color(sev: str) -> str:
    return {
        "critical": "#ef4444",
        "high":     "#f97316",
        "medium":   "#f59e0b",
        "low":      "#10b981",
        "info":     "#6366f1",
    }.get(sev.lower(), "#a0a0a0")

def _sev_icon(sev: str) -> str:
    return {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "🔵"}.get(sev.lower(), "⚪")


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def generate_html_report(config: "PhantomConfig", state: "SessionState") -> Path:
    from phantom.report.cvss import score_finding
    from phantom.analyzer.mitigation import MitigationAdvisor

    findings = state.findings_by_severity()
    summary  = state.summary()
    advisor  = MitigationAdvisor()

    # Attach CVSS scores
    for f in findings:
        cvss = score_finding(f.payload_category)
        f.cvss_vector     = cvss.vector_string
        f.cvss_base_score = cvss.base_score
        f.cvss_severity   = cvss.severity_label

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = (f.severity.value if hasattr(f.severity, "value") else str(f.severity)).lower()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    max_cvss   = max((f.cvss_base_score for f in findings), default=0.0)
    scan_date  = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    target     = config.target_url

    # Overall risk
    if sev_counts["critical"] > 0:
        risk_label = "CRITICAL RISK"
        risk_color = "#ef4444"
        risk_icon  = "🔴"
    elif sev_counts["high"] > 0:
        risk_label = "HIGH RISK"
        risk_color = "#f97316"
        risk_icon  = "🟠"
    elif sev_counts["medium"] > 0:
        risk_label = "MEDIUM RISK"
        risk_color = "#f59e0b"
        risk_icon  = "🟡"
    elif findings:
        risk_label = "LOW RISK"
        risk_color = "#10b981"
        risk_icon  = "🟢"
    else:
        risk_label = "NO FINDINGS"
        risk_color = "#6366f1"
        risk_icon  = "✅"

    finding_panels = _render_finding_panels(findings, advisor)
    risk_register  = _render_risk_register(findings)
    roadmap_html   = _render_roadmap(findings)
    surfaces_html  = _render_surfaces(state)
    cvss_ref_html  = _render_cvss_ref()

    html = _HTML_TEMPLATE.format(
        target=_escape_html(target),
        scan_date=scan_date,
        risk_label=risk_label,
        risk_color=risk_color,
        risk_icon=risk_icon,
        total_findings=len(findings),
        critical_count=sev_counts["critical"],
        high_count=sev_counts["high"],
        medium_count=sev_counts["medium"],
        low_count=sev_counts["low"],
        surfaces_count=len(list(state.surfaces.values())),
        payloads_fired=summary.get("payloads_fired", 0),
        max_cvss=max_cvss,
        runtime=summary.get("runtime_seconds", 0),
        risk_register=risk_register,
        finding_panels=finding_panels,
        roadmap_html=roadmap_html,
        surfaces_html=surfaces_html,
        cvss_ref_html=cvss_ref_html,
    )

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = config.output_dir / f"report_{_sanitize_filename(target)}_{ts}.html"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html, encoding="utf-8")
    return out


# ---------------------------------------------------------------------------
# Section renderers
# ---------------------------------------------------------------------------

def _render_risk_register(findings) -> str:
    if not findings:
        return "<p class='empty'>No findings above confidence threshold.</p>"

    rows = []
    for i, f in enumerate(findings):
        sev     = (f.severity.value if hasattr(f.severity, "value") else str(f.severity)).lower()
        icon    = _sev_icon(sev)
        color   = _sev_color(sev)
        cat     = _escape_html(f.payload_category)
        pid     = _escape_html(f.payload_id)
        conf    = f"{f.confidence:.0%}"
        cvss    = f.cvss_base_score
        cvss_sev= _escape_html(f.cvss_severity)
        vector  = _escape_html(f.cvss_vector)
        rows.append(f"""
        <tr data-severity="{sev}" onclick="jumpToFinding({i})">
            <td>{i+1}</td>
            <td><span class="sev-badge" style="background:{color}22;color:{color};border:1px solid {color}40">{icon} {sev.upper()}</span></td>
            <td><code>{pid}</code></td>
            <td>{cat}</td>
            <td><strong style="color:{color}">{cvss}</strong> <span class="cvss-sev">({cvss_sev})</span></td>
            <td><code class="vector-small">{vector}</code></td>
            <td>{conf}</td>
        </tr>""")

    return f"""
    <table class="register-table" id="riskTable">
        <thead>
            <tr>
                <th onclick="sortReg(0)">#</th>
                <th onclick="sortReg(1)">Severity</th>
                <th onclick="sortReg(2)">Finding ID</th>
                <th onclick="sortReg(3)">Category</th>
                <th onclick="sortReg(4)">CVSSv3.1</th>
                <th>Vector String</th>
                <th onclick="sortReg(6)">Confidence</th>
            </tr>
        </thead>
        <tbody>{"".join(rows)}</tbody>
    </table>"""


def _render_finding_panels(findings, advisor) -> str:
    if not findings:
        return "<p class='empty'>No findings to display.</p>"

    panels = []
    for i, f in enumerate(findings):
        from phantom.report.cvss import score_finding
        cvss    = score_finding(f.payload_category)
        sev     = (f.severity.value if hasattr(f.severity, "value") else str(f.severity)).lower()
        color   = _sev_color(sev)
        icon    = _sev_icon(sev)
        cat     = _escape_html(f.payload_category)
        payload = _escape_html(f.payload_text)
        resp    = _escape_html(str(f.raw_response)[:800])
        poc_curl= _escape_html(f.poc_curl)
        poc_py  = _escape_html(f.poc_python)
        ev_items= "".join(f"<li>{_escape_html(e)}</li>" for e in f.success_indicators)

        # CVSS table
        cvss_rows = ""
        for label, val in [
            ("Vector String",        f"<code>{cvss.vector_string}</code>"),
            ("Base Score",           f"<strong style='color:{color}'>{cvss.base_score} / 10.0</strong>"),
            ("Severity",             cvss.severity_label),
            ("Attack Vector",        cvss.attack_vector),
            ("Attack Complexity",    cvss.attack_complexity),
            ("Privileges Required",  cvss.privileges_required),
            ("User Interaction",     cvss.user_interaction),
            ("Scope",                cvss.scope),
            ("Confidentiality",      cvss.confidentiality_impact),
            ("Integrity",            cvss.integrity_impact),
            ("Availability",         cvss.availability_impact),
        ]:
            cvss_rows += f"<tr><td class='metric-label'>{label}</td><td>{val}</td></tr>"

        # Mitigation
        mit_report  = advisor.generate_mitigations(
            vulnerability_type=f.payload_category,
            severity=sev,
        )
        mit_items = []
        for rec in (mit_report.immediate_actions + mit_report.long_term_fixes)[:4]:
            mit_items.append(
                f"<div class='mit-item'>"
                f"<strong>{_escape_html(rec.title)}</strong> "
                f"<span class='mit-meta'>difficulty: {rec.difficulty} · effectiveness: {rec.effectiveness}</span>"
                f"<p>{_escape_html(rec.description)}</p>"
                f"</div>"
            )
        mit_html = "".join(mit_items) or "<p>Apply input validation and output filtering.</p>"

        panels.append(f"""
        <div class="finding-panel" id="finding-{i}" data-severity="{sev}">
            <div class="finding-header" onclick="togglePanel({i})" style="border-left:4px solid {color}">
                <div class="finding-title">
                    <span class="finding-num">#{i+1}</span>
                    <span class="sev-badge" style="background:{color}22;color:{color};border:1px solid {color}40">{icon} {sev.upper()}</span>
                    <code>{_escape_html(f.payload_id)}</code>
                    <span class="finding-cat">{cat}</span>
                </div>
                <div class="finding-meta">
                    CVSSv3.1: <strong style="color:{color}">{cvss.base_score}</strong> &nbsp;|&nbsp;
                    Confidence: {f.confidence:.0%} &nbsp;|&nbsp;
                    <code class="url-small">{_escape_html(f.surface_url)}</code>
                    <span class="chevron" id="chevron-{i}">▼</span>
                </div>
            </div>
            <div class="finding-body" id="panel-body-{i}" style="display:none">

                <div class="panel-grid">
                    <div class="panel-section">
                        <h4>CVSSv3.1 Risk Rating</h4>
                        <table class="cvss-table">
                            <tbody>{cvss_rows}</tbody>
                        </table>
                        <p class="rationale-note">ℹ️ {_escape_html(cvss.rationale)}</p>
                    </div>
                    <div class="panel-section">
                        <h4>Attack Path Narrative</h4>
                        <p class="narrative">
                            An unauthenticated attacker with network access to
                            <code>{_escape_html(f.surface_url)}</code> submitted a crafted
                            <strong>{cat}</strong> payload via the <strong>{_escape_html(f.surface_type)}</strong>
                            interface. The target processed the input without sufficient
                            validation and produced a response containing indicators of
                            successful injection. No special privileges or user interaction
                            were required. The attack was completed in a single HTTP request.
                        </p>
                        <h4 style="margin-top:16px">Evidence</h4>
                        <ul class="evidence-list">{ev_items}</ul>
                    </div>
                </div>

                <div class="panel-section full-width">
                    <h4>Payload Used</h4>
                    <pre class="code-block">{payload}</pre>
                </div>

                <div class="panel-section full-width">
                    <h4>Response Snippet</h4>
                    <pre class="code-block response-block">{resp}</pre>
                </div>

                <div class="panel-section full-width">
                    <h4>⚠️ Proof of Concept</h4>
                    <p class="poc-warning">Execute only against systems you are authorised to test.</p>
                    <div class="poc-tabs">
                        <button class="poc-tab active" onclick="switchTab({i}, 'curl', this)">curl</button>
                        <button class="poc-tab" onclick="switchTab({i}, 'python', this)">Python</button>
                    </div>
                    <div id="poc-curl-{i}" class="poc-content">
                        <pre class="code-block">{poc_curl}</pre>
                    </div>
                    <div id="poc-python-{i}" class="poc-content" style="display:none">
                        <pre class="code-block">{poc_py}</pre>
                    </div>
                    <button class="copy-btn" id="copy-{i}"
                        onclick='copyPoC({i}, "copy-{i}")'>📋 Copy PoC</button>
                </div>

                <div class="panel-section full-width">
                    <h4>Remediation</h4>
                    {mit_html}
                </div>

            </div>
        </div>""")

    return "\n".join(panels)


def _render_roadmap(findings) -> str:
    if not findings:
        return "<p class='empty'>No findings — no remediation actions required.</p>"

    seen  = set()
    imm   = []
    short = []

    for f in findings:
        if f.payload_category in seen:
            continue
        seen.add(f.payload_category)
        sev = (f.severity.value if hasattr(f.severity, "value") else str(f.severity)).lower()
        if sev in ("critical", "high"):
            imm.append(f)
        elif sev == "medium":
            short.append(f)

    _ACTIONS = {
        "system_prompt_leak": "Remove credentials from system prompt; add output filtering",
        "direct":             "Implement prompt firewall; validate and sanitize all user input",
        "jailbreak":          "Deploy output-side safety classifier; update system prompt constraints",
        "role_confusion":     "Enforce persona at API level; add role-lock instructions",
        "indirect":           "Sanitize all external content before LLM processing",
        "exfiltration":       "Add output monitoring; restrict model response scope",
    }

    def rows(items, color):
        out = []
        for i, f in enumerate(sorted(items, key=lambda x: x.cvss_base_score, reverse=True), 1):
            action = _ACTIONS.get(f.payload_category, "Apply input validation and output filtering")
            out.append(
                f"<tr><td>{i}</td>"
                f"<td><code>{_escape_html(f.payload_category)}</code></td>"
                f"<td><strong style='color:{color}'>{f.cvss_base_score}</strong></td>"
                f"<td>{_escape_html(action)}</td></tr>"
            )
        return "".join(out)

    imm_html = f"""
    <h4 style="color:#ef4444">🔴 Immediate (0–7 days)</h4>
    <table class="roadmap-table">
        <thead><tr><th>#</th><th>Category</th><th>CVSSv3.1</th><th>Action</th></tr></thead>
        <tbody>{rows(imm, "#ef4444")}</tbody>
    </table>""" if imm else ""

    short_html = f"""
    <h4 style="color:#f97316;margin-top:24px">🟠 Short-term (7–30 days)</h4>
    <table class="roadmap-table">
        <thead><tr><th>#</th><th>Category</th><th>CVSSv3.1</th><th>Action</th></tr></thead>
        <tbody>{rows(short, "#f97316")}</tbody>
    </table>""" if short else ""

    long_html = """
    <h4 style="color:#10b981;margin-top:24px">🟢 Long-term (30–90 days)</h4>
    <table class="roadmap-table">
        <thead><tr><th>Action</th><th>Standard</th></tr></thead>
        <tbody>
            <tr><td>Integrate Phantom into CI/CD pipeline for automated regression testing</td><td>NIST SP 800-115</td></tr>
            <tr><td>Conduct manual red-team assessment of all AI surfaces</td><td>PTES</td></tr>
            <tr><td>Adopt OWASP LLM Top 10 mitigations (LLM01–LLM10)</td><td>OWASP LLM Top 10</td></tr>
            <tr><td>Implement prompt firewall (Rebuff / Lakera Guard / custom)</td><td>—</td></tr>
            <tr><td>Establish quarterly AI security review cadence</td><td>NIST CSF</td></tr>
        </tbody>
    </table>"""

    return imm_html + short_html + long_html


def _render_surfaces(state) -> str:
    if not state.surfaces:
        return "<p class='empty'>No AI surfaces discovered.</p>"

    rows = []
    for url, surface in state.surfaces.items():
        fp      = getattr(surface, "fingerprint", None)
        stype   = getattr(surface, "surface_type", "unknown")
        conf    = getattr(fp, "confidence", None)
        label   = getattr(fp, "label", "unknown")
        vectors = getattr(surface, "attack_vectors", [])
        conf_str = f"{conf:.0%}" if isinstance(conf, float) else str(conf)
        vec_html = " ".join(f"<code class='vec-badge'>{v}</code>" for v in vectors)
        rows.append(
            f"<tr><td><code>{_escape_html(url)}</code></td>"
            f"<td>{_escape_html(stype)}</td>"
            f"<td>{conf_str}</td>"
            f"<td><code>{_escape_html(label)}</code></td>"
            f"<td>{vec_html}</td></tr>"
        )

    return f"""
    <table class="register-table">
        <thead><tr><th>URL</th><th>Type</th><th>AI Confidence</th><th>Label</th><th>Attack Vectors</th></tr></thead>
        <tbody>{"".join(rows)}</tbody>
    </table>"""


def _render_cvss_ref() -> str:
    from phantom.report.cvss import _CATEGORY_VECTORS
    rows = "".join(
        f"<tr><td><code>{cat}</code></td>"
        f"<td><code class='vector-small'>{r.vector_string}</code></td>"
        f"<td><strong>{r.base_score}</strong></td>"
        f"<td>{r.severity_label}</td>"
        f"<td>{_escape_html(r.rationale[:80])}…</td></tr>"
        for cat, r in sorted(_CATEGORY_VECTORS.items())
    )
    return f"""
    <table class="register-table">
        <thead><tr><th>Category</th><th>Vector String</th><th>Score</th><th>Severity</th><th>Rationale</th></tr></thead>
        <tbody>{rows}</tbody>
    </table>"""


# ---------------------------------------------------------------------------
# HTML template
# ---------------------------------------------------------------------------

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Phantom Security Report — {target}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0d0d1a;color:#d4d4e0;line-height:1.6;font-size:15px}}
a{{color:#7c8cf8}}
code{{font-family:'JetBrains Mono','Fira Code','Courier New',monospace;font-size:0.88em;background:#1a1a2e;padding:2px 6px;border-radius:4px}}
pre{{margin:0}}

/* Layout */
.container{{max-width:1300px;margin:0 auto;padding:24px}}
.section{{background:#13132a;border-radius:12px;padding:28px;margin-bottom:24px;border:1px solid #2a2a4a}}
.section h2{{font-size:1.3em;color:#a5b4fc;margin-bottom:16px;padding-bottom:10px;border-bottom:1px solid #2a2a4a;display:flex;align-items:center;gap:8px}}
.section h3{{font-size:1.1em;color:#c4b5fd;margin:20px 0 12px}}
.section h4{{font-size:0.95em;color:#93c5fd;margin:14px 0 8px}}

/* Classification banner */
.banner{{background:#7f1d1d;color:#fecaca;text-align:center;padding:10px;font-weight:700;font-size:0.9em;letter-spacing:2px;border-radius:8px;margin-bottom:20px}}

/* Header */
header{{background:linear-gradient(135deg,#1e1b4b 0%,#312e81 50%,#1e1b4b 100%);padding:36px;border-radius:12px;margin-bottom:24px;border:1px solid #4338ca40}}
header h1{{font-size:2em;color:#e0e7ff;margin-bottom:6px}}
.subtitle{{color:#a5b4fc;font-size:0.95em}}
.risk-badge{{display:inline-flex;align-items:center;gap:8px;padding:8px 20px;border-radius:8px;font-weight:700;font-size:1em;margin-top:14px;border:2px solid}}

/* Stats grid */
.stats-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:16px;margin-bottom:24px}}
.stat-card{{background:#13132a;padding:20px;border-radius:10px;border:1px solid #2a2a4a;text-align:center}}
.stat-label{{font-size:0.8em;color:#6b7280;margin-bottom:6px;text-transform:uppercase;letter-spacing:1px}}
.stat-value{{font-size:2em;font-weight:700;color:#fff}}
.stat-value.c{{color:#ef4444}}.stat-value.h{{color:#f97316}}.stat-value.m{{color:#f59e0b}}.stat-value.l{{color:#10b981}}
.stat-value.cvss{{font-size:1.5em;color:#a5b4fc}}

/* Disclaimer */
.disclaimer{{background:#1a0f0f;border:1px solid #7f1d1d40;border-left:4px solid #ef4444;padding:16px 20px;border-radius:8px;color:#fca5a5;font-size:0.9em;line-height:1.7}}

/* Controls */
.controls{{display:flex;gap:12px;flex-wrap:wrap;align-items:center;margin-bottom:16px}}
.search-box{{flex:1;min-width:220px;padding:10px 16px;background:#0d0d1a;border:2px solid #3730a3;border-radius:8px;color:#d4d4e0;font-size:0.95em}}
.filter-btn{{padding:8px 18px;background:#1e1b4b;border:1px solid #3730a3;border-radius:8px;color:#a5b4fc;cursor:pointer;font-size:0.88em;transition:all .2s}}
.filter-btn:hover,.filter-btn.active{{background:#3730a3;color:#fff}}

/* Risk register table */
.register-table{{width:100%;border-collapse:collapse;font-size:0.9em}}
.register-table thead{{background:#1e1b4b}}
.register-table th{{padding:12px 14px;text-align:left;color:#a5b4fc;font-weight:600;cursor:pointer;user-select:none}}
.register-table th:hover{{background:#312e81}}
.register-table td{{padding:11px 14px;border-bottom:1px solid #1e1e3a;vertical-align:middle}}
.register-table tbody tr{{cursor:pointer;transition:background .15s}}
.register-table tbody tr:hover{{background:#1e1b4b60}}
.sev-badge{{display:inline-block;padding:3px 10px;border-radius:20px;font-size:0.82em;font-weight:700;white-space:nowrap}}
.vector-small{{font-size:0.78em;color:#818cf8}}
.cvss-sev{{font-size:0.82em;color:#6b7280}}

/* Finding panels */
.finding-panel{{background:#13132a;border-radius:10px;margin-bottom:12px;overflow:hidden;border:1px solid #2a2a4a}}
.finding-header{{padding:16px 20px;cursor:pointer;transition:background .2s;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px}}
.finding-header:hover{{background:#1e1b4b40}}
.finding-title{{display:flex;align-items:center;gap:10px;flex-wrap:wrap}}
.finding-num{{color:#6b7280;font-weight:700;min-width:28px}}
.finding-cat{{color:#94a3b8;font-size:0.9em}}
.finding-meta{{color:#6b7280;font-size:0.85em;display:flex;align-items:center;gap:4px;flex-wrap:wrap}}
.url-small{{font-size:0.82em;color:#818cf8}}
.chevron{{color:#6b7280;font-size:0.8em;transition:transform .2s;margin-left:8px}}
.finding-body{{padding:20px;border-top:1px solid #2a2a4a}}
.panel-grid{{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:20px}}
@media(max-width:800px){{.panel-grid{{grid-template-columns:1fr}}}}
.panel-section{{background:#0d0d1a;border-radius:8px;padding:16px}}
.panel-section.full-width{{background:#0d0d1a;border-radius:8px;padding:16px;margin-bottom:12px}}
.cvss-table{{width:100%;font-size:0.88em;border-collapse:collapse}}
.cvss-table tr{{border-bottom:1px solid #1e1e3a}}
.cvss-table td{{padding:7px 10px}}
.metric-label{{color:#6b7280;width:45%}}
.rationale-note{{font-size:0.82em;color:#6b7280;margin-top:10px;font-style:italic}}
.narrative{{font-size:0.9em;color:#94a3b8;line-height:1.7}}
.evidence-list{{font-size:0.88em;color:#94a3b8;padding-left:18px;line-height:1.8}}
.code-block{{background:#050510;padding:14px;border-radius:8px;overflow-x:auto;font-family:'JetBrains Mono','Courier New',monospace;font-size:0.83em;color:#a5f3fc;white-space:pre-wrap;word-break:break-all}}
.response-block{{color:#86efac}}
.poc-warning{{font-size:0.85em;color:#f97316;margin-bottom:10px}}
.poc-tabs{{display:flex;gap:6px;margin-bottom:10px}}
.poc-tab{{padding:6px 16px;background:#1e1b4b;border:1px solid #3730a3;border-radius:6px;color:#a5b4fc;cursor:pointer;font-size:0.85em}}
.poc-tab.active{{background:#3730a3;color:#fff}}
.poc-content{{}}
.copy-btn{{margin-top:10px;padding:8px 18px;background:#065f46;border:1px solid #10b98140;border-radius:6px;color:#6ee7b7;cursor:pointer;font-size:0.88em;transition:all .2s}}
.copy-btn:hover{{background:#047857}}
.copy-btn.copied{{background:#3730a3;color:#c7d2fe}}
.mit-item{{background:#0d1a0d;border-left:3px solid #10b981;padding:10px 14px;border-radius:0 8px 8px 0;margin-bottom:10px}}
.mit-item strong{{color:#6ee7b7}}
.mit-item p{{font-size:0.88em;color:#94a3b8;margin-top:4px}}
.mit-meta{{font-size:0.8em;color:#6b7280;margin-left:8px}}

/* Roadmap */
.roadmap-table{{width:100%;border-collapse:collapse;font-size:0.9em;margin-bottom:8px}}
.roadmap-table th{{background:#1e1b4b;padding:10px 14px;text-align:left;color:#a5b4fc}}
.roadmap-table td{{padding:10px 14px;border-bottom:1px solid #1e1e3a;color:#94a3b8}}

/* Vec badges */
.vec-badge{{background:#1e3a5f;color:#93c5fd;padding:2px 8px;border-radius:4px;font-size:0.8em;margin:2px}}

/* Nav */
nav{{background:#13132a;border-radius:10px;padding:16px 20px;margin-bottom:24px;border:1px solid #2a2a4a}}
nav h3{{color:#a5b4fc;font-size:0.9em;margin-bottom:10px;text-transform:uppercase;letter-spacing:1px}}
.nav-links{{display:flex;flex-wrap:wrap;gap:8px}}
.nav-link{{padding:6px 14px;background:#1e1b4b;border-radius:6px;color:#a5b4fc;font-size:0.85em;cursor:pointer;border:1px solid #3730a340;transition:all .2s}}
.nav-link:hover{{background:#3730a3;color:#fff}}

/* Empty */
.empty{{color:#6b7280;font-style:italic;padding:16px 0}}

/* Footer */
footer{{margin-top:40px;padding:24px;text-align:center;color:#4b5563;border-top:1px solid #1e1e3a;font-size:0.85em}}
</style>
</head>
<body>
<div class="container">

<div class="banner">⚠ CONFIDENTIAL — FOR AUTHORISED PERSONNEL ONLY — PHANTOM SECURITY ASSESSMENT REPORT</div>

<header>
    <h1>👻 Phantom Security Report</h1>
    <div class="subtitle">NIST SP 800-115 / PTES Compliant Prompt Injection Assessment</div>
    <div class="subtitle" style="margin-top:6px">Target: <code>{target}</code> &nbsp;|&nbsp; {scan_date}</div>
    <div class="risk-badge" style="color:{risk_color};border-color:{risk_color}40;background:{risk_color}15">
        {risk_icon} Overall Risk: {risk_label}
    </div>
</header>

<nav>
    <h3>Navigation</h3>
    <div class="nav-links">
        <span class="nav-link" onclick="scrollTo('sec-disclaimer')">Disclaimer</span>
        <span class="nav-link" onclick="scrollTo('sec-summary')">Executive Summary</span>
        <span class="nav-link" onclick="scrollTo('sec-risk')">Risk Register</span>
        <span class="nav-link" onclick="scrollTo('sec-findings')">Findings</span>
        <span class="nav-link" onclick="scrollTo('sec-roadmap')">Remediation Roadmap</span>
        <span class="nav-link" onclick="scrollTo('sec-methodology')">Methodology</span>
        <span class="nav-link" onclick="scrollTo('sec-surfaces')">Surfaces</span>
        <span class="nav-link" onclick="scrollTo('sec-cvssref')">CVSS Reference</span>
    </div>
</nav>

<!-- Disclaimer -->
<div class="section" id="sec-disclaimer">
    <h2>⚠️ Legal Disclaimer</h2>
    <div class="disclaimer">
        This report was produced by an automated security assessment tool for <strong>authorised testing
        purposes only</strong>. All testing was conducted against systems for which explicit written
        permission was obtained prior to assessment. Unauthorised use of this tool or the techniques
        described herein against systems without permission is illegal and may result in civil and/or
        criminal liability.<br><br>
        Findings reflect the state of the target at the time of testing. This report is
        <strong>confidential</strong> and must be distributed only to authorised personnel.
        <em>Generated by Phantom — an academic security research tool. Not a substitute for
        professional penetration testing.</em>
    </div>
</div>

<!-- Executive Summary -->
<div class="section" id="sec-summary">
    <h2>📊 Executive Summary</h2>
    <div class="stats-grid">
        <div class="stat-card"><div class="stat-label">Total Findings</div><div class="stat-value">{total_findings}</div></div>
        <div class="stat-card"><div class="stat-label">Critical</div><div class="stat-value c">{critical_count}</div></div>
        <div class="stat-card"><div class="stat-label">High</div><div class="stat-value h">{high_count}</div></div>
        <div class="stat-card"><div class="stat-label">Medium</div><div class="stat-value m">{medium_count}</div></div>
        <div class="stat-card"><div class="stat-label">Low</div><div class="stat-value l">{low_count}</div></div>
        <div class="stat-card"><div class="stat-label">AI Surfaces</div><div class="stat-value">{surfaces_count}</div></div>
        <div class="stat-card"><div class="stat-label">Payloads Fired</div><div class="stat-value">{payloads_fired}</div></div>
        <div class="stat-card"><div class="stat-label">Max CVSSv3.1</div><div class="stat-value cvss">{max_cvss}</div></div>
        <div class="stat-card"><div class="stat-label">Runtime</div><div class="stat-value" style="font-size:1.3em">{runtime}s</div></div>
    </div>
</div>

<!-- Risk Register -->
<div class="section" id="sec-risk">
    <h2>🗂 Risk Register (CVSSv3.1)</h2>
    <div class="controls">
        <input type="text" class="search-box" id="regSearch" placeholder="🔍 Filter findings..." oninput="filterRegister()">
        <button class="filter-btn" onclick="filterBySev('all',this)">All</button>
        <button class="filter-btn" onclick="filterBySev('critical',this)">Critical</button>
        <button class="filter-btn" onclick="filterBySev('high',this)">High</button>
        <button class="filter-btn" onclick="filterBySev('medium',this)">Medium</button>
        <button class="filter-btn" onclick="filterBySev('low',this)">Low</button>
    </div>
    {risk_register}
</div>

<!-- Findings -->
<div class="section" id="sec-findings">
    <h2>🔍 Findings</h2>
    {finding_panels}
</div>

<!-- Remediation Roadmap -->
<div class="section" id="sec-roadmap">
    <h2>🛠 Remediation Roadmap</h2>
    <p style="color:#6b7280;font-size:0.9em;margin-bottom:16px">
        Prioritised per NIST SP 800-115 §6.4 and PTES, ordered by CVSSv3.1 base score.
    </p>
    {roadmap_html}
</div>

<!-- Methodology -->
<div class="section" id="sec-methodology">
    <h2>📋 Methodology</h2>
    <p style="color:#94a3b8;margin-bottom:16px">
        This assessment follows <strong>NIST SP 800-115</strong> (Technical Guide to Information
        Security Testing) adapted for LLM surfaces per <strong>OWASP LLM Top 10</strong>
        (LLM01: Prompt Injection).
    </p>
    <h3>Phase 1 — Discovery &amp; Crawl</h3>
    <p style="color:#94a3b8;font-size:0.9em">Async web crawler visits the target domain up to the configured depth, collecting links, HTML forms, and JS-referenced API endpoints. Scope is strictly enforced.</p>
    <h3>Phase 2 — AI Surface Fingerprinting</h3>
    <p style="color:#94a3b8;font-size:0.9em">Each URL is scored across four signal channels: URL pattern matching, JSON body key analysis, SSE/streaming detection, and latency profiling.</p>
    <h3>Phase 3 — Surface Classification</h3>
    <p style="color:#94a3b8;font-size:0.9em">Fingerprinted surfaces are categorised by type and assigned attack vectors per surface class.</p>
    <h3>Phase 4 — Payload Injection &amp; Analysis</h3>
    <p style="color:#94a3b8;font-size:0.9em">163 prompt injection payloads fired across 8 categories. Responses compared against clean baselines. Confirmed findings assigned CVSSv3.1 severity.</p>
</div>

<!-- Surfaces -->
<div class="section" id="sec-surfaces">
    <h2>🌐 Appendix A: Discovered Surfaces</h2>
    {surfaces_html}
</div>

<!-- CVSS Reference -->
<div class="section" id="sec-cvssref">
    <h2>📐 Appendix B: CVSSv3.1 Scoring Reference</h2>
    <p style="color:#6b7280;font-size:0.88em;margin-bottom:16px">
        Base scores computed per <a href="https://www.first.org/cvss/v3.1/specification-document" target="_blank">FIRST.org CVSSv3.1 specification</a>.
        Scores represent base scores only — temporal and environmental modifiers not applied.
    </p>
    {cvss_ref_html}
</div>

<footer>
    <p>Generated by <strong>Phantom v0.1</strong> — Prompt Injection Reconnaissance Framework</p>
    <p style="margin-top:6px">NIST SP 800-115 / PTES Compliant &nbsp;|&nbsp; CVSSv3.1 Scoring &nbsp;|&nbsp; {scan_date}</p>
    <p style="margin-top:6px;color:#374151">CONFIDENTIAL — For Authorised Personnel Only</p>
</footer>

</div>
<script>
let _pocMode = {{}};
let _regSev = 'all';
let _sortDir = {{}};
let _pocCurl = {{}};
let _pocPy = {{}};

function scrollTo(id){{document.getElementById(id).scrollIntoView({{behavior:'smooth',block:'start'}})}}

function togglePanel(i){{
    const body = document.getElementById('panel-body-'+i);
    const chev = document.getElementById('chevron-'+i);
    const open = body.style.display === 'block';
    body.style.display = open ? 'none' : 'block';
    chev.style.transform = open ? '' : 'rotate(180deg)';
}}

function jumpToFinding(i){{
    const panel = document.getElementById('finding-'+i);
    panel.scrollIntoView({{behavior:'smooth',block:'start'}});
    const body = document.getElementById('panel-body-'+i);
    if(body.style.display !== 'block')togglePanel(i);
}}

function switchTab(i, mode, btn){{
    _pocMode[i] = mode;
    document.getElementById('poc-curl-'+i).style.display = mode==='curl' ? '' : 'none';
    document.getElementById('poc-python-'+i).style.display = mode==='python' ? '' : 'none';
    btn.closest('.poc-tabs').querySelectorAll('.poc-tab').forEach(b=>b.classList.remove('active'));
    btn.classList.add('active');
}}

function copyPoC(i, btnId){{
    const mode = _pocMode[i] || 'curl';
    const src = document.getElementById('poc-'+mode+'-'+i).querySelector('pre');
    navigator.clipboard.writeText(src.textContent).then(()=>{{
        const btn = document.getElementById(btnId);
        btn.textContent = '✓ Copied!';
        btn.classList.add('copied');
        setTimeout(()=>{{btn.textContent='📋 Copy PoC';btn.classList.remove('copied')}},2000);
    }});
}}

function filterBySev(sev, btn){{
    _regSev = sev;
    document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));
    btn.classList.add('active');
    filterRegister();
    // Also filter finding panels
    document.querySelectorAll('.finding-panel').forEach(p=>{{
        p.style.display = (sev==='all' || p.dataset.severity===sev) ? '' : 'none';
    }});
}}

function filterRegister(){{
    const term = document.getElementById('regSearch').value.toLowerCase();
    document.querySelectorAll('#riskTable tbody tr').forEach(row=>{{
        const matchSev = _regSev==='all' || row.dataset.severity===_regSev;
        const matchTxt = row.textContent.toLowerCase().includes(term);
        row.style.display = matchSev && matchTxt ? '' : 'none';
    }});
}}

function sortReg(col){{
    const tbody = document.querySelector('#riskTable tbody');
    const rows = Array.from(tbody.rows);
    const dir = _sortDir[col] = !_sortDir[col];
    rows.sort((a,b)=>{{
        const av = a.cells[col]?.textContent.trim() || '';
        const bv = b.cells[col]?.textContent.trim() || '';
        const an = parseFloat(av), bn = parseFloat(bv);
        if(!isNaN(an) && !isNaN(bn)) return dir ? an-bn : bn-an;
        return dir ? av.localeCompare(bv) : bv.localeCompare(av);
    }});
    rows.forEach(r=>tbody.appendChild(r));
}}
</script>
</body>
</html>"""