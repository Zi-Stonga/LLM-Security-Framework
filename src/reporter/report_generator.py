"""Report generation from classified AttackResult lists.

Provides two pure functions with no side effects:
- generate_json_report: produces a structured JSON string
- generate_html_report: produces an HTML document string

Neither function writes to disk or any external service.
"""
from __future__ import annotations

import json
from datetime import datetime
from datetime import timezone
from typing import Dict
from typing import List
from typing import Tuple

from src.runner.attack_runner import AttackResult

_SEVERITY_ORDER: Tuple[str, ...] = ("critical", "high", "medium", "low", "none")

_SEVERITY_COLOURS: Dict[str, str] = {
    "critical": "#C00000",
    "high": "#E65C00",
    "medium": "#CC8800",
    "low": "#2980B9",
    "none": "#888",
}


def generate_json_report(
    results: List[AttackResult],
    run_id: str = "",
) -> str:
    """Generate a structured JSON security report from classified results.

    Args:
        results: List of classified AttackResult instances.
        run_id: Optional run identifier. Defaults to a UTC timestamp.

    Returns:
        Formatted JSON string with summary and findings sections.
    """
    counts = _count_by_severity(results)
    total = len(results)
    passed = sum(1 for r in results if r.verdict == "passed")
    failed = sum(1 for r in results if r.verdict == "failed")
    errors = sum(1 for r in results if r.verdict == "error")

    report = {
        "run_id": run_id or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_attacks": total,
            "passed": passed,
            "failed": failed,
            "errors": errors,
            "pass_rate_pct": round(passed / total * 100, 1) if total else 0.0,
            "severity_breakdown": counts,
        },
        "findings": [
            {
                "category": r.attack.category,
                "technique": r.attack.technique,
                "verdict": r.verdict,
                "severity": r.severity,
                "evidence": r.evidence,
                "latency_ms": round(r.latency_ms, 1),
            }
            for r in results
            if r.vulnerability_found
        ],
    }
    return json.dumps(report, indent=2)


def generate_html_report(
    results: List[AttackResult],
    run_id: str = "",
) -> str:
    """Generate an HTML security report from classified results.

    Args:
        results: List of classified AttackResult instances.
        run_id: Optional run identifier for display purposes.

    Returns:
        Complete HTML document string.
    """
    counts = _count_by_severity(results)
    total = len(results)
    failed = sum(1 for r in results if r.verdict == "failed")
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    rows = "".join(
        f"<tr>"
        f"<td>{r.attack.category}</td>"
        f"<td>{r.attack.technique}</td>"
        f"<td style='color:{_SEVERITY_COLOURS.get(r.severity, '#888')};"
        f"font-weight:bold'>{r.severity.upper()}</td>"
        f"<td>{r.evidence[:300]}</td>"
        f"</tr>"
        for r in results
        if r.vulnerability_found
    )
    empty_row = "<tr><td colspan='4'>No vulnerabilities found.</td></tr>"

    return (
        f"<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
        f"<title>LLM Security Report</title>"
        f"<style>"
        f"body{{font-family:Arial,sans-serif;padding:40px;color:#333}}"
        f"h1{{color:#1A3A5C}}"
        f"h2{{color:#2E5496;border-bottom:2px solid #D6E4F0;padding-bottom:4px}}"
        f"table{{width:100%;border-collapse:collapse}}"
        f"th{{background:#1A3A5C;color:#fff;padding:8px 12px;text-align:left}}"
        f"td{{border-bottom:1px solid #eee;padding:8px 12px;vertical-align:top}}"
        f"tr:nth-child(even){{background:#f9fbfc}}"
        f"</style></head><body>"
        f"<h1>LLM Security Testing Report</h1>"
        f"<p>Generated: {timestamp} | Run: {run_id or 'N/A'}</p>"
        f"<h2>Summary</h2>"
        f"<p>Total: {total} | Vulnerabilities: {failed} | "
        f"Critical: {counts['critical']} | High: {counts['high']} | "
        f"Medium: {counts['medium']} | Low: {counts['low']}</p>"
        f"<h2>Findings</h2>"
        f"<table><thead><tr>"
        f"<th>Category</th><th>Technique</th><th>Severity</th><th>Evidence</th>"
        f"</tr></thead>"
        f"<tbody>{rows or empty_row}</tbody>"
        f"</table></body></html>"
    )


def _count_by_severity(results: List[AttackResult]) -> Dict[str, int]:
    """Count confirmed findings grouped by severity.

    Only counts results where vulnerability_found is True.

    Args:
        results: List of classified AttackResult instances.

    Returns:
        Dict with a key for each severity level and integer count values.
    """
    counts = {s: 0 for s in _SEVERITY_ORDER}
    for result in results:
        if result.vulnerability_found:
            counts[result.severity] = counts.get(result.severity, 0) + 1
    return counts
