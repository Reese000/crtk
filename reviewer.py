"""
Orchestrator that ties analysis, AI-powered insights, and reporting together.

The public API consists of :func:`review` which drives the full workflow and
returns a complete report dictionary suitable for CLI or web presentation.
"""

import json
import logging
import os
from typing import Any

from crtk.analyzer import CodeAnalyzer

logger = logging.getLogger("crtk.reviewer")


# ------------------------------------------------------------------
# Public API
# ------------------------------------------------------------------
def review(
    directory: str,
    use_ai: bool = False,
) -> dict[str, Any]:
    """
    Run a comprehensive code review on *directory*.

    Parameters
    ----------
    directory : str
        Absolute or relative path to the project root.
    use_ai : bool
        When ``True`` *and* the ``OPENAI_API_KEY`` environment variable is
        set, the analysis results are sent to the OpenAI API for additional
        AI-powered insights.

    Returns
    -------
    dict
        A report dictionary with the following top-level keys:
        ``project_path``, ``analysis``, ``ai_insights``, ``recommendations``,
        ``risk_score``, and ``summary``.
    """
    logger.info("Starting review for %s (ai=%s)", directory, use_ai)
    abs_path = os.path.abspath(directory)

    analyzer = CodeAnalyzer(abs_path)
    analysis = analyzer.analyze_directory()

    ai_insights: dict[str, Any] | None = None
    if use_ai and os.environ.get("OPENAI_API_KEY"):
        logger.info("Requesting AI insights from OpenAI …")
        ai_insights = get_ai_insights(analysis)
    elif use_ai:
        logger.warning(
            "AI insights requested but OPENAI_API_KEY is not set — skipping."
        )

    recommendations = generate_recommendations(analysis)
    if ai_insights and ai_insights.get("recommendations"):
        recommendations = _merge_recommendations(recommendations, ai_insights["recommendations"])

    risk_score = _compute_risk_score(analysis)
    summary = _build_summary(analysis, risk_score, ai_insights)

    report: dict[str, Any] = {
        "project_path": abs_path,
        "analysis": analysis,
        "ai_insights": ai_insights,
        "recommendations": recommendations,
        "risk_score": risk_score,
        "summary": summary,
    }

    logger.info(
        "Review complete — %d files, risk score %d/100",
        analysis["files_analyzed"],
        risk_score,
    )
    return report


# ------------------------------------------------------------------
# AI insights
# ------------------------------------------------------------------
def get_ai_insights(analysis_results: dict[str, Any]) -> dict[str, Any]:
    """
    Query the OpenAI API for AI-powered code review insights.

    Parameters
    ----------
    analysis_results : dict
        The full analysis dictionary produced by
        :meth:`CodeAnalyzer.analyze_directory`.

    Returns
    -------
    dict
        Dictionary with ``recommendations``, ``risk_areas``, and ``summary``
        strings.  On any failure the function returns a safe default and
        never raises.
    """
    import requests as _requests  # deferred import — only needed when AI is used

    api_key = os.environ.get("OPENAI_API_KEY", "")
    if not api_key:
        logger.warning("OPENAI_API_KEY not set — returning empty insights.")
        return _empty_insights()

    # Build a concise prompt from the analysis
    files_count = analysis_results.get("files_analyzed", 0)
    total_lines = analysis_results.get("total_lines", 0)
    avg_complexity = analysis_results.get("average_complexity", 0)
    sec_summary = analysis_results.get("security_summary", {})
    perf_summary = analysis_results.get("performance_summary", {})

    # Top issues (limit to 10 each)
    all_sec_issues: list[dict[str, Any]] = []
    all_perf_issues: list[dict[str, Any]] = []
    for f in analysis_results.get("files", []):
        all_sec_issues.extend(f.get("security_issues", []))
        all_perf_issues.extend(f.get("performance_issues", []))

    # Sort by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    all_sec_issues.sort(key=lambda x: severity_order.get(x.get("severity", ""), 4))
    all_perf_issues.sort(key=lambda x: severity_order.get(x.get("severity", ""), 4))
    top_sec = all_sec_issues[:10]
    top_perf = all_perf_issues[:10]

    user_message = (
        f"Analyse this codebase and provide prioritised recommendations:\n\n"
        f"Files analysed: {files_count}\n"
        f"Total lines of code: {total_lines}\n"
        f"Average complexity: {avg_complexity}/100\n\n"
        f"Security summary: {json.dumps(sec_summary)}\n"
        f"Performance summary: {json.dumps(perf_summary)}\n\n"
        f"Top 10 security issues:\n{json.dumps(top_sec, indent=2)}\n\n"
        f"Top 10 performance issues:\n{json.dumps(top_perf, indent=2)}\n\n"
        f"Provide:\n"
        f"1. A prioritised list of recommendations (strings)\n"
        f"2. Key risk areas (list of strings)\n"
        f"3. A brief summary of the codebase health (string)\n"
        f"Respond with JSON only: "
        f'{{"recommendations": [...], "risk_areas": [...], "summary": "..."}}'
    )

    system_prompt = (
        "You are a senior code review assistant. Analyse codebases for "
        "security vulnerabilities, performance bottlenecks, and maintainability "
        "concerns. Always respond with valid JSON matching the requested schema. "
        "Be specific and actionable."
    )

    try:
        response = _requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": "gpt-3.5-turbo",
                "temperature": 0.3,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_message},
                ],
            },
            timeout=60,
        )
        response.raise_for_status()
        content = response.json()["choices"][0]["message"]["content"]
        parsed = json.loads(content)
        return {
            "recommendations": parsed.get("recommendations", []),
            "risk_areas": parsed.get("risk_areas", []),
            "summary": parsed.get("summary", ""),
        }
    except Exception:
        logger.exception("OpenAI API call failed")
        return _empty_insights()


def _empty_insights() -> dict[str, Any]:
    """Return the safe-default dict when AI insights are unavailable."""
    return {
        "recommendations": [],
        "risk_areas": [],
        "summary": "AI analysis unavailable",
    }


# ------------------------------------------------------------------
# Recommendations
# ------------------------------------------------------------------
def generate_recommendations(analysis: dict[str, Any]) -> list[str]:
    """
    Produce a prioritised list of actionable recommendation strings.

    Parameters
    ----------
    analysis : dict
        The full analysis dictionary from :class:`CodeAnalyzer`.

    Returns
    -------
    list[str]
        Recommendations sorted by severity: CRITICAL first, then HIGH,
        MEDIUM, LOW.
    """
    severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    recs: list[tuple[int, str]] = []

    for file_info in analysis.get("files", []):
        fname = file_info.get("file", "<unknown>")

        for issue in file_info.get("security_issues", []):
            sev = issue.get("severity", "LOW")
            line = issue.get("line", "?")
            msg = issue.get("message", "")
            sug = issue.get("suggestion", "")
            if sev in ("CRITICAL", "HIGH"):
                recs.append(
                    (
                        severity_rank.get(sev, 4),
                        f"{sev}: {fname}:{line} -- {msg}. Fix: {sug}",
                    )
                )

        for issue in file_info.get("performance_issues", []):
            sev = issue.get("severity", "LOW")
            if sev == "HIGH":
                line = issue.get("line", "?")
                msg = issue.get("message", "")
                sug = issue.get("suggestion", "")
                recs.append(
                    (
                        severity_rank.get(sev, 4),
                        f"HIGH: {fname}:{line} -- {msg}. Fix: {sug}",
                    )
                )

    avg_complexity = analysis.get("average_complexity", 0)
    if avg_complexity > 60:
        recs.append(
            (
                3,
                f"Consider refactoring — average complexity is {avg_complexity}/100",
            )
        )

    total_sec = sum(analysis.get("security_summary", {}).values())
    if total_sec > 10:
        recs.append(
            (
                1,
                f"Project has {total_sec} security issues — prioritise remediation",
            )
        )

    recs.sort(key=lambda r: r[0])
    return [r[1] for r in recs]


# ------------------------------------------------------------------
# Risk score
# ------------------------------------------------------------------
def _compute_risk_score(analysis: dict[str, Any]) -> int:
    """
    Compute an overall risk score (0–100).

    Weighting: security 50 %, performance 30 %, complexity 20 %.

    Security and performance scores are derived from issue counts and
    severity weights.
    """
    sec = analysis.get("security_summary", {})
    perf = analysis.get("performance_summary", {})
    avg_cx = analysis.get("average_complexity", 0)

    # Severity weights
    weights = {"critical": 10, "high": 5, "medium": 2, "low": 1}

    sec_raw = sum(sec.get(s, 0) * w for s, w in weights.items())
    perf_raw = sum(perf.get(s, 0) * w for s, w in weights.items())

    # Normalise: cap at 100
    sec_score = min(sec_raw, 100)
    perf_score = min(perf_raw, 100)

    risk = sec_score * 0.50 + perf_score * 0.30 + avg_cx * 0.20
    return int(min(max(round(risk), 0), 100))


# ------------------------------------------------------------------
# Summary text
# ------------------------------------------------------------------
def _build_summary(
    analysis: dict[str, Any],
    risk_score: int,
    ai_insights: dict[str, Any] | None,
) -> str:
    """Build a human-readable summary string for the report."""
    files = analysis.get("files_analyzed", 0)
    lines = analysis.get("total_lines", 0)
    cx = analysis.get("average_complexity", 0)
    total_sec = sum(analysis.get("security_summary", {}).values())
    total_perf = sum(analysis.get("performance_summary", {}).values())

    parts = [
        f"Analysed {files} files ({lines:,} lines of code).",
        f"Average complexity: {cx}/100.",
        f"Security issues: {total_sec} total "
        f"({analysis.get('security_summary', {}).get('critical', 0)} critical, "
        f"{analysis.get('security_summary', {}).get('high', 0)} high).",
        f"Performance issues: {total_perf}.",
        f"Overall risk score: {risk_score}/100.",
    ]

    if ai_insights and ai_insights.get("summary"):
        parts.append(f"AI summary: {ai_insights['summary']}")

    return " ".join(parts)


# ------------------------------------------------------------------
# Internal helpers
# ------------------------------------------------------------------
def _merge_recommendations(
    base: list[str],
    ai_recs: list[str],
) -> list[str]:
    """Merge AI-generated recommendations into the base list, deduplicating."""
    seen = set(base)
    merged = list(base)
    for rec in ai_recs:
        if rec not in seen:
            merged.append(rec)
            seen.add(rec)
    return merged
