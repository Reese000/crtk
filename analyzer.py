"""
Core analysis engine for CRTK.

Provides file scanning, security checks, performance checks,
and complexity scoring for Python and JavaScript/TypeScript projects.
"""

import logging
import math
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger("crtk.analyzer")

# ---------------------------------------------------------------------------
# Directories to skip during file scanning
# ---------------------------------------------------------------------------
SKIP_DIRS: set[str] = {
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "dist",
    "build",
    ".egg-info",
}

# ---------------------------------------------------------------------------
# File extensions to analyse
# ---------------------------------------------------------------------------
VALID_EXTENSIONS: set[str] = {
    ".py",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
}

# ---------------------------------------------------------------------------
# Pre-compiled security regex patterns
# ---------------------------------------------------------------------------
SECURITY_PATTERNS: list[tuple[str, str, str, re.Pattern[str]]] = [
    (
        "hardcoded_secret",
        "HIGH",
        "Potential hardcoded secret detected",
        re.compile(
            r"""(?:password|secret|api_key|token)\s*=\s*['"][^'"]+['"]""",
            re.IGNORECASE,
        ),
    ),
    (
        "sql_injection",
        "CRITICAL",
        "Possible SQL injection via string formatting",
        re.compile(
            r'f["\'].*SELECT.*\{|"SELECT.*%s|"\s*SELECT.*\+',
            re.IGNORECASE,
        ),
    ),
    (
        "command_injection",
        "CRITICAL",
        "Potential command injection vector",
        re.compile(
            r"""\bos\.system\s*\(|"""
            r"""subprocess\.call\s*\(\s*["']|"""
            r"""\beval\s*\(|"""
            r"""\bexec\s*\(""",
        ),
    ),
    (
        "insecure_crypto",
        "MEDIUM",
        "Use of weak / deprecated cryptographic primitive",
        re.compile(r"""\bmd5\s*\(|sha1\s*\(|\bDES\b|\bECB\b"""),
    ),
    (
        "path_traversal",
        "MEDIUM",
        "Potential path traversal in file open",
        re.compile(r"""\bopen\s*\([^)]*\.\./"""),
    ),
    (
        "xss_innerhtml",
        "HIGH",
        "Potential XSS via innerHTML assignment",
        re.compile(r"""innerHTML\s*="""),
    ),
    (
        "xss_document_write",
        "HIGH",
        "Potential XSS via document.write",
        re.compile(r"""document\.write\s*\("""),
    ),
    (
        "insecure_deserialization",
        "CRITICAL",
        "Insecure deserialization detected",
        re.compile(r"""\bpickle\.loads?\s*\(|yaml\.load\s*\("""),
    ),
]

# ---------------------------------------------------------------------------
# Pre-compiled performance regex patterns
# ---------------------------------------------------------------------------
PERF_QUERY_PATTERNS: list[tuple[str, str, str, re.Pattern[str]]] = [
    (
        "missing_pagination",
        "MEDIUM",
        "Uncapped result set — missing pagination / limit",
        re.compile(r"""\.all\(\)|\.fetchall\(\)"""),
    ),
    (
        "large_file_read",
        "LOW",
        "Unbounded file read — consider chunked reading",
        re.compile(r"""\.read\(\)"""),
    ),
    (
        "sync_io_in_async",
        "MEDIUM",
        "Synchronous I/O inside async context",
        re.compile(r"""requests\.get\s*\("""),
    ),
]

# ---------------------------------------------------------------------------
# N+1 query: look for .filter( inside loops — handled in-line via line scanning
# ---------------------------------------------------------------------------
LOOP_RE = re.compile(r"""^\s*(?:for|while)\s""")
FILTER_RE = re.compile(r"""\.filter\s*\(""")

# Recursion: function that references its own name
FUNC_DEF_RE = re.compile(r"""^\s*(?:async\s+)?def\s+(\w+)\s*\(""")

# Import statement
IMPORT_RE = re.compile(
    r"""^\s*import\s+([\w., ]+)|^\s*from\s+\S+\s+import\s+([\w., *]+)"""
)

# Complexity counting
IF_RE = re.compile(r"""^\s*(?:if|elif|else)\b""")
LOOP_COMPLEXITY_RE = re.compile(r"""^\s*(?:for|while)\b""")


def _count_functions(source: str) -> int:
    """Return the number of function / method definitions in *source*."""
    return len(FUNC_DEF_RE.findall(source))


def _count_branches(source: str) -> int:
    """Return the number of if / elif / else blocks."""
    return len(IF_RE.findall(source))


def _count_loops(source: str) -> int:
    """Return the number of loop constructs."""
    return len(LOOP_COMPLEXITY_RE.findall(source))


def _count_nesting_depth(source: str) -> int:
    """Return the maximum indentation nesting level (in spaces)."""
    max_depth = 0
    for line in source.splitlines():
        stripped = line.lstrip()
        if stripped and not stripped.startswith("#"):
            indent = len(line) - len(stripped)
            # Convert to "depth" assuming 4-space indent
            depth = indent // 4
            if depth > max_depth:
                max_depth = depth
    return max_depth


def _complexity_score(
    lines_of_code: int,
    functions: int,
    branches: int,
    loops: int,
    nesting: int,
) -> float:
    """
    Compute a heuristic complexity score in the range 0–100.

    The score is built from:
    - +5 per function/method
    - +2 per if / elif / else block
    - +1 per loop
    - +0.5 per line of code (capped at +20)
    - nesting depth adds a small multiplier
    """
    raw = (
        functions * 5
        + branches * 2
        + loops * 1
        + min(lines_of_code * 0.5, 20)
        + nesting * 2
    )
    return round(min(max(raw, 0), 100), 1)


class CodeAnalyzer:
    """
    Analyses a project directory for security, performance, and complexity issues.

    Parameters
    ----------
    directory : str
        Absolute or relative path to the project root to analyse.
    """

    def __init__(self, directory: str) -> None:
        self.directory: str = os.path.abspath(directory)
        if not os.path.isdir(self.directory):
            raise NotADirectoryError(
                f"Directory does not exist or is not a directory: {self.directory}"
            )
        logger.info("CodeAnalyzer initialised for %s", self.directory)

    # ------------------------------------------------------------------
    # File discovery
    # ------------------------------------------------------------------
    def scan_files(self) -> list[str]:
        """
        Recursively discover source files to analyse.

        Skips well-known non-source directories (``.git``, ``node_modules``,
        ``__pycache__``, etc.) and only returns files with recognised
        extensions.

        Returns
        -------
        list[str]
            Absolute paths of discovered source files.
        """
        files: list[str] = []
        for root, dirs, filenames in os.walk(self.directory):
            # Prune directories in-place so os.walk doesn't descend
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in filenames:
                ext = os.path.splitext(fname)[1].lower()
                if ext in VALID_EXTENSIONS:
                    files.append(os.path.join(root, fname))
        logger.info("Discovered %d source files", len(files))
        return files

    # ------------------------------------------------------------------
    # Per-file analysis
    # ------------------------------------------------------------------
    def analyze_file(self, filepath: str) -> dict[str, Any]:
        """
        Analyse a single source file for issues and metrics.

        Parameters
        ----------
        filepath : str
            Absolute path to the file to analyse.

        Returns
        -------
        dict
            Dictionary containing ``file``, ``lines_of_code``,
            ``complexity_score``, ``security_issues``, and
            ``performance_issues``.
        """
        rel_path = os.path.relpath(filepath, self.directory)
        result: dict[str, Any] = {
            "file": rel_path,
            "lines_of_code": 0,
            "complexity_score": 0.0,
            "security_issues": [],
            "performance_issues": [],
        }

        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
                source = fh.read()
        except PermissionError:
            logger.warning("Permission denied: %s", rel_path)
            return result
        except OSError as exc:
            logger.warning("Could not read %s: %s", rel_path, exc)
            return result

        lines = source.splitlines()
        non_blank = [l for l in lines if l.strip() and not l.strip().startswith("#")]
        result["lines_of_code"] = len(non_blank)

        if not lines:
            return result

        # --- Security checks ---
        for pattern_name, severity, message, regex in SECURITY_PATTERNS:
            for idx, line in enumerate(lines, start=1):
                if regex.search(line):
                    result["security_issues"].append(
                        {
                            "type": pattern_name,
                            "severity": severity,
                            "line": idx,
                            "message": message,
                            "suggestion": _security_suggestion(pattern_name),
                        }
                    )

        # --- Performance checks ---
        # N+1 query detection: .filter() inside a loop
        in_loop = False
        loop_start = 0
        for idx, line in enumerate(lines, start=1):
            if LOOP_RE.match(line):
                in_loop = True
                loop_start = idx
            # Heuristic: a less-indented line or a new block breaks the loop context
            elif in_loop and not line.startswith(" ") and not line.startswith("\t"):
                in_loop = False

            if in_loop and FILTER_RE.search(line):
                result["performance_issues"].append(
                    {
                        "type": "n_plus_one_query",
                        "severity": "HIGH",
                        "line": idx,
                        "message": (
                            "Possible N+1 query: .filter() call inside a loop "
                            f"(loop started at line {loop_start})"
                        ),
                        "suggestion": "Batch the query outside the loop or use select_related / prefetch_related.",
                    }
                )
                in_loop = False  # avoid duplicate hits on same loop

        # Pattern-based perf checks
        for pattern_name, severity, message, regex in PERF_QUERY_PATTERNS:
            for idx, line in enumerate(lines, start=1):
                if regex.search(line):
                    suggestion = _performance_suggestion(pattern_name)
                    # For sync-io-in-async, only flag inside async def
                    if pattern_name == "sync_io_in_async":
                        if _is_inside_async_def(lines, idx - 1):
                            result["performance_issues"].append(
                                {
                                    "type": pattern_name,
                                    "severity": severity,
                                    "line": idx,
                                    "message": message,
                                    "suggestion": suggestion,
                                }
                            )
                    else:
                        result["performance_issues"].append(
                            {
                                "type": pattern_name,
                                "severity": severity,
                                "line": idx,
                                "message": message,
                                "suggestion": suggestion,
                            }
                        )

        # Unbounded recursion
        func_names = FUNC_DEF_RE.findall(source)
        for fname in func_names:
            pattern = re.compile(rf"\b{re.escape(fname)}\s*\(")
            for idx, line in enumerate(lines, start=1):
                if FUNC_DEF_RE.match(line):
                    continue  # skip the definition itself
                if pattern.search(line):
                    result["performance_issues"].append(
                        {
                            "type": "unbounded_recursion",
                            "severity": "MEDIUM",
                            "line": idx,
                            "message": f"Function '{fname}' calls itself recursively without obvious depth limit",
                            "suggestion": "Add a max-depth parameter or a visited set to prevent stack overflow.",
                        }
                    )
                    break  # one hit per function is enough

        # Missing caching: requests.get inside a loop
        requests_get_re = re.compile(r"""\brequests\.get\s*\(""")
        in_loop = False
        for idx, line in enumerate(lines, start=1):
            if LOOP_RE.match(line):
                in_loop = True
            elif in_loop and not line.startswith(" ") and not line.startswith("\t"):
                in_loop = False
            if in_loop and requests_get_re.search(line):
                result["performance_issues"].append(
                    {
                        "type": "missing_caching",
                        "severity": "LOW",
                        "line": idx,
                        "message": "HTTP request inside a loop without apparent caching",
                        "suggestion": "Cache responses or batch requests to reduce network overhead.",
                    }
                )
                in_loop = False

        # Unnecessary imports
        imported_names = _extract_imported_names(source)
        used_names = {
            word
            for line in non_blank
            for word in re.split(r"[\s(,.)\[\]{}]+", line)
            if word.isidentifier()
        }
        for name in imported_names:
            if name not in used_names and name != "*":
                result["performance_issues"].append(
                    {
                        "type": "unused_import",
                        "severity": "LOW",
                        "line": 0,
                        "message": f"Imported name '{name}' does not appear to be used",
                        "suggestion": "Remove unused imports to reduce clutter and improve load time.",
                    }
                )

        # --- Complexity ---
        functions = _count_functions(source)
        branches = _count_branches(source)
        loops = _count_loops(source)
        nesting = _count_nesting_depth(source)
        result["complexity_score"] = _complexity_score(
            result["lines_of_code"], functions, branches, loops, nesting
        )

        # Deduplicate issues by (type, line) to avoid noisy output
        result["security_issues"] = _deduplicate_issues(result["security_issues"])
        result["performance_issues"] = _deduplicate_issues(result["performance_issues"])

        return result

    # ------------------------------------------------------------------
    # Full directory analysis
    # ------------------------------------------------------------------
    def analyze_directory(self) -> dict[str, Any]:
        """
        Scan and analyse every source file in the project directory.

        Returns
        -------
        dict
            Aggregate analysis results including per-file breakdowns,
            summary counts, and a timestamp.
        """
        files = self.scan_files()
        file_results: list[dict[str, Any]] = []
        total_lines = 0
        complexity_scores: list[float] = []
        security_summary: dict[str, int] = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }
        performance_summary: dict[str, int] = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }

        for filepath in files:
            try:
                result = self.analyze_file(filepath)
            except Exception:
                logger.exception("Unexpected error analysing %s", filepath)
                continue

            file_results.append(result)
            total_lines += result["lines_of_code"]
            complexity_scores.append(result["complexity_score"])

            for issue in result["security_issues"]:
                sev = issue["severity"].lower()
                if sev in security_summary:
                    security_summary[sev] += 1

            for issue in result["performance_issues"]:
                sev = issue["severity"].lower()
                if sev in performance_summary:
                    performance_summary[sev] += 1

        avg_complexity = (
            round(sum(complexity_scores) / len(complexity_scores), 1)
            if complexity_scores
            else 0.0
        )

        return {
            "files_analyzed": len(file_results),
            "total_lines": total_lines,
            "average_complexity": avg_complexity,
            "security_summary": security_summary,
            "performance_summary": performance_summary,
            "files": file_results,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


# ------------------------------------------------------------------
# Module-level convenience wrapper
# ------------------------------------------------------------------
def analyze(directory: str) -> dict[str, Any]:
    """
    Analyse a directory and return the results dict.

    This is a thin wrapper around :class:`CodeAnalyzer` for convenience.

    Parameters
    ----------
    directory : str
        Path to the project root.

    Returns
    -------
    dict
        Full analysis results.
    """
    analyzer = CodeAnalyzer(directory)
    return analyzer.analyze_directory()


# ------------------------------------------------------------------
# Internal helpers
# ------------------------------------------------------------------
def _security_suggestion(pattern_name: str) -> str:
    """Return a human-readable remediation suggestion for a security issue."""
    suggestions: dict[str, str] = {
        "hardcoded_secret": (
            "Move secrets to environment variables or a secrets manager."
        ),
        "sql_injection": (
            "Use parameterised queries or an ORM instead of string formatting."
        ),
        "command_injection": (
            "Use subprocess with a list of arguments instead of shell strings. "
            "Never pass user input to eval/exec."
        ),
        "insecure_crypto": (
            "Switch to a modern algorithm such as SHA-256 or AES-GCM."
        ),
        "path_traversal": (
            "Validate and sanitise file paths; use pathlib to resolve paths "
            "and verify they remain within the project root."
        ),
        "xss_innerhtml": (
            "Use textContent instead of innerHTML, or sanitise input with a "
            "library like DOMPurify."
        ),
        "xss_document_write": (
            "Avoid document.write; use DOM manipulation methods instead."
        ),
        "insecure_deserialization": (
            "Avoid pickle for untrusted data. For YAML, use yaml.safe_load() "
            "or pass Loader=yaml.SafeLoader."
        ),
    }
    return suggestions.get(pattern_name, "Review and remediate as appropriate.")


def _performance_suggestion(pattern_name: str) -> str:
    """Return a human-readable remediation suggestion for a perf issue."""
    suggestions: dict[str, str] = {
        "missing_pagination": (
            "Add .limit() / .offset() or equivalent to cap result sets."
        ),
        "large_file_read": (
            "Read files in chunks to avoid loading entire contents into memory."
        ),
        "sync_io_in_async": (
            "Use an async HTTP client (e.g. aiohttp, httpx) inside async "
            "functions to avoid blocking the event loop."
        ),
    }
    return suggestions.get(pattern_name, "Review and optimise as appropriate.")


def _is_inside_async_def(lines: list[str], target_idx: int) -> bool:
    """
    Determine whether *target_idx* sits inside an ``async def`` block.

    Walks backward from *target_idx* looking for the nearest ``def`` at a
    lower indentation level.  Returns ``True`` if that def is ``async``.
    """
    target_line = lines[target_idx]
    target_indent = len(target_line) - len(target_line.lstrip())
    for i in range(target_idx - 1, -1, -1):
        line = lines[i]
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(stripped)
        if indent < target_indent:
            if stripped.startswith("async def") or stripped.startswith("async def\t"):
                return True
            if stripped.startswith("def "):
                return False
    return False


def _extract_imported_names(source: str) -> set[str]:
    """Extract top-level imported names from Python source."""
    names: set[str] = set()
    for match in IMPORT_RE.finditer(source):
        if match.group(1):
            for n in match.group(1).split(","):
                names.add(n.strip().split(".")[0])
        if match.group(2):
            for n in match.group(2).split(","):
                n = n.strip()
                if n == "*":
                    names.add("*")
                else:
                    alias = n.split(" as ")
                    names.add(alias[-1].strip() if len(alias) > 1 else alias[0].strip())
    return names


def _deduplicate_issues(issues: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Remove duplicate issues sharing the same (type, line) key."""
    seen: set[tuple[str, int]] = set()
    unique: list[dict[str, Any]] = []
    for issue in issues:
        key = (issue["type"], issue["line"])
        if key not in seen:
            seen.add(key)
            unique.append(issue)
    return unique
