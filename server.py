"""
Flask web server for the CRTK dashboard.

Provides a single-page web interface and REST API for running
code analyses and reviews from the browser.
"""

import functools
import logging
import os
import time
from pathlib import Path
from typing import Any, Callable

from flask import Flask, jsonify, render_template, request

from crtk.analyzer import CodeAnalyzer
from crtk.reviewer import review

logger = logging.getLogger("crtk.server")

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------
app = Flask(__name__)

# Record uptime baseline
_SERVER_START: float = time.time()

# ---------------------------------------------------------------------------
# Security configuration
# ---------------------------------------------------------------------------
# Shared-secret token required on every /api/* request. Set CRTK_API_TOKEN in
# the environment before starting the server. If unset, the server refuses to
# start (fail closed) rather than silently running without authentication.
_API_TOKEN: str | None = os.environ.get("CRTK_API_TOKEN")

# Root directory that all `directory` request params must resolve within.
# Defaults to the CAM project root (two levels up from this file:
# crtk/server.py -> crtk/ -> project root). Override with CRTK_ALLOWED_ROOT.
_ALLOWED_ROOT: Path = Path(
    os.environ.get("CRTK_ALLOWED_ROOT", str(Path(__file__).resolve().parent.parent))
).resolve()

# Origins allowed for CORS. Local dev tool only — no public/wildcard access.
_ALLOWED_ORIGINS = {
    "http://127.0.0.1",
    "http://localhost",
}


def _origin_allowed(origin: str | None) -> bool:
    """Return True if the request Origin header is a local dev origin."""
    if not origin:
        return False
    # Strip port, e.g. "http://127.0.0.1:5173" -> "http://127.0.0.1"
    scheme_host = origin.rsplit(":", 1)[0] if origin.count(":") > 1 else origin
    return scheme_host in _ALLOWED_ORIGINS


def require_api_token(view_func: Callable) -> Callable:
    """Decorator enforcing the CRTK_API_TOKEN shared secret on an endpoint.

    Accepts the token via the ``X-CRTK-Token`` header or a ``token`` query
    param. Returns 401 if the server has no configured token, or if the
    request's token is missing/incorrect.
    """

    @functools.wraps(view_func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        if not _API_TOKEN:
            logger.error("CRTK_API_TOKEN is not set; refusing request")
            return jsonify({"error": "Server is not configured with an API token"}), 401

        supplied = request.headers.get("X-CRTK-Token") or request.args.get("token")
        if not supplied or supplied != _API_TOKEN:
            logger.warning("Rejected request with missing/invalid API token")
            return jsonify({"error": "Unauthorized"}), 401

        return view_func(*args, **kwargs)

    return wrapper


def _resolve_within_allowed_root(directory: str) -> Path | None:
    """Resolve `directory` and verify it is a descendant of _ALLOWED_ROOT.

    Returns the resolved Path if it is safely contained within the allowlist
    root, or None if it escapes the root (e.g. via `..` traversal or an
    absolute path elsewhere on disk).
    """
    try:
        candidate = (_ALLOWED_ROOT / directory).resolve() if not os.path.isabs(directory) else Path(directory).resolve()
    except (OSError, ValueError):
        return None

    try:
        candidate.relative_to(_ALLOWED_ROOT)
    except ValueError:
        return None

    return candidate


# ---------------------------------------------------------------------------
# CORS — manual after_request hook, restricted to local dev origins
# ---------------------------------------------------------------------------
@app.after_request
def _add_cors_headers(response: Any) -> Any:
    """Attach CORS headers scoped to local dev origins only."""
    origin = request.headers.get("Origin")
    if _origin_allowed(origin):
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-CRTK-Token"
    return response


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def index() -> Any:
    """
    Render the main dashboard page.

    Returns the ``index.html`` template from the ``templates/`` directory.
    """
    return render_template("index.html")


@app.route("/api/analyze", methods=["POST"])
@require_api_token
def api_analyze() -> Any:
    """
    Run analysis on a directory and return JSON results.

    Expects a JSON body with ``{"directory": "/path/to/project"}``. The
    directory must resolve to a descendant of the configured allowlist root
    (CRTK_ALLOWED_ROOT, defaults to the CAM project root). Requires a valid
    CRTK_API_TOKEN (see require_api_token).

    Returns
    -------
    flask.Response
        JSON analysis results, or an error with status 400/401/500.
    """
    try:
        body = request.get_json(force=True, silent=True) or {}
        directory = body.get("directory", "")
        if not directory:
            return jsonify({"error": "No directory provided"}), 400

        abs_dir = _resolve_within_allowed_root(directory)
        if abs_dir is None:
            logger.warning("Rejected directory outside allowlist root: %s", directory)
            return jsonify({"error": "Directory is outside the allowed root"}), 400
        if not abs_dir.is_dir():
            return jsonify({"error": f"Directory not found: {abs_dir}"}), 400

        logger.info("Analyzing directory: %s", abs_dir)
        analyzer = CodeAnalyzer(str(abs_dir))
        results = analyzer.analyze_directory()
        return jsonify(results)

    except Exception as exc:
        logger.exception("Error in /api/analyze")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/review", methods=["POST"])
@require_api_token
def api_review() -> Any:
    """
    Run a full code review (analysis + optional AI) and return JSON report.

    Expects a JSON body with
    ``{"directory": "/path/to/project", "use_ai": false}``. The directory
    must resolve to a descendant of the configured allowlist root. Requires
    a valid CRTK_API_TOKEN (see require_api_token).

    Returns
    -------
    flask.Response
        JSON review report, or an error with status 400/401/500.
    """
    try:
        body = request.get_json(force=True, silent=True) or {}
        directory = body.get("directory", "")
        use_ai = body.get("use_ai", False)

        if not directory:
            return jsonify({"error": "No directory provided"}), 400

        abs_dir = _resolve_within_allowed_root(directory)
        if abs_dir is None:
            logger.warning("Rejected directory outside allowlist root: %s", directory)
            return jsonify({"error": "Directory is outside the allowed root"}), 400
        if not abs_dir.is_dir():
            return jsonify({"error": f"Directory not found: {abs_dir}"}), 400

        logger.info("Full review of directory: %s (ai=%s)", abs_dir, use_ai)
        report = review(str(abs_dir), use_ai=use_ai)
        return jsonify(report)

    except Exception as exc:
        logger.exception("Error in /api/review")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/status", methods=["GET"])
def api_status() -> Any:
    """
    Return server status, version, and uptime.

    Returns
    -------
    flask.Response
        ``{"status": "running", "version": "1.0.0", "uptime": <seconds>}``
    """
    from crtk import __version__

    uptime = round(time.time() - _SERVER_START, 1)
    return jsonify({"status": "running", "version": __version__, "uptime": uptime})


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    port = int(os.environ.get("CRTK_PORT", 5000))
    logger.info("Starting CRTK server on 127.0.0.1:%d", port)
    app.run(host="127.0.0.1", port=port, debug=False)
