# CRTK — Code Review Tool Kit

A standalone **Python code review toolkit** combining static security analysis, performance detection, complexity scoring, optional AI-powered insights, and a web dashboard. Designed for local development use.

## Tech Stack

- **Language:** Python 3.10+
- **Web Framework:** Flask
- **AI (optional):** OpenAI API (GPT-3.5-turbo)
- **Frontend:** Vanilla HTML/CSS/JS (single-page dark-theme dashboard)
- **No external static analysis dependencies** — all pattern matching is regex-based

## Quick Start

```bash
# Install dependencies
pip install flask requests

# Run CLI
python -m crtk review <directory>         # Full code review (JSON output)
python -m crtk analyze <directory>        # Analysis only (text or JSON)
python -m crtk analyze <directory> --format json
python -m crtk serve --port 5000          # Start web dashboard
```

### Web Dashboard

```bash
# Set API token (required)
export CRTK_API_TOKEN=your_secret_token

# Optional: restrict filesystem access
export CRTK_ALLOWED_ROOT=/path/to/projects

python -m crtk serve
# Open http://127.0.0.1:5000
```

## Architecture

```
crtk/
├── __init__.py          # Package init — exports review(), analyze(), CodeAnalyzer
├── __main__.py          # CLI entrypoint (argparse: review, analyze, serve)
├── analyzer.py          # Core analysis engine (636 lines)
├── reviewer.py          # Orchestrator — ties analysis + AI + reporting (341 lines)
├── server.py            # Flask web server with auth, CORS, API routes (238 lines)
├── templates/
│   └── index.html       # Dark-theme SPA dashboard (657 lines)
└── __pycache__/         # Runtime cache (gitignored)
```

### Analysis Capabilities

**Security checks** (8 pattern categories):
- Hardcoded secrets, SQL injection, command injection
- Insecure crypto (MD5, SHA1, DES, ECB)
- Path traversal, XSS (innerHTML, document.write)
- Insecure deserialization (pickle, yaml.load)

**Performance checks** (6 categories):
- N+1 queries (`.filter()` inside loops)
- Missing pagination (`.all()`, `.fetchall()`)
- Large unbounded file reads
- Sync I/O in async contexts
- Unbounded recursion
- Unused imports

**Complexity scoring** (0–100):
- Weighted formula: functions × 5, branches × 2, loops × 1, lines × 0.5 (capped), nesting × 2

### Web API

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/` | GET | Dashboard UI |
| `/api/analyze` | POST | Run analysis, return JSON |
| `/api/review` | POST | Full review (analysis + optional AI) |
| `/api/status` | GET | Server version and uptime |

All `/api/*` endpoints require `X-CRTK-Token` header or `?token=` query parameter. Server fails closed if `CRTK_API_TOKEN` is not set.

### AI Insights

When `use_ai=true` and `OPENAI_API_KEY` is set, the reviewer sends analysis summaries to OpenAI for additional recommendations, risk areas, and health summaries. Falls back gracefully when unavailable.

## Configuration

| Env Variable | Default | Purpose |
|-------------|---------|---------|
| `CRTK_API_TOKEN` | *(required)* | Shared secret for API auth |
| `CRTK_ALLOWED_ROOT` | Parent of crtk/ | Root directory for filesystem access |
| `CRTK_PORT` | 5000 | Web server port |
| `OPENAI_API_KEY` | *(optional)* | Enable AI-powered insights |

## Relationship to Other Critic-Tool Work

Three folders in the workspace relate to "code critic" tooling. Here is the lineage:

- **`Agent MCP (critic)/`** is a **TypeScript MCP server** for the Hermes Agent ecosystem (v2.4.0, started 2026-03-23). It implements an Actor-Critic protocol with 17 MCP tools, swarm orchestration, and computer vision. It is a completely different architecture — MCP protocol, TypeScript, multi-agent focused.

- **`RND Team/`** is a **documentation compilation** (started 2026-06-09) containing snapshots of the Agent MCP critic code plus 9 other framework/constitution modules. It is not live code.

- **This project (`crtk`)** is a **standalone Python toolkit**. It shares no code, language, protocol, or architecture with either of the above. It was built independently as a traditional code review / static analysis tool with a web UI — not as part of the MCP agent ecosystem. The `__pycache__/` directory confirms it has been run locally.

**In short:** Three different projects, three different architectures, one shared concept (code review). This tool is the simplest and most self-contained of the three.

## Status

**Functional prototype.** Version 1.0.0. Has been run locally (evidenced by `__pycache__/`). The Flask web server is fully functional with auth, CORS, and path traversal protection. No test suite yet — the analyzer has good coverage of common patterns but lacks formal tests.

## License

MIT
