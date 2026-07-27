"""
CLI entrypoint for the CRTK code review tool.

Usage:
    python -m crtk review <directory>
    python -m crtk serve [--port 5000]
    python -m crtk analyze <directory> [--format json|text]
"""

import argparse
import json
import logging
import sys

from crtk.analyzer import CodeAnalyzer
from crtk.reviewer import review

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("crtk")


def cmd_review(args: argparse.Namespace) -> None:
    """Run a full code review and print the JSON result."""
    result = review(args.directory, use_ai=False)
    print(json.dumps(result, indent=2))


def cmd_analyze(args: argparse.Namespace) -> None:
    """Run analysis only, output in the requested format."""
    analyzer = CodeAnalyzer(args.directory)
    result = analyzer.analyze_directory()

    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print(f"Files analyzed: {result['files_analyzed']}")
        print(f"Total lines: {result['total_lines']}")
        print(f"Average complexity: {result['average_complexity']:.1f}")
        print(f"Security issues: {sum(result['security_summary'].values())}")
        print(f"Performance issues: {sum(result['performance_summary'].values())}")
        print()
        for f in result["files"]:
            if f["security_issues"] or f["performance_issues"]:
                print(f"--- {f['file']} ---")
                for issue in f["security_issues"]:
                    print(
                        f"  [SEC][{issue['severity']}] L{issue['line']}: "
                        f"{issue['message']}"
                    )
                for issue in f["performance_issues"]:
                    print(
                        f"  [PERF][{issue['severity']}] L{issue['line']}: "
                        f"{issue['message']}"
                    )
                print()


def cmd_serve(args: argparse.Namespace) -> None:
    """Start the Flask web server."""
    from crtk.server import app

    logger.info("Starting CRTK web server on port %d", args.port)
    app.run(host="127.0.0.1", port=args.port, debug=False)


def main() -> None:
    """Parse arguments and dispatch to the appropriate subcommand."""
    parser = argparse.ArgumentParser(
        prog="crtk",
        description="CRTK — Code Review Tool Kit",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # review
    review_parser = subparsers.add_parser(
        "review", help="Run full code review on a project directory"
    )
    review_parser.add_argument("directory", help="Path to the project directory")
    review_parser.set_defaults(func=cmd_review)

    # analyze
    analyze_parser = subparsers.add_parser(
        "analyze", help="Run analysis only (no review orchestration)"
    )
    analyze_parser.add_argument("directory", help="Path to the project directory")
    analyze_parser.add_argument(
        "--format",
        choices=["json", "text"],
        default="text",
        help="Output format (default: text)",
    )
    analyze_parser.set_defaults(func=cmd_analyze)

    # serve
    serve_parser = subparsers.add_parser(
        "serve", help="Start the CRTK web dashboard"
    )
    serve_parser.add_argument(
        "--port", type=int, default=5000, help="Port to listen on (default: 5000)"
    )
    serve_parser.set_defaults(func=cmd_serve)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
