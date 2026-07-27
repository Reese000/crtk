"""
CRTK — Code Review Tool Kit

A comprehensive, modular code review tool combining security analysis,
performance detection, and AI-powered insights, accessible via CLI and web interface.
"""

__version__ = "1.0.0"

from crtk.reviewer import review
from crtk.analyzer import CodeAnalyzer, analyze

__all__ = ["review", "analyze", "CodeAnalyzer", "__version__"]
