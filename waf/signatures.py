"""
Signature-based attack detection for the WAF.

These are simple, well-known textbook patterns -- the same general
class of patterns OWASP's public Core Rule Set documents -- used here
to demonstrate signature-based filtering. A production WAF layers far
more rules, anomaly scoring, and regular signature updates on top of
a base like this.
"""

import re
from dataclasses import dataclass


@dataclass
class Signature:
    name: str
    category: str
    pattern: re.Pattern


def _compile(patterns, category):
    return [Signature(name=p, category=category, pattern=re.compile(p, re.IGNORECASE))
            for p in patterns]


SQL_INJECTION = _compile([
    r"(\bor\b|\band\b)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",   # e.g. OR 1=1
    r"union\s+select",
    r"['\"]\s*;\s*drop\s+table",
    r"sleep\(\d+\)",
    r"--\s",
], "sql_injection")

XSS = _compile([
    r"<script[^>]*>",
    r"on(error|load|click)\s*=",
    r"javascript:",
], "xss")

PATH_TRAVERSAL = _compile([
    r"\.\./",
    r"\.\.\\",
    r"/etc/passwd",
    r"\\windows\\system32",
], "path_traversal")

COMMAND_INJECTION = _compile([
    r";\s*(rm|cat|wget|curl|nc)\s",
    r"\|\s*(rm|cat|wget|curl|nc)\s",
    r"`[^`]+`",
], "command_injection")

ALL_SIGNATURES = SQL_INJECTION + XSS + PATH_TRAVERSAL + COMMAND_INJECTION


def scan(text: str):
    """Return the list of Signature objects that match the given text."""
    if not text:
        return []
    return [sig for sig in ALL_SIGNATURES if sig.pattern.search(text)]
