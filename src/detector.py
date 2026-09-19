"""
detector.py
Scans a chunk of text (a git diff, a file body, a webhook payload) for
hard-coded secrets using a mix of high-confidence regex signatures and
a Shannon-entropy fallback for opaque tokens that don't match a known
vendor format.

This module has NO AWS dependency on purpose — it has to run in <50ms
inside a Lambda cold start, so it stays pure Python / re / math.
"""

from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass, field
from typing import Iterable


# ---------------------------------------------------------------------------
# Signatures: (finding_type, compiled_regex, severity_hint, value_group)
# value_group tells the scanner which regex group is the ACTUAL secret to
# mask/vault (0 = whole match). Getting this wrong means masking the wrong
# substring (e.g. the variable name instead of its value) — worth being
# explicit rather than guessing from m.groups().
# severity_hint is a starting point; triage_agent.py can raise/lower it.
# ---------------------------------------------------------------------------
SIGNATURES: list[tuple[str, re.Pattern, str, int]] = [
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "high", 0),
    ("aws_secret_access_key",
     re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
     "high", 1),
    ("aws_session_token",
     re.compile(r"(?i)aws_session_token\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{100,})['\"]?"),
     "high", 1),
    ("private_key_block",
     re.compile(r"-----BEGIN (RSA|EC|OPENSSH|DSA|PGP)?\s?PRIVATE KEY-----"),
     "critical", 0),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"), "high", 0),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,48}\b"), "medium", 0),
    ("kube_client_key_data",
     re.compile(r"(?i)client-key-data:\s*([A-Za-z0-9+/=]{20,})"),
     "high", 1),
    ("kube_bearer_token",
     re.compile(r"(?i)\b(?:token|bearer)\s*[:=]\s*['\"]?([A-Za-z0-9\-_\.]{20,})['\"]?"),
     "high", 1),
    ("generic_api_key",
     re.compile(r"(?i)(?:api[_-]?key|apikey|secret|passwd|password)\s*[=:]\s*['\"]([0-9A-Za-z\-_/+]{12,64})['\"]"),
     "medium", 1),
    ("db_connection_string",
     re.compile(r"(?i)(?:postgres|mysql|mongodb(?:\+srv)?):\/\/[^\s'\"]+:[^\s'\"@]+@[^\s'\"]+"),
     "critical", 0),
]

_ENTROPY_CANDIDATE = re.compile(r"['\"]([A-Za-z0-9+/_\-]{20,80})['\"]")
_ENTROPY_THRESHOLD = 4.3  # bits/char; random base64-ish secrets sit ~4.5-6.0


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


@dataclass
class Finding:
    finding_type: str
    severity_hint: str
    matched_value: str
    line_no: int
    file_path: str
    fingerprint: str = field(init=False)

    def __post_init__(self):
        # Stable id so the same secret found twice (e.g. re-pushed) maps to
        # the same vault entry instead of creating duplicates.
        self.fingerprint = hashlib.sha256(
            f"{self.file_path}:{self.matched_value}".encode()
        ).hexdigest()[:16]


def scan_text(text: str, file_path: str = "<unknown>") -> list[Finding]:
    findings: list[Finding] = []
    lines = text.splitlines()

    for line_no, line in enumerate(lines, start=1):
        matched_spans: list[tuple[int, int]] = []

        for finding_type, pattern, severity, value_group in SIGNATURES:
            for m in pattern.finditer(line):
                value = m.group(value_group)
                findings.append(Finding(finding_type, severity, value, line_no, file_path))
                matched_spans.append(m.span(value_group))

        # Entropy fallback — only run on spans not already claimed by a
        # signature match, to avoid double-flagging the same token.
        for m in _ENTROPY_CANDIDATE.finditer(line):
            span = m.span()
            if any(s[0] <= span[0] < s[1] for s in matched_spans):
                continue
            candidate = m.group(1)
            score = shannon_entropy(candidate)
            if score >= _ENTROPY_THRESHOLD:
                findings.append(
                    Finding("high_entropy_string", "low", candidate, line_no, file_path)
                )

    return findings


def scan_files(files: Iterable[tuple[str, str]]) -> list[Finding]:
    """files: iterable of (file_path, file_content)."""
    out: list[Finding] = []
    for path, content in files:
        out.extend(scan_text(content, path))
    return out
