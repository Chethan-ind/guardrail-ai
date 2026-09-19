"""
masker.py
Takes the raw file content + the Findings detector.py produced, and
returns a masked version of the content plus the mapping of
fingerprint -> real secret value (which vault.py will push to Secrets
Manager, never to disk and never back into git history).
"""

from __future__ import annotations

from src.detector import Finding


def mask_content(content: str, findings: list[Finding]) -> tuple[str, dict[str, str]]:
    """
    Returns (masked_content, {fingerprint: original_value}).
    Only replaces exact matched_value substrings, so surrounding code /
    formatting / quotes are preserved and the diff stays readable.
    """
    masked = content
    vault_payload: dict[str, str] = {}

    # Longest value first, so masking a substring finding doesn't corrupt
    # a longer finding that contains it.
    for finding in sorted(findings, key=lambda f: len(f.matched_value), reverse=True):
        if finding.matched_value not in masked:
            continue
        placeholder = f"[GUARDRAIL_MASKED:{finding.finding_type}:{finding.fingerprint}]"
        masked = masked.replace(finding.matched_value, placeholder)
        vault_payload[finding.fingerprint] = finding.matched_value

    return masked, vault_payload
