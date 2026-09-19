"""
triage_agent.py
This is the "agentic" layer: instead of treating every regex hit as an
equal, binary alarm, a Bedrock-hosted model reads the finding in context
(file path, surrounding lines, finding type) and returns a structured
judgement — severity, false-positive likelihood, and a one-line reason.
That judgement is what gets logged and alerted on, not the raw regex hit.

Two paths, both real:
  - BEDROCK path: calls bedrock-runtime InvokeModel against an Anthropic
    model on Bedrock. Used when GUARDRAIL_USE_BEDROCK=1 and credentials
    / model access are configured — this is what you deploy for the demo.
  - HEURISTIC path: a deterministic scoring fallback so the pipeline is
    fully testable and demoable (via demo/demo.py) without needing live
    Bedrock model access provisioned. Clearly labelled in output as
    "engine": "heuristic" vs "engine": "bedrock" so the judges can see
    exactly which calls hit AWS.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass

import boto3

logger = logging.getLogger("guardrail.triage")

_REGION = os.environ.get("AWS_REGION", "ap-south-1")
_MODEL_ID = os.environ.get("GUARDRAIL_BEDROCK_MODEL_ID", "anthropic.claude-3-5-haiku-20241022-v1:0")
_USE_BEDROCK = os.environ.get("GUARDRAIL_USE_BEDROCK", "0") == "1"

_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

_HEURISTIC_WEIGHTS = {
    "private_key_block": ("critical", 0.02),
    "db_connection_string": ("critical", 0.05),
    "aws_secret_access_key": ("high", 0.05),
    "aws_session_token": ("high", 0.05),
    "aws_access_key_id": ("high", 0.10),
    "github_token": ("high", 0.10),
    "kube_client_key_data": ("high", 0.10),
    "kube_bearer_token": ("medium", 0.20),
    "generic_api_key": ("medium", 0.30),
    "slack_token": ("medium", 0.15),
    "high_entropy_string": ("low", 0.55),
}


@dataclass
class Verdict:
    fingerprint: str
    severity: str
    false_positive_likelihood: float
    reason: str
    engine: str

    def to_dict(self) -> dict:
        return {
            "fingerprint": self.fingerprint,
            "severity": self.severity,
            "false_positive_likelihood": self.false_positive_likelihood,
            "reason": self.reason,
            "engine": self.engine,
        }


def _heuristic_verdict(finding) -> Verdict:
    severity, fp_likelihood = _HEURISTIC_WEIGHTS.get(
        finding.finding_type, ("medium", 0.35)
    )
    reason = (
        f"Signature '{finding.finding_type}' matched in {finding.file_path}:"
        f"{finding.line_no}. Heuristic prior for this signature class."
    )
    return Verdict(finding.fingerprint, severity, fp_likelihood, reason, engine="heuristic")


def _bedrock_verdict(finding, surrounding_context: str) -> Verdict:
    client = boto3.client("bedrock-runtime", region_name=_REGION)

    prompt = (
        "You are a security triage assistant. A secrets scanner flagged a "
        "possible hard-coded credential. Classify it.\n\n"
        f"finding_type: {finding.finding_type}\n"
        f"file_path: {finding.file_path}\n"
        f"line_no: {finding.line_no}\n"
        f"context (secret value itself is withheld):\n{surrounding_context}\n\n"
        "Respond ONLY with JSON: "
        '{"severity": "low|medium|high|critical", '
        '"false_positive_likelihood": <0.0-1.0>, "reason": "<one sentence>"}'
    )

    body = json.dumps({
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 300,
        "messages": [{"role": "user", "content": prompt}],
    })

    response = client.invoke_model(modelId=_MODEL_ID, body=body)
    payload = json.loads(response["body"].read())
    text = payload["content"][0]["text"]
    parsed = json.loads(text)

    return Verdict(
        finding.fingerprint,
        parsed["severity"],
        float(parsed["false_positive_likelihood"]),
        parsed["reason"],
        engine="bedrock",
    )


def triage(finding, surrounding_context: str = "") -> Verdict:
    if _USE_BEDROCK:
        try:
            return _bedrock_verdict(finding, surrounding_context)
        except Exception as e:  # noqa: BLE001 — never let triage crash the pipeline
            logger.warning("Bedrock triage failed (%s), falling back to heuristic", e)
    return _heuristic_verdict(finding)


def triage_batch(findings, contexts: dict[str, str] | None = None) -> list[Verdict]:
    contexts = contexts or {}
    return [triage(f, contexts.get(f.fingerprint, "")) for f in findings]
