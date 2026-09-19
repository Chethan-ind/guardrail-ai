"""
lambda_handler.py
Entry point deployed behind API Gateway. GitHub is configured to POST
a `push` webhook here. For each commit, we pull the changed files'
content via the GitHub Contents API, run them through the pipeline:

    detect -> mask -> vault -> triage -> audit log -> alert

and return a summary. (GitHub can't be told to rewrite history it
already accepted, so this is a "detect-and-remediate-forward" model:
the leak is vaulted + rotated-eligible + alerted within seconds of the
push, not blocked pre-commit. That trade-off is explained in
docs/WRITEUP.md.)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os

import requests

from detector import scan_files
from masker import mask_content
from triage_agent import triage_batch
from vault import store_batch
from audit_log import log_batch
from alerting import notify_batch

logger = logging.getLogger("guardrail.handler")
logger.setLevel(logging.INFO)

_GITHUB_WEBHOOK_SECRET = os.environ.get("GITHUB_WEBHOOK_SECRET", "")
_GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")


def _verify_signature(body: bytes, signature_header: str) -> bool:
    if not _GITHUB_WEBHOOK_SECRET:
        return True  # local/demo mode — no secret configured
    if not signature_header:
        return False
    expected = "sha256=" + hmac.new(
        _GITHUB_WEBHOOK_SECRET.encode(), body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature_header)


def _fetch_file_content(repo_full_name: str, path: str, ref: str) -> str:
    url = f"https://api.github.com/repos/{repo_full_name}/contents/{path}?ref={ref}"
    headers = {"Accept": "application/vnd.github.v3.raw"}
    if _GITHUB_TOKEN:
        headers["Authorization"] = f"token {_GITHUB_TOKEN}"
    resp = requests.get(url, headers=headers, timeout=5)
    resp.raise_for_status()
    return resp.text


def process_push_event(payload: dict) -> dict:
    repo_full_name = payload["repository"]["full_name"]
    ref = payload.get("after", payload.get("ref", "HEAD"))

    changed_paths: set[str] = set()
    for commit in payload.get("commits", []):
        changed_paths.update(commit.get("added", []))
        changed_paths.update(commit.get("modified", []))

    files: list[tuple[str, str]] = []
    for path in changed_paths:
        try:
            content = _fetch_file_content(repo_full_name, path, ref)
            files.append((path, content))
        except Exception as e:  # noqa: BLE001
            logger.warning("Could not fetch %s: %s", path, e)

    return run_pipeline(repo_full_name, files)


def run_pipeline(repo: str, files: list[tuple[str, str]]) -> dict:
    """Core pipeline, decoupled from the webhook transport so demo.py can
    call it directly against local fixture files without a real GitHub
    push, using the exact same code path that runs in Lambda."""

    findings = scan_files(files)
    if not findings:
        return {"repo": repo, "findings": 0, "summary": "clean"}

    finding_types = {f.fingerprint: f.finding_type for f in findings}
    verdicts = triage_batch(findings)

    # Only vault + remediate things the triage layer thinks are real.
    real_findings = [
        f for f, v in zip(findings, verdicts)
        if v.false_positive_likelihood < 0.5
    ]

    masked_by_file: dict[str, str] = {}
    all_vault_payload: dict[str, str] = {}
    for path, content in files:
        file_findings = [f for f in real_findings if f.file_path == path]
        if not file_findings:
            continue
        masked_content, vault_payload = mask_content(content, file_findings)
        masked_by_file[path] = masked_content
        all_vault_payload.update(vault_payload)

    vault_arns = {}
    if all_vault_payload:
        arns = store_batch(repo, all_vault_payload, finding_types)
        vault_arns = dict(zip(all_vault_payload.keys(), arns))

    remediated_map = {fp: fp in vault_arns for fp in finding_types}

    log_batch(repo, findings, verdicts, vault_arns)
    notify_batch(repo, findings, verdicts, remediated_map)

    return {
        "repo": repo,
        "findings": len(findings),
        "remediated": len(vault_arns),
        "masked_files": list(masked_by_file.keys()),
        "verdicts": [v.to_dict() for v in verdicts],
    }


def lambda_handler(event, context):
    method = (
        event.get("requestContext", {}).get("http", {}).get("method")
        or event.get("httpMethod")
        or "POST"
    )

    if method == "OPTIONS":
        return {"statusCode": 200, "headers": _cors_headers(), "body": ""}

    if method == "GET":
        return get_findings(event, context)

    body = event.get("body", "{}")
    raw_body = body.encode() if isinstance(body, str) else body
    signature = event.get("headers", {}).get("x-hub-signature-256", "")

    if not _verify_signature(raw_body, signature):
        return {"statusCode": 401, "body": json.dumps({"error": "bad signature"})}

    payload = json.loads(body)
    result = process_push_event(payload)
    return {"statusCode": 200, "headers": _cors_headers(), "body": json.dumps(result)}


def _cors_headers() -> dict:
    return {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
    }


def get_findings(event, context):
    """
    GET /findings — powers frontend/index.html's live mode. Scans the
    audit table and returns it newest-first as JSON. Separate from the
    webhook path so the dashboard never needs write access or a GitHub
    signature — it's read-only by construction.
    """
    import boto3

    region = os.environ.get("AWS_REGION", "ap-south-1")
    table_name = os.environ.get("GUARDRAIL_TABLE_NAME", "guardrail-findings")
    dynamodb = boto3.resource("dynamodb", region_name=region)
    table = dynamodb.Table(table_name)

    items = table.scan().get("Items", [])
    items.sort(key=lambda i: int(i.get("detected_at", 0)), reverse=True)

    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json", **_cors_headers()},
        "body": json.dumps(items, default=str),
    }
