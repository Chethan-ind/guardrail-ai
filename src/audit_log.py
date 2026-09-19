"""
audit_log.py
Every finding + verdict + remediation action gets written to DynamoDB.
This is the compliance/demo trail: in the video you open this table and
show a real push producing a real row within seconds.
"""

from __future__ import annotations

import logging
import os
import time

import boto3

logger = logging.getLogger("guardrail.audit")

_REGION = os.environ.get("AWS_REGION", "ap-south-1")
_TABLE_NAME = os.environ.get("GUARDRAIL_TABLE_NAME", "guardrail-findings")


def _table():
    dynamodb = boto3.resource("dynamodb", region_name=_REGION)
    return dynamodb.Table(_TABLE_NAME)


def log_finding(repo: str, finding, verdict, vault_arn: str | None, remediated: bool) -> None:
    item = {
        "fingerprint": finding.fingerprint,
        "detected_at": int(time.time()),
        "repo": repo,
        "file_path": finding.file_path,
        "line_no": finding.line_no,
        "finding_type": finding.finding_type,
        "severity": verdict.severity,
        "false_positive_likelihood": str(verdict.false_positive_likelihood),
        "reason": verdict.reason,
        "triage_engine": verdict.engine,
        "vault_arn": vault_arn or "not_stored",
        "remediated": remediated,
    }
    _table().put_item(Item=item)
    logger.info("Audit-logged finding %s (%s)", finding.fingerprint, verdict.severity)


def log_batch(repo: str, findings, verdicts, vault_arns: dict[str, str]) -> None:
    verdict_by_fp = {v.fingerprint: v for v in verdicts}
    for finding in findings:
        verdict = verdict_by_fp[finding.fingerprint]
        arn = vault_arns.get(finding.fingerprint)
        log_finding(repo, finding, verdict, arn, remediated=arn is not None)
