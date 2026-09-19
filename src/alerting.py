"""
alerting.py
Publishes a human-readable alert (SNS -> email/Slack subscriber) and a
machine-readable event (EventBridge -> anything downstream can react,
e.g. auto-open a ticket) whenever a high/critical severity finding is
remediated.
"""

from __future__ import annotations

import json
import logging
import os

import boto3

logger = logging.getLogger("guardrail.alerting")

_REGION = os.environ.get("AWS_REGION", "ap-south-1")
_SNS_TOPIC_ARN = os.environ.get("GUARDRAIL_SNS_TOPIC_ARN", "")
_EVENT_BUS = os.environ.get("GUARDRAIL_EVENT_BUS", "default")
_ALERT_THRESHOLD = {"high", "critical"}


def _sns_client():
    return boto3.client("sns", region_name=_REGION)


def _events_client():
    return boto3.client("events", region_name=_REGION)


def notify(repo: str, finding, verdict, remediated: bool) -> None:
    if verdict.severity not in _ALERT_THRESHOLD:
        return

    message = (
        f"[GuardRail] {verdict.severity.upper()} secret remediated in {repo}\n"
        f"File: {finding.file_path}:{finding.line_no}\n"
        f"Type: {finding.finding_type}\n"
        f"Reason: {verdict.reason}\n"
        f"Auto-remediated: {remediated}"
    )

    if _SNS_TOPIC_ARN:
        _sns_client().publish(
            TopicArn=_SNS_TOPIC_ARN,
            Subject=f"GuardRail alert: {verdict.severity} secret in {repo}",
            Message=message,
        )
        logger.info("Published SNS alert for %s", finding.fingerprint)

    _events_client().put_events(
        Entries=[{
            "Source": "guardrail.pipeline",
            "DetailType": "SecretRemediated",
            "Detail": json.dumps({
                "repo": repo,
                "fingerprint": finding.fingerprint,
                "finding_type": finding.finding_type,
                "severity": verdict.severity,
                "remediated": remediated,
            }),
            "EventBusName": _EVENT_BUS,
        }]
    )
    logger.info("Published EventBridge event for %s", finding.fingerprint)


def notify_batch(repo: str, findings, verdicts, remediated_map: dict[str, bool]) -> None:
    verdict_by_fp = {v.fingerprint: v for v in verdicts}
    for finding in findings:
        verdict = verdict_by_fp[finding.fingerprint]
        notify(repo, finding, verdict, remediated_map.get(finding.fingerprint, False))
