"""
vault.py
Real AWS Secrets Manager integration. Every masked secret gets stored
here under a deterministic name, tagged with the finding type and repo,
so a human can rotate it later instead of it just sitting deleted from
the diff and forgotten.

This module makes real boto3 calls. It works against:
  - real AWS (default credential chain: env vars / IAM role / profile)
  - moto's mocked Secrets Manager, when tests wrap calls in @mock_aws
There is no local-file fallback on purpose — a "vault" that writes
plaintext to disk defeats the point of the project.
"""

from __future__ import annotations

import json
import logging
import os

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger("guardrail.vault")

_REGION = os.environ.get("AWS_REGION", "ap-south-1")
_SECRET_PREFIX = os.environ.get("GUARDRAIL_SECRET_PREFIX", "guardrail/quarantined")


def _client():
    return boto3.client("secretsmanager", region_name=_REGION)


def store_secret(fingerprint: str, finding_type: str, repo: str, value: str) -> str:
    """
    Stores (or updates) one quarantined secret. Returns the ARN.
    """
    client = _client()
    name = f"{_SECRET_PREFIX}/{repo}/{finding_type}/{fingerprint}"
    payload = json.dumps({
        "finding_type": finding_type,
        "repo": repo,
        "fingerprint": fingerprint,
        "value": value,
    })

    try:
        resp = client.create_secret(
            Name=name,
            SecretString=payload,
            Tags=[
                {"Key": "GuardrailManaged", "Value": "true"},
                {"Key": "FindingType", "Value": finding_type},
                {"Key": "Repo", "Value": repo},
            ],
        )
        logger.info("Created new vault entry %s", name)
        return resp["ARN"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceExistsException":
            resp = client.put_secret_value(SecretId=name, SecretString=payload)
            logger.info("Updated existing vault entry %s", name)
            return resp["ARN"]
        raise


def store_batch(repo: str, vault_payload: dict[str, str], finding_types: dict[str, str]) -> list[str]:
    """vault_payload: {fingerprint: value}. finding_types: {fingerprint: finding_type}."""
    arns = []
    for fingerprint, value in vault_payload.items():
        finding_type = finding_types.get(fingerprint, "unknown")
        arns.append(store_secret(fingerprint, finding_type, repo, value))
    return arns
