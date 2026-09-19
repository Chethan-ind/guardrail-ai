"""
demo.py
Runs the exact same pipeline code (src/lambda_handler.run_pipeline) that
deploys to Lambda, but against local fixture files and a moto-mocked AWS
account — so the whole detect -> mask -> vault -> triage -> audit ->
alert loop can be proven end-to-end without needing a live AWS account
wired up first.

For the actual hackathon demo video: deploy infra/ with Terraform and
run this same flow against a real `git push`, then screen-record the
real Secrets Manager / DynamoDB / CloudWatch consoles. This script is
for development and for judges who want to `git clone` and run it in
under a minute.

Usage:
    pip install -r requirements.txt
    python -m demo.demo
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

os.environ.setdefault("AWS_REGION", "ap-south-1")
os.environ.setdefault("GUARDRAIL_TABLE_NAME", "guardrail-findings")
os.environ.setdefault("GUARDRAIL_SNS_TOPIC_ARN", "")  # set after topic creation below
os.environ.setdefault("GUARDRAIL_USE_BEDROCK", "0")  # heuristic triage for offline demo

from moto import mock_aws  # noqa: E402
import boto3  # noqa: E402

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _load_fixtures() -> list[tuple[str, str]]:
    files = []
    for path in sorted(FIXTURES_DIR.iterdir()):
        if path.is_file():
            files.append((str(path.relative_to(FIXTURES_DIR.parent.parent)), path.read_text()))
    return files


def _provision_mock_aws():
    region = os.environ["AWS_REGION"]

    dynamodb = boto3.client("dynamodb", region_name=region)
    dynamodb.create_table(
        TableName=os.environ["GUARDRAIL_TABLE_NAME"],
        KeySchema=[{"AttributeName": "fingerprint", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "fingerprint", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )

    sns = boto3.client("sns", region_name=region)
    topic = sns.create_topic(Name="guardrail-alerts")
    os.environ["GUARDRAIL_SNS_TOPIC_ARN"] = topic["TopicArn"]

    events = boto3.client("events", region_name=region)
    events.create_event_bus(Name="default") if False else None  # 'default' bus always exists


def _print_header(title: str) -> None:
    print("\n" + "=" * 72)
    print(f"  {title}")
    print("=" * 72)


def main():
    with mock_aws():
        _provision_mock_aws()

        # Import AFTER env vars + mock context are live, so boto3 clients
        # inside these modules pick up the mocked region/credentials.
        from src.lambda_handler import run_pipeline

        _print_header("GuardRail AI — local pipeline demo (moto-mocked AWS)")
        files = _load_fixtures()
        print(f"Scanning {len(files)} fixture files:")
        for path, _ in files:
            print(f"  - {path}")

        result = run_pipeline("demo-org/demo-repo", files)

        _print_header("Pipeline result")
        print(f"Findings detected : {result['findings']}")
        print(f"Auto-remediated   : {result.get('remediated', 0)}")
        print(f"Masked files      : {result.get('masked_files', [])}")

        _print_header("Triage verdicts (Bedrock-agent shaped, heuristic engine offline)")
        for v in result.get("verdicts", []):
            print(f"  [{v['severity'].upper():8s}] {v['reason']}  "
                  f"(fp_likelihood={v['false_positive_likelihood']}, engine={v['engine']})")

        _print_header("Secrets Manager — vaulted entries")
        sm = boto3.client("secretsmanager", region_name=os.environ["AWS_REGION"])
        for s in sm.list_secrets().get("SecretList", []):
            print(f"  {s['Name']}")

        _print_header("DynamoDB — audit log")
        ddb = boto3.resource("dynamodb", region_name=os.environ["AWS_REGION"])
        table = ddb.Table(os.environ["GUARDRAIL_TABLE_NAME"])
        for item in table.scan().get("Items", []):
            print(f"  {item['finding_type']:24s} severity={item['severity']:8s} "
                  f"file={item['file_path']}:{item['line_no']} remediated={item['remediated']}")

        _print_header("Done")
        print("Run `python -m demo.show_masked_diff` to see the redacted file contents.")


if __name__ == "__main__":
    main()
