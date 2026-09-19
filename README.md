# GuardRail AI

An AWS-native pipeline that detects, triages, masks, and vaults hardcoded
secrets within seconds of a `git push` — instead of just flagging them
and leaving a human to clean up.

Built for WeMakeDevs × AWS **First Commit** (Bharat Builds Tour, Sept
17–20, 2026). See `docs/BUSINESS_REQUIREMENTS.md` for how this repo maps
to the official rules, `docs/WRITEUP.md` for the submission writeup, and
`docs/DEMO_SCRIPT.md` for the 3-minute video script.

## Why

Existing tools (Gitleaks, TruffleHog, detect-secrets, GitHub Push
Protection) detect a hardcoded secret and stop there. GuardRail closes
the loop: mask the value in the diff, quarantine the real value in AWS
Secrets Manager, log it, and alert — automatically, per push.

## Quickstart (no AWS account needed)

```bash
pip install -r requirements.txt
python -m pytest tests/ -v          # 8 unit tests, detector + masker
python -m demo.demo                 # full pipeline against moto-mocked AWS
python -m demo.show_masked_diff     # before/after masking, no AWS at all
```

`demo/demo.py` runs the exact same code path (`src/lambda_handler.run_pipeline`)
that deploys to Lambda, against local fixture files and a mocked AWS
account — so you can see detect → triage → vault → audit → alert work
end-to-end in under a second.

## Deploying for real (what the demo video runs against)

```bash
cd infra
./build_layer.sh                    # packages boto3/requests into a Lambda layer
terraform init
terraform apply \
  -var="github_webhook_secret=<your-secret>" \
  -var="github_token=<fine-grained-PAT-with-contents:read>" \
  -var="alert_email=<your-email>"
```

Copy the `webhook_url` output into your GitHub repo's webhook settings
(content type `application/json`, same secret as above). Confirm the SNS
email subscription (check your inbox). Push a file from `demo/fixtures/`
to trigger it live.

To route triage through a real Bedrock model instead of the offline
heuristic fallback, set `-var="use_bedrock=1"` (the default) and make
sure your account has model access enabled for the configured model ID
in `infra/main.tf`.

## Dashboard

`frontend/index.html` is a self-contained live-ops wallboard — no build
step, no framework. Open it directly in a browser.

- **Draggable panels** — drag any panel by its header to reposition it
  anywhere on the canvas; "Reset layout" puts them back.
- **Demo mode** — click "Load demo data" to see it populated instantly
  with fixture data shaped exactly like what `audit_log.py` writes to
  DynamoDB, no AWS account needed.
- **Live mode** — after `terraform apply`, paste the `findings_api_url`
  output into the API field and click Connect. It polls a read-only
  `GET /findings` route (added in `infra/api_gateway.tf`) that scans the
  DynamoDB table — no write access, no GitHub signature needed for this
  path.
- Panels: Findings stream, Severity mix, Vault ledger, Audit trail, and
  an AWS pulse panel that reflects which services the currently-loaded
  data actually touched (e.g. the Bedrock dot goes amber if every loaded
  finding used the heuristic fallback instead of a live model call).

Good B-roll for the demo video: load demo data on camera once to show
the UI, then switch to live mode and do the real push so the panels
update from an actual DynamoDB write.

## Architecture

See `docs/ARCHITECTURE.md` for the full sequence diagram and a rationale
for every AWS service used — nothing here is a checkbox integration.

```
GitHub push → API Gateway → Lambda
  → detector.py (scan)
  → triage_agent.py (Bedrock agent judgement)
  → masker.py (redact) + vault.py (Secrets Manager)
  → audit_log.py (DynamoDB)
  → alerting.py (SNS + EventBridge)
```

## Splitting the work across a team

If teammates join before the deadline, the pipeline is already split
cleanly by AWS service:

- **Detection/masking** (`detector.py`, `masker.py`) — pure Python, no
  AWS dependency, good first task for anyone getting oriented.
- **Bedrock triage** (`triage_agent.py`) — needs Bedrock model access
  enabled on the account.
- **Infra** (`infra/`) — Terraform, can be built in parallel once the
  Lambda handler's interface is stable.
- **Demo + video** (`docs/DEMO_SCRIPT.md`) — start scripting this Saturday,
  not Sunday night.

## Repo layout

```
src/            application code (see docs/ARCHITECTURE.md)
demo/           local runner + fixtures, no AWS account required
infra/          Terraform for the real deployment
tests/          pytest unit tests
docs/           architecture, writeup, demo script, business-requirements map
```

## License

MIT — see `LICENSE`.
