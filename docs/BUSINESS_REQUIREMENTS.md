# Business Requirements — WeMakeDevs × AWS "First Commit" Hackathon

This maps every rule from the official rulebook (Sept 17–20, 2026) to the
specific thing in this repo that satisfies it. Keep this file — it's the
first thing to check before submitting, and it's the fastest way to answer
a judge's "does this actually meet the criteria?" question.

## Eligibility & entry (Rule 01–02)

| Requirement | Status |
|---|---|
| University student in India, 18+ | Team registered under WeMakeDevs account `code2S8BP6`, leader Chethan K |
| WeMakeDevs account + AWS Builder Center profile, student status verified | Owner-side account setup — confirm both are verified before submission, not a code deliverable |
| Team of 1–4, one submission per team | Currently 1/4 seats filled — code and infra here work solo, but the Lambda/Terraform split is deliberately divisible if teammates join (see README "Splitting the work") |

## What you build (Rule 03) — the one that actually gates disqualification

| Requirement | How this repo satisfies it |
|---|---|
| Build starts when the clock opens; pre-built projects don't qualify | Repo history must start fresh at kickoff — **do not** push this zip's contents as one commit; commit it in the logical build order (detector → masker → vault → triage → audit → alerting → handler → infra) across the weekend so the commit timestamps tell the real story. See `docs/DEMO_SCRIPT.md` for the suggested commit cadence |
| Open-source libraries/boilerplate OK; judged on what you added | `boto3`, `moto`, `requests`, Terraform AWS/archive providers are the only third-party dependencies — everything else (detector signatures, masking logic, triage heuristics, pipeline orchestration, IaC) is original |
| **Project must use AWS, and the demo video has to show it** | 5 AWS services wired with real boto3 calls: **Secrets Manager** (vault.py), **DynamoDB** (audit_log.py), **SNS + EventBridge** (alerting.py), **Bedrock** (triage_agent.py), **Lambda + API Gateway** (lambda_handler.py + infra/). The video script in `docs/DEMO_SCRIPT.md` is built specifically to show the AWS consoles, not just the code |
| AI coding tools must be listed in the writeup | Listed in `docs/WRITEUP.md` — be honest about which parts were AI-assisted |
| Work has to be yours; credit anything you didn't write | Only third-party code is the pinned library dependencies, credited in `requirements.txt` / `infra/main.tf` |

## Submissions (Rule 04)

| Requirement | Where it lives |
|---|---|
| Public repository | Push this to a **public** GitHub repo before the deadline — private repos don't count |
| Demo video, ≤ 3 minutes, has to show AWS | Script + shot list in `docs/DEMO_SCRIPT.md` |
| Writeup: problem, build, where AWS fits | `docs/WRITEUP.md` — copy into the submission form, don't just link it |
| Submit early, keep editing until the deadline | Do a "clean but incomplete" submission Friday night as insurance, then keep improving |
| "If the video doesn't show it, it doesn't count" | Every AWS service claimed in the writeup has a corresponding on-screen moment planned in the demo script — nothing is asserted without being shown |

## Judging (Rule 05)

| Criterion (implied by rule 05 + AWS's usual hackathon rubric) | How this project is scoped for it |
|---|---|
| Real-world problem | Grounded in a named, dated incident (2022 Uber breach — hardcoded PAM credentials, 57M users, $148M settlement) rather than a hypothetical |
| Technical depth / AWS usage | 5 services, not 1 — deliberately avoids the common hackathon failure mode of "Bedrock chatbot + nothing else AWS" |
| Working demo, not just slides | `demo/demo.py` proves the full pipeline runs end-to-end today, before any AWS account is even provisioned — reduces risk of a broken live demo |
| Originality vs. existing tools | Differentiator vs. Gitleaks / TruffleHog / detect-secrets / GitHub Push Protection: they detect-and-block; this detects **and auto-remediates** (mask, vault, triage) — stated explicitly in `docs/WRITEUP.md` |

## Fast-track Amazon interview (Rule 06)

Chethan is Final Year (2027 graduation) — eligible by class year. Eligibility
also requires registration details and AWS Builder Center profile to be
correct and verified *before* the hackathon — that's an account-settings
action, not something this codebase can do for you. Do it before Thursday.

A security/infra project is a deliberate choice here over another AI-chatbot
entry: it's a stronger signal for an SDE-track interview because it
demonstrates systems design (IAM scoping, event-driven architecture, IaC)
rather than only prompt engineering.

## Conduct (Rule 07)

Not a code concern — just don't violate the Code of Conduct in team
channels, judge interactions, or the repo's own commit history/comments.

## What's explicitly OUT of scope (be upfront about this in the writeup)

Being honest about trade-offs is worth more to judges than pretending the
project is finished:

- **This is detect-and-remediate-forward, not pre-commit blocking.** The
  secret is already in GitHub's history for one push before GuardRail acts.
  A local pre-commit hook (like the original EnvShield concept) blocks
  before push; this pipeline reacts within seconds after. Both have a
  place — this repo picks the cloud-native, AWS-scored side of that trade
  intentionally for this hackathon.
- **Bedrock triage has a heuristic fallback** (`GUARDRAIL_USE_BEDROCK=0`) so
  the pipeline is fully testable without live model access. Say this
  plainly in the demo video/writeup — claiming a mocked path as a live
  Bedrock call would violate rule 03's "what gets judged is what's real."
- **No git-history rewrite / secret rotation automation yet** — vaulting
  makes the leaked value available to a human to rotate; it doesn't rotate
  it automatically. Listed as a clear "next" item, not hidden.
