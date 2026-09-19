# Demo Video Script (target: 2:45, hard cap 3:00)

Rule 04 is explicit: "If the video does not show it, it does not count."
Every AWS claim below has a matching on-screen shot. Don't narrate AWS
usage over a slide — show the console.

## Shot list

**0:00–0:15 — The problem (talking head or voiceover + slide)**
"In 2022, a hardcoded credential inside Uber's internal PAM system led to
a breach of 57 million users and a $148M settlement. Secret scanners like
Gitleaks or GitHub Push Protection can *detect* a hardcoded key — none of
them automatically fix it. The leaked value just sits there, flagged,
until a human manually rotates it."

**0:15–0:30 — What GuardRail does (one sentence + architecture diagram)**
Show `docs/ARCHITECTURE.md`'s Mermaid diagram rendered (GitHub renders
Mermaid natively, or export it). "GuardRail is a serverless AWS pipeline
that detects, triages, masks, and vaults a leaked secret automatically,
within seconds of the push that leaked it."

**0:30–1:15 — Live push → live remediation (screen recording, real terminal)**
1. Show the fixture file with a fake AWS key in an editor.
2. `git push` to the real (public) repo wired to the deployed webhook.
3. Cut to **CloudWatch Logs** — show the Lambda invocation firing in
   real time.
4. Cut to **AWS Secrets Manager console** — show the new quarantined
   secret appear, named `guardrail/quarantined/<repo>/<type>/<fingerprint>`.
5. Cut to **DynamoDB console** — show the new audit row: finding type,
   severity, `remediated: true`.
6. Cut to the **email/Slack alert** landing (SNS subscription).

This is the section that proves rule 04's "video has to show AWS" — five
different AWS consoles, all showing a change that happened because of one
real push, not a canned screenshot.

**1:15–1:45 — The agent layer (Bedrock)**
Show the triage verdict — either the CloudWatch log line with
`"engine": "bedrock"`, or (if running the heuristic fallback for this
take) say so explicitly on camera: "Triage here is the offline heuristic
engine — the Bedrock call path is in `triage_agent.py` and used with
`GUARDRAIL_USE_BEDROCK=1`." Being explicit about this avoids
misrepresenting what's live, which rule 03 cares about.

**1:45–2:15 — Before/after masking**
Run `python -m demo.show_masked_diff` on screen. Show the raw secret,
then the masked commit content, side by side. "The variable name and
surrounding code are untouched — only the secret value is replaced, so
the diff stays reviewable."

**2:15–2:35 — Why this over existing tools**
One slide, three bullets: Gitleaks/TruffleHog/detect-secrets detect;
GitHub Push Protection blocks; nothing auto-masks-and-vaults in place.
Say the differentiator once, clearly, don't over-explain.

**2:35–2:45 — Close**
"Built end-to-end on AWS Lambda, API Gateway, Secrets Manager, DynamoDB,
SNS, EventBridge, and Bedrock, over this hackathon weekend. Repo link in
the description."

## Recording checklist before you hit record

- [ ] `terraform apply` succeeded, `webhook_url` output captured
- [ ] GitHub webhook configured with that URL + the same
      `github_webhook_secret` as `infra/main.tf`
- [ ] SNS email subscription confirmed (check inbox for the confirm link —
      easy to forget and then the alert silently never arrives)
- [ ] Fixture push tested once *before* recording, so the live take isn't
      the first time you find a bug
- [ ] Screen recording software already capturing at 1080p+, console text
      legible when re-uploaded and compressed
