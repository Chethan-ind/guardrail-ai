# GuardRail AI — Submission Writeup

## Problem

Hardcoded secrets in source control are a recurring security risk. A leaked credential can provide unauthorized access to databases, cloud services, APIs, and other infrastructure.

Existing tools such as Gitleaks, TruffleHog, detect-secrets, and GitHub Push Protection are effective at detecting and flagging potential secrets. However, detection alone does not complete the remediation process. A leaked value may still exist in source code until a developer manually removes it, secures the credential, and records what happened.

GuardRail AI was built to close this gap by combining secret detection, AI-assisted triage, automated masking, secure vaulting, audit logging, and alerting in a single serverless AWS pipeline.

## What We Built

GuardRail AI is a serverless security pipeline triggered by GitHub push events. It:

1. **Detects** hardcoded secrets using regex-based signatures for credentials such as AWS access keys, GitHub tokens, private keys, database connection strings, Slack tokens, and Kubernetes credentials. It also uses a Shannon-entropy based detector for high-entropy strings that may represent unknown or previously unseen secrets.

2. **Triages** detected findings using an AI-assisted security analysis layer. When Bedrock model access is available, the finding can be analyzed using an Amazon Bedrock-hosted model to determine severity and false-positive likelihood. GuardRail also includes an offline heuristic fallback so that detection and remediation continue when the model is unavailable.

3. **Masks** detected secret values in the affected source content while preserving the surrounding code and variable names. This makes the remediation visible without exposing the original secret.

4. **Vaults** the original secret value in AWS Secrets Manager so that the sensitive value is removed from the source while remaining securely stored for authorized investigation and credential rotation.

5. **Logs** findings, triage results, and remediation information in Amazon DynamoDB, creating an auditable record of the security event.

6. **Alerts** the team through Amazon SNS and publishes an Amazon EventBridge event so that downstream systems can respond programmatically.

The pipeline runs using AWS Lambda and API Gateway, without requiring a continuously running server.

## Where AWS Fits

| AWS Service             | Role                                                                                        |
| ----------------------- | ------------------------------------------------------------------------------------------- |
| **AWS Lambda**          | Receives the webhook and orchestrates detection, triage, remediation, storage, and alerting |
| **Amazon API Gateway**  | Provides the GitHub webhook and findings API endpoints                                      |
| **Amazon Bedrock**      | Provides the AI-assisted contextual triage layer when model access is enabled               |
| **AWS Secrets Manager** | Securely stores quarantined secret values                                                   |
| **Amazon DynamoDB**     | Stores findings, triage information, and remediation audit records                          |
| **Amazon SNS**          | Sends security alerts to subscribed recipients                                              |
| **Amazon EventBridge**  | Publishes security events for downstream automation                                         |

## AI Tools Used During the Build

The following AI tools were used during development:

* **Claude (Anthropic)** — Used for architecture brainstorming, implementation guidance, boto3 integration, Terraform configuration, debugging, and development of the local test harness.
* **ChatGPT (OpenAI)** — Used for technical guidance, AWS and Terraform troubleshooting, debugging, testing guidance, documentation, and explaining implementation details.

AI tools were used as development assistants. The project implementation, configuration, AWS deployment, testing, integration, and final submission preparation were performed by the project team.

## Current Implementation Status

GuardRail AI currently demonstrates the complete core security workflow:

**GitHub Push → API Gateway → Lambda → Secret Detection → Triage → Masking → Secrets Manager → DynamoDB → SNS / EventBridge → Dashboard**

The deployed system has been tested with a GitHub repository containing simulated secret values. The webhook signature is validated before processing, findings are stored in DynamoDB, detected values are quarantined in Secrets Manager, and the findings are exposed through an API-backed dashboard.

The system also includes an offline heuristic triage path so that the security pipeline remains operational when AI model access is unavailable.

## What's Not Finished

The following limitations are intentionally documented:

* **Detect-and-remediate-forward rather than pre-commit blocking:** GuardRail processes GitHub push events after a push rather than acting as a pre-commit or pre-push blocker. This architecture was chosen to demonstrate an end-to-end automated remediation workflow.

* **Automatic credential rotation:** GuardRail securely vaults detected credentials in AWS Secrets Manager, but it does not yet automatically rotate the compromised credential with the originating provider.

* **Live Bedrock authorization:** The Bedrock integration is implemented, but live model invocation depends on AWS account/model authorization. The deployed system therefore supports a tested heuristic fallback when Bedrock access is unavailable.

* **Production hardening:** Additional production features such as provider-specific automatic rotation, expanded secret signatures, advanced IAM isolation, and deeper downstream integrations can be added in future iterations.

## Demo

The demo demonstrates the complete flow from a GitHub push containing simulated secrets through detection, triage, masking, secure vaulting, DynamoDB audit logging, and dashboard visualization.

The demo clearly identifies whether the AI triage path or the offline heuristic fallback is being used.

## Repository

**GitHub Repository:** https://github.com/Chethan-ind/guardrail-ai

The repository contains the project source and documentation for the GuardRail AI implementation.
