terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  description = "AWS region to deploy GuardRail into"
  type        = string
  default     = "ap-south-1"
}

variable "project_name" {
  type    = string
  default = "guardrail"
}

variable "github_webhook_secret" {
  description = "Shared secret configured on the GitHub webhook, verified in lambda_handler._verify_signature"
  type        = string
  sensitive   = true
}

variable "github_token" {
  description = "Fine-grained GitHub PAT with contents:read, used to fetch changed-file contents"
  type        = string
  sensitive   = true
}

variable "alert_email" {
  description = "Email address subscribed to the SNS alert topic"
  type        = string
}

variable "use_bedrock" {
  description = "1 to route triage through Bedrock, 0 for the offline heuristic engine"
  type        = string
  default     = "1"
}

variable "bedrock_model_id" {
  type    = string
  default = "anthropic.claude-3-haiku-20240307-v1:0"
}
