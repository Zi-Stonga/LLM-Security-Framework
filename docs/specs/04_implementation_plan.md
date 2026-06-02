# 04 Implementation Plan

## Status: v1.1.0 -- Complete

## Phase 1 -- Core Pipeline (Complete)

- AttackGenerator with Claude API and retry logic
- AttackRunner with async httpx and bounded concurrency
- VulnerabilityClassifier with Claude API
- JSON and HTML report generation
- FastAPI endpoints: POST /test, GET /status/{run_id}, GET /health

## Phase 2 -- AWS Infrastructure (Complete)

- CDK stack: Lambda, S3, DynamoDB, SQS DLQ, EventBridge, CodePipeline,
  CloudWatch, SNS, KMS CMK
- Least-privilege IAM with explicit DENY boundary
- LocalStack local development environment

## Phase 3 -- Security Hardening (Complete)

13 issues identified and resolved:
- SSRF guard on target_endpoint (Critical)
- API key TTL cache replacing unsafe lru_cache (High)
- Background task error handling and DynamoDB status writes (High)
- DynamoDB sort key fix (High)
- IAM least-privilege replacing CDK convenience grants (High)
- GitHub Actions OIDC replacing static credentials (High)
- CodeStar Connections replacing deprecated GitHub OAuth (High)
- CloudWatch alarm SNS action wired (Medium)
- SQS DLQ upgraded from AWS-managed key to CMK (Medium)
- S3 upload explicit SSE-KMS at call level (Medium)
- pip-audit replacing abandoned safety scanner (Medium)
- Lambda reserved concurrency cap (Low)
- Hardcoded account ID placeholder removed (Info)

## Phase 4 -- Next Steps

- Add authentication to POST /test endpoint
- VPC placement for Lambda
- AWS Config rules for drift detection
- CloudTrail data events on S3 and DynamoDB
