# 07 Cloud Deployment

## Prerequisites

- AWS CLI configured
- Node.js 18 or higher
- AWS CDK CLI: npm install -g aws-cdk

## Step 1 -- Store the Anthropic API key

```bash
aws secretsmanager create-secret \
  --name security-testing/anthropic-api-key \
  --secret-string '{"ANTHROPIC_API_KEY":"sk-ant-..."}'
```

## Step 2 -- Fill in infra/cdk.json

Replace all REPLACE_WITH_ placeholder values:
- account: your 12-digit AWS account ID
- github_owner: Zi-Stonga
- github_repo: LLM-Security-Framework
- codestar_connection_arn: from AWS Console, Developer Tools, Connections

## Step 3 -- Deploy

```bash
cd infra
pip install -r requirements-cdk.txt
cdk bootstrap
cdk deploy
```

## Step 4 -- Set up GitHub Actions OIDC

1. In AWS IAM, create an OIDC identity provider:
   URL: https://token.actions.githubusercontent.com
   Audience: sts.amazonaws.com

2. Create an IAM role with trust condition:
   token.actions.githubusercontent.com:sub StringEquals
   repo:Zi-Stonga/LLM-Security-Framework:ref:refs/heads/main

3. Attach a policy allowing lambda:UpdateFunctionCode on the function ARN only.

4. Store the role ARN as AWS_DEPLOY_ROLE_ARN in:
   GitHub repo, Settings, Environments, staging, Secrets.

## Infrastructure Created

- Lambda function: llm-security-test-runner (Python 3.12, 1GB, 15min timeout)
- S3 bucket: llm-security-reports-{account} (versioned, KMS, HTTPS-only)
- DynamoDB table: llm-security-results (composite key, CMK, PITR, TTL)
- KMS CMK: alias/llm-security-testing (annual rotation)
- SQS DLQ: llm-security-nightly-dlq (CMK encrypted)
- EventBridge rule: nightly at 02:00 UTC
- CodePipeline: llm-security-testing
- CloudWatch alarm: LLMSecurity-CriticalOrHighVuln
- SNS topic: llm-security-alerts

## Environment Variables (Lambda)

Set automatically by CDK:
- REPORTS_BUCKET
- RESULTS_TABLE
- SECRET_NAME
- LOG_LEVEL
