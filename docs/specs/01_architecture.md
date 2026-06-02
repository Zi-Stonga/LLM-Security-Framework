# 01 Architecture

## Components

### src/api/main.py
FastAPI application. Two endpoints: POST /test and GET /status/{run_id}.
Validates all input via Pydantic field validators before any processing.
Runs the attack pipeline in a FastAPI BackgroundTask.
Writes status to DynamoDB so callers can poll for completion.

### src/generator/attack_generator.py
AttackGenerator class. Calls Claude to generate adversarial prompts.
Input: category, system_context, count.
Output: list of AttackPrompt dataclass instances.
Retries up to MAX_RETRIES=3 on JSON parse failure with exponential backoff.

### src/runner/attack_runner.py
AttackRunner class. Executes attacks against the target endpoint.
Uses async httpx with asyncio.Semaphore for bounded concurrency.
AttackResult dataclass holds response, status code, latency, and verdict.

### src/classifier/vulnerability_classifier.py
VulnerabilityClassifier class. Calls Claude to classify each AttackResult.
Extracts vulnerability_found, severity, evidence, and remediation from response.
Skips results already marked as error.

### src/reporter/report_generator.py
Two pure functions: generate_json_report and generate_html_report.
No side effects. Input: list of AttackResult. Output: string.

### src/aws/aws_helpers.py
Shared AWS utility functions. No classes -- module-level functions only.
Covers: Secrets Manager, S3, DynamoDB, SQS, SNS, CloudWatch, SSM, Lambda.
API key uses a 5-minute TTL dict cache keyed on (secret_name, region).

### infra/cdk_stack.py
AWS CDK stack. Defines all infrastructure as code.
Lambda, S3, DynamoDB, SQS DLQ, EventBridge, CodePipeline, CloudWatch, SNS, KMS.

## Security Boundaries

- SSRF guard: target_endpoint validated against allowed schemes and blocked hosts
  before any network call.
- IAM: Lambda role is least-privilege with explicit DENY on iam:*, ec2:*, and
  all destructive operations.
- Secrets: API keys in Secrets Manager only. Never in environment variables in
  production. Never logged. Never serialised to JSON.
- Encryption: all data at rest uses a customer-managed KMS key (CMK).
- CI/CD: GitHub Actions OIDC. No long-lived AWS credentials stored anywhere.

## Data Flow

1. Trigger: EventBridge nightly / POST /test / CLI
2. AttackGenerator calls Claude API -- returns adversarial prompts
3. AttackRunner calls target endpoint -- returns responses
4. VulnerabilityClassifier calls Claude API -- classifies each response
5. ReportGenerator produces JSON report
6. Report written to S3 with SSE-KMS
7. Run metadata written to DynamoDB
8. CloudWatch alarm fires to SNS on critical/high findings
