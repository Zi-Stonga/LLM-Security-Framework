# 03 Workflows and API

## REST API

### POST /test

Starts a test run in the background. Returns immediately with a run_id.

Request body:

| Field | Type | Required | Default | Constraints |
|-------|------|----------|---------|-------------|
| target_endpoint | str | yes | | https or http only; blocks 169.254.169.254 |
| target_api_key | str | no | "" | Excluded from serialisation and logs |
| categories | list[str] | no | ["prompt_injection_direct"] | Must be valid ATTACK_CATEGORIES values |
| system_prompt | str | no | "You are a helpful assistant." | |
| attacks_per_category | int | no | 5 | 1-20 |
| concurrency | int | no | 5 | 1-20 |
| secret_name | str | no | "security-testing/anthropic-api-key" | |

Response (202 Accepted):

| Field | Type | Description |
|-------|------|-------------|
| run_id | str | UUID to poll for status |
| message | str | Human-readable status message |
| status | str | Always "running" on acceptance |

Error responses: 422 on validation failure.

### GET /status/{run_id}

Poll for test run status.

Response (200):

| Field | Type | Description |
|-------|------|-------------|
| run_id | str | The run UUID |
| attack_id | str | Always "__meta__" for this endpoint |
| status | str | running, completed, or failed |
| summary | object | Present when status is completed |
| error | str | Present when status is failed |

Error responses: 404 if run_id not found. 503 if RESULTS_TABLE not configured.

### GET /health

Returns {"status": "healthy", "service": "llm-security-testing"}.

## CLI Workflow

python -m src.runner.cli --target URL [options]

Exit codes:
- 0: no critical or high findings
- 1: one or more critical or high findings
- 2: no API key found

## Nightly Schedule

EventBridge rule fires at 02:00 UTC daily.
Lambda invoked with retry_attempts=2.
Failed invocations routed to SQS DLQ llm-security-nightly-dlq.
