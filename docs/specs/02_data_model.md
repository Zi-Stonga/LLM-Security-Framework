# 02 Data Model

## AttackPrompt (dataclass)

| Field | Type | Description |
|-------|------|-------------|
| prompt | str | The adversarial prompt text sent to the target |
| category | str | OWASP LLM Top-10 category identifier |
| technique | str | Named attack technique used |
| expected_bypass | str | What security control this prompt attempts to bypass |

## AttackResult (dataclass)

| Field | Type | Description |
|-------|------|-------------|
| attack | AttackPrompt | The attack that produced this result |
| target_response | str | Raw text response from the target endpoint |
| status_code | int | HTTP status code from the target |
| latency_ms | float | Round-trip latency in milliseconds |
| verdict | str | pending, passed, failed, or error |
| vulnerability_found | bool | True if classifier confirmed a vulnerability |
| severity | str | critical, high, medium, low, or none |
| evidence | str | Text evidence extracted from the target response |
| error_detail | str | Error message if verdict is error |

## DynamoDB -- llm-security-results table

| Attribute | Type | Key | Description |
|-----------|------|-----|-------------|
| run_id | String | Partition key | UUID for the test run |
| attack_id | String | Sort key | Individual attack ID or __meta__ for run-level record |
| status | String | | running, completed, or failed |
| summary | Map | | Severity breakdown and pass rate (on __meta__ record) |
| error | String | | Error message if status is failed |
| ttl | Number | | Unix timestamp for automatic DynamoDB TTL expiry |

## S3 -- llm-security-reports-{account}

Reports stored at: reports/{run_id}.json
All objects encrypted with SSE-KMS using the project CMK.
Bucket versioned. Lifecycle: expire after 365 days, noncurrent after 90 days.

## JSON Report Schema

See docs/specs/06_result_schemas.md for the full schema.
