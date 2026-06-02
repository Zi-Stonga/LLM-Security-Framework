# Changelog

All notable changes to this project are documented here.

## [1.1.0] - 2026-05-16

### Security
- Removed lru_cache from get_api_key() -- replaced with a 5-minute TTL dict cache
- Added SSRF guard on target_endpoint -- blocks metadata IP and non-http/https schemes
- Replaced static AWS credentials in CI/CD with GitHub Actions OIDC
- Replaced deprecated GitHub OAuth in CodePipeline with CodeStar Connections
- Added explicit DENY boundary on Lambda IAM role
- S3 uploads now declare explicit SSE-KMS at call level
- SQS DLQ upgraded from AWS-managed key to customer-managed KMS key
- Replaced abandoned safety scanner with pip-audit

### Fixed
- DynamoDB write was missing required attack_id sort key
- Background task had no error handling
- CloudWatch alarm had no SNS action
- Lambda FunctionError was silently swallowed by lambda_invoke()
- ssm_put() allowed writing empty string as a secret value

### Added
- GET /status/{run_id} polling endpoint
- Reserved concurrency cap on Lambda (10)
- DynamoDB TTL attribute for automatic item expiry
- SNS alarm topic wired to CloudWatch vulnerability alarm
- Full docs/specs/ folder per project AI standards

## [1.0.0] - 2026-05-04

### Added
- Initial release
- Attack generation across 8 OWASP LLM Top-10 categories
- Async attack runner with bounded concurrency
- Claude-powered vulnerability classifier
- JSON and HTML report generation
- FastAPI REST interface
- AWS CDK infrastructure stack
- GitHub Actions CI/CD pipeline
- LocalStack local development environment
- moto-based AWS integration tests
