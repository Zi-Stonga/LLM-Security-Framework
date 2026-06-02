#!/bin/bash
set -e
ENDPOINT="http://localhost:4566"
REGION="us-east-1"
echo "=== Initializing LocalStack ==="

aws --endpoint-url=$ENDPOINT --region=$REGION s3 mb s3://dev-llm-security-reports || true

aws --endpoint-url=$ENDPOINT --region=$REGION dynamodb create-table \
  --table-name llm-security-results \
  --attribute-definitions \
    AttributeName=run_id,AttributeType=S \
    AttributeName=attack_id,AttributeType=S \
  --key-schema \
    AttributeName=run_id,KeyType=HASH \
    AttributeName=attack_id,KeyType=RANGE \
  --billing-mode PAY_PER_REQUEST || true

aws --endpoint-url=$ENDPOINT --region=$REGION sqs create-queue \
  --queue-name llm-security-nightly-dlq || true

aws --endpoint-url=$ENDPOINT --region=$REGION sns create-topic \
  --name llm-security-alerts || true

aws --endpoint-url=$ENDPOINT --region=$REGION secretsmanager create-secret \
  --name "security-testing/anthropic-api-key" \
  --secret-string '{"ANTHROPIC_API_KEY":"test-key-localstack"}' || true

echo "=== LocalStack initialization complete ==="
