# 05 Local Development

## Prerequisites

- Python 3.12 or higher
- Git
- Docker Desktop (for Docker Compose with LocalStack)
- An Anthropic API key from console.anthropic.com

## Setup

```bash
git clone https://github.com/Zi-Stonga/LLM-Security-Framework.git
cd LLM-Security-Framework
python -m venv .venv
source .venv/Scripts/activate   # Windows Git Bash
pip install -r requirements.txt
cp .env.example .env
# Set ANTHROPIC_API_KEY in .env
```

## Activate venv each session

```bash
cd "/c/Users/Zinakho Stonga/Documents/GitHub/Dev/LLM-Security-Framework"
source .venv/Scripts/activate
```

## Run tests

```bash
pytest tests/ -v
```

All AWS calls are mocked with moto. No real AWS account needed.

## Run all quality checks

```bash
make all
```

Runs: ruff lint, mypy type check, bandit SAST, pip-audit, pytest with coverage.

## Run the API locally

```bash
uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --reload
```

## Run with Docker Compose and LocalStack

```bash
docker compose up --build
```

Starts the app and a full local AWS stack (S3, DynamoDB, SQS, SNS, Secrets Manager).

## Run the CLI

```bash
python -m src.runner.cli \
  --target https://your-llm-api/v1/messages \
  --target-api-key sk-ant-... \
  --categories prompt_injection_direct,jailbreak_roleplay \
  --attacks-per-category 5 \
  --output report.json
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| ANTHROPIC_API_KEY | Local dev only | Anthropic API key |
| REPORTS_BUCKET | Production | S3 bucket name |
| RESULTS_TABLE | Production | DynamoDB table name |
| SECRET_NAME | Production | Secrets Manager path |
| LOG_LEVEL | Optional | DEBUG/INFO/WARNING/ERROR |
| AWS_DEFAULT_REGION | Optional | Default: us-east-1 |
| AWS_ENDPOINT_URL | Local dev only | LocalStack override |
