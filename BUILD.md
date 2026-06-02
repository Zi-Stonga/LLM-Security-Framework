# Build Guide

## Prerequisites

- Python 3.12 or higher
- Git
- Docker Desktop (for Docker Compose with LocalStack)
- An Anthropic API key from console.anthropic.com
- AWS CLI (for deployment only)
- Node.js 18 or higher (for CDK deployment only)

## Local setup

```bash
git clone https://github.com/Zi-Stonga/LLM-Security-Framework.git
cd LLM-Security-Framework
python -m venv .venv
source .venv/Scripts/activate
pip install -r requirements.txt
cp .env.example .env
```

Set ANTHROPIC_API_KEY in .env.

## Activate venv each session

```bash
cd "/c/Users/Zinakho Stonga/Documents/GitHub/Dev/LLM-Security-Framework"
source .venv/Scripts/activate
```

## Run tests

```bash
pytest tests/ -v
```

## Run all quality checks

```bash
make all
```

## Run the API

```bash
uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --reload
```

## Run with Docker Compose and LocalStack

```bash
docker compose up --build
```

## Run the CLI

```bash
python -m src.runner.cli \
  --target https://your-llm-api/v1/messages \
  --categories prompt_injection_direct \
  --attacks-per-category 5 \
  --output report.json
```

## Deploy to AWS

```bash
aws secretsmanager create-secret \
  --name security-testing/anthropic-api-key \
  --secret-string '{"ANTHROPIC_API_KEY":"sk-ant-..."}'

cd infra
pip install -r requirements-cdk.txt
npm install -g aws-cdk
cdk bootstrap
cdk deploy
```

## Common issues

- pytest not found: activate the venv first with source .venv/Scripts/activate
- ModuleNotFoundError: run pytest from the repo root
- ValidationError blocked address: the SSRF guard is working. Use a real https endpoint
