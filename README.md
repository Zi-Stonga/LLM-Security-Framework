# LLM Security Testing Framework

[![CI](https://github.com/Zi-Stonga/LLM-Security-Framework/actions/workflows/ci.yml/badge.svg)](https://github.com/Zi-Stonga/LLM-Security-Framework/actions)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://python.org)
[![AWS CDK](https://img.shields.io/badge/AWS_CDK-2.x-orange.svg)](https://docs.aws.amazon.com/cdk)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Security Policy](https://img.shields.io/badge/security-policy-red.svg)](SECURITY.md)

Automated red-team security testing framework for LLM-based applications. It uses Claude to generate realistic adversarial attack prompts, fires them at your target system, and uses Claude again to classify whether each response indicates a real vulnerability. The whole thing runs serverless on AWS. Zero cost when idle, scales automatically when running.

---

## What it does

You point it at any LLM API endpoint. It generates adversarial prompts across 8 OWASP LLM Top-10 vulnerability categories, sends them to your target, and produces a structured report with severity ratings and evidence for every finding. The CLI exits with code 1 when critical or high findings are detected, so you can wire it as a hard CI gate that blocks deployments.

You can run it three ways: from the command line, via the REST API, or on a nightly schedule via EventBridge.

---

## Attack Categories

| Category | What it tests |
|---|---|
| prompt_injection_direct | Direct instruction override: can an attacker replace your system prompt? |
| prompt_injection_indirect | Data-driven injection via documents or retrieved context |
| jailbreak_roleplay | Role-play and persona-based bypasses |
| jailbreak_hypothetical | Hypothetical framing to extract restricted behaviour |
| data_exfiltration | Attempts to leak system prompts, internal configs, or user data |
| denial_of_service | Resource exhaustion via malformed or recursive inputs |
| privilege_escalation | Attempts to gain capabilities beyond what the model should have |
| toxic_content_generation | Harmful content bypass attempts |

---

## Security Design

- Lambda IAM role is least-privilege with explicit DENY on iam:*, ec2:*, and all destructive operations.
- SSRF guard blocks 169.254.169.254, metadata.google.internal, and all non-HTTP/HTTPS schemes.
- CI/CD uses GitHub Actions OIDC. No long-lived AWS credentials stored anywhere.
- All S3 uploads declare SSE-KMS at the call level.
- Dependency scanning via pip-audit and SAST via bandit run on every CI build.

See [SECURITY.md](SECURITY.md) for the full security policy.

---

## Cost

A typical deployment running one nightly scan costs around **$14/month**.

| Service | Est. Monthly Cost |
|---|---|
| Lambda | ~$2.00 |
| Anthropic API | ~$8.00 |
| S3 | ~$0.50 |
| Secrets Manager | ~$0.80 |
| KMS | ~$0.30 |
| CloudWatch | ~$1.00 |
| CodePipeline + CodeBuild | ~$1.76 |
| DynamoDB | ~$0.01 |
| **Total** | **~$14.37/month** |

---

## Quick Start -- CLI

```bash
git clone https://github.com/Zi-Stonga/LLM-Security-Framework.git
cd LLM-Security-Framework
python -m venv .venv
source .venv/Scripts/activate
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-ant-...

python -m src.runner.cli \
  --target https://your-llm-api/v1/messages \
  --categories prompt_injection_direct,jailbreak_roleplay \
  --attacks-per-category 5 \
  --output report.json
```

Exit code 0 means clean. Exit code 1 means critical or high findings. Exit code 2 means no API key.

---

## Quick Start -- Docker Compose

```bash
cp .env.example .env
docker compose up --build
```

Submit a run:

```bash
curl -X POST http://localhost:8000/test \
  -H "Content-Type: application/json" \
  -d '{"target_endpoint":"https://your-api/v1/messages","categories":["prompt_injection_direct"],"attacks_per_category":5}'
```

Poll for results:

```bash
curl http://localhost:8000/status/YOUR_RUN_ID
```

---

## Running Tests

```bash
make test
```

All AWS calls are mocked via moto. No AWS account needed.

---

## Make Commands

```bash
make install    # install dependencies
make test       # pytest with coverage
make lint       # ruff
make typecheck  # mypy
make security   # bandit
make audit      # pip-audit
make all        # run everything
make clean      # remove artifacts
```

---

## Documentation

Full project documentation lives in [docs/specs/](docs/specs/):

- [00 System Overview](docs/specs/00_system_overview.md)
- [01 Architecture](docs/specs/01_architecture.md)
- [02 Data Model](docs/specs/02_data_model.md)
- [03 Workflows and API](docs/specs/03_workflows_and_api.md)
- [04 Implementation Plan](docs/specs/04_implementation_plan.md)
- [05 Local Development](docs/specs/05_local_development.md)
- [06 Result Schemas](docs/specs/06_result_schemas.md)
- [07 Cloud Deployment](docs/specs/07_cloud_deployment.md)

---

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md)

---

## License

MIT -- see [LICENSE](LICENSE).
