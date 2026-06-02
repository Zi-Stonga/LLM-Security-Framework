# Contributing

## Getting started

```bash
git clone https://github.com/Zi-Stonga/LLM-Security-Framework.git
cd LLM-Security-Framework
python -m venv .venv
source .venv/Scripts/activate
pip install -r requirements.txt
pytest tests/ -v
```

## Before submitting a PR

Run make all and confirm zero failures:

```bash
make all
```

## Rules

- One logical change per PR
- Every new function needs a docstring, a happy path test, an edge case
  test, and an error path test
- No secrets, credentials, or real API keys committed
- All tests must pass before requesting review
- Update CHANGELOG.md under the Unreleased section
