.PHONY: install test lint typecheck security audit all clean

install:
	pip install -r requirements.txt

test:
	pytest tests/ -v --cov=src --cov-report=term

lint:
	ruff check src/ tests/

typecheck:
	mypy src/ --ignore-missing-imports

security:
	bandit -r src/ -ll

audit:
	pip-audit -r requirements.txt

all: lint typecheck security audit test

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	rm -f coverage.xml .coverage report.json
	rm -rf htmlcov/
