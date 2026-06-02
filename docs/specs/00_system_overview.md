# 00 System Overview

## What This System Does

The LLM Security Testing Framework is a serverless red-team pipeline that
automatically tests LLM-based applications for vulnerabilities defined in
the OWASP LLM Top-10. It uses Claude to generate adversarial attack prompts,
fires them at a target LLM endpoint, uses Claude again to classify each
response for real vulnerabilities, and produces structured JSON reports.

## Why It Exists

Traditional AppSec tooling (WAF, SAST, DAST) cannot detect prompt injection,
jailbreaks, or data exfiltration through LLM interfaces. This framework
fills that gap with automated, continuous, evidence-producing coverage.

## Code Conventions

### Language
Python 3.12. All code targets Python 3.12 for Lambda deployment.
Local development uses Python 3.13 -- behaviour is equivalent for this codebase.

### Naming
- Variables and functions: snake_case
- Classes: PascalCase
- Constants: SCREAMING_SNAKE_CASE
- Private attributes: leading underscore (_name)
- Boolean variables: is_, has_, should_, can_ prefix
- Functions named for what they do: generate_attacks, not attack_generator

### Imports
Order: stdlib, blank line, third-party, blank line, internal.
Each group sorted alphabetically. One import per line.

### File structure
One primary concern per file. Files stay under 300 lines.
If a file would exceed 300 lines, propose a split before proceeding.

### Functions
Single responsibility. Max 20 lines per function body.
Max 4 parameters -- use a dataclass if more are needed.
Early returns over nested conditionals.
No side effects in query functions (get_, fetch_, find_, calculate_).

### Error handling
Never swallow silently. Log with context and re-raise or return structured error.
All external I/O wrapped in error handling.

### Logging
Use the logging module only. No print() in production code.
Structured: include timestamp, level, logger name, message, context.
Levels: DEBUG for tracing, INFO for events, WARNING for recoverable, ERROR for failures.

### Configuration
All config from environment variables. Validated at startup.
No scattered os.getenv() calls -- use a single config object where possible.
No hardcoded values. No secrets in code.

### Docstrings
Every public function and class has a docstring.
Format: one-line summary, blank line, Args:, Returns:, Raises: sections where applicable.

### Testing
Arrange / Act / Assert structure always.
One assertion focus per test.
Every function: happy path + at least one edge case + at least one error path.
Mocks documented with a comment explaining what they replace.
