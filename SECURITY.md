# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | Yes       |

## Reporting a Vulnerability

Do not open a public GitHub issue for security vulnerabilities.

Email the maintainers with a description, steps to reproduce, potential
impact, and any suggested remediation. You will receive an acknowledgement
within 48 hours and a resolution timeline within 5 business days.

## Security Design

- All secrets are stored in AWS Secrets Manager. No plaintext credentials
  in environment variables in production.
- The API validates target_endpoint to prevent SSRF attacks. It blocks
  169.254.169.254, metadata.google.internal, and all non-HTTP/HTTPS schemes.
- The Lambda execution role is least-privilege with explicit DENY statements
  on iam:*, ec2:*, and all destructive operations.
- All data at rest is encrypted with a customer-managed KMS key.
- CI/CD uses GitHub Actions OIDC. No long-lived credentials in GitHub Secrets.
- Dependency scanning runs on every CI build via pip-audit.
- SAST scanning runs on every CI build via bandit.
