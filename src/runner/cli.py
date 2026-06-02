"""Command-line interface for the LLM Security Testing Framework.

Runs the full attack pipeline against a target endpoint and writes
JSON and optionally HTML reports to disk.

Exit codes:
    0: No critical or high findings.
    1: One or more critical or high findings detected.
    2: No Anthropic API key found.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys

from src.aws.aws_helpers import get_api_key
from src.classifier.vulnerability_classifier import VulnerabilityClassifier
from src.generator.attack_generator import ATTACK_CATEGORIES
from src.generator.attack_generator import AttackGenerator
from src.reporter.report_generator import generate_html_report
from src.reporter.report_generator import generate_json_report
from src.runner.attack_runner import AttackRunner

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s - %(message)s",
)
logger = logging.getLogger(__name__)


def _build_arg_parser() -> argparse.ArgumentParser:
    """Build and return the CLI argument parser.

    Returns:
        Configured ArgumentParser instance.
    """
    parser = argparse.ArgumentParser(
        description="LLM Security Testing Framework CLI"
    )
    parser.add_argument("--target", required=True, help="Target LLM API endpoint URL")
    parser.add_argument("--target-api-key", default="", help="Bearer token for target API")
    parser.add_argument(
        "--categories",
        default="all",
        help="Comma-separated attack categories, or 'all'",
    )
    parser.add_argument("--system", default="You are a helpful assistant.")
    parser.add_argument("--attacks-per-category", type=int, default=5)
    parser.add_argument("--concurrency", type=int, default=5)
    parser.add_argument("--output", default="report.json")
    parser.add_argument("--html", default="")
    parser.add_argument(
        "--secret-name",
        default="security-testing/anthropic-api-key",
    )
    return parser


def _resolve_categories(categories_arg: str) -> list:
    """Resolve the --categories argument to a list of category strings.

    Args:
        categories_arg: "all" or a comma-separated list of category names.

    Returns:
        List of category strings.
    """
    if categories_arg.lower() == "all":
        return ATTACK_CATEGORIES
    return [c.strip() for c in categories_arg.split(",")]


async def _run(args: argparse.Namespace) -> int:
    """Execute the full attack pipeline and write output files.

    Args:
        args: Parsed CLI arguments.

    Returns:
        Exit code: 0 for no critical/high findings, 1 if found, 2 if no key.
    """
    api_key = get_api_key(args.secret_name)
    if not api_key:
        logger.error("No API key found. Set ANTHROPIC_API_KEY or --secret-name.")
        return 2

    categories = _resolve_categories(args.categories)
    generator = AttackGenerator(api_key=api_key)

    attacks = []
    for category in categories:
        attacks.extend(
            generator.generate_attacks(
                category, args.system, count=args.attacks_per_category
            )
        )

    logger.info("Generated %d attacks across %d categories", len(attacks), len(categories))

    runner = AttackRunner(args.target, args.target_api_key)
    results = await runner.run_suite(attacks, args.system, args.concurrency)

    classifier = VulnerabilityClassifier(api_key=api_key)
    results = classifier.classify_batch(results)

    report = generate_json_report(results)

    with open(args.output, "w", encoding="utf-8") as f:
        f.write(report)

    if args.html:
        with open(args.html, "w", encoding="utf-8") as f:
            f.write(generate_html_report(results))

    severity_breakdown = json.loads(report)["summary"]["severity_breakdown"]
    has_high_or_critical = (
        severity_breakdown.get("critical", 0) + severity_breakdown.get("high", 0) > 0
    )
    return 1 if has_high_or_critical else 0


def main() -> None:
    """Entry point for the CLI. Parses arguments and runs the pipeline."""
    parser = _build_arg_parser()
    args = parser.parse_args()
    sys.exit(asyncio.run(_run(args)))


if __name__ == "__main__":
    main()
