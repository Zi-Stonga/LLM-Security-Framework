"""FastAPI application for the LLM Security Testing Framework.

Exposes three endpoints:
- POST /test: accepts a test request, starts the pipeline in the background,
  returns a run_id for polling.
- GET /status/{run_id}: polls DynamoDB for the current run status.
- GET /health: liveness check.

All input is validated via Pydantic field validators before any processing.
The target_api_key field is excluded from all serialisation to prevent
credential leakage in logs or DynamoDB records.
"""
from __future__ import annotations

import json
import logging
import os
import uuid
from typing import List
from urllib.parse import urlparse

from fastapi import BackgroundTasks
from fastapi import FastAPI
from fastapi import HTTPException
from pydantic import BaseModel
from pydantic import Field
from pydantic import field_validator

from src.aws.aws_helpers import dynamo_get
from src.aws.aws_helpers import dynamo_put
from src.aws.aws_helpers import get_api_key
from src.aws.aws_helpers import upload_to_s3
from src.classifier.vulnerability_classifier import VulnerabilityClassifier
from src.generator.attack_generator import ATTACK_CATEGORIES
from src.generator.attack_generator import AttackGenerator
from src.reporter.report_generator import generate_json_report
from src.runner.attack_runner import AttackRunner

logger = logging.getLogger(__name__)

app = FastAPI(title="LLM Security Testing Framework", version="1.1.0")

_ALLOWED_SCHEMES: set = {"https", "http"}
_BLOCKED_HOSTS: set = {"169.254.169.254", "metadata.google.internal"}


class TestRequest(BaseModel):
    """Validated input for a security test run.

    The target_api_key is excluded from serialisation so it never
    appears in DynamoDB records, S3 reports, or structured logs.
    """

    target_endpoint: str
    target_api_key: str = Field(default="", exclude=True)
    categories: List[str] = ["prompt_injection_direct"]
    system_prompt: str = "You are a helpful assistant."
    attacks_per_category: int = Field(default=5, ge=1, le=20)
    concurrency: int = Field(default=5, ge=1, le=20)
    secret_name: str = "security-testing/anthropic-api-key"

    @field_validator("target_endpoint")
    @classmethod
    def validate_endpoint(cls, value: str) -> str:
        """Block SSRF by rejecting non-http/https schemes and blocked hosts.

        Args:
            value: The raw target_endpoint string from the request.

        Returns:
            The validated endpoint string.

        Raises:
            ValueError: If the scheme is not allowed or the host is blocked.
        """
        parsed = urlparse(value)
        if parsed.scheme not in _ALLOWED_SCHEMES:
            raise ValueError(
                f"target_endpoint scheme must be one of {_ALLOWED_SCHEMES};"
                f" got {parsed.scheme!r}"
            )
        if not parsed.netloc:
            raise ValueError("target_endpoint must include a valid host")
        if parsed.hostname in _BLOCKED_HOSTS:
            raise ValueError("target_endpoint points to a blocked address")
        return value

    @field_validator("categories")
    @classmethod
    def validate_categories(cls, value: List[str]) -> List[str]:
        """Reject any category not in the known ATTACK_CATEGORIES list.

        Args:
            value: List of category strings from the request.

        Returns:
            The validated list.

        Raises:
            ValueError: If any category is not in ATTACK_CATEGORIES.
        """
        invalid = [c for c in value if c not in ATTACK_CATEGORIES]
        if invalid:
            raise ValueError(f"Unknown categories: {invalid}")
        return value


class TestResponse(BaseModel):
    """Response returned immediately when a test run is accepted.

    Attributes:
        run_id: UUID to use when polling GET /status/{run_id}.
        message: Human-readable confirmation message.
        status: Always "running" when first returned.
    """

    run_id: str
    message: str
    status: str


@app.get("/health")
async def health() -> dict:
    """Liveness check endpoint.

    Returns:
        Dict with status and service name.
    """
    return {"status": "healthy", "service": "llm-security-testing"}


@app.get("/status/{run_id}")
async def get_status(run_id: str) -> dict:
    """Return the current status of a test run from DynamoDB.

    Args:
        run_id: The UUID returned by POST /test.

    Returns:
        The DynamoDB item for this run, including status and summary.

    Raises:
        HTTPException 503: If RESULTS_TABLE is not configured.
        HTTPException 404: If the run_id is not found in DynamoDB.
    """
    table = os.environ.get("RESULTS_TABLE")
    if not table:
        raise HTTPException(503, "Results table not configured")
    item = dynamo_get(table, {"run_id": run_id, "attack_id": "__meta__"})
    if item is None:
        raise HTTPException(404, f"Run {run_id!r} not found")
    return item


@app.post("/test", response_model=TestResponse, status_code=202)
async def start_test(req: TestRequest, bg: BackgroundTasks) -> TestResponse:
    """Accept a security test request and start the pipeline in the background.

    Returns immediately with a run_id. Poll GET /status/{run_id} for results.

    Args:
        req: Validated TestRequest with target endpoint and test configuration.
        bg: FastAPI BackgroundTasks injected by the framework.

    Returns:
        TestResponse with the run_id and initial status of "running".
    """
    run_id = str(uuid.uuid4())
    bg.add_task(_run_test_pipeline, req, run_id)
    return TestResponse(run_id=run_id, message="Test suite started", status="running")


async def _run_test_pipeline(req: TestRequest, run_id: str) -> None:
    """Execute the full attack pipeline and write results to DynamoDB and S3.

    Writes status="running" on start, "completed" with summary on success,
    or "failed" with error message on any unhandled exception.

    Args:
        req: The validated TestRequest.
        run_id: The UUID for this run, used as the DynamoDB partition key.
    """
    table = os.environ.get("RESULTS_TABLE")
    bucket = os.environ.get("REPORTS_BUCKET")

    _write_run_status(table, run_id, "running")

    try:
        api_key = get_api_key(req.secret_name)
        generator = AttackGenerator(api_key=api_key)

        attacks = []
        for category in req.categories:
            attacks.extend(
                generator.generate_attacks(
                    category, req.system_prompt, req.attacks_per_category
                )
            )

        runner = AttackRunner(req.target_endpoint, req.target_api_key)
        results = await runner.run_suite(attacks, req.system_prompt, req.concurrency)

        classifier = VulnerabilityClassifier(api_key=api_key)
        results = classifier.classify_batch(results)

        report = generate_json_report(results, run_id=run_id)

        if bucket:
            upload_to_s3(report, bucket, f"reports/{run_id}.json")

        summary = json.loads(report)["summary"]
        _write_run_status(table, run_id, "completed", {"summary": summary})

    except Exception as exc:
        logger.exception("Test pipeline failed for run_id=%s", run_id)
        _write_run_status(table, run_id, "failed", {"error": str(exc)})


def _write_run_status(
    table: str | None,
    run_id: str,
    status: str,
    extra: dict | None = None,
) -> None:
    """Write a run status record to DynamoDB.

    Uses attack_id="__meta__" as the sort key for the run-level status record.
    Logs and continues on DynamoDB write failure rather than raising.

    Args:
        table: DynamoDB table name. Does nothing if None.
        run_id: The run UUID (partition key).
        status: Status string: running, completed, or failed.
        extra: Optional additional fields to merge into the item.
    """
    if not table:
        return
    item: dict = {"run_id": run_id, "attack_id": "__meta__", "status": status}
    if extra:
        item.update(extra)
    try:
        dynamo_put(table, item)
    except Exception as exc:
        logger.error("Failed to write run status to DynamoDB: %s", exc)
