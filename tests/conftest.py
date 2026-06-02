"""Shared pytest fixtures applied automatically to every test in the suite.

Sets dummy AWS credentials so moto can intercept boto3 calls without
contacting real AWS endpoints. Sets a dummy ANTHROPIC_API_KEY so
tests that instantiate clients do not fail on missing env vars.
"""
import pytest


@pytest.fixture(autouse=True)
def set_test_env(monkeypatch):
    """Inject required environment variables for all tests.

    Moto requires AWS credential env vars to be set even though it
    intercepts all API calls. The values are intentionally fake.
    """
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-for-unit-tests")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


@pytest.fixture
def anyio_backend():
    """Force anyio to use the asyncio backend for async tests."""
    return "asyncio"
