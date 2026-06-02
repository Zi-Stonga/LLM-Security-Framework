"""Async attack runner that executes AttackPrompts against a target LLM endpoint.

Uses httpx for async HTTP with a bounded semaphore to limit concurrency.
Supports both Anthropic API response format (content[].text) and
OpenAI response format (choices[].message.content).
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import List

import httpx

from src.generator.attack_generator import AttackPrompt

logger = logging.getLogger(__name__)


@dataclass
class AttackResult:
    """Result of executing a single AttackPrompt against a target endpoint.

    Attributes:
        attack: The AttackPrompt that was executed.
        target_response: Extracted text from the target endpoint response.
        status_code: HTTP status code from the target endpoint.
        latency_ms: Round-trip latency in milliseconds.
        verdict: pending, passed, failed, or error.
        vulnerability_found: True if classifier confirmed a vulnerability.
        severity: critical, high, medium, low, or none.
        evidence: Text evidence from the target response.
        error_detail: Error message when verdict is error.
    """

    attack: AttackPrompt
    target_response: str
    status_code: int
    latency_ms: float
    verdict: str = "pending"
    vulnerability_found: bool = False
    severity: str = "none"
    evidence: str = ""
    error_detail: str = ""


class AttackRunner:
    """Executes attack prompts against a target LLM API endpoint.

    Handles both Anthropic and OpenAI compatible response formats.
    Uses asyncio.Semaphore to bound concurrent requests.
    """

    def __init__(
        self,
        target_endpoint: str,
        target_api_key: str = "",
        timeout_seconds: float = 30.0,
    ) -> None:
        """Initialise the runner with a target endpoint.

        Args:
            target_endpoint: Full URL of the target LLM API endpoint.
            target_api_key: Bearer token for the target API. Empty string
                means no Authorization header is sent.
            timeout_seconds: Per-request timeout. Defaults to 30 seconds.
        """
        self.endpoint = target_endpoint
        self.timeout = timeout_seconds
        self.headers: dict = {"Content-Type": "application/json"}
        if target_api_key:
            self.headers["Authorization"] = f"Bearer {target_api_key}"

    async def run_attack(
        self,
        attack: AttackPrompt,
        system_prompt: str = "",
    ) -> AttackResult:
        """Execute a single attack prompt against the target endpoint.

        Args:
            attack: The AttackPrompt to execute.
            system_prompt: System prompt to include in the request payload.

        Returns:
            AttackResult with verdict set to error on any exception.
        """
        payload = {
            "messages": [{"role": "user", "content": attack.prompt}],
            "system": system_prompt,
        }
        start = time.monotonic()
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(
                    self.endpoint, json=payload, headers=self.headers
                )
            latency = (time.monotonic() - start) * 1000
            return AttackResult(
                attack=attack,
                target_response=_extract_response_text(resp),
                status_code=resp.status_code,
                latency_ms=latency,
            )
        except httpx.TimeoutException as exc:
            latency = (time.monotonic() - start) * 1000
            logger.warning("Timeout on attack %r: %s", attack.technique, exc)
            return AttackResult(
                attack=attack,
                target_response="",
                status_code=0,
                latency_ms=latency,
                verdict="error",
                error_detail=f"Timeout: {exc}",
            )
        except Exception as exc:
            latency = (time.monotonic() - start) * 1000
            logger.error("Unexpected error on attack %r: %s", attack.technique, exc)
            return AttackResult(
                attack=attack,
                target_response="",
                status_code=0,
                latency_ms=latency,
                verdict="error",
                error_detail=str(exc),
            )

    async def run_suite(
        self,
        attacks: List[AttackPrompt],
        system_prompt: str = "",
        concurrency: int = 5,
    ) -> List[AttackResult]:
        """Execute a list of attack prompts with bounded concurrency.

        Args:
            attacks: List of AttackPrompt instances to execute.
            system_prompt: System prompt to include in each request.
            concurrency: Maximum concurrent requests. Defaults to 5.

        Returns:
            List of AttackResult instances in the same order as attacks.
        """
        sem = asyncio.Semaphore(concurrency)

        async def _bounded_run(attack: AttackPrompt) -> AttackResult:
            async with sem:
                return await self.run_attack(attack, system_prompt)

        return list(await asyncio.gather(*(_bounded_run(a) for a in attacks)))


def _extract_response_text(resp: httpx.Response) -> str:
    """Extract the text content from a target endpoint response.

    Handles both Anthropic API format (content[0].text) and
    OpenAI API format (choices[0].message.content).

    Args:
        resp: The httpx Response object.

    Returns:
        Extracted text string, or an error description if extraction fails.
    """
    if resp.status_code != 200:
        return f"HTTP {resp.status_code}: {resp.text[:500]}"
    try:
        data = resp.json()
    except Exception:
        return resp.text[:2000]
    if "content" in data and isinstance(data["content"], list):
        return data["content"][0].get("text", "")
    if "choices" in data and data["choices"]:
        return data["choices"][0].get("message", {}).get("content", "")
    return str(data)[:2000]
