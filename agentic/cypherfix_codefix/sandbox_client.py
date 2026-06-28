"""Client for the CodeFix build sandbox (T6/E10).

The UNTRUSTED clone+build+test step of CypherFix must not run inside the agent
container, which holds INTERNAL_API_KEY, the Neo4j/Postgres creds, every per-user
LLM key, and the GitHub token. Instead `github_bash` runs build commands in an
ephemeral, secret-free, network-isolated sandbox container.

The agent cannot reach the privileged orchestrator directly, so it drives the
sandbox through a webapp passthrough authenticated with X-Internal-Key:

    agent ──X-Internal-Key──> webapp ──X-Orchestrator-Key──> orchestrator ──docker──> sandbox

The orchestrator spawns the sandbox (real docker socket) and runs each command via
`docker exec`, so the sandbox shares NO network with the agent.
"""

import logging
import os

import httpx

logger = logging.getLogger(__name__)

WEBAPP_API_URL = os.environ.get("WEBAPP_API_URL", "http://webapp:3000").rstrip("/")
INTERNAL_HEADERS = {"X-Internal-Key": os.environ.get("INTERNAL_API_KEY", "")}

_BASE = f"{WEBAPP_API_URL}/api/internal/codefix-sandbox"


async def spawn(job_id: str) -> None:
    """Start a build sandbox for this job. Raises on failure."""
    async with httpx.AsyncClient(timeout=120.0) as client:
        resp = await client.post(f"{_BASE}/{job_id}/start", headers=INTERNAL_HEADERS)
        resp.raise_for_status()
        logger.info(f"[sandbox] started for job {job_id}")


async def run_bash(job_id: str, command: str, timeout: int = 600) -> dict:
    """Run one shell command in the sandbox. Returns {output, exit_code}.

    Errors are returned as a dict (never raised) so the tool layer surfaces them
    to the LLM as normal tool output rather than crashing the loop.
    """
    # Allow the HTTP call to outlast the in-sandbox `timeout` wrapper.
    http_timeout = min(timeout, 1800) + 60
    try:
        async with httpx.AsyncClient(timeout=http_timeout) as client:
            resp = await client.post(
                f"{_BASE}/{job_id}/exec",
                headers={**INTERNAL_HEADERS, "Content-Type": "application/json"},
                json={"command": command, "timeout": timeout},
            )
            resp.raise_for_status()
            return resp.json()
    except Exception as e:
        logger.error(f"[sandbox] exec failed for job {job_id}: {e}")
        return {"output": f"Error: sandbox execution failed: {e}", "exit_code": 1}


async def teardown(job_id: str) -> None:
    """Best-effort removal of the sandbox and its worktree."""
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            await client.post(f"{_BASE}/{job_id}/stop", headers=INTERNAL_HEADERS)
            logger.info(f"[sandbox] torn down for job {job_id}")
    except Exception as e:
        logger.warning(f"[sandbox] teardown failed for job {job_id}: {e}")
