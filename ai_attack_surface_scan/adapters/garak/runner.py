"""Invoke garak as a subprocess (TOOL_API.md §1) and locate its report.jsonl."""
from __future__ import annotations

import glob
import logging
import os
import subprocess
from pathlib import Path

logger = logging.getLogger("ai-attack-surface")


def run_garak_scan(
    config_path: str,
    probes: list[str],
    generations: int,
    seed: int,
    report_prefix: str,
    judge_base_url: str | None = None,
    api_key: str | None = None,
    timeout: int | None = None,
):
    """Run garak with the REST generator. Returns (report_path|None, returncode,
    tail_of_output). Never raises on a non-zero garak exit — the caller decides."""
    cmd = [
        "python", "-m", "garak",
        "--model_type", "rest",
        "--generator_option_file", str(config_path),
        "--probes", ",".join(probes),
        "--generations", str(generations),
        "--seed", str(seed),
        "--report_prefix", str(report_prefix),
        "--parallel_attempts", "8",
    ]

    env = dict(os.environ)
    if api_key:
        env["REST_API_KEY"] = api_key
    # Judge-based detectors (if any) use the OpenAI client; point it at the local
    # Ollama OpenAI-compat endpoint so nothing egresses to a hosted model.
    if judge_base_url:
        base = judge_base_url.rstrip("/")
        env.setdefault("OPENAI_API_BASE", base + "/v1")
        env.setdefault("OPENAI_BASE_URL", base + "/v1")
        env.setdefault("OPENAI_API_KEY", "ollama-local")

    logger.info(f"Running garak: {' '.join(cmd)}")
    try:
        proc = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=timeout)
        rc = proc.returncode
        tail = (proc.stdout or "")[-2000:] + (proc.stderr or "")[-2000:]
    except subprocess.TimeoutExpired as e:
        logger.warning(f"garak timed out after {timeout}s")
        rc = -1
        tail = f"TIMEOUT after {timeout}s\n{(e.stdout or '')[-1000:]}"

    report_path = _locate_report(report_prefix)
    if report_path is None:
        logger.warning(f"garak produced no report.jsonl for prefix {report_prefix} (rc={rc})")
    return report_path, rc, tail


def _locate_report(report_prefix: str) -> str | None:
    """garak writes <prefix>.report.jsonl; fall back to a glob in the dir."""
    candidate = f"{report_prefix}.report.jsonl"
    if os.path.exists(candidate):
        return candidate
    matches = sorted(glob.glob(f"{Path(report_prefix).parent}/*.report.jsonl"))
    return matches[-1] if matches else None
