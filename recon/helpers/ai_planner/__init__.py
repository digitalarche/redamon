"""AI-planner helpers that delegate small LLM classification calls to the agent.

D3: these callers must present the internal/scanner key so the agent's now-
guarded ``/llm/*`` endpoints accept the request.
"""

import os


def internal_key_headers() -> dict:
    """Header dict carrying the internal/scanner API key for agent /llm/* calls.

    Prefers the scoped ``SCANNER_API_KEY`` (S3/E6) and falls back to
    ``INTERNAL_API_KEY``. An empty value is harmless before the secret is
    generated -- the agent guard fails open until a key exists.
    """
    key = os.environ.get("SCANNER_API_KEY") or os.environ.get("INTERNAL_API_KEY") or ""
    return {"X-Internal-Key": key}
