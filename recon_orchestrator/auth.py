"""Inbound API authentication policy for the recon orchestrator (V1-auth).

This is the security-critical decision: which requests may reach the orchestrator,
which holds the real Docker socket. It is a pure, dependency-free function so it can
be unit-tested in isolation (no FastAPI app, no docker, no network).

Threat: network isolation stops bridge peers (the worker) from reaching the
orchestrator, but a host-net peer (a compromised recon container) shares the host
loopback and can still reach 127.0.0.1:8010. So every request must carry the shared
secret ORCHESTRATOR_API_KEY, which is held ONLY by the webapp (deliberately NOT
INTERNAL_API_KEY, which the recon containers hold and could replay).
"""
import hmac

# Exact-path exemptions. Only `/health` (polled unauthenticated by the Docker
# healthcheck). Exact match means no protected route can masquerade as exempt via
# `/health/`, `/health/../recon/running`, query strings, case changes, etc.
AUTH_EXEMPT_PATHS = frozenset({"/health"})


def is_orchestrator_request_authorized(
    path: str, method: str, presented_key: str, expected_key: str
) -> bool:
    """Return True if a request may proceed, False if it must be rejected (401).

    - Exempt paths (exact match) and CORS preflight (OPTIONS) are always allowed.
    - Otherwise require a constant-time match against the configured key.
    - Fail-closed: if no key is configured (empty), deny everything non-exempt.
    """
    if path in AUTH_EXEMPT_PATHS or method == "OPTIONS":
        return True
    if not expected_key:
        return False
    # Constant-time comparison: never leak the key length/bytes via timing.
    # compare_digest requires both args be str (or both bytes); presented_key is
    # always a str from the header (defaulting to "").
    return hmac.compare_digest(presented_key, expected_key)
