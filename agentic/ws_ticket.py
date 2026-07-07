"""
Agent WebSocket ticket verification (STRIDE S6).

The `/ws/agent` init frame historically self-asserted `user_id`/`project_id`/
`session_id` with no authentication, letting any LAN host that guessed a live
session key hijack the running agent task and evict the operator. To close this
without breaking the direct browser->agent connection, the (JWT-authenticated)
webapp mints a short-lived HS256 ticket bound to the operator's identity, and
the agent verifies it here before registering the session.

Ticket format: a standard compact HS256 JWS produced by the webapp via `jose`
(`webapp/src/lib/auth.ts` -> createWsTicket), claims `{ sub, pid, sid, iat, exp }`.
Verification is stdlib-only (hmac/hashlib/base64) so the agent image needs no
new dependency.

Fail-open convention (mirrors the MCP `MCP_AUTH_TOKEN` design, S10): when
`AGENT_WS_TICKET_SECRET` is unset the agent logs a one-time warning and accepts
the init without a ticket, so dev / pre-generation stacks keep working. Real
deployments get the secret from `redamon.sh ensure_auth_secrets`.
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import time
from typing import Optional

logger = logging.getLogger(__name__)

_warned_failopen = False


def ticket_secret() -> str:
    """Return the configured signing secret, or '' when unset (dev fail-open)."""
    return os.environ.get("AGENT_WS_TICKET_SECRET", "") or ""


def warn_ticket_failopen_once() -> None:
    """Emit a single warning when running without a ticket secret."""
    global _warned_failopen
    if not _warned_failopen:
        logger.warning(
            "AGENT_WS_TICKET_SECRET is not set - /ws/agent init is accepted "
            "without ticket verification (fail-open; dev only). Generate it via "
            "redamon.sh to enforce WebSocket authentication (S6)."
        )
        _warned_failopen = True


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def verify_ws_ticket(ticket: Optional[str], secret: str, *, leeway: int = 30) -> Optional[dict]:
    """Verify a compact HS256 ticket.

    Returns the claims dict on success, or None if the ticket is missing,
    malformed, wrong-algorithm, has a bad signature, is expired, or lacks the
    required `sub`/`pid`/`sid` claims. Never raises.
    """
    if not ticket or not secret:
        return None

    parts = ticket.split(".")
    if len(parts) != 3:
        return None
    header_b64, payload_b64, sig_b64 = parts

    try:
        header = json.loads(_b64url_decode(header_b64))
    except Exception:
        return None
    # Only accept HS256; reject `alg: none` and any asymmetric/other alg.
    if not isinstance(header, dict) or header.get("alg") != "HS256":
        return None

    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    expected_sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    try:
        got_sig = _b64url_decode(sig_b64)
    except Exception:
        return None
    if not hmac.compare_digest(expected_sig, got_sig):
        return None

    try:
        payload = json.loads(_b64url_decode(payload_b64))
    except Exception:
        return None
    if not isinstance(payload, dict):
        return None

    exp = payload.get("exp")
    if not isinstance(exp, (int, float)) or time.time() > exp + leeway:
        return None

    if not payload.get("sub") or not payload.get("pid") or not payload.get("sid"):
        return None

    return payload
