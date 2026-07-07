"""
STRIDE S6 — agent WebSocket ticket verification + takeover hardening.

Part A (pure, host-runnable): verify_ws_ticket accepts a well-formed HS256
ticket and rejects tampered / expired / wrong-alg / missing-claim ones.

Part B (needs agent deps, SKIPs otherwise): the exploit reproduction at the
WebSocketManager.authenticate() layer — an UNVERIFIED peer that self-asserts a
live session key can NOT transfer the running task or evict the operator; a
VERIFIED reconnect still transfers the task.

Run: python -m unittest tests.test_ws_ticket_auth -v   (from agentic/)
"""
import asyncio
import base64
import hashlib
import hmac
import json
import os
import sys
import time
import unittest
from pathlib import Path

_AGENTIC_DIR = str(Path(__file__).resolve().parents[1])
if _AGENTIC_DIR not in sys.path:
    sys.path.insert(0, _AGENTIC_DIR)

from ws_ticket import verify_ws_ticket  # noqa: E402

SECRET = "0" * 64


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _sign(payload: dict, secret: str = SECRET, alg: str = "HS256") -> str:
    header = {"alg": alg, "typ": "JWT"}
    h = _b64url(json.dumps(header).encode())
    p = _b64url(json.dumps(payload).encode())
    signing_input = f"{h}.{p}".encode("ascii")
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url(sig)}"


def _claims(**over):
    base = {"sub": "user1", "pid": "proj1", "sid": "sess1",
            "iat": int(time.time()), "exp": int(time.time()) + 60}
    base.update(over)
    return base


class VerifyTicket(unittest.TestCase):
    def test_valid_ticket_returns_claims(self):
        claims = verify_ws_ticket(_sign(_claims()), SECRET)
        self.assertIsNotNone(claims)
        self.assertEqual((claims["sub"], claims["pid"], claims["sid"]),
                         ("user1", "proj1", "sess1"))

    def test_missing_ticket(self):
        self.assertIsNone(verify_ws_ticket(None, SECRET))
        self.assertIsNone(verify_ws_ticket("", SECRET))

    def test_no_secret(self):
        self.assertIsNone(verify_ws_ticket(_sign(_claims()), ""))

    def test_wrong_signature(self):
        self.assertIsNone(verify_ws_ticket(_sign(_claims(), secret="9" * 64), SECRET))

    def test_tampered_payload(self):
        tok = _sign(_claims())
        h, _p, s = tok.split(".")
        forged = _b64url(json.dumps(_claims(sub="admin")).encode())
        self.assertIsNone(verify_ws_ticket(f"{h}.{forged}.{s}", SECRET))

    def test_alg_none_rejected(self):
        # classic JWT bypass attempt
        h = _b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
        p = _b64url(json.dumps(_claims()).encode())
        self.assertIsNone(verify_ws_ticket(f"{h}.{p}.", SECRET))

    def test_expired(self):
        self.assertIsNone(verify_ws_ticket(_sign(_claims(exp=int(time.time()) - 120)), SECRET))

    def test_missing_claims(self):
        self.assertIsNone(verify_ws_ticket(_sign({"sub": "u", "exp": int(time.time()) + 60}), SECRET))

    def test_malformed(self):
        self.assertIsNone(verify_ws_ticket("not-a-jwt", SECRET))
        self.assertIsNone(verify_ws_ticket("a.b", SECRET))


# --- Part B: authenticate() takeover hardening -------------------------------
try:
    from websocket_api import WebSocketManager, WebSocketConnection
    _HAVE_WS = True
except Exception as _e:  # pragma: no cover - deps missing on bare host
    _HAVE_WS = False
    _WS_ERR = str(_e)


class _FakeWS:
    def __init__(self):
        self.closed = False
        self.close_code = None
        self.client = "test"

    async def close(self, code=1000, reason=""):
        self.closed = True
        self.close_code = code

    async def send_json(self, msg):
        pass


@unittest.skipUnless(_HAVE_WS, "agent deps unavailable (run in-container)")
class AuthenticateTakeover(unittest.TestCase):
    def test_unverified_peer_cannot_hijack_or_evict(self):
        async def scenario():
            mgr = WebSocketManager()
            victim = WebSocketConnection(_FakeWS())
            # Give the victim a live task so a hijack would be catastrophic.
            async def _busy():
                await asyncio.sleep(5)
            victim._active_task = asyncio.ensure_future(_busy())
            await mgr.authenticate(victim, "u", "p", "s", verified=True)
            self.assertIs(mgr.active_connections["u:p:s"], victim)

            attacker = WebSocketConnection(_FakeWS())
            await mgr.authenticate(attacker, "u", "p", "s", verified=False)

            # Attacker rejected; operator untouched.
            self.assertFalse(attacker.authenticated)
            self.assertTrue(attacker.websocket.closed)
            self.assertEqual(attacker.websocket.close_code, 1008)
            self.assertIs(mgr.active_connections["u:p:s"], victim)
            self.assertFalse(victim.websocket.closed)
            self.assertIsNone(attacker._active_task)
            victim._active_task.cancel()

        asyncio.run(scenario())

    def test_verified_reconnect_transfers_task(self):
        async def scenario():
            mgr = WebSocketManager()
            first = WebSocketConnection(_FakeWS())
            async def _busy():
                await asyncio.sleep(5)
            task = asyncio.ensure_future(_busy())
            first._active_task = task
            await mgr.authenticate(first, "u", "p", "s", verified=True)

            second = WebSocketConnection(_FakeWS())
            await mgr.authenticate(second, "u", "p", "s", verified=True)

            self.assertTrue(second.authenticated)
            self.assertIs(mgr.active_connections["u:p:s"], second)
            self.assertTrue(first.websocket.closed)
            self.assertEqual(first.websocket.close_code, 1000)
            self.assertIs(second._active_task, task)
            task.cancel()

        asyncio.run(scenario())

    def test_new_unverified_session_still_allowed(self):
        # Fail-open: a brand-new session (no collision) connects even unverified.
        async def scenario():
            mgr = WebSocketManager()
            conn = WebSocketConnection(_FakeWS())
            await mgr.authenticate(conn, "u", "p", "fresh", verified=False)
            self.assertTrue(conn.authenticated)
            self.assertIs(mgr.active_connections["u:p:fresh"], conn)

        asyncio.run(scenario())


if __name__ == "__main__":
    unittest.main(verbosity=2)
