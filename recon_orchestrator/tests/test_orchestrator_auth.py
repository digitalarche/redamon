#!/usr/bin/env python3
"""Tests for the orchestrator API authentication (V1-auth).

Part A - PURE UNIT tests of the security decision (auth.is_orchestrator_request_
authorized). No FastAPI, no docker, no network: runs anywhere. This is the
security-critical core - it decides which requests reach the Docker-socket holder.

Part B - INTEGRATION / EXPLOIT REPRODUCTION via FastAPI TestClient: a minimal app
WITHOUT the middleware (pre-patch: unauth request succeeds = the vulnerability) vs.
WITH the real middleware (post-patch: unauth = 401, /health exempt, valid key = 200).
Part B is skipped automatically if fastapi/httpx are unavailable.

Run:  cd recon_orchestrator && python3 tests/test_orchestrator_auth.py
      (or inside the orchestrator container, which has fastapi, for Part B)
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import auth  # noqa: E402

PASS = 0
FAIL = 0


def check(desc, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS {desc}")
    else:
        FAIL += 1
        print(f"  FAIL {desc}")


KEY = "s3cret-orchestrator-key-0123456789abcdef"


def allow(desc, path, method, presented, expected=KEY):
    check(f"ALLOW {desc}", auth.is_orchestrator_request_authorized(path, method, presented, expected) is True)


def deny(desc, path, method, presented, expected=KEY):
    check(f"DENY  {desc}", auth.is_orchestrator_request_authorized(path, method, presented, expected) is False)


def part_a_unit():
    print("=== Part A: pure auth-decision unit tests ===")

    print("--- legitimate webapp calls (correct key) ---")
    allow("GET /recon/running with correct key", "/recon/running", "GET", KEY)
    allow("POST /recon/x/start with correct key", "/recon/x/start", "POST", KEY)
    allow("GET /defaults with correct key", "/defaults", "GET", KEY)

    print("--- the exploit: unauthenticated access must be DENIED ---")
    deny("GET /recon/running with NO key", "/recon/running", "GET", "")
    deny("POST /recon/x/start with NO key", "/recon/x/start", "POST", "")
    deny("POST /ai-attack-surface/x/start with NO key", "/ai-attack-surface/x/start", "POST", "")
    deny("DELETE /recon/x/data with NO key", "/recon/x/data", "DELETE", "")
    deny("wrong key", "/recon/running", "GET", "wrong-key")
    deny("almost-right key (trailing space)", "/recon/running", "GET", KEY + " ")
    deny("almost-right key (one char off)", "/recon/running", "GET", KEY[:-1] + "X")
    deny("prefix of the key", "/recon/running", "GET", KEY[:10])

    print("--- /health is exempt (Docker healthcheck), any method, no key ---")
    allow("GET /health no key", "/health", "GET", "")
    allow("HEAD /health no key", "/health", "HEAD", "")

    print("--- CORS preflight (OPTIONS) is exempt ---")
    allow("OPTIONS /recon/x/start no key", "/recon/x/start", "OPTIONS", "")

    print("--- fail-closed: no key configured => deny everything non-exempt ---")
    deny("expected key empty, presented empty", "/recon/running", "GET", "", expected="")
    deny("expected key empty, presented anything", "/recon/running", "GET", "anything", expected="")
    allow("expected key empty, /health still exempt", "/health", "GET", "", expected="")

    print("--- BYPASS attempts: no protected route may masquerade as /health ---")
    deny("/health/ trailing slash (no key)", "/health/", "GET", "")
    deny("/health/../recon/running (no key)", "/health/../recon/running", "GET", "")
    deny("/HEALTH uppercase (no key)", "/HEALTH", "GET", "")
    deny("/health/x subpath (no key)", "/health/x", "GET", "")
    deny("//health double slash (no key)", "//health", "GET", "")
    deny("/healthz (no key)", "/healthz", "GET", "")
    deny("/health with query but wrong route (no key)", "/health2", "GET", "")
    # and the exempt path is NOT a free pass for a wrong key when it IS /health-like:
    deny("/health/../local-llm/ensure (no key)", "/health/../local-llm/ensure", "POST", "")


def part_b_integration():
    print()
    print("=== Part B: ASGI exploit reproduction (pre-patch vs post-patch) ===")
    try:
        import asyncio

        from fastapi import FastAPI, Request
        from fastapi.responses import JSONResponse
    except Exception as e:  # pragma: no cover
        print(f"  SKIP (fastapi unavailable: {e})")
        return

    def build_app(with_auth: bool):
        app = FastAPI()

        if with_auth:
            @app.middleware("http")
            async def mw(request: Request, call_next):
                if auth.is_orchestrator_request_authorized(
                    request.url.path, request.method,
                    request.headers.get("X-Orchestrator-Key", ""), KEY,
                ):
                    return await call_next(request)
                return JSONResponse(status_code=401, content={"detail": "Unauthorized"})

        @app.get("/health")
        async def health():
            return {"status": "healthy"}

        @app.post("/recon/{pid}/start")
        async def start(pid: str):
            # Stand-in for "spawn a container / drive the privileged orchestrator".
            return {"started": pid}

        return app

    async def call(app, method, path, headers=None):
        """Drive an ASGI app directly (no httpx). Returns the HTTP status code."""
        hdrs = [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
        scope = {
            "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
            "method": method, "path": path, "raw_path": path.encode(),
            "query_string": b"", "headers": hdrs, "client": ("127.0.0.1", 12345),
            "server": ("127.0.0.1", 8010), "scheme": "http",
        }
        state = {"status": None}

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(msg):
            if msg["type"] == "http.response.start":
                state["status"] = msg["status"]

        await app(scope, receive, send)
        return state["status"]

    def run(coro):
        return asyncio.new_event_loop().run_until_complete(coro)

    # PRE-PATCH: no middleware -> the exploit works (unauth POST starts a scan).
    pre = build_app(with_auth=False)
    st = run(call(pre, "POST", "/recon/victim/start"))
    check("PRE-PATCH: unauth POST /recon/start SUCCEEDS (200) = the vulnerability", st == 200)

    # POST-PATCH: real middleware in front.
    post = build_app(with_auth=True)
    check("POST-PATCH: unauth POST /recon/start REJECTED (401)",
          run(call(post, "POST", "/recon/victim/start")) == 401)
    check("POST-PATCH: wrong key REJECTED (401)",
          run(call(post, "POST", "/recon/victim/start", {"X-Orchestrator-Key": "wrong"})) == 401)
    check("POST-PATCH: correct key ALLOWED (200)",
          run(call(post, "POST", "/recon/victim/start", {"X-Orchestrator-Key": KEY})) == 200)
    check("POST-PATCH: /health exempt without key (200)",
          run(call(post, "GET", "/health")) == 200)
    check("POST-PATCH: lowercase header name accepted (200)",
          run(call(post, "POST", "/recon/victim/start", {"x-orchestrator-key": KEY})) == 200)


if __name__ == "__main__":
    part_a_unit()
    part_b_integration()
    print()
    print(f"RESULT: PASS={PASS} FAIL={FAIL}")
    sys.exit(0 if FAIL == 0 else 1)
