#!/usr/bin/env python3
"""Server-side enforcement tests for the /graph/exec proxy endpoint (DP5).

The worker (redagraph) no longer holds Neo4j creds — it asks the agent to run
graph queries. ALL enforcement (read-only, tenant scoping, fixed schema/types
queries, no raw/unscoped path) must happen HERE so a compromised worker cannot
bypass it. Run inside the agent container: cd /app && python3 tests/test_graph_exec.py
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

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


def run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


class _FakeSession:
    def __init__(self, capture):
        self.capture = capture

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, params=None):
        self.capture["q"] = query
        self.capture["p"] = params or {}
        return []  # empty result set


class _FakeDriver:
    def __init__(self, capture):
        self.capture = capture

    def session(self):
        return _FakeSession(self.capture)


def main():
    from unittest import mock
    import api

    def req(**kw):
        return api.GraphExecRequest(**kw)

    print("=== read-only enforcement (server-side, authoritative) ===")
    for write in ["CREATE (n:Foo)", "MATCH (n:Foo) DELETE n", "MATCH (n:Foo) SET n.x=1", "MERGE (n:Foo)"]:
        resp = run(api.graph_exec(req(op="cypher", cypher=write, user_id="U", project_id="P")))
        check(f"write rejected 403: {write[:24]}", resp.status_code == 403)

    print("=== un-scoped query refused (no labelled pattern) ===")
    resp = run(api.graph_exec(req(op="cypher", cypher="MATCH (n) RETURN n", user_id="U", project_id="P")))
    check("MATCH (n) RETURN n -> 400 (cannot scope)", resp.status_code == 400)

    print("=== op=cypher: tenant filter injected + executed ===")
    cap = {}
    with mock.patch.object(api, "_graph_exec_get_driver", return_value=_FakeDriver(cap)):
        resp = run(api.graph_exec(req(op="cypher", cypher="MATCH (n:Subdomain) RETURN n.name AS name", user_id="U", project_id="P")))
    check("labelled read -> 200", resp.status_code == 200)
    check("tenant filter injected into executed query", "$tenant_user_id" in cap.get("q", ""))
    check("tenant params bound from request", cap.get("p", {}).get("tenant_user_id") == "U")

    print("=== op=types / op=schema use FIXED server queries (worker can't alter) ===")
    cap = {}
    with mock.patch.object(api, "_graph_exec_get_driver", return_value=_FakeDriver(cap)):
        run(api.graph_exec(req(op="types", user_id="U", project_id="P")))
    check("types query is tenant-scoped", "$tenant_user_id" in cap.get("q", ""))
    cap = {}
    with mock.patch.object(api, "_graph_exec_get_driver", return_value=_FakeDriver(cap)):
        run(api.graph_exec(req(op="schema", user_id="U", project_id="P")))
    check("schema runs the fixed visualization call", "db.schema.visualization" in cap.get("q", ""))

    print("=== the BYPASS attempt: no raw/unscoped op exists ===")
    # A compromised worker cannot ask for an arbitrary unscoped query: there is no
    # 'raw' op, op=cypher forces a labelled pattern + filter, and unknown ops 400.
    resp = run(api.graph_exec(req(op="raw", cypher="MATCH (n) RETURN n", user_id="U", project_id="P")))
    check("unknown op 'raw' -> 400 (no unscoped escape)", resp.status_code == 400)
    resp = run(api.graph_exec(req(op="cypher", cypher="", user_id="U", project_id="P")))
    check("empty cypher -> 400", resp.status_code == 400)
    resp = run(api.graph_exec(req(op="cypher", cypher="MATCH (n:Foo) RETURN n", user_id="", project_id="P")))
    check("missing tenant identity -> 400", resp.status_code == 400)

    print("=== op=cypher blocks apoc.atomic.* (E8 residual, landed with S8) ===")
    resp = run(api.graph_exec(req(op="cypher", cypher="MATCH (n:Foo) CALL apoc.atomic.add(n,'x',1) RETURN n", user_id="U", project_id="P")))
    check("apoc.atomic.* rejected 403", resp.status_code == 403)

    print("=== S8/I8/D7: /graph/exec and /emergency-stop-all require internal auth ===")
    from llm_guard import require_internal_auth

    def _route_deps(path):
        for r in api.app.routes:
            if getattr(r, "path", None) == path:
                return [d.call for d in getattr(r, "dependant", None).dependencies] if getattr(r, "dependant", None) else []
        return None

    ge_deps = _route_deps("/graph/exec")
    es_deps = _route_deps("/emergency-stop-all")
    check("/graph/exec depends on require_internal_auth", ge_deps is not None and require_internal_auth in ge_deps)
    check("/emergency-stop-all depends on require_internal_auth", es_deps is not None and require_internal_auth in es_deps)

    print()
    print(f"RESULT: PASS={PASS} FAIL={FAIL}")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
