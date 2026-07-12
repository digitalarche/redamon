"""
Regression: the agent's /mcp/* endpoints must be internal-auth gated.

/mcp/test spawns an operator-supplied stdio command, and /mcp/manifest returns
server config; leaving them unauthenticated let any agent-bridge peer reach
them. This test asserts each carries the require_internal_auth_only dependency.

Runs inside the agent container (imports the FastAPI app + its deps):
    python /app/test_mcp_endpoints_gated.py
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import api  # noqa: E402

GATED = {"/mcp/test", "/mcp/reload", "/mcp/manifest"}


def _dep_names(route):
    names = []
    for d in list(getattr(route, "dependencies", []) or []):
        call = getattr(d, "dependency", None)
        names.append(getattr(call, "__name__", str(call)))
    return names


class McpEndpointsGatedTests(unittest.TestCase):
    def test_mcp_endpoints_require_internal_auth(self):
        found = {}
        for r in api.app.routes:
            p = getattr(r, "path", "")
            if p in GATED:
                found[p] = _dep_names(r)
        for p in GATED:
            self.assertIn(p, found, f"{p} route not registered")
            self.assertIn(
                "require_internal_auth_only",
                found[p],
                f"{p} is not internal-auth gated (deps: {found[p]})",
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
