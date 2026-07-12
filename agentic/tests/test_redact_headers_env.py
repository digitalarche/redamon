"""
Regression test: redact_for_api must mask secret-bearing header values and
stdio env values (not just auth.token) before they leave via /mcp/manifest.

Run inside the agent container (needs pydantic):
    python /app/tests/test_redact_headers_env.py
"""
import sys
import unittest
from pathlib import Path

_AGENTIC_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_AGENTIC_DIR))

import mcp_registry as reg  # noqa: E402

MASK = "••••"


def _stdio(**overrides):
    base = {
        "id": "s1",
        "name": "s1",
        "transport": "stdio",
        "command": "node",
        "args": [],
        "tools": [],
    }
    base.update(overrides)
    return reg.MCPServer(**base)


class RedactHeadersEnvTests(unittest.TestCase):
    def test_masks_token_headers_and_env(self):
        srv = _stdio(
            headers={"X-Api-Key": "headersecret9999", "Content-Type": "application/json"},
            env={"OPENAI_API_KEY": "sk-realenvsecret"},
            auth={"token": "realtoken1234"},
        )
        out = reg.redact_for_api([srv])[0]

        self.assertTrue(out["auth"]["token"].startswith(MASK))
        self.assertNotIn("realtoken", out["auth"]["token"])

        self.assertTrue(out["headers"]["X-Api-Key"].startswith(MASK))
        self.assertNotIn("headersecret", out["headers"]["X-Api-Key"])
        # all header values masked, keys preserved
        self.assertTrue(out["headers"]["Content-Type"].startswith(MASK))
        self.assertEqual(set(out["headers"].keys()), {"X-Api-Key", "Content-Type"})

        self.assertTrue(out["env"]["OPENAI_API_KEY"].startswith(MASK))
        self.assertNotIn("realenvsecret", out["env"]["OPENAI_API_KEY"])

    def test_no_secrets_leaves_empty_maps(self):
        srv = _stdio(auth={"token": "tok12345"})
        out = reg.redact_for_api([srv])[0]
        # empty headers/env stay empty (no crash, nothing to mask)
        self.assertEqual(out.get("headers", {}), {})
        self.assertEqual(out.get("env", {}), {})
        self.assertTrue(out["auth"]["token"].startswith(MASK))


if __name__ == "__main__":
    unittest.main(verbosity=2)
