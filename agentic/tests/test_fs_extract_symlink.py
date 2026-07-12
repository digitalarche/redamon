"""
Regression tests for fs_extract tar symlink-target escape (workspace_fs).

Runnable standalone (stdlib only, stubs agent_context):
    python3 agentic/tests/test_fs_extract_symlink.py
or via unittest/pytest from the repo root.
"""
import asyncio
import contextvars
import os
import sys
import tarfile
import tempfile
import types
import unittest
from pathlib import Path

# --- make workspace_fs importable standalone -------------------------------
_AGENTIC = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _AGENTIC not in sys.path:
    sys.path.insert(0, _AGENTIC)

# workspace_fs reads WORKSPACE_ROOT at import time; point it at a temp dir.
_WS_ROOT = tempfile.mkdtemp(prefix="ws_fsx_")
os.environ["WORKSPACE_ROOT"] = _WS_ROOT

# Stub agent_context (only present inside the agent runtime) with a ContextVar
# so _project_id() resolves to a fixed test project.
if "agent_context" not in sys.modules:
    _stub = types.ModuleType("agent_context")
    _stub.current_project_id = contextvars.ContextVar("current_project_id", default="p1")
    sys.modules["agent_context"] = _stub

import workspace_fs  # noqa: E402

PROJECT = "p1"


def _ws() -> Path:
    # Ensure the project workspace + default subdirs exist and return the root.
    return workspace_fs._workspace_root_for(PROJECT)


def _run(coro):
    return asyncio.run(coro)


class TestFsExtractSymlink(unittest.TestCase):
    def setUp(self):
        # Make sure the fixed project is active for _project_id().
        try:
            workspace_fs.current_project_id  # type: ignore[attr-defined]
        except AttributeError:
            pass
        sys.modules["agent_context"].current_project_id.set(PROJECT)
        self.ws = _ws()

    def _make_tar(self, name, build):
        p = self.ws / name
        with tarfile.open(p, "w") as tf:
            build(tf)
        return name  # workspace-relative path for fs_extract

    def test_symlink_escaping_target_is_rejected(self):
        def build(tf):
            info = tarfile.TarInfo("link")
            info.type = tarfile.SYMTYPE
            info.linkname = "../../../../../../etc/passwd"
            tf.addfile(info)
        arc = self._make_tar("malicious_symlink.tar", build)
        out = _run(workspace_fs.fs_extract(arc, "out_sym", format="tar"))
        self.assertIn("unsafe link target", out, out)
        # The escaping symlink must not have been created.
        self.assertFalse((self.ws / "out_sym" / "link").exists())

    def test_tar_slip_name_is_rejected(self):
        def build(tf):
            data = b"x"
            info = tarfile.TarInfo("../evil.txt")
            info.size = len(data)
            import io
            tf.addfile(info, io.BytesIO(data))
        arc = self._make_tar("malicious_slip.tar", build)
        out = _run(workspace_fs.fs_extract(arc, "out_slip", format="tar"))
        self.assertIn("tar-slip", out, out)

    def test_benign_tar_extracts(self):
        def build(tf):
            data = b"hello world"
            import io
            info = tarfile.TarInfo("hello.txt")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        arc = self._make_tar("benign.tar", build)
        out = _run(workspace_fs.fs_extract(arc, "out_ok", format="tar"))
        self.assertIn("Extracted", out, out)
        self.assertTrue((self.ws / "out_ok" / "hello.txt").exists())
        self.assertEqual((self.ws / "out_ok" / "hello.txt").read_bytes(), b"hello world")

    def test_safe_relative_symlink_within_dest_allowed(self):
        def build(tf):
            import io
            data = b"target"
            fi = tarfile.TarInfo("target.txt")
            fi.size = len(data)
            tf.addfile(fi, io.BytesIO(data))
            li = tarfile.TarInfo("link.txt")
            li.type = tarfile.SYMTYPE
            li.linkname = "target.txt"  # stays inside dest
            tf.addfile(li)
        arc = self._make_tar("benign_symlink.tar", build)
        out = _run(workspace_fs.fs_extract(arc, "out_safe", format="tar"))
        self.assertIn("Extracted", out, out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
