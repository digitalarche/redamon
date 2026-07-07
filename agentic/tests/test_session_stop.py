"""
Per-session stop: deleting a conversation must cancel its running agent task so
the loop doesn't keep running headlessly and re-seeding the attack-chain graph.

Run in-container: python -m unittest tests.test_session_stop
"""
import asyncio
import sys
import unittest
from pathlib import Path

_AGENTIC_DIR = str(Path(__file__).resolve().parents[1])
if _AGENTIC_DIR not in sys.path:
    sys.path.insert(0, _AGENTIC_DIR)

try:
    from websocket_api import WebSocketManager, WebSocketConnection
    _HAVE = True
except Exception:
    _HAVE = False


class _FakeWS:
    def __init__(self):
        self.closed = False
        self.client = "test"

    async def close(self, code=1000, reason=""):
        self.closed = True

    async def send_json(self, msg):
        pass


@unittest.skipUnless(_HAVE, "agent deps unavailable (run in-container)")
class StopSession(unittest.TestCase):
    def test_stop_session_cancels_task_and_marks_stopped(self):
        async def scenario():
            mgr = WebSocketManager()

            async def _busy():
                await asyncio.sleep(30)

            task = asyncio.ensure_future(_busy())
            mgr.register_task("u:p:s", task)
            conn = WebSocketConnection(_FakeWS())
            await mgr.authenticate(conn, "u", "p", "s", verified=True)

            cancelled = await mgr.stop_session("u:p:s")
            await asyncio.sleep(0)  # let cancellation propagate

            self.assertTrue(cancelled)
            self.assertTrue(task.cancelled() or task.done())
            self.assertIsNone(mgr.get_task("u:p:s"))
            self.assertTrue(conn._is_stopped)

        asyncio.run(scenario())

    def test_stop_session_no_running_task_returns_false(self):
        async def scenario():
            mgr = WebSocketManager()
            self.assertFalse(await mgr.stop_session("x:y:z"))

        asyncio.run(scenario())

    def test_stop_session_only_targets_its_own_key(self):
        async def scenario():
            mgr = WebSocketManager()

            async def _busy():
                await asyncio.sleep(30)

            other = asyncio.ensure_future(_busy())
            mgr.register_task("other:proj:sess", other)
            mine = asyncio.ensure_future(_busy())
            mgr.register_task("u:p:s", mine)

            await mgr.stop_session("u:p:s")
            await asyncio.sleep(0)

            self.assertTrue(mine.cancelled() or mine.done())
            self.assertFalse(other.cancelled())  # untouched
            other.cancel()

        asyncio.run(scenario())


if __name__ == "__main__":
    unittest.main(verbosity=2)
