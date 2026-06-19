"""Tests for the AI Attack Surface SSE log stream generator (Step 3).

The Docker log iterator + timestamp parsing + phase detection were previously
only exercised by the live gate. Here container.logs is mocked to yield
timestamped lines, so the async generator is tested without a daemon.
"""
import unittest
from unittest.mock import MagicMock, patch

from docker.errors import NotFound

import container_manager as cm
from container_manager import ContainerManager
from models import AiAttackSurfaceState, AiAttackSurfaceStatus


def make_manager():
    with patch("container_manager.docker") as md:
        md.from_env.return_value = MagicMock()
        mgr = ContainerManager()
    mgr.client = MagicMock()
    mgr.local_llm_manager = MagicMock()
    return mgr


async def _collect(agen):
    return [ev async for ev in agen]


class TestStreamLogs(unittest.IsolatedAsyncioTestCase):
    async def test_yields_parsed_phase_events_in_order(self):
        mgr = make_manager()
        state = AiAttackSurfaceState(project_id="p", run_id="r",
                                     status=AiAttackSurfaceStatus.RUNNING,
                                     container_id="c0ffee")
        mgr.ai_attack_states = {"p": {"r": state}}

        container = MagicMock()
        container.status = "running"
        container.logs.return_value = iter([
            b"2026-06-19T13:00:00.000000000Z [Phase 1] Safety / bounds",
            b"2026-06-19T13:00:01.000000000Z [Phase 2] Target loading",
            b"2026-06-19T13:00:02.000000000Z [Phase 3] Attack (skeleton)",
            b"2026-06-19T13:00:03.000000000Z [Phase 4] Findings",
            b"2026-06-19T13:00:04.000000000Z [*] Done.",
        ])
        mgr.client.containers.get.return_value = container

        events = await _collect(mgr.stream_ai_attack_surface_logs("p", "r"))
        phases = [e.phase_number for e in events if e.is_phase_start]
        self.assertEqual(phases, [1, 2, 3, 4])
        # High-water mark recorded for SSE reconnect resume.
        self.assertIsNotNone(mgr.ai_attack_states["p"]["r"].last_log_timestamp)

    async def test_no_container_id_yields_notice(self):
        mgr = make_manager()
        state = AiAttackSurfaceState(project_id="p", run_id="r",
                                     status=AiAttackSurfaceStatus.RUNNING,
                                     container_id=None)
        mgr.ai_attack_states = {"p": {"r": state}}
        events = await _collect(mgr.stream_ai_attack_surface_logs("p", "r"))
        self.assertEqual(len(events), 1)
        self.assertIn("No AI attack container", events[0].log)

    async def test_container_gone_yields_graceful_stop(self):
        # Connecting after the container was auto-removed must not raise; it
        # yields a "stopped" notice (documents the fast-job race).
        mgr = make_manager()
        state = AiAttackSurfaceState(project_id="p", run_id="r",
                                     status=AiAttackSurfaceStatus.RUNNING,
                                     container_id="gone")
        mgr.ai_attack_states = {"p": {"r": state}}
        mgr.client.containers.get.side_effect = NotFound("gone")
        events = await _collect(mgr.stream_ai_attack_surface_logs("p", "r"))
        self.assertTrue(any("stopped" in e.log.lower() for e in events))


if __name__ == "__main__":
    unittest.main(verbosity=2)
