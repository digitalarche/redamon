"""
Regression + unit + integration tests for the redundant phase-transition loop.

BUG (pre-fix)
-------------
After an auto-approved transition to ``exploitation`` the model re-requested the
SAME transition for several no-op iterations. Root cause: the think node builds
a *stateless* prompt each turn and never replays ``state["messages"]``, so the
only "you are already in exploitation" correction (an AIMessage / HumanMessage
nudge) never reached the reasoning model. Meanwhile the leftover in-progress
"Request transition to exploitation phase" todo and the *absent* execution_trace
breadcrumb kept re-triggering the request. Pre-954e1ff the first redundant
request even routed to generate_response and killed solvable runs.

FIX
---
On auto-approve AND on every redundant same-phase / just-transitioned re-request:
  1. write the correction into ``execution_trace`` (the channel the think LLM
     actually re-reads, rendered as chain_context),
  2. check off the transition todo so it stops reading as open work,
  3. count consecutive no-op requests (``_redundant_transition_count``) so the
     wording escalates ("STOP RE-REQUESTING THE PHASE") on repeats.

HOW TO RUN
----------
Post-fix (mount the edited source over the baked image):
    docker compose run --rm --no-deps \\
      -v "$PWD/agentic/tests:/app/tests" \\
      -v "$PWD/agentic/orchestrator_helpers/nodes/think_node.py:/app/orchestrator_helpers/nodes/think_node.py" \\
      -v "$PWD/agentic/state.py:/app/state.py" \\
      agent python -m unittest -v tests.test_phase_transition_redundant

Pre-fix demonstration (baked source, no edited files mounted):
    docker compose run --rm --no-deps \\
      -v "$PWD/agentic/tests:/app/tests" \\
      agent python -m unittest -v tests.test_phase_transition_redundant
The RegressionThinkNode class fails on assertions and the helper classes error
on import — both prove the pre-fix source is broken.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import os
import sys
import unittest
from unittest.mock import AsyncMock, patch

_agentic_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _agentic_dir)


class _FakeResp:
    """Minimal stand-in for an LLM response object."""
    def __init__(self, content, usage=None):
        self.content = content
        self.usage_metadata = usage or {"input_tokens": 10, "output_tokens": 5}


def _transition_decision_json(**over):
    base = {
        "thought": "recon done, exploit now",
        "reasoning": "workflow says transition before payloads",
        "action": "transition_phase",
        "phase_transition": {
            "to_phase": "exploitation",
            "reason": "map done, exploit now",
            "planned_actions": ["Test ALERT('XSS') payload"],
        },
    }
    base.update(over)
    return json.dumps(base)


# ===========================================================================
# 1. UNIT — _complete_transition_todos (pure dict logic)
# ===========================================================================
class CompleteTransitionTodos(unittest.TestCase):
    def _f(self):
        from orchestrator_helpers.nodes.think_node import _complete_transition_todos
        return _complete_transition_todos

    def test_checks_off_only_the_transition_todo(self):
        f = self._f()
        todos = [
            {"description": "Request transition to exploitation phase", "status": "in_progress"},
            {"description": "Test <script>ALERT('XSS')</script>", "status": "pending"},
            {"description": "Capture flag from XSS response", "status": "pending"},
        ]
        out = f(todos, "exploitation")
        self.assertEqual(out[0]["status"], "completed")
        self.assertEqual(out[1]["status"], "pending")
        self.assertEqual(out[2]["status"], "pending")

    def test_idempotent_when_already_completed(self):
        f = self._f()
        out = f([{"description": "request transition to exploitation", "status": "completed"}], "exploitation")
        self.assertEqual(out[0]["status"], "completed")

    def test_empty_and_none_are_safe(self):
        f = self._f()
        self.assertEqual(f([], "exploitation"), [])
        self.assertEqual(f(None, "exploitation"), [])

    def test_does_not_touch_a_payload_todo_that_merely_names_the_phase(self):
        # "exploitation" appears but there is no "transition" — must stay open.
        f = self._f()
        out = f([{"description": "Run exploitation payload against /page", "status": "pending"}], "exploitation")
        self.assertEqual(out[0]["status"], "pending")

    def test_preserves_other_fields_and_list_length(self):
        f = self._f()
        todos = [{"id": "a1", "description": "Request transition to exploitation", "status": "in_progress", "priority": "high"}]
        out = f(todos, "exploitation")
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["id"], "a1")
        self.assertEqual(out[0]["priority"], "high")
        self.assertEqual(out[0]["status"], "completed")


# ===========================================================================
# 2. UNIT — _phase_breadcrumb_trace (builds the execution_trace correction)
# ===========================================================================
class PhaseBreadcrumbTrace(unittest.TestCase):
    def _f(self):
        from orchestrator_helpers.nodes.think_node import _phase_breadcrumb_trace
        return _phase_breadcrumb_trace

    def test_auto_approve_appends_announcement_step(self):
        f = self._f()
        trace = f({}, {}, 5, "exploitation", redundant=False)
        self.assertEqual(len(trace), 1)
        step = trace[-1]
        self.assertEqual(step["tool_name"], "phase_transition")
        self.assertTrue(step["success"])
        self.assertIn("DO NOT", step["output_analysis"])
        self.assertIn("exploitation", step["output_analysis"])

    def test_first_redundant_is_soft(self):
        f = self._f()
        step = f({}, {}, 6, "exploitation", redundant=True, count=1)[-1]
        self.assertNotIn("STOP", step["output_analysis"])
        self.assertIn("no-op", step["output_analysis"].lower())

    def test_second_redundant_escalates(self):
        f = self._f()
        step = f({}, {}, 7, "exploitation", redundant=True, count=2)[-1]
        self.assertIn("STOP", step["output_analysis"])

    def test_appends_and_does_not_clobber_existing_trace(self):
        f = self._f()
        state = {"execution_trace": [{"iteration": 1, "phase": "informational", "thought": "x", "reasoning": "y"}]}
        trace = f(state, {}, 8, "exploitation", redundant=False)
        self.assertEqual(len(trace), 2)
        self.assertEqual(trace[0]["thought"], "x")

    def test_prefers_updates_trace_over_state_trace(self):
        # If this turn already appended a pending-output step to updates, we must
        # build on that, not on the stale state copy (else we'd drop the step).
        f = self._f()
        state = {"execution_trace": [{"iteration": 1}]}
        updates = {"execution_trace": [{"iteration": 1}, {"iteration": 2}]}
        trace = f(state, updates, 9, "exploitation", redundant=True, count=1)
        self.assertEqual(len(trace), 3)


# ===========================================================================
# 3. REGRESSION / INTEGRATION — real think_node, redundant same-phase request
# ===========================================================================
class RegressionThinkNodeRedundantTransition(unittest.TestCase):
    """The behavioral regression. Fails pre-fix (no counter, no execution_trace
    breadcrumb, todo left in_progress); passes post-fix."""

    def _run_think(self, state):
        import importlib
        # NOTE: `import orchestrator_helpers.nodes.think_node as tn` returns the
        # FUNCTION here — the package __init__ re-exports it as an attribute and
        # dotted `import ... as` uses attribute access. import_module returns the
        # real module from sys.modules, so retry_llm_call is patchable.
        tn = importlib.import_module("orchestrator_helpers.nodes.think_node")
        resp = _FakeResp(_transition_decision_json())
        with patch.object(tn, "retry_llm_call", new=AsyncMock(return_value=resp)):
            return asyncio.run(tn.think_node(
                state,
                {"configurable": {"user_id": "u", "project_id": "p", "session_id": "s"}},
                llm=AsyncMock(),
                guidance_queues={},
                neo4j_creds=("bolt://x", "u", "p"),
            ))

    def _base_state(self, counter=0):
        from state import create_initial_state, TodoItem
        st = create_initial_state("u", "p", "s", "recover the flag", 100)
        st["current_phase"] = "exploitation"      # transition already happened
        st["_just_transitioned_to"] = None         # exercise the same-phase branch
        st["_redundant_transition_count"] = counter
        st["todo_list"] = [
            TodoItem(description="Request transition to exploitation phase", status="in_progress").model_dump(),
            TodoItem(description="Test ALERT payload against /page", status="pending").model_dump(),
        ]
        return st

    def test_increments_redundant_counter(self):
        updates = self._run_think(self._base_state(counter=0))
        self.assertEqual(updates.get("_redundant_transition_count"), 1)

    def test_writes_execution_trace_breadcrumb_the_model_reads(self):
        updates = self._run_think(self._base_state(counter=0))
        trace = updates.get("execution_trace") or []
        self.assertTrue(trace, "execution_trace must carry the correction (messages are not replayed)")
        last = trace[-1]
        self.assertEqual(last.get("tool_name"), "phase_transition")
        self.assertIn("do not request", (last.get("output_analysis") or "").lower())

    def test_checks_off_transition_todo_but_not_the_payload_todo(self):
        updates = self._run_think(self._base_state(counter=0))
        todos = updates.get("todo_list") or []
        trans = [t for t in todos if "transition" in t["description"].lower()]
        payload = [t for t in todos if "ALERT" in t["description"]]
        self.assertTrue(trans and all(t["status"] == "completed" for t in trans))
        self.assertTrue(payload and payload[0]["status"] == "pending")

    def test_second_consecutive_redundant_escalates_to_stop(self):
        updates = self._run_think(self._base_state(counter=1))
        self.assertEqual(updates.get("_redundant_transition_count"), 2)
        trace = updates.get("execution_trace") or []
        self.assertIn("STOP", (trace[-1].get("output_analysis") or ""))


# ===========================================================================
# 4. RELATED BUG (same root cause) — switch_skill rejection must also leave a
#    correction in execution_trace, not only in the unread messages channel.
# ===========================================================================
class SwitchSkillRejectionBreadcrumb(unittest.TestCase):
    def _run_reject(self):
        import importlib
        tn = importlib.import_module("orchestrator_helpers.nodes.think_node")
        from state import create_initial_state
        st = create_initial_state("u", "p", "s", "recover the flag", 100)
        st["current_phase"] = "informational"
        decision = json.dumps({
            "thought": "wrong class", "reasoning": "switch to xss",
            "action": "switch_skill", "skill_switch": {"to_skill": "xss"},
        })
        resp = _FakeResp(decision)
        # Force the rejected outcome deterministically (independent of which skills
        # happen to be enabled in the container's settings). "xss" parses fine.
        with patch.object(tn, "retry_llm_call", new=AsyncMock(return_value=resp)), \
             patch.object(tn, "evaluate_skill_switch", return_value=("rejected", None)):
            return asyncio.run(tn.think_node(
                st,
                {"configurable": {"user_id": "u", "project_id": "p", "session_id": "s"}},
                llm=AsyncMock(),
                guidance_queues={},
                neo4j_creds=("bolt://x", "u", "p"),
            ))

    def test_rejected_switch_skill_writes_execution_trace_breadcrumb(self):
        updates = self._run_reject()
        trace = updates.get("execution_trace") or []
        self.assertTrue(trace, "rejected switch_skill must leave a trace the model reads")
        last = trace[-1]
        self.assertEqual(last.get("tool_name"), "switch_skill")
        self.assertFalse(last.get("success"))
        self.assertIn("do not request", (last.get("output_analysis") or "").lower())


# ===========================================================================
# 5. WIRING — source-inspection backstop (matches the codebase idiom)
# ===========================================================================
class WiringLocks(unittest.TestCase):
    def test_think_node_wires_the_helpers_and_counter(self):
        from orchestrator_helpers.nodes.think_node import think_node
        src = inspect.getsource(think_node)
        self.assertIn("_phase_breadcrumb_trace", src)
        self.assertIn("_complete_transition_todos", src)
        self.assertIn("_redundant_transition_count", src)

    def test_switch_skill_rejection_wires_execution_trace(self):
        from orchestrator_helpers.nodes.think_node import think_node
        src = inspect.getsource(think_node)
        # the rejected branch must build a switch_skill trace step, not only messages
        self.assertIn('tool_name="switch_skill"', src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
