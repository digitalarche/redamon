"""Tests for Deep Think feature — trigger conditions, parsing, and state management."""

import os
import unittest
import json
from unittest.mock import patch

from state import CompetingHypothesis, DeepThinkResult, LLMDecision
from orchestrator_helpers.parsing import try_parse_llm_decision


class TestDeepThinkResult(unittest.TestCase):
    """Test DeepThinkResult Pydantic model parsing."""

    def test_parse_valid_json(self):
        raw = json.dumps({
            "situation_assessment": "Target has port 80 open",
            "attack_vectors_identified": ["SQLi", "XSS"],
            "recommended_approach": "Start with SQLi on login form",
            "priority_order": ["SQLi", "XSS", "SSRF"],
            "risks_and_mitigations": "WAF may block payloads"
        })
        result = DeepThinkResult.model_validate_json(raw)
        self.assertEqual(result.situation_assessment, "Target has port 80 open")
        self.assertEqual(len(result.attack_vectors_identified), 2)
        self.assertEqual(result.priority_order[0], "SQLi")

    def test_parse_with_markdown_fences(self):
        """LLMs often wrap JSON in ```json ... ``` fences."""
        inner = json.dumps({
            "situation_assessment": "Test",
            "attack_vectors_identified": [],
            "recommended_approach": "Test approach",
            "priority_order": [],
            "risks_and_mitigations": "None"
        })
        raw = f"```json\n{inner}\n```"
        # Strip fences (same logic as think_node)
        if raw.startswith("```"):
            raw = raw.split("\n", 1)[1] if "\n" in raw else raw[3:]
            if raw.endswith("```"):
                raw = raw[:-3].strip()
        result = DeepThinkResult.model_validate_json(raw)
        self.assertEqual(result.situation_assessment, "Test")

    def test_parse_minimal_fields(self):
        """Only required fields, defaults for lists."""
        raw = json.dumps({
            "situation_assessment": "Minimal",
            "recommended_approach": "Do something",
            "risks_and_mitigations": "Low risk"
        })
        result = DeepThinkResult.model_validate_json(raw)
        self.assertEqual(result.attack_vectors_identified, [])
        self.assertEqual(result.priority_order, [])


class TestLLMDecisionNeedDeepThink(unittest.TestCase):
    """Test need_deep_think field in LLMDecision."""

    def test_default_false_when_absent(self):
        """need_deep_think defaults to False when not in JSON."""
        decision, error = try_parse_llm_decision(json.dumps({
            "thought": "Scanning target",
            "reasoning": "Need port info",
            "action": "use_tool",
            "tool_name": "execute_nmap",
            "tool_args": {"target": "10.0.0.1", "args": "-sV"},
        }))
        self.assertIsNotNone(decision)
        self.assertFalse(decision.need_deep_think)

    def test_explicit_true(self):
        """LLM explicitly sets need_deep_think: true."""
        decision, error = try_parse_llm_decision(json.dumps({
            "thought": "I keep trying the same approach",
            "reasoning": "Not making progress, need to rethink",
            "action": "use_tool",
            "tool_name": "execute_command",
            "tool_args": {"command": "nmap -sV 10.0.0.1"},
            "need_deep_think": True,
        }))
        self.assertIsNotNone(decision)
        self.assertTrue(decision.need_deep_think)

    def test_explicit_false(self):
        """LLM explicitly sets need_deep_think: false."""
        decision, error = try_parse_llm_decision(json.dumps({
            "thought": "Making good progress",
            "reasoning": "Found open ports",
            "action": "use_tool",
            "tool_name": "execute_nmap",
            "tool_args": {"target": "10.0.0.1", "args": "-sC"},
            "need_deep_think": False,
        }))
        self.assertIsNotNone(decision)
        self.assertFalse(decision.need_deep_think)


class TestDeepThinkTriggerConditions(unittest.TestCase):
    """Test the trigger detection logic (extracted from think_node)."""

    def _detect_trigger(self, iteration, just_transitioned, exec_trace, need_deep_think):
        """Replicate the trigger detection logic from think_node."""
        trigger_reason = None

        # Condition 1: first iteration
        if iteration == 1:
            trigger_reason = "First iteration — establishing initial strategy"

        # Condition 2: phase transition
        elif just_transitioned:
            trigger_reason = f"Phase transition to {just_transitioned} — re-evaluating strategy"

        # Condition 3: failure loop (3+ consecutive failures)
        if not trigger_reason and len(exec_trace) >= 3:
            consecutive = 0
            for step in reversed(exec_trace[-6:]):
                out = ((step.get("tool_output") or "")[:500]).lower()
                is_fail = (
                    not step.get("success", True)
                    or "failed" in out
                    or "error" in out
                    or "exploit completed, but no session" in out
                )
                if is_fail:
                    consecutive += 1
                else:
                    break
            if consecutive >= 3:
                trigger_reason = f"Failure loop detected ({consecutive} consecutive failures) — pivoting strategy"

        # Condition 4: LLM self-requested
        if not trigger_reason and need_deep_think:
            trigger_reason = "Agent self-assessed stagnation — strategic re-evaluation requested"

        return trigger_reason

    def test_trigger_first_iteration(self):
        reason = self._detect_trigger(iteration=1, just_transitioned=None, exec_trace=[], need_deep_think=False)
        self.assertIn("First iteration", reason)

    def test_trigger_phase_transition(self):
        reason = self._detect_trigger(iteration=5, just_transitioned="exploitation", exec_trace=[], need_deep_think=False)
        self.assertIn("Phase transition to exploitation", reason)

    def test_trigger_failure_loop_3(self):
        trace = [
            {"success": False, "tool_output": "Connection refused"},
            {"success": False, "tool_output": "Error: timeout"},
            {"success": False, "tool_output": "Failed to connect"},
        ]
        reason = self._detect_trigger(iteration=5, just_transitioned=None, exec_trace=trace, need_deep_think=False)
        self.assertIn("Failure loop detected", reason)
        self.assertIn("3 consecutive failures", reason)

    def test_trigger_failure_loop_keyword_error(self):
        """success=True but output contains 'error' keyword."""
        trace = [
            {"success": True, "tool_output": "error: permission denied"},
            {"success": True, "tool_output": "Error occurred during scan"},
            {"success": True, "tool_output": "Command failed with error code 1"},
        ]
        reason = self._detect_trigger(iteration=5, just_transitioned=None, exec_trace=trace, need_deep_think=False)
        self.assertIn("Failure loop detected", reason)

    def test_trigger_failure_loop_broken_by_success(self):
        """2 failures then 1 success — should NOT trigger."""
        trace = [
            {"success": True, "tool_output": "Found open port 80"},
            {"success": False, "tool_output": "Failed"},
            {"success": False, "tool_output": "Failed"},
        ]
        reason = self._detect_trigger(iteration=5, just_transitioned=None, exec_trace=trace, need_deep_think=False)
        self.assertIsNone(reason)

    def test_trigger_self_request(self):
        """Condition 4: LLM self-requested deep think."""
        trace = [
            {"success": True, "tool_output": "Found some info"},
            {"success": True, "tool_output": "Scan complete"},
        ]
        reason = self._detect_trigger(iteration=5, just_transitioned=None, exec_trace=trace, need_deep_think=True)
        self.assertIn("Agent self-assessed stagnation", reason)

    def test_self_request_not_triggered_when_first_iteration(self):
        """Condition 1 takes priority over condition 4."""
        reason = self._detect_trigger(iteration=1, just_transitioned=None, exec_trace=[], need_deep_think=True)
        self.assertIn("First iteration", reason)
        self.assertNotIn("stagnation", reason)

    def test_self_request_not_triggered_when_phase_transition(self):
        """Condition 2 takes priority over condition 4."""
        reason = self._detect_trigger(iteration=5, just_transitioned="exploitation", exec_trace=[], need_deep_think=True)
        self.assertIn("Phase transition", reason)
        self.assertNotIn("stagnation", reason)

    def test_self_request_not_triggered_when_failure_loop(self):
        """Condition 3 takes priority over condition 4."""
        trace = [
            {"success": False, "tool_output": "error"},
            {"success": False, "tool_output": "error"},
            {"success": False, "tool_output": "error"},
        ]
        reason = self._detect_trigger(iteration=5, just_transitioned=None, exec_trace=trace, need_deep_think=True)
        self.assertIn("Failure loop", reason)
        self.assertNotIn("stagnation", reason)

    def test_no_trigger(self):
        """Normal operation — no trigger."""
        trace = [
            {"success": True, "tool_output": "Scan complete"},
            {"success": True, "tool_output": "Found services"},
        ]
        reason = self._detect_trigger(iteration=3, just_transitioned=None, exec_trace=trace, need_deep_think=False)
        self.assertIsNone(reason)

    def test_metasploit_no_session_trigger(self):
        """'exploit completed, but no session' counts as failure."""
        trace = [
            {"success": True, "tool_output": "Exploit completed, but no session was created"},
            {"success": True, "tool_output": "Exploit completed, but no session was created"},
            {"success": True, "tool_output": "Exploit completed, but no session was created"},
        ]
        reason = self._detect_trigger(iteration=5, just_transitioned=None, exec_trace=trace, need_deep_think=False)
        self.assertIn("Failure loop detected", reason)


class TestDeepThinkFormatting(unittest.TestCase):
    """Test the formatting of DeepThinkResult into markdown."""

    def test_format_as_markdown(self):
        """Verify the formatted output matches what think_node produces."""
        dt = DeepThinkResult(
            situation_assessment="Port 80 is open running Apache 2.4.49",
            attack_vectors_identified=["CVE-2021-41773", "CVE-2021-42013"],
            recommended_approach="Try path traversal RCE",
            priority_order=["CVE-2021-41773", "CVE-2021-42013", "brute force SSH"],
            risks_and_mitigations="Target may be patched"
        )
        # Same formatting as think_node.py
        formatted = (
            f"**Situation:** {dt.situation_assessment}\n\n"
            f"**Attack Vectors:** {', '.join(dt.attack_vectors_identified)}\n\n"
            f"**Approach:** {dt.recommended_approach}\n\n"
            f"**Priority:** {' → '.join(dt.priority_order)}\n\n"
            f"**Risks:** {dt.risks_and_mitigations}"
        )
        self.assertIn("**Situation:** Port 80 is open", formatted)
        self.assertIn("CVE-2021-41773, CVE-2021-42013", formatted)
        self.assertIn("CVE-2021-41773 → CVE-2021-42013 → brute force SSH", formatted)


# ---------------------------------------------------------------------------
# CompetingHypothesis + competing_hypotheses field (Option B)
# ---------------------------------------------------------------------------

class TestCompetingHypothesisSchema(unittest.TestCase):
    """The schema is the structural fix for confirmation bias in deep-think:
    forcing the strategist to enumerate >=2 explanations before pivoting."""

    def test_competing_hypothesis_requires_three_fields(self):
        h = CompetingHypothesis(
            hypothesis="NoSQL injection in job_type",
            supporting_evidence="iter 7: {'$gt':''} → 500",
            disambiguating_probe="Send {job_type: 42} — if 500 the dict wasn't the cause",
        )
        self.assertEqual(h.hypothesis, "NoSQL injection in job_type")
        self.assertIn("$gt", h.supporting_evidence)
        self.assertIn("dict wasn't the cause", h.disambiguating_probe)

    def test_competing_hypothesis_rejects_missing_field(self):
        """All three fields are required — a hypothesis without a
        disambiguating probe is a guess, not a science experiment."""
        from pydantic import ValidationError
        with self.assertRaises(ValidationError):
            CompetingHypothesis(
                hypothesis="X",
                supporting_evidence="Y",
                # missing disambiguating_probe
            )


class TestDeepThinkCompetingHypothesesField(unittest.TestCase):

    def test_parse_with_competing_hypotheses(self):
        """A realistic deep-think output: two hypotheses for the same evidence
        plus the probes that distinguish them."""
        raw = json.dumps({
            "situation_assessment": "Multiple SQL payloads returned 500",
            "competing_hypotheses": [
                {
                    "hypothesis": "NoSQL injection",
                    "supporting_evidence": "iter 7: $gt → 500",
                    "disambiguating_probe": "Send {job_type:42}",
                },
                {
                    "hypothesis": "SQL parse error on non-string input",
                    "supporting_evidence": "Same 500s, same shape",
                    "disambiguating_probe": "Send quote-mixed string job_type",
                },
            ],
            "attack_vectors_identified": ["SQLi", "NoSQLi"],
            "recommended_approach": "Run disambiguating probe before pivoting",
            "priority_order": ["probe", "interpret", "exploit"],
            "risks_and_mitigations": "None",
        })
        result = DeepThinkResult.model_validate_json(raw)
        self.assertEqual(len(result.competing_hypotheses), 2)
        self.assertEqual(result.competing_hypotheses[0].hypothesis, "NoSQL injection")
        self.assertIn("quote-mixed string", result.competing_hypotheses[1].disambiguating_probe)

    def test_competing_hypotheses_defaults_to_empty(self):
        """The field is required by the prompt (when triggers fire) but
        not by the schema — that lets early-session deep-thinks (iter 1,
        phase transition) skip it. The prompt copy carries the policy."""
        raw = json.dumps({
            "situation_assessment": "Initial recon",
            "attack_vectors_identified": ["recon"],
            "recommended_approach": "Probe HTTP root",
            "priority_order": ["GET /"],
            "risks_and_mitigations": "Low",
        })
        result = DeepThinkResult.model_validate_json(raw)
        self.assertEqual(result.competing_hypotheses, [])

    def test_field_documented_in_schema_description(self):
        """The schema description tells the LLM WHEN it must populate the
        field. Without that string, the model can't infer the policy from
        the field name alone."""
        field = DeepThinkResult.model_fields["competing_hypotheses"]
        self.assertIn("confidence >= 60", field.description)
        self.assertIn("Unproductive streak", field.description)


class TestDeepThinkRenderedOutput(unittest.TestCase):
    """The competing_hypotheses block must render into the deep_think_result
    string that the NEXT iteration's system prompt receives. If the render
    drops the hypotheses, the LLM never sees them and the whole feature
    silently degrades to the old behavior."""

    def _render(self, dt: DeepThinkResult) -> str:
        """Mirror the render logic in think_node.py:222-251."""
        if dt.competing_hypotheses:
            hyp_lines = []
            for i, h in enumerate(dt.competing_hypotheses, 1):
                hyp_lines.append(
                    f"  {i}. **{h.hypothesis}**\n"
                    f"     - Supporting: {h.supporting_evidence}\n"
                    f"     - Disambiguating probe: {h.disambiguating_probe}"
                )
            hypotheses_block = (
                "**Competing Hypotheses (run a probe that distinguishes them — "
                "do not just confirm your favorite):**\n"
                + "\n".join(hyp_lines)
                + "\n\n"
            )
        else:
            hypotheses_block = ""
        return (
            f"**Situation:** {dt.situation_assessment}\n\n"
            f"{hypotheses_block}"
            f"**Attack Vectors:** {', '.join(dt.attack_vectors_identified)}\n\n"
            f"**Approach:** {dt.recommended_approach}\n\n"
            f"**Priority:** {' → '.join(dt.priority_order)}\n\n"
            f"**Risks:** {dt.risks_and_mitigations}"
        )

    def test_hypotheses_block_surfaces_each_probe(self):
        dt = DeepThinkResult(
            situation_assessment="500s on SQL payloads",
            competing_hypotheses=[
                CompetingHypothesis(
                    hypothesis="NoSQL injection",
                    supporting_evidence="$gt → 500",
                    disambiguating_probe="Send int payload",
                ),
                CompetingHypothesis(
                    hypothesis="SQL parse error",
                    supporting_evidence="Same 500s",
                    disambiguating_probe="Send valid quote-mixed string",
                ),
            ],
            recommended_approach="probe first",
            risks_and_mitigations="",
        )
        out = self._render(dt)
        # Header carries the imperative "do not just confirm your favorite"
        self.assertIn("Competing Hypotheses", out)
        self.assertIn("do not just confirm", out)
        # Each probe must appear verbatim so the LLM can act on it directly
        self.assertIn("Send int payload", out)
        self.assertIn("Send valid quote-mixed string", out)
        # Hypotheses are numbered so the LLM can reference them in followups
        self.assertIn("  1. **NoSQL injection**", out)
        self.assertIn("  2. **SQL parse error**", out)

    def test_empty_hypotheses_omits_block_cleanly(self):
        """Backward compat: a deep-think without competing_hypotheses
        renders the original layout — no empty/dangling 'Hypotheses:' header."""
        dt = DeepThinkResult(
            situation_assessment="Initial recon",
            attack_vectors_identified=["recon"],
            recommended_approach="GET /",
            priority_order=["root"],
            risks_and_mitigations="",
        )
        out = self._render(dt)
        self.assertNotIn("Competing Hypotheses", out)
        self.assertIn("**Situation:**", out)
        self.assertIn("**Attack Vectors:**", out)


class TestDeepThinkPromptWiring(unittest.TestCase):
    """Source-level wiring guards. If a refactor removes the prompt section
    or the render block, the structural fix silently degrades. These tests
    catch that even though the LLM-in-the-loop path isn't exercised."""

    def _read(self, rel_path: str) -> str:
        p = os.path.join(
            os.path.dirname(__file__), "..", rel_path,
        )
        with open(p, "r", encoding="utf-8") as f:
            return f.read()

    def test_prompt_template_explains_competing_hypotheses(self):
        src = self._read("prompts/base.py")
        # The header section must exist
        self.assertIn("Competing Hypotheses (REQUIRED when stuck or recovering)", src)
        # The two trigger conditions must be spelled out
        self.assertIn("Unproductive streak detected", src)
        self.assertIn("confidence >= 60", src)
        # The three field names must be documented
        self.assertIn("hypothesis", src)
        self.assertIn("supporting_evidence", src)
        self.assertIn("disambiguating_probe", src)
        # The schema example must include the field
        self.assertIn('"competing_hypotheses":', src)

    def test_think_node_renders_hypotheses_block(self):
        src = self._read("orchestrator_helpers/nodes/think_node.py")
        # Guard 1: the field is consulted
        self.assertIn("dt_parsed.competing_hypotheses", src,
                      "think_node no longer reads dt_parsed.competing_hypotheses")
        # Guard 2: the render produces the expected header
        self.assertIn("Competing Hypotheses", src,
                      "think_node no longer renders the Competing Hypotheses block")
        # Guard 3: the probe field is surfaced (not just the hypothesis name)
        self.assertIn("disambiguating_probe", src,
                      "think_node renders hypotheses but drops the probe field — "
                      "without the probe, the block is informational not actionable")


# ---------------------------------------------------------------------------
# Edge cases that the original 27 tests don't cover
# ---------------------------------------------------------------------------

class TestRobustnessAgainstLLMQuirks(unittest.TestCase):
    """The LLM may emit unexpected shapes. Schema validation + render must
    handle them gracefully — degrading to no-deep-think is acceptable;
    crashing the whole think_node is not."""

    def test_hypotheses_field_rejects_list_of_strings(self):
        """LLM might shortcut and emit a list of strings instead of a list
        of objects. Schema must reject so the orchestrator's try/except
        catches it and falls back."""
        from pydantic import ValidationError
        raw = json.dumps({
            "situation_assessment": "x",
            "competing_hypotheses": ["just a string", "another string"],
            "recommended_approach": "y",
            "risks_and_mitigations": "z",
        })
        with self.assertRaises(ValidationError):
            DeepThinkResult.model_validate_json(raw)

    def test_hypotheses_field_rejects_dict_instead_of_list(self):
        """LLM might emit a single hypothesis as a dict (not wrapped in list)."""
        from pydantic import ValidationError
        raw = json.dumps({
            "situation_assessment": "x",
            "competing_hypotheses": {
                "hypothesis": "h",
                "supporting_evidence": "e",
                "disambiguating_probe": "p",
            },
            "recommended_approach": "y",
            "risks_and_mitigations": "z",
        })
        with self.assertRaises(ValidationError):
            DeepThinkResult.model_validate_json(raw)

    def test_hypothesis_accepts_multiline_strings(self):
        """Real-world LLM output often contains newlines in fields. Must not
        break the render — the next-iteration prompt should keep the
        structure even if a hypothesis spans lines."""
        h = CompetingHypothesis(
            hypothesis="Line 1\nLine 2 of the hypothesis",
            supporting_evidence="Evidence with\nmultiple lines\nincluding code blocks",
            disambiguating_probe="Send payload:\n  curl -X POST ...",
        )
        self.assertIn("Line 2", h.hypothesis)
        self.assertIn("curl", h.disambiguating_probe)

    def test_hypothesis_accepts_braces_in_content(self):
        """Probes will frequently contain `{...}` (JSON payloads, dict
        literals, etc.). Must not break later .format() calls on the
        rendered deep_think_result."""
        h = CompetingHypothesis(
            hypothesis="NoSQL injection",
            supporting_evidence='{"$gt": ""} returns 500',
            disambiguating_probe='Send {"job_type": 42}',
        )
        self.assertIn("{", h.disambiguating_probe)
        self.assertIn("}", h.disambiguating_probe)


class TestRenderDoesNotBreakDownstreamFormatting(unittest.TestCase):
    """The rendered deep_think_result is fed into DEEP_THINK_SECTION.format().
    If the rendered string contains brace-like content from the LLM, the
    format() call must NOT try to substitute it as a field. This is a
    long-standing risk in the codebase that the competing_hypotheses
    feature amplifies (probes routinely contain JSON-like syntax)."""

    def test_format_section_does_not_reparse_substituted_value(self):
        """Python's .format() only parses the template, not substituted
        values. Verify this assumption holds for our specific template."""
        from prompts.base import DEEP_THINK_SECTION
        # Worst-case content: looks like a format field
        content = 'Send {"job_type": 42} and check {result.upper()}'
        out = DEEP_THINK_SECTION.format(deep_think_result=content)
        self.assertIn('{"job_type": 42}', out)
        self.assertIn('{result.upper()}', out)

    def test_rendered_block_passes_through_format_unchanged(self):
        """Full end-to-end: render a deep-think with brace-laden probes,
        feed it through DEEP_THINK_SECTION.format, verify nothing exploded."""
        from prompts.base import DEEP_THINK_SECTION
        dt = DeepThinkResult(
            situation_assessment="500s on dict payloads",
            competing_hypotheses=[
                CompetingHypothesis(
                    hypothesis="NoSQL injection",
                    supporting_evidence='{"$gt":""} → 500',
                    disambiguating_probe='Send {"job_type": 42}',
                ),
            ],
            recommended_approach="probe with int payload",
            risks_and_mitigations="",
        )
        # Replicate the render in think_node
        hyp_lines = []
        for i, h in enumerate(dt.competing_hypotheses, 1):
            hyp_lines.append(
                f"  {i}. **{h.hypothesis}**\n"
                f"     - Supporting: {h.supporting_evidence}\n"
                f"     - Disambiguating probe: {h.disambiguating_probe}"
            )
        result = (
            f"**Situation:** {dt.situation_assessment}\n\n"
            "**Competing Hypotheses:**\n"
            + "\n".join(hyp_lines)
            + f"\n\n**Approach:** {dt.recommended_approach}"
        )
        # The braces in disambiguating_probe must survive .format()
        out = DEEP_THINK_SECTION.format(deep_think_result=result)
        self.assertIn('Send {"job_type": 42}', out)


class TestPromptTokenBudget(unittest.TestCase):
    """The new prompt section is sizeable (~50 lines including worked
    example). This test pins the rough budget so we notice if a future
    edit doubles it accidentally. Not a hard cap — the budget should
    grow if the policy gets more nuanced."""

    def test_deep_think_prompt_under_size_cap(self):
        """Soft cap: 8000 chars. Current is ~5500. Catches accidental
        runaway prompt growth (e.g. someone embeds a 10KB worked example)."""
        from prompts.base import DEEP_THINK_PROMPT
        # Format with stub values so we measure the actual rendered size
        out = DEEP_THINK_PROMPT.format(
            current_phase="x", objective="x", attack_path_type="x",
            attack_path_behavior="x", phase_definitions="x",
            iteration=1, max_iterations=100, target_info="x",
            chain_context="x", objective_history="x",
            trigger_reason="x", todo_list="x",
            session_config="", roe_section="",
        )
        size = len(out)
        self.assertLess(size, 8000,
                        f"DEEP_THINK_PROMPT rendered to {size} chars — "
                        f"investigate before exceeding 8000")
        self.assertGreater(size, 2000,
                          "DEEP_THINK_PROMPT unexpectedly small — "
                          "the new section may have been dropped")

    def test_competing_hypotheses_section_keyword_present(self):
        """Sanity: the key imperative from the prompt copy must survive
        any future prompt rewrite. If someone trims the prompt and loses
        'disambiguating', the LLM stops generating useful probes."""
        from prompts.base import DEEP_THINK_PROMPT
        # The three field names + the imperative must all appear
        for keyword in ("disambiguating", "Competing Hypotheses",
                        "supporting_evidence", "confidence >= 60"):
            self.assertIn(keyword, DEEP_THINK_PROMPT,
                          f"DEEP_THINK_PROMPT lost the load-bearing keyword: {keyword!r}")


class TestBackwardCompatibility(unittest.TestCase):
    """Legacy state checkpoints (from before this feature shipped) must
    deserialize and render without crashing. Deep-think results stored in
    persistent state across sessions need to round-trip."""

    def test_legacy_json_without_competing_hypotheses_parses(self):
        """The pre-Option-B schema: no competing_hypotheses field. Schema
        defaults to [] and the rest of the deep-think continues working."""
        legacy_raw = json.dumps({
            "situation_assessment": "Old session pre-Option-B",
            "attack_vectors_identified": ["SQLi", "XSS"],
            "recommended_approach": "Start with recon",
            "priority_order": ["recon", "exploit"],
            "risks_and_mitigations": "Low risk lab",
            # NOTE: no competing_hypotheses field
        })
        result = DeepThinkResult.model_validate_json(legacy_raw)
        self.assertEqual(result.competing_hypotheses, [])
        # The rest of the legacy data should still be intact
        self.assertEqual(result.attack_vectors_identified, ["SQLi", "XSS"])

    def test_render_legacy_result_does_not_inject_empty_header(self):
        """If chain context references a legacy deep_think_result (no
        hypotheses), the render path must NOT emit an empty 'Competing
        Hypotheses' header — that would mislead the LLM into thinking
        zero hypotheses were considered."""
        # Use the same render shape as think_node
        dt = DeepThinkResult(
            situation_assessment="Legacy result",
            attack_vectors_identified=["recon"],
            recommended_approach="GET /",
            priority_order=["root"],
            risks_and_mitigations="None",
        )
        # No competing_hypotheses — render path must collapse cleanly
        rendered = (
            f"**Situation:** {dt.situation_assessment}\n\n"
            + ("**Competing Hypotheses:**\n" if dt.competing_hypotheses else "")
            + f"**Attack Vectors:** {', '.join(dt.attack_vectors_identified)}"
        )
        self.assertNotIn("**Competing Hypotheses:**", rendered)


class TestEmptyOrMinimalHypothesisLists(unittest.TestCase):
    """The schema allows 1 hypothesis or 0. The prompt says >=2 is required
    when conditions are met. This test pair documents the gap and behavior."""

    def test_single_hypothesis_schema_accepts(self):
        """Schema accepts 1 hypothesis. This is a design choice: enforcing
        min_length=2 at the schema level would reject legitimate 'no
        credible alternative' cases. Policy lives in the prompt, not the
        schema — by design."""
        h = CompetingHypothesis(
            hypothesis="The only credible explanation",
            supporting_evidence="No alternatives plausible given evidence",
            disambiguating_probe="Direct verification: try X and confirm Y",
        )
        dt = DeepThinkResult(
            situation_assessment="x",
            competing_hypotheses=[h],
            recommended_approach="y",
            risks_and_mitigations="z",
        )
        self.assertEqual(len(dt.competing_hypotheses), 1)

    def test_schema_does_not_enforce_min_two_hypotheses(self):
        """Document the design: schema is permissive, prompt is strict.
        If you tighten the schema later, this test will catch it — and
        you'll need to add an orchestrator-side validation path with a
        useful fallback (not a crash)."""
        dt = DeepThinkResult(
            situation_assessment="x",
            competing_hypotheses=[],  # explicitly empty
            recommended_approach="y",
            risks_and_mitigations="z",
        )
        # No exception — empty list is valid at the schema level
        self.assertEqual(dt.competing_hypotheses, [])


class TestMalformedLLMOutputFallback(unittest.TestCase):
    """When the LLM emits malformed JSON or a schema-violating shape,
    think_node has a non-blocking try/except that logs a warning and
    proceeds without a deep-think result. The new schema must not have
    introduced a code path that swallows the error silently — the
    warning must still surface and the fallback must still leave the
    session usable."""

    def test_pydantic_error_message_includes_field_name(self):
        """If the LLM emits {hypothesis: ...} (missing the other two
        fields), the ValidationError message must name the missing
        field — otherwise debugging is impossible."""
        from pydantic import ValidationError
        raw = json.dumps({
            "situation_assessment": "x",
            "competing_hypotheses": [
                {"hypothesis": "just one field"}  # missing 2 required
            ],
            "recommended_approach": "y",
            "risks_and_mitigations": "z",
        })
        with self.assertRaises(ValidationError) as ctx:
            DeepThinkResult.model_validate_json(raw)
        msg = str(ctx.exception)
        # Pydantic emits which fields are missing; verify the message
        # carries enough signal that an operator could fix the prompt.
        self.assertTrue(
            "supporting_evidence" in msg or "disambiguating_probe" in msg,
            f"ValidationError message lacks missing-field info: {msg}",
        )


class TestLargeHypothesisListsRender(unittest.TestCase):
    """Worst-case render: 20 hypotheses with long fields. Must not
    crash, must not produce malformed output."""

    def test_twenty_hypotheses_render_cleanly(self):
        hypotheses = [
            CompetingHypothesis(
                hypothesis=f"Hypothesis {i}: " + ("x" * 500),
                supporting_evidence=f"Evidence {i}: " + ("y" * 500),
                disambiguating_probe=f"Probe {i}: " + ("z" * 500),
            )
            for i in range(20)
        ]
        dt = DeepThinkResult(
            situation_assessment="stress test",
            competing_hypotheses=hypotheses,
            recommended_approach="approach",
            risks_and_mitigations="",
        )
        # Mirror the render in think_node
        hyp_lines = []
        for i, h in enumerate(dt.competing_hypotheses, 1):
            hyp_lines.append(
                f"  {i}. **{h.hypothesis}**\n"
                f"     - Supporting: {h.supporting_evidence}\n"
                f"     - Disambiguating probe: {h.disambiguating_probe}"
            )
        block = "\n".join(hyp_lines)
        # No crash; the 20th hypothesis must appear
        self.assertIn("Hypothesis 19:", block)
        # Each block must be properly numbered (no '0.' or '21.')
        self.assertIn("  1. **Hypothesis 0:", block)
        self.assertIn("  20. **Hypothesis 19:", block)


if __name__ == "__main__":
    unittest.main()
