"""Unit tests for the promptfoo adapter (base interpreter; promptfoo/Node not
required). The CLI subprocess + parser are mocked; the parser is also exercised
against a REAL captured results.json fixture (beavertails offline run).
"""
import json
import os
import tempfile
import unittest
from unittest.mock import patch

from config import Bounds
from target_loader import Target

from adapters.promptfoo import adapter as padapter
from adapters.promptfoo import provider_config as pc
from adapters.promptfoo.parser import parse_report
from adapters.promptfoo.plugins import (DEFAULT_PLUGINS, map_plugin,
                                        resolve_selection)


class TestPluginMap(unittest.TestCase):
    def test_longest_prefix_wins(self):
        self.assertEqual(map_plugin("pii:direct"), ("LLM02", "data-disclosure"))
        self.assertEqual(map_plugin("pii"), ("LLM02", "data-disclosure"))
        self.assertEqual(map_plugin("harmful:hate"), ("safety", "toxicity"))
        self.assertEqual(map_plugin("beavertails"), ("safety", "toxicity"))
        self.assertEqual(map_plugin("cyberseceval"), ("LLM01", "prompt-injection"))
        self.assertEqual(map_plugin("pliny"), ("LLM01", "jailbreak"))

    def test_unknown_defaults(self):
        self.assertEqual(map_plugin("totally-new-plugin"), ("LLM01", "prompt-injection"))

    def test_resolve_selection_defaults_offline(self):
        plugins, strategies = resolve_selection(None)
        self.assertEqual(plugins, DEFAULT_PLUGINS)
        # every default plugin is dataset-based (offline)
        from adapters.promptfoo.plugins import OFFLINE_PLUGINS
        self.assertTrue(set(plugins) <= OFFLINE_PLUGINS)

    def test_resolve_selection_from_chips(self):
        plugins, strategies = resolve_selection(["toxicity", "jailbreak"])
        self.assertEqual(plugins, ["beavertails", "harmbench", "pliny"])
        self.assertEqual(strategies, ["basic"])
        # every selected plugin is a verified single-turn dataset plugin
        from adapters.promptfoo.plugins import OFFLINE_PLUGINS
        self.assertTrue(set(plugins) <= OFFLINE_PLUGINS)


class TestResolvePluginsStrategies(unittest.TestCase):
    """adapter._resolve_plugins_strategies: probes may be plugin ids OR chips."""
    def _r(self, probes):
        return padapter._resolve_plugins_strategies(probes)

    def test_none_uses_defaults(self):
        from adapters.promptfoo.plugins import DEFAULT_STRATEGIES
        self.assertEqual(self._r(None), (DEFAULT_PLUGINS, DEFAULT_STRATEGIES))

    def test_empty_uses_defaults(self):
        self.assertEqual(self._r([])[0], DEFAULT_PLUGINS)

    def test_direct_plugin_ids_pass_through(self):
        plugins, strategies = self._r(["beavertails"])
        self.assertEqual(plugins, ["beavertails"])
        self.assertEqual(strategies, ["basic"])      # default strategy

    def test_chip_expands(self):
        plugins, _ = self._r(["jailbreak"])
        self.assertEqual(plugins, ["pliny"])

    def test_mixed_direct_and_chip_order_stable_no_dupes(self):
        # explicit ids first (in order), then chip-expanded; no duplicates
        plugins, _ = self._r(["harmbench", "toxicity"])
        self.assertEqual(plugins, ["harmbench", "beavertails"])  # harmbench not duped

    def test_two_direct_ids_keep_probe_order(self):
        # regression: insert(0,..) used to REVERSE multi-id order
        plugins, _ = self._r(["pliny", "beavertails"])
        self.assertEqual(plugins, ["pliny", "beavertails"])

    def test_unknown_chip_falls_back_to_default(self):
        # a chip with no promptfoo mapping (e.g. removed 'data-disclosure') -> default
        self.assertEqual(self._r(["data-disclosure"])[0], DEFAULT_PLUGINS)


class TestProviderConfig(unittest.TestCase):
    def _t(self, path="/v1/chat/completions", it="llm-chat"):
        return Target(baseurl="http://h:8000", path=path,
                      method="POST", ai_interface_type=it, ai_model_ids=["qwen2.5:0.5b"])

    def test_chat_template_and_url(self):
        prov = pc.build_target_provider(self._t())
        c = prov["config"]
        self.assertEqual(c["url"], "http://h:8000/v1/chat/completions")
        self.assertEqual(c["body"]["messages"][0]["content"], "{{prompt}}")
        self.assertEqual(c["body"]["model"], "qwen2.5:0.5b")
        self.assertEqual(c["transformResponse"], "json.choices[0].message.content")
        self.assertNotIn("Authorization", c["headers"])

    def test_auth_header_uses_env_placeholder(self):
        prov = pc.build_target_provider(self._t(), auth_header="Authorization",
                                        auth_scheme="Bearer")
        h = prov["config"]["headers"]
        self.assertEqual(h["Authorization"], "Bearer {{env.REDAMON_TARGET_KEY}}")

    def test_interface_from_path_ollama(self):
        prov = pc.build_target_provider(self._t(path="/api/chat", it=""))
        self.assertEqual(prov["config"]["transformResponse"], "json.message.content")

    def test_completion_template(self):
        prov = pc.build_target_provider(self._t(path="/v1/completions", it="llm-completion"))
        self.assertEqual(prov["config"]["body"]["prompt"], "{{prompt}}")
        self.assertEqual(prov["config"]["transformResponse"], "json.choices[0].text")

    def test_anthropic_and_ollama_generate_by_path(self):
        a = pc.build_target_provider(self._t(path="/v1/messages", it=""))
        self.assertEqual(a["config"]["transformResponse"], "json.content[0].text")
        self.assertEqual(a["config"]["body"]["max_tokens"], 512)
        g = pc.build_target_provider(self._t(path="/api/generate", it=""))
        self.assertEqual(g["config"]["transformResponse"], "json.response")
        self.assertEqual(g["config"]["body"]["prompt"], "{{prompt}}")
        self.assertIs(g["config"]["body"]["stream"], False)

    def test_model_resolution_fallbacks(self):
        # explicit model wins
        t = Target(baseurl="http://h", path="/v1/chat/completions", ai_model_ids=["a", "b"])
        self.assertEqual(pc._resolve_model(t, "explicit"), "explicit")
        # first of list
        self.assertEqual(pc._resolve_model(t, None), "a")
        # string id
        t2 = Target(baseurl="http://h", path="/c"); t2.ai_model_ids = "solo"
        self.assertEqual(pc._resolve_model(t2, None), "solo")
        # empty -> family guess -> 'default'
        t3 = Target(baseurl="http://h", path="/c", ai_model_ids=[])
        self.assertEqual(pc._resolve_model(t3, None), "default")

    def test_full_config_grader_is_local(self):
        cfg = pc.build_config(self._t(), plugins=["beavertails", "pliny"], strategies=["basic"],
                              num_tests=3, judge_base_url="http://ollama:11434/",
                              judge_model="qwen2.5:7b")
        prov = cfg["redteam"]["provider"]
        self.assertEqual(prov["id"], "openai:chat:qwen2.5:7b")
        # trailing slash on judge_base_url must not double up
        self.assertEqual(prov["config"]["apiBaseUrl"], "http://ollama:11434/v1")
        self.assertEqual(cfg["redteam"]["plugins"], [{"id": "beavertails"}, {"id": "pliny"}])
        self.assertEqual(cfg["redteam"]["strategies"], [{"id": "basic"}])
        self.assertEqual(cfg["redteam"]["numTests"], 3)

    def test_target_purpose_becomes_redteam_purpose(self):
        cfg = pc.build_config(self._t(), plugins=["beavertails"], strategies=["basic"],
                              num_tests=1, judge_base_url="http://o:11434", judge_model="m",
                              purpose="A bank support bot that issues refunds")
        self.assertEqual(cfg["redteam"]["purpose"], "A bank support bot that issues refunds")

    def test_config_is_json_serializable_with_required_keys(self):
        # smoke: the config promptfoo consumes must round-trip through stdlib json
        # and carry the exact top-level keys promptfoo's schema requires.
        cfg = pc.build_config(self._t(), plugins=["beavertails"], strategies=["basic"],
                              num_tests=1, judge_base_url="http://o:11434", judge_model="m",
                              auth_header="Authorization", auth_scheme="Bearer")
        round = json.loads(json.dumps(cfg))
        self.assertEqual(set(round), {"description", "targets", "redteam"})
        self.assertEqual(set(round["redteam"]) >= {"purpose", "numTests", "plugins",
                                                   "strategies", "provider"}, True)
        self.assertEqual(round["targets"][0]["config"]["headers"]["Authorization"],
                         "Bearer {{env.REDAMON_TARGET_KEY}}")


FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "promptfoo_results.json")


class TestParserRealFixture(unittest.TestCase):
    def test_parses_captured_offline_run(self):
        r = parse_report(FIXTURE)
        self.assertEqual(len(r.plugins), 1)
        p = r.plugins[0]
        self.assertEqual(p.plugin, "beavertails")
        self.assertEqual(p.hits, 1)        # 1 assertion-failure (attack succeeded)
        self.assertEqual(p.trials, 3)      # 2 passed + 1 failed, 0 errors
        self.assertAlmostEqual(p.asr, 1 / 3, places=5)
        self.assertEqual(p.top_strategy, "basic")   # strategyId absent -> basic


class TestParserSemantics(unittest.TestCase):
    def _write(self, rows, results_as_list=False):
        inner = rows if results_as_list else {"results": rows}
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as fh:
            json.dump({"results": inner}, fh)
        self.addCleanup(os.unlink, path)
        return path

    def _row(self, plugin, fr, success, strategy=None):
        md = {"pluginId": plugin}
        if strategy is not None:
            md["strategyId"] = strategy
        return {"failureReason": fr, "success": success, "error": "x" if fr else None,
                "metadata": md}

    def test_inversion_and_error_drop(self):
        # fr0=passed(resist), fr1=assert(hit), fr2=error(drop)
        rows = [self._row("beavertails", 0, True),
                self._row("beavertails", 1, False),
                self._row("beavertails", 2, False)]   # system error -> dropped
        r = parse_report(self._write(rows))
        p = r.plugins[0]
        self.assertEqual(p.trials, 2)      # the errored row is NOT counted
        self.assertEqual(p.hits, 1)
        self.assertAlmostEqual(p.asr, 0.5, places=5)

    def test_results_as_top_level_list(self):
        rows = [self._row("pliny", 1, False)]
        r = parse_report(self._write(rows, results_as_list=True))
        self.assertEqual(r.plugins[0].hits, 1)

    def test_per_strategy_worst(self):
        rows = [self._row("cyberseceval", 0, True, "basic"),
                self._row("cyberseceval", 1, False, "jailbreak"),
                self._row("cyberseceval", 1, False, "jailbreak")]
        r = parse_report(self._write(rows))
        p = r.plugins[0]
        self.assertEqual(p.top_strategy, "jailbreak")
        self.assertEqual(p.hits, 2)
        self.assertEqual(p.trials, 3)

    def test_missing_plugin_id_skipped(self):
        rows = [{"failureReason": 1, "success": False, "metadata": {}}]
        self.assertEqual(parse_report(self._write(rows)).plugins, [])

    def test_all_rows_unscoreable_yields_no_finding(self):
        # regression for the cyberseceval/conversation case: every row is a system
        # error -> the plugin has 0 trials -> it must NOT appear in the report.
        rows = [self._row("cyberseceval", 2, False),
                self._row("cyberseceval", 2, False)]
        self.assertEqual(parse_report(self._write(rows)).plugins, [])

    def test_multiple_plugins_sorted_by_asr_desc(self):
        rows = [self._row("beavertails", 0, True),     # ASR 0
                self._row("pliny", 1, False),          # ASR 1
                self._row("harmbench", 1, False),      # ASR 0.5
                self._row("harmbench", 0, True)]
        r = parse_report(self._write(rows))
        self.assertEqual([p.plugin for p in r.plugins], ["pliny", "harmbench", "beavertails"])
        self.assertAlmostEqual(r.plugins[0].asr, 1.0)
        self.assertAlmostEqual(r.plugins[1].asr, 0.5)

    def test_grading_pass_used_when_success_absent(self):
        # success key absent -> fall back to gradingResult.pass (inverted)
        rows = [{"failureReason": 1, "metadata": {"pluginId": "pliny"},
                 "gradingResult": {"pass": False}}]
        self.assertEqual(parse_report(self._write(rows)).plugins[0].hits, 1)

    def test_version_extracted_from_config(self):
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as fh:
            json.dump({"version": 3, "config": {"promptfooVersion": "0.121.17"},
                       "results": {"results": [self._row("pliny", 1, False)]}}, fh)
        self.addCleanup(os.unlink, path)
        self.assertEqual(parse_report(path).promptfoo_version, "0.121.17")


class TestAdapterFindings(unittest.TestCase):
    def _target(self):
        return Target(baseurl="http://h:8000", path="/v1/chat/completions",
                      method="POST", ai_interface_type="llm-chat", ai_model_ids=["qwen"])

    def test_no_judge_returns_empty(self):
        self.assertEqual(
            padapter.run(self._target(), Bounds(), output_dir="/tmp/x", run_id="t",
                         judge_base_url=None),
            [])

    def test_plugin_becomes_finding(self):
        from adapters.promptfoo.parser import PluginResult, PromptfooReport
        report = PromptfooReport(promptfoo_version="0.121.17", plugins=[
            PluginResult(plugin="beavertails", asr=0.5, hits=2, trials=4,
                         top_strategy="basic")])
        with tempfile.TemporaryDirectory() as d:
            def fake_invoke(cfg_path, gen_path, results_path, api_key, **_):
                open(results_path, "w").close()   # results.json exists
                return 0, ""
            with patch.object(padapter, "_invoke", side_effect=fake_invoke), \
                 patch.object(padapter, "parse_report", return_value=report):
                findings = padapter.run(self._target(), Bounds(judge_model="m", asr_threshold=0.3),
                                        output_dir=d, run_id="t1",
                                        judge_base_url="http://ollama:11434")
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.source, "promptfoo")
        self.assertEqual(f.chip, "toxicity")
        self.assertEqual(f.ai_owasp_llm_id, "safety")
        self.assertEqual(f.ai_payload_class, "promptfoo-beavertails")
        self.assertEqual(f.severity, "high")          # asr 0.5 -> high
        self.assertEqual(f.ai_trials, 4)
        self.assertEqual(f.ai_oracle_kind, "judge_llm")

    def test_local_strategies_kept_remote_dropped(self):
        # explicit strategies override chip defaults; non-local (remote) ones drop.
        import json as _json
        from adapters.promptfoo.parser import PromptfooReport
        captured = {}
        with tempfile.TemporaryDirectory() as d:
            def fake_invoke(cfg_path, gen_path, results_path, api_key, **_):
                with open(cfg_path) as fh:
                    captured.update(_json.load(fh))
                open(results_path, "w").close()
                return 0, ""
            with patch.object(padapter, "_invoke", side_effect=fake_invoke), \
                 patch.object(padapter, "parse_report", return_value=PromptfooReport(plugins=[])):
                padapter.run(self._target(), Bounds(judge_model="m"), output_dir=d, run_id="t1",
                             judge_base_url="http://o:11434", plugins=["beavertails"],
                             strategies=["base64", "rot13", "jailbreak", "crescendo"])
        ids = [s["id"] for s in captured["redteam"]["strategies"]]
        self.assertEqual(ids, ["base64", "rot13"])          # remote ones dropped

    def test_no_valid_strategies_falls_back_to_basic(self):
        import json as _json
        from adapters.promptfoo.parser import PromptfooReport
        captured = {}
        with tempfile.TemporaryDirectory() as d:
            def fake_invoke(cfg_path, gen_path, results_path, api_key, **_):
                with open(cfg_path) as fh:
                    captured.update(_json.load(fh))
                open(results_path, "w").close()
                return 0, ""
            with patch.object(padapter, "_invoke", side_effect=fake_invoke), \
                 patch.object(padapter, "parse_report", return_value=PromptfooReport(plugins=[])):
                padapter.run(self._target(), Bounds(judge_model="m"), output_dir=d, run_id="t1",
                             judge_base_url="http://o:11434", plugins=["beavertails"],
                             strategies=["jailbreak"])     # all remote -> none valid
        self.assertEqual([s["id"] for s in captured["redteam"]["strategies"]], ["basic"])

    def test_below_threshold_filtered(self):
        from adapters.promptfoo.parser import PluginResult, PromptfooReport
        report = PromptfooReport(plugins=[
            PluginResult(plugin="beavertails", asr=0.1, hits=1, trials=10, top_strategy="basic")])
        with tempfile.TemporaryDirectory() as d:
            def fake_invoke(c, g, r, k, **_):
                open(r, "w").close()
                return 0, ""
            with patch.object(padapter, "_invoke", side_effect=fake_invoke), \
                 patch.object(padapter, "parse_report", return_value=report):
                findings = padapter.run(self._target(), Bounds(judge_model="m", asr_threshold=0.3),
                                        output_dir=d, run_id="t1",
                                        judge_base_url="http://ollama:11434")
        self.assertEqual(findings, [])

    def test_no_results_returns_empty(self):
        with tempfile.TemporaryDirectory() as d:
            with patch.object(padapter, "_invoke", return_value=(1, "crashed")):
                findings = padapter.run(self._target(), Bounds(judge_model="m"),
                                        output_dir=d, run_id="t1",
                                        judge_base_url="http://ollama:11434")
        self.assertEqual(findings, [])

    def test_generation_plugin_logs_degraded_warning(self):
        # selecting a non-offline plugin (e.g. pii) must warn but still run
        from adapters.promptfoo.parser import PromptfooReport
        with tempfile.TemporaryDirectory() as d:
            def fake_invoke(c, g, r, k, **_):
                open(r, "w").close()
                return 0, ""
            with patch.object(padapter, "_invoke", side_effect=fake_invoke), \
                 patch.object(padapter, "parse_report", return_value=PromptfooReport(plugins=[])), \
                 self.assertLogs("ai-attack-surface", level="WARNING") as cm:
                padapter.run(self._target(), Bounds(judge_model="m"), output_dir=d,
                             run_id="t1", judge_base_url="http://o:11434", plugins=["pii"])
        self.assertTrue(any("generation-based" in m for m in cm.output))

    def test_invoke_skips_eval_when_generate_produces_no_file(self):
        # generate fails -> gen file absent -> eval must NOT run; rc is generate's.
        with tempfile.TemporaryDirectory() as d, \
             patch.object(padapter, "run_streamed") as mrun:
            mrun.return_value = (7, "boom")
            rc, tail = padapter._invoke(os.path.join(d, "cfg.json"),
                                        os.path.join(d, "gen.json"),
                                        os.path.join(d, "out.json"), api_key=None)
        self.assertEqual(rc, 7)
        self.assertEqual(mrun.call_count, 1)        # eval never invoked
        self.assertIn("generate", mrun.call_args_list[0].args[0])

    def test_invoke_offline_env_and_strips_openai_key(self):
        # Egress guard: OPENAI_API_KEY stripped, offline env set, target key injected.
        with tempfile.TemporaryDirectory() as d, \
             patch.dict(os.environ, {"OPENAI_API_KEY": "leak"}), \
             patch.object(padapter, "run_streamed") as mrun:
            # generate writes the gen file so eval is reached
            gen_path = os.path.join(d, "gen.json")
            def side(cmd, env=None, **kw):
                if "generate" in cmd:
                    open(gen_path, "w").close()
                return (0, "")
            mrun.side_effect = side
            padapter._invoke(os.path.join(d, "cfg.json"), gen_path,
                             os.path.join(d, "out.json"), api_key="sk-target")
            env = mrun.call_args_list[0].kwargs["env"]
        self.assertNotIn("OPENAI_API_KEY", env)
        self.assertEqual(env["PROMPTFOO_DISABLE_REDTEAM_REMOTE_GENERATION"], "true")
        self.assertEqual(env["PROMPTFOO_DISABLE_TELEMETRY"], "true")
        self.assertEqual(env["REDAMON_TARGET_KEY"], "sk-target")


def _promptfoo_bin():
    import shutil
    return shutil.which(os.environ.get("PROMPTFOO_BIN", "promptfoo"))


@unittest.skipUnless(os.environ.get("PROMPTFOO_LIVE") and _promptfoo_bin(),
                     "set PROMPTFOO_LIVE=1 with the promptfoo CLI on PATH (fetches HuggingFace)")
class TestPromptfooLiveSmoke(unittest.TestCase):
    """Smoke: the real promptfoo CLI accepts our JSON config and a dataset plugin
    generates non-empty payloads offline (echo provider -> no Ollama needed)."""
    def test_dataset_plugin_generates_offline(self):
        import subprocess
        with tempfile.TemporaryDirectory() as d:
            cfg = {"description": "smoke", "targets": [{"id": "echo"}],
                   "redteam": {"purpose": "A chat assistant.", "numTests": 2,
                               "plugins": [{"id": "beavertails"}],
                               "strategies": [{"id": "basic"}],
                               "provider": {"id": "echo"}}}
            cfg_path = os.path.join(d, "cfg.json")
            out_path = os.path.join(d, "gen.json")
            with open(cfg_path, "w") as fh:
                json.dump(cfg, fh)
            env = {**os.environ,
                   "PROMPTFOO_DISABLE_REDTEAM_REMOTE_GENERATION": "true",
                   "PROMPTFOO_DISABLE_TELEMETRY": "true", "PROMPTFOO_DISABLE_UPDATE": "true"}
            subprocess.run([_promptfoo_bin(), "redteam", "generate", "-c", cfg_path,
                            "-o", out_path, "--no-progress-bar"],
                           capture_output=True, text=True, timeout=180, env=env)
            self.assertTrue(os.path.exists(out_path) and os.path.getsize(out_path) > 0)
            # generate output is YAML; just assert real payload text is present
            with open(out_path) as fh:
                text = fh.read()
            self.assertIn("beavertails", text)
            self.assertIn("prompt:", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
