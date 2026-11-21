#!/usr/bin/env python3
"""Unit tests for the OSINT agent. stdlib unittest only.
Run: python3 -m unittest discover -s tests -v
No Ollama, no network, no live checks."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from osint_agent.config import load_config
from osint_agent.llm import NullProvider, OllamaProvider, build_provider
from osint_agent.planner import build_plan
from osint_agent.tools import (PHOENIX_TOOLS, get_tool, registry_summary,
                               run_tool)
from osint_agent.verifier import gate_finding, verify_findings
from osint_agent.agent import run_case, sanitise_case


class TestConfig(unittest.TestCase):
    def test_defaults(self):
        cfg = load_config("/nonexistent.yaml")
        self.assertEqual(cfg["model"]["name"], "llama3.1:8b")
        self.assertEqual(cfg["model"]["endpoint"], "http://localhost:11434")
        self.assertEqual(cfg["limits"]["max_posts_per_sweep"], 5)

    def test_unknown_provider_raises(self):
        with self.assertRaises(ValueError):
            build_provider({"model": {"provider": "cloud-xyz"}})


class TestLLM(unittest.TestCase):
    def test_null_provider_raises(self):
        with self.assertRaises(Exception):
            NullProvider().chat("s", "u")

    def test_ollama_provider_fields(self):
        p = OllamaProvider(endpoint="http://localhost:11434", model="llama3.1:8b")
        self.assertEqual(p.name, "ollama")
        self.assertEqual(p.model, "llama3.1:8b")

    def test_ollama_unreachable_raises(self):
        p = OllamaProvider(endpoint="http://127.0.0.1:1", model="x", timeout=2)
        with self.assertRaises(Exception):
            p.chat("s", "u")


class TestVerifier(unittest.TestCase):
    def test_all_pass_high(self):
        v = gate_finding({"claim": "c", "source": "pass", "corroboration": "pass",
                          "identity": "pass", "time": "pass", "access": "pass",
                          "exit": "pass"})
        self.assertEqual(v["confidence"], "High")
        self.assertIsNone(v["weakest_gate"])

    def test_identity_fail_unverified(self):
        v = gate_finding({"claim": "c", "source": "pass", "corroboration": "pass",
                          "identity": "fail", "time": "pass", "access": "pass",
                          "exit": "pass"})
        self.assertEqual(v["confidence"], "Unverified")
        self.assertEqual(v["weakest_gate"], "identity")

    def test_one_weak_medium(self):
        v = gate_finding({"claim": "c", "source": "pass", "corroboration": "weak",
                          "identity": "pass", "time": "pass", "access": "pass",
                          "exit": "pass"})
        self.assertEqual(v["confidence"], "Medium")

    def test_verify_counts(self):
        _, counts = verify_findings([
            {"claim": "a", "source": "pass", "corroboration": "pass",
             "identity": "pass", "time": "pass", "access": "pass", "exit": "pass"},
            {"claim": "b", "source": "fail"},
        ])
        self.assertEqual(counts.get("High"), 1)
        self.assertEqual(counts.get("Unverified"), 1)


class TestPlanner(unittest.TestCase):
    def test_plan_steps_and_registry(self):
        plan = build_plan({"name": "T", "handles": ["@h"],
                           "platforms": ["instagram"], "question": "?"})
        self.assertGreaterEqual(len(plan), 8)
        names = {t["name"] for t in registry_summary()}
        for step in plan:
            self.assertIn(step["tool"], names)


class TestTools(unittest.TestCase):
    def test_registry_size(self):
        self.assertGreaterEqual(len(registry_summary()), 10)

    def test_unknown_tool_raises(self):
        with self.assertRaises(KeyError):
            get_tool("no-such-tool")

    def test_phoenix_empty_and_guarded(self):
        self.assertEqual(PHOENIX_TOOLS, [])
        with self.assertRaises(KeyError):
            run_tool("phoenix-x", {}, False, load_config("/nonexistent.yaml"))

    def test_guidance_tool_dry(self):
        cfg = load_config("/nonexistent.yaml")
        r = run_tool("reverse_image", {"target": "X"}, False, cfg)
        self.assertEqual(r["status"], "guidance")

    def test_handle_enum_dry_run(self):
        cfg = load_config("/nonexistent.yaml")
        r = run_tool("handle_enum", {"handle": "@example", "name": "Example",
                                     "platforms": "instagram", "max_queries": 2},
                     False, cfg)
        self.assertEqual(r["status"], "dry_run")


class TestSignalSearch(unittest.TestCase):
    def test_registered(self):
        names = {t["name"] for t in registry_summary()}
        self.assertIn("signal_search", names)
        self.assertGreaterEqual(len(registry_summary()), 11)

    def test_planner_adds_step_for_identifiers(self):
        plan = build_plan({"name": "T", "handles": ["@h"],
                           "platforms": ["instagram"], "question": "?",
                           "identifiers": ["00:0C:42:1F:65:E9"]})
        sig_steps = [s for s in plan if s["tool"] == "signal_search"]
        self.assertEqual(len(sig_steps), 1)
        self.assertEqual(sig_steps[0]["args"]["query"], "00:0C:42:1F:65:E9")

    def test_planner_no_step_without_identifiers(self):
        plan = build_plan({"name": "T", "handles": ["@h"],
                           "platforms": ["instagram"], "question": "?"})
        self.assertFalse([s for s in plan if s["tool"] == "signal_search"])

    def test_dry_run(self):
        cfg = load_config("/nonexistent.yaml")
        r = run_tool("signal_search", {"query": "00:0C:42:1F:65:E9"},
                     False, cfg)
        self.assertEqual(r["status"], "dry_run")
        self.assertEqual(r["tool"], "signal_search")

    def test_fixture_no_network_merged_schema(self):
        # Local files only: no network, no API keys. The fixture BSSID
        # 00:0C:42:1F:65:E9 is the published Mylnikov documentation
        # example; signal-search data/ holds matching fixture files.
        cfg = load_config("/nonexistent.yaml")
        r = run_tool("signal_search",
                     {"query": "00:0C:42:1F:65:E9",
                      "no_network": True, "no_cache": True},
                     True, cfg)
        self.assertEqual(r["status"], "ok")
        self.assertGreaterEqual(r["data"]["summary"]["found"], 2)
        merged = r["data"]["merged"]
        self.assertTrue(merged)
        self.assertIn("spread_m", merged[0])
        self.assertIn("sources", merged[0])
        self.assertIn("disagree_gt_200m", merged[0])
        for row in r["data"]["results"]:
            self.assertIn("source", row)
            self.assertIn("lat", row)
            self.assertIn("lon", row)
            self.assertIn("status", row)
            self.assertIn("confidence", row)
        # No secret-looking field may survive into a tool result.
        blob = str(r["data"])
        self.assertNotIn("api_token", blob)
        self.assertNotIn("api_key", blob)

    def test_no_identifier_errors(self):
        cfg = load_config("/nonexistent.yaml")
        r = run_tool("signal_search", {"query": ""}, True, cfg)
        self.assertEqual(r["status"], "error")


class TestAgent(unittest.TestCase):
    def test_sanitise_strips_phone(self):
        clean, notes = sanitise_case({"name": "T 808-555-0100", "handles": []})
        self.assertNotIn("808-555-0100", clean["name"])
        self.assertTrue(notes)

    def test_dry_run_case(self):
        cfg = load_config("/nonexistent.yaml")
        result = run_case(
            {"name": "Example Target", "handles": ["@example-handle"],
             "platforms": ["instagram", "facebook"],
             "question": "Is there a public footprint?",
             "scope": "Read-only public collection"},
            cfg, live=False, dry_run=True, llm_provider=NullProvider())
        self.assertTrue(os.path.exists(result["report"]))
        self.assertIn("no-model", result["llm_note"])
        self.assertGreaterEqual(len(result["tool_results"]), 8)
        self.assertGreaterEqual(len(result["verified"]), 8)


    def test_dry_run_case_dict_handles(self):
        # case.json stores handles as [{"handle": "@x", ...}] — must not crash.
        cfg = load_config("/nonexistent.yaml")
        result = run_case(
            {"name": "Example Target",
             "handles": [{"handle": "@example-handle", "platform": "instagram",
                          "status": "suspected"}],
             "platforms": ["instagram"],
             "question": "Is there a public footprint?",
             "scope": "Read-only public collection"},
            cfg, live=False, dry_run=True, llm_provider=NullProvider())
        self.assertTrue(os.path.exists(result["report"]))
        self.assertIn("example-handle",
                      open(result["report"]).read())


if __name__ == "__main__":
    unittest.main()
