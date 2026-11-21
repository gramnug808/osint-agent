#!/usr/bin/env python3
"""OSINT agent CLI — self-hosted model, Ben's OSINT toolkit, 6-gate verifier.

Usage:
  python3 agent.py --case cases/example --dry-run
  python3 agent.py --target "Example Target" --handles @example-handle --dry-run
  python3 agent.py --case cases/example --live --report
  python3 agent.py --self-test

Default is dry-run (no network, no live checks). --live runs the tools
for real; breach_check stays dry-run unless --breach-live is given AND
HIBP/DeHashed keys are set in the environment. No cloud LLM is used:
the model is Ollama on localhost by default (see config.yaml).
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from osint_agent.agent import run_case
from osint_agent.config import load_config
from osint_agent.llm import build_provider, NullProvider
from osint_agent.planner import build_plan, plan_text
from osint_agent.tools import (registry_summary, run_tool, PHOENIX_TOOLS,
                               PHOENIX_ISSUE_URL)
from osint_agent.verifier import gate_finding


def load_case(case_dir):
    path = os.path.join(case_dir, "case.json")
    with open(path) as fh:
        return json.load(fh)


def self_test():
    """Run internal checks without Ollama and without network. Returns
    (passed, failed, messages)."""
    from osint_agent.config import DEFAULTS
    from osint_agent.tools import get_tool
    passed = failed = 0
    msgs = []

    def check(label, ok):
        nonlocal passed, failed
        if ok:
            passed += 1
            msgs.append(f"PASS {label}")
        else:
            failed += 1
            msgs.append(f"FAIL {label}")

    cfg = load_config("/nonexistent-config.yaml")
    check("config defaults load", cfg["model"]["name"] == "llama3.1:8b")
    check("config defaults endpoint", cfg["model"]["endpoint"] == "http://localhost:11434")

    provider = build_provider({"model": {"provider": "none"}})
    check("null provider", isinstance(provider, NullProvider))
    try:
        provider.chat("s", "u")
        check("null provider raises", False)
    except Exception:
        check("null provider raises", True)

    # Verifier: all gates pass -> High; identity fails -> Unverified.
    v = gate_finding({"claim": "x", "source": "pass", "corroboration": "pass",
                      "identity": "pass", "time": "pass", "access": "pass",
                      "exit": "pass"})
    check("verifier all-pass -> High", v["confidence"] == "High")
    v = gate_finding({"claim": "x", "source": "pass", "corroboration": "fail",
                      "identity": "fail", "time": "pass", "access": "pass",
                      "exit": "pass"})
    check("verifier identity-fail -> Unverified", v["confidence"] == "Unverified")
    v = gate_finding({"claim": "x", "source": "pass", "corroboration": "weak",
                      "identity": "pass", "time": "pass", "access": "pass",
                      "exit": "pass"})
    check("verifier one weak -> Medium", v["confidence"] == "Medium")

    # Planner + registry
    plan = build_plan({"name": "Example", "handles": ["@example"],
                       "platforms": ["instagram"], "question": "?"})
    check("planner builds steps", len(plan) >= 8)
    check("planner tools all registered",
          all(s["tool"] in [t["name"] for t in registry_summary()] for s in plan))
    check("registry has tools", len(registry_summary()) >= 10)
    check("signal_search registered",
          "signal_search" in [t["name"] for t in registry_summary()])
    plan_sig = build_plan({"name": "Example", "handles": ["@example"],
                           "platforms": ["instagram"], "question": "?",
                           "identifiers": ["00:0C:42:1F:65:E9"]})
    check("planner adds signal_search for identifiers",
          any(s["tool"] == "signal_search" for s in plan_sig))
    check("signal_search dry-run is dry_run",
          run_tool("signal_search", {"query": "00:0C:42:1F:65:E9"},
                   False, cfg)["status"] == "dry_run")
    # Fixture signal search: local files only, no network, no keys.
    # 00:0C:42:1F:65:E9 is the published Mylnikov documentation example,
    # and the signal-search data/ folder holds matching fixture files.
    sig = run_tool("signal_search",
                   {"query": "00:0C:42:1F:65:E9",
                    "no_network": True, "no_cache": True},
                   True, cfg)
    check("signal_search fixture run ok", sig["status"] == "ok")
    check("signal_search fixture found locally",
          sig["data"].get("summary", {}).get("found", 0) >= 2)
    check("signal_search merged schema present",
          bool(sig["data"].get("merged")) and
          "spread_m" in sig["data"]["merged"][0] and
          "sources" in sig["data"]["merged"][0])
    check("signal_search per-source lat/lon present",
          all("lat" in r and "lon" in r for r in sig["data"].get("results", [])))
    try:
        get_tool("phoenix-anything")
        check("phoenix tool raises", False)
    except KeyError:
        check("phoenix tool raises", True)
    check("phoenix tools empty (pending reply)", PHOENIX_TOOLS == [])

    # Full dry-run case, no model, no network
    result = run_case(
        {"name": "Example Target", "handles": ["@example-handle"],
         "platforms": ["instagram", "facebook"],
         "question": "Is there a public footprint?",
         "scope": "Read-only public collection"},
        cfg, live=False, dry_run=True, llm_provider=NullProvider())
    check("dry-run case produces report",
          os.path.exists(result["report"]))
    check("dry-run case has no-model note",
          "no-model" in result["llm_note"])
    check("dry-run tool results recorded", len(result["tool_results"]) >= 8)
    check("dry-run verified findings recorded", len(result["verified"]) >= 8)
    return passed, failed, msgs


def main():
    ap = argparse.ArgumentParser(description="Self-hosted OSINT agent.")
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--case", help="Case dir containing case.json")
    ap.add_argument("--target", help="Target name (used with --handles)")
    ap.add_argument("--handles", help="Comma-separated handles, e.g. @a,@b")
    ap.add_argument("--platforms", default="instagram,facebook",
                    help="Comma-separated platforms")
    ap.add_argument("--question", default="What is the public footprint?")
    ap.add_argument("--dry-run", action="store_true",
                    help="Plan + tool dry-runs only, no network (default if no --live)")
    ap.add_argument("--live", action="store_true",
                    help="Run tools for real (breach_check still dry-run unless --breach-live)")
    ap.add_argument("--breach-live", action="store_true",
                    help="Allow live breach_check (needs HIBP/DeHashed keys in env)")
    ap.add_argument("--report", action="store_true",
                    help="Print the report path after the run")
    ap.add_argument("--self-test", action="store_true",
                    help="Run internal checks (no Ollama, no network) and exit")
    ap.add_argument("--list-tools", action="store_true",
                    help="List the registered tools and exit")
    a = ap.parse_args()

    if a.self_test:
        passed, failed, msgs = self_test()
        print("\n".join(msgs))
        print(f"\nself-test: {passed} passed, {failed} failed")
        return 0 if failed == 0 else 1

    if a.list_tools:
        for tool in registry_summary():
            print(f"{tool['name']} [{tool['kind']}] — {tool['description']}")
        print(f"\nPhoenix tools: {len(PHOENIX_TOOLS)} registered "
              f"(pending his reply on {PHOENIX_ISSUE_URL})")
        return 0

    cfg = load_config(a.config)
    if a.breach_live:
        cfg["breach_live"] = True
    live = a.live and not a.dry_run

    if a.case:
        case = load_case(a.case)
    elif a.target:
        case = {"name": a.target,
                "handles": [h.strip() for h in (a.handles or "").split(",") if h.strip()],
                "platforms": [p.strip() for p in a.platforms.split(",") if p.strip()],
                "question": a.question,
                "scope": "Read-only public collection"}
    else:
        ap.error("give --case or --target")

    provider = build_provider(cfg)
    if not isinstance(provider, NullProvider):
        if not provider.ping():
            print(f"Model {getattr(provider, 'model', provider.name)} at "
                  f"{getattr(provider, 'endpoint', '')} not reachable — "
                  "continuing in no-model mode.")
            provider = NullProvider()

    result = run_case(case, cfg, live=live, dry_run=not live,
                      llm_provider=provider)
    print(f"Run dir: {result['run_dir']}")
    print(f"Report:  {result['report']}")
    print(f"LLM:     {result['llm_note']}")
    print(f"Counts:  {result['counts']}")
    if a.report:
        with open(result["report"]) as fh:
            print(fh.read())
    return 0


if __name__ == "__main__":
    sys.exit(main())
