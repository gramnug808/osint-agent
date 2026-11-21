"""Agent core — task loop.

Intake -> Plan -> Collect (tools) -> Verify (6 gates) -> Report.
The LLM drafts plans and synthesis; it never decides what is verified.
The 6-gate verifier decides. No-model mode works: tools and verifier
still run, the LLM step is skipped with a clear note.
"""
import json
import os
import re
from datetime import datetime, timezone

from .llm import (NullProvider, PLAN_PROMPT, SYNTHESIS_PROMPT,
                  SYSTEM_PROMPT, build_provider)
from .planner import build_plan, plan_text
from .tools import run_tool
from .verifier import verify_findings
from .report import write_report

SENSITIVE_PATTERNS = [
    (r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b", "phone-like value"),
    (r"\b\d{4}-\d{2}-\d{2}\b", "date-like value (possible DOB)"),
    (r"(?i)\b(password|passwd|otp|verification code|2fa)\b",
     "credential-like value"),
]


def sanitise_case(case):
    """Strip sensitive intake values; note that they were supplied, not stored."""
    notes = []
    clean = dict(case)
    for field in ("name", "question", "handles"):
        value = clean.get(field)
        if isinstance(value, list):
            text = " ".join(str(v) for v in value)
        else:
            text = str(value or "")
        for pattern, what in SENSITIVE_PATTERNS:
            if re.search(pattern, text):
                notes.append(f"{field}: {what} supplied, not stored")
                if isinstance(value, list):
                    clean[field] = [re.sub(pattern, "[redacted]", v)
                                    for v in value]
                else:
                    clean[field] = re.sub(pattern, "[redacted]", text)
    return clean, notes


def run_case(case, config, live=False, dry_run=False, llm_provider=None):
    """Run one case end to end. Returns a dict with plan, tool results,
    verified findings, report path, and the LLM note."""
    case, notes = sanitise_case(case)
    # Normalise handles: case.json stores [{"handle": "@x", ...}];
    # the planner / tools expect plain handle strings.
    raw_handles = case.get("handles") or []
    case["handles"] = [
        h.get("handle", "") if isinstance(h, dict) else str(h)
        for h in raw_handles if (h.get("handle") if isinstance(h, dict) else h)
    ]
    provider = llm_provider or build_provider(config)
    if dry_run:
        live = False

    plan = build_plan(case)

    # LLM plan draft (best effort; never required, never authoritative).
    llm_note = ""
    llm_plan = ""
    if isinstance(provider, NullProvider):
        llm_note = ("no-model mode: no local model reachable/configured; "
                    "LLM step skipped, tools and 6-gate verifier still ran.")
    else:
        try:
            llm_plan = provider.chat(
                SYSTEM_PROMPT,
                PLAN_PROMPT + "\n\nCase: " + json.dumps(case, indent=2))
            llm_note = f"model {getattr(provider, 'model', provider.name)} responded."
        except Exception as exc:
            llm_note = (f"model call failed ({exc}); continuing in no-model "
                        "mode — tools and verifier still ran.")
            provider = NullProvider()

    tool_results = []
    for step in plan:
        if step["tool"] in ("report",):
            continue
        result = run_tool(step["tool"], step["args"], live, config)
        tool_results.append(result)

    # Findings: one per tool result, gated on what the tool actually saw.
    # Tool output is a clue until its gates pass — never auto-High.
    findings = []
    for result in tool_results:
        status = result["status"]
        if status == "dry_run":
            gates = {"source": "fail", "corroboration": "fail",
                     "identity": "fail", "time": "fail",
                     "access": "fail", "exit": "pass"}
            claim = (f"Tool {result['tool']} planned (dry-run) — "
                     "no live evidence collected.")
        elif status == "blocked":
            gates = {"source": "fail", "corroboration": "fail",
                     "identity": "fail", "time": "fail",
                     "access": "fail", "exit": "pass"}
            claim = (f"Tool {result['tool']} blocked (rate limit) — "
                     "not a negative finding.")
        elif status == "guidance":
            gates = {"source": "weak", "corroboration": "fail",
                     "identity": "fail", "time": "fail",
                     "access": "fail", "exit": "pass"}
            claim = (f"Tool {result['tool']} returned guidance only — "
                     "manual step required, no evidence collected.")
        elif status == "ok":
            gates = {"source": "weak", "corroboration": "fail",
                     "identity": "weak", "time": "weak",
                     "access": "pass", "exit": "pass"}
            claim = (f"Tool {result['tool']} ran OK — output needs the "
                     "6 gates applied by a human before it is a finding.")
        else:
            gates = {"source": "fail", "corroboration": "fail",
                     "identity": "fail", "time": "fail",
                     "access": "fail", "exit": "pass"}
            claim = f"Tool {result['tool']} errored — no evidence collected."
        findings.append({"claim": claim, **gates})

    verified, counts = verify_findings(findings)

    # LLM synthesis draft (best effort, labelled as a draft).
    synthesis = ""
    if llm_plan or not isinstance(provider, NullProvider):
        try:
            synthesis = provider.chat(
                SYSTEM_PROMPT,
                SYNTHESIS_PROMPT + "\n\n" +
                json.dumps(tool_results, indent=2)[:6000])
        except Exception:
            synthesis = ""

    runs_dir = config["paths"]["runs_dir"]
    os.makedirs(runs_dir, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    slug = re.sub(r"[^a-z0-9]+", "-",
                  (case.get("handles") or [case.get("name", "target")])[0]
                  .lstrip("@").lower()).strip("-") or "target"
    run_dir = os.path.join(runs_dir, f"{stamp}-{slug}")
    os.makedirs(run_dir, exist_ok=True)
    report_path = write_report(
        case, plan, tool_results, verified, counts, llm_note,
        os.path.join(run_dir, "report.md"),
        model_info=getattr(provider, "model", provider.name)
        if not isinstance(provider, NullProvider) else "none (no-model mode)")
    with open(os.path.join(run_dir, "run.json"), "w") as fh:
        json.dump({"case": case, "plan": plan, "tool_results": tool_results,
                   "verified": verified, "counts": counts,
                   "llm_note": llm_note, "llm_plan_draft": llm_plan,
                   "llm_synthesis_draft": synthesis,
                   "sanitise_notes": notes, "report": report_path},
                  fh, indent=2)
    return {"run_dir": run_dir, "report": report_path, "plan": plan,
            "tool_results": tool_results, "verified": verified,
            "counts": counts, "llm_note": llm_note,
            "llm_plan_draft": llm_plan, "llm_synthesis_draft": synthesis}
