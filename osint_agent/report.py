"""Report writer — structured OSINT report with confidence, gates,
and Confirmed / Inferred / Unverified separated. No invented evidence.
"""
import json
import os
from datetime import datetime, timezone


def _ts():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_report(case, plan, tool_results, verified, counts, llm_note,
                 out_path, model_info):
    """Write a Markdown report. verified: list from verifier.verify_findings."""
    confirmed = [v for v in verified if v["confidence"] == "High"]
    inferred = [v for v in verified if v["confidence"] in ("Medium", "Low")]
    unverified = [v for v in verified if v["confidence"] in
                  ("Unverified", "Cannot determine")]
    lines = [
        f"# OSINT Report — {case.get('name', 'target')}",
        "",
        f"Generated: {_ts()} (UTC) · Model: {model_info} · "
        f"LLM note: {llm_note}",
        "",
        f"Question: {case.get('question', '')}",
        f"Handles: {', '.join(case.get('handles') or ['(none)'])}",
        f"Platforms: {', '.join(case.get('platforms') or [])}",
        f"Scope: {case.get('scope', 'Read-only public collection')}",
        "",
        "## Confidence counts",
        "",
        ", ".join(f"{k}: {v}" for k, v in sorted(counts.items())) or "No findings.",
        "",
        "## Confirmed (High — all 6 gates pass)",
        "",
    ]
    for item in confirmed:
        lines.append(f"- {item['claim']} — {item['verdict']}")
    if not confirmed:
        lines.append("- (none)")
    lines += ["", "## Inferred / strong or weak clues (Medium / Low)",
              ""]
    for item in inferred:
        lines.append(f"- {item['claim']} — {item['verdict']}")
    if not inferred:
        lines.append("- (none)")
    lines += ["", "## Unverified / cannot determine", ""]
    for item in unverified:
        lines.append(f"- {item['claim']} — {item['verdict']}")
    if not unverified:
        lines.append("- (none)")
    lines += ["", "## Plan executed", ""]
    for step in plan:
        lines.append(f"{step['step']}. [{step['tool']}] {step['why']}")
    lines += ["", "## Tool results (structured)", ""]
    for result in tool_results:
        lines.append(
            f"- {result['tool']}: {result['status']} "
            f"(confidence {result['confidence']}) — {result.get('note', '')}")
    lines += [
        "",
        "## What was checked and found nothing",
        "",
        "(List each tool / query that returned no hit, with its exact scope.)",
        "",
        "## What could not be determined",
        "",
        "(Private-account content, rate-limited sweeps, and anything "
        "needing a browser step go here — with why.)",
        "",
        "## What would confirm / disprove each key claim",
        "",
        "(One line per key claim.)",
        "",
        "## Next steps",
        "",
        "1. Re-run the plan with --live once the model is reachable, "
        "if a live run is authorised.",
        "2. Ask Phoenix for his tool list on "
        "https://github.com/gramnug808/wardrive-companion/issues/1 "
        "and register any tools he supplies under tools/phoenix/.",
        "3. If a follow / DM / browser step is needed, hand it to the "
        "browser agent — this agent never does it.",
        "",
        "## Limits",
        "",
        "- Lawful public OSINT only. No bypassing private settings, no "
        "DMs / location / phone data, no contacting targets.",
        "- A no-hit means no hit in the queries actually run.",
        "- Private Instagram accounts: posts, likers, follower/following "
        "lists are not visible. A follow still 'Requested' changes nothing.",
        "- Rate limits (HTTP 429) stop a sweep; a blocked sweep is not a "
        "negative finding.",
        "",
    ]
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as fh:
        fh.write("\n".join(lines))
    return out_path
