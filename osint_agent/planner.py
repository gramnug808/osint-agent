"""Investigation planner. Produces an ordered, rate-limit-aware plan
from a case intake, using only tools in the registry. No network here.
"""
from .tools import TOOL_NAMES, get_tool

MAX_SWEEP = 5


def build_plan(case):
    """case: dict with name, handles, platforms, question.
    Returns a list of plan steps, each a dict with step, tool, args, why."""
    name = case.get("name", "target")
    handles = case.get("handles") or []
    platforms = case.get("platforms") or ["instagram"]
    question = case.get("question", "What is the public footprint?")
    steps = []
    n = 0

    def add(tool, args, why):
        nonlocal n
        n += 1
        steps.append({"step": n, "tool": tool, "args": args, "why": why})

    add("case_intake", {"name": name, "handles": handles,
                        "platforms": platforms, "question": question},
        "Record intake, create the case folder, strip sensitive values.")
    if handles:
        add("handle_enum", {"handle": handles[0], "name": name,
                            "platforms": ",".join(platforms), "max_queries": 10},
            "Public handle search across platforms; a hit is a candidate, "
            "not a match, until the identity gates pass.")
    add("leak_search", {"target": handles[0] if handles else name,
                        "target_type": "handle" if handles else "name"},
        "Public leak-mention search plan (dry-run first); never download "
        "paste or dump content.")
    add("breach_check", {"target": handles[0] if handles else name,
                         "target_type": "handle" if handles else "name"},
        "Breach check, dry-run unless keys are set in env; redacted output only.")
    identifiers = case.get("identifiers") or case.get("signals") or []
    for ident in identifiers[:3]:
        add("signal_search", {"query": str(ident)},
            "One-input signal-database search for this BSSID / MAC / SSID / "
            "cell ID: WiGLE, Mylnikov, OpenCelliD, local Kismet / WiGLE "
            "files, plus key-required sources only if keys are set in "
            "signal-search config. Merged per-source lat/lon; >200 m "
            "disagreement flagged, not averaged away.")
    if "instagram" in platforms and handles:
        add("snapshot", {"username": handles[0].lstrip("@")},
            "Profile snapshot (counts, bio, private/public) for baseline.")
        add("like_sweep", {"targets": f"{handles[0].lstrip('@')}:{MAX_SWEEP}"},
            f"Like/comment sweep, max {MAX_SWEEP} posts, >=5s apart, "
            "stop on HTTP 429. A blocked sweep is not a negative finding.")
    add("reverse_image", {"target": name},
        "Reverse-image guidance only: public sources, a match is a lead, "
        "not an identity, until the 6 gates pass.")
    add("public_records", {"target": name},
        "Public-records search guidance (court, property, business, news); "
        "never merge same-name people.")
    add("timeline", {"events": "from verified findings only"},
        "Build a dated timeline from verified events only; flag "
        "UNVERIFIED-TIME where no raw timestamp exists.")
    add("correlate", {"overlaps": "from verified overlaps only"},
        "Social graph from verified overlaps only; weak clues are not edges.")
    add("report", {},
        "Structured report: findings with confidence, what was checked "
        "and found nothing, what could not be determined, next steps.")
    # Sanity: every planned tool must exist in the registry.
    for step in steps:
        if step["tool"] not in TOOL_NAMES:
            raise ValueError(f"planner referenced unknown tool: {step['tool']}")
    return steps


def plan_text(steps):
    lines = []
    for step in steps:
        lines.append(f"{step['step']}. [{step['tool']}] {step['why']}")
    return "\n".join(lines)
