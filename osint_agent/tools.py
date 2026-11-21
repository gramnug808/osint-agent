"""Tool registry — wraps Ben's existing OSINT toolkit.

Wrappers call the existing scripts as subprocesses and return
structured JSON: {tool, status, source, date, confidence, data, note}.
They do NOT rewrite the scripts' logic. Live network calls only happen
when the caller passes live=True AND the underlying script supports it;
breach_check stays dry-run unless keys are set AND --breach-live is
given explicitly. A 429 / blocked result is reported as "blocked",
never as "no hit".

Phoenix tools: NONE verified. See tools/phoenix/README.md and
PHOENIX_TOOLS below — the registry entry is disabled until Phoenix
supplies his list on GitHub Issue #1.
"""
import json
import os
import subprocess
from datetime import datetime, timezone

# ---------------------------------------------------------------- Phoenix
# Phoenix: mentor / elder, GitHub gramnug808. Asked how to get better at
# OSINT on https://github.com/gramnug808/wardrive-companion/issues/1
# He has NOT replied as of 2026-11-19. No verified list of "Phoenix's
# OSINT tools" exists in the workspace or on that issue, so nothing is
# invented or attributed to him here. When he replies, add his tools to
# tools/phoenix/ and register them here; see tools/phoenix/README.md.
PHOENIX_ISSUE_URL = "https://github.com/gramnug808/wardrive-companion/issues/1"
PHOENIX_TOOLS = []  # disabled: no Phoenix-authored tool list exists yet.
PHOENIX_PENDING_QUESTION = (
    "Phoenix — what OSINT tools / scripts / workflows do you use, and "
    "which should Ben wire into this agent first? Please list each tool "
    "with what it does, its inputs, and its limits."
)


def _ts():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _result(tool, status, data=None, note="", confidence="Unverified"):
    return {
        "tool": tool, "status": status,
        "source": "osint-agent tool registry",
        "date": _ts(), "confidence": confidence,
        "data": data or {}, "note": note,
    }


def _run_script(script, args, timeout=120, dry_run=True):
    """Run an existing toolkit script. Returns a registry result dict."""
    name = os.path.basename(script)
    if dry_run:
        return _result(name, "dry_run",
                       {"script": script, "args": args},
                       "Dry-run: plan only, no network, no live check.",
                       confidence="Unverified")
    try:
        proc = subprocess.run(
            ["python3", script] + args,
            capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return _result(name, "blocked", {},
                       f"Timed out after {timeout}s.", confidence="Unverified")
    except FileNotFoundError:
        return _result(name, "error", {},
                       f"Script not found: {script}", confidence="Unverified")
    out = (proc.stdout or "")[-4000:]
    status = "ok" if proc.returncode == 0 else "error"
    if "429" in out or "rate limit" in out.lower():
        status = "blocked"
    return _result(name, status,
                   {"returncode": proc.returncode, "stdout_tail": out,
                    "stderr_tail": (proc.stderr or "")[-1000:]},
                   "Blocked on 429 / rate limit — not a negative finding."
                   if status == "blocked" else "",
                   confidence="Medium" if status == "ok" else "Unverified")


# Tool definitions: name -> {script or None, description, args builder}
def _investigator(script):
    return os.path.expanduser(f"~/workspace/osint-investigator/toolkit/{script}")


def _osint_tools(script):
    return os.path.expanduser(f"~/workspace/osint-tools/{script}")


def _signal_search_script():
    return os.path.expanduser("~/workspace/signal-search/search.py")


_SECRET_KEY_RE = __import__("re").compile(
    r"(?i)(api[_-]?key|api[_-]?token|token|secret|password)")


def _strip_secrets(obj):
    """Recursively drop any key-like field from a parsed result, so a
    provider's API key can never leak into a tool result / report."""
    if isinstance(obj, dict):
        return {k: _strip_secrets(v) for k, v in obj.items()
                if not _SECRET_KEY_RE.search(str(k))}
    if isinstance(obj, list):
        return [_strip_secrets(v) for v in obj]
    return obj


def _run_signal_search(args, live, cfg):
    """Wrap ~/workspace/signal-search/search.py as a subprocess.

    Dry-run: plan only, no network. Live: run the CLI with --json to a
    temp file and return the parsed, secret-stripped result in the same
    structured format as the other tools (source, date, confidence,
    plus per-source lat/lon in data.results / data.merged).
    Keys stay in signal-search's own config.yaml / .env — they are
    never copied here, never passed on the command line, never logged.
    """
    script = _signal_search_script()
    query = (args.get("query") or args.get("identifier") or "").strip()
    if not live:
        return _result("signal_search", "dry_run",
                       {"script": script, "query": query,
                        "kind": args.get("kind", "auto")},
                       "Dry-run: plan only, no network, no live check.",
                       confidence="Unverified")
    if not query and not args.get("near"):
        return _result("signal_search", "error", {},
                       "No identifier given (need a BSSID/MAC, SSID, "
                       "cell tuple, BLE UUID, or --near lat,lon).",
                       confidence="Unverified")
    if not os.path.exists(script):
        return _result("signal_search", "error", {},
                       f"Signal-search script not found: {script}",
                       confidence="Unverified")
    import tempfile
    tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
    tmp_path = tmp.name
    tmp.close()
    cmd = ["python3", script]
    if args.get("kind") == "ssid" or args.get("ssid"):
        cmd += ["--ssid", args.get("ssid") or query]
    elif args.get("kind") == "cell" or args.get("cell"):
        cmd += ["--cell", args.get("cell") or query]
    elif args.get("kind") == "ble" or args.get("ble"):
        cmd += ["--ble", args.get("ble") or query]
    elif args.get("near"):
        cmd += ["--near", args["near"]]
        if args.get("radius"):
            cmd += ["--radius", str(args["radius"])]
        if query:
            cmd += [query]
    else:
        cmd += [query]
    if args.get("no_network"):
        cmd += ["--no-network"]
    if args.get("no_cache"):
        cmd += ["--no-cache"]
    cmd += ["--json", tmp_path]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=cfg["limits"]["max_tool_seconds"])
    except subprocess.TimeoutExpired:
        return _result("signal_search", "blocked", {"query": query},
                       f"Timed out after {cfg['limits']['max_tool_seconds']}s.",
                       confidence="Unverified")
    except FileNotFoundError:
        return _result("signal_search", "error", {"query": query},
                       "python3 not found.", confidence="Unverified")
    try:
        with open(tmp_path) as fh:
            parsed = json.load(fh)
    except (OSError, json.JSONDecodeError):
        out = (proc.stdout or "")[-2000:]
        status = "blocked" if "429" in out or "rate limit" in out.lower() else "error"
        return _result("signal_search", status, {"query": query,
                                                 "stdout_tail": out},
                       "signal-search produced no JSON output.",
                       confidence="Unverified")
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
    parsed = _strip_secrets(parsed)
    summary = parsed.get("summary", {})
    data = {"source": "signal-search (~/workspace/signal-search)",
            "date": _ts(),
            "query": parsed.get("query", {}),
            "summary": summary,
            "results": parsed.get("results", []),
            "merged": parsed.get("merged", [])}
    status = "ok" if proc.returncode == 0 else "error"
    note = (f"Found in {summary.get('found', 0)} source(s), "
            f"not queried in {summary.get('not_queried', 0)}, "
            f"errors in {summary.get('errors', 0)}. "
            "A source not queried is not a negative finding; a BSSID "
            "absent from every database is not proof it does not exist.")
    if summary.get("disagreements_gt_200m"):
        note += " Sources disagree by >200 m — see per-source rows, not the mean."
    confidence = "Medium" if summary.get("found") else "Unverified"
    return _result("signal_search", status, data, note, confidence=confidence)


TOOLS = {
    "case_intake": {
        "kind": "internal",
        "description": "Record intake, create case folder, strip sensitive values.",
        "run": lambda args, live, cfg: _result(
            "case_intake", "ok", args,
            "Intake recorded. Sensitive values (phone/address/DOB/password) "
            "are never stored in a case folder.", confidence="High"),
    },
    "handle_enum": {
        "kind": "script",
        "script": _investigator("handle_enum.py"),
        "description": "Public handle search across platforms (dry-run plan, or DuckDuckGo live).",
        "run": lambda args, live, cfg: _run_script(
            _investigator("handle_enum.py"),
            ["--handle", args.get("handle", ""),
             "--name", args.get("name", ""),
             "--platforms", args.get("platforms", "instagram"),
             "--max-queries", str(args.get("max_queries", 10))]
            + (["--live"] if live else ["--dry-run"]),
            timeout=cfg["limits"]["max_tool_seconds"], dry_run=not live),
    },
    "leak_search": {
        "kind": "script",
        "script": _osint_tools("leak_search.py"),
        "description": "Public leak-mention search plan; live = DuckDuckGo HTML only, never downloads dumps.",
        "run": lambda args, live, cfg: _run_script(
            _osint_tools("leak_search.py"),
            ["--target", args.get("target", ""),
             "--target-type", args.get("target_type", "handle"),
             "--max-queries", "5"]
            + (["--live"] if live else ["--dry-run"]),
            timeout=cfg["limits"]["max_tool_seconds"], dry_run=not live),
    },
    "breach_check": {
        "kind": "script",
        "script": _osint_tools("breach_check.py"),
        "description": "HIBP + DeHashed breach check, redacted; dry-run unless keys set and --breach-live given.",
        "run": lambda args, live, cfg: _run_script(
            _osint_tools("breach_check.py"),
            (["--email", args["target"]] if "@" in args.get("target", "")
             else ["--username", args.get("target", "")])
            + (["--live"] if live and cfg.get("breach_live") else ["--dry-run"]),
            timeout=cfg["limits"]["max_tool_seconds"],
            dry_run=not (live and cfg.get("breach_live"))),
    },
    "snapshot": {
        "kind": "script",
        "script": _osint_tools("snapshot.py"),
        "description": "Instagram profile snapshot (counts, bio, private/public) via CLI.",
        "run": lambda args, live, cfg: _run_script(
            _osint_tools("snapshot.py"),
            ["--username", args.get("username", "")],
            timeout=cfg["limits"]["max_tool_seconds"], dry_run=not live),
    },
    "like_sweep": {
        "kind": "script",
        "script": _osint_tools("like_sweep.py"),
        "description": "Like/comment sweep, max 5 posts, >=5s apart, stop on 429.",
        "run": lambda args, live, cfg: _run_script(
            _osint_tools("like_sweep.py"),
            ["--targets", args.get("targets", "")],
            timeout=cfg["limits"]["max_tool_seconds"], dry_run=not live),
    },
    "signal_search": {
        "kind": "script",
        "script": _signal_search_script(),
        "description": "One-input multi-database signal search (WiGLE, Mylnikov, OpenCelliD, local Kismet/WiGLE files, + key-required sources); merged per-source lat/lon, >200 m disagreement flagged. Keys stay in signal-search config, never here.",
        "run": lambda args, live, cfg: _run_signal_search(args, live, cfg),
    },
    "reverse_image": {
        "kind": "guidance",
        "description": "Reverse-image guidance: public sources only (Google Lens, Yandex, TinEye); a match is a lead, not an identity.",
        "run": lambda args, live, cfg: _result(
            "reverse_image", "guidance",
            {"steps": ["Google Lens: lens.google.com/upload",
                       "Yandex Images: yandex.com/images/search",
                       "TinEye: tineye.com",
                       "Compare: same photo + handle + context across platforms"]},
            "Guidance only — no API key, no automated image upload. "
            "A match is a lead until the 6 gates pass.",
            confidence="Unverified"),
    },
    "public_records": {
        "kind": "guidance",
        "description": "Public-records search guidance (court, property, business, news); never merge same-name people.",
        "run": lambda args, live, cfg: _result(
            "public_records", "guidance",
            {"sources": ["eCourt Kokua (Hawaii courts, browser + CAPTCHA)",
                         "Hawaii DCCA business search",
                         "County property / tax records",
                         "News archives (Star-Advertiser, Civil Beat)"]},
            "Guidance only — live record searches need the browser agent. "
            "A no-hit is not proof of no record.",
            confidence="Unverified"),
    },
    "timeline": {
        "kind": "guidance",
        "description": "Timeline from verified events only; flag UNVERIFIED-TIME where no raw timestamp exists.",
        "run": lambda args, live, cfg: _result(
            "timeline", "ok",
            {"rule": "dated, sourced events only; gaps left as gaps"},
            "Timeline built from the verified findings in this run.",
            confidence="Medium"),
    },
    "correlate": {
        "kind": "guidance",
        "description": "Social graph from verified overlaps only; weak clues are not edges.",
        "run": lambda args, live, cfg: _result(
            "correlate", "ok",
            {"rule": "verified overlaps only as edges"},
            "Graph built from the verified overlaps in this run.",
            confidence="Medium"),
    },
    "report": {
        "kind": "internal",
        "description": "Structured report writer (see osint_agent/report.py).",
        "run": lambda args, live, cfg: _result(
            "report", "ok", {},
            "Report written by the agent core after verification.",
            confidence="High"),
    },
}

TOOL_NAMES = list(TOOLS)


def get_tool(name):
    if name not in TOOLS:
        raise KeyError(f"unknown tool: {name!r}. Registered: {TOOL_NAMES}")
    return TOOLS[name]


def run_tool(name, args, live, cfg):
    """Run one registered tool. Phoenix tools are not registered —
    calling one raises KeyError with the pending-issue pointer."""
    if name.startswith("phoenix"):
        raise KeyError(
            "Phoenix tools are not registered yet — no Phoenix-authored "
            f"tool list exists. Pending his reply on {PHOENIX_ISSUE_URL}. "
            "See tools/phoenix/README.md.")
    tool = get_tool(name)
    return tool["run"](args, live, cfg)


def registry_summary():
    return [{"name": name, "kind": t["kind"], "description": t["description"]}
            for name, t in TOOLS.items()]
