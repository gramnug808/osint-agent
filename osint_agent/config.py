"""Config loading for the OSINT agent. stdlib only — a tiny YAML subset
reader, so no PyYAML dependency is needed on the host."""
import os

DEFAULTS = {
    "model": {
        "provider": "ollama",
        "name": "llama3.1:8b",
        "endpoint": "http://localhost:11434",
        "timeout_seconds": 120,
    },
    "limits": {
        "max_posts_per_sweep": 5,
        "min_seconds_between_calls": 5,
        "stop_on_429": True,
        "max_tool_seconds": 120,
    },
    "paths": {
        "investigator_home": "~/workspace/osint-investigator",
        "tools_home": "~/workspace/osint-tools",
        "signal_search_home": "~/workspace/signal-search",
        "cases_dir": "~/workspace/osint-agent/cases",
        "runs_dir": "~/workspace/osint-agent/runs",
    },
    "report": {
        "require_6_gate": True,
        "mask_private_values": True,
    },
}


def _parse_scalar(value):
    value = value.strip()
    if value in ("true", "True"):
        return True
    if value in ("false", "False"):
        return False
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        pass
    return value.strip("\"'")


def _expand_paths(cfg):
    for key, value in cfg.get("paths", {}).items():
        if isinstance(value, str):
            cfg["paths"][key] = os.path.expanduser(value)
    return cfg


def load_config(path):
    """Load config.yaml (tiny subset: top-level sections, key: value).
    Missing file or missing keys fall back to DEFAULTS."""
    cfg = {section: dict(vals) for section, vals in DEFAULTS.items()}
    if not path or not os.path.exists(os.path.expanduser(path)):
        return _expand_paths(cfg)
    section = None
    with open(os.path.expanduser(path)) as fh:
        for line in fh:
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            if not line.startswith((" ", "\t")) and line.rstrip().endswith(":"):
                section = line.rstrip().rstrip(":").strip()
                cfg.setdefault(section, {})
                continue
            if ":" in line and section:
                key, _, value = line.partition(":")
                cfg[section][key.strip()] = _parse_scalar(value)
    return _expand_paths(cfg)
