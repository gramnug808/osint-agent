"""6-gate fail-closed verifier.

Port of the rules in ~/workspace/osint-investigator/VERIFICATION.md.
Any gate that fails downgrades the claim; the weakest gate sets the
confidence for that part of the claim. The model never overrides this.
"""
GATES = ["source", "corroboration", "identity", "time", "access", "exit"]

GATE_DESCRIPTIONS = {
    "source": "Primary, public, reachable again. URL, date, method recorded.",
    "corroboration": "A second independent source agrees.",
    "identity": "Name + handle + photo/DOB/context match. No merge on name alone.",
    "time": "Timestamp from the platform, raw value + timezone recorded.",
    "access": "Seen yourself, after reload where it matters — not a Cloudflare fetch.",
    "exit": "Re-checkable: snapshot / raw output saved, what would disprove it noted.",
}


def gate_finding(finding):
    """finding: dict with keys per gate, each "pass" / "weak" / "fail"
    (missing = "fail"), plus "claim" and optional "downgraded_from".

    Returns dict with confidence, weakest gate, and a verdict string.
    """
    gates = {}
    for gate in GATES:
        value = str(finding.get(gate, "fail")).lower()
        gates[gate] = value if value in ("pass", "weak", "fail") else "fail"
    fails = [g for g, v in gates.items() if v == "fail"]
    weaks = [g for g, v in gates.items() if v == "weak"]

    if "identity" in fails or "source" in fails:
        confidence = "Unverified"
    elif len(fails) >= 2:
        confidence = "Low"
    elif fails:
        confidence = "Low"
    elif weaks:
        confidence = "Medium"
    else:
        confidence = "High"

    weakest = fails[0] if fails else (weaks[0] if weaks else None)
    verdict = (
        f"{confidence} — gates: "
        + ", ".join(f"{g}={gates[g]}" for g in GATES)
        + (f". Weakest gate: {weakest}." if weakest else ". All 6 gates pass.")
    )
    return {
        "claim": finding.get("claim", ""),
        "gates": gates,
        "confidence": confidence,
        "weakest_gate": weakest,
        "verdict": verdict,
    }


def verify_findings(findings):
    """Verify a list of finding dicts. Returns (verified_list, summary)."""
    verified = [gate_finding(f) for f in findings]
    counts = {}
    for item in verified:
        counts[item["confidence"]] = counts.get(item["confidence"], 0) + 1
    return verified, counts
