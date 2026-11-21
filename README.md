# OSINT Agent — self-hosted AI model, Ben's toolkit, 6-gate verifier

Built 2026-11-20 for Kevin / Ben. An OSINT agent that runs on a
**self-hosted model** (Ollama-first, no cloud API keys, no data leaves
the machine by default), wired to Ben's existing OSINT toolkit, with
the 6-gate fail-closed verifier deciding what counts as verified —
never the model.

## Phoenix tools — the honest status

**There is no verified list of "Phoenix's OSINT tools".** Phoenix is
the user's mentor / elder (GitHub gramnug808). Ben asked him how to
get better at OSINT on
https://github.com/gramnug808/wardrive-companion/issues/1 — **he has
not replied as of 2026-11-19**. A grep of the workspace
(`osint-investigator/`, `osint-tools/`, both OSINT skills) finds zero
Phoenix tool mentions.

So nothing in this agent is invented or attributed to Phoenix. The
toolset wired in is **Ben's toolkit** (below), and
`tools/phoenix/` is a clearly-marked placeholder: a README with the
exact question to ask him, and a disabled registry entry that raises
until he supplies a list. When he replies, follow
`tools/phoenix/README.md` § "How to add a Phoenix tool".

## What it is

```
Intake → Plan → Collect (tools) → Verify (6 gates) → Report
```

- **Model layer** (`osint_agent/llm.py`): provider interface.
  Ollama (`http://localhost:11434`, default model `llama3.1:8b`) or
  any OpenAI-compatible local endpoint (LM Studio, llama.cpp, vLLM).
  `none` = no-model mode. The model drafts plans and synthesis; it
  never decides what is verified.
- **Agent core** (`osint_agent/agent.py`): task loop, intake
  sanitising (phone / address / DOB / passwords are stripped, never
  stored), tool runs, 6-gate verification, report + `run.json`.
- **Planner** (`osint_agent/planner.py`): ordered, rate-limit-aware
  plan — sweeps ≤5 posts, ≥5s apart, stop on HTTP 429.
- **Verifier** (`osint_agent/verifier.py`): the 6 gates from
  `~/workspace/osint-investigator/VERIFICATION.md` — source,
  corroboration, identity, time, access, exit. Any gate fails →
  downgrade. Identity or source fails → Unverified.
- **Tools** (`osint_agent/tools.py`): wrappers around the existing
  scripts — they call them, they do not rewrite their logic.
- **Report** (`osint_agent/report.py`): Confirmed / Inferred /
  Unverified separated, with confidence counts, plan, tool results,
  gaps, and next steps.

## Tools wired in (Ben's toolkit)

| Tool | Source | Notes |
|---|---|---|
| `case_intake` | internal | Creates the case record, strips sensitive values |
| `handle_enum` | `osint-investigator/toolkit/handle_enum.py` | Public handle search; a hit is a candidate, not a match |
| `leak_search` | `osint-tools/leak_search.py` | Public leak-mention plan; live = DuckDuckGo HTML only |
| `breach_check` | `osint-tools/breach_check.py` | HIBP + DeHashed, redacted; dry-run unless keys set + `--breach-live` |
| `snapshot` | `osint-tools/snapshot.py` | Instagram profile snapshot via CLI |
| `like_sweep` | `osint-tools/like_sweep.py` | ≤5 posts, ≥5s apart, stop on 429 |
| `signal_search` | `~/workspace/signal-search/search.py` | One-input signal-database search; merged per-source lat/lon, >200 m disagreement flagged |
| `reverse_image` | guidance only | Google Lens / Yandex / TinEye; a match is a lead |
| `public_records` | guidance only | eCourt Kokua / DCCA / property / news; browser step needed live |
| `timeline` | internal | Dated verified events only; UNVERIFIED-TIME flagged |
| `correlate` | internal | Verified overlaps only as edges |
| `report` | internal | Structured report writer |

## The `signal_search` tool

Wired in 2026-11-20 from `~/workspace/signal-search/` — one identifier
in, every wardriving / signal database out. The agent wraps
`search.py` as a subprocess; it does not rewrite its provider logic.

- **Input:** a BSSID / MAC, SSID, cell tuple (MCC,MNC,LAC,CID), BLE
  UUID, or lat/lon + radius. Auto-detected. Add identifiers to a case
  as `"identifiers": ["00:0C:42:1F:65:E9"]` in `case.json` — the
  planner adds one `signal_search` step per identifier (max 3).
  See `cases/example-signal/case.json`.
- **Sources:** local Kismet / WiGLE files in `signal-search/data/`
  (offline first), WiGLE, Mylnikov, 3WiFi, OpenCelliD, CellMapper and
  OpenWiFiMap (manual link only — no public API), Mozilla / Google /
  Combain / Skyhook (key-required, off by default unless a key is set).
- **Keys stay in signal-search's own `config.yaml` / `.env`** — never
  copied into the agent, never passed on the command line, never
  logged. The wrapper strips any key-like field from the parsed
  result before it reaches a tool result or report.
- **Result shape:** `data.query`, `data.summary` (found / not_found /
  not_queried / errors), `data.results[]` (one row per source: source,
  identifier, lat, lon, accuracy, first_seen, last_seen, ssid,
  channel, signal, confidence, raw_url, error, status), and
  `data.merged[]` (mean position, spread in metres,
  `disagree_gt_200m`, per-source rows). A source that was not queried
  is never reported as "not found", and a BSSID absent from every
  database is not proof it does not exist.
- **Limits:** passive lookup only — no uploads, no connecting, no
  transmitting. One dead source never kills the search. Locations are
  crowd-sourced observations, not proof of who owns an AP or who was
  there. See `~/workspace/signal-search/README.md` for the full source
  table and limits.

```bash
# List it
python3 agent.py --list-tools
# Dry-run a case that carries an identifier
python3 agent.py --case cases/example-signal --dry-run
# Live run — queries all sources; key-required sources report
# "not_queried — no API key" until keys are added to signal-search
# config.yaml. The fixture BSSID below is the published Mylnikov
# documentation example, not a real person's AP.
python3 agent.py --case cases/example-signal --live
```

## Install

```bash
# 1. Python 3.10+ (stdlib only — no pip packages needed)
python3 --version

# 2. Install Ollama (model host) — https://ollama.com/download
#    Linux:
curl -fsSL https://ollama.com/install.sh | sh
#    macOS: brew install ollama

# 3. Pull a model (pick one; default in config.yaml is llama3.1:8b)
ollama pull llama3.1:8b
#    Stronger, needs ~9 GB RAM: ollama pull qwen2.5:14b
#    Bigger, needs a GPU / lots of RAM: ollama pull llama3.1:70b

# 4. Start Ollama (it usually starts itself; check with:)
curl http://localhost:11434/api/tags

# 5. (Optional) copy .env.example to .env for breach API keys.
#    No key is required to run in dry-run / no-model mode.
```

**No Ollama?** The agent still works: it runs in no-model mode —
tools run, the verifier runs, the LLM step is skipped with a clear
note in the report. Test that with `--self-test` and `--dry-run`.

## Run a case

```bash
cd ~/workspace/osint-agent

# Dry-run (default, no network, no live checks) — example case
python3 agent.py --case cases/example --dry-run

# Same, from a target name + handles
python3 agent.py --target "Example Target" --handles @example-handle --dry-run

# Live run (tools run for real; breach_check stays dry-run)
python3 agent.py --case cases/example --live

# Live run including breach_check (needs HIBP/DeHashed keys in env)
python3 agent.py --case cases/example --live --breach-live

# List tools
python3 agent.py --list-tools

# Self-test (no Ollama, no network)
python3 agent.py --self-test
```

Each run writes `runs/<timestamp>-<slug>/report.md` and `run.json`
(plan, tool results, verified findings, LLM drafts, sanitise notes).

## Change the model

Edit `config.yaml`:

```yaml
model:
  provider: ollama            # ollama | openai-compatible | none
  name: qwen2.5:14b           # ollama pull qwen2.5:14b first
  endpoint: http://localhost:11434
```

For LM Studio: set `provider: openai-compatible`,
`endpoint: http://localhost:1234/v1`, `name: <model loaded in LM Studio>`.

## Add a Phoenix tool when he replies

See `tools/phoenix/README.md`. In short: save his reply verbatim,
put the tool under `tools/phoenix/<name>/`, register it in
`osint_agent/tools.py` with `"origin": "phoenix"`, run `--self-test`
and a dry-run case. If a suggested tool would bypass a private
setting, pull DMs / location / phone data, or contact a target, do
NOT wire it in — flag it to the user.

## Limits — read before trusting a result

- Lawful public OSINT only. No hacking, no bypassing private
  settings, no DMs / location / phone data, no contacting targets,
  no interacting with other people's accounts.
- The model drafts; the 6-gate verifier decides. A tool result is a
  clue until its gates pass — the agent never auto-marks a finding High.
- Private Instagram accounts: posts, likers, follower/following
  lists are not visible. A follow still "Requested" changes nothing.
- A 429 / blocked sweep is not a negative finding. 0 posts checked
  = 0 hits, not "no likes".
- A no-hit means no hit in the queries actually run.
- Breach output is redacted by design (breach name / date / data
  types only). No password checking, no Tor / onion, no marketplaces,
  no stolen-DB downloads.
- Browser-only steps (canarytokens.org, live Instagram, sign-in,
  forms, eCourt Kokua CAPTCHA) need the browser agent — this agent
  never claims a website visit it only fetched as text.

## File map

```
~/workspace/osint-agent/
  agent.py               — CLI
  config.yaml            — model, limits, paths (edit me)
  .env.example           — optional breach keys, env only
  README.md              — this file
  osint_agent/
    __init__.py  agent.py     — task loop
    config.py    llm.py       — config + model providers
    planner.py   verifier.py  — plan + 6-gate verifier
    tools.py     report.py    — tool registry + report writer
  tools/phoenix/README.md    — Phoenix placeholder (pending Issue #1)
  cases/example/case.json    — example case (fictional target)
  tests/test_agent.py        — unit tests (stdlib unittest)
  runs/                      — run outputs (report.md + run.json)
```

## Sources

- Directives / verifier / workflow:
  `~/workspace/osint-investigator/{DIRECTIVES,INVESTIGATOR,VERIFICATION}.md`
- Toolkit: `~/workspace/osint-investigator/toolkit/`,
  `~/workspace/osint-tools/`
- Skills: `~/workspace/custom-skills/{sigint-osint,osint-investigator}/SKILL.md`
- Phoenix Issue #1: https://github.com/gramnug808/wardrive-companion/issues/1
  (no reply as of 2026-11-19)
