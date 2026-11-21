# Phoenix tools — PENDING, do not invent

## Status: no verified list exists

Phoenix is the user's mentor / elder and GitHub collaborator
(gramnug808). On 2026-11-16 Ben asked him how to get better at OSINT
on GitHub Issue #1:

- https://github.com/gramnug808/wardrive-companion/issues/1

**As of 2026-11-19 he has NOT replied.** The issue contains only the
original question and Ben's follow-up comment. No Phoenix-authored
tool list, script, or workflow exists in the workspace or on that
issue — a grep of `~/workspace/osint-investigator/`,
`~/workspace/osint-tools/`, and both OSINT skills returns zero
Phoenix tool mentions.

So this directory is intentionally empty. Nothing here is attributed
to Phoenix, and no tool in the agent claims to be his.

## The exact question to ask him

> Phoenix — what OSINT tools / scripts / workflows do you use, and
> which should Ben wire into this agent first? Please list each tool
> with what it does, its inputs, and its limits.

That is the follow-up already posted on Issue #1 (2026-11-17), plus
the request to "write Ben into being better and knowing what to do
without being told".

## How to add a Phoenix tool when he replies

1. Save his reply (link + date) in this directory as
   `phoenix-reply-<date>.md`. Do not paraphrase his list into
   something else — quote it.
2. Put each tool he supplies under `tools/phoenix/<tool-name>/`
   with its own README (what it does, inputs, limits, source).
3. Register it in `osint_agent/tools.py`: add an entry to the
   `TOOLS` dict with `"origin": "phoenix"`, and append its name to
   `PHOENIX_TOOLS`. Remove the disabled guard for that name only.
4. Run `python3 agent.py --self-test` and a dry-run case, and
   confirm the tool appears in `--list-tools` with origin phoenix.
5. If a tool he suggests would bypass a private setting, pull DMs /
   location / phone data, or contact a target, do NOT wire it in —
   flag it to the user and keep it out of the registry.

## What is wired in now (Ben's toolkit, not Phoenix's)

See `osint_agent/tools.py` — handle_enum, leak_search, breach_check
(dry-run), snapshot, like_sweep, reverse-image guidance,
public-records guidance, timeline, correlate, report, case_intake.
All from `~/workspace/osint-investigator/toolkit/` and
`~/workspace/osint-tools/`, built 2026-11-13/14.
