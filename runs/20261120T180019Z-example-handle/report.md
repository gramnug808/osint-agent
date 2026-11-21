# OSINT Report — Example Target

Generated: 2026-11-20T18:00:19Z (UTC) · Model: none (no-model mode) · LLM note: no-model mode: no local model reachable/configured; LLM step skipped, tools and 6-gate verifier still ran.

Question: Is there a public footprint?
Handles: @example-handle
Platforms: instagram, facebook
Scope: Read-only public collection

## Confidence counts

Low: 3, Unverified: 7

## Confirmed (High — all 6 gates pass)

- (none)

## Inferred / strong or weak clues (Medium / Low)

- Tool case_intake ran OK — output needs the 6 gates applied by a human before it is a finding. — Low — gates: source=weak, corroboration=fail, identity=weak, time=weak, access=pass, exit=pass. Weakest gate: corroboration.
- Tool timeline ran OK — output needs the 6 gates applied by a human before it is a finding. — Low — gates: source=weak, corroboration=fail, identity=weak, time=weak, access=pass, exit=pass. Weakest gate: corroboration.
- Tool correlate ran OK — output needs the 6 gates applied by a human before it is a finding. — Low — gates: source=weak, corroboration=fail, identity=weak, time=weak, access=pass, exit=pass. Weakest gate: corroboration.

## Unverified / cannot determine

- Tool handle_enum.py planned (dry-run) — no live evidence collected. — Unverified — gates: source=fail, corroboration=fail, identity=fail, time=fail, access=fail, exit=pass. Weakest gate: source.
- Tool leak_search.py planned (dry-run) — no live evidence collected. — Unverified — gates: source=fail, corroboration=fail, identity=fail, time=fail, access=fail, exit=pass. Weakest gate: source.
- Tool breach_check.py planned (dry-run) — no live evidence collected. — Unverified — gates: source=fail, corroboration=fail, identity=fail, time=fail, access=fail, exit=pass. Weakest gate: source.
- Tool snapshot.py planned (dry-run) — no live evidence collected. — Unverified — gates: source=fail, corroboration=fail, identity=fail, time=fail, access=fail, exit=pass. Weakest gate: source.
- Tool like_sweep.py planned (dry-run) — no live evidence collected. — Unverified — gates: source=fail, corroboration=fail, identity=fail, time=fail, access=fail, exit=pass. Weakest gate: source.
- Tool reverse_image returned guidance only — manual step required, no evidence collected. — Unverified — gates: source=weak, corroboration=fail, identity=fail, time=fail, access=fail, exit=pass. Weakest gate: corroboration.
- Tool public_records returned guidance only — manual step required, no evidence collected. — Unverified — gates: source=weak, corroboration=fail, identity=fail, time=fail, access=fail, exit=pass. Weakest gate: corroboration.

## Plan executed

1. [case_intake] Record intake, create the case folder, strip sensitive values.
2. [handle_enum] Public handle search across platforms; a hit is a candidate, not a match, until the identity gates pass.
3. [leak_search] Public leak-mention search plan (dry-run first); never download paste or dump content.
4. [breach_check] Breach check, dry-run unless keys are set in env; redacted output only.
5. [snapshot] Profile snapshot (counts, bio, private/public) for baseline.
6. [like_sweep] Like/comment sweep, max 5 posts, >=5s apart, stop on HTTP 429. A blocked sweep is not a negative finding.
7. [reverse_image] Reverse-image guidance only: public sources, a match is a lead, not an identity, until the 6 gates pass.
8. [public_records] Public-records search guidance (court, property, business, news); never merge same-name people.
9. [timeline] Build a dated timeline from verified events only; flag UNVERIFIED-TIME where no raw timestamp exists.
10. [correlate] Social graph from verified overlaps only; weak clues are not edges.
11. [report] Structured report: findings with confidence, what was checked and found nothing, what could not be determined, next steps.

## Tool results (structured)

- case_intake: ok (confidence High) — Intake recorded. Sensitive values (phone/address/DOB/password) are never stored in a case folder.
- handle_enum.py: dry_run (confidence Unverified) — Dry-run: plan only, no network, no live check.
- leak_search.py: dry_run (confidence Unverified) — Dry-run: plan only, no network, no live check.
- breach_check.py: dry_run (confidence Unverified) — Dry-run: plan only, no network, no live check.
- snapshot.py: dry_run (confidence Unverified) — Dry-run: plan only, no network, no live check.
- like_sweep.py: dry_run (confidence Unverified) — Dry-run: plan only, no network, no live check.
- reverse_image: guidance (confidence Unverified) — Guidance only — no API key, no automated image upload. A match is a lead until the 6 gates pass.
- public_records: guidance (confidence Unverified) — Guidance only — live record searches need the browser agent. A no-hit is not proof of no record.
- timeline: ok (confidence Medium) — Timeline built from the verified findings in this run.
- correlate: ok (confidence Medium) — Graph built from the verified overlaps in this run.

## What was checked and found nothing

(List each tool / query that returned no hit, with its exact scope.)

## What could not be determined

(Private-account content, rate-limited sweeps, and anything needing a browser step go here — with why.)

## What would confirm / disprove each key claim

(One line per key claim.)

## Next steps

1. Re-run the plan with --live once the model is reachable, if a live run is authorised.
2. Ask Phoenix for his tool list on https://github.com/gramnug808/wardrive-companion/issues/1 and register any tools he supplies under tools/phoenix/.
3. If a follow / DM / browser step is needed, hand it to the browser agent — this agent never does it.

## Limits

- Lawful public OSINT only. No bypassing private settings, no DMs / location / phone data, no contacting targets.
- A no-hit means no hit in the queries actually run.
- Private Instagram accounts: posts, likers, follower/following lists are not visible. A follow still 'Requested' changes nothing.
- Rate limits (HTTP 429) stop a sweep; a blocked sweep is not a negative finding.
