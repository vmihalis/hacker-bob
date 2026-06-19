# Reachability provenance — finding-level `attack_vector` assertion (Δ2 lead PR)

**Node:** I9-prov (extends the I9 reachability producer + C9 grade-time consumer with a finding-level provenance override). **Sequence:** lead Δ2 PR — **must land before C14 (PR7)**, because C14 derives the disclosure-bundle CVSS from `attack_vector`.

**Provenance:** issue **#78** (+ its empirical comment) and the net-snmp validation (session `repo-net-snmp-a358c7cc`, commit `f128c80`; adversarial re-grade `wf_ca39ab51-748`). Builds on Δ1 ([[capability-hypergraph-delta]] I9/C9), landed via PR #79.

---

## The defect (proven, do not re-derive)

The I9 producer (`mcp/lib/reachability.js`) classifies `attack_vector` / `network_reachable` by **file-directory locality with socket primitives** (an anchor file in a dir → the dir's depth-2 prefix is tagged network → every file under it inherits `network`). Measured on net-snmp `f128c80`:

| finding | file | producer stamp | correct | why |
|---|---|---|---|---|
| F-1/F-5 | `agent/mibgroup/mibII/vacm_vars.c` | network | network | correct *by accident* of broad propagation |
| F-6/F-7 | `agent/mibgroup/agentx/{master,subagent}.c` | network | **local** | AgentX **unix-socket IPC**, not UDP-161 |
| F-3 | `snmplib/mib.c` | local | **network** | renders a **reflected PDU value** (socket-free file) |

All three have **zero own network evidence and non-semantic dirs**, yet need different vectors. **No file-locality heuristic can separate them** — empirically: the AF_UNIX tweak is a no-op on these (the files aren't anchors), and tightening propagation converts F-1/F-5 into a false-negative `local`. The distinguishing fact is the **call path to the sink**, which only the evaluator (or full taint, Δ3) knows. Therefore the fix is provenance, not a better heuristic.

---

## Spec contract

A finding MAY carry an **evaluator-asserted reachability** (`attack_vector` + `network_reachable` + a **cited `call_path`** + `justification`). At grade time, an asserted reachability **wins for `attack_vector` + `network_reachable` only**; the producer heuristic remains the **fallback** when no assertion exists. This is the pair C14's disclosure-bundle CVSS consumes. The disposition records its `reachability_source` (`asserted | heuristic | none`) so C9 (lift/cap) and C14 know the confidence basis. **`cap-not-kill` is unchanged** — an `AV:L` assertion caps severity, it never drops a finding from the reportable set.

**Precedence:** `asserted` (with non-empty `call_path`) > `heuristic` surface stamp > `unknown` for `attack_vector` + `network_reachable`. On disagreement, asserted wins for those fields and a divergence note is recorded (no silent override). `severity_ceiling` stays class/locality-constrained through `stricterSeverityCeiling`: an existing inventory/heuristic ceiling still constrains the asserted class ceiling, and assertion-only grading derives the ceiling from the asserted class with an audit note. Only `attack_vector` + `network_reachable` come directly from the assertion.

**Trust boundary:** `reachability_assertion` is evaluator-authored grading provenance. It is not independently verifier-revalidated in this PR, so evaluators must record it only when they personally verified the cited entrypoint-to-sink path from code or replay evidence. Assertion-backed AV:N HIGH/CRIT findings may be marked `lifted`, but they do not set `defensible:true`; `reachability_source:"asserted"` stays visible so the operator can review the cited path. Severity-lift for locality under-counts, such as a network-reachable sink in a file the heuristic stamped local/medium, is deferred to the Δ3 taint backstop because lifting graded severity from an unverified, `defensible:false` assertion would violate honest-severity. This is a deliberate Δ2 bridge until full data-flow provenance lands.

**Conflict policy:** frozen claims are ordered by `created_at`, then `claim_id`. The first distinct valid `attack_vector`/`network_reachable` assertion wins; same-classification `call_path` refinements are not conflicts and update the rendered call path, while conflicting later classifications add an audit note but do not override the first one. Correcting a stale frozen classification requires operator amendment / re-freeze, not recording another conflicting claim.

---

## Build slices (real anchors on the Δ1 base; verify exact lines at build time)

1. **Claim schema** — `mcp/lib/finding-contracts.js` `normalizeFindingRecord` (~:392, beside `surface_id` ~:420): add an optional `reachability_assertion` object:
   - `attack_vector` — validated against `ATTACK_VECTOR_VALUES` (`reachability-ceiling.js` ~:31)
   - `network_reachable` — boolean
   - `call_path` — **required when the assertion is present** (entrypoint→sink, cited; reject a bare assertion with no path)
   - `justification` — short text
   It MUST NOT enter `computeFindingDedupeKey` (~:370) — reachability is not an identity field.
2. **Recording** — `mcp/lib/tools/record-candidate-claim.js`: thread the field through (it already normalizes via `normalizeFindingRecord`); add `call_path`/`justification` text caps consistent with `CLAIM_TEXT_LIMITS` (~:53).
3. **Consumer override** — `mcp/lib/reachability-ceiling.js` `resolveFindingReachability` (~:237): before the surface-ceilings match, read the finding's frozen-claim `reachability_assertion`; if present + cited, return `{severity_ceiling: <asserted class ceiling constrained by any existing inventory/heuristic ceiling via stricterSeverityCeiling>, attack_vector, network_reachable, reachability_source:"asserted"}`. Else the current heuristic path with `reachability_source:"heuristic"`; null → `"none"`. `computeReachabilityDisposition` (~:57) carries `reachability_source` into the disposition.
4. **Disposition stamp** — add `reachability_source` to the object from `computeReachabilityDisposition` + the normalizer `normalizeReachabilityDispositionStamp` (**defined in `mcp/lib/reachability-ceiling.js` ~:139**, invoked at `grade-verdict-store.js` ~:125) + a `- Reachability Source:` line in the markdown render (`grade-verdict-store.js` ~:313-317).
5. **Gate** — `mcp/lib/lifecycle-gates.js` `missingReachabilityStampsForReportableFindings` (~:89): an asserted reachability satisfies the stamp requirement even when the surface carries no producer stamp (don't flag a cited-assertion finding as "missing reachability"). If no producer inventory/stamped-surface fallback exists, the grade records a `reachability_divergence` audit note instead of silently treating the assertion as inventory-backed.
6. **Evaluator behavior** — the evaluator agent(s) (`evaluator-agent` + the OSS evaluator family) must assert `reachability_assertion` when recording a native/code finding: cite entrypoint→sink and classify network vs local. Examples to encode in the prompt: `"UDP-161 SNMP SET → write_vacmAccessStatus → access_parse_oid"` = network/PR:H; `"AgentX master unix socket → handle_subagent_set_response"` = local. **Registry-driven** so Codex/Kimi reach parity; run `node scripts/generate-agent-tools.js` (+ `generate-hacker-bob-skill.js`, `generate-kimi-roles.js`) if role/tool metadata changes.

---

## Tests (`test/reachability.test.js` + a claim-override test)

- **net-snmp shapes (the acceptance core):** asserted `local` overrides heuristic `network` for `attack_vector`/`network_reachable` (F-6/F-7); asserted `network` overrides heuristic `local` for `attack_vector`/`network_reachable` (F-3) while the heuristic/locality ceiling still constrains graded severity; asserted `network` where heuristic is also `network` (F-1/F-5) → stays `network`.
- **fallback:** no assertion → heuristic stamp used (existing reachability tests stay green, unchanged).
- **validation:** assertion present but no `call_path` → rejected at record time.
- **provenance:** `reachability_source` is `asserted`/`heuristic`/`none` in the three branches.
- **cap-not-kill:** an `AV:L` assertion caps severity but the finding stays in the reportable set.
- **gate:** asserted reachability satisfies `missingReachabilityStampsForReportableFindings` even with no surface-ceiling match.

---

## Done / acceptance

- `npm test` green (`test:mcp` + `test:prompts` + `test:install`).
- The three net-snmp shapes produce the correct `attack_vector` + `network_reachable` **via assertion**; fallback path unchanged, and graded severity remains constrained by `severity_ceiling`.
- `cap-not-kill` preserved; `reachability_source` threaded to `grade.md` (and available to C14's CVSS input).
- **Parishioner gate:** re-run `/bob-evaluate` on net-snmp (or replay the frozen claims) → F-6/F-7 `attack_vector=local`, F-1/F-5 `attack_vector=network`, F-3 `attack_vector=network`, all `reachability_source=asserted`; graded severity remains ceiling-constrained. Then **#78 closes**.

---

## Constraints / doctrine

- **`cap-not-kill`** — `AV:L` caps, never drops.
- **Do NOT tighten the file-locality heuristic** — empirically proven (#78) to relocate over-counts into under-counts. Keep it strictly as the fallback.
- **MCP-owned artifacts stay MCP-owned** — `claims.jsonl`, `grade.json` are written via tools, never hand-edited.
- **Codex/Kimi parity** — evaluator-prompt change must be registry-driven; regenerate generated surfaces.
- **Coordinate with C9** — this touches `reachability-ceiling.js` + `grade-verdict-store.js`, the just-landed C9 code (PR #75). Extend, don't duplicate.
- Full data-flow (`taint_trace`) provenance is the **Δ3 backstop** for the fallback path and for severity-lift on locality under-counts; this PR is the evaluator-assertion override for `attack_vector` + `network_reachable` only.

## Risks

- **Lazy/wrong assertion** → mitigate by requiring a cited `call_path` + keeping the heuristic fallback + divergence logging.
- **C9 intersection** → reuse `computeReachabilityDisposition`; add `reachability_source` rather than reshaping the disposition.
- **Dedupe drift** → keep `reachability_assertion` out of `computeFindingDedupeKey`.
