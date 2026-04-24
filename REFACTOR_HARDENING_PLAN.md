# Hacker Bob Refactor And Hardening Plan

## Summary

This update added useful capability, but the architecture now needs clearer boundaries. The biggest concern is that `mcp/server.js` has become responsible for too many unrelated domains: tool registration, validation, session storage, wave state, HTTP scanning, audit logs, imported traffic, public intel, ranking, hunter briefs, auth, temp email, signup, markdown rendering, and test exports.

The product direction is strong. The code now needs to reduce blast radius, make side effects explicit, protect sensitive data, and make the system easier to test and maintain.

## First Principles

Great code should make the important behavior obvious. Each module should have one clear responsibility, and the cost of changing one feature should not require understanding the whole system.

State mutations should be explicit. A read operation should not quietly rewrite session artifacts unless that behavior is named and documented.

Security tooling should be conservative with stored data. Request history, imported traffic, and audit logs can contain sensitive information, so persistence should default to redaction and bounded retention.

Heuristics should assist decisions, not hide them. Ranking, public intel, and traffic-derived prioritization should explain why they made a recommendation and should not silently override stronger local evidence.

Tests should protect the contracts that matter most: artifact integrity, backward compatibility, scope boundaries, redaction, deterministic state transitions, and prompt/tool alignment.

## Refactor Plan

### 1. Split `mcp/server.js` By Domain

The current server file is too large. Split it into smaller modules with explicit ownership:

| Module | Responsibility |
|---|---|
| `mcp/tools.js` | MCP tool definitions and dispatch |
| `mcp/session.js` | session paths, locks, atomic writes, JSONL helpers |
| `mcp/validation.js` | validators, parsers, normalizers |
| `mcp/state.js` | FSM transitions, wave start, handoff merge, requeue logic |
| `mcp/findings.js` | findings, verification rounds, grading |
| `mcp/http-audit.js` | `bounty_http_scan`, audit records, circuit-breaker summaries |
| `mcp/traffic.js` | Burp/HAR import, traffic validation, traffic summaries |
| `mcp/intel.js` | public intel fetch/cache/parsing |
| `mcp/ranking.js` | surface scoring and ranking explanations |
| `mcp/hunter-brief.js` | final hunter brief assembly |
| `mcp/auth.js` | auth profile storage and loading |
| `mcp/temp-email.js` | temp email helpers |
| `mcp/signup.js` | browser-assisted signup |

Keep the public behavior the same during the first split. The initial goal is movement of code, not behavior changes.

### 2. Make Write Side Effects Explicit

Some read-style paths currently call ranking logic that can mutate `attack_surface.json`. That is convenient, but surprising.

Preferred approaches:

- Compute ranking in memory when serving read tools.
- Add an explicit mutation tool such as `bounty_rank_attack_surfaces`.
- If a read tool must refresh ranking, return a field like `ranking_refreshed: true` and document the write.

The clean target is that read tools do not mutate files.

### 3. Harden Sensitive Data Handling

Traffic and audit logs should avoid storing sensitive values by default.

Add redaction before writing `traffic.jsonl` and `http-audit.jsonl`:

- Redact query values for keys matching `token`, `code`, `session`, `password`, `secret`, `jwt`, `auth`, `key`, `credential`, `csrf`, `xsrf`, and similar names.
- Store header names, not header values.
- Keep request bodies out of persistent logs unless an explicit debug mode is enabled.
- Consider storing `url_redacted` as the canonical field and `url` only when the caller opts in.

This matters because imported Burp/HAR traffic can easily include real session tokens or one-time auth codes in URLs.

### 4. Control Log Growth

The new session files are append-only:

- `coverage.jsonl`
- `http-audit.jsonl`
- `traffic.jsonl`

Add retention and compaction controls:

- Maximum records per file.
- Maximum records per surface.
- Maximum imported traffic entries per source.
- A compaction tool such as `bounty_compact_session_logs`.
- Summary records that preserve signal while dropping repeated low-value entries.

The goal is to keep long sessions usable without letting logs become unbounded state.

### 5. Keep Ranking Explainable And Bounded

Ranking is valuable, but it should remain advisory.

Recommendations:

- Preserve `original_priority`.
- Store `ranking.score`, `ranking.priority`, and `ranking.reasons`.
- Separate recon evidence, imported traffic evidence, and public intel evidence.
- Cap the contribution of public intel so disclosed reports do not dominate local findings.
- Add tests that show ranking cannot remove required recon fields.

Hunters should know why a surface moved up in priority.

### 6. Keep Public Intel Optional

Public intel should never block the core hunt.

Rules to preserve:

- Network failures degrade gracefully.
- Public reports are hints, not proof.
- Public intel should not validate a finding.
- Cached intel should be session-scoped.
- Output should be capped and summarized.

This feature is useful, but external parsing is inherently fragile.

### 7. Improve Test Entrypoints

`npm test` currently runs only the MCP server tests. It should run all relevant tests.

Suggested scripts:

```json
{
  "scripts": {
    "test:mcp": "node --test test/mcp-server.test.js",
    "test:prompts": "node --test test/prompt-contracts.test.js",
    "test:hooks": "python3 test/test-write-guard.py",
    "test": "npm run test:mcp && npm run test:prompts && npm run test:hooks"
  }
}
```

This makes the default test command match the actual quality bar.

### 8. Add Artifact Contract Tests

The most important system contract is artifact integrity. Add focused tests for:

- Malformed `coverage.jsonl`.
- Malformed `http-audit.jsonl`.
- Malformed `traffic.jsonl`.
- Huge traffic imports.
- Redaction of sensitive query values.
- Read tools not mutating files.
- Ranking preserving required `attack_surface.json` fields.
- Old sessions still loading.
- Coverage requeue behavior when latest status changes from `promising` to `tested`.
- Scope rejection for imported off-target traffic.

These tests should be small and deterministic.

## Suggested Implementation Order

1. Wire all existing tests into `npm test`.
2. Add redaction helpers and tests.
3. Add log caps or compaction.
4. Remove or make explicit ranking write side effects.
5. Split session/path/JSONL helpers out of `mcp/server.js`.
6. Split coverage, traffic, HTTP audit, and ranking modules.
7. Split hunter brief assembly after the supporting modules are stable.
8. Keep public exports stable so existing tests continue to pass during the move.

## Migration Progress

### Slice 1: Hardening Before Large Module Split

Completed:

- Added a dedicated URL redaction module at `mcp/redaction.js`.
- Redacted persisted audit and imported-traffic URLs, paths, credentials, query values, and fragments.
- Redacted legacy raw audit and traffic records on read so older session summaries do not leak stored query values.
- Kept actual outbound `bounty_http_scan` requests unchanged while storing only redacted audit metadata.
- Redacted out-of-scope URL logging in `.claude/hooks/scope-guard-mcp.sh`.
- Changed read-style `bounty_wave_status` and `bounty_read_hunter_brief` ranking to use in-memory overlays instead of rewriting `attack_surface.json`.
- Preserved explicit ranking writes for mutation paths such as traffic import, public intel refresh, and direct `rankAttackSurfaces` calls.
- Hardened auth path resolution so supplied target domains go through the same session-domain guard as other session artifacts.
- Updated `npm test` to run MCP, prompt-contract, and hook tests.
- Added regression tests for redaction, legacy log read redaction, read-tool non-mutation, auth path traversal, and full test entrypoints.

Still pending:

- Bounded JSONL retention or compaction.
- Large module split of `mcp/server.js`.
- Export snapshot tests.
- MCP tool registry and dispatch consistency tests.
- Stdio transport contract tests.
- Concurrency hardening around duplicate traffic imports.

### Slice 2: Foundation Module Extraction

Completed:

- Moved shared constants into `mcp/lib/constants.js`.
- Moved parser, normalizer, assertion, and small collection helpers into `mcp/lib/validation.js`.
- Moved session and artifact path helpers into `mcp/lib/paths.js`.
- Moved atomic writes, JSONL append, markdown mirror helpers, strict JSON loading, and session lock helpers into `mcp/lib/storage.js`.
- Kept `mcp/server.js` as the compatibility facade and public export source.
- Ran the full test suite after extraction.

Still pending:

- Split session state and wave assignment helpers.
- Split coverage, HTTP audit, traffic, public intel, findings, and verification modules.
- Split hunter brief assembly after provider modules are stable.
- Split auth, HTTP scan, temp email, signup, dispatch, and transport near the end.

### Slice 3: State And Assignment Extraction

Completed:

- Moved session state normalization, compact/public state views, strict state reads, state writes, and state tool handlers into `mcp/lib/session-state.js`.
- Moved assignment file loading, assignment input normalization, and wave-agent-surface validation into `mcp/lib/assignments.js`.
- Kept full wave readiness, handoff merge, coverage requeue, and orchestration logic in `mcp/server.js` for now.
- Preserved `mcp/server.js` as the compatibility facade and public export source.
- Ran focused MCP tests and the full test suite after extraction.

Still pending:

- Extract full wave readiness and handoff merge logic after coverage and findings dependencies are split.
- Extract coverage module next, using `mcp/lib/assignments.js` for assignment validation to avoid a wave/coverage cycle.
- Add export snapshot and tool registry consistency tests before deeper facade reduction.

### Slice 4: Coverage Extraction

Completed:

- Moved coverage record normalization, JSONL loading, latest-record reduction, unfinished-status detection, coverage summaries, coverage requeue selection, and coverage logging into `mcp/lib/coverage.js`.
- Reused assignment validation from `mcp/lib/assignments.js` so coverage handling stays aligned with wave ownership rules.
- Kept public exports stable through `mcp/server.js` while moving implementation out of the facade.
- Verified there are no stale coverage function bodies left in `mcp/server.js`.
- Ran focused MCP tests and the full test suite after extraction.

Still pending:

- Extract HTTP audit and imported traffic record handling next.
- Add bounded retention or compaction for JSONL session logs.
- Add export snapshot and tool registry consistency tests before deeper facade reduction.

### Slice 5: HTTP Audit And Traffic Extraction

Completed:

- Added `mcp/lib/url-surface.js` for URL parsing, first-party host checks, scan URL blocking, and surface/record matching.
- Moved HTTP audit normalization, audit JSONL reads, audit appends, audit summaries, and circuit-breaker summaries into `mcp/lib/http-records.js`.
- Moved imported traffic normalization, HAR-style input parsing, dedupe keys, traffic JSONL reads, traffic summaries, and `bounty_import_http_traffic` implementation into `mcp/lib/http-records.js`.
- Kept tool behavior stable through thin wrappers in `mcp/server.js`.
- Avoided reparsing import input when reporting capped entries.
- Verified there are no stale local HTTP audit or traffic record function bodies left in `mcp/server.js`.
- Ran focused MCP tests and the full test suite after extraction.

Still pending:

- Extract public intel using the shared URL/surface helper.
- Add bounded retention or compaction for JSONL session logs.
- Add export snapshot and tool registry consistency tests before deeper facade reduction.

### Slice 6: Public Intel Extraction

Completed:

- Moved public intel document reads, surface-specific intel summaries, HackerOne handle normalization, bounded fetch helpers, policy/stat/scope extraction, disclosed report parsing, and `bounty_public_intel` implementation into `mcp/lib/public-intel.js`.
- Reused `mcp/lib/url-surface.js` for surface host matching.
- Kept ranking refresh as an injected callback so public intel does not depend on the server facade.
- Preserved the existing public intel tool response shape and fetch header behavior.
- Verified there are no stale local public intel helper function bodies left in `mcp/server.js`.
- Ran focused MCP tests after extraction.

Still pending:

- Split findings, verification, and grading artifact handling.
- Add bounded retention or compaction for JSONL session logs.
- Add export snapshot and tool registry consistency tests before deeper facade reduction.

### Slice 7: Findings, Verification, And Grading Extraction

Completed:

- Moved finding normalization, finding JSONL reads, finding summaries, finding markdown rendering, and finding record/list/read tool implementations into `mcp/lib/findings.js`.
- Moved verification result normalization, verification round validation, verifier markdown rendering, write/read verification tools, and prior-round completeness enforcement into `mcp/lib/findings.js`.
- Moved grade verdict validation, grade markdown rendering, and write/read grade tools into `mcp/lib/findings.js`.
- Preserved sequential finding IDs under the session lock.
- Kept tool schema vocabulary in `mcp/server.js` while moving implementation behind stable imports.
- Verified there are no stale local finding, verification, or grading implementation function bodies left in `mcp/server.js`.
- Ran focused MCP tests after extraction.

Still pending:

- Split ranking and hunter brief assembly.
- Split auth, HTTP scan, temp email, signup, dispatch, and transport near the end.
- Add bounded retention or compaction for JSONL session logs.
- Add export snapshot and tool registry consistency tests before deeper facade reduction.

### Slice 8: Attack Surface And Ranking Extraction

Completed:

- Added `mcp/lib/attack-surface.js` for strict `attack_surface.json` loading and surface ID validation.
- Added `mcp/lib/ranking.js` for priority scoring, ranking reason generation, and explicit/in-memory attack surface ranking.
- Kept read-style ranking non-mutating by preserving the existing `rankAttackSurfaces(domain, { write: false })` behavior.
- Reused extracted traffic and public intel summaries from the ranking module.
- Verified there are no stale local attack-surface loading or ranking function bodies left in `mcp/server.js`.
- Ran focused MCP tests after extraction.

Still pending:

- Split hunter brief assembly and scope exclusion parsing.
- Split auth, HTTP scan, temp email, signup, dispatch, and transport near the end.
- Add bounded retention or compaction for JSONL session logs.
- Add export snapshot and tool registry consistency tests before deeper facade reduction.

### Slice 9: Scope And Hunter Brief Extraction

Completed:

- Added `mcp/lib/scope.js` for scope warning parsing, normalized scope exclusions, and host-filtered exclusion summaries.
- Added `mcp/lib/hunter-brief.js` for bypass table resolution, curated hunter knowledge loading/scoring/bounding, and `bounty_read_hunter_brief` assembly.
- Preserved project/global `.claude` lookup behavior after moving code under `mcp/lib`.
- Kept hunter brief read-style ranking non-mutating.
- Verified there are no stale local scope parsing or hunter brief assembly function bodies left in `mcp/server.js`.
- Ran focused MCP tests after extraction.

Still pending:

- Split auth, HTTP scan, temp email, signup, dispatch, and transport near the end.
- Add bounded retention or compaction for JSONL session logs.
- Add export snapshot and tool registry consistency tests before deeper facade reduction.

### Slice 10: Contract Guardrails And JSONL Retention

Completed:

- Added a public export snapshot test for `mcp/server.js` so future facade changes are intentional.
- Added a tool registry/dispatcher consistency test so every `TOOLS[]` entry has an `executeTool` case and every dispatch case has a schema.
- Added bounded JSONL retention support to `appendJsonlLine`.
- Added batch JSONL append support through `appendJsonlLines` so coverage and imported traffic trim once per batch instead of once per record.
- Wired retention caps into `coverage.jsonl`, `http-audit.jsonl`, and `traffic.jsonl`.
- Added retention regression tests for generic JSONL appends, coverage logs, HTTP audit logs, and imported traffic logs.
- Ran focused MCP tests after adding guardrails and retention.

Still pending:

- Split auth, HTTP scan, temp email, signup, dispatch, and transport near the end.
- Consider a manual compaction tool for existing oversized legacy logs.

### Slice 11: Auth And HTTP Scan Extraction

Completed:

- Added `mcp/lib/auth.js` for auth profile construction, legacy auth migration, session auth path resolution, disk reads, profile storage, manual auth compatibility, and scan-time auth profile lookup.
- Kept the auth profile cache inside the auth module instead of the server facade.
- Added `mcp/lib/http-scan.js` for outbound HTTP scan execution and response analysis.
- Preserved scan audit behavior, URL redaction, auth-missing short-circuit behavior, timeout handling, response modes, body truncation, and analysis output shape.
- Left `mcp/server.js` responsible for tool schema registration, dispatch, and public compatibility exports.
- Verified no stale local `httpScan`, `analyzeResponse`, or direct scan helper references remain in `mcp/server.js`.
- Ran `node --check` for the moved modules and `mcp/server.js`.
- Ran `git diff --check`.
- Ran `npm run test:mcp`: 118 tests passing.

Still pending:

- Split temp email and signup helpers.
- Split dispatch/transport only after the behavior modules are thin and contract tests are in place.
- Consider a manual compaction tool for existing oversized legacy logs.

### Slice 12: Temp Email And Signup Extraction

Completed:

- Added `mcp/lib/temp-email.js` for temporary mailbox creation, polling, extraction, provider fallback, mailbox cache state, provider headers, and verification code/link parsing.
- Added `mcp/lib/signup.js` for signup endpoint probing, CAPTCHA/form/OAuth detection, and optional Patchright-backed auto signup.
- Adjusted the moved auto-signup script lookup so the module under `mcp/lib` still launches `mcp/auto-signup.js`.
- Kept successful auto signup wired to `authStore` so extracted browser credentials still persist as attacker/victim auth profiles.
- Left the public tool schemas, dispatcher cases, and exported function names in `mcp/server.js`.
- Verified no stale local temp-email, signup-detect, or auto-signup function bodies remain in `mcp/server.js`.
- Ran `node --check` for the moved modules and `mcp/server.js`.
- Ran `git diff --check`.
- Ran `npm run test:mcp`: 118 tests passing.

Still pending:

- Split dispatch/transport after deciding whether to keep `mcp/server.js` as the public compatibility facade.
- Consider a manual compaction tool for existing oversized legacy logs.

### Slice 13: Wave And Handoff Orchestration Extraction

Completed:

- Added `mcp/lib/waves.js` for wave start, wave merge, wave readiness, handoff indexing, wave handoff validation, live dead-end logging, legacy session handoff reads/writes, and wave status summaries.
- Kept assignment validation and session locking behavior routed through the existing extracted assignment/session modules.
- Preserved merge requeue behavior, including partial surfaces, missing handoffs, invalid handoffs, and unfinished coverage records.
- Preserved read-style wave status behavior, including non-mutating ranking, finding summaries, HTTP audit summaries, traffic summaries, and circuit-breaker summaries.
- Left `mcp/server.js` responsible for tool schemas, dispatch, transport, and public compatibility exports.
- Removed stale local wave/handoff function bodies from `mcp/server.js`.
- Ran `node --check` for `mcp/lib/waves.js` and `mcp/server.js`.
- Ran `git diff --check`.
- Ran `npm run test:mcp`: 118 tests passing.

Still pending:

- Decide whether to split dispatch/transport or intentionally keep `mcp/server.js` as the stable facade.
- Consider a manual compaction tool for existing oversized legacy logs.

## What Good Looks Like

After the refactor, a developer should be able to answer these questions quickly:

- Where is session state written?
- Which tools mutate artifacts?
- Where is sensitive request data redacted?
- Why did a surface get ranked higher?
- Which module owns coverage requeue behavior?
- Which tests prove prompt/tool contracts still match?

The goal is not to make the system smaller by removing useful features. The goal is to make the useful features safer to change.
