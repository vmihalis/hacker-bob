# Hacker Bob Generic MCP Prompt

Use this when a host supports MCP servers but does not have a dedicated Hacker
Bob adapter.

## Runtime

The project-local MCP server is `hacker-bob`. Treat its tools as the source of
truth for session state, waves, handoffs, findings, verification, grading,
telemetry, and report inputs.

## Evaluation

`bob_advance_session(to_state)` is the canonical lifecycle tool. The session
moves through six explicit states: `SETUP`, `OPEN_FRONTIER`, `CLAIM_FREEZE`,
`VERIFY`, `GRADE`, `REPORT`. Each state has hard entry conditions enforced by
the MCP runtime; advance only when the prerequisite ledgers are populated. Keep
all durable state in MCP-owned tools and artifacts and do not manually edit Bob
session JSON or JSONL files.

### Six-state operator runbook

1. `SETUP` — call `bob_init_session` with `target_domain`, `target_url`, and
   the egress/policy parameters. The runtime writes the session nucleus and
   binds scope. Stage authorization material with `bob_list_auth_profiles`
   and the auth-import tools before advancing.
2. `OPEN_FRONTIER` — call
   `bob_advance_session(target_domain, to_state: "OPEN_FRONTIER")`, then expand
   the frontier through `bob_record_surface_leads`,
   `bob_promote_surface_leads`, `bob_build_surface_graph`,
   `bob_materialize_frontier`, and the scheduling verbs
   (`bob_start_next_wave` / `bob_start_wave` /
   `bob_apply_wave_merge`). Evaluator agents record claims with
   `bob_record_candidate_claim` and finalize their runs with
   `bob_finalize_agent_run`.
3. `CLAIM_FREEZE` — call
   `bob_advance_session(target_domain, to_state: "CLAIM_FREEZE")` to freeze the
   current claim batch into an immutable artifact. Read the freeze through
   `bob_read_candidate_claims` and the state summary tools; do not append new claims
   to a frozen batch. Re-enter `OPEN_FRONTIER` from any later state if the
   frontier needs more work.
4. `VERIFY` — call
   `bob_advance_session(target_domain, to_state: "VERIFY")`, then drive
   verification rounds with `bob_write_verification_round` and read results
   through `bob_read_verification_round` and
   `bob_read_verification_context`. Verification operates on the frozen
   claim batch only.
5. `GRADE` — call `bob_advance_session(target_domain, to_state: "GRADE")` and
   record the grade verdict with `bob_write_grade_verdict`. Read the verdict
   back through `bob_read_grade_verdict`. Severity must match the verified
   impact recorded in the verification rounds.
6. `REPORT` — call `bob_advance_session(target_domain, to_state: "REPORT")`,
   compose `report.md`, and finalize the report through the report tool
   (`bounty_report_written` during the deprecation window). The runtime binds
   the report to the frozen claim batch, the final verification, the evidence
   pack hash, and the grade verdict.

For session-bound tools, treat `target_domain` as a session selector, not proof
of authorization. The MCP runtime binds calls to initialized session state and
blocks raw target or target URL drift before handlers run. If an authority error
is returned, stop and use the error details or status/debug readers rather than
editing session files. Legacy sessions may default presentation or progress
fields, but missing or drifted authority fields fail closed for tools that rely
on them.

Evaluator completion is portable through `bob_finalize_agent_run`. A evaluator
must write a structured wave handoff and then finalize the run with
`target_domain`, `wave`, `agent`, and `surface_id`.

## Status And Debug

For status, use read-only MCP tools first:

- `bob_read_pipeline_analytics`
- `bob_read_state_summary`
- `bob_wave_status`
- `bob_read_wave_handoffs`
- `bob_read_candidate_claims`
- `bob_read_verification_round`
- `bob_read_grade_verdict`

For debugging, add `bob_read_tool_telemetry` and inspect only the local
session artifacts needed to explain the failure. Keep root-cause analysis
separate from new evaluating.

## Manual Host Mode

Generic MCP mode does not provide host-native background agents, slash commands,
status lines, or hooks. The host operator is responsible for spawning workers
and returning to the orchestrator after background work completes. MCP tools
remain the correctness boundary.
