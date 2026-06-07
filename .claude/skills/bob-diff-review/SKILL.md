---
skill: bob-diff-review
name: bob-diff-review
description: >
  Headless Bob diff-review pipeline — invoked by bob-runner.ts via
  'claude --dangerously-skip-permissions --print "/bob-diff-review -- ..."'.
  Ingests a unified diff, initializes a Bob repo session, builds the symbol
  surface index, maps changed hunks to impacted surfaces, spawns per-surface
  evaluator agents, and serializes findings to diff-review-findings.json.
  Do not invoke interactively; use /bob-evaluate for interactive sessions.
disable-model-invocation: false
argument-hint: "--repo <abs-path> --diff-file <path> [--target-domain-override <string>] [--output-dir <path>]"
allowed-tools:
  - Read
  - Write
  - Bash(node *)
  - Bash(find *)
  - Bash(ls *)
  - Bash(cat *)
  - Task
  - mcp__hacker-bob__bob_init_repo_session
  - mcp__hacker-bob__bob_repo_inventory
  - mcp__hacker-bob__bob_extract_routes
  - mcp__hacker-bob__bob_build_symbol_surface_index
  - mcp__hacker-bob__bob_summarize_diff_impact
  - mcp__hacker-bob__bob_build_surface_graph
  - mcp__hacker-bob__bob_promote_surface_leads
  - mcp__hacker-bob__bob_record_candidate_claim
  - mcp__hacker-bob__bob_finalize_node
  - mcp__hacker-bob__bob_write_handoff
  - mcp__hacker-bob__bob_read_session_state
  - mcp__hacker-bob__bob_read_state_summary
  - mcp__hacker-bob__bob_advance_session
  - mcp__hacker-bob__bob_read_candidate_claims
  - mcp__hacker-bob__bob_read_surface_leads
  - mcp__hacker-bob__bob_record_surface_leads
  - mcp__hacker-bob__bob_query_surface_graph
  - mcp__hacker-bob__bob_read_session_nucleus
  - mcp__hacker-bob__bob_read_assignment_brief
  - mcp__hacker-bob__bob_log_coverage
  - mcp__hacker-bob__bob_append_frontier_event
  - mcp__hacker-bob__bob_propose_hypothesis
  - mcp__hacker-bob__bob_propose_transition
  - mcp__hacker-bob__bob_attach_contract
  - mcp__hacker-bob__bob_append_chain_node
  - mcp__hacker-bob__bob_query_chain_tree
  - mcp__hacker-bob__bob_write_chain_attempt
  - mcp__hacker-bob__bob_read_chain_attempts
  - mcp__hacker-bob__bob_read_verification_round
  - mcp__hacker-bob__bob_start_next_wave
  - mcp__hacker-bob__bob_start_wave
  - mcp__hacker-bob__bob_wave_status
  - mcp__hacker-bob__bob_apply_wave_merge
  - mcp__hacker-bob__bob_write_wave_handoff
  - mcp__hacker-bob__bob_finalize_agent_run
  - mcp__hacker-bob__bob_log_technique_attempt
  - mcp__hacker-bob__bob_read_technique_pack
  - mcp__hacker-bob__bob_select_technique_packs
  - mcp__hacker-bob__bob_get_context_budget
  - mcp__hacker-bob__bob_read_pipeline_analytics
  - mcp__hacker-bob__bob_read_wave_handoffs
  - mcp__hacker-bob__bob_log_dead_ends
  - mcp__hacker-bob__bob_log_protocol_drift
  - mcp__hacker-bob__bob_emit_runtime_drift
---

You are the **bob-diff-review** pipeline orchestrator. You run headlessly,
invoked by `bob-runner.ts`. Parse `$ARGUMENTS`, execute the S2-S6 pipeline
steps in order, and write `diff-review-findings.json` to `--output-dir`.

## Environment Requirements

The runner environment MUST supply:
- Exactly one Anthropic credential injected by the runner — see
  [Authentication](#authentication). The runner spawns this skill inside an
  already-authenticated `claude` subprocess, so the skill inherits whichever
  credential the runner chose (`CLAUDE_CODE_OAUTH_TOKEN` preferred, or
  `ANTHROPIC_API_KEY` fallback). The skill does not select auth itself.
- `BOB_INSTALL_TOKEN` — GitHub App installation token or fine-grained PAT with
  `read:packages` + `contents:read` scopes (org-level secret `BOB_INSTALL_TOKEN`,
  mapped to `NODE_AUTH_TOKEN` for npm registry auth). Required for resolving
  private `@bobnetsec/*` packages during the action run.

No credential value must appear in any log or output file. Confirm presence
only, e.g.:
`if [ -n "$CLAUDE_CODE_OAUTH_TOKEN" ] || [ -n "$ANTHROPIC_API_KEY" ]; then echo present; fi`.

## Authentication

bob-diff-review supports **dual auth** for the headless `claude` subprocess:
OAuth-token auth (preferred) and API-key auth (fallback). The runner injects
**exactly one** credential into the child environment with deterministic
precedence — OAuth wins and the API key is never injected alongside it.

| Credential | Env var the CLI reads | Action input | Workflow secret |
|---|---|---|---|
| OAuth token (preferred, from `claude setup-token`) | `CLAUDE_CODE_OAUTH_TOKEN` | `anthropic-oauth-token` | `ANTHROPIC_OAUTH_TOKEN` |
| API key (pay-per-use fallback) | `ANTHROPIC_API_KEY` | `anthropic-api-key` | `ANTHROPIC_API_KEY` |

Runner precedence (single injection, OAuth wins):

- If an OAuth token is present, the runner sets `CLAUDE_CODE_OAUTH_TOKEN` and
  **does not set** `ANTHROPIC_API_KEY` at all. This prevents the API key from
  silently shadowing OAuth and exhausting credits.
- Otherwise (only the API key is present), the runner sets `ANTHROPIC_API_KEY`
  and does not set the OAuth var.
- Exactly one credential is injected, never both.

Action input and workflow contract:

- `action.yml` exposes `anthropic-oauth-token` (optional) and
  `anthropic-api-key` (optional). At least one must be provided; if neither is,
  the action fails fast with an error naming both inputs and recommending OAuth.
  `anthropic-api-key` is no longer `required: true`.
- The workflow (`bob-review.yml`) and any caller declare both secrets as
  optional with at least one required, and pass them through to the action's
  `with:` block as `anthropic-oauth-token` and `anthropic-api-key`.
- The existing `ANTHROPIC_MODEL` passthrough behavior is unchanged.

This skill runs inside the already-authenticated subprocess and inherits
whichever credential the runner injected; it never selects or reads the
credential value, and never echoes either credential.

## Headless Invocation (from bob-runner.ts)

```bash
claude --dangerously-skip-permissions --print \
  "/bob-diff-review --repo $REPO --diff-file $DIFF_FILE --target-domain-override $TARGET_DOMAIN --output-dir $OUTPUT_DIR"
```

Paths that contain spaces must be quoted. `bob-runner.ts` is responsible for
quoting before exec.

## Arguments

| Flag | Required | Description |
|------|----------|-------------|
| `--repo` | Yes | Absolute path to the locally checked-out repository. Must be an existing directory. Refuses remote shapes (`git@`, `git+`, `ssh://`, bare slugs). |
| `--diff-file` | Yes | Path to a unified diff file (output of `git diff base...head`). The pipeline reads the full text from this file. |
| `--target-domain-override` | No | GitHub context slug (e.g. `gh-<repository_id>`) stamped into `diff-review-findings.json` for traceability. NOT used for the Bob session: the MCP authority requires the server-derived `repo-<safeName>-<sha8>` slug, so the session domain always comes from `bob_init_repo_session`'s result. |
| `--output-dir` | No | Directory where `diff-review-findings.json` is written. Defaults to `$RUNNER_TEMP/bob-diff-review` when running inside GitHub Actions, or a temp directory otherwise. |

## Pipeline Steps (S2-S6)

Execute the following steps in order. Each step is gated on the previous step
succeeding. Log each step start and completion to stdout.

### S2 — Session init + inventory

1. Read `--repo` and resolve it to an absolute path. Refuse if the path does
   not exist, is not a directory, or looks like a remote ref (`git@`, `git+`,
   `ssh://`, bare `owner/repo` slugs). Surface the refusal as a structured JSON
   error and stop the pipeline.
2. Call `bob_init_repo_session({ repo_path, deep_mode: false,
   egress_profile: "default" })`.
   **Do NOT pass a `target_domain` override.** The MCP repo-session authority
   requires the server-derived `repo-<safeName>-<sha8>` slug and rejects any
   other value (e.g. a `gh-<id>` slug) with `normalization_failed`. Omit
   `target_domain` so the server derives it, then read the derived slug from
   `result.data.target_domain` and use THAT value as `<target_domain>` for every
   subsequent S2–S6 MCP call. `result.data.created === false` means the C2 cache
   restored an existing session (resume); the server merges existing state either
   way, so calling init is always safe. Surface any structured error
   (`repo_path_not_found`, `repo_path_not_directory`, `session_corrupt`) as a JSON
   object on stdout and stop.
   Note: the `--target-domain-override` argument is GitHub context for the
   findings file only — the runner stamps it into `diff-review-findings.json`.
   Never pass it to the MCP repo-session tools.
3. Verify `bob_read_session_nucleus({ target_domain })` returns successfully
   (using the derived `<target_domain>` from step 2). This confirms the session
   nucleus was written to MCP state and is readable before proceeding.
4. Call `bob_repo_inventory({ target_domain })` to walk the repo and emit
   `surface.observed` events (writes `repo-inventory.json` to the session dir).
   Stop if inventory returns zero files or an error; surface the failure as a
   structured JSON error.
5. Log `S2: init ok — <N> files inventoried, is_resume=<bool>` on success.

### S3 — Route extraction + symbol surface index (conditional on cache miss)

Check whether `SKIP_SURFACE_BUILD=true` is set in the runner environment or
whether `symbol-surface-index.json` already exists in the session directory
(`result.data.session_dir` from the S2 init result, restored from cache). If
either condition holds, log exactly:

```
CACHE HIT: skipping index build
```

and skip to S4.

Otherwise:
1. Call `bob_extract_routes({ target_domain })` to extract API routes, entry
   points, and call-graph edges from the repository source.  Log the route
   count on success.
2. Call `bob_build_symbol_surface_index({ target_domain })` to construct the
   indexed symbol-to-surface mapping used by diff impact analysis.  On success
   log the surface count, e.g.:
   `[S3] symbol index built: <N> surface(s), <M> symbol(s)`

Log `S3: surface index built` after both calls succeed. If either call fails,
log the error loudly (including the structured JSON from `formatS3FailureJson`)
and proceed to S4b (PATH B fallback).

### S4 — Diff impact analysis (PATH A)

Read the unified diff text from `--diff-file`. Call
`bob_summarize_diff_impact({ target_domain, diff_text })` with the full diff
text. On success the tool writes `diff-impact.json` to the session directory
(MCP-owned; do not write it via the Write tool). Use
`result.data.impacted_entries` — the list of `{file, line_start, line_end,
surface_ids[], hunk_summary}` objects — as the authoritative surface dispatch
list. Log `S4 PATH A: N impacted entries from symbol index`.

**PATH B fallback:** If `bob_summarize_diff_impact` is unavailable or returns
an error, activate PATH B heuristic dispatch. Log loudly:
`PATH B: heuristic dispatch (no symbol index)`. Map changed file paths to
surface IDs using the following pattern table:

| Path pattern | surface_id prefix |
|---|---|
| `auth/*`, `*/auth/*`, `*login*`, `*session*` | `heuristic:authentication` |
| `routes/*`, `*/routes/*`, `*/api/*`, `*controller*` | `heuristic:api-route` |
| `contracts/*`, `*/contracts/*`, `*.sol`, `*.move` | `heuristic:smart-contract` |
| `admin/*`, `*/admin/*` | `heuristic:admin` |
| (no match) | `heuristic:unknown` |

Cap `heuristic:unknown` dispatches at 5 per run to avoid flooding S5. Produce
the same `impacted_entries` schema as PATH A.

### S5 — Evaluator agents (background, per impacted surface)

For each unique `surface_id` in `impacted_entries`, spawn a background evaluator
agent scoped to that surface. Use `bob_start_next_wave` / `bob_start_wave` per
the standard Bob orchestrator wave contract. Each agent receives:

- `surface_id`
- The diff hunks relevant to that surface (`file`, `line_start`, `line_end`,
  `hunk_summary`)
- `target_domain`
- The session's `egress_profile` and `block_internal_hosts` effective values

Agents follow the standard Bob evaluator loop: hypothesize, probe surfaces
through MCP tools, call `bob_record_candidate_claim` for any confirmed finding,
write a wave handoff via `bob_write_wave_handoff`, and finalize via
`bob_finalize_agent_run`. After all background agents complete, settle the wave
via `bob_apply_wave_merge`.

Call `bob_build_surface_graph({ target_domain })` after the wave settles to
materialize cross-surface relationships into the session graph. Call
`bob_promote_surface_leads({ target_domain })` to elevate high-score leads into
the next dispatch cycle if additional evaluator waves are warranted.

### S6 — Findings serialization

1. Call `bob_read_candidate_claims({ target_domain })` to read all recorded
   claims from the session.
2. Join claims with `impacted_entries` on `surface_id` to produce per-file,
   per-line-range annotations.
3. Write `diff-review-findings.json` to `--output-dir` (create the directory
   if absent). Use the following top-level schema:

```json
{
  "schema_version": 1,
  "target_domain": "<string>",
  "run_id": "<string>",
  "findings": [
    {
      "claim_id": "<string>",
      "severity": "<critical|high|medium|low|info>",
      "title": "<string>",
      "surface_id": "<string>",
      "file": "<string>",
      "line_start": <number>,
      "line_end": <number>,
      "hunk_summary": "<string>",
      "description": "<string>",
      "proof": "<string>"
    }
  ]
}
```

4. Call `bob_finalize_node({ target_domain })` to close the session node and
   mark the diff-review run complete in the Bob session ledger.
5. Write the handoff record via `bob_write_handoff({ target_domain, ... })` so
   downstream action steps (resolver.ts, comment-poster) can read session
   metadata without re-initializing a Bob session.

Log `S6: N findings written to <output-dir>/diff-review-findings.json` and exit
cleanly (exit code 0). Exit with a non-zero code only when a hard error
prevents any output from being produced.

## Hard Rules

- Never clone remote repositories. `--repo` must be a pre-checked-out local
  path. Refuse any value that looks like `git@`, `git+`, `ssh://`, or a bare
  `owner/repo` slug.
- Never write to Bob MCP-owned audit-graded artifacts (`report.md`, `chains.md`,
  `evidence-packs.md`, `grade.md`, JSONL ledgers) via the Write tool. All
  structured state flows through the MCP tools listed in `allowed-tools`.
- Do not echo any Anthropic credential (`CLAUDE_CODE_OAUTH_TOKEN` or
  `ANTHROPIC_API_KEY`) or `BOB_INSTALL_TOKEN` values in any log, output file, or
  tool call argument. The runner injects exactly one Anthropic credential
  (OAuth preferred, API key fallback); the skill inherits it via env and must
  never read or surface its value.
- Exit non-zero only on unrecoverable errors. PATH B fallback and partial
  surface coverage are degraded but non-fatal outcomes; write whatever findings
  were produced and exit 0 with a warning summary.
- `bob_finalize_node` and `bob_write_handoff` must be called even when zero
  findings are produced so that the downstream resolver and comment-poster steps
  can read a well-formed (empty) output.
