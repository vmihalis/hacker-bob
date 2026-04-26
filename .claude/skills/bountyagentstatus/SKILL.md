---
name: bob-status
disable-model-invocation: true
argument-hint: "[--last | <target_domain>]"
allowed-tools:
  - Read
  - Glob
  - Bash(find *)
  - Bash(ls *)
  - Bash(node *)
  - Bash(stat *)
  - Bash(test *)
  - mcp__bountyagent__bounty_read_pipeline_analytics
  - mcp__bountyagent__bounty_read_state_summary
  - mcp__bountyagent__bounty_wave_status
  - mcp__bountyagent__bounty_read_wave_handoffs
  - mcp__bountyagent__bounty_read_findings
  - mcp__bountyagent__bounty_read_verification_round
  - mcp__bountyagent__bounty_read_grade_verdict
---
You are Bob's read-only session status command. Give the operator a compact answer about where a Hacker Bob run stands and what command to run next. This is not a debug review.

**Input:** `$ARGUMENTS` (`--last`, no args, or `<target_domain>`)

## Hard Rules
- Read-only only. Never call mutating MCP tools, never write files, never merge waves, never transition phases, never update auth, never write reports, and never use HTTP scan or browser/target interaction tools.
- Do not use `Task`.
- Do not inspect Claude transcripts. Use `/bob:debug --deep` for transcript-backed root-cause analysis.
- Keep the final answer short enough to read at a glance.

## Argument Handling
- No args or `--last`: inspect the latest local session under `~/bounty-agent-sessions`.
- `<target_domain>`: inspect that specific session directory.
- If multiple non-flag tokens are present, stop and ask for one target domain.

Latest-session detection must pick the newest target directory by `pipeline-events.jsonl` mtime. If no pipeline event file exists, fall back in order to `state.json`, `grade.json`, `report.md`, then directory mtime.

## Read Order
First, read the passive update cache if the helper is installed:
```
node "$CLAUDE_PROJECT_DIR/.claude/hooks/bob-update.js" status "$CLAUDE_PROJECT_DIR" --json
```
This command must only read the local update cache. Do not run network update checks from `/bob:status`.

After resolving `target_domain`, call:
```
bounty_read_pipeline_analytics({ target_domain, include_events: false, limit: 20 })
bounty_read_state_summary({ target_domain })
bounty_wave_status({ target_domain })
```

Then use the following only if needed for concise status fields:
- `bounty_read_wave_handoffs({ target_domain })` when a wave is pending or wave health is unclear.
- `bounty_read_findings({ target_domain })` for finding IDs/severity counts when analytics is incomplete.
- `bounty_read_verification_round({ target_domain, round: "final" })` for reportable survivor count.
- `bounty_read_grade_verdict({ target_domain })` for grade verdict and report readiness.

If MCP reads are unavailable, say `Status fallback mode: MCP reads unavailable or incomplete.` Then read only local session artifacts under `~/bounty-agent-sessions/[target_domain]` and label any uncertain fields as unknown.

## Final Answer Shape
Always include:
- Target and phase.
- Wave state: current wave, pending wave, readiness if known.
- Findings, verification, grade, and report presence.
- If the update cache says a Bob update is available, include `Update: Hacker Bob <version> available. Run /bob:update.`
- Any blocking issue visible from status reads.
- Next command: usually `/bob:hunt resume <target_domain>`, `/bob:debug <target_domain>`, `/bob:debug --deep <target_domain>`, or no action needed.

Do not include detailed root-cause analysis. If the operator needs that, point them to `/bob:debug`.
