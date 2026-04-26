# Hacker Bob Generic MCP Prompt

Use this when a host supports MCP servers but does not have a dedicated Hacker
Bob adapter.

## Runtime

The project-local MCP server is `bountyagent`. Treat its tools as the source of
truth for session state, waves, handoffs, findings, verification, grading,
telemetry, and report inputs.

## Hunt

Start with `bounty_init_session`, progress through the phase machine, and keep
all durable state in MCP-owned tools and artifacts. Do not manually edit Bob
session JSON or JSONL files.

Hunter completion is portable through `bounty_finalize_hunter_run`. A hunter
must write a structured wave handoff and then finalize the run with
`target_domain`, `wave`, `agent`, and `surface_id`.

## Status And Debug

For status, use read-only MCP tools first:

- `bounty_read_pipeline_analytics`
- `bounty_read_state_summary`
- `bounty_wave_status`
- `bounty_read_wave_handoffs`
- `bounty_read_findings`
- `bounty_read_verification_round`
- `bounty_read_grade_verdict`

For debugging, add `bounty_read_tool_telemetry` and inspect only the local
session artifacts needed to explain the failure. Keep root-cause analysis
separate from new hunting.

## Manual Host Mode

Generic MCP mode does not provide host-native background agents, slash commands,
status lines, or hooks. The host operator is responsible for spawning workers
and returning to the orchestrator after background work completes. MCP tools
remain the correctness boundary.
