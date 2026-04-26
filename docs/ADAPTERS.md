# Adapter Architecture

Hacker Bob should be packaged as a portable MCP runtime with thin host adapters.
The MCP runtime owns session state, tool schemas, durable artifacts, wave
assignments, handoff validation, findings, verification, grading, and report
inputs. CLI-specific files are adapters around that runtime.

## Runtime Boundary

Portable runtime code lives under `mcp/`. It should not require a specific host
directory like `.claude/` unless that path is an explicit compatibility fallback.
Runtime code should prefer these neutral environment variables:

- `BOB_PROJECT_DIR`: project root where Bob is installed or operating.
- `BOB_RESOURCE_DIR`: root for Bob resources such as knowledge and bypass tables.
- `BOB_CLIENT`: adapter name, for example `claude`, `codex`, or `generic-mcp`.

Claude compatibility remains supported through `CLAUDE_PROJECT_DIR` and existing
legacy `.claude/` resource locations. New installs write canonical Bob resources
under `.hacker-bob/knowledge` and `.hacker-bob/bypass-tables`; adapters should
not create new `.claude/knowledge` or `.claude/bypass-tables` copies.

## Adapter Boundary

Adapters own host-specific packaging and ergonomics:

- Claude adapter: `.claude/commands`, `.claude/skills`, `.claude/agents`,
  `.claude/settings.json`, `.mcp.json`, status line, and Claude hooks.
- Codex adapter: Codex plugin metadata, `$hacker-bob:*` skills, plugin
  command wrappers, `.codex` configuration, repo-local plugin marketplace
  metadata, Codex cache/config activation, and MCP config.
- Generic MCP adapter: MCP server configuration and prompt documentation only.

Adapters may generate files from a shared role and policy model, but generated
host files should not become the source of truth for runtime behavior.

## Capability Rule

Host lifecycle hooks are guardrails, not correctness boundaries. In particular,
Claude `SubagentStop` can keep enforcing the hunter handoff contract, but the
portable runtime must also be able to verify hunter completion through MCP state
and tools so hosts without a matching hook can still run Bob predictably.

The continued implementation graph for this migration is tracked in
[`PLATFORM_TASK_GRAPH.md`](PLATFORM_TASK_GRAPH.md).
