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
- `BOB_CLIENT`: adapter name, for example `claude`, `codex`, `generic-mcp`, or `kimi`.

Claude compatibility remains supported through `CLAUDE_PROJECT_DIR` and existing
legacy `.claude/` resource locations. New installs write canonical Bob resources
under `.hacker-bob/knowledge` and `.hacker-bob/bypass-tables`; adapters should
not create new `.claude/knowledge` or `.claude/bypass-tables` copies.

## Compatibility Policy

Legacy install metadata and resource fallbacks are long-term read compatibility
for projects installed before Bob moved shared state under `.hacker-bob/`.
Adapter stale-file pruning is also intentional reinstall hygiene: when Bob
renames a command, skill, plugin file, or generated role, reinstall should remove
the previously managed path instead of leaving two host-visible entrypoints.

Do not add new legacy paths unless they correspond to a shipped Bob version. A
legacy path may be removed only in a major-version migration after the installer,
doctor, and release notes document that old workspaces must reinstall from a
fresh adapter surface.

## Adapter Boundary

Adapters own host-specific packaging and ergonomics:

- Claude adapter: `.claude/commands`, `.claude/skills`, `.claude/agents`,
  `.claude/settings.json`, `.mcp.json`, status line, and Claude hooks.
- Codex adapter: direct `$bob-*` skills in `~/.codex/skills`, Codex plugin
  metadata, plugin command wrappers, `.codex` configuration, repo-local plugin
  marketplace metadata, Codex cache/config activation, and MCP config.
- Kimi adapter: `.kimi/skills`, `.kimi/mcp.json`, and `.kimi/bob`
  compatibility metadata. Kimi skills are invoked as `/skill:bob-evaluate`,
  `/skill:bob-status`, `/skill:bob-debug`, `/skill:bob-update`,
  `/skill:bob-export`, and `/skill:bob-egress`. The Kimi adapter does not
  install PreToolUse hooks; session enforcement currently relies on prompt
  discipline plus MCP-side validation, matching the Codex adapter's model.
  Kimi hook source files live under `adapters/kimi/hooks/` for a future PR
  that wires them via `~/.kimi/config.toml`.
- Generic MCP adapter: MCP server configuration and prompt documentation only.

Adapters may generate files from a shared role and policy model, but generated
host files should not become the source of truth for runtime behavior.

Shared role prompts must stay semantic. They may define Bob roles, phase
ordering, handoff contracts, and MCP artifact rules, but host launch mechanics
belong to adapters. The orchestrator prompt uses launch placeholders such as
`{{SPAWN_EVALUATOR_AGENT}}`; the Claude renderer fills those with Claude named
subagent calls, while the Codex renderer fills them with Codex worker-agent
spawn instructions.

Codex does not have Bob-specific named subagents. In Codex, `evaluator-agent`,
`surface-discovery-agent`, `grader`, and similar names are Bob logical roles rendered into
`worker` agent prompts. Durable identity remains in MCP state through `wN`,
`aN`, `surface_id`, and `handoff_token`; Codex host agent IDs and UI nicknames
are execution metadata only.

## Capability Rule

Host lifecycle hooks are guardrails, not correctness boundaries. In particular,
Claude `SubagentStop` can keep enforcing the evaluator handoff contract, but the
portable runtime must also be able to verify evaluator completion through MCP state
and tools so hosts without a matching hook can still run Bob predictably.

Longer-running platform work is tracked in the roadmap and release notes rather
than through adapter-owned host files.
