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
- Kimi adapter: `.kimi/skills`, `.kimi/hooks`, `.kimi/mcp.json`, and `.kimi/bob`
  compatibility metadata. Kimi skills are invoked as `/skill:bob-evaluate`,
  `/skill:bob-status`, `/skill:bob-debug`, `/skill:bob-update`,
  `/skill:bob-export`, and `/skill:bob-egress`. The Kimi adapter installs the
  PreToolUse guard scripts under `.kimi/hooks/` (with the executable bit and the
  generated `write-guard-tables.json` allow/deny manifest) and registers them in
  `~/.kimi/config.toml` as a sentinel-fenced `[[hooks]]` block (honoring
  `KIMI_SHARE_DIR`, merge-not-clobber with operator hooks). This wiring is
  best-effort: the Kimi tool-name strings and PreToolUse payload shape are not
  pinned to a Kimi CLI version, so enforcement is present-but-unverified rather
  than hard Y-P13. The write-guard emits a loud stderr warning (then allows) when
  it receives a payload it cannot parse, so a fail-open is visible. `doctor`
  always surfaces a `kimi_hook_best_effort` warning telling operators to verify a
  real blocked write against their Kimi CLI version.
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

## Audit-graded enforcement trust boundary (R-HOST)

Y-P13 (audit-graded paths are MCP-write-only) has two enforcement layers with
different reach:

- **In-process (MCP server).** `mcp/lib/tools/_write-base.js` and
  `mcp/lib/belief/authority.js` gate the server's OWN writes — the report / grade /
  chain-rollup / evidence / verification-round / wave-handoff / proof-bundle /
  amend composers and belief artifacts — against `paths.js` `isAuditGradedPath`.
  `scripts/check-audit-graded-writers.js` anchors the composer whitelist to the
  writers' actual audit-graded paths (ground truth, not a self-referential flag).
  This layer is fail-closed and host-independent.
- **External (PreToolUse hook).** The agent's own `Write`/`Bash` tools run in a
  separate process from the MCP server, which cannot intercept them. Only the
  PreToolUse `session-write-guard.sh` — whose allow/deny is generated from
  `AUDIT_GRADED_PATHS` (`scripts/generate-write-guard-tables.js`, gated by
  `check:write-guard-tables`; full session-root coverage gated by
  `check:mcp-owned-basename-inventory`) — blocks an agent from directly writing an
  audit-graded path.

**Irreducible host-trust assumption (R-HOST).** Because the server cannot see the
harness's own tools, audit-graded enforcement for AGENT writes depends entirely on
the host honoring PreToolUse hooks. A host that strips or ignores them loses Y-P13
for agent writes; the in-process gate does not and cannot back-fill that. Full
Y-P13 requires a host that runs PreToolUse hooks. Per adapter: **Claude** registers
the guards via `.claude/settings.json` (hard); **Kimi** registers via
`~/.kimi/config.toml` but best-effort (unverified tool-name/payload shape — the
guard loud-warns then allows on an unrecognized payload, and `doctor` surfaces
`kimi_hook_best_effort`); **Codex** has no PreToolUse guard and relies on MCP-side
authority validation; **generic-mcp** has MCP-side validation only.

### Session-authority enforcement mode

`BOB_SESSION_AUTHORITY_MODE=shadow` downgrades session-authority failures ONLY for
the narrow legitimate case of a missing-session READ-ONLY block. It is not a
general escape hatch: a mutating session write under shadow is REFUSED
(`STATE_CONFLICT` / `enforcement_degraded_unacked`, plus a runtime-drift record)
unless the operator explicitly sets `BOB_SESSION_AUTHORITY_SHADOW_ACK`, which
stamps `operator_ack` on the audit-graded decision. Unset (the default) is
`enforce`. The ack token is single-homed in `mcp/lib/enforcement-attest.js`
(asserted by `test/enforcement-liveness-attest.test.js`).

Longer-running platform work is tracked in the roadmap and release notes rather
than through adapter-owned host files.
