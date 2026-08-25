# Hacker Bob Repo Instructions

This repository is the install source for the Hacker Bob `/bob-evaluate` Claude Code framework.

If a user asks you to install this framework into a project:

1. Clone this repo locally.
2. Run `./install.sh /absolute/path/to/target/project` from the cloned repo.
3. The installer copies the skills, update command shim, agents, rules, hooks, knowledge, bypass tables, MCP runtime, and generated settings. It merges `.mcp.json` and `.claude/settings.json` instead of overwriting unrelated config.
4. After install, run Claude Code from the target project and use `/bob-evaluate <target>` (slash command) or the `bob-evaluate` skill.

Do not assume this cloned repo is the user's active workspace unless they explicitly want that.

Each installed workspace gets its OWN session root — `~/hacker-bob-sessions-<workspace>-<hash>`, derived from the workspace path (stable across re-installs) and written as `BOB_SESSIONS_ROOT` into that workspace's `.mcp.json` server env and `.claude/settings.json` env. Bob elects one engine per session root, so concurrent engines in two workspaces require DISJOINT roots; the root is operator configuration read once at engine boot and frozen there, and no agent or MCP tool can change it. A workspace that was already installed and still has sessions in the shared `~/hacker-bob-sessions/` keeps using it rather than orphaning them — migrate with `mv ~/hacker-bob-sessions/<target-domain> ~/hacker-bob-sessions-<workspace>-<hash>/` (the installer prints the exact path) and re-run the installer. Operator caution: disjoint roots make concurrent ENGINES safe, not concurrent evaluations of the SAME target — rate limits, circuit breakers, and request budgets are per-engine, so two engines on one target double the request volume it sees and neither one knows it.

If the user is developing this framework itself and wants to test changes in a
local Claude Code workspace:

1. Use `./dev-sync.sh /absolute/path/to/test-workspace` from this repo.
2. This script backs up the target `.mcp.json` and `.claude/settings.json`,
   runs the installer, recopies repo-backed MCP files including
   `mcp/tools/*.js`, re-merges the dev config, and runs `claude mcp list`
   unless `--no-health-check` is supplied.
3. It is intended for a dedicated local test workspace because it overwrites
   Bob-owned runtime files after backing up the target MCP/settings files.
4. After `dev-sync.sh`, fully restart Claude Code in the test workspace, run
   `/mcp`, and smoke test `bob_http_scan` with
   `target_domain: "example.com"` against `https://example.com`.

Maintainer workflow:

- Run `npm test` before handing off changes. Useful focused commands are
  `npm run test:mcp`, `npm run test:prompts`, `npm run test:install`, and
  `npm run check:syntax`.
- Generated prompt/config surfaces must stay current. Run
  `node scripts/generate-agent-tools.js` after role-bundle metadata changes and
  `node scripts/generate-hacker-bob-skill.js` after orchestrator/auth bundle
  changes.
- `TOOLS`, MCP dispatch, role-bundle permissions, agent tool frontmatter, skill
  allowed-tools, Claude settings, and scope-hook registration must remain
  registry-driven.
- Correctness-vocabulary tags (S*, I*, C*, X.*, Y-P*, Y-D*, Y-R*) are
  registry-driven via `mcp/core/invariant-registry.js`. Every tag in the tree
  must resolve to a REGISTRY entry (or the frozen, only-shrinking
  `ALLOWLIST_UNDOCUMENTED` backlog), and every entry's `enforced_by`
  file:symbol must exist. The collision-prone S/C/I families are matched only
  in anchored comment form (`// I6`), so a tag's enforcing anchor MUST be a
  comment. `npm run check:invariant-registry` (in `test:prompts`) is the
  orphan-check. Adding a tag means adding its entry AND anchoring the tag at
  the enforcing site.
- Lifecycle hooks enforce contracts only. Evaluator `SubagentStop` validates the
  final marker and structured handoff but must not advance `pending_wave`,
  `evaluation_wave`, `explored`, findings summaries, or phase state.
- Markdown mirrors are human/debug artifacts. Chain evidence is MCP-owned in
  `chain-attempts.jsonl`; `report.md` remains the final human-facing
  agent-composed (via bob_compose_report) report.
- Audit-graded session paths are MCP-rendered (Y-P13). `mcp/core/io/paths.js`
  exports `AUDIT_GRADED_PATHS` (positive list — `report.md`, `chains.md`,
  `evidence-packs.md`, `grade.md`, verification-round mirrors, wave-handoff
  mirrors, claim-freeze snapshots, and the hash-bound JSONL ledgers) and the
  `isAuditGradedPath(absolutePath, target_domain)` predicate. Agents never
  call the Write tool on these paths; structured composition flows through
  `bob_compose_report` (Y-D15b), `bob_write_chain_rollup` (Y-D15c),
  `bob_amend_report` (Y-P13a operator-amendment path), `bob_write_evidence_packs`,
  `bob_write_grade_verdict`, `bob_write_verification_round`, and
  `bob_write_wave_handoff`. Scratch artifacts (`subdomains.txt`,
  `attack_surface.json`, `family_seeds.txt`, `surface-discovery-tools.txt`)
  are explicitly NOT in `AUDIT_GRADED_PATHS` and remain agent-writable.
- Evaluator briefs must stay bounded: array counts are capped, scalar strings are
  capped or omitted, and agents should use auth through `bob_list_auth_profiles`
  rather than reading secret files directly.
