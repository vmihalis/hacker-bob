# Changelog

## [1.1.4] - 2026-04-27

- Fixed the installer to copy the shipped `testing/policy-replay/` harness into target projects so `/bob-debug` replay escalation can run from installed workspaces.
- Added doctor and install-smoke coverage for the policy replay harness files.

## [1.1.3] - 2026-04-27

- Added a shipped `testing/policy-replay/` harness for diagnosing Bob policy/refusal regressions with the Claude Agent SDK and local Claude OAuth.
- Updated `/bob-debug` so post-session QA can detect policy/refusal stuck signals, run bounded local replay/tune diagnostics, and suggest a reviewed prompt change without editing prompts or mutating session state.
- Added structured chain-attempt artifacts and read/write MCP tools so CHAIN, VERIFY, GRADE, REPORT, analytics, and hooks consume machine-readable chain evidence instead of markdown.
- Added CI-safe policy replay tests, package coverage for the replay harness, and release packaging of the harness scripts and sample fixture.
- Deprecated the older raw Anthropic API refusal replay helpers in favor of the maintained policy replay case format.

## [1.1.2] - 2026-04-26

- Renamed the three skill directories and frontmatter `name:` fields to hyphen form (`bob-hunt`, `bob-status`, `bob-debug`). v1.1.1 used colon-form `name:` (`bob:hunt`), which Claude Code v2.1.119 rejects as invalid (`name:` only accepts lowercase letters, numbers, and hyphens), so it silently fell back to the directory name and registered the slashes as `/bountyagent`, `/bountyagentstatus`, `/bountyagentdebug` — meaning typing `/bob:hunt` got rewritten to `/bountyagent` on enter.
- Renamed `/bob:update` to `/bob-update` and moved the command from `.claude/commands/bob/update.md` to `.claude/commands/bob-update.md` so all four slash commands share the same hyphen scheme.
- Installer and `dev-sync.sh` now proactively delete the legacy `bountyagent`, `bountyagentstatus`, `bountyagentdebug` skill directories and the entire `commands/bob/` subdirectory on upgrade, so users coming from `<=1.1.1` do not keep orphan slash entries.
- Uninstall manifest sweeps the new layout, the v1.1.1 layout, and the v1.1.0 layout so old installs still clean up entirely.
- Updated README, CLAUDE.md, FIRST_RUN, ROADMAP, TROUBLESHOOTING, and media docs to use the new `/bob-hunt`, `/bob-status`, `/bob-debug`, `/bob-update` slashes.

## [1.1.1] - 2026-04-25

- Fixed duplicate slash entries (`/bob-hunt` + `/bob:hunt`, etc.) in the Claude Code menu by giving the three skills colon-form `name:` frontmatter (`bob:hunt`, `bob:status`, `bob:debug`) so each skill IS its own slash command.
- Removed redundant command shims `commands/bob/{hunt,status,debug}.md`; only `commands/bob/update.md` remains because no skill backs `/bob:update`.
- Installer and `dev-sync.sh` now proactively delete the legacy hunt/status/debug shims on upgrade so users coming from <=1.1.0 do not retain orphan files that would re-introduce the duplicates.
- Uninstall manifest sweeps both the current shim layout and the legacy three-shim layout so old installs still clean up entirely.

## [1.1.0] - 2026-04-26

- Added `hacker-bob doctor <project-dir> [--json]` for read-only install diagnostics.
- Added `hacker-bob uninstall <project-dir> [--dry-run] [--yes] [--json]` for conservative removal of Bob-managed files and config entries.
- Added the `hacker-bob` npm alias package while keeping `hacker-bob-cc` canonical.
- Updated release publishing to publish both npm packages with provenance.
- Added Quickstart, troubleshooting docs, release notes, and bug report diagnostics guidance.
- Optimized the README image to reduce npm package size.

## [1.0.1] - 2026-04-26

- Clarified install docs and CLI help: Bob installs into one project directory per command, while global npm install only installs the `hacker-bob` CLI.

## [1.0.0] - 2026-04-26

- Initial public `hacker-bob-cc` npm package with `hacker-bob` CLI install and update commands.
- Added `/bob:update`, passive update cache checks, installed version metadata, and status update hints.
- Preserved the source `install.sh` path as a compatibility wrapper.
