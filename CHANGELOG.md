# Changelog

## [1.1.2] - 2026-04-26

- Renamed the Claude adapter skill directories to hyphen form (`bob-hunt`, `bob-status`, `bob-debug`) so Claude Code registers the same names shown in `name:` frontmatter.
- Renamed the Claude update command from `/bob:update` to `/bob-update` and moved the source file to `.claude/commands/bob-update.md`.
- Added installer, dev-sync, and uninstall cleanup for legacy Claude `commands/bob/*` shims and `bountyagent*` skill directories.
- Updated Claude docs and generated prompts to use `/bob-hunt`, `/bob-status`, `/bob-debug`, and `/bob-update`.
- Switched Codex to direct `$bob-hunt`, `$bob-status`, `$bob-debug`, and `$bob-update` skills in `~/.codex/skills`; the Codex plugin now handles MCP wiring only and installer cleanup removes deprecated plugin-scoped skill copies.
- Normalized the canonical package, compatibility package, Codex plugin manifest, and installed metadata to `1.1.2` version semantics.

## [1.1.1] - 2026-04-25

- Removed the redundant Claude hunt/status/debug command-shim approach from the release line after duplicate slash menu entries were reported.
- Added upgrade cleanup for the old Claude command shim files so stale slash entries do not survive installs.
- Superseded by `1.1.2` because Claude Code rejects colon-form skill `name:` values.

## [1.1.0] - 2026-04-26

- Added `hacker-bob doctor <project-dir> [--json]` for read-only install diagnostics.
- Added `hacker-bob uninstall <project-dir> [--dry-run] [--yes] [--json]` for conservative removal of Bob-managed files and config entries.
- Added host adapter selection with `--adapter claude|codex|generic-mcp|all`.
- Made `hacker-bob` the canonical npm package and kept `hacker-bob-cc` as a compatibility wrapper.
- Updated release publishing to publish both npm packages with provenance.
- Added Quickstart, troubleshooting docs, release notes, and bug report diagnostics guidance.
- Optimized the README image to reduce npm package size.

## [1.0.1] - 2026-04-26

- Clarified install docs and CLI help: Bob installs into one project directory per command, while global npm install only installs the `hacker-bob` CLI.

## [1.0.0] - 2026-04-26

- Initial public `hacker-bob-cc` npm package with `hacker-bob` CLI install and update commands.
- Added `/bob:update`, passive update cache checks, installed version metadata, and status update hints.
- Preserved the source `install.sh` path as a compatibility wrapper.
