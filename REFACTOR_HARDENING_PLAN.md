# Refactor Hardening Plan Status

This file used to track the monolith extraction plan. That work is complete enough that the old checklist was misleading.

Current contract:

- Tool definitions flow through the registry/envelope path, with generated tool lists, manifest metadata, dispatcher lookup, and Claude config helpers.
- MCP transport responses use the standard `{ ok, data/error, meta }` envelope.
- Runtime arguments are recursively validated against Bob's supported schema subset before handlers run.
- Markdown artifacts are human/debug mirrors only. Chain context comes from structured wave handoff `summary` and `chain_notes`.
- New wave handoffs use per-assignment provenance tokens. Assignment files store only SHA-256 token hashes.
- Installer and dev-sync merge `.mcp.json` and `.claude/settings.json` without clobbering unrelated user config.

For new tool work, add the registry-backed tool entry, implement the handler, and add tests for validation, envelope behavior, metadata, and role permissions.
