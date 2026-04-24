# Refactor Hardening Plan Status

This file used to track the monolith extraction plan. That work is complete enough that the old checklist was misleading.

Current contract:

- Tool definitions flow through the registry/envelope path, with generated tool lists, manifest metadata, dispatcher lookup, and Claude config helpers. New tools should use the per-tool module pattern in `mcp/lib/tools/` where practical; unmigrated legacy tools still flow through `tool-definitions.js`, `tool-manifest.js`, and `tool-handlers.js`.
- MCP transport responses use the standard `{ ok, data/error, meta }` envelope.
- Runtime arguments are recursively validated against Bob's supported schema subset before handlers run.
- The FSM is `RECON → AUTH → HUNT → CHAIN → VERIFY → GRADE → REPORT`, with optional `REPORT → EXPLORE → CHAIN → VERIFY → GRADE → REPORT` when the user asks for more hunting.
- Markdown mirrors are human/debug only. Chain context comes from structured wave handoff `summary` and `chain_notes`. Legacy prose exceptions are `chains.md` for verifier narrative context and `report.md` for the final report.
- New wave handoffs use per-assignment provenance tokens. Assignment files store only SHA-256 token hashes.
- Hunter `SubagentStop` is validation-only: it requires the final marker and valid structured handoff, but it does not merge waves or mutate session state.
- Installer and dev-sync merge `.mcp.json` and `.claude/settings.json` without clobbering unrelated user config. Both copy the complete MCP runtime, including `mcp/lib/tools/*.js`.

For new tool work, add a registry-backed per-tool module when possible, implement the handler, and add tests for validation, envelope behavior, metadata, and role permissions.
