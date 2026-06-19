# Package Surfaces

This package ships runtime files, installer helpers, adapter prompts, and tests'
fixture data. Shipping a file does not make it a stable CommonJS API.

## Supported Runtime Surfaces

- CLI: `hacker-bob`, implemented by `bin/hacker-bob.js`.
- Wrapper CLIs: `hacker-bob-cc` and `hacker-bob-codex`, which depend on the exact matching `hacker-bob` version and delegate to `hacker-bob/bin/hacker-bob.js` while pinning a default adapter.
- Project-local MCP server: `mcp/server.js`, either executed as a process or loaded with `require("./mcp/server.js")` from an installed project.
- `mcp/server.js` exports exactly `TOOLS`, `TOOL_MANIFEST`, `executeTool`, and `startServer`.

## Installed Helper Surfaces

Adapter-generated local commands may invoke packaged helper modules with
`node -e` from an installed project. These are stable only for Bob-generated
skills, commands, and lifecycle code, not for general package consumers:

- `mcp/lib/update-check.js`
- `mcp/lib/bob-export.js`
- `mcp/lib/egress-profiles.js`

External consumers should prefer the CLI or `mcp/server.js`. Adding another
installed helper surface requires documenting it here and covering its package
presence in the shared package policy.

## Internal Surfaces

Everything under `mcp/lib/**`, `mcp/lib/tools/**`, `scripts/**`, `adapters/**`,
`prompts/**`, and `.claude/**` is internal implementation unless a document or
test names it as an installed runtime surface. These files are packaged because
the installer, generated prompts, and MCP runtime need them on disk. External
package consumers should not deep-import them as stable APIs.

Inside this repository, tests and maintenance scripts may import the internal
module that owns the behavior they are asserting. `mcp/server.js` should stay a
small facade for runtime entrypoints, not a dumping ground for lower-level
helpers.

Session authority lives behind the MCP dispatcher and tool envelopes. Files such
as `mcp/lib/session-authority.js`, `mcp/lib/tool-policy.js`, and
`mcp/lib/tool-telemetry.js` are packaged runtime implementation, not stable
deep-import APIs. External consumers should observe authority through MCP errors
and `bounty_read_tool_telemetry` aggregates.

## Package Policy

The npm `files` allowlist lives in `package.json`; the executable package-shape
policy lives in `scripts/lib/package-policy.js` and is consumed by both
`scripts/release-check.js` and `test/package.test.js`. Update the shared policy
when changing packaged runtime surfaces, intentional support files, excluded
generated artifacts, or wrapper package shape.

Plane-Delta graph and verification docs may ship as support material; per-node
detail docs under `docs/plane-delta/detail/` are internal planning notes and are
excluded from npm packages.
