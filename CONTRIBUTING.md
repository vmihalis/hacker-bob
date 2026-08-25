# Contributing

Thanks for taking the time to improve Hacker Bob. This project is a security
tool, so contributions need to preserve operator safety, clear authorization
boundaries, and reproducible behavior.

## Before opening an issue or pull request

- Read `README.md`, `DISCLAIMER.md`, and `SECURITY.md`.
- Do not include real target data, private bug bounty reports, credentials,
  session artifacts, cookies, tokens, or screenshots containing secrets.
- Report vulnerabilities in Hacker Bob itself through the private security
  reporting flow described in `SECURITY.md`, not through public issues.
- Report vulnerabilities found in third-party targets to that target's official
  disclosure or bug bounty channel.

## Development setup

Use Node.js 20 or newer.

```bash
git clone https://github.com/vmihalis/hacker-bob.git
cd hacker-bob
npm ci
npm test
```

Useful focused checks:

```bash
npm run check:syntax
npm run test:mcp
npm run test:prompts
# Darwin arm64 with Node.js 20 only (native qualification):
npm run test:native-darwin
npm run test:install
npm run test:hooks
```

## Project layout

- `adapters/` contains host-specific install, doctor, uninstall, render, and
  config ownership for Claude, Codex, Kimi, and generic MCP hosts.
- `.claude/agents/`, `.claude/skills/`, `.claude/rules/`, and
  `.claude/hooks/` are the generated Claude adapter surface.
- `prompts/roles/` and `mcp/core/dispatch/role-model.js` define shared role contracts
  that adapters render into host-specific files.
- `mcp/` contains the MCP server and runtime tool implementation.
- `.hacker-bob/` contains neutral runtime resources copied into installs.
- `scripts/` contains generation and config merge helpers.
- `test/` contains the contract, MCP, installer, and hook tests.

## Generated surfaces

Some Claude-facing files are generated from registry metadata. If you change
tool definitions, role bundles, or prompt permissions, run the relevant
generator and commit the resulting changes:

```bash
node scripts/generate-agent-tools.js
node scripts/generate-hacker-bob-skill.js
node scripts/generate-claude-roles.js
node scripts/generate-codex-skills.js
```

Then run:

```bash
npm run test:prompts
```

## Pull request expectations

- Keep pull requests focused and explain the behavior change.
- Add or update tests for changes to MCP tools, session state, validation,
  hooks, prompts, install behavior, or security boundaries.
- Run `npm test` before marking the pull request ready for review. Changes to
  installer, lifecycle-custodian, or Darwin-native surfaces must also pass
  `npm run test:native-darwin` on Darwin arm64 with Node.js 20; the required CI
  job enforces that qualification separately from portable tests.
- Update docs when user-facing behavior, install steps, permissions, or safety
  assumptions change.
- Do not loosen SSRF, path traversal, session-write, secret-redaction, or
  authorization guardrails without tests and a clear rationale.

## Testing installed changes

For local end-to-end testing, use a dedicated throwaway workspace:

```bash
./dev-sync.sh /absolute/path/to/test-workspace
./dev-sync.sh /absolute/path/to/test-workspace --adapter codex
./dev-sync.sh /absolute/path/to/test-workspace --adapter generic-mcp
```

Restart the selected host in that workspace after syncing. Do not use a
workspace that contains real credentials or target data unless you intend to
test with them.

## Release checklist

- Update `CHANGELOG.md` with a semver section for the release.
- Confirm `package.json` has the intended canonical package metadata and
  `packages/hacker-bob-cc/package.json`, `packages/hacker-bob-codex/package.json`,
  and `packages/hacker-bob-kimi/package.json` pin the same version.
- Run `npm test` for the portable release surface.
- Run `npm run test:native-darwin` on Darwin arm64 with Node.js 20.
- Run `npm run release:check` and verify the canonical package includes
  adapter surfaces, neutral resources, `mcp/`, `bin/`, `scripts/`, docs, and
  release metadata without test or cache artifacts.
- Push a signed `v*` tag after npm publishing credentials are configured for
  the release workflow.
