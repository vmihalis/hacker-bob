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
npm run test:install
npm run test:hooks
```

## Project layout

- `.claude/agents/`, `.claude/skills/`, `.claude/rules/`, and
  `.claude/hooks/` define the Claude Code-facing experience.
- `mcp/` contains the MCP server and runtime tool implementation.
- `scripts/` contains generation and config merge helpers.
- `test/` contains the contract, MCP, installer, and hook tests.

## Generated surfaces

Some Claude-facing files are generated from registry metadata. If you change
tool definitions, role bundles, or prompt permissions, run the relevant
generator and commit the resulting changes:

```bash
node scripts/generate-agent-tools.js
node scripts/generate-bountyagent-skill.js
```

Then run:

```bash
npm run test:prompts
```

## Pull request expectations

- Keep pull requests focused and explain the behavior change.
- Add or update tests for changes to MCP tools, session state, validation,
  hooks, prompts, install behavior, or security boundaries.
- Run `npm test` before marking the pull request ready for review.
- Update docs when user-facing behavior, install steps, permissions, or safety
  assumptions change.
- Do not loosen SSRF, path traversal, session-write, secret-redaction, or
  authorization guardrails without tests and a clear rationale.

## Testing installed changes

For local end-to-end testing, use a dedicated throwaway Claude Code workspace:

```bash
./dev-sync.sh /absolute/path/to/test-workspace
```

Restart Claude Code in that workspace after syncing. Do not use a workspace that
contains real credentials or target data unless you intend to test with them.
