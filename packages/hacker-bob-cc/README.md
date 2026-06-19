# hacker-bob-cc

Claude Code adapter wrapper for [Hacker Bob](https://www.npmjs.com/package/hacker-bob).

This package is intentionally tiny: it ships a single `hacker-bob-cc` CLI shim that pins `--adapter claude` and delegates to the canonical `hacker-bob` runtime, which is pulled in as a dependency. Use it when you want a dedicated Claude Code install command without remembering the `--adapter` flag.

## Install

```bash
npx -y hacker-bob-cc install /path/to/your/project
```

The wrapper installs the full Hacker Bob framework into the target project under `.claude/`, `.hacker-bob/`, and the project's `.mcp.json`. After installing, restart Claude Code in that project and run `/bob-evaluate <target>`. Claude Code also exposes `/bob-status`, `/bob-debug`, `/bob-update`, `/bob-export`, and `/bob-egress`.

## Other commands

```bash
npx -y hacker-bob-cc update /path/to/your/project
npx -y hacker-bob-cc check-update /path/to/your/project
npx -y hacker-bob-cc doctor /path/to/your/project
npx -y hacker-bob-cc uninstall /path/to/your/project
```

Explicit `--adapter` flags are respected, so multi-adapter installs continue to work.

## Links

- Canonical CLI: [`hacker-bob`](https://www.npmjs.com/package/hacker-bob)
- Codex adapter wrapper: [`hacker-bob-codex`](https://www.npmjs.com/package/hacker-bob-codex)
- Source and documentation: <https://github.com/vmihalis/hacker-bob>

Released under the Apache-2.0 license.
