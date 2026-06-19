# hacker-bob-codex

Codex adapter wrapper for [Hacker Bob](https://www.npmjs.com/package/hacker-bob).

This package is intentionally tiny: it ships a single `hacker-bob-codex` CLI shim that pins `--adapter codex` and delegates to the canonical `hacker-bob` runtime, which is pulled in as a dependency. Use it when you want a dedicated Codex install command without remembering the `--adapter` flag.

## Install

```bash
npx -y hacker-bob-codex install /path/to/your/project
```

The wrapper installs the full Hacker Bob framework into the target project under `.codex/plugins/`, `.hacker-bob/`, and Codex plugin MCP wiring. After installing, restart Codex in that project and use `$bob-evaluate <target>`. Codex also exposes `$bob-status`, `$bob-debug`, `$bob-update`, `$bob-export`, and `$bob-egress`.

## Other commands

```bash
npx -y hacker-bob-codex update /path/to/your/project
npx -y hacker-bob-codex check-update /path/to/your/project
npx -y hacker-bob-codex doctor /path/to/your/project
npx -y hacker-bob-codex uninstall /path/to/your/project
```

Explicit `--adapter` flags are respected, so multi-adapter installs continue to work.

## Links

- Canonical CLI: [`hacker-bob`](https://www.npmjs.com/package/hacker-bob)
- Claude Code adapter wrapper: [`hacker-bob-cc`](https://www.npmjs.com/package/hacker-bob-cc)
- Source and documentation: <https://github.com/vmihalis/hacker-bob>

Released under the Apache-2.0 license.
