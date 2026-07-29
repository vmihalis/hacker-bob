# hacker-bob-kimi

Hacker Bob — Kimi CLI adapter wrapper.

This package pins `--adapter kimi` and delegates to the canonical `hacker-bob` CLI. Use it when you want Kimi CLI as the default host adapter.

## Usage

```bash
npx -y hacker-bob-kimi install /path/to/project
```

Equivalent to:

```bash
npx -y hacker-bob --adapter kimi install /path/to/project
```

After install, launch Kimi CLI with:

```bash
kimi --mcp-config-file .kimi/mcp.json
```

Then run:

```text
/skill:bob-evaluate target.com
```

## Other commands

```bash
npx -y hacker-bob-kimi update /path/to/project
npx -y hacker-bob-kimi check-update /path/to/project
npx -y hacker-bob-kimi doctor /path/to/project
npx -y hacker-bob-kimi uninstall /path/to/project
```

Explicit `--adapter` flags are respected, so multi-adapter installs continue to work.
