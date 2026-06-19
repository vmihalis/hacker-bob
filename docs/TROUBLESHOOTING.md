# Troubleshooting

## Run Doctor First

Use the CLI doctor before changing files manually:

```bash
hacker-bob doctor /path/to/your/project
hacker-bob doctor /path/to/your/project --json
```

The command is read-only. It checks Node.js, installed Bob files, neutral install metadata, selected adapter config, and whether `mcp/server.js` can load.

Use `--adapter claude`, `--adapter codex`, `--adapter generic-mcp`, `--adapter kimi`, or `--adapter all` when checking a non-default install:

```bash
hacker-bob doctor /path/to/your/project --adapter codex --json
```

## MCP Server Is Not Listed

Bob writes a `hacker-bob` server entry into the selected host config. Claude and generic MCP use the project `.mcp.json`; Codex uses `.codex/plugins/hacker-bob/.mcp.json`; Kimi uses `.kimi/mcp.json` and reads skills from `.kimi/skills/bob-{evaluate,status,debug,update,export,egress}/SKILL.md`. Existing v1.x installs (which used the legacy `bountyagent` server key) are auto-migrated to `hacker-bob` on next install or update — operator-managed sibling servers and custom permissions are preserved. Make sure you installed into the same directory you run the host CLI from:

```bash
npx -y hacker-bob@latest install /path/to/your/project --adapter claude
cd /path/to/your/project
claude mcp list
```

If `hacker-bob doctor` reports a missing or mismatched `.mcp.json` entry, rerun the install command for that project directory.

For Codex installs, check that `.codex/plugins/hacker-bob/.codex-plugin/plugin.json`, `.codex/plugins/hacker-bob/.mcp.json`, `~/.codex/skills/bob-{evaluate,status,debug,update,export,egress}/SKILL.md`, `.agents/plugins/marketplace.json`, and the doctor `codex_plugin_activation` and `codex_global_skills` checks are present. For Kimi installs, check `.kimi/skills/bob-{evaluate,status,debug,update,export,egress}/SKILL.md`, `.kimi/mcp.json`, and the doctor `kimi_skills` and `kimi_mcp_server_config` checks are present. For generic MCP installs, check `.hacker-bob/generic-mcp/hacker-bob.md` and the root `.mcp.json`.

## Codex Skills Are Missing

Codex reads Bob as direct skills from `~/.codex/skills` and reads MCP wiring from the enabled local plugin cache. Rerun the Codex adapter install in the exact project directory you start Codex from:

```bash
npx -y hacker-bob@latest install /path/to/your/project --adapter codex
cd /path/to/your/project
codex
```

The install should print `Codex plugin cache/config activated for MCP discovery`. Then look for `$bob-evaluate`, `$bob-status`, `$bob-debug`, `$bob-update`, `$bob-export`, and `$bob-egress`. If they still do not appear, run:

```bash
hacker-bob doctor /path/to/your/project --adapter codex --json
```

## Kimi Skills Are Missing

Kimi CLI reads Bob skills from `.kimi/skills` and MCP wiring from `.kimi/mcp.json`. Rerun the Kimi adapter install in the exact project directory you start Kimi from:

```bash
npx -y hacker-bob@latest install /path/to/your/project --adapter kimi
cd /path/to/your/project
kimi --mcp-config-file .kimi/mcp.json
```

Then look for `/skill:bob-evaluate`, `/skill:bob-status`, `/skill:bob-debug`, `/skill:bob-update`, `/skill:bob-export`, and `/skill:bob-egress`. If they still do not appear, run:

```bash
hacker-bob doctor /path/to/your/project --adapter kimi --json
```

Kimi installs the PreToolUse guard scripts under `.kimi/hooks/` and registers them in `~/.kimi/config.toml`, but this wiring is best-effort: the Kimi tool-name strings and PreToolUse payload shape are not pinned to a Kimi CLI version. Run `hacker-bob doctor /path/to/your/project --adapter kimi --json` and watch for the `kimi_hook_best_effort` warning; before relying on write enforcement on Kimi, verify a guard actually fires (e.g. attempt a blocked write to a session-dir `report.md`). Prompt-side discipline plus MCP-side validation remain the primary enforcement until that verification is done.

## Claude Restart Required

Claude Code reads project MCP and settings during startup. After installing or updating Bob, fully restart Claude Code in that project before running `/bob-evaluate`.

## `/bob-update` Is Missing

Legacy Claude installs may not have the update command. Update from outside Claude Code:

```bash
npx -y hacker-bob@latest install /path/to/your/project
```

Then restart Claude Code in that project.

For Codex installs, use `$bob-update`. For Kimi installs, use `/skill:bob-update`. For generic MCP installs, run `hacker-bob update /path/to/your/project --adapter generic-mcp` from a shell and reload the host config.

## Egress Command Is Missing

Claude installs expose `/bob-egress`; Codex installs expose `$bob-egress`. After installing or updating, restart the selected host CLI in the target project. If the command is still missing in Codex, rerun:

```bash
npx -y hacker-bob@latest install /path/to/your/project --adapter codex
```

## Legacy Metadata Warning

Older Claude-only installs may have `.claude/bob/VERSION` and `.claude/bob/install.json` without neutral `.hacker-bob/` install metadata. Doctor reports this as a warning and uses the legacy version as a migration fallback. Rerun the installer to write `.hacker-bob/VERSION`, `.hacker-bob/install.json`, and the installed adapter list:

```bash
npx -y hacker-bob@latest install /path/to/your/project --adapter claude
```

## npm Cache Or Network Issues

If `npx` cannot fetch the package, retry with a clean npm cache directory:

```bash
npm_config_cache=/tmp/hacker-bob-npm-cache npx -y hacker-bob@latest install /path/to/your/project
```

If your network blocks npm, install the CLI on a network that can reach the npm registry or use a source checkout:

```bash
git clone https://github.com/vmihalis/hacker-bob.git
cd hacker-bob
./install.sh /path/to/your/project
```

## Optional Surface-discovery Tools Missing

Bob works without optional surface-discovery tools, but some surface-discovery steps are skipped. `hacker-bob doctor` reports these as warnings.

Install the optional surface-discovery tools when you want deeper surface-discovery:

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/owasp-amass/amass/v4/...@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/PentestPad/subzy@latest
git clone https://github.com/ticarpi/jwt_tool ~/jwt_tool
python3 -m pip install -r ~/jwt_tool/requirements.txt
```

Optional browser automation for Tier 2 auto-signup requires `patchright` in the project and browser binaries:

```bash
cd /path/to/your/project
npm init -y
npm install patchright
npx patchright install chromium
```

CAPTCHA solving also requires `CAPSOLVER_API_KEY`.
