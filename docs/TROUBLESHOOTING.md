# Troubleshooting

## Run Doctor First

Use the CLI doctor before changing files manually:

```bash
hacker-bob doctor /path/to/your/project
hacker-bob doctor /path/to/your/project --json
```

The command is read-only. It checks Node.js, installed Bob files, neutral install metadata, selected adapter config, and whether `mcp/server.js` can load.

Use `--adapter claude`, `--adapter codex`, `--adapter generic-mcp`, or `--adapter all` when checking a non-default install:

```bash
hacker-bob doctor /path/to/your/project --adapter codex --json
```

## MCP Server Is Not Listed

Bob writes a `bountyagent` server entry into the selected host config. Claude and generic MCP use the project `.mcp.json`; Codex uses `.codex/plugins/hacker-bob/.mcp.json`. Make sure you installed into the same directory you run the host CLI from:

```bash
npx -y hacker-bob@latest install /path/to/your/project --adapter claude
cd /path/to/your/project
claude mcp list
```

If `hacker-bob doctor` reports a missing or mismatched `.mcp.json` entry, rerun the install command for that project directory.

For Codex installs, check that `.codex/plugins/hacker-bob/.codex-plugin/plugin.json`, `.codex/plugins/hacker-bob/.mcp.json`, `.codex/plugins/hacker-bob/skills/{hunt,status,debug,update}/SKILL.md`, `.agents/plugins/marketplace.json`, and the doctor `codex_plugin_activation` check are present. For generic MCP installs, check `.hacker-bob/generic-mcp/hacker-bob.md` and the root `.mcp.json`.

## Codex Skills Are Missing

Codex reads plugin skills from enabled plugins in its plugin cache. Rerun the Codex adapter install in the exact project directory you start Codex from:

```bash
npx -y hacker-bob@latest install /path/to/your/project --adapter codex
cd /path/to/your/project
codex
```

The install should print `Codex plugin cache/config activated for skill discovery`. Then look for `$hacker-bob:hunt`, `$hacker-bob:status`, `$hacker-bob:debug`, and `$hacker-bob:update`. If they still do not appear, run:

```bash
hacker-bob doctor /path/to/your/project --adapter codex --json
```

## Claude Restart Required

Claude Code reads project MCP and settings during startup. After installing or updating Bob, fully restart Claude Code in that project before running `/bob:hunt`.

## `/bob:update` Is Missing

Legacy Claude installs may not have the update command. Update from outside Claude Code:

```bash
npx -y hacker-bob@latest install /path/to/your/project
```

Then restart Claude Code in that project.

For Codex installs, use `$hacker-bob:update`. For generic MCP installs, run `hacker-bob update /path/to/your/project --adapter generic-mcp` from a shell and reload the host config.

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

## Optional Recon Tools Missing

Bob works without optional recon tools, but some recon steps are skipped. `hacker-bob doctor` reports these as warnings.

Install the ProjectDiscovery tools when you want deeper recon:

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

Optional browser automation for Tier 2 auto-signup requires `patchright` in the project and browser binaries:

```bash
cd /path/to/your/project
npm init -y
npm install patchright
npx patchright install chromium
```

CAPTCHA solving also requires `CAPSOLVER_API_KEY`.
