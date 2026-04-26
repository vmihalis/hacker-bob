# Troubleshooting

## Run Doctor First

Use the CLI doctor before changing files manually:

```bash
hacker-bob doctor /path/to/your/project
hacker-bob doctor /path/to/your/project --json
```

The command is read-only. It checks Node.js, installed Bob files, MCP config, Claude settings hooks, statusline config, and whether `mcp/server.js` can load.

## MCP Server Is Not Listed

Bob writes a `bountyagent` server entry into the project's `.mcp.json`. Make sure you installed into the same directory you run Claude Code from:

```bash
npx -y hacker-bob-cc@latest install /path/to/your/project
cd /path/to/your/project
claude mcp list
```

If `hacker-bob doctor` reports a missing or mismatched `.mcp.json` entry, rerun the install command for that project directory.

## Claude Restart Required

Claude Code reads project MCP and settings during startup. After installing or updating Bob, fully restart Claude Code in that project before running `/bob-hunt`.

## `/bob-update` Is Missing

Legacy installs may not have the update command. Update from outside Claude Code:

```bash
npx -y hacker-bob-cc@latest install /path/to/your/project
```

Then restart Claude Code in that project.

## npm Cache Or Network Issues

If `npx` cannot fetch the package, retry with a clean npm cache directory:

```bash
npm_config_cache=/tmp/hacker-bob-npm-cache npx -y hacker-bob-cc@latest install /path/to/your/project
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
