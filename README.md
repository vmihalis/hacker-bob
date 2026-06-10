<p align="center">
  <img src="docs/hacker-bob.png" alt="Hacker Bob" width="320" />
</p>

<h1 align="center">Hacker Bob</h1>

<p align="center"><i>A local MCP workflow framework for authorized bug bounty research.</i></p>

<p align="center">
  <a href="https://github.com/vmihalis/hacker-bob/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/vmihalis/hacker-bob/actions/workflows/ci.yml/badge.svg" /></a>
  <a href="https://www.npmjs.com/package/hacker-bob"><img alt="hacker-bob on npm" src="https://img.shields.io/npm/v/hacker-bob?label=hacker-bob" /></a>
  <a href="https://www.npmjs.com/package/hacker-bob-cc"><img alt="hacker-bob-cc on npm" src="https://img.shields.io/npm/v/hacker-bob-cc?label=hacker-bob-cc" /></a>
  <a href="https://www.npmjs.com/package/hacker-bob-codex"><img alt="hacker-bob-codex on npm" src="https://img.shields.io/npm/v/hacker-bob-codex?label=hacker-bob-codex" /></a>
  <a href="https://www.npmjs.com/package/hacker-bob-kimi"><img alt="hacker-bob-kimi on npm" src="https://img.shields.io/npm/v/hacker-bob-kimi?label=hacker-bob-kimi" /></a>
  <a href="LICENSE"><img alt="Apache-2.0 license" src="https://img.shields.io/github/license/vmihalis/hacker-bob" /></a>
  <a href="https://securityscorecards.dev/viewer/?uri=github.com/vmihalis/hacker-bob"><img alt="OpenSSF Scorecard" src="https://api.securityscorecards.dev/projects/github.com/vmihalis/hacker-bob/badge" /></a>
</p>

Hacker Bob installs a local MCP runtime into a project directory and connects it to Claude Code, Codex, Kimi CLI, or another MCP-capable host. The runtime coordinates surface mapping, authentication setup, parallel surface testing, finding verification, grading, reporting, and local evidence handling.

Bob is designed for authorized security testing. It can send real network requests, run local surface-discovery tools, import local artifacts, and preserve sensitive run data on disk. You are responsible for using it only where you have permission.

## Quickstart

Choose the project directory where you want to run Bob. Install into that project, not into this source checkout unless you are developing Bob itself.

```bash
npx -y hacker-bob@latest install /path/to/your/project
cd /path/to/your/project
node -e "require('./mcp/server.js'); console.log('MCP ok')"
```

Restart your host CLI from the same project directory, then run the matching command:

| Host | Command |
|---|---|
| Claude Code | `/bob-evaluate target.com` |
| Codex | `$bob-evaluate target.com` |
| Kimi CLI | `/skill:bob-evaluate target.com` |
| OpenCode | `/bob-evaluate target.com` |
| Generic MCP host | Connect the generated `.mcp.json`, then follow `.hacker-bob/generic-mcp/hacker-bob.md`. |

Run a status check before a full evaluate if you want to confirm the integration is loaded:

| Host | Status command |
|---|---|
| Claude Code | `/bob-status` |
| Codex | `$bob-status` |
| Kimi CLI | `/skill:bob-status` |
| OpenCode | `/bob-status` |
| Shell | `hacker-bob doctor /path/to/your/project` |

## Safety

Only run Bob against targets, accounts, applications, APIs, and infrastructure you own or are explicitly authorized to test. Read the target program's scope and rules of engagement before starting a evaluate.

Bob does not prove authorization, enforce a program policy, or guarantee containment. For session-bound MCP tools, caller `target_domain` is only a lookup key: Bob authorizes against initialized session state, validates the stored `target` and `target_url`, and rejects drift before handlers run. Bob's MCP-scoped HTTP tools additionally require a public `target_domain` and only send first-party target-host requests; browser auto-signup routes page HTTP requests through a target-host guard but refuses effective `block_internal_hosts: true` because Chromium resolves network destinations outside Bob's safeFetch transport. Bob does not control arbitrary host shell commands, unrelated browser activity, or external surface-discovery binaries. By default, `normal`, `yolo`, and compatible legacy sessions allow public first-party hostnames that resolve to private infrastructure; `paranoid` sessions default to direct-egress DNS/private-address blocking unless the operator starts the session with `--allow-internal-hosts` for an explicitly authorized internal/lab program. First-party host scope is not DNS-rebinding or SSRF protection. Bob uses the packaged Public Suffix List via `psl` to reject public-suffix-only `target_domain` values and isolate registrable tenant domains. If that packaged list is stale, an operator can set `BOB_PSL_OVERLAY_FILE` to a local suffix file before running Bob; overlay matches are recorded in HTTP audit rows with `public_suffix_source` and `psl_overlay_file`, and the overlay is not a per-request bypass. For tools that support it, pass `--block-internal-hosts` or `block_internal_hosts: true` when you need local DNS/private-address blocking outside paranoid mode. The effective value is persisted in state and HTTP audit rows. That stricter mode is only available on direct egress, not proxy-backed egress profiles where target DNS and routing happen outside Bob.

Bob binds the selected `egress_profile` to the session at `bounty_init_session` and records a redacted `egress_profile_identity_hash` in state, HTTP audit, evaluator briefs, signup responses, pipeline events, and analytics. Egress-bound HTTP and signup tools require initialized session state; legacy sessions may default presentation/progress fields, but missing or drifted authority fields such as `target`, `target_url`, internal-host policy, or egress identity fail closed for tools that rely on them. Bob hashes the profile name, region, proxy-configured bit, proxy route, and env/source identity, excluding raw credentials and description text; credential rotation on the same proxy route is allowed, but profile, route, or source drift fails closed.

Smart-contract RPC/REST tools use a separate direct-only model: shipped public ladders, explicit `endpoints` / `fork_urls`, and `BOB_<FAMILY>_RPCS_<NETWORK>` env overrides must be public HTTPS endpoints. Bob filters localhost/private/internal literals and performs bounded DNS private-address preflight for SC endpoints. Bob-owned Node SC reads and EVM source fetches then pin the HTTPS socket lookup to one of those preflighted public DNS answers. Fork runners are different: Foundry, Anchor, Aptos, Sui, Substrate, CosmWasm, and Halmos subprocesses run with proxy/RPC/secret env scrubbed, then receive only runner-created fork URL env or CLI args that came from preflighted public endpoints; Bob does not control or DNS-pin the downstream CLI socket. SC RPC does not use `egress_profile` proxy routing, and private/localnet RPC is unsupported by default until a per-family opt-in policy exists. Returned endpoint evidence and policy rejections redact credentials and query values.

If your Claude Code workflow uses `--dangerously-skip-permissions`, use it only in a dedicated workspace for authorized security testing.

## Installation

`hacker-bob` is the canonical npm package:

```bash
npx -y hacker-bob@latest install /path/to/your/project
```

Adapter-specific installs are available when you want to choose the host explicitly:

```bash
npx -y hacker-bob@latest install /path/to/your/project --adapter claude
npx -y hacker-bob@latest install /path/to/your/project --adapter codex
npx -y hacker-bob@latest install /path/to/your/project --adapter generic-mcp
npx -y hacker-bob@latest install /path/to/your/project --adapter kimi
npx -y hacker-bob@latest install /path/to/your/project --adapter opencode
npx -y hacker-bob@latest install /path/to/your/project --adapter all
```

The installer is idempotent and preserves unrelated host configuration. It writes the shared MCP runtime to `mcp/`, neutral Bob resources to `.hacker-bob/`, and adapter-specific files for the selected host.

| Adapter | Installed files |
|---|---|
| `claude` | `.claude/` commands, skills, agents, hooks, statusline setup, and MCP settings. |
| `codex` | `$bob-*` skills in `~/.codex/skills`, a local `.codex/plugins/hacker-bob` plugin, `.agents/plugins/marketplace.json`, and Codex MCP activation metadata. |
| `kimi` | `.kimi/skills`, `.kimi/mcp.json`, and `.kimi/bob` compatibility metadata. Relies on prompt-side enforcement; no PreToolUse hooks until `~/.kimi/config.toml` wiring lands. |
| `opencode` | A project-root `opencode.json` MCP entry, per-role subagents under `.opencode/agents/bob-*.md` (orchestrator `mode: primary`, the rest `mode: subagent`, no pinned model — BYOK), `/bob-*` slash commands under `.opencode/commands/`, and `.opencode/bob` install metadata. The orchestrator dispatches subagents through the task tool (`subagent_type: "bob-<role>"`). |
| `generic-mcp` | A root `.mcp.json` entry plus prompt guide files under `.hacker-bob/generic-mcp/`. |

When `--adapter` is omitted, Bob chooses an adapter from prior install metadata, host environment markers, project files (`.claude/`, `.codex/plugins/`, `.kimi/`, `opencode.json`/`.opencode/`, `.mcp.json`), and installed host CLIs. Claude is the final fallback.

The MCP server name is `hacker-bob`. You will see `hacker-bob` in `.mcp.json`, in `claude mcp list`, and as the prefix on tool names such as `mcp__hacker-bob__bob_*`. Existing v1.x installs are auto-migrated on the next install or update: the legacy `bountyagent` server key and `mcp__bountyagent__*` permission strings are rewritten to the canonical `hacker-bob` form while operator-managed sibling servers and custom permissions are preserved.

Small wrapper packages are available when you want the host choice encoded in the package name:

```bash
npx -y hacker-bob-cc@latest install /path/to/your/project
npx -y hacker-bob-codex@latest install /path/to/your/project
npx -y hacker-bob-kimi@latest install /path/to/your/project
```

You can also install the CLI globally:

```bash
npm install -g hacker-bob
hacker-bob install /path/to/your/project --adapter claude
```

A global install only adds the `hacker-bob` command to your `PATH`; it does not install Bob into every project automatically.

Source installs are for contributors and local development:

```bash
git clone https://github.com/vmihalis/hacker-bob.git
cd hacker-bob
./install.sh /path/to/your/project
```

## Commands

Claude Code commands:

```text
/bob-evaluate target.com         # start a normal evaluate
/bob-evaluate target.com --deep  # broader surface-discovery and deep lead follow-up
/bob-evaluate resume target.com  # resume an existing session
/bob-status                  # show latest session status
/bob-debug                   # inspect the latest local run
/bob-update                  # preview and install the latest release
/bob-export                  # create a release-scoped improvement bundle
/bob-egress                  # manage operator-controlled egress profiles
```

Codex uses the same command names with a `$` prefix:

```text
$bob-evaluate target.com
$bob-status
$bob-debug
$bob-update
$bob-export
$bob-egress
```

Kimi CLI uses a `/skill:` prefix:

```text
/skill:bob-evaluate target.com
/skill:bob-status
/skill:bob-debug
/skill:bob-update
/skill:bob-export
/skill:bob-egress
```

For install diagnostics:

```bash
hacker-bob doctor /path/to/your/project
hacker-bob doctor /path/to/your/project --adapter codex
hacker-bob doctor /path/to/your/project --adapter kimi
```

## Integrating Bob Diff Review into your repo

Bob can review pull request diffs automatically using GitHub Actions. The
review runs headless inside GitHub-hosted runners and posts inline comments
plus a Check Run result on every PR.

### Quick setup

1. **Set org-level secrets and variables** once in your GitHub organization
   (Settings > Secrets and variables > Actions):

   | Name | Type | Description |
   |---|---|---|
   | `ANTHROPIC_OAUTH_TOKEN` | Secret | Recommended Anthropic OAuth token from `claude setup-token` for the headless Claude reviewer. |
   | `ANTHROPIC_API_KEY` | Secret | Anthropic API key fallback for the headless Claude reviewer. Required only when `ANTHROPIC_OAUTH_TOKEN` is not set. |
   | `BOB_INSTALL_TOKEN` | Secret | GitHub App token or fine-grained PAT with `read:packages` and `contents:read` scopes. Used to install `@bobnetsec/*` packages. |
   | `BOB_VERSION` | Variable | Bob release tag to cache, e.g. `v1.2.3`. Shared across repos in the org so they reuse the same warm workspace cache. |

2. **Add the caller workflow** to each repository you want reviewed. Create
   `.github/workflows/bob-review.yml` with the minimal content below:

   ```yaml
   name: Bob Diff Review

   on:
     pull_request:
       types: [opened, synchronize, reopened]

   permissions:
     pull-requests: write
     checks: write
     contents: read

   jobs:
     bob-review:
       uses: bobnetsec/bob-workflows/.github/workflows/bob-review.yml@v1
       secrets: inherit
   ```

   That is the complete file. `secrets: inherit` propagates the org-level
   secrets automatically — no per-repo secret declarations required.

### Optional inputs

Pass these under `with:` on the `bob-review` job if you need to override the
reusable workflow defaults:

| Input | Default | Description |
|---|---|---|
| `min-severity-for-failure` | `high` | Minimum severity that sets the PR check to failed. Accepts `critical`, `high`, `medium`, or `low`. Set to `critical` to fail only on critical findings; set to `low` to fail on any finding. |

Example with `min-severity-for-failure` overridden:

```yaml
jobs:
  bob-review:
    uses: bobnetsec/bob-workflows/.github/workflows/bob-review.yml@v1
    secrets: inherit
    with:
      min-severity-for-failure: critical
      bob-workflows-ref: v1
```

### Viewing findings

- **Inline PR comments**: Bob posts a comment on each changed line that
  contains a finding. Comments include severity, a short description, and a
  suggested fix when available.
- **Check Run**: A "Bob Diff Review" check appears in the PR Checks tab. The
  summary shows `findings_count`, `critical_count`, and links to the full
  report artifact.
- **Actions log**: The "Log review outputs" step in the run log prints
  `findings_count`, `critical_count`, and `review_url` for quick triage.

### Fork PRs

Forked PRs do not receive org-level secrets, and same-repo PRs may also run
before reviewer credentials are configured. The workflow detects missing
Anthropic credentials and skips the Bob review steps instead of failing the PR
check in setup. No additional guard is needed in the caller workflow.

### Versioning

Pin the reusable workflow to a release tag or full commit SHA. If you override
`bob-workflows-ref`, set it to the same immutable ref so the workflow checks out
the matching local action source:

```yaml
uses: bobnetsec/bob-workflows/.github/workflows/bob-review.yml@v1
```

## How A Evaluation Works

Bob follows a structured workflow:

```text
SURFACE_DISCOVERY -> AUTH -> EVALUATE -> CHAIN -> VERIFY -> GRADE -> REPORT
```

- `SURFACE_DISCOVERY`: Collects subdomains, live hosts, archived URLs, crawled URLs, nuclei signals, JavaScript hints, and optional deep-surface-discovery lead data.
- `AUTH`: Attempts authorized account setup when possible and records usable profiles for later differential testing.
- `EVALUATE`: Starts parallel evaluators against runtime-prioritized attack surfaces.
- `CHAIN`: Evaluates whether individual findings combine into higher-impact scenarios.
- `VERIFY`: Runs independent verification passes and collects bounded evidence for surviving reportable findings.
- `GRADE`: Scores confirmed findings and decides whether they are ready to submit, should be held, or should be discarded.
- `REPORT`: Produces a clean report with verified proof and evidence references.

MCP ranking computes runtime priority for status views and evaluator briefs. Imports and public-intel fetches do not rewrite `attack_surface.json`.

### OSS Project Review Mode

Local open-source project review runs against a checked-out repository instead of a live target domain. It inventories repo files, writes a session-scoped Docker plan, and keeps dependency installs and build repros inside a Docker image when explicitly requested. Docker command replay mounts the repo read-only by default and uses a session-owned writable work directory. Native C/C++ projects get a dedicated parser/protocol/memory-safety surface so evaluators bias toward reachable file/function evidence instead of generic repo audit notes. OSS mode is plumbed through the same v2 governance/frontier/scheduler/claim planes and is exposed as a forward-ported entry point (`/bob-evaluate <repo-path>` semantics) under the unified lifecycle FSM.

### Local Multi-Session Dashboard

For a local read-only dashboard over multiple concurrent sessions:

```bash
hacker-bob dashboard --repo-only
```

The dashboard binds to `127.0.0.1:4873` by default and reads `~/hacker-bob-sessions` (falling back to the legacy `~/bounty-agent-sessions` root during the v2.0.x migration window). It shows OSS/repo progress, pending handoffs, claims, verification/evidence/grade state, and cross-session bottlenecks.

## Requirements

- Node.js 20 or newer
- One supported host: Claude Code, Codex, Kimi CLI, or another MCP-capable host
- `curl` and `python3`
- A dedicated project directory for the installed runtime

Optional surface-discovery tools improve coverage when they are installed:

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

Bob still runs without the optional tools; the installed toolset determines which surface-discovery paths are available.

## Updates

From Claude Code:

```text
/bob-update
```

From Codex:

```text
$bob-update
```

From Kimi:

```text
/skill:bob-update
```

From a shell:

```bash
hacker-bob update /path/to/your/project --adapter claude
```

After an update, fully restart your host CLI in the project directory so it reloads commands, MCP config, hooks, and skills.

Bob also checks for available updates once per day on session start and stores the result under `~/.cache/hacker-bob/update-checks/`. Status views read that local cache.

## Exporting Run Data

After testing with an installed release, run `/bob-export` in Claude, `$bob-export` in Codex, or `/skill:bob-export` in Kimi. Bob writes a timestamped bundle under:

```text
~/bounty-agent-telemetry/release-bundles/v<version>/
```

The bundle includes summaries, filtered telemetry, session references, and a handoff document for improving future releases. Export is read-only and does not touch targets.

## Troubleshooting

Use the doctor command first:

```bash
hacker-bob doctor /path/to/your/project --adapter all
```

Common checks:

- `node -e "require('./mcp/server.js'); console.log('MCP ok')"` should pass from the installed project.
- Claude Code must be restarted after install or update before `/bob-*` commands and MCP settings load.
- Codex must be restarted after install or update before `$bob-*` skills and local plugin wiring load.
- Kimi CLI must be restarted after install or update before `/skill:bob-*` skills and MCP config load.
- `.mcp.json` should contain an `mcpServers["hacker-bob"]` entry pointing at the installed project's `mcp/server.js`. v1.x installs are auto-migrated to this canonical key on next install or update.
- If an upgrade leaves `mcp/lib/tools/` missing, rerun the installer with `hacker-bob@latest`.

Detailed guides:

- [First Run](docs/FIRST_RUN.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)
- [Adapters](docs/ADAPTERS.md)
- [Package surfaces](docs/PACKAGE_SURFACES.md)
- [Roadmap](docs/ROADMAP.md)

## Data And Security Model

Bob stores local run state, telemetry, and evidence under `~/hacker-bob-sessions`. Legacy `~/bounty-agent-sessions/` is migrated to `~/hacker-bob-sessions/` on first use; preserved until v2.1.0 (`--purge-legacy-session-root`). Bob copies — never moves — any legacy domain directories into the canonical root on first session access, so the legacy directory remains readable as a fallback for sessions created before the v2.0 rename. Treat both directories as sensitive. They can contain target names, request metadata, notes, credentials metadata, and report evidence from authorized testing.

During a evaluate, Bob may make outbound HTTP requests, run local surface-discovery tools, import HTTP or static artifacts, and use host-side reasoning over the collected context. Optional third-party services and dependencies, such as browser automation dependencies, CAPTCHA solving, public-intel sources, or external surface-discovery tools, are used only when you configure the relevant dependencies or credentials.

The npm packages are published through the project release workflow with npm provenance. `hacker-bob` is the canonical package; `hacker-bob-cc`, `hacker-bob-codex`, and `hacker-bob-kimi` are small wrapper packages that depend on the matching canonical version.

Read [DISCLAIMER.md](DISCLAIMER.md) before using Bob on any target.

## Development

For local development on Bob itself:

```bash
npm test
npm run release:check
npm run release:check:dependencies
```

To push the current checkout into a separate test workspace:

```bash
./dev-sync.sh /absolute/path/to/test-workspace
./dev-sync.sh /absolute/path/to/test-workspace --adapter codex
./dev-sync.sh /absolute/path/to/test-workspace --adapter kimi
```

The maintainer workflow is documented in [CLAUDE.md](CLAUDE.md).

## Contributing

Pull requests are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening an issue or PR. Report vulnerabilities in Hacker Bob itself through [SECURITY.md](SECURITY.md).

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
