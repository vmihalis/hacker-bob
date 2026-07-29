# AgentCore runner image

This directory contains the deployable Hacker Bob AgentCore runtime wrapper.
The engine under `mcp/`, generated Claude/Codex/Kimi surfaces, and lifecycle
gates remain the normal Hacker Bob engine; the runner only provides the
AgentCore HTTP entrypoint, model environment, and owned loopback fixture.

## Runtime Contract

- Image platform: `linux/arm64`.
- HTTP contract: AgentCore calls `/invocations`; `/ping` is served by the
  `bedrock-agentcore` SDK app.
- Process user: `node`, not root. Claude Code refuses
  `--dangerously-skip-permissions` as root.
- `$HOME=/mnt/efs/bob-home` so session state lands on the EFS mount declared in
  `infra/aws/hacker-bob-stack/template.yaml`.
- Model provider default: Bedrock with `CLAUDE_CODE_USE_BEDROCK=1`.
- Claude API budget default: `BOB_MAX_BUDGET_USD=2.00` per invocation, passed as
  `--max-budget-usd`.
- Invocation timeout default: `BOB_INVOCATION_TIMEOUT_SECONDS=780`, below the
  AgentCore 15-minute request timeout.

## Built-In Demo Target

When `BOB_BUILTIN_DEMO_TARGET=true`, the entrypoint starts:

```text
127.0.0.1:8081
```

using `scripts/mock-github-api.js` in strict-route mode. AgentCore only exposes
port 8080, so the fixture remains container-local. The demo payload is:

```json
{
  "target": "http://127.0.0.1:8081/repos/acme/demo/pulls/42",
  "target_domain": "127.0.0.1",
  "no_auth": true,
  "private_targets": true,
  "mode": "normal"
}
```

## Build And Smoke

From the repo root:

```bash
docker buildx build \
  --platform linux/arm64 \
  --load \
  -t hacker-bob-agentcore:demo \
  -f infra/runner/Dockerfile .

docker image inspect hacker-bob-agentcore:demo \
  --format '{{.Architecture}} {{.Size}} {{.Config.User}}'
```

The architecture must be `arm64`, user must be `node`, and size must be below
AgentCore's 2048 MB image limit.

Local server smoke without invoking Claude:

```bash
docker run --rm -d \
  --name hb-agentcore-local \
  -p 8080:8080 \
  -e HOME=/tmp/bob-home \
  -e BOB_BUILTIN_DEMO_TARGET=true \
  hacker-bob-agentcore:demo

curl -fsS http://127.0.0.1:8080/ping

docker exec hb-agentcore-local node -e \
  "fetch('http://127.0.0.1:8081/healthz').then(r=>r.json()).then(x=>console.log(JSON.stringify(x)))"

docker rm -f hb-agentcore-local
```

## Files

- `agentcore-entrypoint.py` starts the optional loopback fixture, builds the
  `/bob-evaluate` prompt, injects a per-invocation MCP caller-auth token, runs
  Claude with timeout and budget guards, and returns either the last report
  snapshot or the GRADE-stage `awaiting_verifier_gate` sentinel.
- `Dockerfile` installs Node 22, Claude Code `2.1.202`, the AgentCore SDK,
  boto3, runtime dependencies, generated AgentCore Claude settings, and Bedrock
  model overrides.
- `bedrock-model-overrides.json` maps canonical Claude source model IDs to the
  Bedrock inference profile IDs.
- `callback-ssrf-guard.js` remains the callback allowlist guard.

The full AWS deployment runbook is in
`infra/aws/hacker-bob-stack/README.md`.
