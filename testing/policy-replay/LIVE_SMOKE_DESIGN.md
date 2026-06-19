# Policy-Replay Live Smoke — Design (Task #140)

Status: design_only — implementation deferred pending CI OAuth credential infrastructure.

## 1. Problem

`v1.3.5` repaired the SDK + native-binary resolution path in
`testing/policy-replay/replay.mjs` (see `CHANGELOG.md:120` — bare specifier first,
then `createRequire(<workspace>/mcp/server.js).resolve("@anthropic-ai/claude-agent-sdk")`,
with the installer walking `optionalDependencies` so the current-platform
native package propagates into installed workspaces).

`test/install-smoke.test.js` asserts the static resolution contract. The
`policy-replay.test.js` cases all run with `--dry-run`, so the live
`query()` invocation path through `loadSdkQuery()` (`replay.mjs:100-120`) plus
the `query({ ... resume: sessionId, systemPrompt, ... })` stream consumer
(`replay.mjs:159-200`) is never exercised in CI.

Result: a regression that breaks the native binary at runtime
(e.g., SDK upgrade, optionalDependencies key rename, claude-code binary
relocation) can ship without CI catching it. The failure would only surface
when a user runs `/bob-debug` live replay against a real transcript.

## 2. Goal

Add a Claude-OAuth-gated end-to-end smoke test that:

1. Loads the SDK via `loadSdkQuery()` from an installed-workspace layout.
2. Invokes `query()` against a minimized, synthetic, in-repo case.
3. Asserts that `ok === true`, that a `stop_reason` is set, and that a
   `text_preview` was captured — i.e., the SDK actually emitted assistant
   messages and a `result` event.
4. Skips cleanly when no credential is present, so the default CI matrix
   (Node 20 / Node 22 on ubuntu-latest) is unaffected.

Non-goals: judging policy correctness on the live path (that is what the
`expected` field + `evaluateExpected()` already do offline). The live smoke
only asserts that the resolution + invocation path round-trips.

## 3. Credential surface

Two viable OAuth carriers:

### Option A — `ANTHROPIC_API_KEY` fallback
Cleanest CI surface. `@anthropic-ai/claude-agent-sdk` accepts an
`apiKey` option (or `ANTHROPIC_API_KEY` env). Store as a repo secret
`POLICY_REPLAY_ANTHROPIC_API_KEY`, exposed only on a separate workflow job
(see §5). Pros: trivial to wire. Cons: not a true OAuth path; misses bugs
specific to `~/.claude/oauth.json` lookup.

### Option B — Claude OAuth token file
Closer to what users actually run. Encode the credential JSON
(`~/.claude/oauth.json` shape: `{ access_token, refresh_token, expires_at, ... }`)
into a repo secret `POLICY_REPLAY_CLAUDE_OAUTH_JSON`, decode + write to
`$HOME/.claude/oauth.json` in the job. Pros: exercises the real lookup. Cons:
refresh-token rotation may invalidate the stored secret between runs; needs a
rotation runbook.

Recommendation: **Option A for v1.3.6**, with a follow-up task to layer
Option B once an OAuth-rotation cron exists.

## 4. Case fixture

Add `testing/policy-replay/cases/live-smoke-noop.json`:

- `agent_type`: `evaluator-agent`
- `failure_type`: `refusal`
- `expected`: `should_continue_safely`
- `transcript`: 4-event synthetic transcript identical in shape to the one in
  `test/policy-replay.test.js#transcript()` (authorized brief → tool_use →
  tool_result → refusal), with all targets set to `redacted.example`.
- `redaction.status`: `synthetic`.

The smoke does not need a real prompt: `.claude/agents/evaluator-agent.md`
is already in-tree and resolved by `resolvePromptPath()`.

## 5. CI wiring

New workflow `.github/workflows/policy-replay-live-smoke.yml`:

- Trigger: `workflow_dispatch` + `schedule` (weekly cron) — NOT on every PR,
  to bound credential exposure and API spend.
- Job: `live-smoke`, `runs-on: ubuntu-latest`, `if: ${{ secrets.POLICY_REPLAY_ANTHROPIC_API_KEY != '' }}`.
- Steps: checkout, setup-node 22, `npm ci`, then
  `node --test test/policy-replay-live-smoke.test.js`.
- Secret: `POLICY_REPLAY_ANTHROPIC_API_KEY` (env-injected).

No change to `.github/workflows/ci.yml`. The live smoke stays out of the
default `npm test` graph; it is invoked directly by the dedicated workflow.

## 6. Test file shape

New `test/policy-replay-live-smoke.test.js`:

```js
const test = require("node:test");
const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const REPLAY = path.join(ROOT, "testing", "policy-replay", "replay.mjs");
const CASE = path.join(ROOT, "testing", "policy-replay", "cases", "live-smoke-noop.json");
const PROMPT = path.join(ROOT, ".claude", "agents", "evaluator-agent.md");

const hasCred = Boolean(process.env.ANTHROPIC_API_KEY);

test("policy-replay live smoke invokes SDK query() end-to-end", { skip: !hasCred }, () => {
  const output = execFileSync(
    process.execPath,
    [REPLAY, "--case", CASE, "--system", PROMPT],
    { cwd: ROOT, encoding: "utf8", env: process.env },
  );
  const parsed = JSON.parse(output);
  assert.equal(parsed.ok, true, `live replay failed: ${parsed.error}`);
  assert.ok(parsed.stop_reason, "missing stop_reason");
  assert.ok(parsed.text_preview, "missing text_preview");
});
```

The `skip: !hasCred` keeps the file safe to live in `test/` without
breaking the default `npm test` run (which has no credential), while still
being executable by the dedicated workflow.

## 7. Failure modes the smoke catches

1. `loadSdkQuery()` throws — SDK package missing or native binary not on
   `optionalDependencies` for the runner's platform/arch.
2. `query()` rejects synchronously — auth carrier malformed or rejected.
3. Stream completes with no `assistant` event — SDK API contract drift
   (message shape changed).
4. `result` event marked `is_error` without the `Reached maximum number of
   turns` carve-out — runtime regression.

## 8. Failure modes the smoke does NOT cover

- Policy correctness on novel prompts (existing offline `expected` tests).
- Tool-use round-trips through MCP (live smoke uses `tools: []`,
  `mcpServers: {}` to bound surface).
- Cross-platform native-binary coverage (workflow is ubuntu-only;
  darwin-arm64 / win32-x64 native binaries remain a static assertion in
  `install-smoke.test.js`). A future follow-up could matrix the live smoke
  across `ubuntu-latest` + `macos-latest`.

## 9. Operational runbook

1. Generate a scoped API key in the Anthropic console, low spend cap (e.g.,
   $5/month).
2. Add as repo secret `POLICY_REPLAY_ANTHROPIC_API_KEY`.
3. Trigger workflow_dispatch run; confirm green.
4. On rotation: regenerate key, update secret, dispatch.
5. On hard failure: page maintainer, investigate before the next release.

## 10. Estimated implementation scope

- 1 new test file (~40 LOC)
- 1 new case fixture (~30 LOC JSON)
- 1 new workflow file (~25 LOC YAML)
- 0 changes to `replay.mjs` (path already exists)
- README update: add §"Live smoke in CI" pointing at this design doc

Total: ~100 LOC across 4 files + README delta. Risk: medium (credential
handling, API spend, rotation surface). Bottleneck: not engineering — it is
acquiring the credential and committing to the rotation runbook. That is why
this task is `design_only` until that infrastructure decision is made.

## 11. Cross-refs

- `testing/policy-replay/replay.mjs:100-120` — `loadSdkQuery()` (path under test).
- `testing/policy-replay/replay.mjs:159-214` — `query()` invocation + stream consumer.
- `test/policy-replay.test.js` — existing dry-run coverage.
- `test/install-smoke.test.js` — existing static SDK + native-binary assertions.
- `CHANGELOG.md:66` — v1.3.6 follow-up promise.
- `CHANGELOG.md:120` — v1.3.5 fix that this smoke would protect.
