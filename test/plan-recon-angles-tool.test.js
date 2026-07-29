"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const planReconAngles = require("../mcp/lib/tools/plan-recon-angles.js");

function withEnv(overrides, fn) {
  const previous = {};
  for (const key of Object.keys(overrides)) {
    previous[key] = process.env[key];
    if (overrides[key] === undefined) delete process.env[key];
    else process.env[key] = overrides[key];
  }
  try {
    return fn();
  } finally {
    for (const key of Object.keys(overrides)) {
      if (previous[key] === undefined) delete process.env[key];
      else process.env[key] = previous[key];
    }
  }
}

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "recon-angle-tool-"));
  process.env.HOME = tempHome;
  try {
    return fn(tempHome);
  } finally {
    if (previousHome === undefined) delete process.env.HOME;
    else process.env.HOME = previousHome;
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
}

test("registry metadata: read-only, orchestrator-only, no network, writes nothing", () => {
  assert.equal(planReconAngles.name, "bob_plan_recon_angles");
  assert.equal(planReconAngles.mutating, false);
  assert.equal(planReconAngles.network_access, false);
  assert.equal(planReconAngles.browser_access, false);
  assert.equal(planReconAngles.scope_required, false);
  assert.deepEqual(planReconAngles.role_bundles, ["orchestrator"]);
  assert.deepEqual(planReconAngles.session_artifacts_written, []);
  assert.equal(typeof planReconAngles.handler, "function");
  assert.equal(planReconAngles.inputSchema.required.includes("target_domain"), true);
});

test("requires target_domain", () => {
  assert.throws(() => planReconAngles.handler({}), /target_domain/);
});

test("self-managing host (claude) with no session/ledger fans out all four angles", () => {
  withTempHome(() => {
    withEnv({ BOB_CLIENT: "claude" }, () => {
      const out = JSON.parse(planReconAngles.handler({ target_domain: "example.com" }));
      assert.equal(out.host_id, "claude");
      assert.equal(out.plan.mode, "fanout");
      assert.deepEqual(out.plan.angles.map((a) => a.id), [
        "host_family",
        "urls",
        "nuclei",
        "js_jwt",
      ]);
      // empty ledger -> total_spawned 0; default policy max_total_spawned_agents null
      assert.equal(out.governor.total_spawned, 0);
    });
  });
});

test("unknown host fail-closes to a single sequential agent (no over-spawn)", () => {
  withTempHome(() => {
    withEnv({ BOB_CLIENT: undefined, CLAUDE_PROJECT_DIR: undefined }, () => {
      const out = JSON.parse(planReconAngles.handler({ target_domain: "example.com" }));
      assert.equal(out.host_id, "unknown");
      assert.equal(out.plan.mode, "sequential");
      assert.equal(out.plan.degrade_reason, "host_pool_finite");
      // RANK != BOUND: all four angles still listed even when degraded.
      assert.deepEqual(out.plan.angles.map((a) => a.id), [
        "host_family",
        "urls",
        "nuclei",
        "js_jwt",
      ]);
    });
  });
});

test("kimi host fail-closes to sequential", () => {
  withTempHome(() => {
    withEnv({ BOB_CLIENT: "kimi" }, () => {
      const out = JSON.parse(planReconAngles.handler({ target_domain: "example.com" }));
      assert.equal(out.host_id, "kimi");
      assert.equal(out.plan.mode, "sequential");
      assert.equal(out.plan.degrade_reason, "host_pool_finite");
    });
  });
});

test("deep_mode read from persisted session state enriches the urls angle", () => {
  withTempHome((home) => {
    const dir = path.join(home, "hacker-bob-sessions", "example.com");
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(
      path.join(dir, "state.json"),
      JSON.stringify({
        target: "example.com",
        target_url: "https://example.com",
        deep_mode: true,
      }),
      "utf8",
    );
    withEnv({ BOB_CLIENT: "claude" }, () => {
      const out = JSON.parse(planReconAngles.handler({ target_domain: "example.com" }));
      assert.equal(out.deep_mode, true);
      const urls = out.plan.angles.find((a) => a.id === "urls");
      assert.equal(urls.deep, true);
    });
  });
});

test("output is deterministic for the same session + host", () => {
  withTempHome(() => {
    withEnv({ BOB_CLIENT: "claude" }, () => {
      const a = JSON.parse(planReconAngles.handler({ target_domain: "example.com" }));
      const b = JSON.parse(planReconAngles.handler({ target_domain: "example.com" }));
      assert.deepEqual(a, b);
    });
  });
});
