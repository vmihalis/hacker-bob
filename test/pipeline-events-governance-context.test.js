"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  appendPipelineEventDirect,
  safeAppendPipelineEventDirect,
  safeAppendPipelineEventWithSessionLock,
  assertGovernanceContext,
} = require("../mcp/lib/pipeline-events.js");
const {
  buildGovernanceContext,
  buildGovernanceContextFromNucleus,
} = require("../mcp/lib/governance-context.js");
const {
  sessionDir,
  pipelineEventsJsonlPath,
  statePath,
} = require("../mcp/lib/paths.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-pipeline-governance-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function seedState(domain, overrides = {}) {
  const dir = sessionDir(domain);
  fs.mkdirSync(dir, { recursive: true });
  const state = {
    target: domain,
    target_url: `https://${domain}`,
    deep_mode: false,
    checkpoint_mode: "normal",
    block_internal_hosts: false,
    block_internal_hosts_source: "legacy_default",
    phase: "EVALUATE",
    lifecycle_state: "OPEN_FRONTIER",
    evaluation_wave: 0,
    pending_wave: null,
    total_findings: 0,
    explored: [],
    terminally_blocked: [],
    prereq_registry_snapshots: [],
    blocked_prereq_history: [],
    terminal_block_clear_history: [],
    dead_ends: [],
    waf_blocked_endpoints: [],
    lead_surface_ids: [],
    scope_exclusions: [],
    hold_count: 0,
    auth_status: "pending",
    egress_profile: "default",
    egress_region: null,
    proxy_configured: false,
    egress_profile_identity_hash: null,
    egress_profile_identity_version: null,
    egress_profile_identity_source: {
      proxy_url_source: "none",
      proxy_env_var: null,
      proxy_url_redacted: null,
      resolved_proxy: null,
    },
    egress_profile_identity_bound_at: null,
    egress_profile_identity_bind_source: null,
    egress_profile_legacy_migration: null,
    operator_note: null,
    verification_schema_version: null,
    verification_attempt_id: null,
    verification_snapshot_hash: null,
    verification_entered_at: null,
    ...overrides,
  };
  fs.writeFileSync(statePath(domain), `${JSON.stringify(state, null, 2)}\n`, "utf8");
  return state;
}

test("appendPipelineEventDirect throws when governance_context is absent", () => {
  withTempHome(() => {
    const domain = "missing-context.example";
    seedState(domain);
    assert.throws(
      () => appendPipelineEventDirect(domain, "report_written", {
        status: "written",
        source: "test",
        counts: { report_size_bytes: 1 },
      }),
      /governance_context is required/,
    );
  });
});

test("appendPipelineEventDirect throws when governance_context is null", () => {
  withTempHome(() => {
    const domain = "null-context.example";
    seedState(domain);
    assert.throws(
      () => appendPipelineEventDirect(domain, "report_written", {
        status: "written",
        source: "test",
        counts: { report_size_bytes: 1 },
      }, null),
      /governance_context is required/,
    );
  });
});

test("appendPipelineEventDirect throws when nucleus_hash is missing", () => {
  withTempHome(() => {
    const domain = "missing-nucleus-hash.example";
    seedState(domain);
    const partial = {
      lifecycle_state: "OPEN_FRONTIER",
      egress_identity_hash: "0".repeat(64),
    };
    assert.throws(
      () => appendPipelineEventDirect(domain, "report_written", {
        status: "written",
        source: "test",
        counts: { report_size_bytes: 1 },
      }, partial),
      /governance_context\.nucleus_hash is required/,
    );
  });
});

test("appendPipelineEventDirect throws when lifecycle_state is missing", () => {
  withTempHome(() => {
    const domain = "missing-lifecycle.example";
    seedState(domain);
    const partial = {
      nucleus_hash: "a".repeat(64),
      egress_identity_hash: "b".repeat(64),
    };
    assert.throws(
      () => appendPipelineEventDirect(domain, "report_written", {
        status: "written",
        source: "test",
        counts: { report_size_bytes: 1 },
      }, partial),
      /governance_context\.lifecycle_state is required/,
    );
  });
});

test("appendPipelineEventDirect throws when egress_identity_hash is missing", () => {
  withTempHome(() => {
    const domain = "missing-egress-hash.example";
    seedState(domain);
    const partial = {
      nucleus_hash: "a".repeat(64),
      lifecycle_state: "OPEN_FRONTIER",
    };
    assert.throws(
      () => appendPipelineEventDirect(domain, "report_written", {
        status: "written",
        source: "test",
        counts: { report_size_bytes: 1 },
      }, partial),
      /governance_context\.egress_identity_hash is required/,
    );
  });
});

test("appendPipelineEventDirect rejects ill-formed hashes", () => {
  withTempHome(() => {
    const domain = "bad-hash.example";
    seedState(domain);
    const context = {
      nucleus_hash: "not-a-hash",
      lifecycle_state: "OPEN_FRONTIER",
      egress_identity_hash: "b".repeat(64),
    };
    assert.throws(
      () => appendPipelineEventDirect(domain, "report_written", {
        status: "written",
        source: "test",
        counts: { report_size_bytes: 1 },
      }, context),
      /nucleus_hash must be a 64-char sha256 hex/,
    );
  });
});

test("appendPipelineEventDirect persists governance_context triple on the event", () => {
  withTempHome(() => {
    const domain = "happy-path.example";
    const state = seedState(domain);
    const governanceContext = buildGovernanceContext(state);
    const event = appendPipelineEventDirect(domain, "report_written", {
      status: "written",
      source: "test",
      counts: { report_size_bytes: 1 },
    }, governanceContext);
    assert.equal(event.nucleus_hash, governanceContext.nucleus_hash);
    assert.equal(event.egress_identity_hash, governanceContext.egress_identity_hash);
    assert.equal(event.lifecycle_state, governanceContext.lifecycle_state);

    const lines = fs.readFileSync(pipelineEventsJsonlPath(domain), "utf8")
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line));
    assert.equal(lines.length, 1);
    assert.equal(lines[0].nucleus_hash, governanceContext.nucleus_hash);
    assert.equal(lines[0].egress_identity_hash, governanceContext.egress_identity_hash);
    assert.equal(lines[0].lifecycle_state, governanceContext.lifecycle_state);
  });
});

test("safeAppendPipelineEventDirect returns null when governance_context is absent", () => {
  withTempHome(() => {
    const domain = "safe-missing.example";
    seedState(domain);
    const result = safeAppendPipelineEventDirect(domain, "report_written", {
      status: "written",
      source: "test",
      counts: { report_size_bytes: 1 },
    });
    assert.equal(result, null);
    assert.equal(fs.existsSync(pipelineEventsJsonlPath(domain)), false);
  });
});

test("safeAppendPipelineEventWithSessionLock returns null when governance_context is absent", () => {
  withTempHome(() => {
    const domain = "safe-lock-missing.example";
    seedState(domain);
    const result = safeAppendPipelineEventWithSessionLock(domain, "report_written", {
      status: "written",
      source: "test",
      counts: { report_size_bytes: 1 },
    });
    assert.equal(result, null);
    assert.equal(fs.existsSync(pipelineEventsJsonlPath(domain)), false);
  });
});

test("assertGovernanceContext accepts the canonical triple", () => {
  const context = {
    nucleus_hash: "a".repeat(64),
    lifecycle_state: "OPEN_FRONTIER",
    egress_identity_hash: "b".repeat(64),
  };
  assert.doesNotThrow(() => assertGovernanceContext(context));
});

test("buildGovernanceContext returns canonical triple from session state", () => {
  withTempHome(() => {
    const domain = "build-from-state.example";
    const state = seedState(domain);
    const context = buildGovernanceContext(state);
    assert.match(context.nucleus_hash, /^[0-9a-f]{64}$/);
    assert.equal(context.lifecycle_state, "OPEN_FRONTIER");
    assert.match(context.egress_identity_hash, /^[0-9a-f]{64}$/);
  });
});

test("buildGovernanceContextFromNucleus pulls fields from the nucleus document", () => {
  withTempHome(() => {
    const domain = "build-from-nucleus.example";
    const state = seedState(domain);
    const nucleus = require("../mcp/lib/governance-contracts.js").sessionNucleusFromState(state);
    const context = buildGovernanceContextFromNucleus(nucleus);
    assert.equal(context.nucleus_hash, nucleus.nucleus_hash);
    assert.equal(context.lifecycle_state, nucleus.lifecycle_state);
    assert.match(context.egress_identity_hash, /^[0-9a-f]{64}$/);
  });
});
