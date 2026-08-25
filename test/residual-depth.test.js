"use strict";

// E2 — residual-anomaly depth trigger. A high/medium-band residual flags a
// surface (token overlap); each COVERED cell on it is re-proposed as a Tier-2
// depth re-probe. Diagnostic, default-off, non-gating: a Tier-2 re-probe is
// dispatched after all Tier-1 breadth (C1) and never blocks closure.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { deriveResidualDepthReprobes, reprobeCellKey } = require("../mcp/core/belief/residual-depth.js");
const { appendFrontierEvent } = require("../mcp/core/frontier/frontier-events.js");
const { materializeFrontier } = require("../mcp/core/frontier/frontier-materializer.js");
const { logCellCoverage } = require("../mcp/core/frontier/coverage.js");
const { writeBeliefSignalScratch } = require("../mcp/core/belief/authority.js");
const { writeQueuePolicy, normalizeQueuePolicy, DEFAULT_QUEUE_POLICY } = require("../mcp/core/io/queue-policy.js");
const { materializeTaskGraph } = require("../mcp/core/waves/task-graph-materializer.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-residual-depth-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    try { fs.rmSync(home, { recursive: true, force: true }); } catch {}
  }
}

function seedSurface(domain, surfaceId, title) {
  appendFrontierEvent({
    target_domain: domain,
    kind: "surface.observed",
    ts: "2026-05-31T00:00:00.000Z",
    surface_id: surfaceId,
    payload: { title: title || surfaceId },
  });
  materializeFrontier(domain, { write: true });
}

function seedResidualAnomaly(domain, { band = "high", effectId = "effect:billing:unauth_succeeds" } = {}) {
  return writeBeliefSignalScratch({
    target_domain: domain,
    kind: "belief_signal",
    source: "test#residual-depth",
    provenance: "residual_anomaly",
    artifact_ref: "belief_sample:test",
    role: "diagnostic",
    payload: {
      residual_hash: "deadbeefcafe1234abcd5678",
      residual_band: band,
      decomposition: [
        {
          variable_id: "BV-x",
          variable_type: "effective_permission",
          scope: { effect_id: effectId, policy_gate_id: "policy_gate:owner", principal_id: "principal:attacker" },
        },
      ],
    },
  });
}

test("E2: no residual signal yields no depth re-probes", () => {
  withTempHome(() => {
    assert.deepEqual(deriveResidualDepthReprobes("e2-none.example.com"), []);
  });
});

test("E2: a high-band residual re-probes the covered cells on a flagged surface", () => {
  withTempHome(() => {
    const domain = "e2-reprobe.example.com";
    seedSurface(domain, "surface:billing", "billing");
    // A covered cell on the surface the residual will flag (token 'billing').
    logCellCoverage({ target_domain: domain, surface_id: "surface:billing", bug_class: "idor", auth_profile: "admin", status: "tested", evidence_summary: "probed" });
    seedResidualAnomaly(domain, { band: "high" });

    const reprobes = deriveResidualDepthReprobes(domain);
    assert.equal(reprobes.length, 1, "the covered cell on the flagged surface is re-probed");
    const r = reprobes[0];
    assert.equal(r.surface_id, "surface:billing");
    assert.equal(r.bug_class, "idor");
    assert.equal(r.auth_profile, "admin");
    assert.equal(r.tier, 2);
    // The re-probe cell_key carries the reprobe discriminator → a distinct node.
    assert.equal(r.cell_key, reprobeCellKey("surface:billing", "idor", "admin", "deadbeefcafe"));
    assert.notEqual(r.cell_key, JSON.stringify(["surface:billing", "", "", "idor", "admin"]));
  });
});

test("E2: a low-band residual does NOT re-probe (band filter)", () => {
  withTempHome(() => {
    const domain = "e2-lowband.example.com";
    seedSurface(domain, "surface:billing", "billing");
    logCellCoverage({ target_domain: domain, surface_id: "surface:billing", bug_class: "idor", auth_profile: "admin", status: "tested", evidence_summary: "probed" });
    seedResidualAnomaly(domain, { band: "low" });
    assert.deepEqual(deriveResidualDepthReprobes(domain), []);
  });
});

test("E2: a residual that matches no surface yields no re-probe", () => {
  withTempHome(() => {
    const domain = "e2-nomatch.example.com";
    seedSurface(domain, "surface:billing", "billing");
    logCellCoverage({ target_domain: domain, surface_id: "surface:billing", bug_class: "idor", auth_profile: "admin", status: "tested", evidence_summary: "probed" });
    // The residual flags an unrelated effect — no token overlaps 'billing'.
    seedResidualAnomaly(domain, { band: "high", effectId: "effect:payments:zzz" });
    assert.deepEqual(deriveResidualDepthReprobes(domain), []);
  });
});

test("E2: bob_materialize_cell_floor mints a Tier-2 re-probe only when the flag is ON", () => {
  withTempHome(() => {
    const domain = "e2-floor.example.com";
    seedSurface(domain, "surface:billing", "billing");
    logCellCoverage({ target_domain: domain, surface_id: "surface:billing", bug_class: "idor", auth_profile: "admin", status: "tested", evidence_summary: "probed" });
    seedResidualAnomaly(domain, { band: "high" });
    const floor = require("../mcp/tools/materialize-cell-floor.js").handler;

    // Flag explicitly OFF: no residual read, no Tier-2 cell. The advisory is
    // default-ON; an explicit operator `false` disables the depth re-probe per session.
    writeQueuePolicy(domain, normalizeQueuePolicy({ ...DEFAULT_QUEUE_POLICY, residual_depth_reprobe_enabled: false }));
    const off = JSON.parse(floor({ target_domain: domain }));
    assert.equal(off.reprobe_cells_emitted, 0);

    // Flag ON: the covered cell is re-proposed as a Tier-2 depth re-probe.
    writeQueuePolicy(domain, normalizeQueuePolicy({ ...DEFAULT_QUEUE_POLICY, residual_depth_reprobe_enabled: true }));
    const on = JSON.parse(floor({ target_domain: domain }));
    assert.equal(on.reprobe_cells_emitted, 1);

    // The materialized re-probe node carries tier=2 (so C1 dispatches it last).
    const doc = materializeTaskGraph(domain, { write: true }).document;
    const reprobe = doc.nodes.find((n) => n.kind === "cell" && n.tier === 2);
    assert.ok(reprobe, "a Tier-2 cell node was materialized");
    assert.ok(reprobe.contract_hash, "the re-probe was auto-contracted like any cell");

    // The scheduler projection carries tier=2 to the candidate, so C1's tier key
    // dispatches the depth re-probe after all Tier-1 breadth (end-to-end plumb).
    const { selectNextExecutableNodes } = require("../mcp/core/waves/graph-scheduler.js");
    const sel = selectNextExecutableNodes(domain, normalizeQueuePolicy({ ...DEFAULT_QUEUE_POLICY }), 16);
    const selReprobe = sel.selected.find((n) => n.node_id === reprobe.node_id);
    assert.ok(selReprobe, "the contracted Tier-2 re-probe is dispatch-eligible");
    assert.equal(selReprobe.tier, 2, "the candidate carries tier=2 so C1 sorts it as depth");
  });
});

test("E2: re-running the floor on the same residual generation does not duplicate re-probes (idempotent)", () => {
  withTempHome(() => {
    const domain = "e2-idempotent.example.com";
    seedSurface(domain, "surface:billing", "billing");
    logCellCoverage({ target_domain: domain, surface_id: "surface:billing", bug_class: "idor", auth_profile: "admin", status: "tested", evidence_summary: "probed" });
    seedResidualAnomaly(domain, { band: "high" });
    writeQueuePolicy(domain, normalizeQueuePolicy({ ...DEFAULT_QUEUE_POLICY, residual_depth_reprobe_enabled: true }));
    const floor = require("../mcp/tools/materialize-cell-floor.js").handler;

    floor({ target_domain: domain });
    floor({ target_domain: domain });
    // The same residual_hash mints the same cell_key, so the materializer dedupes
    // to ONE Tier-2 node across re-runs — no unbounded accumulation per generation.
    const doc = materializeTaskGraph(domain, { write: true }).document;
    const tier2 = doc.nodes.filter((n) => n.kind === "cell" && n.tier === 2);
    assert.equal(tier2.length, 1, "a re-probe dedupes to one node within a residual generation");
  });
});

test("E2: an uncovered Tier-2 re-probe does NOT block closure (non-gating)", () => {
  withTempHome(() => {
    const domain = "e2-nongating.example.com";
    const { evaluateSchedulerPrecondition } = require("../mcp/core/waves/scheduler-preconditions.js");
    // surface:billing has no bug_class_hints -> ZERO Tier-1 floor cells; its only
    // coverage is one tested cell. A residual flags it -> a Tier-2 re-probe.
    seedSurface(domain, "surface:billing", "billing");
    logCellCoverage({ target_domain: domain, surface_id: "surface:billing", bug_class: "idor", auth_profile: "admin", status: "tested", evidence_summary: "probed" });
    seedResidualAnomaly(domain, { band: "high" });
    writeQueuePolicy(domain, normalizeQueuePolicy({ ...DEFAULT_QUEUE_POLICY, residual_depth_reprobe_enabled: true }));
    require("../mcp/tools/materialize-cell-floor.js").handler({ target_domain: domain });

    // A Tier-2 cell node now exists and is UNCOVERED — but the closure gate
    // counts only the Tier-1 floor (0 here), so it stays satisfied. The advisory
    // depth re-probe can never block CLAIM_FREEZE.
    const gate = evaluateSchedulerPrecondition("uncovered_reachable_cells", { target_domain: domain });
    assert.equal(gate.cell_floor_active, true, "a cell node exists (the Tier-2 re-probe)");
    assert.equal(gate.satisfied, true, "the uncovered Tier-2 re-probe does not block freeze");
    assert.equal(gate.uncovered_count, 0);
  });
});
