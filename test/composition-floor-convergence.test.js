"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { transitionEdgeToken } = require("../mcp/lib/assignment-brief.js");
const { TRANSITION_BUG_CLASS_AXIS } = require("../mcp/lib/capability-packs.js");
const { transitionCellKey } = require("../mcp/lib/capability-pack-derivation.js");
const { logCellCoverage, readCoverageRecordsFromJsonl } = require("../mcp/lib/coverage.js");
const { appendTransitionProposal } = require("../mcp/lib/task-graph-events.js");
const { handler: materializeCellFloor } = require("../mcp/lib/tools/materialize-cell-floor.js");

const PINNED_STUCK_CELL_EMISSION_THRESHOLD = 3;

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-composition-floor-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    try { fs.rmSync(home, { recursive: true, force: true }); } catch {}
  }
}

function proposal(targetDomain, from, to, kind) {
  return {
    target_domain: targetDomain,
    from_surface: from,
    to_surface: to,
    kind,
    trust_assumption: `${from} transfers trust to ${to}`,
  };
}

function seedTransitionProposals(targetDomain) {
  const edges = [
    proposal(targetDomain, "surface:login", "surface:api", "identity_propagation"),
    proposal(targetDomain, "surface:api", "surface:ledger", "value_movement"),
    proposal(targetDomain, "surface:ledger", "surface:admin", "trust_handoff"),
  ];
  for (const edge of edges) appendTransitionProposal(edge);
  return edges.map((edge) => ({
    from_surface: edge.from_surface,
    to_surface: edge.to_surface,
    kind: edge.kind,
    edge_token: transitionEdgeToken(edge.from_surface, edge.to_surface, edge.kind),
    bug_classes: TRANSITION_BUG_CLASS_AXIS[edge.kind].slice(),
  }));
}

function edgeCellCount(edges) {
  return edges.reduce((total, edge) => total + edge.bug_classes.length, 0);
}

function provenBound(edges) {
  return edgeCellCount(edges) + (PINNED_STUCK_CELL_EMISSION_THRESHOLD * edges.length);
}

function runFloor(targetDomain) {
  return JSON.parse(materializeCellFloor({ target_domain: targetDomain }));
}

function runUntilFixpoint(targetDomain, bound) {
  const passes = [];
  for (let pass = 1; pass <= bound; pass += 1) {
    const result = runFloor(targetDomain);
    passes.push(result);
    if (passes.length > 1) {
      const previous = passes[passes.length - 2];
      assert.ok(
        result.transition_cells_emitted <= previous.transition_cells_emitted,
        `transition emissions increased on pass ${pass}: ${previous.transition_cells_emitted} -> ${result.transition_cells_emitted}`,
      );
    }
    if (result.floor_at_fixpoint === true) return passes;
  }
  assert.fail(`composition floor did not reach fixpoint within bound ${bound}`);
}

function allAutoBlockedCells(passes) {
  return passes.flatMap((pass) => pass.auto_blocked_cells || []);
}

function coverageRowsForCell(targetDomain, surfaceId, bugClass) {
  return readCoverageRecordsFromJsonl(targetDomain).filter((record) => (
    record.surface_id === surfaceId
    && record.bug_class === bugClass
    && (record.auth_profile || "") === ""
  ));
}

test("composition edge floor reaches fixpoint through the shared stuck-cell backstop", () => {
  withTempHome(() => {
    const domain = "s5-composition-worst-case.example.com";
    const edges = seedTransitionProposals(domain);
    const initialPhi = edgeCellCount(edges);
    assert.equal(edges.length, 3);
    assert.ok(initialPhi >= 6, "the transition frontier must exercise a combinatorial edge-cell floor");

    const passes = runUntilFixpoint(domain, provenBound(edges));
    const last = passes[passes.length - 1];
    assert.equal(last.floor_at_fixpoint, true);
    assert.equal(last.tier1_cells_emitted, 0);
    assert.equal(last.transition_cells_emitted, 0);

    const blocked = allAutoBlockedCells(passes);
    assert.equal(blocked.length, initialPhi);
    for (const edge of edges) {
      for (const bugClass of edge.bug_classes) {
        const cellKey = transitionCellKey(edge.edge_token, bugClass);
        const row = blocked.find((cell) => cell.cell_key === cellKey);
        assert.ok(row, `expected ${cellKey} to close through the backstop`);
        assert.equal(row.surface_id, edge.edge_token);
        assert.equal(row.bug_class, bugClass);
        assert.equal(row.auth_profile, null);
        assert.equal(
          row.emissions,
          PINNED_STUCK_CELL_EMISSION_THRESHOLD,
          "the observed backstop threshold is pinned by the emitted row",
        );
        const coverageRows = coverageRowsForCell(domain, edge.edge_token, bugClass);
        assert.equal(coverageRows.filter((record) => record.status === "blocked").length, 1);
        assert.equal(coverageRows.filter((record) => record.status === "tested").length, 0);
      }
    }
    assert.equal(last.auto_blocked_cell_count, initialPhi);
  });
});

test("real terminal edge coverage is not mislabeled as an auto-blocked edge-cell", () => {
  withTempHome(() => {
    const domain = "s5-composition-covered.example.com";
    const edges = seedTransitionProposals(domain);
    const coveredEdge = edges[0];
    const coveredBugClass = coveredEdge.bug_classes[0];
    const siblingBugClass = coveredEdge.bug_classes[1];
    const coveredCellKey = transitionCellKey(coveredEdge.edge_token, coveredBugClass);
    const siblingCellKey = transitionCellKey(coveredEdge.edge_token, siblingBugClass);

    logCellCoverage({
      target_domain: domain,
      surface_id: coveredEdge.edge_token,
      bug_class: coveredBugClass,
      auth_profile: "",
      status: "tested",
      evidence_summary: "terminal edge coverage row written before the floor sweep",
    });

    const passes = runUntilFixpoint(domain, provenBound(edges));
    const blocked = allAutoBlockedCells(passes);
    assert.equal(
      blocked.some((cell) => cell.cell_key === coveredCellKey),
      false,
      "a tested edge-cell must be pruned as real coverage, not reported as backstop-blocked",
    );
    const sibling = blocked.find((cell) => cell.cell_key === siblingCellKey);
    assert.ok(sibling, "an uncovered sibling edge-cell must still close through the backstop");
    assert.equal(sibling.emissions, PINNED_STUCK_CELL_EMISSION_THRESHOLD);

    const coveredRows = coverageRowsForCell(domain, coveredEdge.edge_token, coveredBugClass);
    assert.equal(coveredRows.filter((record) => record.status === "tested").length, 1);
    assert.equal(coveredRows.filter((record) => record.status === "blocked").length, 0);

    const siblingRows = coverageRowsForCell(domain, coveredEdge.edge_token, siblingBugClass);
    assert.equal(siblingRows.filter((record) => record.status === "tested").length, 0);
    assert.equal(siblingRows.filter((record) => record.status === "blocked").length, 1);
  });
});

test("composition edge floor is vacuous on a clean session", () => {
  withTempHome(() => {
    const result = runFloor("s5-composition-clean.example.com");
    assert.equal(result.floor_at_fixpoint, true);
    assert.equal(result.tier1_cells_emitted, 0);
    assert.equal(result.transition_cells_emitted, 0);
    assert.deepEqual(result.auto_blocked_cells, []);
    assert.equal(result.auto_blocked_cell_count, 0);
  });
});
