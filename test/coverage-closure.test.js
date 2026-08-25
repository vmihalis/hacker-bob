"use strict";

// H1 — coverage-closure surfacing.
//
// The deterministic cell floor (A1-E1) is reconciled into coverage.jsonl; this
// node makes that coverage MEASURABLE in the human-facing audit output as a
// PURE, non-gating annotation (annotate-don't-gate, like the CVSS/CWE layer).
// These tests pin: (1) the covered/total/uncovered stat math; (2) the grade
// verdict carry/omit + markdown line; (3) the report.md section. Legacy/surface-
// only sessions (no cell floor) must stay byte-identical — no annotation.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { coverageClosureStat } = require("../mcp/core/frontier/coverage-closure.js");
const { appendFrontierEvent } = require("../mcp/core/frontier/frontier-events.js");
const { materializeFrontier } = require("../mcp/core/frontier/frontier-materializer.js");
const { logCellCoverage } = require("../mcp/core/frontier/coverage.js");
const {
  normalizeGradeVerdictDocument,
  renderGradeVerdictMarkdown,
} = require("../mcp/core/grade-verdict-store.js");
const composeReportTool = require("../mcp/tools/compose-report.js");
const { planCellsForSurface } = require("../mcp/core/session/assignment-brief.js");
const {
  reportMarkdownPath,
  sessionDir,
  verificationRoundPaths,
} = require("../mcp/core/io/paths.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-coverage-closure-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    try { fs.rmSync(home, { recursive: true, force: true }); } catch {}
  }
}

// Seed an OSS surface and materialize its deterministic cell floor (3 sanitizers
// x 3 input classes = 9 reachable cells, no auth axis). Returns the surface id.
function seedOssCellFloor(domain) {
  appendFrontierEvent({
    target_domain: domain,
    kind: "surface.observed",
    ts: "2026-05-31T00:00:00.000Z",
    surface_id: "surface:harness-x",
    payload: { title: "harness-x", surface_type: "oss_native_code" },
  });
  materializeFrontier(domain, { write: true });
  const { writeQueuePolicy, normalizeQueuePolicy, DEFAULT_QUEUE_POLICY } = require("../mcp/core/io/queue-policy.js");
  // Lift the per-surface child cap so all 9 floor cells materialize as nodes.
  writeQueuePolicy(domain, normalizeQueuePolicy({ ...DEFAULT_QUEUE_POLICY, max_spawn_children: 64 }));
  const floor = require("../mcp/tools/materialize-cell-floor.js").handler;
  JSON.parse(floor({ target_domain: domain }));
  return "surface:harness-x";
}

function seedFinalRound(domain, results) {
  const dir = sessionDir(domain);
  fs.mkdirSync(dir, { recursive: true });
  const paths = verificationRoundPaths(domain, "final");
  fs.writeFileSync(paths.json, JSON.stringify({
    target_domain: domain,
    round: "final",
    notes: null,
    results,
    written_at: "2026-05-31T00:00:00.000Z",
  }));
}

function baseGradeDoc(domain, extra = {}) {
  return {
    version: 1,
    target_domain: domain,
    verdict: "SKIP",
    total_score: 0,
    findings: [],
    feedback: null,
    claim_freeze_id: null,
    ...extra,
  };
}

// ─── stat math ─────────────────────────────────────────────────────────────

test("coverageClosureStat is vacuous (inactive) when the session has no cell floor", () => {
  withTempHome(() => {
    const domain = "h1-no-floor.example.com";
    const stat = coverageClosureStat(domain);
    assert.deepEqual(stat, {
      cell_floor_active: false,
      covered_cells: 0,
      total_reachable_cells: 0,
      uncovered_reachable_cells: 0,
    });
  });
});

test("coverageClosureStat reports the true reachable floor and reconciled coverage", () => {
  withTempHome(() => {
    const domain = "h1-floor.example.com";
    const surfaceId = seedOssCellFloor(domain);

    // Fresh floor: 9 reachable cells (3 sanitizer x 3 input class), 0 covered.
    const before = coverageClosureStat(domain);
    assert.equal(before.cell_floor_active, true);
    assert.equal(before.total_reachable_cells, 9);
    assert.equal(before.covered_cells, 0);
    assert.equal(before.uncovered_reachable_cells, 9);

    // Reconcile ONE cell (exactly what bob_finalize_node does on a verified cell).
    logCellCoverage({
      target_domain: domain,
      surface_id: surfaceId,
      bug_class: "asan",
      auth_profile: "value_profile",
      status: "tested",
      evidence_summary: "probed",
    });

    const after = coverageClosureStat(domain);
    assert.equal(after.cell_floor_active, true);
    assert.equal(after.total_reachable_cells, 9, "the denominator is the full reachable floor, not the budgeted slice");
    assert.equal(after.covered_cells, 1, "the reconciled cell counts as covered");
    assert.equal(after.uncovered_reachable_cells, 8);
    // total == covered + uncovered holds exactly (hard cap => no budget pruning).
    assert.equal(after.covered_cells + after.uncovered_reachable_cells, after.total_reachable_cells);
  });
});

// ─── grade verdict carry / omit / render ─────────────────────────────────────

test("the grade normalizer carries coverage_closure when present and validates it", () => {
  const doc = baseGradeDoc("h1-grade.example.com", {
    coverage_closure: {
      cell_floor_active: true,
      covered_cells: 1,
      total_reachable_cells: 9,
      uncovered_reachable_cells: 8,
    },
  });
  const normalized = normalizeGradeVerdictDocument(doc);
  assert.deepEqual(normalized.coverage_closure, {
    cell_floor_active: true,
    covered_cells: 1,
    total_reachable_cells: 9,
    uncovered_reachable_cells: 8,
  });
});

test("the grade normalizer OMITS coverage_closure for legacy verdicts (byte-identical shape)", () => {
  const normalized = normalizeGradeVerdictDocument(baseGradeDoc("h1-legacy.example.com"));
  assert.ok(!("coverage_closure" in normalized), "legacy/surface-only verdicts gain no new key");
});

test("renderGradeVerdictMarkdown shows the coverage line only when the stat is present", () => {
  const withStat = renderGradeVerdictMarkdown(baseGradeDoc("h1-md.example.com", {
    coverage_closure: {
      cell_floor_active: true,
      covered_cells: 1,
      total_reachable_cells: 9,
      uncovered_reachable_cells: 8,
    },
  }));
  assert.match(withStat, /Coverage closure \(informational\): 1\/9 reachable cells covered \(8 uncovered\)/);

  const without = renderGradeVerdictMarkdown(baseGradeDoc("h1-md.example.com"));
  assert.doesNotMatch(without, /Coverage closure/);
});

// ─── report.md section (full handler) ────────────────────────────────────────

test("bob_compose_report renders the coverage-closure section when a cell floor exists", () => {
  withTempHome(() => {
    const domain = "h1-report.example.com";
    const surfaceId = seedOssCellFloor(domain);
    logCellCoverage({
      target_domain: domain,
      surface_id: surfaceId,
      bug_class: "asan",
      auth_profile: "value_profile",
      status: "tested",
      evidence_summary: "probed",
    });
    seedFinalRound(domain, [{
      finding_id: "F-1",
      disposition: "confirmed",
      severity: "high",
      reportable: true,
      reasoning: "Confirmed",
      repro_steps: ["step 1"],
      evidence_refs: ["frontier_event:e1"],
    }]);

    const result = JSON.parse(composeReportTool.handler({
      target_domain: domain,
      sections: [{
        kind: "impact",
        heading: "Impact Summary",
        prose: "An attacker can crash the parser with a crafted input.",
        provenance: "bob_verified",
        evidence_refs: ["verification_round:final:F-1"],
      }],
    }));
    assert.equal(result.coverage_closure_rendered, true);
    const rendered = fs.readFileSync(reportMarkdownPath(domain), "utf8");
    assert.match(rendered, /## Coverage closure \(informational\)/);
    assert.match(rendered, /\*\*Reachable cells covered:\*\* 1\/9 \(8 uncovered\)/);
  });
});

test("bob_compose_report renders NO coverage section for a session with no cell floor", () => {
  withTempHome(() => {
    const domain = "h1-report-nofloor.example.com";
    seedFinalRound(domain, [{
      finding_id: "F-1",
      disposition: "confirmed",
      severity: "high",
      reportable: true,
      reasoning: "Confirmed",
      repro_steps: ["step 1"],
      evidence_refs: ["frontier_event:e1"],
    }]);

    const result = JSON.parse(composeReportTool.handler({
      target_domain: domain,
      sections: [{
        kind: "impact",
        heading: "Impact Summary",
        prose: "An attacker can crash the parser with a crafted input.",
        provenance: "bob_verified",
        evidence_refs: ["verification_round:final:F-1"],
      }],
    }));
    assert.equal(result.coverage_closure_rendered, false);
    const rendered = fs.readFileSync(reportMarkdownPath(domain), "utf8");
    assert.doesNotMatch(rendered, /Coverage closure/);
  });
});

// Review round-3 CRITICAL: the prune computed covered = (tested|blocked) - unfinished,
// so a `blocked` cell with a needs_auth/promising/requeue SIBLING row (the exact state a
// stuck cell is in when it fails its witness) was filtered back into "uncovered" — the
// stuck-cell auto-block wrote `blocked` but the gate still counted it, wedging closure.
// `blocked` must DOMINATE an unfinished sibling; `tested` must not (still re-spawnable).
test("prune: blocked dominates an unfinished sibling so an auto-blocked stuck cell is retired", () => {
  withTempHome(() => {
    const plan = planCellsForSurface({
      domain: "prune-blocked.example.com",
      surfaceObj: { id: "surface:api", bug_class_hints: ["idor"] },
      surfaceId: "surface:api",
      coverageSummary: {
        blocked: [{ bug_class: "idor", auth_profile: "" }],
        needs_auth: [{ bug_class: "idor", auth_profile: "" }],
      },
      remainingDepth: 1,
      maxChildren: 8,
    });
    assert.equal(plan, null, "the only cell is blocked → covered despite the unfinished sibling → nothing left uncovered");
  });
});

test("prune: a tested cell with an unfinished sibling stays re-spawnable (unchanged semantics)", () => {
  withTempHome(() => {
    const plan = planCellsForSurface({
      domain: "prune-tested.example.com",
      surfaceObj: { id: "surface:api", bug_class_hints: ["idor"] },
      surfaceId: "surface:api",
      coverageSummary: {
        tested: [{ bug_class: "idor", auth_profile: "" }],
        needs_auth: [{ bug_class: "idor", auth_profile: "" }],
      },
      remainingDepth: 1,
      maxChildren: 8,
    });
    assert.ok(plan && plan.children.length > 0, "tested + unfinished is NOT pruned — an in-progress success re-spawns");
  });
});
