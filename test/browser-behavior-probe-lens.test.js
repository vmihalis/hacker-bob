"use strict";

// Plane T cycle T.4 — `browser_behavior_probe` task lens.
//
// T.4 adds a new task_lens value (`browser_behavior_probe`) distinct from the
// HTTP-shaped `behavior_probe`. The brief renderer must:
//
//   1. Enumerate the new value in `TASK_LENSES` and accept it via the
//      `normalizeTaskLens` enum guard. Unknown lens values must still throw.
//
//   2. When `task_lens === "browser_behavior_probe"`, the rendered assignment
//      brief leads with the Patchright session workflow stanza naming
//      `bob_browser_session_start`, `bob_browser_snapshot`, and
//      `bob_browser_evaluate`. Under the HTTP `behavior_probe` lens the same
//      surface must NOT carry that stanza (regression guard).
//
//   3. Technique packs gain an optional `lens_affinity` field. Under
//      `browser_behavior_probe` packs whose affinity matches are foregrounded
//      under `selected[]`; everything else is demoted into
//      `other_applicable[]`. This is parameter wiring — no live browser-
//      affined pack ships in T.4; the unit-test layer pins the partition
//      function directly using synthesized pack records.
//
// Determinism: all assertions hold across repeated calls after normalizing
// per-render untrusted-content envelope nonces.

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  TASK_LENSES,
  isTaskLens,
  normalizeTaskLens,
} = require("../mcp/lib/task-lenses.js");
const {
  BROWSER_BEHAVIOR_PROBE_LENS,
  BROWSER_BEHAVIOR_PROBE_WORKFLOW_TEXT,
  partitionTechniquePacksByLensAffinity,
  readAssignmentBrief,
} = require("../mcp/lib/assignment-brief.js");
const {
  attackSurfacePath,
  sessionDir,
  statePath,
} = require("../mcp/lib/paths.js");
const {
  startWave,
} = require("../mcp/lib/waves.js");
const {
  writeFileAtomic,
} = require("../mcp/lib/storage.js");

// ── Fixture helpers ──────────────────────────────────────────────────────────

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bob-browser-lens-"));
  process.env.HOME = tempHome;
  try {
    return fn(tempHome);
  } finally {
    if (previousHome === undefined) {
      delete process.env.HOME;
    } else {
      process.env.HOME = previousHome;
    }
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
}

function uniqueDomain(prefix) {
  return `${prefix}-${crypto.randomBytes(4).toString("hex")}.example`;
}

function normalizeEnvelopeNonces(text) {
  return String(text).replace(/nonce=[0-9a-f]{32}/g, "nonce=<nonce>");
}

function seedSessionState(domain) {
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  writeFileAtomic(statePath(domain), `${JSON.stringify({
    target: domain,
    target_url: `https://${domain}`,
    deep_mode: false,
    phase: "EVALUATE",
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
    operator_note: null,
    verification_schema_version: null,
    verification_attempt_id: null,
    verification_snapshot_hash: null,
    verification_entered_at: null,
  }, null, 2)}\n`);
}

function seedAttackSurface(domain, surfaces) {
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  writeFileAtomic(attackSurfacePath(domain), `${JSON.stringify({ surfaces }, null, 2)}\n`);
}

function baseWebSurface(id, overrides = {}) {
  return {
    id,
    surface_type: "api",
    hosts: ["https://api.example"],
    title: "Web surface",
    description: "Web evaluator surface for browser_behavior_probe lens test.",
    endpoint_pattern: "/api",
    tech_stack: ["Express"],
    endpoints: ["/api/users", "/api/login"],
    interesting_params: ["id"],
    nuclei_hits: [],
    bug_class_hints: [],
    high_value_flows: [],
    evidence: [],
    ...overrides,
  };
}

function startWaveWithLens(domain, surfaceId, lens) {
  return JSON.parse(startWave({
    target_domain: domain,
    wave_number: 1,
    assignments: [{ agent: "a1", surface_id: surfaceId, task_lens: lens }],
  }));
}

function readBriefAsJson(domain) {
  return JSON.parse(readAssignmentBrief({
    target_domain: domain,
    wave: "w1",
    agent: "a1",
  }));
}

// ── TASK_LENSES enum ─────────────────────────────────────────────────────────

test("TASK_LENSES enum includes browser_behavior_probe alongside behavior_probe", () => {
  assert.ok(
    TASK_LENSES.includes("browser_behavior_probe"),
    "TASK_LENSES must enumerate browser_behavior_probe",
  );
  assert.ok(
    TASK_LENSES.includes("behavior_probe"),
    "TASK_LENSES must still enumerate the HTTP behavior_probe lens (regression)",
  );
  // browser_behavior_probe slotted next to behavior_probe so a human reading
  // the enum sees the pair together. Pin the relative order — the HTTP lens
  // comes first; the browser sibling comes second.
  const httpIdx = TASK_LENSES.indexOf("behavior_probe");
  const browserIdx = TASK_LENSES.indexOf("browser_behavior_probe");
  assert.equal(browserIdx, httpIdx + 1, "browser_behavior_probe must sit immediately after behavior_probe");
});

test("isTaskLens recognises browser_behavior_probe", () => {
  assert.equal(isTaskLens("browser_behavior_probe"), true);
  assert.equal(isTaskLens("behavior_probe"), true);
  assert.equal(isTaskLens("not_a_real_lens"), false);
});

test("normalizeTaskLens accepts browser_behavior_probe and rejects unknowns", () => {
  assert.equal(
    normalizeTaskLens("browser_behavior_probe"),
    "browser_behavior_probe",
    "normalizer must round-trip the new lens value",
  );
  // Regression — existing HTTP lens still normalises.
  assert.equal(normalizeTaskLens("behavior_probe"), "behavior_probe");
  // Unknown lens values throw via the shared enum guard. Pin the message shape
  // loosely (validation.js owns the exact wording).
  assert.throws(
    () => normalizeTaskLens("xss_browser_probe"),
    /lens/,
    "normalizer must reject unknown lens values",
  );
});

// ── Lens-aware brief: Patchright stanza under browser_behavior_probe ─────────

test("brief under task_lens=browser_behavior_probe leads with Patchright workflow", () => {
  withTempHome(() => {
    const domain = uniqueDomain("brief-browser-lens");
    const surfaceId = "web-browser";
    seedSessionState(domain);
    seedAttackSurface(domain, [baseWebSurface(surfaceId, {
      hosts: ["https://browser.example"],
    })]);
    startWaveWithLens(domain, surfaceId, "browser_behavior_probe");

    const brief = readBriefAsJson(domain);
    assert.equal(
      brief.run_context && typeof brief.run_context === "object",
      true,
      "brief must carry a run_context object",
    );
    assert.equal(typeof brief.browser_workflow, "string", "browser_workflow slice must render under browser_behavior_probe");

    // Spec-required Patchright session driver tool names — the brief must
    // mention each so the evaluator picks the browser-shaped path on first read.
    assert.match(brief.browser_workflow, /bob_browser_session_start/, "must name bob_browser_session_start");
    assert.match(brief.browser_workflow, /bob_browser_snapshot/, "must name bob_browser_snapshot");
    assert.match(brief.browser_workflow, /bob_browser_evaluate/, "must name bob_browser_evaluate");

    // Browser-shaped surface vocabulary must appear in the intro stanza.
    assert.match(brief.browser_workflow, /DOM/, "must name DOM source/sink");
    assert.match(brief.browser_workflow, /postMessage/, "must name postMessage handlers");
    assert.match(brief.browser_workflow, /WebAuthn/, "must name WebAuthn ceremonies");
    assert.match(brief.browser_workflow, /OAuth/, "must name OAuth callbacks");
    assert.match(brief.browser_workflow, /ServiceWorker/, "must name ServiceWorker");
    assert.match(brief.browser_workflow, /IndexedDB/, "must name IndexedDB");
    // Phrase "multi-step in-session flows" may span a line break in the
    // rendered stanza; match the two adjectives separately so a future
    // wrap-width change does not break the assertion.
    assert.match(brief.browser_workflow, /multi-step/, "must name multi-step flows");
    assert.match(brief.browser_workflow, /in-session/, "must name in-session flows");

    // The static stanza constant must be exactly what landed in the brief —
    // partner test ensures the constant is the rendering target.
    assert.equal(brief.browser_workflow, BROWSER_BEHAVIOR_PROBE_WORKFLOW_TEXT);
  });
});

test("brief under task_lens=behavior_probe does NOT lead with Patchright workflow (regression)", () => {
  withTempHome(() => {
    const domain = uniqueDomain("brief-http-lens-regression");
    const surfaceId = "web-http";
    seedSessionState(domain);
    seedAttackSurface(domain, [baseWebSurface(surfaceId, {
      hosts: ["https://http.example"],
    })]);
    startWaveWithLens(domain, surfaceId, "behavior_probe");

    const brief = readBriefAsJson(domain);
    assert.equal(brief.run_context.target_domain, domain);
    assert.equal(
      Object.prototype.hasOwnProperty.call(brief, "browser_workflow"),
      false,
      "browser_workflow slice must be absent under HTTP behavior_probe",
    );

    // The Patchright session driver tool names must NOT appear in the brief
    // (they could still appear on a stop-list elsewhere, but not in slice text).
    // Serialise the full brief and check that no Patchright tool name leaks
    // into the HTTP-lens projection.
    const raw = JSON.stringify(brief);
    assert.ok(!raw.includes("bob_browser_session_start"), "Patchright session tool must not surface under behavior_probe");
    assert.ok(!raw.includes("bob_browser_snapshot"), "Patchright snapshot tool must not surface under behavior_probe");
    assert.ok(!raw.includes("bob_browser_evaluate"), "Patchright evaluate tool must not surface under behavior_probe");
  });
});

// ── lens_affinity partition ──────────────────────────────────────────────────

test("partitionTechniquePacksByLensAffinity foregrounds browser-affined packs under browser_behavior_probe", () => {
  // Synthesize two packs: one with lens_affinity targeting the new lens, one
  // without affinity. Order in the source mimics what `selectedTechniquePacks`
  // would carry to the brief renderer.
  const browserAffined = {
    id: "dom-source-sink",
    title: "DOM source/sink probe",
    score: 12,
    matched: ["tech:spa"],
    summary: { guidance: ["g"], payload_hints: ["p"] },
    summary_limits: { guidance: {}, payload_hints: {} },
    estimated_tokens: { summary: 500, full: 1500 },
    lens_affinity: ["browser_behavior_probe"],
  };
  const httpOnly = {
    id: "generic-rest-api",
    title: "REST/API authorization",
    score: 8,
    matched: ["tech:api"],
    summary: { guidance: ["g"], payload_hints: ["p"] },
    summary_limits: { guidance: {}, payload_hints: {} },
    estimated_tokens: { summary: 500, full: 1500 },
  };
  const partitioned = partitionTechniquePacksByLensAffinity(
    [browserAffined, httpOnly],
    "browser_behavior_probe",
  );
  // Foregrounded: only the browser-affined pack survives as a full summary.
  assert.equal(partitioned.selected.length, 1);
  assert.equal(partitioned.selected[0].id, "dom-source-sink");
  // Demoted: the HTTP-only pack lands in other_applicable with a shorter
  // snippet (no guidance / payload_hints).
  assert.equal(partitioned.other_applicable.length, 1);
  assert.equal(partitioned.other_applicable[0].id, "generic-rest-api");
  assert.equal(partitioned.other_applicable[0].title, "REST/API authorization");
  assert.equal(
    Object.prototype.hasOwnProperty.call(partitioned.other_applicable[0], "summary"),
    false,
    "demoted snippet must omit the full summary blob",
  );
  assert.equal(
    Object.prototype.hasOwnProperty.call(partitioned.other_applicable[0], "estimated_tokens"),
    false,
    "demoted snippet must omit estimated_tokens",
  );
});

test("partitionTechniquePacksByLensAffinity is a no-op under other lenses", () => {
  // Under any lens that is not `browser_behavior_probe` the partition is a
  // no-op: every input pack lands in `selected` and `other_applicable` is
  // empty. This is the regression guard — adding the partition must not
  // alter the brief for behavior_probe / claim_development / etc.
  const a = { id: "a", title: "A", score: 1, summary: { guidance: ["x"] } };
  const b = {
    id: "b",
    title: "B",
    score: 2,
    summary: { guidance: ["y"] },
    lens_affinity: ["browser_behavior_probe"],
  };
  for (const lens of ["behavior_probe", "control_check", "claim_development", "seed_mapping"]) {
    const partitioned = partitionTechniquePacksByLensAffinity([a, b], lens);
    assert.equal(partitioned.selected.length, 2, `lens=${lens} must keep both packs in selected[]`);
    assert.equal(partitioned.other_applicable.length, 0, `lens=${lens} must emit no other_applicable[]`);
    // Order preserved.
    assert.equal(partitioned.selected[0].id, "a");
    assert.equal(partitioned.selected[1].id, "b");
  }
});

test("partitionTechniquePacksByLensAffinity is deterministic across repeated calls", () => {
  const packs = [
    { id: "p1", title: "P1", score: 5, lens_affinity: ["browser_behavior_probe"] },
    { id: "p2", title: "P2", score: 3 },
    { id: "p3", title: "P3", score: 1, lens_affinity: ["behavior_probe"] },
  ];
  const first = partitionTechniquePacksByLensAffinity(packs, "browser_behavior_probe");
  const second = partitionTechniquePacksByLensAffinity(packs, "browser_behavior_probe");
  const third = partitionTechniquePacksByLensAffinity(packs, "browser_behavior_probe");
  assert.deepEqual(
    first.selected.map((pack) => pack.id),
    second.selected.map((pack) => pack.id),
    "repeated partition calls must produce the same selected[] ordering",
  );
  assert.deepEqual(
    second.selected.map((pack) => pack.id),
    third.selected.map((pack) => pack.id),
  );
  assert.deepEqual(
    first.other_applicable.map((pack) => pack.id),
    second.other_applicable.map((pack) => pack.id),
    "repeated partition calls must produce the same other_applicable[] ordering",
  );
});

// ── End-to-end: technique_packs slice carries lens_partitioned wiring ────────

test("brief technique_packs slice exposes other_applicable + lens_partitioned under browser_behavior_probe", () => {
  withTempHome(() => {
    const domain = uniqueDomain("brief-tp-partition");
    const surfaceId = "web-tp";
    seedSessionState(domain);
    seedAttackSurface(domain, [baseWebSurface(surfaceId, {
      hosts: ["https://tp.example"],
      tech_stack: ["api", "rest", "json"],
      endpoints: ["/api/users", "/api/login"],
    })]);
    startWaveWithLens(domain, surfaceId, "browser_behavior_probe");
    const brief = readBriefAsJson(domain);
    assert.ok(brief.technique_packs && typeof brief.technique_packs === "object");
    assert.equal(brief.technique_packs.lens_partitioned, true, "technique_packs must declare lens_partitioned under the browser lens");
    assert.ok(Array.isArray(brief.technique_packs.other_applicable), "other_applicable[] must exist under the browser lens");
    // No browser-affined packs ship in T.4 — the registry's HTTP-shaped packs
    // (generic-rest-api, graphql, wordpress, jwt, ...) all lack lens_affinity,
    // so they all demote to other_applicable. The selected[] foregrounded
    // list is correspondingly empty or contains only future browser-affined
    // packs (none today). This test pins the plumbing, not pack-content.
    assert.equal(
      brief.technique_packs.selected.length,
      0,
      "no browser-affined packs ship in T.4; selected[] must be empty under the browser lens",
    );
    assert.ok(
      brief.technique_packs.other_applicable.length >= 1,
      "HTTP-shaped packs without lens_affinity must demote to other_applicable[] under the browser lens",
    );
    // Each demoted snippet must be the shorter shape: id, title, score,
    // matched only — no guidance / payload_hints / estimated_tokens.
    for (const snippet of brief.technique_packs.other_applicable) {
      assert.equal(typeof snippet.id, "string");
      assert.equal(typeof snippet.title, "string");
      assert.equal(
        Object.prototype.hasOwnProperty.call(snippet, "summary"),
        false,
        `demoted snippet for ${snippet.id} must not carry full summary`,
      );
    }
  });
});

test("brief technique_packs slice keeps the original flat shape under behavior_probe (regression)", () => {
  withTempHome(() => {
    const domain = uniqueDomain("brief-tp-regression");
    const surfaceId = "web-tp-r";
    seedSessionState(domain);
    seedAttackSurface(domain, [baseWebSurface(surfaceId, {
      hosts: ["https://tp-r.example"],
      tech_stack: ["api", "rest", "json"],
      endpoints: ["/api/users", "/api/login"],
    })]);
    startWaveWithLens(domain, surfaceId, "behavior_probe");
    const brief = readBriefAsJson(domain);
    assert.ok(brief.technique_packs && typeof brief.technique_packs === "object");
    assert.equal(
      Object.prototype.hasOwnProperty.call(brief.technique_packs, "lens_partitioned"),
      false,
      "technique_packs must not declare lens_partitioned under non-browser lenses",
    );
    assert.equal(
      Object.prototype.hasOwnProperty.call(brief.technique_packs, "other_applicable"),
      false,
      "other_applicable[] must be absent under non-browser lenses",
    );
    assert.ok(brief.technique_packs.selected.length >= 1, "selected[] must surface the HTTP-shaped packs under behavior_probe");
    // The flat shape carries the full summary block; pick the first pack and
    // assert it has the full structure (regression).
    const first = brief.technique_packs.selected[0];
    assert.equal(typeof first.summary, "object");
    assert.ok(Array.isArray(first.summary.guidance), "regression: selected[] under behavior_probe carries the full summary blob");
  });
});

// ── Determinism ──────────────────────────────────────────────────────────────

test("browser_behavior_probe brief is deterministic across repeated assembly", () => {
  withTempHome(() => {
    const domain = uniqueDomain("brief-browser-determ");
    const surfaceId = "web-bd";
    seedSessionState(domain);
    seedAttackSurface(domain, [baseWebSurface(surfaceId, {
      hosts: ["https://bd.example"],
    })]);
    startWaveWithLens(domain, surfaceId, "browser_behavior_probe");
    const a = readAssignmentBrief({ target_domain: domain, wave: "w1", agent: "a1" });
    const b = readAssignmentBrief({ target_domain: domain, wave: "w1", agent: "a1" });
    const c = readAssignmentBrief({ target_domain: domain, wave: "w1", agent: "a1" });
    assert.equal(
      normalizeEnvelopeNonces(a),
      normalizeEnvelopeNonces(b),
      "repeated brief reads must produce the same output aside from envelope nonces",
    );
    assert.equal(normalizeEnvelopeNonces(b), normalizeEnvelopeNonces(c));
  });
});
