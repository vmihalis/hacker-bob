"use strict";

// E1 — No-unsatisfiable-gate registry invariant.
//
// For every registered capability pack, every pack-keyed gate it can hit must be
// EITHER satisfiable-by-honest-work OR a typed escape. Concretely, each entry in
// CAPABILITY_PACKS must resolve to exactly one of:
//   (a) typed honest-block  — non-dispatchable + a non-empty dispatch_block_reason,
//                             and it resolves to NO technique family (physical);
//   (b) typed no-attempt    — dispatchable but context_budget.attempt_log_required
//                             is false, so the technique-attempt gate never fires
//                             (smart_contract_*);
//   (c) satisfiable-by-work — dispatchable AND attempt_log_required===true, so the
//                             gate fires and honest work MUST be recordable: the
//                             pack's canonical technique family is advertised by at
//                             least one shipped technique pack (web, web_fanout,
//                             oss_*).
//
// A dispatchable, attempt_log_required pack whose compatibility family no technique
// pack advertises is the web_fanout finalize-wedge class: an evaluator that did
// honest work cannot log a matching technique attempt, so it can never finalize.
// This test must go RED the moment such a pack appears.
//
// Every symbol used here is the REAL production resolver, imported (never
// re-implemented). The satisfiability leg keys on the ACTUAL gate trigger
// (context_budget.attempt_log_required) and the ACTUAL satisfaction mechanism
// (techniquePackSupportsCapability over loadTechniqueRegistry().packs) — exactly
// what bob_log_technique_attempt and the finalize/merge technique-attempt gate
// enforce — so the test tracks production satisfiability, not a parallel
// derivation that could drift.

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  CAPABILITY_PACKS,
  isCapabilityPackDispatchable,
  getCapabilityPackContextBudget,
  techniqueCompatibilityPackId,
} = require("../mcp/core/capability/capability-packs.js");
const {
  loadTechniqueRegistry,
  techniquePackSupportsCapability,
} = require("../mcp/core/dispatch/technique-packs.js");

// Load the shipped registry once, the same cwd-independent way production does
// (loadTechniqueRegistry -> resourceCandidatePaths), so this suite is stable
// under the session-tempdir/env manipulation other suites perform.
const registry = loadTechniqueRegistry();

// The production satisfaction predicate: does at least one shipped technique pack
// advertise `compatId`? This is exactly what selectTechniquePacksForSurface,
// assertTechniquePackMatchesCapability, and logTechniqueAttempt consult before a
// technique attempt is accepted, so branch (c) below tracks real satisfiability.
function familyAdvertised(compatId) {
  return registry.packs.some((entry) => techniquePackSupportsCapability(entry, compatId));
}

const KNOWN_PACK_IDS = Object.freeze([
  "web",
  "web_fanout",
  "oss_dependency",
  "oss_native_code",
  "oss_api_schema",
  "oss_authz",
  "oss_ci_cd",
  "oss_secrets_config",
  "oss_docs_behavior",
  "smart_contract_evm",
  "smart_contract_svm",
  "smart_contract_aptos",
  "smart_contract_sui",
  "smart_contract_substrate",
  "smart_contract_cosmwasm",
  "physical",
]);

test("technique registry loads cleanly and advertises at least one family", () => {
  assert.equal(
    registry.warnings.length,
    0,
    `technique registry loaded with warnings: ${JSON.stringify(registry.warnings)}`,
  );
  assert.ok(registry.packs.length > 0, "shipped technique registry is empty");
});

test("every known capability pack is still registered (no silent removal)", () => {
  for (const id of KNOWN_PACK_IDS) {
    assert.ok(
      Object.prototype.hasOwnProperty.call(CAPABILITY_PACKS, id),
      `known capability pack ${id} disappeared from CAPABILITY_PACKS`,
    );
  }
});

test("every CAPABILITY_PACKS entry resolves to exactly one satisfiable branch", () => {
  const ids = Object.keys(CAPABILITY_PACKS);
  assert.ok(ids.length > 0, "CAPABILITY_PACKS is empty");

  const classified = { honest_block: [], no_attempt: [], satisfiable_by_work: [] };

  for (const id of ids) {
    const dispatchable = isCapabilityPackDispatchable(id);

    // Branch (a): typed honest-block. A non-dispatchable pack must name WHY it is
    // blocked and must resolve to NO technique family (the physical case). Both
    // facts are required: a block without a reason is untyped; a block that still
    // resolves a family would let a consumer route honest work at a dead gate.
    if (!dispatchable) {
      const reason = CAPABILITY_PACKS[id].dispatch_block_reason;
      assert.ok(
        typeof reason === "string" && reason.trim().length > 0,
        `pack ${id} is non-dispatchable but carries no dispatch_block_reason (untyped block)`,
      );
      assert.equal(
        techniqueCompatibilityPackId(id),
        null,
        `pack ${id} is non-dispatchable yet still resolves a technique family`,
      );
      classified.honest_block.push(id);
      continue;
    }

    const budget = getCapabilityPackContextBudget(id);
    assert.ok(budget, `dispatchable pack ${id} exposes no context budget`);

    // Branch (b): typed no-attempt path. The technique-attempt gate never fires
    // for this pack, so no technique family is required (smart_contract_*). The
    // flag must be an explicit boolean false, not merely falsy/absent.
    if (budget.attempt_log_required !== true) {
      assert.equal(
        budget.attempt_log_required,
        false,
        `pack ${id} attempt_log_required must be an explicit boolean (typed no-attempt)`,
      );
      classified.no_attempt.push(id);
      continue;
    }

    // Branch (c): the gate FIRES (attempt_log_required===true), so honest work
    // must be recordable. The pack's canonical compatibility family must resolve,
    // point at a registered dispatchable pack, and be advertised by at least one
    // shipped technique pack. This is the leg that catches the web_fanout wedge.
    const compat = techniqueCompatibilityPackId(id);
    assert.ok(
      typeof compat === "string" && compat.length > 0,
      `pack ${id} fires the technique-attempt gate but resolves no compatibility pack`,
    );
    assert.ok(
      Object.prototype.hasOwnProperty.call(CAPABILITY_PACKS, compat),
      `pack ${id} resolves to compatibility pack ${compat}, which is not a registered capability pack`,
    );
    assert.ok(
      isCapabilityPackDispatchable(compat),
      `pack ${id} resolves to non-dispatchable compatibility pack ${compat}`,
    );
    assert.ok(
      familyAdvertised(compat),
      `UNSATISFIABLE GATE: capability pack ${id} fires the technique-attempt gate but no shipped technique pack advertises its compatibility family ${compat}; an evaluator that did honest work could not log a matching technique attempt (web_fanout finalize-wedge class)`,
    );
    classified.satisfiable_by_work.push(id);
  }

  // No entry may be silently skipped: every id lands in exactly one branch.
  const totalClassified =
    classified.honest_block.length +
    classified.no_attempt.length +
    classified.satisfiable_by_work.length;
  assert.equal(
    totalClassified,
    ids.length,
    `classified ${totalClassified} of ${ids.length} packs; some entry was left unclassified`,
  );

  // Non-vacuity: on the current tree all three branches are genuinely exercised.
  assert.ok(classified.honest_block.length > 0, "no typed honest-block pack exercised branch (a)");
  assert.ok(classified.no_attempt.length > 0, "no typed no-attempt pack exercised branch (b)");
  assert.ok(
    classified.satisfiable_by_work.length > 0,
    "no satisfiable-by-work pack exercised branch (c)",
  );
});

test("physical is a typed honest-block (non-dispatchable + reason + no family)", () => {
  assert.equal(
    isCapabilityPackDispatchable("physical"),
    false,
    "physical must remain non-dispatchable until its consumers are wired",
  );
  const reason = CAPABILITY_PACKS.physical.dispatch_block_reason;
  assert.ok(
    typeof reason === "string" && reason.trim().length > 0,
    "physical must carry a non-empty dispatch_block_reason",
  );
  assert.equal(
    techniqueCompatibilityPackId("physical"),
    null,
    "physical must resolve to no technique family while non-dispatchable",
  );
});

test("every smart_contract_* pack is a typed no-attempt path", () => {
  const scIds = Object.keys(CAPABILITY_PACKS).filter((id) => id.startsWith("smart_contract_"));
  assert.ok(scIds.length > 0, "expected at least one smart_contract_* pack");
  for (const id of scIds) {
    assert.equal(
      isCapabilityPackDispatchable(id),
      true,
      `smart_contract pack ${id} should be dispatchable`,
    );
    const budget = getCapabilityPackContextBudget(id);
    assert.ok(budget, `smart_contract pack ${id} exposes no context budget`);
    assert.equal(
      budget.attempt_log_required,
      false,
      `smart_contract pack ${id} must be typed no-attempt (attempt_log_required===false)`,
    );
  }
});

test("completeness predicate has teeth: it distinguishes advertised from absent families", () => {
  // A family a shipped technique pack really advertises reads true, so the
  // predicate is not vacuously false...
  assert.equal(
    familyAdvertised("web"),
    true,
    "the web family must be advertised by the shipped registry",
  );
  // ...and a family no pack advertises reads false, so the predicate is not
  // vacuously true. This is the guard branch (c) relies on.
  assert.equal(
    familyAdvertised("definitely_absent_family_xyz"),
    false,
    "an unadvertised family must not be reported as advertised",
  );
});

test("branch (c) goes RED for a fabricated gate-firing pack whose family is unadvertised", () => {
  // Model the web_fanout finalize-wedge WITHOUT mutating the frozen
  // CAPABILITY_PACKS: a hypothetical dispatchable pack that fires the
  // attempt-log gate but whose compatibility family no technique pack advertises.
  // The branch-(c) satisfiability predicate (familyAdvertised over the real
  // registry) must classify it UNSATISFIABLE, i.e. return false — which is what
  // turns the completeness invariant RED for such a pack.
  const fabricatedGateFiringCompat = "web_fanout_wedge_unadvertised_family";
  assert.equal(
    familyAdvertised(fabricatedGateFiringCompat),
    false,
    "a fabricated gate-firing pack with an unadvertised compatibility family must fail the satisfiability predicate",
  );
});
