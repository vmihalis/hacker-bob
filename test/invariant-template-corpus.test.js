"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  TEMPLATES,
  getMechanismTemplate,
  SUPPORTED_CLASSES,
  loadMechanismTemplates,
  getTemplatesForClass,
  suggestInvariantsForFinding,
  suggestInvariantsForReport,
} = require("../mcp/lib/invariant-template-corpus.js");

test("SUPPORTED_CLASSES covers the smart-contract bug classes IP4 emits", () => {
  for (const cls of [
    "reentrancy",
    "access_control",
    "arithmetic_overflow",
    "oracle_manipulation",
    "unchecked_call",
    "signature_validation",
    "delegatecall_storage",
  ]) {
    assert.ok(SUPPORTED_CLASSES.includes(cls), `${cls} present`);
  }
});

test("TEMPLATES every entry declares id, vulnerability_class, name, parameter_slots, and foundry_test_template", () => {
  for (const template of TEMPLATES) {
    assert.ok(typeof template.id === "string" && template.id.length > 0);
    assert.ok(typeof template.vulnerability_class === "string");
    assert.ok(typeof template.name === "string" && template.name.length > 0);
    assert.ok(Array.isArray(template.parameter_slots));
    assert.ok(typeof template.foundry_test_template === "string" && template.foundry_test_template.length > 0);
  }
});

test("getTemplatesForClass returns the templates whose vulnerability_class matches", () => {
  const reentrancy = getTemplatesForClass("reentrancy");
  assert.ok(reentrancy.length >= 1);
  assert.ok(reentrancy.every((t) => t.vulnerability_class === "reentrancy"));
});

test("getTemplatesForClass returns an empty array for unknown classes", () => {
  assert.deepEqual(getTemplatesForClass("nope"), []);
  assert.deepEqual(getTemplatesForClass(""), []);
});

test("suggestInvariantsForFinding emits suggestions when class is supported", () => {
  const result = suggestInvariantsForFinding({
    title: "Reentrancy in withdraw",
    vulnerability_class: "reentrancy",
  });
  assert.equal(result.vulnerability_class, "reentrancy");
  assert.ok(result.template_count >= 1);
  assert.ok(result.suggestions.length >= 1);
  assert.equal(result.missing_class, false);
});

test("suggestInvariantsForFinding flags missing_class for unsupported vulnerability_class", () => {
  const result = suggestInvariantsForFinding({ vulnerability_class: "nope" });
  assert.equal(result.template_count, 0);
  assert.deepEqual(result.suggestions, []);
  assert.equal(result.missing_class, true);
});

test("slot_values fill placeholders and unfilled_slots reports the gap", () => {
  const result = suggestInvariantsForFinding({ vulnerability_class: "access_control" }, {
    slot_values: { target_contract: "Pool", admin_function: "emergencyPause" },
  });
  assert.equal(result.suggestions.length, 1);
  const suggestion = result.suggestions[0];
  assert.match(suggestion.foundry_test, /Pool\.emergencyPause/);
  assert.deepEqual(suggestion.unfilled_slots, ["admin_role_check"]);
});

test("missing slot_values keeps placeholders intact and unfilled_slots lists every slot", () => {
  const result = suggestInvariantsForFinding({ vulnerability_class: "reentrancy" });
  const suggestion = result.suggestions[0];
  assert.match(suggestion.foundry_test, /\{TARGET_CONTRACT\}/);
  assert.equal(suggestion.unfilled_slots.length, suggestion.parameter_slots.length);
});

test("limit clamps suggestion count below the hard ceiling", () => {
  const result = suggestInvariantsForFinding({ vulnerability_class: "reentrancy" }, { limit: 1 });
  assert.equal(result.suggestions.length, 1);
});

test("suggestInvariantsForReport groups suggestions per vulnerability_class", () => {
  const parsed = {
    findings: [
      { finding_index: 0, title: "Reentrancy", vulnerability_class: "reentrancy", finding_hash: "h1" },
      { finding_index: 1, title: "Access bypass", vulnerability_class: "access_control", finding_hash: "h2" },
      { finding_index: 2, title: "Reentrancy 2", vulnerability_class: "reentrancy", finding_hash: "h3" },
    ],
  };
  const result = suggestInvariantsForReport(parsed);
  assert.equal(result.total_templates, TEMPLATES.length);
  assert.equal(result.by_class.reentrancy.count, 2);
  assert.equal(result.by_class.access_control.count, 1);
  assert.equal(result.by_class.reentrancy.suggestions[0].finding_title, "Reentrancy");
});

test("suggestInvariantsForReport rejects malformed input", () => {
  assert.throws(() => suggestInvariantsForReport(null), /parsedReport/);
  assert.throws(() => suggestInvariantsForReport({}), /findings/);
});

test("template ids are unique", () => {
  const ids = new Set();
  for (const template of TEMPLATES) {
    assert.ok(!ids.has(template.id), `duplicate template id: ${template.id}`);
    ids.add(template.id);
  }
});

test("object_authorization mechanism template is closed, bounded, and maps to catalog CWE", () => {
  const template = getMechanismTemplate("object_authorization");
  assert.ok(template);
  assert.equal(template.mechanism_id, "CWE-639");
  assert.ok(template.required_entities.includes("principal"));
  assert.ok(template.required_entities.includes("policy_gate"));
  assert.ok(template.interventions.includes("principal_fixed_object_swap"));
  assert.ok(template.positive_controls.includes("attacker_owned_object_allowed"));
  assert.ok(template.negative_controls.includes("public_object_check"));
  assert.ok(template.confounders.includes("public_object"));
  assert.equal(template.evidence_predicate.kind, "differential_effect");
  assert.equal(Object.isFrozen(template.required_entities), true);
});

test("a non-catalog but CWE-shaped mechanism_id LOADS with cwe_in_catalog:false (annotate, not gate)", () => {
  const result = loadMechanismTemplates([
    {
      // CWE-9999 canonicalizes (shape-valid) but is not in the curated catalog.
      // It must LOAD as a tier-3 annotated candidate, not vanish.
      id: "novel_mechanism",
      mechanism_id: "CWE-9999",
      candidate: true,
      tier: 3,
      claim_authority: false,
      required_entities: ["principal", "novel_component", "guard", "effect"],
      interventions: ["exercise_novel_path"],
      positive_controls: ["novel_effect_observed"],
      negative_controls: ["benign_baseline_must_hold", "non_discriminating_control_refused"],
      confounders: ["environment_specific_state"],
      evidence_predicate: { kind: "differential_effect", required_cwe: "CWE-9999" },
    },
  ]);
  assert.equal(result.templates.length, 1, "a novel-but-CWE-shaped mechanism loads instead of dropping");
  assert.equal(result.warnings.length, 0);
  assert.equal(result.templates[0].mechanism_id, "CWE-9999");
  assert.equal(result.templates[0].cwe_in_catalog, false, "non-catalog membership is annotated, not a drop-gate");
});

test("a catalog CWE annotates cwe_in_catalog:true", () => {
  const result = loadMechanismTemplates([
    {
      id: "catalog_mechanism",
      mechanism_id: "CWE-639",
      required_entities: ["principal", "object"],
      interventions: ["object_swap"],
      positive_controls: ["owned_object"],
      negative_controls: ["public_object_check"],
      confounders: ["public_object"],
      evidence_predicate: { kind: "differential_effect" },
    },
  ]);
  assert.equal(result.templates.length, 1);
  assert.equal(result.templates[0].cwe_in_catalog, true);
});

test("a non-CWE-shaped mechanism_id still fails the shape floor (catalog relaxed, shape preserved)", () => {
  const result = loadMechanismTemplates([
    {
      id: "shapeless_mechanism",
      mechanism_id: "not-a-cwe",
      required_entities: ["principal", "object"],
      interventions: ["object_swap"],
      positive_controls: ["owned_object"],
      negative_controls: ["public_object_check"],
      confounders: ["public_object"],
      evidence_predicate: { kind: "differential_effect" },
    },
  ]);
  assert.equal(result.templates.length, 0, "a non-CWE-shaped id is dropped by the shape floor");
  assert.match(result.warnings[0].warnings.join(" "), /canonicalize|CWE/);
});

test("the loader output projection PRESERVES tier / candidate / claim_authority", () => {
  const corpus = loadMechanismTemplates([
    {
      id: "corpus_default",
      mechanism_id: "CWE-639",
      required_entities: ["principal", "object"],
      interventions: ["object_swap"],
      positive_controls: ["owned_object"],
      negative_controls: ["public_object_check"],
      confounders: ["public_object"],
      evidence_predicate: { kind: "differential_effect" },
    },
  ]);
  // A record that declares no tier defaults to the confirmed tier-2 corpus exemplar.
  assert.equal(corpus.templates[0].tier, 2);
  assert.equal(corpus.templates[0].candidate, false);
  assert.equal(corpus.templates[0].claim_authority, false);

  const candidate = loadMechanismTemplates([
    {
      id: "tier3_candidate",
      mechanism_id: "CWE-862",
      tier: 3,
      candidate: true,
      claim_authority: false,
      source_tier: "cwe_catalog",
      required_entities: ["principal", "function"],
      interventions: ["unprivileged_invoke"],
      positive_controls: ["privileged_allowed"],
      negative_controls: ["public_function_check"],
      confounders: ["client_side_only_gating"],
      evidence_predicate: { kind: "differential_effect" },
    },
  ]);
  // A declared tier-3 candidate keeps its advisory markers and is distinguishable
  // from a confirmed corpus template by tier !== 2 / candidate === true.
  assert.equal(candidate.templates[0].tier, 3);
  assert.equal(candidate.templates[0].candidate, true);
  assert.equal(candidate.templates[0].claim_authority, false);
  assert.equal(candidate.templates[0].source_tier, "cwe_catalog");
  assert.notEqual(candidate.templates[0].tier, corpus.templates[0].tier);
});

test("mechanism template loader skips malformed records with bounded warnings", () => {
  const result = loadMechanismTemplates([
    {
      id: "valid_object_auth",
      mechanism_id: "CWE-639",
      required_entities: ["principal", "object"],
      interventions: ["object_swap"],
      positive_controls: ["owned_object"],
      negative_controls: ["public_object_check"],
      confounders: ["public_object"],
      evidence_predicate: { kind: "differential_effect" },
    },
    {
      id: "bad",
      mechanism_id: "CWE-999999",
      required_entities: ["principal"],
      interventions: [],
      positive_controls: [],
      negative_controls: [],
      confounders: [],
      evidence_predicate: null,
    },
  ]);
  assert.equal(result.templates.length, 1);
  assert.equal(result.templates[0].id, "valid_object_auth");
  assert.equal(result.warnings.length, 1);
  assert.match(result.warnings[0].warnings.join(" "), /CWE-999999|evidence_predicate/);
});
