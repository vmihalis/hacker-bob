"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  AXES,
  CANONICAL_REQUIRED_ENTITIES,
  CLAIM_AUTHORITY,
  TEMPLATE_TIER,
  FAMILY_BINDINGS,
  OBJECT_AUTH_BINDING,
  assertValidBinding,
  instantiateTemplate,
  instantiateFamily,
  toCorpusRecord,
  deriveEvidencePredicate,
  validateFamilyAgainstLoader,
} = require("../mcp/core/authorization-differential-family.js");

const {
  OBJECT_AUTHORIZATION_MECHANISM_TEMPLATE,
  loadMechanismTemplates,
  normalizeMechanismTemplate,
} = require("../mcp/core/mechanism/invariant-template-corpus.js");

// The four axes that parameterize the family.
test("the family is parameterized by exactly the four authorization axes", () => {
  assert.deepEqual(AXES.slice(), ["principal", "resource", "policy_gate", "effect"]);
});

// ---------------------------------------------------------------------------
// The load-bearing faithfulness witness: the object-auth binding must
// reproduce OBJECT_AUTHORIZATION_MECHANISM_TEMPLATE field-for-field after the
// REAL loader normalizes both. The abstraction is faithful, not lossy.
// ---------------------------------------------------------------------------
test("object-auth binding reproduces the hardcoded template field-for-field through the loader", () => {
  const generated = toCorpusRecord(instantiateTemplate(OBJECT_AUTH_BINDING));

  const fromFamily = normalizeMechanismTemplate(generated).template;
  const fromHardcoded = normalizeMechanismTemplate(OBJECT_AUTHORIZATION_MECHANISM_TEMPLATE).template;

  assert.ok(fromFamily, "family object-auth template normalizes");
  assert.ok(fromHardcoded, "hardcoded template normalizes");
  assert.deepEqual(fromFamily, fromHardcoded);
});

test("object-auth required_entities equals the hardcoded template's, not a superset", () => {
  const generated = toCorpusRecord(instantiateTemplate(OBJECT_AUTH_BINDING));
  assert.deepEqual(
    generated.required_entities,
    OBJECT_AUTHORIZATION_MECHANISM_TEMPLATE.required_entities.slice()
  );
  // And it is the canonical role set the axes resolve to.
  assert.deepEqual(generated.required_entities, CANONICAL_REQUIRED_ENTITIES.slice());
});

test("object-auth evidence_predicate matches the hardcoded template", () => {
  const generated = toCorpusRecord(instantiateTemplate(OBJECT_AUTH_BINDING));
  assert.deepEqual(
    generated.evidence_predicate,
    { ...OBJECT_AUTHORIZATION_MECHANISM_TEMPLATE.evidence_predicate }
  );
});

// ---------------------------------------------------------------------------
// The family generality: distinct bindings yield distinct mechanisms, and ALL
// of them load in the existing loadMechanismTemplates shape with zero warnings.
// ---------------------------------------------------------------------------
test("the family emits the five distinct authorization mechanisms", () => {
  const ids = instantiateFamily().map((t) => t.id);
  assert.deepEqual(ids.sort(), [
    "business_logic_authorization",
    "function_access_control",
    "object_authorization",
    "privilege_escalation",
    "ssrf_as_authorization",
  ]);
});

test("distinct bindings instantiate distinct mechanisms with distinct CWE membership", () => {
  const templates = instantiateFamily();
  const cwes = new Set(templates.map((t) => t.mechanism_id));
  assert.equal(cwes.size, templates.length, "each instance binds a distinct CWE");
  const axisShapes = new Set(templates.map((t) => JSON.stringify(t.axes)));
  assert.equal(axisShapes.size, templates.length, "each instance binds distinct axes");
});

test("every family instance loads in the existing corpus shape with zero warnings", () => {
  const { templates, warnings } = validateFamilyAgainstLoader();
  assert.equal(warnings.length, 0, JSON.stringify(warnings));
  assert.equal(templates.length, FAMILY_BINDINGS.length);
});

test("every family instance fills all four axes with a concrete entity", () => {
  for (const template of instantiateFamily()) {
    for (const axis of AXES) {
      assert.ok(
        typeof template.axes[axis] === "string" && template.axes[axis].trim().length > 0,
        `${template.id} fills ${axis}`
      );
    }
  }
});

test("every family instance asserts the two authorization edges in its predicate", () => {
  for (const template of instantiateFamily()) {
    assert.equal(template.evidence_predicate.kind, "differential_effect");
    assert.deepEqual(template.evidence_predicate.required_edges, [
      "principal->policy_gate",
      "policy_gate->effect",
    ]);
    assert.equal(template.evidence_predicate.required_cwe, template.mechanism_id);
  }
});

// ---------------------------------------------------------------------------
// Mint != confirm: minted templates are advisory and never self-confirm.
// ---------------------------------------------------------------------------
test("minting yields advisory templates that never carry claim authority", () => {
  assert.equal(CLAIM_AUTHORITY, false);
  assert.equal(TEMPLATE_TIER, 3);
  for (const template of instantiateFamily()) {
    assert.equal(template.claim_authority, false);
    assert.equal(template.tier, 3);
  }
});

test("the advisory metadata is not part of the corpus record the loader sees", () => {
  const record = toCorpusRecord(instantiateTemplate(OBJECT_AUTH_BINDING));
  assert.ok(!("claim_authority" in record));
  assert.ok(!("tier" in record));
  assert.ok(!("axes" in record));
});

// ---------------------------------------------------------------------------
// The refuting arm is universal: every instance carries a negative control
// that must flip. A binding with no negative control is refused.
// ---------------------------------------------------------------------------
test("every family instance carries a refuting negative control", () => {
  for (const template of instantiateFamily()) {
    assert.ok(
      Array.isArray(template.negative_controls) && template.negative_controls.length > 0,
      `${template.id} carries a negative control`
    );
    assert.ok(
      Array.isArray(template.positive_controls) && template.positive_controls.length > 0,
      `${template.id} carries a positive control`
    );
  }
});

test("a binding with no negative control is refused at instantiation", () => {
  const broken = { ...OBJECT_AUTH_BINDING, negative_controls: [] };
  assert.throws(() => instantiateTemplate(broken), /negative_controls/);
});

test("a binding missing an axis entity is refused at instantiation", () => {
  const broken = {
    ...OBJECT_AUTH_BINDING,
    axes: { principal: "p", resource: "r", policy_gate: "g" },
  };
  assert.throws(() => instantiateTemplate(broken), /effect/);
});

test("a binding missing interventions is refused", () => {
  const broken = { ...OBJECT_AUTH_BINDING, interventions: [] };
  assert.throws(() => instantiateTemplate(broken), /interventions/);
});

test("assertValidBinding rejects non-object input", () => {
  assert.throws(() => assertValidBinding(null), /must be an object/);
  assert.throws(() => assertValidBinding("nope"), /must be an object/);
});

// ---------------------------------------------------------------------------
// A documented superset of required_entities is accepted identically by the
// loader (the acceptance clause allows a superset, not a lossy subset).
// ---------------------------------------------------------------------------
test("a binding may declare a documented superset of required_entities and still load", () => {
  const superset = {
    ...OBJECT_AUTH_BINDING,
    id: "object_authorization_extended",
    required_entities: [...CANONICAL_REQUIRED_ENTITIES, "tenant_boundary"],
  };
  const record = toCorpusRecord(instantiateTemplate(superset));
  const { templates, warnings } = loadMechanismTemplates([record]);
  assert.equal(warnings.length, 0, JSON.stringify(warnings));
  assert.equal(templates.length, 1);
  assert.ok(templates[0].required_entities.includes("tenant_boundary"));
});

// ---------------------------------------------------------------------------
// HW2: the family is standalone and does NOT touch the live corpus or loader
// state. It produces data only.
// ---------------------------------------------------------------------------
test("the live MECHANISM_TEMPLATES corpus is untouched by the family module", () => {
  const corpus = require("../mcp/core/mechanism/invariant-template-corpus.js").MECHANISM_TEMPLATES;
  // The live corpus still holds only the single hardcoded mechanism.
  assert.equal(corpus.length, 1);
  assert.equal(corpus[0].id, "object_authorization");
});

test("deriveEvidencePredicate defaults to the two-edge differential keyed to the binding CWE", () => {
  const predicate = deriveEvidencePredicate({ mechanism_id: "CWE-918" });
  assert.equal(predicate.required_cwe, "CWE-918");
  assert.deepEqual(predicate.required_edges, [
    "principal->policy_gate",
    "policy_gate->effect",
  ]);
});
