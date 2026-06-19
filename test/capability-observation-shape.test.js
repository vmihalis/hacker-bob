"use strict";

// Cycle Y.1 — shape + witness-ref validators for the two new
// observation_kind values. Tests assert:
//   * The two kinds register as siblings of OSS_OBSERVATION_KIND_VALUES
//     under the existing `observation.recorded` top-level event kind
//     (Y-P1 — zero new top-level FRONTIER_EVENT_KINDS).
//   * Rationale is capped at 512 characters, every closed enum is
//     enforced, and wanted_tool must exist in TOOL_REGISTRY (Y-P2).
//   * `tool_inadequate` REQUIRES `inadequate_invocation_ref` + non-empty
//     `inadequacy_mode` (Y-P10 mechanical witness).
//   * `tool_absent` REJECTS both `inadequacy_mode` and
//     `inadequate_invocation_ref` (Y-P11 — the two kinds must not
//     collapse).
//   * The witness ref must match the same `run_id` and the wanted_tool
//     when a session-context lookup function is supplied.
//   * B1 — bob_write_verification_round.inputSchema lifts severity +
//     repro_steps + evidence_refs into the per-result `required[]` so AJV
//     catches missing attempt-binding fields at the dispatch layer.
//
// Cycle Y.1 EXTEND (rev 4.1): cap-threshold regression test that imports
// CLAIM_TEXT_LIMITS live from mcp/lib/tools/record-candidate-claim.js (set
// by Y.0 hotfix 1) and asserts the post-O2 caps are large enough to
// accommodate the field-observed failing payload retained in
// test/fixtures/o2-field-observed-payload.js. The payload + cap thresholds
// are sourced from live modules so there are no duplicated literals in
// this test.

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  CAPABILITY_OBSERVATION_KIND_VALUES,
  PURPOSE_VALUES,
  FALLBACK_USED_VALUES,
  FRICTION_KIND_VALUES,
  INADEQUACY_MODE_VALUES,
  DETECTED_BY_VALUES,
  DRIFT_SIGNATURE_VALUES,
  RATIONALE_MAX_CHARS,
  isCapabilityObservationKind,
  assertCapabilityFrictionPayload,
  assertProtocolDriftPayload,
} = require("../mcp/lib/capability-observations.js");

const {
  FRONTIER_EVENT_KINDS,
} = require("../mcp/lib/frontier-events.js");

const {
  OSS_OBSERVATION_KIND_VALUES,
  CAPABILITY_OBSERVATION_KIND_VALUES: CAPABILITY_KINDS_FROM_REPO_TARGET,
  isCapabilityObservationKind: isCapabilityKindFromRepoTarget,
} = require("../mcp/lib/repo-target.js");

const writeVerificationRoundTool = require("../mcp/lib/tools/write-verification-round.js");
const { validateAgainstSchema } = require("../mcp/lib/tool-validation.js");

const {
  CLAIM_TEXT_LIMITS,
} = require("../mcp/lib/tools/record-candidate-claim.js");
const {
  fieldObservedPayload,
} = require("./fixtures/o2-field-observed-payload.js");

function baseFrictionPayload(overrides = {}) {
  return {
    run_id: "run-001",
    node_id: "N-7",
    wanted_tool: "bob_http_scan",
    purpose: "http_probe",
    fallback_used: "bash_curl",
    friction_kind: "tool_absent",
    detected_by: "agent_self_report",
    rationale: "Pack omitted bob_http_scan; reached for curl as fallback.",
    ...overrides,
  };
}

function baseDriftPayload(overrides = {}) {
  return {
    run_id: "run-002",
    drift_signature: "wrong_mode_tool_call",
    detected_by: "mcp_runtime_auto_emit",
    rationale: "Verifier invoked bob_repo_check on a web-mode session.",
    ...overrides,
  };
}

// ── Y-P1 + sibling-registration with OSS kinds ────────────────────────────────

test("Y-P1: capability observation kinds add ZERO new top-level FRONTIER_EVENT_KINDS", () => {
  // observation.recorded must remain in the top-level set; neither new
  // capability kind may appear there (they ride observation.recorded as
  // payload.observation_kind siblings of OSS kinds).
  assert.ok(FRONTIER_EVENT_KINDS.includes("observation.recorded"));
  for (const kind of CAPABILITY_OBSERVATION_KIND_VALUES) {
    assert.equal(
      FRONTIER_EVENT_KINDS.includes(kind),
      false,
      `${kind} must not appear in FRONTIER_EVENT_KINDS (Y-P1 honours X-P8)`,
    );
  }
});

test("CAPABILITY_OBSERVATION_KIND_VALUES enumerates exactly two kinds and is frozen", () => {
  assert.equal(CAPABILITY_OBSERVATION_KIND_VALUES.length, 2);
  assert.ok(CAPABILITY_OBSERVATION_KIND_VALUES.includes("capability_friction_observed"));
  assert.ok(CAPABILITY_OBSERVATION_KIND_VALUES.includes("protocol_drift_observed"));
  assert.ok(Object.isFrozen(CAPABILITY_OBSERVATION_KIND_VALUES));
});

test("closed enums for purpose/fallback/friction/inadequacy/detected_by/drift_signature are frozen", () => {
  for (const enumValues of [
    PURPOSE_VALUES,
    FALLBACK_USED_VALUES,
    FRICTION_KIND_VALUES,
    INADEQUACY_MODE_VALUES,
    DETECTED_BY_VALUES,
    DRIFT_SIGNATURE_VALUES,
  ]) {
    assert.ok(Object.isFrozen(enumValues), "enum array must be Object.freeze'd");
    assert.ok(enumValues.length > 0, "enum array must be non-empty");
  }
  assert.deepEqual(FRICTION_KIND_VALUES.slice().sort(), ["tool_absent", "tool_inadequate"]);
  assert.deepEqual(
    INADEQUACY_MODE_VALUES.slice().sort(),
    [
      "body_truncated",
      "missing_auth_mode",
      "missing_parameter",
      "other",
      "output_format_unsuitable",
      "rate_limited",
      "response_timeout",
    ].sort(),
  );
});

test("capability and OSS observation kinds are disjoint siblings under observation.recorded", () => {
  // repo-target.js re-exports both registries so producers branching by
  // payload.observation_kind can resolve at one import boundary. The two
  // value sets must not overlap.
  assert.deepEqual(CAPABILITY_KINDS_FROM_REPO_TARGET, CAPABILITY_OBSERVATION_KIND_VALUES);
  for (const ossKind of OSS_OBSERVATION_KIND_VALUES) {
    assert.equal(
      CAPABILITY_OBSERVATION_KIND_VALUES.includes(ossKind),
      false,
      `OSS kind ${ossKind} must not appear in CAPABILITY kinds`,
    );
  }
  for (const capabilityKind of CAPABILITY_OBSERVATION_KIND_VALUES) {
    assert.equal(
      OSS_OBSERVATION_KIND_VALUES.includes(capabilityKind),
      false,
      `capability kind ${capabilityKind} must not appear in OSS kinds`,
    );
    assert.equal(isCapabilityKindFromRepoTarget(capabilityKind), true);
    assert.equal(isCapabilityObservationKind(capabilityKind), true);
  }
  assert.equal(isCapabilityObservationKind("dependency_observed"), false);
  assert.equal(isCapabilityObservationKind("not-a-kind"), false);
});

// ── Y-P2 shape validation: friction ──────────────────────────────────────────

test("assertCapabilityFrictionPayload accepts a well-formed tool_absent record", () => {
  const out = assertCapabilityFrictionPayload(baseFrictionPayload({
    surface_id: "surface:billing-admin",
  }));
  assert.equal(out.observation_kind, "capability_friction_observed");
  assert.equal(out.run_id, "run-001");
  assert.equal(out.wanted_tool, "bob_http_scan");
  assert.equal(out.friction_kind, "tool_absent");
  assert.equal(out.surface_id, "surface:billing-admin");
  assert.equal(Object.prototype.hasOwnProperty.call(out, "inadequacy_mode"), false);
  assert.equal(Object.prototype.hasOwnProperty.call(out, "inadequate_invocation_ref"), false);
});

test("rationale longer than RATIONALE_MAX_CHARS is REJECTED", () => {
  const tooLong = "x".repeat(RATIONALE_MAX_CHARS + 1);
  assert.throws(
    () => assertCapabilityFrictionPayload(baseFrictionPayload({ rationale: tooLong })),
    /rationale must be <= 512/,
  );
});

test("unknown purpose / fallback_used / friction_kind / detected_by REJECTED", () => {
  assert.throws(
    () => assertCapabilityFrictionPayload(baseFrictionPayload({ purpose: "not_a_purpose" })),
    /purpose must be one of/,
  );
  assert.throws(
    () => assertCapabilityFrictionPayload(baseFrictionPayload({ fallback_used: "telnet" })),
    /fallback_used must be one of/,
  );
  assert.throws(
    () => assertCapabilityFrictionPayload(baseFrictionPayload({ friction_kind: "tool_meh" })),
    /friction_kind must be one of/,
  );
  assert.throws(
    () => assertCapabilityFrictionPayload(baseFrictionPayload({ detected_by: "vibes" })),
    /detected_by must be one of/,
  );
});

test("wanted_tool not in TOOL_REGISTRY is REJECTED", () => {
  assert.throws(
    () => assertCapabilityFrictionPayload(baseFrictionPayload({ wanted_tool: "bob_not_a_real_tool" })),
    /wanted_tool must exist in TOOL_REGISTRY/,
  );
});

// ── Y-P10 mechanical witness on tool_inadequate ──────────────────────────────

test("tool_inadequate WITHOUT inadequate_invocation_ref is REJECTED (Y-P10)", () => {
  assert.throws(
    () => assertCapabilityFrictionPayload(baseFrictionPayload({
      friction_kind: "tool_inadequate",
      inadequacy_mode: "body_truncated",
      // inadequate_invocation_ref omitted
    })),
    /inadequate_invocation_ref is required/,
  );
});

test("tool_inadequate WITHOUT inadequacy_mode is REJECTED", () => {
  assert.throws(
    () => assertCapabilityFrictionPayload(baseFrictionPayload({
      friction_kind: "tool_inadequate",
      // inadequacy_mode omitted
      inadequate_invocation_ref: "frontier_event:FE-abc123",
    })),
    /inadequacy_mode is required/,
  );
});

test("tool_inadequate inadequate_invocation_ref must match frontier_event:<id> pattern", () => {
  assert.throws(
    () => assertCapabilityFrictionPayload(baseFrictionPayload({
      friction_kind: "tool_inadequate",
      inadequacy_mode: "body_truncated",
      inadequate_invocation_ref: "FE-abc123",
    })),
    /must match \^frontier_event:/,
  );
});

test("tool_inadequate witness lookup REJECTS when run_id does not match", () => {
  const lookup = (eventId) => {
    if (eventId !== "FE-abc123") return null;
    return {
      event_id: "FE-abc123",
      run_id: "run-OTHER",
      tool: "bob_http_scan",
    };
  };
  assert.throws(
    () => assertCapabilityFrictionPayload(
      baseFrictionPayload({
        friction_kind: "tool_inadequate",
        inadequacy_mode: "body_truncated",
        inadequate_invocation_ref: "frontier_event:FE-abc123",
      }),
      { lookupFrontierEvent: lookup },
    ),
    /run_id .* does not match record run_id/,
  );
});

test("tool_inadequate witness lookup REJECTS when tool does not match wanted_tool", () => {
  const lookup = () => ({
    event_id: "FE-abc123",
    run_id: "run-001",
    tool: "bob_extract_routes",
  });
  assert.throws(
    () => assertCapabilityFrictionPayload(
      baseFrictionPayload({
        friction_kind: "tool_inadequate",
        inadequacy_mode: "body_truncated",
        inadequate_invocation_ref: "frontier_event:FE-abc123",
      }),
      { lookupFrontierEvent: lookup },
    ),
    /does not match wanted_tool/,
  );
});

test("tool_inadequate witness lookup REJECTS missing referenced event", () => {
  const lookup = () => null;
  assert.throws(
    () => assertCapabilityFrictionPayload(
      baseFrictionPayload({
        friction_kind: "tool_inadequate",
        inadequacy_mode: "body_truncated",
        inadequate_invocation_ref: "frontier_event:FE-missing",
      }),
      { lookupFrontierEvent: lookup },
    ),
    /not found in session frontier events/,
  );
});

test("tool_inadequate witness lookup ACCEPTS matching run_id + tool", () => {
  const lookup = (eventId) => ({
    event_id: eventId,
    run_id: "run-001",
    tool: "bob_http_scan",
  });
  const out = assertCapabilityFrictionPayload(
    baseFrictionPayload({
      friction_kind: "tool_inadequate",
      inadequacy_mode: "body_truncated",
      inadequate_invocation_ref: "frontier_event:FE-abc123",
    }),
    { lookupFrontierEvent: lookup },
  );
  assert.equal(out.friction_kind, "tool_inadequate");
  assert.equal(out.inadequacy_mode, "body_truncated");
  assert.equal(out.inadequate_invocation_ref, "frontier_event:FE-abc123");
});

// ── Y-P11 disjointness: tool_absent must reject inadequacy fields ────────────

test("tool_absent WITH inadequacy_mode is REJECTED (Y-P11 — kinds must not collapse)", () => {
  assert.throws(
    () => assertCapabilityFrictionPayload(baseFrictionPayload({
      friction_kind: "tool_absent",
      inadequacy_mode: "body_truncated",
    })),
    /inadequacy_mode must be absent when friction_kind is tool_absent/,
  );
});

test("tool_absent WITH inadequate_invocation_ref is REJECTED", () => {
  assert.throws(
    () => assertCapabilityFrictionPayload(baseFrictionPayload({
      friction_kind: "tool_absent",
      inadequate_invocation_ref: "frontier_event:FE-abc",
    })),
    /inadequate_invocation_ref must be absent when friction_kind is tool_absent/,
  );
});

// ── Y-P2 shape validation: protocol drift ────────────────────────────────────

test("assertProtocolDriftPayload accepts a well-formed runtime drift record", () => {
  const out = assertProtocolDriftPayload(baseDriftPayload({
    skill_path: "prompts/roles/verifier.md",
    details: { tool: "bob_repo_check", session_mode: "web" },
  }));
  assert.equal(out.observation_kind, "protocol_drift_observed");
  assert.equal(out.run_id, "run-002");
  assert.equal(out.drift_signature, "wrong_mode_tool_call");
  assert.equal(out.skill_path, "prompts/roles/verifier.md");
  assert.deepEqual(out.details, { tool: "bob_repo_check", session_mode: "web" });
});

test("protocol drift rationale > 512 chars REJECTED", () => {
  assert.throws(
    () => assertProtocolDriftPayload(baseDriftPayload({ rationale: "x".repeat(RATIONALE_MAX_CHARS + 1) })),
    /rationale must be <= 512/,
  );
});

test("unknown drift_signature / detected_by REJECTED", () => {
  assert.throws(
    () => assertProtocolDriftPayload(baseDriftPayload({ drift_signature: "totally_made_up" })),
    /drift_signature must be one of/,
  );
  assert.throws(
    () => assertProtocolDriftPayload(baseDriftPayload({ detected_by: "vibes" })),
    /detected_by must be one of/,
  );
});

test("protocol drift details must be a plain object when supplied", () => {
  assert.throws(
    () => assertProtocolDriftPayload(baseDriftPayload({ details: [1, 2, 3] })),
    /details must be a plain object/,
  );
});

// ── B1 — write-verification-round inputSchema attempt-binding required ───────

test("B1: bob_write_verification_round inputSchema results[].required lifts attempt-binding fields", () => {
  const required = writeVerificationRoundTool
    .inputSchema
    .properties
    .results
    .items
    .required;
  // The five attempt-binding fields B1 lifts so AJV catches them at the
  // dispatch layer rather than slipping through to the handler. severity
  // had been nullable; B1 makes it a required non-null enum. repro_steps
  // and evidence_refs were not enforceable at all; B1 makes them
  // dispatch-layer rejections.
  for (const field of ["severity", "repro_steps", "evidence_refs", "finding_id"]) {
    assert.ok(required.includes(field), `results[].required must include ${field}`);
  }
  assert.ok(
    writeVerificationRoundTool.inputSchema.required.includes("target_domain"),
    "target_domain is required at the top level",
  );
  const severitySchema = writeVerificationRoundTool
    .inputSchema
    .properties
    .results
    .items
    .properties
    .severity;
  assert.equal(severitySchema.type, "string", "severity must be a non-nullable string");
  assert.equal(severitySchema.enum.includes(null), false, "severity enum must not contain null");
});

test("B1: dispatch-layer schema rejects a result missing repro_steps / evidence_refs", () => {
  const baseArgs = {
    target_domain: "example.com",
    round: "brutalist",
    notes: null,
    results: [
      {
        finding_id: "F-1",
        disposition: "confirmed",
        severity: "high",
        reportable: true,
        reasoning: "Replayed successfully.",
        // repro_steps + evidence_refs omitted on purpose
      },
    ],
  };
  assert.throws(
    () => validateAgainstSchema(baseArgs, writeVerificationRoundTool.inputSchema, []),
    /repro_steps is required/,
  );

  const withReproOnly = {
    ...baseArgs,
    results: [{ ...baseArgs.results[0], repro_steps: ["GET /admin"] }],
  };
  assert.throws(
    () => validateAgainstSchema(withReproOnly, writeVerificationRoundTool.inputSchema, []),
    /evidence_refs is required/,
  );

  // With all attempt-binding fields present + severity non-null, schema accepts.
  const complete = {
    ...baseArgs,
    results: [{
      ...baseArgs.results[0],
      repro_steps: ["GET /admin"],
      evidence_refs: ["frontier_event:FE-123"],
    }],
  };
  // Should not throw.
  validateAgainstSchema(complete, writeVerificationRoundTool.inputSchema, []);
});

test("B1: dispatch-layer schema rejects severity: null after the lift", () => {
  const args = {
    target_domain: "example.com",
    round: "balanced",
    notes: null,
    results: [
      {
        finding_id: "F-2",
        disposition: "denied",
        severity: null,
        reportable: false,
        reasoning: "Could not reproduce.",
        repro_steps: ["GET /admin returned 401"],
        evidence_refs: ["frontier_event:FE-456"],
      },
    ],
  };
  assert.throws(
    () => validateAgainstSchema(args, writeVerificationRoundTool.inputSchema, []),
    /severity must be string/,
  );
});

// ── Y.1 EXTEND (rev 4.1) — O2 hotfix cap-threshold regression-test reference
// Confirms the live caps in mcp/lib/tools/record-candidate-claim.js
// (set by Y.0 hotfix 1) accommodate the field-observed failing payload
// retained at test/fixtures/o2-field-observed-payload.js. Both the cap
// thresholds and the payload are imported from source — no duplicated
// literals in this test.

test("Y.1 EXTEND: live CLAIM_TEXT_LIMITS accommodate the Y.0 field-observed payload (no duplicated literals)", () => {
  // Sanity: caps come from the live record-candidate-claim.js module.
  assert.ok(CLAIM_TEXT_LIMITS && typeof CLAIM_TEXT_LIMITS === "object", "CLAIM_TEXT_LIMITS must be imported from the live source");
  assert.ok(Object.isFrozen(CLAIM_TEXT_LIMITS), "CLAIM_TEXT_LIMITS must be Object.freeze'd in source");

  // Build the field-observed payload from the shared fixture so the Y.1
  // extension reads the same payload the Y.0 hotfix regression test asserts
  // against. Neither the payload prose nor the cap numeric values are
  // duplicated in this file.
  const payload = fieldObservedPayload("y1-extend.example.com");

  // For every text field exercised by the field-observed payload, the live
  // cap MUST be at least as large as the payload's actual content length.
  // If a future cap change drops below the field-observed footprint, this
  // test fails immediately and surfaces the regression.
  for (const field of ["description", "proof_of_concept", "response_evidence", "impact"]) {
    const value = payload[field];
    assert.equal(typeof value, "string", `payload.${field} must be a string`);
    const cap = CLAIM_TEXT_LIMITS[field];
    assert.equal(typeof cap, "number", `CLAIM_TEXT_LIMITS.${field} must be a number in source`);
    assert.ok(
      cap >= value.length,
      `CLAIM_TEXT_LIMITS.${field} (${cap}) must accommodate the Y.0 field-observed payload length (${value.length})`,
    );
  }

  // The post-O2 description cap must be strictly larger than the legacy
  // 4000-char cap the hotfix raised, since the field-observed PoC narrative
  // exceeds it. Asserting the inequality (not a magic number) keeps the
  // intent stable across future cap-raise rounds without duplicating the
  // literal value.
  const LEGACY_DESCRIPTION_CAP = 4000;
  assert.ok(
    CLAIM_TEXT_LIMITS.description > LEGACY_DESCRIPTION_CAP,
    "post-O2 description cap must exceed the pre-hotfix 4000-char cap",
  );
  assert.ok(
    payload.description.length > LEGACY_DESCRIPTION_CAP,
    "field-observed payload must exceed the pre-hotfix 4000-char cap (proves the hotfix is load-bearing)",
  );
});
