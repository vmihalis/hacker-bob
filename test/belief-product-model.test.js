"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  appendFrontierEvent,
} = require("../mcp/core/frontier/frontier-events.js");
const {
  appendEdges,
} = require("../mcp/core/frontier/surface-graph.js");
const {
  queryBeliefSignals,
} = require("../mcp/core/belief/authority.js");
const {
  buildProductModel,
  buildProductModelFromInputs,
  runProductModel,
  writeProductModelSignal,
} = require("../mcp/core/belief/organs/product-model.js");
const {
  claimsJsonlPath,
  gradeArtifactPaths,
  reportMarkdownPath,
  sessionDir,
  verificationAdjudicationPath,
} = require("../mcp/core/io/paths.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-belief-product-model-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function ensureSession(domain) {
  fs.mkdirSync(sessionDir(domain), { recursive: true });
}

test("product model emits cited inert product semantics as diagnostic belief scratch", () => {
  withTempHome(() => {
    const domain = "belief-product-model.example.com";
    ensureSession(domain);
    appendEdges({
      target_domain: domain,
      edges: [
        {
          source: { type: "surface", id: "surface:blocks" },
          target: { type: "endpoint", id: "/api/blocks/{id}" },
          edge_type: "contains",
          source_artifact: "schema-contracts.jsonl",
        },
        {
          source: { type: "endpoint", id: "/api/blocks/{id}" },
          target: { type: "auth_scheme", id: "bearerAuth" },
          edge_type: "claims_auth",
          source_artifact: "schema-contracts.jsonl",
        },
        {
          source: { type: "principal", id: "principal:attacker" },
          target: { type: "policy_gate", id: "policy_gate:block-owner" },
          edge_type: "tests_gate",
          source_artifact: "auth-differential-results.json",
        },
        {
          source: { type: "policy_gate", id: "policy_gate:block-owner" },
          target: { type: "effect", id: "effect:block-read" },
          edge_type: "permits_effect",
          source_artifact: "auth-differential-results.json",
        },
      ],
    });
    appendFrontierEvent({
      target_domain: domain,
      kind: "observation.recorded",
      ts: "2026-08-23T00:00:00.000Z",
      surface_id: "surface:blocks",
      payload: {
        observation_kind: "schema_field",
        endpoint: "/api/blocks/{id}",
        method: "GET",
        claimed_auth: "bearerAuth",
      },
      source: { artifact: "schema-contracts.jsonl", tool: "bob_ingest_schema_doc" },
    });

    const model = buildProductModel({ target_domain: domain });
    assert.equal(model.advisory, true);
    assert.equal(model.inert, true);
    assert.equal(model.closure_authority, false);
    assert.equal(model.evidence_authority, false);
    assert.equal(model.dispatch_authority, false);
    assert.ok(model.entities.length >= 4);
    assert.ok(model.relations.length >= 4);
    assert.equal(model.operations.length, 1);
    assert.ok(model.permission_predicates.length >= 2);
    for (const edge of [...model.relations, ...model.permission_predicates]) {
      assert.ok(Array.isArray(edge.evidence_refs) && edge.evidence_refs.length > 0);
      assert.equal(edge.closure_authority, false);
      assert.equal(edge.inert, true);
    }
    assert.ok(
      model.coverage_gaps.some((gap) => gap.gap_kind === "unobserved_operation" && gap.disposition === "HOLD"),
      "effects without an observed operation binding must be named coverage gaps",
    );

    const result = runProductModel({ target_domain: domain });
    assert.equal(result.closure_authority, false);
    assert.equal(result.inert, true);
    const signals = queryBeliefSignals({
      target_domain: domain,
      source: "mcp/core/belief/organs/product-model.js#runProductModel",
      role: "diagnostic",
    }).signals;
    assert.equal(signals.length, 1);
    assert.equal(signals[0].kind, "mechanism_projection");
    assert.equal(signals[0].advisory, true);
    assert.equal(signals[0].payload.model_hash, result.model_hash);
    assert.equal(signals[0].payload.closure_authority, false);
  });
});

test("product model refuses forged, soft, and unknown inputs into HOLD without closure artifacts", () => {
  withTempHome(() => {
    const domain = "belief-product-model-forgery.example.com";
    ensureSession(domain);
    const model = buildProductModelFromInputs({
      target_domain: domain,
      surface_edges: [
        {
          source: { type: "principal", id: "principal:attacker" },
          target: { type: "effect", id: "effect:forged-close" },
          edge_type: "permits_effect",
          source_artifact: "agent-scratch:not-signed",
        },
      ],
      frontier_facts: [
        {
          fact_kind: "frontier_observation",
          fact_id: "BFF-0123456789abcdef01234567",
          source_event_id: "FE-unknown",
          target_domain: domain,
          surface_id: "surface:unknown",
          observation_kind: "agent_invented_product_class",
          provenance: "operator_asserted",
          artifact_ref: "agent-scratch:hypothesis",
          payload: { endpoint: "/api/unknown", fallback: "validated-denied" },
        },
        {
          fact_kind: "frontier_observation",
          fact_id: "BFF-89abcdef0123456701234567",
          source_event_id: "FE-captured-unknown",
          target_domain: domain,
          surface_id: "surface:unknown",
          observation_kind: "new_product_semantic_shape",
          provenance: "observed_http",
          artifact_ref: "frontier_event:FE-captured-unknown",
          payload: { endpoint: "/api/unknown" },
        },
      ],
      belief_signals: [
        {
          kind: "belief_signal",
          provenance: "llm_inferred",
          role: "prior",
          payload: { generated_hypothesis: "attacker can read victim block" },
        },
      ],
    });

    assert.equal(model.admission.status, "HOLD");
    assert.equal(model.admission.no_generic_web_fallback, true);
    assert.equal(model.closure_authority, false);
    assert.equal(model.evidence_authority, false);
    assert.equal(model.dispatch_authority, false);
    assert.equal(model.relations.length, 0);
    assert.equal(model.operations.length, 0);
    assert.ok(model.coverage_gaps.some((gap) => gap.gap_kind === "forged_or_unsigned_surface_edge"));
    assert.ok(model.coverage_gaps.some((gap) => gap.gap_kind === "soft_input_refused"));
    assert.ok(model.coverage_gaps.some((gap) => gap.gap_kind === "unknown_observation_class"));
    assert.ok(model.coverage_gaps.some((gap) => gap.gap_kind === "soft_input_refused" && gap.disposition === "HOLD"));
    assert.doesNotMatch(JSON.stringify(model), /generic web|validated-denied/i);

    const written = writeProductModelSignal({ target_domain: domain, model });
    assert.equal(written.advisory, true);
    assert.equal(written.scratch, true);
    assert.equal(fs.existsSync(claimsJsonlPath(domain)), false);
    assert.equal(fs.existsSync(verificationAdjudicationPath(domain)), false);
    assert.equal(fs.existsSync(gradeArtifactPaths(domain).json), false);
    assert.equal(fs.existsSync(reportMarkdownPath(domain)), false);

    const signals = queryBeliefSignals({ target_domain: domain, role: "diagnostic" }).signals;
    assert.equal(signals.length, 1);
    assert.equal(signals[0].payload.admission.status, "HOLD");
    assert.equal(signals[0].payload.closure_authority, false);
    assert.equal(signals[0].payload.evidence_authority, false);
  });
});
