"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  appendFrontierEvent,
} = require("../mcp/lib/frontier-events.js");
const {
  sessionDir,
} = require("../mcp/lib/paths.js");
const {
  frontierEventToTypedFact,
  provenanceForObservationKind,
  queryFrontierTypedFacts,
} = require("../mcp/lib/belief/frontier-facts.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-belief-frontier-facts-"));
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

test("frontier typed fact projection reuses observation.recorded ledger events", () => {
  withTempHome(() => {
    const domain = "belief-frontier-facts.example.com";
    ensureSession(domain);
    appendFrontierEvent({
      target_domain: domain,
      kind: "observation.recorded",
      ts: "2026-06-13T00:00:02.000Z",
      surface_id: "surface:billing",
      payload: {
        observation_kind: "schema_field",
        endpoint: "/billing/{id}",
        claimed_auth: "bearerAuth",
      },
      source: { artifact: "schema-contracts.jsonl", tool: "bob_ingest_schema_doc" },
    });
    appendFrontierEvent({
      target_domain: domain,
      kind: "observation.recorded",
      ts: "2026-06-13T00:00:01.000Z",
      surface_id: "surface:billing",
      payload: {
        observation_kind: "http_record_observed",
        artifact_ref: "http_record:R7",
        endpoint: "/billing/123",
      },
      source: { artifact: "http-records.jsonl", tool: "bob_import_http_traffic" },
    });
    appendFrontierEvent({
      target_domain: domain,
      kind: "observation.recorded",
      ts: "2026-06-13T00:00:03.000Z",
      surface_id: "surface:worker",
      payload: {
        observation_kind: "unsafe_sink_observed",
        file_path: "src/parser.c",
        symbol: "parse",
      },
      source: { artifact: "oss-observations", tool: "bob_record_oss_observation" },
    });

    const result = queryFrontierTypedFacts({ target_domain: domain, limit: 10 });
    assert.equal(result.source_artifact, "frontier-events.jsonl");
    assert.equal(result.writes_artifacts, false);
    assert.equal(result.facts.length, 3);
    assert.deepEqual(
      result.facts.map((fact) => fact.observation_kind),
      ["http_record_observed", "schema_field", "unsafe_sink_observed"],
    );
    assert.deepEqual(
      result.facts.map((fact) => fact.provenance),
      ["observed_http", "declared_schema", "static_code"],
    );
    assert.equal(result.facts[0].artifact_ref, "http_record:R7");
    assert.match(result.facts[1].artifact_ref, /^frontier_event:FE-/);
    for (const fact of result.facts) {
      assert.equal(fact.fact_kind, "frontier_observation");
      assert.equal(fact.target_domain, domain);
      assert.match(fact.fact_id, /^BFF-[a-f0-9]{24}$/);
      assert.equal(Object.isFrozen(fact), true);
    }
  });
});

test("frontier typed fact query filters by surface, kind, provenance, and bounded limit", () => {
  withTempHome(() => {
    const domain = "belief-frontier-facts-filter.example.com";
    ensureSession(domain);
    for (let index = 0; index < 5; index += 1) {
      appendFrontierEvent({
        target_domain: domain,
        kind: "observation.recorded",
        ts: `2026-06-13T00:00:0${index}.000Z`,
        surface_id: index % 2 === 0 ? "surface:even" : "surface:odd",
        payload: {
          observation_kind: index % 2 === 0 ? "schema_field" : "http_record_observed",
          artifact_ref: `http_record:R${index}`,
        },
      });
    }
    const bySurface = queryFrontierTypedFacts({
      target_domain: domain,
      surface_id: "surface:even",
      limit: 2,
    });
    assert.equal(bySurface.total_matching, 3);
    assert.equal(bySurface.facts.length, 2);
    assert.deepEqual(bySurface.facts.map((fact) => fact.artifact_ref), [
      "http_record:R2",
      "http_record:R4",
    ]);

    const byKind = queryFrontierTypedFacts({
      target_domain: domain,
      observation_kind: "http_record_observed",
    });
    assert.equal(byKind.facts.length, 2);
    assert.ok(byKind.facts.every((fact) => fact.provenance === "observed_http"));

    const byProvenance = queryFrontierTypedFacts({
      target_domain: domain,
      provenance: "declared_schema",
    });
    assert.equal(byProvenance.facts.length, 3);
    assert.ok(byProvenance.facts.every((fact) => fact.observation_kind === "schema_field"));
  });
});

test("frontier typed fact projection redacts string leaves and does not write a second ledger", () => {
  withTempHome(() => {
    const domain = "belief-frontier-facts-readonly.example.com";
    ensureSession(domain);
    const event = appendFrontierEvent({
      target_domain: domain,
      kind: "observation.recorded",
      ts: "2026-06-13T00:00:00.000Z",
      surface_id: "surface:login",
      payload: {
        observation_kind: "http_route",
        note: "login route observed",
      },
    });
    const before = fs.readdirSync(sessionDir(domain)).sort();
    const result = queryFrontierTypedFacts({ target_domain: domain });
    const after = fs.readdirSync(sessionDir(domain)).sort();
    assert.deepEqual(after, before);
    assert.deepEqual(after, ["frontier-events.jsonl"]);
    assert.equal(result.facts.length, 1);

    const direct = frontierEventToTypedFact(event);
    assert.equal(direct.fact_id, result.facts[0].fact_id);

    const redacted = frontierEventToTypedFact({
      ...event,
      payload: {
        observation_kind: "http_route",
        note: "Authorization: Bearer sk_test_1234567890abcdef",
      },
    });
    assert.doesNotMatch(JSON.stringify(redacted), /sk_test_1234567890abcdef/);
  });
});

test("frontier typed fact provenance map is closed and unknown observations remain operator asserted", () => {
  assert.equal(provenanceForObservationKind("schema_field"), "declared_schema");
  assert.equal(provenanceForObservationKind("http_record_observed"), "observed_http");
  assert.equal(provenanceForObservationKind("unsafe_sink_observed"), "static_code");
  assert.equal(provenanceForObservationKind("capability_friction_observed"), "operator_asserted");
  assert.equal(provenanceForObservationKind("not_yet_classified"), "operator_asserted");
});
