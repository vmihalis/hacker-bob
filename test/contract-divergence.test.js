"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  detectDivergences,
  DIVERGENCE_TYPES,
  SEVERITY_SECURITY,
  SEVERITY_INFO_LEAK,
  SEVERITY_DOC_OR_INFRA,
} = require("../mcp/core/contract-divergence.js");

function authedContract(overrides) {
  return {
    endpoint: "/users",
    method: "GET",
    claimed_auth: { schemes: ["bearerAuth"], none_allowed: false },
    claimed_params: [],
    claimed_response_shape: {
      "200": {
        content_type: "application/json",
        shape: {
          type: "object",
          required: ["id"],
          properties: { id: { type: "string" }, name: { type: "string" } },
        },
      },
      "401": { content_type: null, shape: null },
    },
    ...overrides,
  };
}

function publicContract(overrides) {
  return {
    endpoint: "/health",
    method: "GET",
    claimed_auth: { schemes: [], none_allowed: false },
    claimed_params: [],
    claimed_response_shape: {
      "200": {
        content_type: "application/json",
        shape: { type: "object", properties: {} },
      },
    },
    ...overrides,
  };
}

test("auth-required spec + 200 without auth flags security divergence", () => {
  const divergences = detectDivergences(authedContract(), {
    status: 200,
    sent_with_auth: false,
    body: { id: "u-1", name: "Alice" },
    content_type: "application/json",
  });
  const auth = divergences.find((d) => d.type === "auth_required_but_succeeded_without");
  assert.ok(auth, "auth divergence emitted");
  assert.equal(auth.severity_class, SEVERITY_SECURITY);
  assert.match(auth.evidence_summary, /bearerAuth/);
});

test("auth-required spec + 401 with auth flags doc/infra divergence", () => {
  const divergences = detectDivergences(authedContract(), {
    status: 401,
    sent_with_auth: true,
    body: null,
    content_type: null,
  });
  const auth = divergences.find((d) => d.type === "auth_required_but_returned_unauthenticated_class");
  assert.ok(auth);
  assert.equal(auth.severity_class, SEVERITY_DOC_OR_INFRA);
});

test("public spec + 401 without auth does not flag auth divergence", () => {
  const divergences = detectDivergences(publicContract(), {
    status: 401,
    sent_with_auth: false,
    body: null,
    content_type: null,
  });
  assert.equal(
    divergences.filter((d) => d.type.startsWith("auth_")).length,
    0,
  );
});

test("none_allowed=true short-circuits auth divergence", () => {
  const contract = authedContract({
    claimed_auth: { schemes: ["bearerAuth"], none_allowed: true },
  });
  const divergences = detectDivergences(contract, {
    status: 200,
    sent_with_auth: false,
    body: { id: "x" },
    content_type: "application/json",
  });
  assert.equal(divergences.filter((d) => d.type.startsWith("auth_")).length, 0);
});

test("documented endpoint returning 404 flags documented_endpoint_unreachable", () => {
  const divergences = detectDivergences(publicContract(), {
    status: 404,
    sent_with_auth: false,
    body: null,
    content_type: null,
  });
  const reach = divergences.find((d) => d.type === "documented_endpoint_unreachable");
  assert.ok(reach);
  assert.equal(reach.severity_class, SEVERITY_DOC_OR_INFRA);
});

test("claimed status set + observed status outside the set flags claimed_status_not_observed", () => {
  const divergences = detectDivergences(publicContract(), {
    status: 500,
    sent_with_auth: false,
    body: null,
    content_type: null,
  });
  const status = divergences.find((d) => d.type === "claimed_status_not_observed");
  assert.ok(status);
  assert.equal(status.severity_class, SEVERITY_DOC_OR_INFRA);
});

test("undocumented response field flags info_leak_potential", () => {
  const divergences = detectDivergences(authedContract(), {
    status: 200,
    sent_with_auth: true,
    body: { id: "u-1", name: "Alice", internal_id: 42, ssn: "secret" },
    content_type: "application/json",
  });
  const leak = divergences.find((d) => d.type === "undocumented_field_in_response");
  assert.ok(leak);
  assert.equal(leak.severity_class, SEVERITY_INFO_LEAK);
  assert.match(leak.evidence_summary, /internal_id/);
  assert.match(leak.evidence_summary, /ssn/);
});

test("required field missing in response flags doc_or_infra", () => {
  const divergences = detectDivergences(authedContract(), {
    status: 200,
    sent_with_auth: true,
    body: { name: "Alice" },
    content_type: "application/json",
  });
  const missing = divergences.find((d) => d.type === "required_field_missing_in_response");
  assert.ok(missing);
  assert.equal(missing.severity_class, SEVERITY_DOC_OR_INFRA);
  assert.match(missing.evidence_summary, /id/);
});

test("content type mismatch flags content_type_mismatch", () => {
  const divergences = detectDivergences(authedContract(), {
    status: 200,
    sent_with_auth: true,
    body: { id: "u-1" },
    content_type: "text/html",
  });
  const ct = divergences.find((d) => d.type === "content_type_mismatch");
  assert.ok(ct);
  assert.match(ct.evidence_summary, /application\/json/i);
  assert.match(ct.evidence_summary, /text\/html/i);
});

test("matching response satisfies the contract with no divergences", () => {
  const divergences = detectDivergences(authedContract(), {
    status: 200,
    sent_with_auth: true,
    body: { id: "u-1", name: "Alice" },
    content_type: "application/json",
  });
  assert.deepEqual(divergences, []);
});

test("empty contract response shape suppresses status divergence", () => {
  const contract = publicContract({ claimed_response_shape: {} });
  const divergences = detectDivergences(contract, {
    status: 500,
    sent_with_auth: false,
    body: null,
    content_type: null,
  });
  assert.equal(divergences.filter((d) => d.type === "claimed_status_not_observed").length, 0);
});

test("evidence_summary truncates undocumented field lists", () => {
  const contract = authedContract({
    claimed_response_shape: {
      "200": {
        content_type: "application/json",
        shape: { type: "object", properties: { id: { type: "string" } } },
      },
    },
  });
  const observed = {
    status: 200,
    sent_with_auth: true,
    body: { id: "x", a: 1, b: 2, c: 3, d: 4, e: 5, f: 6, g: 7 },
    content_type: "application/json",
  };
  const divergences = detectDivergences(contract, observed);
  const leak = divergences.find((d) => d.type === "undocumented_field_in_response");
  assert.ok(leak);
  assert.match(leak.evidence_summary, /\.\.\./, "truncation marker present");
});

test("DIVERGENCE_TYPES enumerates every type the detector can return", () => {
  assert.ok(DIVERGENCE_TYPES.includes("auth_required_but_succeeded_without"));
  assert.ok(DIVERGENCE_TYPES.includes("auth_required_but_returned_unauthenticated_class"));
  assert.ok(DIVERGENCE_TYPES.includes("documented_endpoint_unreachable"));
  assert.ok(DIVERGENCE_TYPES.includes("claimed_status_not_observed"));
  assert.ok(DIVERGENCE_TYPES.includes("undocumented_field_in_response"));
  assert.ok(DIVERGENCE_TYPES.includes("required_field_missing_in_response"));
  assert.ok(DIVERGENCE_TYPES.includes("content_type_mismatch"));
});

test("detectDivergences rejects non-object contract or observed", () => {
  assert.throws(() => detectDivergences(null, {}), /contract/);
  assert.throws(() => detectDivergences({}, "not-an-object"), /observed/);
});

test("divergences sorted deterministically by type", () => {
  // contract that triggers two divergences with predictable type ordering
  const contract = authedContract({
    claimed_response_shape: {
      "200": {
        content_type: "application/json",
        shape: { type: "object", required: ["id"], properties: { id: { type: "string" } } },
      },
    },
  });
  const divergences = detectDivergences(contract, {
    status: 200,
    sent_with_auth: true,
    body: { name: "Alice", extra: true },
    content_type: "application/json",
  });
  const types = divergences.map((d) => d.type);
  assert.deepEqual(types, [...types].sort(), "types ascend lexicographically");
});
