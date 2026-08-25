"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  computeResponseSignature,
  diffResponseSignatures,
  DIVERGENCE_TYPES,
  SEVERITY_SECURITY,
  SEVERITY_INFO_LEAK,
  SEVERITY_DOC_OR_INFRA,
} = require("../mcp/core/auth-differential.js");

test("computeResponseSignature classifies status into status_class and response_class", () => {
  const sig = computeResponseSignature({ status: 200, body: { id: "1" }, sent_with_auth: true });
  assert.equal(sig.status, 200);
  assert.equal(sig.status_class, "2xx");
  assert.equal(sig.response_class, "ok");
  assert.equal(sig.sent_with_auth, true);

  assert.equal(computeResponseSignature({ status: 401 }).response_class, "auth_required");
  assert.equal(computeResponseSignature({ status: 403 }).response_class, "forbidden");
  assert.equal(computeResponseSignature({ status: 404 }).response_class, "not_found");
  assert.equal(computeResponseSignature({ status: 500 }).response_class, "server_error");
});

test("body_hash is stable across key order but differs across value changes", () => {
  const a = computeResponseSignature({ status: 200, body: { id: "1", name: "Alice" } });
  const b = computeResponseSignature({ status: 200, body: { name: "Alice", id: "1" } });
  const c = computeResponseSignature({ status: 200, body: { id: "2", name: "Bob" } });
  assert.equal(a.body_hash, b.body_hash);
  assert.notEqual(a.body_hash, c.body_hash);
});

test("body_hash differs across different shapes", () => {
  const a = computeResponseSignature({ status: 200, body: { id: "1" } });
  const b = computeResponseSignature({ status: 200, body: { id: "1", admin_role: true } });
  assert.notEqual(a.body_hash, b.body_hash);
});

test("body_length_bucket maps to size buckets", () => {
  assert.equal(computeResponseSignature({ status: 200, body: "" }).body_length_bucket, "empty");
  assert.equal(computeResponseSignature({ status: 200, body: "a".repeat(100) }).body_length_bucket, "small");
  assert.equal(computeResponseSignature({ status: 200, body: "a".repeat(1000) }).body_length_bucket, "medium");
  assert.equal(computeResponseSignature({ status: 200, body: "a".repeat(20000) }).body_length_bucket, "large");
});

test("sensitive_field_count detects emails, tokens, ssn, internal_id, and admin keys", () => {
  const sig = computeResponseSignature({
    status: 200,
    body: {
      id: "u-1",
      email: "x@y.com",
      api_key: "k",
      ssn: "...",
      internal_id: 99,
      is_admin: true,
    },
  });
  assert.ok(sig.sensitive_field_count >= 5);
});

test("sensitive_field_count walks nested arrays and objects within a depth limit", () => {
  const sig = computeResponseSignature({
    status: 200,
    body: { items: [{ password: "x" }, { token: "y" }] },
  });
  assert.ok(sig.sensitive_field_count >= 2);
});

test("diffResponseSignatures returns empty when fewer than two profiles supplied", () => {
  const result = diffResponseSignatures({
    signatures_by_profile: { only: computeResponseSignature({ status: 200, body: {} }) },
  });
  assert.deepEqual(result, []);
});

test("status_class divergence emitted when one profile gets 200 and another 403", () => {
  const result = diffResponseSignatures({
    signatures_by_profile: {
      admin: computeResponseSignature({ status: 200, body: {} }),
      guest: computeResponseSignature({ status: 403, body: null }),
    },
  });
  const status = result.find((d) => d.type === "status_class_differs");
  assert.ok(status);
  assert.equal(status.severity_class, SEVERITY_DOC_OR_INFRA);
  assert.match(status.evidence_summary, /admin=2xx/);
  assert.match(status.evidence_summary, /guest=403/);
});

test("body_hash divergence emitted when the response shape differs across profiles", () => {
  const result = diffResponseSignatures({
    signatures_by_profile: {
      admin: computeResponseSignature({ status: 200, body: { id: "1", admin_role: true } }),
      user: computeResponseSignature({ status: 200, body: { id: "1" } }),
    },
  });
  const body = result.find((d) => d.type === "body_hash_differs");
  assert.ok(body);
});

test("sensitive_field_count divergence emitted with info_leak_potential severity", () => {
  const result = diffResponseSignatures({
    signatures_by_profile: {
      admin: computeResponseSignature({ status: 200, body: { id: "1", email: "a@x", ssn: "..." } }),
      user: computeResponseSignature({ status: 200, body: { id: "1" } }),
    },
  });
  const leak = result.find((d) => d.type === "sensitive_field_count_differs");
  assert.ok(leak);
  assert.equal(leak.severity_class, SEVERITY_INFO_LEAK);
});

test("unauth_succeeds_where_auth_blocked emits a security divergence with profile metadata", () => {
  const result = diffResponseSignatures({
    signatures_by_profile: {
      guest: computeResponseSignature({ status: 200, body: { id: "1" }, sent_with_auth: false }),
      user: computeResponseSignature({ status: 401, body: null, sent_with_auth: true }),
    },
    profile_metadata: {
      guest: { sent_with_auth: false },
      user: { sent_with_auth: true },
    },
  });
  const security = result.find((d) => d.type === "unauth_succeeds_where_auth_blocked");
  assert.ok(security);
  assert.equal(security.severity_class, SEVERITY_SECURITY);
  assert.match(security.evidence_summary, /unauth_ok=\[guest\]/);
  assert.match(security.evidence_summary, /auth_blocked=\[user\]/);
});

test("matching responses across profiles produce no divergences", () => {
  const result = diffResponseSignatures({
    signatures_by_profile: {
      admin: computeResponseSignature({ status: 200, body: { id: "1" } }),
      user: computeResponseSignature({ status: 200, body: { id: "1" } }),
    },
  });
  assert.deepEqual(result, []);
});

test("body_length_bucket divergence emitted when sizes differ across buckets", () => {
  const result = diffResponseSignatures({
    signatures_by_profile: {
      admin: computeResponseSignature({ status: 200, body: { id: "1", data: "a".repeat(2000) } }),
      user: computeResponseSignature({ status: 200, body: { id: "1" } }),
    },
  });
  const length = result.find((d) => d.type === "body_length_bucket_differs");
  assert.ok(length);
});

test("response_class divergence emitted when profiles get different response classes", () => {
  const result = diffResponseSignatures({
    signatures_by_profile: {
      admin: computeResponseSignature({ status: 200, body: {} }),
      user: computeResponseSignature({ status: 404, body: null }),
    },
  });
  const cls = result.find((d) => d.type === "response_class_differs");
  assert.ok(cls);
});

test("DIVERGENCE_TYPES enumerates every type the differ can emit", () => {
  for (const type of [
    "status_class_differs",
    "response_class_differs",
    "body_hash_differs",
    "body_length_bucket_differs",
    "sensitive_field_count_differs",
    "unauth_succeeds_where_auth_blocked",
  ]) {
    assert.ok(DIVERGENCE_TYPES.includes(type), `${type} present`);
  }
});

test("diffResponseSignatures rejects malformed input", () => {
  assert.throws(() => diffResponseSignatures(null), /input/);
  assert.throws(
    () => diffResponseSignatures({ signatures_by_profile: { admin: "not-a-sig", user: {} } }),
    /signature/,
  );
});

test("diff output sorted deterministically by divergence type", () => {
  const result = diffResponseSignatures({
    signatures_by_profile: {
      a: computeResponseSignature({ status: 200, body: { id: "1", email: "a@x", admin_role: true } }),
      b: computeResponseSignature({ status: 403, body: null }),
    },
  });
  const types = result.map((d) => d.type);
  assert.deepEqual(types, [...types].sort());
});
