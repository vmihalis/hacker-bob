"use strict";

// param-lineage — pure dataflow: harvest id key->value pairs from a real 2xx JSON
// body and bind them into id_bearing endpoint templates. The load-bearing property is
// HONESTY: a value only ever appears if it was literally present in the body; no
// harvestable value for a required slot -> empty (never a fabricated id).

const test = require("node:test");
const assert = require("node:assert/strict");

const { extractIds, bindLineage } = require("../mcp/core/param-lineage.js");

test("extractIds harvests id key->value pairs from a nested 2xx JSON body", () => {
  const body = JSON.stringify({
    id: 42,
    name: "Widget",
    order_id: "9f8b",              // too short / not id-shaped value -> dropped
    orderId: 1007,
    owner: {
      user_id: 7,
      uuid: "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
      profile: { slug: "acme-corp-primary-account" },
    },
    items: [
      { item_id: 555, qty: 2 },
      { item_id: 556, qty: 1 },   // duplicate bare key -> first-seen wins (555)
    ],
    note: "id is mentioned here but this is prose",
  });

  const ids = extractIds(body, { contentType: "application/json" });

  assert.equal(ids.id, "42");
  assert.equal(ids.orderId, "1007");
  assert.equal(ids.user_id, "7");
  assert.equal(ids.uuid, "3f2504e0-4f89-41d3-9a0c-0305e82c3301");
  assert.equal(ids.slug, "acme-corp-primary-account");
  assert.equal(ids.item_id, "555"); // first-seen wins across the array
  // "9f8b" is at an id-shaped key but is not an id-shaped VALUE -> never harvested.
  assert.equal(Object.prototype.hasOwnProperty.call(ids, "order_id"), false);
  // Non-id keys are never harvested.
  assert.equal(Object.prototype.hasOwnProperty.call(ids, "name"), false);
  assert.equal(Object.prototype.hasOwnProperty.call(ids, "note"), false);
});

test("extractIds is deterministic: byte-identical across runs and regardless of source key order", () => {
  const a = { order_id: 1007, user_id: 7, uuid: "3f2504e0-4f89-41d3-9a0c-0305e82c3301" };
  const b = { uuid: "3f2504e0-4f89-41d3-9a0c-0305e82c3301", user_id: 7, order_id: 1007 };

  const outA1 = JSON.stringify(extractIds(JSON.stringify(a)));
  const outA2 = JSON.stringify(extractIds(JSON.stringify(a)));
  const outB = JSON.stringify(extractIds(JSON.stringify(b)));

  assert.equal(outA1, outA2, "same input -> byte-identical across runs");
  assert.equal(outA1, outB, "reordered source keys -> byte-identical output");
});

test("extractIds accepts an already-parsed object", () => {
  const ids = extractIds({ order_id: 1007, name: "x" });
  assert.deepEqual(ids, { order_id: "1007" });
});

test("extractIds fails closed: parse failure and non-JSON contentType -> {} (never throws)", () => {
  assert.deepEqual(extractIds("not json at all {", { contentType: "application/json" }), {});
  assert.deepEqual(extractIds("<html>404</html>"), {});
  assert.deepEqual(extractIds(JSON.stringify({ order_id: 1007 }), { contentType: "text/html" }), {});
  assert.deepEqual(extractIds(""), {});
  assert.deepEqual(extractIds(null), {});
  assert.deepEqual(extractIds(undefined), {});
});

test("extractIds no id-shaped keys -> {} (honest empty)", () => {
  assert.deepEqual(extractIds(JSON.stringify({ name: "x", total: 3, status: "ok" })), {});
});

test("bindLineage fills /api/orders/:id from an extracted order id", () => {
  const ids = extractIds(JSON.stringify({ order_id: 1007, name: "Widget" }));
  const endpoints = bindLineage("/api/orders/:id", ids);
  assert.deepEqual(endpoints, ["/api/orders/1007"]);
});

test("bindLineage fills the {id} spelling too (canonical single source via templatize)", () => {
  const ids = extractIds(JSON.stringify({ order_id: 1007 }));
  const colon = bindLineage("/api/orders/:id", ids);
  const brace = bindLineage("/api/orders/{id}", ids);
  assert.deepEqual(colon, ["/api/orders/1007"]);
  assert.deepEqual(brace, ["/api/orders/1007"]);
  assert.deepEqual(colon, brace);
});

test("bindLineage prefers the preceding-noun key, falling back to a generic id", () => {
  // order_id matches the /orders/ noun; the generic `id` is NOT additive when a noun match exists.
  const nounMatch = bindLineage("/api/orders/{id}", { order_id: "1007", id: "9" });
  assert.deepEqual(nounMatch, ["/api/orders/1007"]);

  // Only a generic id present -> fallback fills the slot.
  const generic = bindLineage("/api/orders/{id}", { id: "9" });
  assert.deepEqual(generic, ["/api/orders/9"]);
});

test("bindLineage no-match -> empty (never a fabricated id, never a partial URL)", () => {
  // A user id cannot mis-bind into an /orders/ slot, and there is no generic id.
  assert.deepEqual(bindLineage("/api/orders/{id}", { user_id: "7" }), []);
  // Empty harvest -> empty.
  assert.deepEqual(bindLineage("/api/orders/{id}", {}), []);
  // Non-id-bearing template -> empty (templatize returns null).
  assert.deepEqual(bindLineage("/api/orders", { id: "9" }), []);
  // Bad extracted argument -> empty.
  assert.deepEqual(bindLineage("/api/orders/{id}", null), []);
  assert.deepEqual(bindLineage("/api/orders/{id}", ["9"]), []);
});

test("bindLineage multi-{id} determinism: each slot resolves to its own noun", () => {
  const ids = { user_id: "7", order_id: "1007" };
  const out1 = bindLineage("/api/users/{id}/orders/{id}", ids);
  const out2 = bindLineage("/api/users/:id/orders/:id", ids);
  assert.deepEqual(out1, ["/api/users/7/orders/1007"]);
  assert.deepEqual(out2, ["/api/users/7/orders/1007"]);
  assert.deepEqual(out1, out2, "spelling-invariant and deterministic");

  // A required second slot with no viable value -> whole binding empty (no partial URL).
  assert.deepEqual(bindLineage("/api/users/{id}/orders/{id}", { user_id: "7" }), []);
});

test("bindLineage multi-value produces one sorted, deduped endpoint per viable binding", () => {
  // Two distinct order-noun values -> two endpoints, sorted & deduped, no fabrication.
  const out = bindLineage("/api/orders/{id}", { order_id: "1007", orderId: "42" });
  assert.deepEqual(out, ["/api/orders/1007", "/api/orders/42"]);
});
