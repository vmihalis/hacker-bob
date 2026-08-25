"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  parsePostmanCollection,
  looksLikePostmanCollection,
} = require("../mcp/core/postman-parser.js");

const SIMPLE_COLLECTION = Object.freeze({
  info: {
    name: "Demo",
    schema: "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
  },
  item: [
    {
      name: "Get user",
      request: {
        method: "GET",
        url: {
          raw: "https://api.example.com/users/:userId",
          host: ["api", "example", "com"],
          path: ["users", ":userId"],
          variable: [{ key: "userId", value: "u-1" }],
          query: [{ key: "expand", value: "profile", disabled: false }],
        },
        header: [
          { key: "X-Trace", value: "abc" },
          { key: "Authorization", value: "Bearer xxx" },
        ],
        auth: { type: "bearer", bearer: [{ key: "token", value: "{{TOKEN}}" }] },
      },
      response: [
        {
          name: "200 OK",
          code: 200,
          header: [{ key: "Content-Type", value: "application/json" }],
          body: JSON.stringify({ id: "u-1", name: "Alice" }),
        },
      ],
    },
    {
      name: "Folder",
      item: [
        {
          name: "Create user",
          request: {
            method: "POST",
            url: { raw: "https://api.example.com/users", path: ["users"] },
            body: {
              mode: "raw",
              raw: JSON.stringify({ name: "Alice", email: "a@x" }),
              options: { raw: { language: "json" } },
            },
          },
        },
      ],
    },
  ],
  auth: { type: "apikey" },
});

test("looksLikePostmanCollection accepts a v2.1 collection envelope", () => {
  assert.equal(looksLikePostmanCollection(SIMPLE_COLLECTION), true);
});

test("looksLikePostmanCollection rejects non-collection JSON", () => {
  assert.equal(looksLikePostmanCollection({ openapi: "3.0.3" }), false);
  assert.equal(looksLikePostmanCollection({}), false);
  assert.equal(looksLikePostmanCollection(null), false);
  assert.equal(looksLikePostmanCollection({ item: [] }), false);
});

test("parsePostmanCollection emits one contract per leaf request, including nested folders", () => {
  const result = parsePostmanCollection(SIMPLE_COLLECTION);
  assert.equal(result.schema_format, "postman");
  assert.equal(result.contracts.length, 2);
  const summaries = result.contracts.map((c) => `${c.method} ${c.endpoint}`).sort();
  assert.deepEqual(summaries, [
    "GET /users/{userId}",
    "POST /users",
  ]);
});

test("path variables convert :name to {name}", () => {
  const result = parsePostmanCollection(SIMPLE_COLLECTION);
  const getUser = result.contracts.find((c) => c.method === "GET");
  assert.equal(getUser.endpoint, "/users/{userId}");
  const userIdParam = getUser.claimed_params.find((p) => p.in === "path" && p.name === "userId");
  assert.ok(userIdParam, "path variable extracted as param");
  assert.equal(userIdParam.required, true);
});

test("query parameters extracted with disabled flag honored", () => {
  const result = parsePostmanCollection({
    info: { name: "x", schema: "https://schema.getpostman.com/json/collection/v2.1.0/collection.json" },
    item: [
      {
        name: "x",
        request: {
          method: "GET",
          url: {
            raw: "https://x/y",
            path: ["y"],
            query: [
              { key: "active", value: "1" },
              { key: "deprecated", value: "1", disabled: true },
            ],
          },
        },
      },
    ],
  });
  const params = result.contracts[0].claimed_params;
  const active = params.find((p) => p.name === "active");
  const deprecated = params.find((p) => p.name === "deprecated");
  assert.equal(active.required, true);
  assert.equal(deprecated.required, false);
});

test("Authorization and Content-Type request headers are excluded from claimed_params", () => {
  const result = parsePostmanCollection(SIMPLE_COLLECTION);
  const getUser = result.contracts.find((c) => c.method === "GET");
  const headerNames = getUser.claimed_params
    .filter((p) => p.in === "header")
    .map((p) => p.name.toLowerCase());
  assert.ok(!headerNames.includes("authorization"));
  assert.ok(!headerNames.includes("content-type"));
  assert.ok(headerNames.includes("x-trace"));
});

test("raw JSON body synthesizes a body param with inferred shape", () => {
  const result = parsePostmanCollection(SIMPLE_COLLECTION);
  const create = result.contracts.find((c) => c.method === "POST");
  const body = create.claimed_params.find((p) => p.in === "body");
  assert.ok(body);
  assert.equal(body.schema_type, "object");
  assert.equal(body.content_type, "application/json");
  assert.ok(body.schema_shape.properties.name);
  assert.ok(body.schema_shape.properties.email);
});

test("collection-level auth cascades to items without their own auth", () => {
  const result = parsePostmanCollection(SIMPLE_COLLECTION);
  const create = result.contracts.find((c) => c.method === "POST");
  assert.deepEqual(create.claimed_auth, {
    schemes: ["postman_auth:apikey"],
    none_allowed: false,
  });
});

test("item-level auth overrides collection-level auth", () => {
  const result = parsePostmanCollection(SIMPLE_COLLECTION);
  const getUser = result.contracts.find((c) => c.method === "GET");
  assert.deepEqual(getUser.claimed_auth, {
    schemes: ["postman_auth:bearer"],
    none_allowed: false,
  });
});

test("noauth type produces none_allowed: true", () => {
  const result = parsePostmanCollection({
    info: { name: "x", schema: "https://schema.getpostman.com/json/collection/v2.1.0/collection.json" },
    auth: { type: "noauth" },
    item: [
      {
        name: "ping",
        request: { method: "GET", url: { raw: "https://x/ping", path: ["ping"] } },
      },
    ],
  });
  assert.deepEqual(result.contracts[0].claimed_auth, { schemes: [], none_allowed: true });
});

test("response examples populate claimed_response_shape with content_type and shape", () => {
  const result = parsePostmanCollection(SIMPLE_COLLECTION);
  const getUser = result.contracts.find((c) => c.method === "GET");
  const ok = getUser.claimed_response_shape["200"];
  assert.equal(ok.content_type, "application/json");
  assert.equal(ok.shape.type, "object");
  assert.ok(ok.shape.properties.id);
  assert.ok(ok.shape.properties.name);
});

test("urlencoded and formdata bodies record content_type without shape inference", () => {
  const result = parsePostmanCollection({
    info: { name: "x", schema: "https://schema.getpostman.com/json/collection/v2.1.0/collection.json" },
    item: [
      {
        name: "form",
        request: {
          method: "POST",
          url: { raw: "https://x/form", path: ["form"] },
          body: { mode: "urlencoded", urlencoded: [{ key: "x", value: "y" }] },
        },
      },
    ],
  });
  const body = result.contracts[0].claimed_params.find((p) => p.in === "body");
  assert.equal(body.content_type, "application/x-www-form-urlencoded");
  assert.equal(body.schema_shape, null);
});

test("contract_hash is stable across re-parses of the same collection", () => {
  const a = parsePostmanCollection(SIMPLE_COLLECTION);
  const b = parsePostmanCollection(SIMPLE_COLLECTION);
  assert.equal(a.source_doc_hash, b.source_doc_hash);
  for (let i = 0; i < a.contracts.length; i++) {
    assert.equal(a.contracts[i].contract_hash, b.contracts[i].contract_hash);
  }
});

test("malformed item lacking a request is skipped without throwing", () => {
  const result = parsePostmanCollection({
    info: { name: "x", schema: "https://schema.getpostman.com/json/collection/v2.1.0/collection.json" },
    item: [
      { name: "no request", description: "..." },
      {
        name: "real",
        request: { method: "GET", url: { raw: "https://x/y", path: ["y"] } },
      },
    ],
  });
  assert.equal(result.contracts.length, 1);
});

test("non-postman input emits not_a_postman_collection warning", () => {
  const result = parsePostmanCollection({ random: "blob" });
  assert.equal(result.contracts.length, 0);
  assert.deepEqual(result.parser_warnings, ["not_a_postman_collection"]);
});
