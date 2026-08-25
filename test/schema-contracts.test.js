"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  parseSchemaDoc,
  parseOpenApi3,
} = require("../mcp/core/schema-contracts.js");

const MINIMAL_OPENAPI_3 = Object.freeze({
  openapi: "3.0.3",
  info: { title: "Demo", version: "1.0.0" },
  paths: {
    "/users": {
      get: {
        responses: {
          "200": {
            description: "ok",
            content: {
              "application/json": {
                schema: { type: "array", items: { type: "object" } },
              },
            },
          },
        },
      },
      post: {
        security: [{ bearerAuth: [] }],
        requestBody: {
          required: true,
          content: {
            "application/json": {
              schema: {
                type: "object",
                required: ["email"],
                properties: { email: { type: "string" } },
              },
            },
          },
        },
        responses: {
          "201": { description: "created" },
          "400": { description: "bad request" },
        },
      },
    },
    "/users/{id}": {
      parameters: [
        { name: "id", in: "path", required: true, schema: { type: "string" } },
      ],
      get: {
        responses: { "200": { description: "ok" } },
      },
    },
  },
  security: [{ apiKeyAuth: [] }],
});

test("parseOpenApi3 emits one contract per (path, method)", () => {
  const result = parseOpenApi3(MINIMAL_OPENAPI_3);
  assert.equal(result.schema_format, "openapi-3");
  assert.equal(result.contracts.length, 3);
  assert.deepEqual(
    result.contracts.map((c) => `${c.method} ${c.endpoint}`).sort(),
    ["GET /users", "GET /users/{id}", "POST /users"],
  );
});

test("operation-level security overrides global security", () => {
  const result = parseOpenApi3(MINIMAL_OPENAPI_3);
  const getUsers = result.contracts.find((c) => c.endpoint === "/users" && c.method === "GET");
  const postUsers = result.contracts.find((c) => c.endpoint === "/users" && c.method === "POST");
  assert.deepEqual(getUsers.claimed_auth, { schemes: ["apiKeyAuth"], none_allowed: false });
  assert.deepEqual(postUsers.claimed_auth, { schemes: ["bearerAuth"], none_allowed: false });
});

test("path-level parameters merge into operation parameters", () => {
  const result = parseOpenApi3(MINIMAL_OPENAPI_3);
  const getById = result.contracts.find((c) => c.endpoint === "/users/{id}");
  const idParam = getById.claimed_params.find((p) => p.name === "id");
  assert.ok(idParam, "id param present");
  assert.equal(idParam.in, "path");
  assert.equal(idParam.required, true);
  assert.equal(idParam.schema_type, "string");
});

test("requestBody synthesizes a body parameter with content type", () => {
  const result = parseOpenApi3(MINIMAL_OPENAPI_3);
  const postUsers = result.contracts.find((c) => c.method === "POST");
  const body = postUsers.claimed_params.find((p) => p.in === "body");
  assert.ok(body, "body param synthesized");
  assert.equal(body.schema_type, "object");
  assert.equal(body.content_type, "application/json");
  assert.deepEqual(body.schema_shape.required, ["email"]);
});

test("contract_hash is stable across key reordering of input", () => {
  const shuffled = {
    info: MINIMAL_OPENAPI_3.info,
    paths: MINIMAL_OPENAPI_3.paths,
    security: MINIMAL_OPENAPI_3.security,
    openapi: MINIMAL_OPENAPI_3.openapi,
  };
  const a = parseOpenApi3(MINIMAL_OPENAPI_3);
  const b = parseOpenApi3(shuffled);
  assert.equal(a.source_doc_hash, b.source_doc_hash);
  for (let i = 0; i < a.contracts.length; i++) {
    assert.equal(a.contracts[i].contract_hash, b.contracts[i].contract_hash);
  }
});

test("parseSchemaDoc dispatches OpenAPI 3 by openapi field", () => {
  const raw = JSON.stringify(MINIMAL_OPENAPI_3);
  const result = parseSchemaDoc(raw);
  assert.equal(result.schema_format, "openapi-3");
  assert.equal(result.contracts.length, 3);
});

test("parseSchemaDoc reports json_parse_failed on malformed JSON", () => {
  const result = parseSchemaDoc("{ not json");
  assert.equal(result.schema_format, null);
  assert.equal(result.contracts.length, 0);
  assert.match(result.parser_warnings[0], /^json_parse_failed:/);
});

test("parseSchemaDoc reports unsupported_format for non-OpenAPI 3 JSON", () => {
  const result = parseSchemaDoc(JSON.stringify({ swagger: "2.0" }));
  assert.equal(result.schema_format, null);
  assert.deepEqual(result.parser_warnings, ["unsupported_format"]);
});

test("local $ref in parameters resolves to component definition", () => {
  const doc = {
    openapi: "3.0.3",
    paths: {
      "/items": {
        get: {
          parameters: [{ $ref: "#/components/parameters/Limit" }],
          responses: { "200": { description: "ok" } },
        },
      },
    },
    components: {
      parameters: {
        Limit: {
          name: "limit",
          in: "query",
          required: false,
          schema: { type: "integer" },
        },
      },
    },
  };
  const result = parseOpenApi3(doc);
  assert.equal(result.contracts.length, 1);
  const limit = result.contracts[0].claimed_params.find((p) => p.name === "limit");
  assert.ok(limit, "limit param resolved through $ref");
  assert.equal(limit.in, "query");
  assert.equal(limit.schema_type, "integer");
});

test("empty security requirement marks none_allowed without dropping schemes", () => {
  const doc = {
    openapi: "3.0.3",
    paths: {
      "/public": {
        get: {
          security: [{}, { bearerAuth: [] }],
          responses: { "200": { description: "ok" } },
        },
      },
    },
  };
  const result = parseOpenApi3(doc);
  assert.equal(result.contracts.length, 1);
  assert.deepEqual(result.contracts[0].claimed_auth, {
    schemes: ["bearerAuth"],
    none_allowed: true,
  });
});

test("response without content yields content_type and shape both null", () => {
  const doc = {
    openapi: "3.0.3",
    paths: {
      "/ping": {
        head: {
          responses: { "204": { description: "no content" } },
        },
      },
    },
  };
  const result = parseOpenApi3(doc);
  const responseShape = result.contracts[0].claimed_response_shape["204"];
  assert.equal(responseShape.content_type, null);
  assert.equal(responseShape.shape, null);
});

test("malformed root produces a single root_not_object warning", () => {
  const result = parseOpenApi3("not an object");
  assert.equal(result.schema_format, "openapi-3");
  assert.equal(result.contracts.length, 0);
  assert.deepEqual(result.parser_warnings, ["root_not_object"]);
});

test("HTTP methods limited to OpenAPI-recognized verbs", () => {
  const doc = {
    openapi: "3.0.3",
    paths: {
      "/x": {
        get: { responses: { "200": { description: "ok" } } },
        invalidVerb: { responses: { "200": { description: "ok" } } },
      },
    },
  };
  const result = parseOpenApi3(doc);
  assert.equal(result.contracts.length, 1);
  assert.equal(result.contracts[0].method, "GET");
});
