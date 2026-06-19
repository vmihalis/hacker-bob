"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");

const {
  ingestSchemaDoc,
  summarizeSchemaSliceForSurface,
} = require("../mcp/lib/schema-contracts-store.js");

function uniqueDomain(prefix = "bob-schema-slice-test") {
  const suffix = crypto.randomBytes(4).toString("hex");
  return `${prefix}-${suffix}.local`;
}

function cleanupDomain(domain) {
  const dir = path.join(os.homedir(), "hacker-bob-sessions", domain);
  if (fs.existsSync(dir)) fs.rmSync(dir, { recursive: true, force: true });
}

const OPENAPI_DOC = JSON.stringify({
  openapi: "3.0.3",
  paths: {
    "/users": {
      get: { responses: { "200": { description: "ok" } } },
      post: {
        security: [{ bearerAuth: [] }],
        responses: { "201": { description: "created" } },
      },
    },
    "/users/{id}": {
      parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
      get: { responses: { "200": { description: "ok" } } },
      delete: { responses: { "204": { description: "no content" } } },
    },
    "/admin/audit": {
      get: {
        security: [{ apiKey: [] }],
        responses: { "200": { description: "ok" } },
      },
    },
  },
});

test("summarizeSchemaSliceForSurface returns null when corpus is empty", () => {
  const domain = uniqueDomain();
  try {
    const result = summarizeSchemaSliceForSurface(domain, { endpoints: ["/x"] });
    assert.equal(result, null);
  } finally {
    cleanupDomain(domain);
  }
});

test("schema_slice limits to 5 contracts by default and reports total_in_corpus", () => {
  const domain = uniqueDomain();
  try {
    ingestSchemaDoc({ target_domain: domain, raw_doc: OPENAPI_DOC });
    const slice = summarizeSchemaSliceForSurface(domain, { endpoints: [] });
    assert.equal(slice.total_in_corpus, 5);
    assert.equal(slice.contracts.length, 5);
    assert.equal(slice.limit, 5);
  } finally {
    cleanupDomain(domain);
  }
});

test("endpoint_pattern hint filters contracts to matching endpoints", () => {
  const domain = uniqueDomain();
  try {
    ingestSchemaDoc({ target_domain: domain, raw_doc: OPENAPI_DOC });
    const slice = summarizeSchemaSliceForSurface(domain, { endpoint_pattern: "/admin" });
    assert.equal(slice.matched_to_surface, 1);
    assert.equal(slice.hint_applied, "/admin");
    assert.equal(slice.contracts[0].endpoint, "/admin/audit");
  } finally {
    cleanupDomain(domain);
  }
});

test("endpoints array hint falls through endpoints in order until one matches", () => {
  const domain = uniqueDomain();
  try {
    ingestSchemaDoc({ target_domain: domain, raw_doc: OPENAPI_DOC });
    const slice = summarizeSchemaSliceForSurface(domain, {
      endpoints: ["/no-such-thing", "/users", "/admin"],
    });
    assert.equal(slice.hint_applied, "/users");
    assert.ok(slice.matched_to_surface >= 2);
    for (const contract of slice.contracts) {
      assert.match(contract.endpoint, /\/users/);
    }
  } finally {
    cleanupDomain(domain);
  }
});

test("compact contracts include claimed_auth_schemes, status codes, and truncated hash", () => {
  const domain = uniqueDomain();
  try {
    ingestSchemaDoc({ target_domain: domain, raw_doc: OPENAPI_DOC });
    const slice = summarizeSchemaSliceForSurface(domain, { endpoint_pattern: "/admin" });
    const contract = slice.contracts[0];
    assert.deepEqual(contract.claimed_auth_schemes, ["apiKey"]);
    assert.deepEqual(contract.documented_status_codes, ["200"]);
    assert.equal(contract.contract_hash.length, 16);
    assert.equal(contract.schema_format, "openapi-3");
  } finally {
    cleanupDomain(domain);
  }
});

test("limit option caps below the hard ceiling", () => {
  const domain = uniqueDomain();
  try {
    ingestSchemaDoc({ target_domain: domain, raw_doc: OPENAPI_DOC });
    const slice = summarizeSchemaSliceForSurface(domain, {}, { limit: 2 });
    assert.equal(slice.limit, 2);
    assert.equal(slice.contracts.length, 2);
    assert.equal(slice.truncated, true);
  } finally {
    cleanupDomain(domain);
  }
});

test("limit above hard ceiling clamps to 25", () => {
  const domain = uniqueDomain();
  try {
    ingestSchemaDoc({ target_domain: domain, raw_doc: OPENAPI_DOC });
    const slice = summarizeSchemaSliceForSurface(domain, {}, { limit: 9999 });
    assert.equal(slice.limit, 25);
    assert.equal(slice.contracts.length, 5);
    assert.equal(slice.truncated, false);
  } finally {
    cleanupDomain(domain);
  }
});

test("hint with no matches falls back to unfiltered contract list", () => {
  const domain = uniqueDomain();
  try {
    ingestSchemaDoc({ target_domain: domain, raw_doc: OPENAPI_DOC });
    const slice = summarizeSchemaSliceForSurface(domain, { endpoint_pattern: "/nothing-matches" });
    assert.equal(slice.hint_applied, null);
    assert.equal(slice.matched_to_surface, 5);
  } finally {
    cleanupDomain(domain);
  }
});
