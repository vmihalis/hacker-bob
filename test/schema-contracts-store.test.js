"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");

const {
  ingestSchemaDoc,
  querySchemaContracts,
} = require("../mcp/lib/schema-contracts-store.js");

function uniqueDomain(prefix = "bob-schema-store-test") {
  const suffix = crypto.randomBytes(4).toString("hex");
  return `${prefix}-${suffix}.local`;
}

function domainDir(domain) {
  return path.join(os.homedir(), "hacker-bob-sessions", domain);
}

function cleanupDomain(domain) {
  const dir = domainDir(domain);
  if (fs.existsSync(dir)) fs.rmSync(dir, { recursive: true, force: true });
}

const MINIMAL_OPENAPI_JSON = JSON.stringify({
  openapi: "3.0.3",
  paths: {
    "/users": {
      get: { responses: { "200": { description: "ok" } } },
      post: {
        security: [{ bearerAuth: [] }],
        requestBody: {
          required: true,
          content: { "application/json": { schema: { type: "object" } } },
        },
        responses: { "201": { description: "created" } },
      },
    },
  },
});

const ALT_OPENAPI_JSON = JSON.stringify({
  openapi: "3.0.3",
  paths: {
    "/admin/users": {
      delete: { responses: { "204": { description: "no content" } } },
    },
  },
});

test("ingestSchemaDoc persists contracts and returns ingestion summary", () => {
  const domain = uniqueDomain();
  try {
    const result = ingestSchemaDoc({
      target_domain: domain,
      raw_doc: MINIMAL_OPENAPI_JSON,
      source_uri: "https://example.com/openapi.json",
    });
    assert.equal(result.schema_format, "openapi-3");
    assert.equal(result.contract_count, 2);
    assert.equal(result.new_count, 2);
    assert.equal(result.replaced_count, 0);
    assert.equal(result.total_in_corpus, 2);
    assert.equal(result.source_uri, "https://example.com/openapi.json");
    assert.ok(result.source_doc_hash, "source_doc_hash returned");
    assert.ok(fs.existsSync(path.join(domainDir(domain), "schema-contracts.jsonl")));
  } finally {
    cleanupDomain(domain);
  }
});

test("re-ingesting the same doc deduplicates by contract_hash", () => {
  const domain = uniqueDomain();
  try {
    const first = ingestSchemaDoc({ target_domain: domain, raw_doc: MINIMAL_OPENAPI_JSON });
    const second = ingestSchemaDoc({ target_domain: domain, raw_doc: MINIMAL_OPENAPI_JSON });
    assert.equal(first.new_count, 2);
    assert.equal(second.new_count, 0);
    assert.equal(second.replaced_count, 2);
    assert.equal(second.total_in_corpus, 2);
  } finally {
    cleanupDomain(domain);
  }
});

test("ingesting two different docs accumulates contracts", () => {
  const domain = uniqueDomain();
  try {
    ingestSchemaDoc({ target_domain: domain, raw_doc: MINIMAL_OPENAPI_JSON });
    const second = ingestSchemaDoc({ target_domain: domain, raw_doc: ALT_OPENAPI_JSON });
    assert.equal(second.new_count, 1);
    assert.equal(second.total_in_corpus, 3);
  } finally {
    cleanupDomain(domain);
  }
});

test("querySchemaContracts filters by HTTP method (case-insensitive)", () => {
  const domain = uniqueDomain();
  try {
    ingestSchemaDoc({ target_domain: domain, raw_doc: MINIMAL_OPENAPI_JSON });
    const all = querySchemaContracts({ target_domain: domain });
    assert.equal(all.total_matched, 2);
    const upper = querySchemaContracts({ target_domain: domain, method: "GET" });
    assert.equal(upper.total_matched, 1);
    const lower = querySchemaContracts({ target_domain: domain, method: "get" });
    assert.equal(lower.total_matched, 1);
    assert.equal(upper.contracts[0].contract_hash, lower.contracts[0].contract_hash);
  } finally {
    cleanupDomain(domain);
  }
});

test("querySchemaContracts filters by endpoint substring", () => {
  const domain = uniqueDomain();
  try {
    ingestSchemaDoc({ target_domain: domain, raw_doc: MINIMAL_OPENAPI_JSON });
    ingestSchemaDoc({ target_domain: domain, raw_doc: ALT_OPENAPI_JSON });
    const usersOnly = querySchemaContracts({ target_domain: domain, endpoint_pattern: "users" });
    assert.equal(usersOnly.total_matched, 3);
    const adminOnly = querySchemaContracts({ target_domain: domain, endpoint_pattern: "/admin" });
    assert.equal(adminOnly.total_matched, 1);
    assert.equal(adminOnly.contracts[0].endpoint, "/admin/users");
  } finally {
    cleanupDomain(domain);
  }
});

test("querySchemaContracts on missing corpus returns empty result", () => {
  const domain = uniqueDomain();
  try {
    const result = querySchemaContracts({ target_domain: domain });
    assert.equal(result.contracts.length, 0);
    assert.equal(result.total_in_corpus, 0);
    assert.equal(result.source_count, 0);
  } finally {
    cleanupDomain(domain);
  }
});

test("ingestSchemaDoc with malformed JSON returns warnings without writing corpus", () => {
  const domain = uniqueDomain();
  try {
    const result = ingestSchemaDoc({ target_domain: domain, raw_doc: "{ not json" });
    assert.equal(result.schema_format, null);
    assert.equal(result.contract_count, 0);
    assert.match(result.parser_warnings[0], /^json_parse_failed:/);
    const corpusFile = path.join(domainDir(domain), "schema-contracts.jsonl");
    assert.ok(!fs.existsSync(corpusFile), "no corpus file written for malformed input");
  } finally {
    cleanupDomain(domain);
  }
});

test("schema-contracts.jsonl is sorted by contract_hash for replay determinism", () => {
  const domain = uniqueDomain();
  try {
    ingestSchemaDoc({ target_domain: domain, raw_doc: MINIMAL_OPENAPI_JSON });
    ingestSchemaDoc({ target_domain: domain, raw_doc: ALT_OPENAPI_JSON });
    const filePath = path.join(domainDir(domain), "schema-contracts.jsonl");
    const content = fs.readFileSync(filePath, "utf8");
    const lines = content.split("\n").filter((line) => line.trim().length > 0);
    const records = lines.map((line) => JSON.parse(line));
    for (let i = 1; i < records.length; i++) {
      assert.ok(
        records[i - 1].contract_hash <= records[i].contract_hash,
        `records sorted by contract_hash at line ${i}`,
      );
    }
  } finally {
    cleanupDomain(domain);
  }
});

test("ingestSchemaDoc rejects unsafe target_domain", () => {
  assert.throws(
    () => ingestSchemaDoc({ target_domain: "../escape", raw_doc: MINIMAL_OPENAPI_JSON }),
    /target_domain/,
  );
  assert.throws(
    () => ingestSchemaDoc({ target_domain: "x/y", raw_doc: MINIMAL_OPENAPI_JSON }),
    /target_domain/,
  );
});

test("ingestSchemaDoc rejects empty raw_doc", () => {
  const domain = uniqueDomain();
  try {
    assert.throws(
      () => ingestSchemaDoc({ target_domain: domain, raw_doc: "" }),
      /raw_doc/,
    );
  } finally {
    cleanupDomain(domain);
  }
});
