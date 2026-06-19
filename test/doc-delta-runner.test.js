"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");

const {
  runDocDelta,
  readResults,
  joinUrl,
  MAX_LIMIT,
} = require("../mcp/lib/doc-delta-runner.js");
const {
  ingestSchemaDoc,
} = require("../mcp/lib/schema-contracts-store.js");

function uniqueDomain(prefix = "bob-doc-delta-test") {
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

function buildOpenApiDoc() {
  return JSON.stringify({
    openapi: "3.0.3",
    paths: {
      "/users": {
        get: {
          security: [{ bearerAuth: [] }],
          responses: {
            "200": {
              description: "ok",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    required: ["id"],
                    properties: { id: { type: "string" }, name: { type: "string" } },
                  },
                },
              },
            },
            "401": { description: "unauthorized" },
          },
        },
      },
      "/health": {
        get: {
          responses: {
            "200": {
              description: "ok",
              content: { "application/json": { schema: { type: "object" } } },
            },
          },
        },
      },
    },
  });
}

function seedCorpus(domain) {
  ingestSchemaDoc({
    target_domain: domain,
    raw_doc: buildOpenApiDoc(),
    source_uri: "https://example.com/openapi.json",
  });
}

test("joinUrl normalizes trailing slash and leading slash", () => {
  assert.equal(joinUrl("https://api.example.com/", "/users"), "https://api.example.com/users");
  assert.equal(joinUrl("https://api.example.com", "users"), "https://api.example.com/users");
  assert.equal(joinUrl("https://api.example.com//", "/users/"), "https://api.example.com/users/");
});

test("joinUrl rejects empty inputs", () => {
  assert.throws(() => joinUrl("", "/x"), /base_url/);
  assert.throws(() => joinUrl("https://api.example.com", ""), /endpoint/);
});

test("runDocDelta produces zero divergences when responses match the spec", async () => {
  const domain = uniqueDomain();
  try {
    seedCorpus(domain);
    const fetch_fn = async ({ contract }) => {
      if (contract.endpoint === "/users") {
        return {
          status: 200,
          content_type: "application/json",
          body: { id: "u-1", name: "Alice" },
          sent_with_auth: true,
        };
      }
      return {
        status: 200,
        content_type: "application/json",
        body: {},
        sent_with_auth: false,
      };
    };
    const result = await runDocDelta({
      target_domain: domain,
      base_url: "https://api.example.com",
      fetch_fn,
    });
    assert.equal(result.summary.contracts_tested, 2);
    assert.equal(result.summary.divergences_total, 0);
    assert.equal(result.summary.fetch_errors, 0);
    assert.deepEqual(result.summary.divergences_by_type, {});
  } finally {
    cleanupDomain(domain);
  }
});

test("runDocDelta surfaces auth bypass when claimed-auth endpoint succeeds without auth", async () => {
  const domain = uniqueDomain();
  try {
    seedCorpus(domain);
    const fetch_fn = async ({ contract }) => ({
      status: 200,
      content_type: "application/json",
      body: contract.endpoint === "/users" ? { id: "u-1" } : {},
      sent_with_auth: false,
    });
    const result = await runDocDelta({
      target_domain: domain,
      base_url: "https://api.example.com",
      fetch_fn,
    });
    assert.ok(result.summary.divergences_total >= 1);
    assert.ok(result.summary.divergences_by_type.auth_required_but_succeeded_without >= 1);
    assert.ok(result.summary.divergences_by_severity.security >= 1);
  } finally {
    cleanupDomain(domain);
  }
});

test("runDocDelta records fetch_error when fetch_fn throws and continues with other contracts", async () => {
  const domain = uniqueDomain();
  try {
    seedCorpus(domain);
    const fetch_fn = async ({ contract }) => {
      if (contract.endpoint === "/users") {
        throw new Error("connection refused");
      }
      return { status: 200, content_type: "application/json", body: {}, sent_with_auth: false };
    };
    const result = await runDocDelta({
      target_domain: domain,
      base_url: "https://api.example.com",
      fetch_fn,
    });
    assert.equal(result.summary.fetch_errors, 1);
    const errored = result.per_contract.find((entry) => entry.fetch_error);
    assert.match(errored.fetch_error, /connection refused/);
    assert.equal(errored.observed, null);
    assert.equal(errored.divergences.length, 0);
    assert.equal(result.summary.contracts_tested, 2);
  } finally {
    cleanupDomain(domain);
  }
});

test("runDocDelta persists results to doc-delta-results.json with deterministic results_hash", async () => {
  const domain = uniqueDomain();
  try {
    seedCorpus(domain);
    const fetch_fn = async ({ contract }) => ({
      status: 200,
      content_type: "application/json",
      body: contract.endpoint === "/users" ? { id: "u-1", name: "Alice" } : {},
      sent_with_auth: contract.endpoint === "/users",
    });
    const first = await runDocDelta({
      target_domain: domain,
      base_url: "https://api.example.com",
      fetch_fn,
    });
    const second = await runDocDelta({
      target_domain: domain,
      base_url: "https://api.example.com",
      fetch_fn,
    });
    assert.equal(first.results_hash, second.results_hash);
    const fromDisk = readResults(domain);
    assert.equal(fromDisk.results_hash, second.results_hash);
    const filePath = path.join(domainDir(domain), "doc-delta-results.json");
    assert.ok(fs.existsSync(filePath));
  } finally {
    cleanupDomain(domain);
  }
});

test("runDocDelta filters corpus by endpoint_pattern", async () => {
  const domain = uniqueDomain();
  try {
    seedCorpus(domain);
    const fetch_fn = async () => ({
      status: 200,
      content_type: "application/json",
      body: {},
      sent_with_auth: false,
    });
    const result = await runDocDelta({
      target_domain: domain,
      base_url: "https://api.example.com",
      fetch_fn,
      endpoint_pattern: "/health",
    });
    assert.equal(result.summary.contracts_tested, 1);
    assert.equal(result.per_contract.length, 1);
    assert.equal(result.per_contract[0].endpoint, "/health");
  } finally {
    cleanupDomain(domain);
  }
});

test("runDocDelta caps caller-supplied limit at MAX_LIMIT", async () => {
  const domain = uniqueDomain();
  try {
    const paths = {};
    for (let i = 0; i < MAX_LIMIT + 5; i++) {
      paths[`/items/${i}`] = {
        get: {
          responses: {
            "200": {
              description: "ok",
              content: { "application/json": { schema: { type: "object" } } },
            },
          },
        },
      };
    }
    ingestSchemaDoc({
      target_domain: domain,
      raw_doc: JSON.stringify({ openapi: "3.0.3", paths }),
      source_uri: "https://example.com/openapi-large.json",
    });
    let fetchCount = 0;
    const fetch_fn = async () => {
      fetchCount += 1;
      return { status: 200, content_type: "application/json", body: {}, sent_with_auth: false };
    };
    const result = await runDocDelta({
      target_domain: domain,
      base_url: "https://api.example.com",
      fetch_fn,
      limit: 999_999,
    });
    assert.equal(result.summary.contracts_tested, MAX_LIMIT);
    assert.equal(fetchCount, MAX_LIMIT);
  } finally {
    cleanupDomain(domain);
  }
});

test("runDocDelta tolerates an empty corpus by reporting zero contracts tested", async () => {
  const domain = uniqueDomain();
  try {
    const fetch_fn = async () => ({
      status: 200,
      content_type: "application/json",
      body: {},
      sent_with_auth: false,
    });
    const result = await runDocDelta({
      target_domain: domain,
      base_url: "https://api.example.com",
      fetch_fn,
    });
    assert.equal(result.summary.contracts_tested, 0);
    assert.equal(result.summary.divergences_total, 0);
  } finally {
    cleanupDomain(domain);
  }
});

test("runDocDelta records a deterministic per_contract sort by contract_hash", async () => {
  const domain = uniqueDomain();
  try {
    seedCorpus(domain);
    const fetch_fn = async () => ({
      status: 200,
      content_type: "application/json",
      body: {},
      sent_with_auth: false,
    });
    const result = await runDocDelta({
      target_domain: domain,
      base_url: "https://api.example.com",
      fetch_fn,
    });
    for (let i = 1; i < result.per_contract.length; i++) {
      assert.ok(
        result.per_contract[i - 1].contract_hash <= result.per_contract[i].contract_hash,
        `per_contract sorted at index ${i}`,
      );
    }
  } finally {
    cleanupDomain(domain);
  }
});

test("runDocDelta validates required arguments", async () => {
  await assert.rejects(
    () => runDocDelta({ target_domain: "x", base_url: "", fetch_fn: () => {} }),
    /base_url/,
  );
  await assert.rejects(
    () => runDocDelta({ target_domain: "x", base_url: "https://x", fetch_fn: null }),
    /fetch_fn/,
  );
});

test("runDocDelta records run_id when supplied", async () => {
  const domain = uniqueDomain();
  try {
    seedCorpus(domain);
    const fetch_fn = async () => ({
      status: 200,
      content_type: "application/json",
      body: {},
      sent_with_auth: false,
    });
    const result = await runDocDelta({
      target_domain: domain,
      base_url: "https://api.example.com",
      fetch_fn,
      run_id: "run-12345",
    });
    assert.equal(result.summary.run_id, "run-12345");
  } finally {
    cleanupDomain(domain);
  }
});

test("readResults returns null when no run has happened yet", () => {
  const domain = uniqueDomain();
  try {
    assert.equal(readResults(domain), null);
  } finally {
    cleanupDomain(domain);
  }
});
