"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");

const {
  runAuthDifferential,
  readResults,
  joinUrl,
  normalizeEndpoints,
  normalizeProfiles,
} = require("../mcp/lib/auth-differential-runner.js");

function uniqueDomain(prefix = "bob-authdiff-test") {
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

test("normalizeEndpoints accepts strings and {endpoint, method} objects", () => {
  const normalized = normalizeEndpoints([
    "/users",
    { endpoint: "/admin", method: "post" },
    { endpoint: "/health" },
  ]);
  assert.deepEqual(normalized, [
    { endpoint: "/admin", method: "POST" },
    { endpoint: "/health", method: "GET" },
    { endpoint: "/users", method: "GET" },
  ]);
});

test("normalizeProfiles deduplicates and rejects fewer than two", () => {
  assert.deepEqual(normalizeProfiles(["admin", "user", "admin"]), ["admin", "user"]);
  assert.throws(() => normalizeProfiles(["admin"]), /at least two/);
});

test("joinUrl normalizes leading and trailing slashes", () => {
  assert.equal(joinUrl("https://api/", "/x"), "https://api/x");
  assert.equal(joinUrl("https://api", "x"), "https://api/x");
});

test("runAuthDifferential produces no divergences when responses match across profiles", async () => {
  const domain = uniqueDomain();
  try {
    const fetch_fn = async () => ({
      status: 200,
      content_type: "application/json",
      body: { id: "1" },
      sent_with_auth: true,
    });
    const result = await runAuthDifferential({
      target_domain: domain,
      base_url: "https://api.example.com",
      endpoints: ["/users", "/health"],
      auth_profiles: ["admin", "user"],
      fetch_fn,
    });
    assert.equal(result.summary.endpoints_tested, 2);
    assert.equal(result.summary.profiles_tested, 2);
    assert.equal(result.summary.fetches_total, 4);
    assert.equal(result.summary.divergences_total, 0);
    assert.equal(result.summary.fetch_errors, 0);
  } finally {
    cleanupDomain(domain);
  }
});

test("runAuthDifferential surfaces status_class divergence when profiles get different status codes", async () => {
  const domain = uniqueDomain();
  try {
    const fetch_fn = async ({ auth_profile }) => ({
      status: auth_profile === "admin" ? 200 : 403,
      content_type: "application/json",
      body: auth_profile === "admin" ? { id: "1" } : null,
      sent_with_auth: true,
    });
    const result = await runAuthDifferential({
      target_domain: domain,
      base_url: "https://api.example.com",
      endpoints: ["/admin/audit"],
      auth_profiles: ["admin", "user"],
      fetch_fn,
    });
    assert.ok(result.summary.divergences_total >= 1);
    assert.ok(result.summary.divergences_by_type.status_class_differs >= 1);
  } finally {
    cleanupDomain(domain);
  }
});

test("runAuthDifferential records per-profile fetch errors without aborting other profiles", async () => {
  const domain = uniqueDomain();
  try {
    const fetch_fn = async ({ auth_profile }) => {
      if (auth_profile === "broken") throw new Error("connection refused");
      return { status: 200, content_type: "application/json", body: {}, sent_with_auth: true };
    };
    const result = await runAuthDifferential({
      target_domain: domain,
      base_url: "https://api.example.com",
      endpoints: ["/x"],
      auth_profiles: ["broken", "ok"],
      fetch_fn,
    });
    assert.equal(result.summary.fetch_errors, 1);
    assert.equal(result.summary.fetches_total, 2);
    const entry = result.per_endpoint[0];
    assert.match(entry.fetch_errors_by_profile.broken, /connection refused/);
    assert.ok(entry.signatures_by_profile.ok);
    assert.ok(!entry.signatures_by_profile.broken);
    assert.equal(entry.divergences.length, 0);
  } finally {
    cleanupDomain(domain);
  }
});

test("profile_metadata enables the unauth_succeeds_where_auth_blocked security flag", async () => {
  const domain = uniqueDomain();
  try {
    const fetch_fn = async ({ auth_profile }) => ({
      status: auth_profile === "guest" ? 200 : 401,
      content_type: "application/json",
      body: auth_profile === "guest" ? { secret: "leak" } : null,
      sent_with_auth: auth_profile !== "guest",
    });
    const result = await runAuthDifferential({
      target_domain: domain,
      base_url: "https://api.example.com",
      endpoints: ["/leaky"],
      auth_profiles: ["guest", "user"],
      fetch_fn,
      profile_metadata: {
        guest: { sent_with_auth: false },
        user: { sent_with_auth: true },
      },
    });
    assert.ok(result.summary.divergences_by_type.unauth_succeeds_where_auth_blocked >= 1);
    assert.ok(result.summary.divergences_by_severity.security >= 1);
  } finally {
    cleanupDomain(domain);
  }
});

test("results persist to auth-differential-results.json with deterministic results_hash", async () => {
  const domain = uniqueDomain();
  try {
    const fetch_fn = async ({ auth_profile }) => ({
      status: auth_profile === "admin" ? 200 : 403,
      content_type: "application/json",
      body: auth_profile === "admin" ? { id: "1" } : null,
      sent_with_auth: true,
    });
    const first = await runAuthDifferential({
      target_domain: domain,
      base_url: "https://api.example.com",
      endpoints: ["/x"],
      auth_profiles: ["admin", "user"],
      fetch_fn,
    });
    const second = await runAuthDifferential({
      target_domain: domain,
      base_url: "https://api.example.com",
      endpoints: ["/x"],
      auth_profiles: ["admin", "user"],
      fetch_fn,
    });
    assert.equal(first.results_hash, second.results_hash);
    const fromDisk = readResults(domain);
    assert.equal(fromDisk.results_hash, second.results_hash);
    assert.ok(fs.existsSync(path.join(domainDir(domain), "auth-differential-results.json")));
  } finally {
    cleanupDomain(domain);
  }
});

test("per_endpoint sorted deterministically by (endpoint, method)", async () => {
  const domain = uniqueDomain();
  try {
    const fetch_fn = async () => ({
      status: 200,
      content_type: "application/json",
      body: {},
      sent_with_auth: true,
    });
    const result = await runAuthDifferential({
      target_domain: domain,
      base_url: "https://api.example.com",
      endpoints: ["/z", "/a", "/m"],
      auth_profiles: ["admin", "user"],
      fetch_fn,
    });
    const order = result.per_endpoint.map((e) => e.endpoint);
    assert.deepEqual(order, ["/a", "/m", "/z"]);
  } finally {
    cleanupDomain(domain);
  }
});

test("limit option caps endpoints_tested while reporting endpoints_skipped_by_limit", async () => {
  const domain = uniqueDomain();
  try {
    const fetch_fn = async () => ({
      status: 200,
      content_type: "application/json",
      body: {},
      sent_with_auth: true,
    });
    const result = await runAuthDifferential({
      target_domain: domain,
      base_url: "https://api.example.com",
      endpoints: ["/a", "/b", "/c", "/d"],
      auth_profiles: ["admin", "user"],
      fetch_fn,
      limit: 2,
    });
    assert.equal(result.summary.endpoints_tested, 2);
    assert.equal(result.summary.endpoints_skipped_by_limit, 2);
  } finally {
    cleanupDomain(domain);
  }
});

test("validates required arguments", async () => {
  await assert.rejects(
    () => runAuthDifferential({ target_domain: "x", base_url: "", fetch_fn: async () => ({}) }),
    /base_url/,
  );
  await assert.rejects(
    () => runAuthDifferential({ target_domain: "x", base_url: "https://x", endpoints: [], auth_profiles: ["a"], fetch_fn: async () => ({}) }),
    /at least two/,
  );
});

test("readResults returns null when no run has happened yet", () => {
  const domain = uniqueDomain();
  try {
    assert.equal(readResults(domain), null);
  } finally {
    cleanupDomain(domain);
  }
});

test("captures run_id when supplied", async () => {
  const domain = uniqueDomain();
  try {
    const fetch_fn = async () => ({
      status: 200,
      content_type: "application/json",
      body: {},
      sent_with_auth: true,
    });
    const result = await runAuthDifferential({
      target_domain: domain,
      base_url: "https://api.example.com",
      endpoints: ["/x"],
      auth_profiles: ["a", "b"],
      fetch_fn,
      run_id: "diff-001",
    });
    assert.equal(result.summary.run_id, "diff-001");
  } finally {
    cleanupDomain(domain);
  }
});
