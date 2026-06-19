"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");

const {
  buildSymbolSurfaceIndex,
  readSymbolSurfaceIndex,
  lookupByFileLine,
  lookupByFile,
  lookupBySurfaceId,
  summarizeImpactedSurfacesForDiff,
} = require("../mcp/lib/symbol-surface-index.js");
const {
  extractRoutesFromFiles,
} = require("../mcp/lib/route-extractor.js");

function uniqueDomain(prefix = "bob-symbol-index-test") {
  const suffix = crypto.randomBytes(4).toString("hex");
  return `${prefix}-${suffix}.local`;
}

function cleanupDomain(domain) {
  const dir = path.join(os.homedir(), "hacker-bob-sessions", domain);
  if (fs.existsSync(dir)) fs.rmSync(dir, { recursive: true, force: true });
}

function buildSampleRoutes() {
  return extractRoutesFromFiles([
    {
      file: "src/users.js",
      source: [
        "app.get('/users', listUsers);",
        "app.post('/users', createUser);",
        "app.get('/users/:id', getUser);",
      ].join("\n"),
    },
    {
      file: "src/admin.js",
      source: "app.delete('/admin/users/:id', deleteUser);",
    },
  ]);
}

const SAMPLE_SURFACES = [
  { id: "S-USERS", endpoint_pattern: "/users", endpoints: ["/users", "/users/{id}"] },
  { id: "S-ADMIN", endpoint_pattern: "/admin", endpoints: ["/admin/users/{id}"] },
];

test("buildSymbolSurfaceIndex matches route paths to surface IDs via endpoints + endpoint_pattern", () => {
  const domain = uniqueDomain();
  try {
    const routes = buildSampleRoutes();
    const result = buildSymbolSurfaceIndex({ target_domain: domain, route_records: routes, surfaces: SAMPLE_SURFACES });
    assert.equal(result.entry_count, 4);
    const usersFile = lookupByFile({ target_domain: domain, file: "src/users.js" });
    assert.ok(usersFile.length === 3);
    for (const entry of usersFile) {
      assert.deepEqual(entry.surface_ids, ["S-USERS"]);
    }
    const adminFile = lookupByFile({ target_domain: domain, file: "src/admin.js" });
    assert.deepEqual(adminFile[0].surface_ids, ["S-ADMIN"]);
  } finally {
    cleanupDomain(domain);
  }
});

test("lookupByFileLine returns the entry for an exact (file, line) hit", () => {
  const domain = uniqueDomain();
  try {
    const routes = buildSampleRoutes();
    buildSymbolSurfaceIndex({ target_domain: domain, route_records: routes, surfaces: SAMPLE_SURFACES });
    const entry = lookupByFileLine({ target_domain: domain, file: "src/users.js", line: 1 });
    assert.ok(entry);
    assert.equal(entry.method, "GET");
    assert.equal(entry.path, "/users");
    assert.equal(entry.handler_hint, "listUsers");
  } finally {
    cleanupDomain(domain);
  }
});

test("lookupByFileLine returns null on a miss", () => {
  const domain = uniqueDomain();
  try {
    const routes = buildSampleRoutes();
    buildSymbolSurfaceIndex({ target_domain: domain, route_records: routes, surfaces: SAMPLE_SURFACES });
    const entry = lookupByFileLine({ target_domain: domain, file: "src/users.js", line: 999 });
    assert.equal(entry, null);
  } finally {
    cleanupDomain(domain);
  }
});

test("lookupBySurfaceId returns every (file, line) entry tagged with that surface", () => {
  const domain = uniqueDomain();
  try {
    const routes = buildSampleRoutes();
    buildSymbolSurfaceIndex({ target_domain: domain, route_records: routes, surfaces: SAMPLE_SURFACES });
    const usersEntries = lookupBySurfaceId({ target_domain: domain, surface_id: "S-USERS" });
    assert.equal(usersEntries.length, 3);
    const adminEntries = lookupBySurfaceId({ target_domain: domain, surface_id: "S-ADMIN" });
    assert.equal(adminEntries.length, 1);
  } finally {
    cleanupDomain(domain);
  }
});

test("summarizeImpactedSurfacesForDiff returns entries hit by any diff line range", () => {
  const domain = uniqueDomain();
  try {
    const routes = buildSampleRoutes();
    buildSymbolSurfaceIndex({ target_domain: domain, route_records: routes, surfaces: SAMPLE_SURFACES });
    const impacted = summarizeImpactedSurfacesForDiff({
      target_domain: domain,
      diff_files: [
        { file: "src/users.js", line_ranges: [{ start: 1, end: 1 }, { start: 3, end: 3 }] },
      ],
    });
    assert.equal(impacted.impacted_entries.length, 2);
    assert.deepEqual(impacted.impacted_surface_ids, ["S-USERS"]);
    assert.equal(impacted.scanned_files, 1);
    assert.equal(impacted.path_used, "A");
  } finally {
    cleanupDomain(domain);
  }
});

test("summarizeImpactedSurfacesForDiff handles diffs that touch multiple files / surfaces", () => {
  const domain = uniqueDomain();
  try {
    const routes = buildSampleRoutes();
    buildSymbolSurfaceIndex({ target_domain: domain, route_records: routes, surfaces: SAMPLE_SURFACES });
    const impacted = summarizeImpactedSurfacesForDiff({
      target_domain: domain,
      diff_files: [
        { file: "src/users.js", line_ranges: [{ start: 1, end: 100 }] },
        { file: "src/admin.js", line_ranges: [{ start: 1, end: 100 }] },
      ],
    });
    assert.deepEqual(impacted.impacted_surface_ids.sort(), ["S-ADMIN", "S-USERS"]);
    assert.equal(impacted.scanned_files, 2);
  } finally {
    cleanupDomain(domain);
  }
});

test("summarizeImpactedSurfacesForDiff defaults to whole-file impact when line_ranges omitted", () => {
  const domain = uniqueDomain();
  try {
    const routes = buildSampleRoutes();
    buildSymbolSurfaceIndex({ target_domain: domain, route_records: routes, surfaces: SAMPLE_SURFACES });
    const impacted = summarizeImpactedSurfacesForDiff({
      target_domain: domain,
      diff_files: [{ file: "src/users.js" }],
    });
    assert.equal(impacted.impacted_entries.length, 3);
  } finally {
    cleanupDomain(domain);
  }
});

test("summarizeImpactedSurfacesForDiff returns empty when index is missing", () => {
  const domain = uniqueDomain();
  try {
    const result = summarizeImpactedSurfacesForDiff({
      target_domain: domain,
      diff_files: [{ file: "src/users.js" }],
    });
    assert.deepEqual(result.impacted_entries, []);
    assert.equal(result.scanned_files, 0);
    assert.equal(result.path_used, "B");
  } finally {
    cleanupDomain(domain);
  }
});

test("readSymbolSurfaceIndex returns null when no index exists yet", () => {
  const domain = uniqueDomain();
  try {
    assert.equal(readSymbolSurfaceIndex(domain), null);
  } finally {
    cleanupDomain(domain);
  }
});

test("index_hash is stable across rebuilds with identical inputs", () => {
  const domain = uniqueDomain();
  try {
    const routes = buildSampleRoutes();
    const a = buildSymbolSurfaceIndex({ target_domain: domain, route_records: routes, surfaces: SAMPLE_SURFACES });
    const b = buildSymbolSurfaceIndex({ target_domain: domain, route_records: routes, surfaces: SAMPLE_SURFACES });
    assert.equal(a.index_hash, b.index_hash);
  } finally {
    cleanupDomain(domain);
  }
});

test("path normalization treats Express :id and OpenAPI {id} and Django <int:id> as the same parameter slot", () => {
  const domain = uniqueDomain();
  try {
    const routes = [
      { framework: "express", method: "GET", path: "/users/:id", file: "a.js", line: 1, edge_kind: "route" },
      { framework: "spring", method: "GET", path: "/users/{id}", file: "B.java", line: 2, edge_kind: "route" },
      { framework: "django", method: "GET", path: "/users/<int:id>", file: "c.py", line: 3, edge_kind: "route" },
    ];
    const surfaces = [{ id: "S-USERS", endpoints: ["/users/{id}"] }];
    buildSymbolSurfaceIndex({ target_domain: domain, route_records: routes, surfaces });
    const usersEntries = lookupBySurfaceId({ target_domain: domain, surface_id: "S-USERS" });
    assert.equal(usersEntries.length, 3);
  } finally {
    cleanupDomain(domain);
  }
});

test("routes with no matching surface still index but with empty surface_ids", () => {
  const domain = uniqueDomain();
  try {
    const routes = [
      { framework: "express", method: "GET", path: "/orphan", file: "x.js", line: 1, edge_kind: "route" },
    ];
    buildSymbolSurfaceIndex({ target_domain: domain, route_records: routes, surfaces: SAMPLE_SURFACES });
    const entry = lookupByFileLine({ target_domain: domain, file: "x.js", line: 1 });
    assert.deepEqual(entry.surface_ids, []);
  } finally {
    cleanupDomain(domain);
  }
});

test("buildSymbolSurfaceIndex rejects unsafe target_domain and non-array routes", () => {
  assert.throws(
    () => buildSymbolSurfaceIndex({ target_domain: "../escape", route_records: [], surfaces: [] }),
    /target_domain/,
  );
  assert.throws(
    () => buildSymbolSurfaceIndex({ target_domain: "ok.example", route_records: null, surfaces: [] }),
    /route_records/,
  );
});
