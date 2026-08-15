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
} = require("../mcp/core/auth-differential-runner.js");
const { deriveLineageEndpoints } = require("../mcp/tools/web/run-auth-differential.js");

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

test("distinct_principal_count counts only VALIDATED principals (a junk profile that only ever 4xx'd does not count)", async () => {
  const domain = uniqueDomain();
  try {
    // "real" authenticates (2xx); "junk" is a distinct-material credential that only ever 401s.
    const fetch_fn = async ({ auth_profile }) => ({
      status: auth_profile === "real" ? 200 : 401,
      content_type: "application/json",
      body: auth_profile === "real" ? { id: 1 } : null,
      sent_with_auth: true,
    });
    const result = await runAuthDifferential({
      target_domain: domain,
      base_url: "https://api.example.com",
      endpoints: ["/orders/1"],
      auth_profiles: ["real", "junk"],
      fetch_fn,
      surface_id: "surface-x",
      profile_metadata: {
        real: { principal_fingerprint: "fp-real" },
        junk: { principal_fingerprint: "fp-junk" },
      },
    });
    // Two distinct fingerprints were swept, but only "real" ever authenticated, so the sweep
    // tested no real SECOND principal -> distinct_principal_count is 1, not 2 (the [real, junk] forge).
    assert.equal(result.per_endpoint[0].distinct_principal_count, 1);
    // junk (401-only) is not a validated principal, so there is no cross-tenant flip.
    assert.equal(result.per_endpoint[0].cross_tenant_flip, false);
  } finally {
    cleanupDomain(domain);
  }
});

test("distinct_principal_count is 2 when BOTH principals authenticate somewhere in the sweep", async () => {
  const domain = uniqueDomain();
  try {
    // A real cross-tenant sweep: each principal gets a 2xx on its OWN object, 403 on the other's.
    const fetch_fn = async ({ auth_profile, endpoint }) => {
      const owns = (auth_profile === "victim" && endpoint === "/orders/1")
        || (auth_profile === "attacker" && endpoint === "/orders/2");
      return { status: owns ? 200 : 403, content_type: "application/json", body: owns ? { id: 1 } : null, sent_with_auth: true };
    };
    const result = await runAuthDifferential({
      target_domain: domain,
      base_url: "https://api.example.com",
      endpoints: ["/orders/1", "/orders/2"],
      auth_profiles: ["victim", "attacker"],
      fetch_fn,
      surface_id: "surface-x",
      id_bearing_templates: ["/orders/{id}"],
      profile_metadata: {
        victim: { principal_fingerprint: "fp-victim" },
        attacker: { principal_fingerprint: "fp-attacker" },
      },
    });
    // Both authenticated somewhere -> both validated -> every row's distinct_principal_count is 2.
    for (const row of result.per_endpoint) assert.equal(row.distinct_principal_count, 2);
    // On each id-bearing url one owner accessed (2xx) while the distinct validated other was
    // denied (403) — the negative control flipped, so this correct secure IDOR test clears.
    for (const row of result.per_endpoint) assert.equal(row.cross_tenant_flip, true);
  } finally {
    cleanupDomain(domain);
  }
});

test("a public-2xx anon arm (sent_with_auth:false) is not a validated-denied tenant, so no false cross_tenant_flip", async () => {
  const domain = uniqueDomain();
  try {
    // "real" authenticates and owns /orders/1 (2xx). "junk" is an ANON profile
    // (sent_with_auth:false) that 2xx's a PUBLIC /health but 401s the protected /orders/1.
    // The public 2xx must NOT let junk act as the "validated denied" arm on /orders/1.
    const fetch_fn = async ({ auth_profile, endpoint }) => {
      const ok = (auth_profile === "real" && endpoint === "/orders/1")
        || (auth_profile === "junk" && endpoint === "/health");
      return { status: ok ? 200 : 401, content_type: "application/json", body: ok ? { id: 1 } : null, sent_with_auth: auth_profile !== "junk" };
    };
    const result = await runAuthDifferential({
      target_domain: domain,
      base_url: "https://api.example.com",
      endpoints: ["/orders/1", "/health"],
      auth_profiles: ["real", "junk"],
      fetch_fn,
      surface_id: "surface-x",
      profile_metadata: {
        real: { principal_fingerprint: "fp-real" },
        junk: { principal_fingerprint: "fp-junk", sent_with_auth: false },
      },
    });
    const orders = result.per_endpoint.find((row) => row.endpoint === "/orders/1");
    // junk's public 2xx on /health does not make it a real denied tenant on /orders/1.
    assert.equal(orders.cross_tenant_flip, false);
  } finally {
    cleanupDomain(domain);
  }
});

test("a non-anon junk profile that only 2xx's a public endpoint does NOT flip an id-bearing row (junk-authenticated forge closed)", async () => {
  const domain = uniqueDomain();
  try {
    // "tenant_a" is the real owner: 2xx on the id-bearing /orders/1. "tenant_b" is a junk
    // credential under a NON-anon name with garbage Authorization and NO sent_with_auth metadata
    // (so it defaults to sent_with_auth:true, evading the U1 anon-exclusion). It 2xx's a PUBLIC,
    // non-id-bearing /health but 401s the gated /orders/1. Its public 2xx must NOT qualify it as
    // the "validated denied" tenant on /orders/1, so no cross_tenant_flip is minted.
    const fetch_fn = async ({ auth_profile, endpoint, headers }) => {
      void headers; // garbage Authorization is opaque to the differential; only status matters
      const ok = (auth_profile === "tenant_a" && endpoint === "/orders/1")
        || (auth_profile === "tenant_b" && endpoint === "/health");
      return { status: ok ? 200 : 401, content_type: "application/json", body: ok ? { id: 1 } : null, sent_with_auth: true };
    };
    const result = await runAuthDifferential({
      target_domain: domain,
      base_url: "https://api.example.com",
      endpoints: ["/orders/1", "/health"],
      auth_profiles: ["tenant_a", "tenant_b"],
      fetch_fn,
      surface_id: "surface-x",
      id_bearing_templates: ["/orders/{id}"],
      profile_metadata: {
        tenant_a: { principal_fingerprint: "fp-tenant-a" },
        tenant_b: { principal_fingerprint: "fp-tenant-b" },
      },
    });
    const orders = result.per_endpoint.find((row) => row.endpoint === "/orders/1");
    // tenant_b never proved authenticated access to a gated id-bearing endpoint, so it is not a
    // validated-denied tenant: the sweep tested no real second principal on /orders/1.
    assert.equal(orders.cross_tenant_flip, false);
  } finally {
    cleanupDomain(domain);
  }
});

test("a junk profile that 2xx's a co-resident PUBLIC id-bearing endpoint (no principal denied there) validates NO ONE -> no flip on the gated row", async () => {
  const domain = uniqueDomain();
  try {
    // Both /orders/{id} and /pub/{id} are id-bearing templates, but /pub/{id} is PUBLIC: every
    // principal 2xx's it (no denial), so it is NOT gated. "owner" 2xx's both /orders/42 and /pub/5.
    // "junk" is a non-anon credential (sent_with_auth defaults true) that 2xx's the public /pub/5
    // and 401s the gated /orders/42. A 2xx on an ungated id-bearing endpoint must NOT validate junk
    // as a denied tenant, so the /orders/42 row mints no cross_tenant_flip. (Under the pre-gatedness
    // code, junk's /pub/5 2xx would have validated it and this same input would forge a false flip.)
    const fetch_fn = async ({ auth_profile, endpoint }) => {
      const ok = endpoint === "/pub/5"
        || (auth_profile === "owner" && endpoint === "/orders/42");
      return { status: ok ? 200 : 401, content_type: "application/json", body: ok ? { id: 1 } : null, sent_with_auth: true };
    };
    const result = await runAuthDifferential({
      target_domain: domain,
      base_url: "https://api.example.com",
      endpoints: ["/orders/42", "/pub/5"],
      auth_profiles: ["owner", "junk"],
      fetch_fn,
      surface_id: "surface-x",
      id_bearing_templates: ["/orders/{id}", "/pub/{id}"],
      profile_metadata: {
        owner: { principal_fingerprint: "fp-owner" },
        junk: { principal_fingerprint: "fp-junk" },
      },
    });
    const orders = result.per_endpoint.find((row) => row.endpoint === "/orders/42");
    // junk validated on no GATED endpoint (/pub/5 has no denial), so it is not a validated-denied tenant.
    assert.equal(orders.cross_tenant_flip, false);
  } finally {
    cleanupDomain(domain);
  }
});

test("gatedness conjunct does not suppress the honest lever: each principal 2xx's its OWN gated /orders object (other denied there) -> every id-bearing row flips even with a co-resident public id-bearing endpoint", async () => {
  const domain = uniqueDomain();
  try {
    // A genuine 2-tenant sweep with a co-resident PUBLIC id-bearing endpoint present. "owner" owns
    // /orders/42 (2xx, attacker 401 there -> gated) and "attacker" owns /orders/99 (2xx, owner 401
    // there -> gated); both 2xx the public /pub/5 (ungated). Each principal proved gated access to
    // its own id-bearing object, so each validates and both gated rows flip. The gatedness conjunct
    // must NOT suppress this honest lever.
    const fetch_fn = async ({ auth_profile, endpoint }) => {
      const owns = endpoint === "/pub/5"
        || (auth_profile === "owner" && endpoint === "/orders/42")
        || (auth_profile === "attacker" && endpoint === "/orders/99");
      return { status: owns ? 200 : 401, content_type: "application/json", body: owns ? { id: 1 } : null, sent_with_auth: true };
    };
    const result = await runAuthDifferential({
      target_domain: domain,
      base_url: "https://api.example.com",
      endpoints: ["/orders/42", "/orders/99", "/pub/5"],
      auth_profiles: ["owner", "attacker"],
      fetch_fn,
      surface_id: "surface-x",
      id_bearing_templates: ["/orders/{id}", "/pub/{id}"],
      profile_metadata: {
        owner: { principal_fingerprint: "fp-owner" },
        attacker: { principal_fingerprint: "fp-attacker" },
      },
    });
    for (const ep of ["/orders/42", "/orders/99"]) {
      const row = result.per_endpoint.find((r) => r.endpoint === ep);
      assert.equal(row.cross_tenant_flip, true);
    }
  } finally {
    cleanupDomain(domain);
  }
});

test("a real 2nd tenant that 2xx's its OWN id-bearing object and 401s the row still flips (honest lever preserved)", async () => {
  const domain = uniqueDomain();
  try {
    // "victim" owns /orders/1 (2xx) and is denied /orders/2 (401). "attacker" owns /orders/2 (2xx,
    // its OWN id-bearing object) and is denied /orders/1 (401). Each principal proved authenticated
    // access to a gated id-bearing endpoint, so each is a validated-for-flip tenant: on /orders/1
    // the victim accessed while the distinct validated attacker was denied -> the control flipped.
    const fetch_fn = async ({ auth_profile, endpoint }) => {
      const owns = (auth_profile === "victim" && endpoint === "/orders/1")
        || (auth_profile === "attacker" && endpoint === "/orders/2");
      return { status: owns ? 200 : 401, content_type: "application/json", body: owns ? { id: 1 } : null, sent_with_auth: true };
    };
    const result = await runAuthDifferential({
      target_domain: domain,
      base_url: "https://api.example.com",
      endpoints: ["/orders/1", "/orders/2"],
      auth_profiles: ["victim", "attacker"],
      fetch_fn,
      surface_id: "surface-x",
      id_bearing_templates: ["/orders/{id}"],
      profile_metadata: {
        victim: { principal_fingerprint: "fp-victim" },
        attacker: { principal_fingerprint: "fp-attacker" },
      },
    });
    for (const row of result.per_endpoint) assert.equal(row.cross_tenant_flip, true);
  } finally {
    cleanupDomain(domain);
  }
});

test("an empty/unresolvable id_bearing_templates set validates no principal for the flip arm (fail closed)", async () => {
  const domain = uniqueDomain();
  try {
    // The SAME genuine 2-tenant differential as above (each principal 2xx's its own id-bearing
    // object, 401s the row), but the caller resolved NO id-bearing templates (empty/unreadable
    // route). With no gated endpoint to validate against, no principal qualifies as the validated-
    // denied tenant, so an id-bearing surface earns NO auth-differential completion coverage.
    const fetch_fn = async ({ auth_profile, endpoint }) => {
      const owns = (auth_profile === "victim" && endpoint === "/orders/1")
        || (auth_profile === "attacker" && endpoint === "/orders/2");
      return { status: owns ? 200 : 401, content_type: "application/json", body: owns ? { id: 1 } : null, sent_with_auth: true };
    };
    const result = await runAuthDifferential({
      target_domain: domain,
      base_url: "https://api.example.com",
      endpoints: ["/orders/1", "/orders/2"],
      auth_profiles: ["victim", "attacker"],
      fetch_fn,
      surface_id: "surface-x",
      id_bearing_templates: [],
      profile_metadata: {
        victim: { principal_fingerprint: "fp-victim" },
        attacker: { principal_fingerprint: "fp-attacker" },
      },
    });
    for (const row of result.per_endpoint) assert.equal(row.cross_tenant_flip, false);
  } finally {
    cleanupDomain(domain);
  }
});

test("deriveLineageEndpoints binds a principal's OWN id-bearing object from its 2xx seed", () => {
  // Profile B's prior 2xx listing echoes its own order id; over the frozen /orders/{id}
  // template, param-lineage binds exactly /orders/2 — the value is LITERALLY present in B's
  // supplied body (no fabricated id).
  assert.deepEqual(
    deriveLineageEndpoints({
      seed_responses: { attacker: { body: { order_id: 2 }, content_type: "application/json" } },
      id_bearing_templates: ["/orders/{id}"],
      profiles: ["victim", "attacker"],
    }),
    ["/orders/2"],
  );
});

test("deriveLineageEndpoints is fail-safe: no seed / non-JSON / idless / empty templates yield no fabricated id", () => {
  // No seed_responses at all -> nothing to derive.
  assert.deepEqual(
    deriveLineageEndpoints({ id_bearing_templates: ["/orders/{id}"], profiles: ["a"] }),
    [],
  );
  // Empty seed map -> nothing to derive.
  assert.deepEqual(
    deriveLineageEndpoints({ seed_responses: {}, id_bearing_templates: ["/orders/{id}"], profiles: ["a"] }),
    [],
  );
  // Non-JSON content_type fails closed inside extractIds -> no harvest.
  assert.deepEqual(
    deriveLineageEndpoints({
      seed_responses: { a: { body: "order_id=2", content_type: "text/html" } },
      id_bearing_templates: ["/orders/{id}"],
      profiles: ["a"],
    }),
    [],
  );
  // A body with no id-shaped value -> honest empty, never a guessed id.
  assert.deepEqual(
    deriveLineageEndpoints({
      seed_responses: { a: { body: { name: "widget", total: 3.14 } } },
      id_bearing_templates: ["/orders/{id}"],
      profiles: ["a"],
    }),
    [],
  );
  // Empty/unresolvable id_bearing_templates -> no arm derived (mirrors the runner's fail-closed flip).
  assert.deepEqual(
    deriveLineageEndpoints({
      seed_responses: { a: { body: { order_id: 2 } } },
      id_bearing_templates: [],
      profiles: ["a"],
    }),
    [],
  );
});

test("lineage-derived own-object arm enables a real cross-tenant flip (deriveLineageEndpoints -> runAuthDifferential)", async () => {
  const domain = uniqueDomain();
  try {
    // The base sweep only knows victim's object /orders/1. Attacker B's OWN object /orders/2 is
    // derived from B's supplied prior 2xx listing via param-lineage and added to the sweep, so B
    // earns a live 2xx on its own gated object and validates under U1b -> the /orders/1 (and
    // /orders/2) rows both flip.
    const templates = ["/orders/{id}"];
    const derived = deriveLineageEndpoints({
      seed_responses: { attacker: { body: { order_id: 2 }, content_type: "application/json" } },
      id_bearing_templates: templates,
      profiles: ["victim", "attacker"],
    });
    assert.deepEqual(derived, ["/orders/2"]);
    const endpoints = ["/orders/1", ...derived];
    const fetch_fn = async ({ auth_profile, endpoint }) => {
      const owns = (auth_profile === "victim" && endpoint === "/orders/1")
        || (auth_profile === "attacker" && endpoint === "/orders/2");
      return { status: owns ? 200 : 401, content_type: "application/json", body: owns ? { id: 1 } : null, sent_with_auth: true };
    };
    const result = await runAuthDifferential({
      target_domain: domain,
      base_url: "https://api.example.com",
      endpoints,
      auth_profiles: ["victim", "attacker"],
      fetch_fn,
      surface_id: "surface-x",
      id_bearing_templates: templates,
      profile_metadata: {
        victim: { principal_fingerprint: "fp-victim" },
        attacker: { principal_fingerprint: "fp-attacker" },
      },
    });
    for (const row of result.per_endpoint) assert.equal(row.cross_tenant_flip, true);
  } finally {
    cleanupDomain(domain);
  }
});

test("no lineage (attacker's own object absent from the sweep) -> attacker never validates -> no forced flip", async () => {
  const domain = uniqueDomain();
  try {
    // Same live behavior as above, but with NO seed for the attacker so param-lineage derives
    // nothing: only /orders/1 is swept. The attacker 401s /orders/1 and its own object is never
    // probed, so it never proves gated authenticated access -> it is not a validated-denied
    // tenant and the /orders/1 row does NOT flip. U1b is not weakened; absence of lineage is an
    // honest false negative, not a forged one.
    const templates = ["/orders/{id}"];
    const derived = deriveLineageEndpoints({
      seed_responses: {},
      id_bearing_templates: templates,
      profiles: ["victim", "attacker"],
    });
    assert.deepEqual(derived, []);
    const endpoints = ["/orders/1", ...derived];
    const fetch_fn = async ({ auth_profile, endpoint }) => {
      const owns = (auth_profile === "victim" && endpoint === "/orders/1")
        || (auth_profile === "attacker" && endpoint === "/orders/2");
      return { status: owns ? 200 : 401, content_type: "application/json", body: owns ? { id: 1 } : null, sent_with_auth: true };
    };
    const result = await runAuthDifferential({
      target_domain: domain,
      base_url: "https://api.example.com",
      endpoints,
      auth_profiles: ["victim", "attacker"],
      fetch_fn,
      surface_id: "surface-x",
      id_bearing_templates: templates,
      profile_metadata: {
        victim: { principal_fingerprint: "fp-victim" },
        attacker: { principal_fingerprint: "fp-attacker" },
      },
    });
    const orders1 = result.per_endpoint.find((row) => row.endpoint === "/orders/1");
    assert.equal(orders1.cross_tenant_flip, false);
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

test("persisted per_endpoint rows carry a verifying ed25519 row_mac; results_hash excludes it and stays deterministic", async () => {
  const domain = uniqueDomain();
  try {
    const {
      verifyRowWithMac,
      MAC_SCHEME_ED25519,
      OFFENSIVE_ROW_MAC_VERSION_V2,
      AUTH_DIFFERENTIAL_ROW_MAC_CONTEXT,
    } = require("../mcp/core/ledger-integrity/offensive-row-mac.js");
    const { readHandoffSigningPublicKey } = require("../mcp/core/ledger-integrity/handoff-signing-key.js");
    // A genuine 2-tenant differential: each owner 2xx's its own id-bearing object, 401s the other's.
    const fetch_fn = async ({ auth_profile, endpoint }) => {
      const owns = (auth_profile === "victim" && endpoint === "/orders/1")
        || (auth_profile === "attacker" && endpoint === "/orders/2");
      return { status: owns ? 200 : 401, content_type: "application/json", body: owns ? { id: 1 } : null, sent_with_auth: true };
    };
    const args = {
      target_domain: domain,
      base_url: "https://api.example.com",
      endpoints: ["/orders/1", "/orders/2"],
      auth_profiles: ["victim", "attacker"],
      fetch_fn,
      surface_id: "surface-x",
      id_bearing_templates: ["/orders/{id}"],
      profile_metadata: {
        victim: { principal_fingerprint: "fp-victim" },
        attacker: { principal_fingerprint: "fp-attacker" },
      },
    };
    const first = await runAuthDifferential(args);
    const { publicKey } = readHandoffSigningPublicKey(domain);

    // Every returned row carries a v2 ed25519 row_mac that VERIFIES under the auth-differential context.
    for (const row of first.per_endpoint) {
      assert.ok(row.row_mac, "each persisted row carries a row_mac envelope");
      assert.equal(row.row_mac.version, OFFENSIVE_ROW_MAC_VERSION_V2);
      assert.equal(row.row_mac.scheme, MAC_SCHEME_ED25519);
      assert.equal(verifyRowWithMac(AUTH_DIFFERENTIAL_ROW_MAC_CONTEXT, row, { publicKey }), true);
      // A different context must NOT verify (domain separation).
      assert.equal(verifyRowWithMac("bob.invariant-run.v1", row, { publicKey }), false);
    }

    // The signed rows survive the read-back byte-identically and still verify.
    const fromDisk = readResults(domain);
    for (const row of fromDisk.per_endpoint) {
      assert.equal(verifyRowWithMac(AUTH_DIFFERENTIAL_ROW_MAC_CONTEXT, row, { publicKey }), true);
    }

    // results_hash EXCLUDES row_mac from its preimage -> re-running the identical sweep (which
    // re-signs the rows) yields the SAME results_hash. The determinism the frontier ref depends on.
    const second = await runAuthDifferential(args);
    assert.equal(second.results_hash, first.results_hash);
    assert.equal(fromDisk.results_hash, first.results_hash);
  } finally {
    cleanupDomain(domain);
  }
});

test("per_endpoint rows carry effective_url = joinUrl(base_url, endpoint) so the signed row binds the TESTED url", async () => {
  const domain = uniqueDomain();
  try {
    const fetch_fn = async () => ({
      status: 200,
      content_type: "application/json",
      body: {},
      sent_with_auth: true,
    });
    const base_url = "https://api.example.com/safe-prefix";
    const result = await runAuthDifferential({
      target_domain: domain,
      base_url,
      endpoints: ["/orders/1", "/health"],
      auth_profiles: ["admin", "user"],
      fetch_fn,
    });
    for (const row of result.per_endpoint) {
      assert.equal(row.effective_url, joinUrl(base_url, row.endpoint));
    }
    // The tested URL is the base_url-joined path, NOT the bare endpoint: a crown-path endpoint
    // string cannot be signed while the arm was actually fetched under a benign base prefix.
    const orders = result.per_endpoint.find((r) => r.endpoint === "/orders/1");
    assert.equal(orders.effective_url, "https://api.example.com/safe-prefix/orders/1");
    // effective_url survives the read-back byte-identically.
    const fromDisk = readResults(domain);
    for (const row of fromDisk.per_endpoint) {
      assert.equal(row.effective_url, joinUrl(base_url, row.endpoint));
    }
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

test("arm order is counterbalanced AB/BA across endpoints without adding requests", async () => {
  const domain = uniqueDomain();
  try {
    const calls = [];
    const fetch_fn = async ({ endpoint, auth_profile }) => {
      calls.push({ endpoint, auth_profile });
      return { status: 200, content_type: "application/json", body: {}, sent_with_auth: true };
    };
    const result = await runAuthDifferential({
      target_domain: domain,
      base_url: "https://api.example.com",
      endpoints: ["/a", "/b", "/c", "/d"],
      auth_profiles: ["admin", "user"],
      fetch_fn,
    });
    // N=1 per (endpoint, profile): exactly endpoints x profiles fetches, no extra requests.
    assert.equal(result.summary.fetches_total, 8);
    assert.equal(calls.length, 8);
    // Endpoints are swept in sorted order (/a,/b,/c,/d); each contributes two consecutive
    // fetches. The FIRST-fetched arm must alternate admin/user across endpoints (AB/BA), so
    // no single profile is systematically the later request.
    const pairs = [];
    for (let i = 0; i < calls.length; i += 2) {
      assert.equal(calls[i].endpoint, calls[i + 1].endpoint, "an endpoint's two fetches are consecutive");
      pairs.push([calls[i].auth_profile, calls[i + 1].auth_profile]);
    }
    assert.deepEqual(pairs[0], ["admin", "user"]); // AB
    assert.deepEqual(pairs[1], ["user", "admin"]); // BA
    assert.deepEqual(pairs[2], ["admin", "user"]); // AB
    assert.deepEqual(pairs[3], ["user", "admin"]); // BA
    // The order change is non-observable in the persisted rows: every row keeps both arms in
    // canonical profileList key order (re-keyed), regardless of the AB/BA fetch order, so the
    // serialized bytes and results_hash are order-invariant.
    assert.equal(result.per_endpoint.length, 4);
    for (const row of result.per_endpoint) {
      assert.deepEqual(Object.keys(row.signatures_by_profile), ["admin", "user"]);
      assert.equal(row.divergences.length, 0);
    }
  } finally {
    cleanupDomain(domain);
  }
});

test("a failed write on a second run leaves the prior results file byte-intact (atomic + locked persist)", async () => {
  const domain = uniqueDomain();
  const filePath = path.join(domainDir(domain), "auth-differential-results.json");
  const realRenameSync = fs.renameSync;
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
    // Snapshot the exact on-disk bytes written by the successful first run.
    const bytesAfterFirst = fs.readFileSync(filePath, "utf8");

    // Force the atomic helper's rename step to fail on the SECOND run's persist. writeFileAtomic
    // writes a sibling temp then renames it onto the target; a failure at the rename must leave
    // the prior file untouched (no truncation/clobber), not a partial write. Only the results
    // path is targeted so session-lock acquisition (which does not rename) is unaffected.
    fs.renameSync = (oldPath, newPath, ...rest) => {
      if (typeof newPath === "string" && newPath.endsWith("auth-differential-results.json")) {
        throw new Error("injected rename failure");
      }
      return realRenameSync(oldPath, newPath, ...rest);
    };
    await assert.rejects(
      () => runAuthDifferential({
        target_domain: domain,
        base_url: "https://api.example.com",
        endpoints: ["/x"],
        auth_profiles: ["admin", "user"],
        fetch_fn,
      }),
      /injected rename failure/,
    );
    fs.renameSync = realRenameSync;

    // The prior ledger is byte-identical and still parses to the first run's payload.
    assert.equal(fs.readFileSync(filePath, "utf8"), bytesAfterFirst);
    const fromDisk = readResults(domain);
    assert.equal(fromDisk.results_hash, first.results_hash);
    // No leftover temp/partial artifacts from the aborted atomic write.
    const leftovers = fs.readdirSync(domainDir(domain))
      .filter((name) => name.includes("auth-differential-results.json") && name !== "auth-differential-results.json");
    assert.deepEqual(leftovers, []);
  } finally {
    fs.renameSync = realRenameSync;
    cleanupDomain(domain);
  }
});

test("R1: a sweep-wide deadline stops issuing arms; un-run endpoints get no row and cannot flip", async () => {
  const domain = uniqueDomain();
  try {
    // Each arm sleeps ~6ms; deadline is 1ms, so after the first endpoint's arms the wall-clock
    // budget is exceeded and the remaining endpoints are left UN-RUN (no row -> cannot mint a flip).
    const fetch_fn = async () => {
      await new Promise((r) => setTimeout(r, 6));
      return { status: 200, content_type: "application/json", body: { id: "1" }, sent_with_auth: true };
    };
    const result = await runAuthDifferential({
      target_domain: domain,
      base_url: "https://api.example.com",
      endpoints: ["/orders/1", "/orders/2", "/orders/3"],
      auth_profiles: ["admin", "user"],
      fetch_fn,
      deadline_ms: 1,
    });
    assert.equal(result.summary.deadline_reached, true);
    assert.ok(result.summary.endpoints_tested < 3, "not all endpoints run");
    assert.ok(result.summary.endpoints_skipped_by_deadline > 0, "some endpoints skipped by deadline");
    // Un-run endpoints produce no per_endpoint row, so they can never mint a cross_tenant_flip.
    assert.equal(result.per_endpoint.length, result.summary.endpoints_tested);
    for (const row of result.per_endpoint) assert.equal(row.cross_tenant_flip, false);
  } finally {
    cleanupDomain(domain);
  }
});

test("R1: an omitted deadline_ms runs the full sweep and emits no deadline keys (byte-stable)", async () => {
  const domain = uniqueDomain();
  try {
    const fetch_fn = async () => ({ status: 200, content_type: "application/json", body: { id: "1" }, sent_with_auth: true });
    const result = await runAuthDifferential({
      target_domain: domain,
      base_url: "https://api.example.com",
      endpoints: ["/users", "/health"],
      auth_profiles: ["admin", "user"],
      fetch_fn,
    });
    assert.equal(result.summary.endpoints_tested, 2);
    assert.ok(!("deadline_reached" in result.summary), "no deadline keys on an un-deadlined run");
    assert.ok(!("endpoints_skipped_by_deadline" in result.summary));
  } finally {
    cleanupDomain(domain);
  }
});

test("R1: makePerCallHttpScanFetcher injects no-cache freshness headers only when freshness:true", async () => {
  const { makePerCallHttpScanFetcher } = require("../mcp/core/http-scan-adapter.js");
  const calls = [];
  const httpScanFn = async (a) => {
    calls.push(a);
    return { status: 200, content_type: "application/json", body: {}, sent_with_auth: true };
  };
  // The differential opts IN -> per-arm cache-control present.
  const fresh = makePerCallHttpScanFetcher({ httpScanFn, target_domain: "x.local", block_internal_hosts: true, freshness: true });
  await fresh({ url: "https://x.local/a", method: "GET", auth_profile: "admin" }).catch(() => {});
  assert.equal(calls[0].headers["Cache-Control"], "no-cache, no-store");
  assert.equal(calls[0].headers["Pragma"], "no-cache");
  // A non-differential caller (freshness omitted) is byte-identical to today -> no headers injected.
  const plain = makePerCallHttpScanFetcher({ httpScanFn, target_domain: "x.local", block_internal_hosts: true });
  await plain({ url: "https://x.local/a", method: "GET", auth_profile: "admin" }).catch(() => {});
  assert.equal(calls[1].headers, undefined);
});

test("a state-changing (DELETE) differential does NOT earn a completion flip even with a real owner/denied divergence", async () => {
  // Identical owner/denied divergence pattern that legitimately flips on a READ.
  const fetch_fn = async ({ auth_profile, endpoint }) => {
    const owns = (auth_profile === "victim" && endpoint === "/orders/1")
      || (auth_profile === "attacker" && endpoint === "/orders/2");
    return { status: owns ? 200 : 403, content_type: "application/json", body: owns ? { id: 1 } : null, sent_with_auth: true };
  };
  const baseFor = (domain) => ({
    target_domain: domain,
    base_url: "https://api.example.com",
    auth_profiles: ["victim", "attacker"],
    fetch_fn,
    surface_id: "surface-x",
    id_bearing_templates: ["/orders/{id}"],
    profile_metadata: {
      victim: { principal_fingerprint: "fp-victim" },
      attacker: { principal_fingerprint: "fp-attacker" },
    },
  });
  // Separate domains: the runner merges persisted rows per (surface_id, endpoint, method) per domain.
  const getDomain = uniqueDomain();
  const delDomain = uniqueDomain();
  try {
    // Baseline: a genuine GET read differential flips.
    const getResult = await runAuthDifferential({ ...baseFor(getDomain), endpoints: ["/orders/1", "/orders/2"] });
    for (const row of getResult.per_endpoint) assert.equal(row.cross_tenant_flip, true);
    // The identical divergence on DELETE must NOT set the completion flip: a delete-then-404/403 is a
    // state artifact an agent can manufacture (even from one account in two sessions), not authorization.
    const delResult = await runAuthDifferential({
      ...baseFor(delDomain),
      endpoints: [{ endpoint: "/orders/1", method: "DELETE" }, { endpoint: "/orders/2", method: "DELETE" }],
    });
    for (const row of delResult.per_endpoint) assert.equal(row.cross_tenant_flip, false);
  } finally {
    cleanupDomain(getDomain);
    cleanupDomain(delDomain);
  }
});
