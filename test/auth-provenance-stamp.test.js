"use strict";

// PR-PROV — arm the bob_http_idor_confirm signed-row producer by stamping synthetic-
// identity provenance at the bob_auto_signup -> authStore seam.
//
// These tests lock the un-fakeability invariant: provenance (synthetic:true +
// email_origin:"temp_email" + provisioned_via:"bob_auto_signup") may be stamped onto a
// persisted auth profile ONLY via authStore's SECOND positional argument, which the MCP
// tool dispatcher never supplies (dispatch.js / tool-registry.js both call
// tool.handler(args) with ONE arg). So the public bob_auth_store tool — which an
// operator may feed a REAL victim's pasted cookie/JWT — can never produce a
// provenance-stamped profile, and an agent confined to the tool surface cannot forge a
// "synthetic" identity to drive a false signed IDOR row. The producer's actual
// refuse-to-sign predicate (profileHasProvenance) is asserted as the bridge.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  applyAuthProfileHeaders,
  authStore,
  resolveAuthProfile,
  resolveAuthJsonPath,
  listAuthProfiles,
  PROFILE_METADATA_KEYS,
} = require("../mcp/lib/auth.js");
const { profileHasProvenance } = require("../mcp/lib/offensive-idor-producer.js");
const { executeTool } = require("../mcp/lib/dispatch.js");
const { initSession } = require("../mcp/lib/session-state.js");
const { ERROR_CODES } = require("../mcp/lib/envelope.js");

// The exact frozen contract the producer's mint condition #18 requires
// (offensive-idor-producer.js REQUIRED_PROVENANCE :140-144).
const SYNTH = Object.freeze({
  synthetic: true,
  email_origin: "temp_email",
  provisioned_via: "bob_auto_signup",
  email: "eval_x@example.test",
});

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-auth-prov-"));
  process.env.HOME = home;
  return Promise.resolve()
    .then(() => fn(home))
    .finally(() => {
      if (previousHome === undefined) delete process.env.HOME;
      else process.env.HOME = previousHome;
      fs.rmSync(home, { recursive: true, force: true });
    });
}

function seedSession(domain) {
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/` }));
}

test("authStore stamps flat synthetic provenance from the 2nd positional arg and round-trips", () => withTempHome(() => {
  const domain = "prov-stamp-ok.test";
  seedSession(domain);
  authStore({
    target_domain: domain,
    profile_name: "identity_a",
    headers: { Authorization: "Bearer eyJatoken" },
  }, { provenance: SYNTH });

  // Read through the SAME path the producer uses (resolveAuthProfile -> raw object).
  const resolved = resolveAuthProfile("identity_a", `https://${domain}/`, domain);
  assert.equal(resolved.synthetic, true);
  assert.equal(resolved.email_origin, "temp_email");
  assert.equal(resolved.provisioned_via, "bob_auto_signup");
  assert.equal(resolved.email, "eval_x@example.test");
  assert.equal(resolved.Authorization, "Bearer eyJatoken");

  // The bridge: the stamped profile satisfies the producer's real refuse-to-sign gate.
  assert.equal(profileHasProvenance(resolved), true);

  // Persisted to disk verbatim, not merely cached.
  const saved = JSON.parse(fs.readFileSync(resolveAuthJsonPath(domain), "utf8"));
  assert.equal(saved.profiles.identity_a.synthetic, true);
  assert.equal(saved.profiles.identity_a.email_origin, "temp_email");
  assert.equal(saved.profiles.identity_a.provisioned_via, "bob_auto_signup");
  assert.equal(saved.profiles.identity_a.email, "eval_x@example.test");
}));

test("authStore exact-value guards: non-contract provenance values are dropped (cannot forge a value)", () => withTempHome(() => {
  const domain = "prov-stamp-badvalues.test";
  seedSession(domain);
  authStore({
    target_domain: domain,
    profile_name: "identity_a",
    headers: { Authorization: "Bearer x" },
  }, {
    provenance: {
      synthetic: "true",            // string, not boolean true
      email_origin: "operator_pasted",
      provisioned_via: "manual",
      email: 12345,                 // not a string
    },
  });

  const resolved = resolveAuthProfile("identity_a", `https://${domain}/`, domain);
  assert.equal(resolved.synthetic, undefined);
  assert.equal(resolved.email_origin, undefined);
  assert.equal(resolved.provisioned_via, undefined);
  assert.equal(resolved.email, undefined);
  // Forged values cannot satisfy the gate.
  assert.equal(profileHasProvenance(resolved), false);
}));

test("authStore with NO second arg (operator bob_auth_store path) carries no provenance — gate fails closed", () => withTempHome(() => {
  const domain = "prov-stamp-operator.test";
  seedSession(domain);
  // Simulates an operator pasting a REAL victim session via bob_auth_store.
  authStore({
    target_domain: domain,
    profile_name: "victim",
    cookies: { session: "real-victim-cookie" },
  });

  const resolved = resolveAuthProfile("victim", `https://${domain}/`, domain);
  assert.equal(resolved.synthetic, undefined);
  assert.equal(profileHasProvenance(resolved), false);
}));

test("authStore IGNORES provenance-shaped fields in the FIRST positional arg (only the 2nd-arg seam stamps)", () => withTempHome(() => {
  const domain = "prov-stamp-argsforge.test";
  seedSession(domain);
  // An attacker who could place these in `args` (the tool-surface object) STILL cannot
  // stamp — authStore reads provenance only from options.provenance (the 2nd arg).
  authStore({
    target_domain: domain,
    profile_name: "victim",
    cookies: { session: "real-victim-cookie" },
    synthetic: true,
    email_origin: "temp_email",
    provisioned_via: "bob_auto_signup",
    email: "eval_x@example.test",
  });

  const resolved = resolveAuthProfile("victim", `https://${domain}/`, domain);
  assert.equal(resolved.synthetic, undefined);
  assert.equal(resolved.email_origin, undefined);
  assert.equal(resolved.provisioned_via, undefined);
  assert.equal(resolved.email, undefined);
  assert.equal(profileHasProvenance(resolved), false);
}));

test("bob_auth_store TOOL surface cannot produce a provenance-stamped profile (forge attempt fails)", () => withTempHome(async () => {
  const domain = "prov-stamp-tool.test";
  seedSession(domain);
  // Adversarial: try to stamp provenance through the public tool by passing the exact
  // contract literals in the tool args.
  const result = await executeTool("bob_auth_store", {
    target_domain: domain,
    profile_name: "victim",
    cookies: { session: "real-victim-cookie" },
    synthetic: true,
    email_origin: "temp_email",
    provisioned_via: "bob_auto_signup",
    email: "eval_x@example.test",
  });

  // Two independent defenses converge on the invariant. (a) Schema validation rejects
  // unknown top-level props (additionalProperties defaults to false). (b) Even if it
  // didn't, one-arg dispatch never reaches the 2nd-arg seam, so the handler ignores
  // them. Under BOTH, no provenance-stamped profile can result.
  if (result.ok) {
    const resolved = resolveAuthProfile("victim", `https://${domain}/`, domain);
    assert.equal(profileHasProvenance(resolved), false);
  } else {
    assert.equal(result.error.code, ERROR_CODES.INVALID_ARGUMENTS);
    assert.match(result.error.message, /not allowed/);
  }
}));

test("bob_list_auth_profiles does not surface provenance flags or the synthetic mailbox", () => withTempHome(() => {
  const domain = "prov-stamp-summary.test";
  seedSession(domain);
  authStore({
    target_domain: domain,
    profile_name: "identity_a",
    headers: { Authorization: "Bearer eyJatoken" },
    cookies: { sid: "abc" },
  }, { provenance: SYNTH });

  const summary = JSON.parse(listAuthProfiles({ target_domain: domain }));
  const prof = summary.profiles.find((p) => p.profile_name === "identity_a");
  assert.ok(prof, "identity_a must be summarized");
  for (const leak of ["synthetic", "email_origin", "provisioned_via", "email"]) {
    assert.equal(prof.header_keys.includes(leak), false, `${leak} must not surface as a header key`);
  }
  // The real header + cookie still surface.
  assert.equal(prof.header_keys.includes("Authorization"), true);
  assert.equal(prof.header_keys.includes("Cookie"), true);
  // The synthetic mailbox must not appear anywhere in the summary JSON.
  assert.doesNotMatch(JSON.stringify(summary), /eval_x@example\.test/);
}));

// ───────────────────────── B1: outbound-header leak fix ─────────────────────────
// PR-PROV newly persists 4 top-level keys onto profiles; bob_http_scan's outbound merge
// (http-scan.js) copies profile keys into request headers. These tests lock that the
// canonical metadata strip prevents the synthetic mailbox + provenance fingerprint from
// reaching the target.

test("applyAuthProfileHeaders strips provenance/mailbox/credentials/storage from outbound headers (B1)", () => {
  const profile = {
    Authorization: "Bearer eyJatoken",
    Cookie: "sid=abc",
    synthetic: true,
    email_origin: "temp_email",
    provisioned_via: "bob_auto_signup",
    email: "eval_x@example.test",
    credentials: { email: "eval_x@example.test", password: "p" },
    local_storage: { k: "v" },
  };
  const out = applyAuthProfileHeaders({}, profile);
  // Real headers pass through.
  assert.equal(out.Authorization, "Bearer eyJatoken");
  assert.equal(out.Cookie, "sid=abc");
  // None of the Bob-local metadata reaches the outbound header map.
  for (const k of ["synthetic", "email_origin", "provisioned_via", "email", "credentials", "local_storage"]) {
    assert.equal(k in out, false, `${k} must not be emitted as an outbound header`);
  }
  assert.doesNotMatch(JSON.stringify(out), /eval_x@example\.test/);
});

test("applyAuthProfileHeaders never clobbers a header the caller already set", () => {
  const out = applyAuthProfileHeaders(
    { Authorization: "Bearer caller" },
    { Authorization: "Bearer profile", "X-Trace": "1" },
  );
  assert.equal(out.Authorization, "Bearer caller");
  assert.equal(out["X-Trace"], "1");
});

test("PROFILE_METADATA_KEYS contains every PR-PROV provenance key (leak-set regression lock)", () => {
  for (const k of ["synthetic", "email_origin", "provisioned_via", "email", "credentials"]) {
    assert.equal(PROFILE_METADATA_KEYS.has(k), true, `${k} must be in the canonical metadata strip set`);
  }
});

test("end-to-end: a stamped profile resolved from disk emits no provenance/mailbox headers (B1)", () => withTempHome(() => {
  const domain = "prov-stamp-leak-e2e.test";
  seedSession(domain);
  authStore({
    target_domain: domain,
    profile_name: "attacker",
    headers: { Authorization: "Bearer eyJatoken" },
  }, { provenance: SYNTH });
  // Exact path bob_http_scan uses: resolveAuthProfile -> applyAuthProfileHeaders.
  const resolved = resolveAuthProfile("attacker", `https://${domain}/`, domain);
  const out = applyAuthProfileHeaders({}, resolved);
  assert.equal(out.Authorization, "Bearer eyJatoken");
  for (const k of ["synthetic", "email_origin", "provisioned_via", "email"]) {
    assert.equal(k in out, false, `${k} must not leak to the target`);
  }
  assert.doesNotMatch(JSON.stringify(out), /eval_x@example\.test/);
}));
