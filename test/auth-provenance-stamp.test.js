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
const { toolNamesForRoleBundle } = require("../mcp/lib/tool-registry.js");
const { executeTool } = require("../mcp/lib/dispatch.js");
const { initSession } = require("../mcp/lib/session-state.js");
const { ERROR_CODES, ToolError } = require("../mcp/lib/envelope.js");

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

test("bob_auth_store is granted to evaluator-web for in-wave credential promotion, and the grant cannot widen the provenance-gated producer arm", () => withTempHome(async () => {
  // The evaluator (bundles evaluator-shared + evaluator-web) may promote a captured second
  // principal's credential into a named profile to run the id-bearing cross-tenant differential
  // in-wave. This grant is safe ONLY because the dispatcher seam cannot stamp synthetic
  // provenance (asserted above): an evaluator-promoted profile can never satisfy the IDOR /
  // mass-read producer's refuse-to-sign gate. Lock both facts together so the grant stays
  // intentional and its safety premise cannot silently regress.
  assert.equal(
    toolNamesForRoleBundle("evaluator-web").includes("bob_auth_store"),
    true,
    "bob_auth_store must be reachable by evaluator-web (route (a) credential promotion)",
  );

  const domain = "prov-stamp-evaluator-grant.test";
  seedSession(domain);
  // The exact call the evaluator makes: promote a captured victim credential via one-arg dispatch.
  const result = await executeTool("bob_auth_store", {
    target_domain: domain,
    profile_name: "victim",
    cookies: { session: "captured-victim-cookie" },
  });
  assert.equal(result.ok, true);
  const resolved = resolveAuthProfile("victim", `https://${domain}/`, domain);
  // A real captured credential is stored (usable for the differential) but carries NO synthetic
  // provenance — so it cannot clear the producer's provenance gate.
  assert.equal(resolved.Cookie, "session=captured-victim-cookie");
  assert.equal(profileHasProvenance(resolved), false);
}));

test("principal_fingerprint is over TRANSMITTED material only: two profiles sharing one cookie collapse to one principal (no forged distinctness)", () => withTempHome(() => {
  const domain = "prov-fingerprint-collapse.test";
  seedSession(domain);
  // One real session (identical transmitted cookie), two profile names with DIFFERENT Bob-local
  // credentials metadata — the exact input F3 makes evaluator-reachable via bob_auth_store.
  authStore({ target_domain: domain, profile_name: "tenant_a", cookies: { sid: "SHARED-SESSION" }, credentials: { email: "a@x.test" } });
  authStore({ target_domain: domain, profile_name: "tenant_b", cookies: { sid: "SHARED-SESSION" }, credentials: { email: "b@x.test" } });
  const summary = JSON.parse(listAuthProfiles({ target_domain: domain }));
  const a = summary.profiles.find((p) => p.profile_name === "tenant_a");
  const b = summary.profiles.find((p) => p.profile_name === "tenant_b");
  assert.ok(a && b, "both profiles summarized");
  // Same cookie -> same principal to the target -> identical fingerprint. The auth-differential
  // distinctness check therefore sees ONE principal, so a same-session pair cannot forge distinctness.
  assert.equal(a.principal_fingerprint, b.principal_fingerprint);
  assert.ok(typeof a.principal_fingerprint === "string" && a.principal_fingerprint);

  // A GENUINELY distinct session (different transmitted cookie) still gets a distinct fingerprint.
  authStore({ target_domain: domain, profile_name: "tenant_c", cookies: { sid: "OTHER-SESSION" }, credentials: { email: "a@x.test" } });
  const summary2 = JSON.parse(listAuthProfiles({ target_domain: domain }));
  const c = summary2.profiles.find((p) => p.profile_name === "tenant_c");
  assert.notEqual(c.principal_fingerprint, a.principal_fingerprint);
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

// ─────────────────────── namespace-clobber guard (F3) ───────────────────────
// bob_auth_store is evaluator-web-reachable (F3), and persistAuthProfiles writes
// doc.profiles[name] = {...}. Without a guard an evaluator could OVERWRITE the
// orchestrator-provisioned "attacker"/"victim" principal and poison concurrent workers.
// The guard: a dispatcher-path bob_auth_store (no 2nd-arg provenance) may CREATE a new name
// or overwrite a non-provenance name it made, but can NEVER clobber a profile carrying
// synthetic provenance. A legitimate in-process re-provision (bob_auto_signup, which does
// carry provenance) may refresh it.

test("namespace-clobber: a dispatcher bob_auth_store refuses to overwrite a provisioned 'victim' but freely creates 'tenant_b'", () => withTempHome(async () => {
  const domain = "prov-clobber.test";
  seedSession(domain);
  // Orchestrator SETUP provisions the crown 'victim' principal in-process (bob_auto_signup seam).
  authStore({
    target_domain: domain,
    profile_name: "victim",
    cookies: { session: "ORCHESTRATOR-VICTIM" },
  }, { provenance: SYNTH });
  const before = resolveAuthProfile("victim", `https://${domain}/`, domain);
  assert.equal(before.Cookie, "session=ORCHESTRATOR-VICTIM");
  assert.equal(profileHasProvenance(before), true);

  // An evaluator, via the one-arg dispatcher, tries to CLOBBER 'victim' with a captured cookie.
  const clobber = await executeTool("bob_auth_store", {
    target_domain: domain,
    profile_name: "victim",
    cookies: { session: "EVALUATOR-FORGE" },
  });
  assert.equal(clobber.ok, false, "clobber of a provisioned principal must be refused");
  assert.equal(clobber.error.code, ERROR_CODES.STATE_CONFLICT);

  // The provisioned principal is untouched on disk (no poisoning of concurrent workers).
  const saved = JSON.parse(fs.readFileSync(resolveAuthJsonPath(domain), "utf8"));
  assert.equal(saved.profiles.victim.Cookie, "session=ORCHESTRATOR-VICTIM");
  assert.equal(saved.profiles.victim.provisioned_via, "bob_auto_signup");
  assert.equal(saved.profiles.victim.synthetic, true);

  // But the SAME evaluator can freely CREATE a fresh, distinct principal name for the differential.
  const create = await executeTool("bob_auth_store", {
    target_domain: domain,
    profile_name: "tenant_b",
    cookies: { session: "EVALUATOR-SECOND-PRINCIPAL" },
  });
  assert.equal(create.ok, true, "creating a new profile name must be allowed");
  const tb = resolveAuthProfile("tenant_b", `https://${domain}/`, domain);
  assert.equal(tb.Cookie, "session=EVALUATOR-SECOND-PRINCIPAL");
  assert.equal(profileHasProvenance(tb), false);
}));

test("namespace-clobber is NOT forgeable via a provisioned_via/synthetic HEADER (guard keys on the unforgeable boolean synthetic===true)", () => withTempHome(async () => {
  const domain = "prov-clobber-forge.test";
  seedSession(domain);
  authStore({ target_domain: domain, profile_name: "victim", cookies: { session: "ORCHESTRATOR-VICTIM" } }, { provenance: SYNTH });

  // The forge the guard's own comment warned about: a dispatcher call that INJECTS a
  // provisioned_via (or synthetic) HEADER to make the incoming write look provenance-bearing.
  // Header values are schema-coerced to STRINGS, so a header named `synthetic` can only be "true"
  // (!== boolean true) and `provisioned_via` is a caller-forgeable string — the guard ignores both.
  for (const forgedHeaders of [
    { provisioned_via: "bob_auto_signup" },
    { synthetic: "true" },
    { provisioned_via: "bob_auto_signup", synthetic: "true" },
  ]) {
    const clobber = await executeTool("bob_auth_store", {
      target_domain: domain,
      profile_name: "victim",
      cookies: { session: "EVALUATOR-FORGE" },
      headers: forgedHeaders,
    });
    assert.equal(clobber.ok, false, `forged provenance header ${JSON.stringify(forgedHeaders)} must NOT bypass the guard`);
    assert.equal(clobber.error.code, ERROR_CODES.STATE_CONFLICT);
  }
  // The provisioned victim is untouched on disk after every forge attempt.
  const saved = JSON.parse(fs.readFileSync(resolveAuthJsonPath(domain), "utf8"));
  assert.equal(saved.profiles.victim.Cookie, "session=ORCHESTRATOR-VICTIM");
}));

test("namespace-clobber: direct authStore with no 2nd-arg provenance throws STATE_CONFLICT over a provisioned name", () => withTempHome(() => {
  const domain = "prov-clobber-direct.test";
  seedSession(domain);
  authStore({ target_domain: domain, profile_name: "attacker", headers: { Authorization: "Bearer eyJorig" } }, { provenance: SYNTH });
  assert.throws(
    () => authStore({ target_domain: domain, profile_name: "attacker", headers: { Authorization: "Bearer eyJforge" } }),
    (err) => err instanceof ToolError && err.code === ERROR_CODES.STATE_CONFLICT,
  );
  // Original token preserved (refusal is not a silent no-op that half-wrote).
  const saved = JSON.parse(fs.readFileSync(resolveAuthJsonPath(domain), "utf8"));
  assert.equal(saved.profiles.attacker.Authorization, "Bearer eyJorig");
}));

test("namespace-clobber: the in-process bob_auto_signup seam (2nd-arg provenance) MAY refresh a provisioned profile", () => withTempHome(() => {
  const domain = "prov-clobber-refresh.test";
  seedSession(domain);
  authStore({ target_domain: domain, profile_name: "victim", cookies: { session: "OLD" } }, { provenance: SYNTH });
  // A legitimate re-provision (token refresh) carries provenance itself → allowed to overwrite.
  authStore({ target_domain: domain, profile_name: "victim", cookies: { session: "REFRESHED" } }, { provenance: SYNTH });
  const resolved = resolveAuthProfile("victim", `https://${domain}/`, domain);
  assert.equal(resolved.Cookie, "session=REFRESHED");
  assert.equal(profileHasProvenance(resolved), true);
}));

test("namespace-clobber: a dispatcher bob_auth_store may overwrite a NON-provenance profile it created", () => withTempHome(async () => {
  const domain = "prov-clobber-nonprov.test";
  seedSession(domain);
  const a = await executeTool("bob_auth_store", { target_domain: domain, profile_name: "tenant_b", cookies: { session: "V1" } });
  assert.equal(a.ok, true);
  // No synthetic provenance on the prior → an evaluator may update its own captured principal.
  const b = await executeTool("bob_auth_store", { target_domain: domain, profile_name: "tenant_b", cookies: { session: "V2" } });
  assert.equal(b.ok, true);
  const resolved = resolveAuthProfile("tenant_b", `https://${domain}/`, domain);
  assert.equal(resolved.Cookie, "session=V2");
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
