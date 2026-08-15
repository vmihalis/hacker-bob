"use strict";

// bob_http_massread_confirm — broken-auth / BFLA mass-read producer.
// Seeded `driver` (no Chromium) + a stored attacker auth profile drive the attacker-vs-control
// differential. Asserts: signs MEDIUM only on the real differential; the signed rail is masked
// (NO raw PII) and MAC-valid; the negatives fail closed; the operator env gate alone enables the
// full raw capture; a minted row backs an exploited_safely MEDIUM claim.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  massreadConfirm,
  deriveMaskedSummary,
  extractRecords,
  cookieObjectsFromProfile,
  MASSREAD_MIN_RECORDS,
  OWNER_AUTHORIZED_ENV,
  TOOL_ID,
  MASSREAD_DEMONSTRATED_CEILING,
} = require("../mcp/domains/web/offensive-massread-producer.js");
const { initSession } = require("../mcp/core/session/session-state.js");
const { authStore } = require("../mcp/core/auth/auth.js");
const { routeSurfaces } = require("../mcp/core/frontier/surface-router.js");
const { ensureHandoffSigningKey, resolveOffensiveRowVerifier } = require("../mcp/core/ledger-integrity/handoff-signing-key.js");
const { attackSurfacePath, offensiveRunsJsonlPath, sessionDir } = require("../mcp/core/io/paths.js");
const { appendCandidateClaim, readOffensiveRunRecords, OFFENSIVE_TOOL_DEMONSTRATED_CEILING } = require("../mcp/core/claims/claims.js");
const { verifyRowWithMac, OFFENSIVE_ROW_MAC_CONTEXT } = require("../mcp/core/ledger-integrity/offensive-row-mac.js");
const { projectExploitRunObservedRef } = require("../mcp/core/claims/claim-freeze.js");
const { resetForTests: resetMaterializationDebounce } = require("../mcp/core/frontier/frontier-materialize-debounce.js");

const PRODUCER_PATH = path.join(__dirname, "..", "mcp", "domains", "web", "offensive-massread-producer.js");
const SURFACE_ID = "surface:listing";
// A canary PII VALUE that must NEVER appear in the signed rail (only its field-name bucket may).
const CANARY_EMAIL = "victim0@canary.example.test";

let DOMAIN_SEQ = 0;
// Unique domain per test: resolveAuthProfile caches by (domain, profile) at module scope, so a
// shared domain would bleed a profile across tests. Unique domains keep each test isolated.
function uniqueDomain() { DOMAIN_SEQ += 1; return `massread${DOMAIN_SEQ}.example.test`; }

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const previousOwner = process.env[OWNER_AUTHORIZED_ENV];
  const previousReadGuard = process.env.BOB_READ_GUARD;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-massread-producer-"));
  process.env.HOME = home;
  return Promise.resolve()
    .then(() => fn(home))
    .finally(() => {
      if (previousHome === undefined) delete process.env.HOME; else process.env.HOME = previousHome;
      if (previousOwner === undefined) delete process.env[OWNER_AUTHORIZED_ENV];
      else process.env[OWNER_AUTHORIZED_ENV] = previousOwner;
      if (previousReadGuard === undefined) delete process.env.BOB_READ_GUARD;
      else process.env.BOB_READ_GUARD = previousReadGuard;
      resetMaterializationDebounce();
      fs.rmSync(home, { recursive: true, force: true });
    });
}

function seedRoutedSurface(domain, { endpoints } = {}) {
  fs.mkdirSync(path.dirname(attackSurfacePath(domain)), { recursive: true });
  fs.writeFileSync(attackSurfacePath(domain), `${JSON.stringify({
    surfaces: [{
      id: SURFACE_ID,
      title: "Synthetic listing surface",
      surface_type: "web",
      hosts: [domain],
      endpoints: endpoints || [`https://${domain}/api/listing`],
      tech_stack: ["fixture"],
      priority: "HIGH",
    }],
  }, null, 2)}\n`, "utf8");
  JSON.parse(routeSurfaces({ target_domain: domain }));
}

function setupSession(domain, { withAttacker = true, blockInternalHosts = false, attackerCookies, attackerProfile } = {}) {
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/`, block_internal_hosts: blockInternalHosts }));
  seedRoutedSurface(domain);
  ensureHandoffSigningKey(domain);
  if (withAttacker) {
    authStore({
      target_domain: domain,
      profile_name: "attacker",
      ...(attackerProfile || { cookies: attackerCookies || { sid: "leaked-session-token" } }),
    });
  }
}

// A listing body of N records carrying an `email` PII column (value = the canary on record 0).
function bulkBody(n = 3) {
  const data = Array.from({ length: n }, (_, i) => ({
    id: i + 1,
    email: i === 0 ? CANARY_EMAIL : `user${i}@canary.example.test`,
    full_name: `User ${i}`,
  }));
  return JSON.stringify({ data });
}

function makeDriver(opts = {}) {
  const {
    available = true,
    attacker,
    control,
    startReturnsNoSession = false,
  } = opts;
  const att = attacker || { status: 200, body: bulkBody(3), final_url: null, body_truncated: false };
  const ctl = control || { status: 401, body: "", final_url: null, body_truncated: false };
  const calls = { starts: [], fetches: [], closed: 0 };
  const driver = {
    isAvailable: () => available,
    start: async (o) => {
      const isAttacker = Array.isArray(o.authCookies) && o.authCookies.length > 0;
      calls.starts.push({ isAttacker, targetUrl: o.targetUrl, cookieCount: o.authCookies ? o.authCookies.length : 0, authCookies: o.authCookies || null });
      if (startReturnsNoSession) return {};
      return { session_id: isAttacker ? "ms-attacker" : "ms-control" };
    },
    authedFetch: async (sessionId, fetchArgs) => {
      calls.fetches.push({ sessionId, fetchArgs });
      return sessionId === "ms-attacker" ? att : ctl;
    },
    close: async () => { calls.closed += 1; return { closed: true }; },
  };
  return { driver, calls };
}

async function run(domain, { driver, args } = {}) {
  return massreadConfirm(args || { target_domain: domain, surface_id: SURFACE_ID }, { driver });
}

// Recursively collect the bytes of the signed rail (everything under the session dir EXCEPT the
// opt-in massread-evidence capture), so a leak anywhere in the rail is caught.
function signedRailBytes(domain) {
  const root = sessionDir(domain);
  let out = "";
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (entry.name === "massread-evidence") continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else { try { out += fs.readFileSync(full, "utf8"); } catch { /* binary/lock */ } }
    }
  };
  if (fs.existsSync(root)) walk(root);
  return out;
}

// ───────────────────────── wiring / invariants ──────────────────────────

test("MASSREAD ceiling is a frozen HIGH that matches the authoritative registry (v1 stamps medium via the override)", () => {
  // The CEILING is HIGH (the max a proven victim-arm row may demonstrate); the v1 authn-vs-anon path is
  // stamped MEDIUM via the always-explicit override, asserted by the positive tests below.
  assert.equal(MASSREAD_DEMONSTRATED_CEILING.bob_http_massread_confirm, "high");
  assert.equal(Object.isFrozen(MASSREAD_DEMONSTRATED_CEILING), true);
  // The producer's doc constant must never drift from the authoritative claims.js registry that
  // buildAndSignOffensiveRow actually stamps from.
  assert.equal(
    MASSREAD_DEMONSTRATED_CEILING.bob_http_massread_confirm,
    OFFENSIVE_TOOL_DEMONSTRATED_CEILING.bob_http_massread_confirm,
    "producer doc ceiling must equal the authoritative registry ceiling",
  );
});

test("buildAndSignOffensiveRow is NOT re-exported (no gate-bypassing signed-row path)", () => {
  const mod = require("../mcp/domains/web/offensive-massread-producer.js");
  assert.equal(typeof mod.buildAndSignOffensiveRow, "undefined");
});

test("the producer uses the established browser subsystem (no child_process of its own)", () => {
  const src = fs.readFileSync(PRODUCER_PATH, "utf8");
  assert.ok(!/require\(\s*['"]child_process['"]\s*\)/.test(src), "must not require child_process directly");
});

// ───────────────────────── deriveMaskedSummary (unit) ──────────────────────────

test("deriveMaskedSummary: counts records, buckets sensitive field NAMES, sets value-shape booleans", () => {
  const s = deriveMaskedSummary(bulkBody(3));
  assert.equal(s.record_count, 3);
  assert.deepEqual(s.sensitive_field_names, ["email"]);
  assert.equal(s.pii_shape_present.email, true);
  // The summary itself carries NO raw value.
  assert.ok(!JSON.stringify(s).includes(CANARY_EMAIL), "masked summary must not echo a raw value");
});

test("deriveMaskedSummary: non-JSON body → 0 records (fail-closed, not a countable collection)", () => {
  const s = deriveMaskedSummary("<html><body>Access denied</body></html>");
  assert.equal(s.record_count, 0);
  assert.equal(s.parse_ok, false);
});

test("deriveMaskedSummary: top-level array and nested collection keys both resolve", () => {
  assert.equal(deriveMaskedSummary(JSON.stringify([{ id: 1 }, { id: 2 }])).record_count, 2);
  assert.equal(deriveMaskedSummary(JSON.stringify({ results: { items: [{ id: 1 }] } })).record_count, 1);
});

// ───────────────────────── positive (signs MEDIUM) ──────────────────────────

test("positive: attacker bulk-reads PII a denied control cannot → signed MEDIUM masked row", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  const { driver, calls } = makeDriver();
  const result = await run(domain, { driver });

  assert.equal(result.confirmed, true, JSON.stringify(result));
  assert.equal(result.row_written, true);
  assert.equal(result.offensive_outcome, "exploited_safely");
  assert.equal(result.demonstrated_severity, "medium");
  assert.equal(result.tool_id, TOOL_ID);
  assert.equal(result.masked_oracle.record_count, 3);
  assert.deepEqual(result.masked_oracle.sensitive_field_names, ["email"]);
  // Two arms: attacker (cookies) + control (none), each its own session, both closed.
  assert.equal(calls.starts.length, 2);
  assert.equal(calls.starts[0].isAttacker, true);
  assert.equal(calls.starts[1].isAttacker, false);
  assert.equal(calls.closed, 2);

  const rows = readOffensiveRunRecords(domain);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].tool_id, TOOL_ID);
  assert.equal(rows[0].demonstrated_severity, "medium");
  assert.equal(rows[0].row_mac.version, 2, "producer-minted rows are the v2 ed25519 envelope");
  assert.ok(verifyRowWithMac(OFFENSIVE_ROW_MAC_CONTEXT, rows[0], resolveOffensiveRowVerifier(domain)), "row must be MAC-signed");

  // The signed rail carries NO raw PII value (only the field-name bucket + booleans).
  const rail = signedRailBytes(domain);
  assert.ok(!rail.includes(CANARY_EMAIL), "signed rail must NOT contain a raw record value");
  assert.ok(rail.includes("email"), "the field-name bucket is recorded (masked)");
}));

test("round-trip: the minted row backs an exploited_safely MEDIUM claim and re-hashes stable", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  const { driver } = makeDriver();
  const result = await run(domain, { driver });
  assert.equal(result.confirmed, true);

  const claim = appendCandidateClaim({
    target_domain: domain,
    title: "Broken-auth mass-read of a bulk PII collection",
    summary: "An under-authorized identity bulk-read a sensitive collection a denied control cannot.",
    severity: "medium",
    exploit_outcome: { outcome: "exploited_safely", safe_oracle: { kind: "differential_response" } },
    surface_ids: [SURFACE_ID],
    evidence_refs: [{
      kind: "exploit_run",
      run_id: result.run_id,
      tool_id: result.tool_id,
      target: result.target,
      offensive_outcome: "exploited_safely",
      command_hash: result.command_hash,
      exit_code: result.exit_code,
      stdout_hash: result.stdout_hash,
      stderr_hash: result.stderr_hash,
    }],
  });
  assert.equal(claim.exploit_outcome.outcome, "exploited_safely");
  assert.equal(claim.severity, "medium");

  const row = readOffensiveRunRecords(domain)[0];
  for (let i = 0; i < 3; i += 1) {
    const observed = projectExploitRunObservedRef(domain, { kind: "exploit_run", run_id: row.run_id });
    assert.equal(observed.stdout_hash, row.stdout_hash, `verify round ${i + 1} re-hash must match`);
  }
}));

test("a HIGH claim from a v1 MEDIUM row is rejected by the row-cap (even though the registry ceiling is now HIGH)", () => withTempHome(async () => {
  // KEY v2 soundness property: raising the tool ceiling to HIGH does NOT let the v1 authn-vs-anon
  // differential back a HIGH claim — the claim-vs-row cap bounds the claim by the ROW's own
  // demonstrated_severity ("medium" on a v1 run), not by the registry ceiling.
  const domain = uniqueDomain();
  setupSession(domain);
  const { driver } = makeDriver();
  const result = await run(domain, { driver });
  assert.equal(result.confirmed, true);
  assert.equal(result.demonstrated_severity, "medium");
  assert.throws(() => appendCandidateClaim({
    target_domain: domain,
    title: "over-severity",
    summary: "attempts high from a medium mass-read row",
    severity: "high",
    exploit_outcome: { outcome: "exploited_safely", safe_oracle: { kind: "differential_response" } },
    surface_ids: [SURFACE_ID],
    evidence_refs: [{
      kind: "exploit_run", run_id: result.run_id, tool_id: result.tool_id, target: result.target,
      offensive_outcome: "exploited_safely", command_hash: result.command_hash, exit_code: result.exit_code,
      stdout_hash: result.stdout_hash, stderr_hash: result.stderr_hash,
    }],
  }), /claim severity exceeds the maximum demonstrated_severity/);
}));

// ───────────────────────── negatives (fail closed, NO row) ──────────────────────────

function assertNoRow(domain, result, outcome, reason) {
  assert.equal(result.confirmed, false, JSON.stringify(result));
  assert.equal(result.row_written, false);
  assert.equal(result.offensive_outcome, outcome);
  assert.equal(result.reason, reason);
  assert.ok(!fs.existsSync(offensiveRunsJsonlPath(domain)), "no signed row may be written on a negative");
}

test("negative: control ALSO reads the bulk collection → public endpoint, not an authz break", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  const { driver } = makeDriver({ control: { status: 200, body: bulkBody(3), final_url: null, body_truncated: false } });
  const result = await run(domain, { driver });
  assertNoRow(domain, result, "blocked_by_design", "control_also_reads_bulk_pii");
}));

test("negative: attacker count below the bulk floor → not a mass-read", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  const { driver } = makeDriver({ attacker: { status: 200, body: bulkBody(1), final_url: null, body_truncated: false } });
  assert.equal(MASSREAD_MIN_RECORDS, 2);
  const result = await run(domain, { driver });
  assertNoRow(domain, result, "blocked_by_defense", "attacker_did_not_read_bulk_pii");
}));

test("negative: attacker reads bulk but NO sensitive field present → not a PII mass-read", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  const benign = JSON.stringify({ data: [{ id: 1, color: "red" }, { id: 2, color: "blue" }, { id: 3, color: "green" }] });
  const { driver } = makeDriver({ attacker: { status: 200, body: benign, final_url: null, body_truncated: false } });
  const result = await run(domain, { driver });
  assertNoRow(domain, result, "blocked_by_defense", "attacker_did_not_read_bulk_pii");
}));

test("negative: attacker arm WAF/429 → cannot prove the read, fail closed", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  const { driver } = makeDriver({ attacker: { status: 429, body: "", final_url: null, body_truncated: false } });
  const result = await run(domain, { driver });
  assertNoRow(domain, result, "blocked_by_defense", "waf_or_rate_limit");
}));

test("ssrf safety: block_internal_hosts on → refuses (fails closed), no session started", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain, { blockInternalHosts: true });
  const { driver, calls } = makeDriver();
  const result = await run(domain, { driver });
  assertNoRow(domain, result, "blocked_by_design", "block_internal_hosts_unsupported_for_browser");
  assert.equal(calls.starts.length, 0, "must refuse BEFORE starting any browser session");
}));

test("negative: no attacker auth profile stored → blocked_by_design", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain, { withAttacker: false });
  const { driver, calls } = makeDriver();
  const result = await run(domain, { driver });
  assertNoRow(domain, result, "blocked_by_design", "attacker_auth_profile_not_found");
  assert.equal(calls.starts.length, 0);
}));

test("negative: bearer-only profile (no cookie) is not cookie-expressible (v2)", () => withTempHome(async () => {
  const domain = uniqueDomain();
  // local_storage with a JWT yields an Authorization header but NO Cookie (buildHeaderProfile).
  setupSession(domain, { attackerProfile: { local_storage: { token: "eyJhbGciOiJIUzI1NiJ9.payload.sig" } } });
  const { driver, calls } = makeDriver();
  const result = await run(domain, { driver });
  assertNoRow(domain, result, "blocked_by_design", "attacker_credential_not_cookie_expressible");
  assert.equal(calls.starts.length, 0);
}));

test("negative: browser unavailable → blocked_by_infra, no row", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  const { driver } = makeDriver({ available: false });
  const result = await run(domain, { driver });
  assertNoRow(domain, result, "blocked_by_infra", "browser_unavailable");
}));

// ───────────────────────── owner-authorized full capture (operator env gate) ──────────────────────────

test("full capture is OFF by default: signed rail masked, NO massread-evidence file", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  delete process.env[OWNER_AUTHORIZED_ENV];
  const { driver } = makeDriver();
  const result = await run(domain, { driver });
  assert.equal(result.confirmed, true);
  assert.equal(result.owner_authorized_capture, false);
  assert.ok(!fs.existsSync(path.join(sessionDir(domain), "massread-evidence")), "no evidence dir without the operator gate");
  assert.ok(!signedRailBytes(domain).includes(CANARY_EMAIL));
}));

test("full capture is enabled ONLY by the operator env gate; the signed rail stays masked either way", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  process.env[OWNER_AUTHORIZED_ENV] = domain; // gate is bound to THIS target (#904)
  process.env.BOB_READ_GUARD = "1"; // read-guard present (Claude/Kimi install) so capture is allowed (#916)
  const { driver } = makeDriver();
  const result = await run(domain, { driver });
  assert.equal(result.confirmed, true);
  assert.equal(result.owner_authorized_capture, true);
  const evidenceDir = path.join(sessionDir(domain), "massread-evidence");
  assert.ok(fs.existsSync(evidenceDir), "operator gate writes the full capture");
  const files = fs.readdirSync(evidenceDir);
  assert.equal(files.length, 1);
  const captureBytes = fs.readFileSync(path.join(evidenceDir, files[0]), "utf8");
  assert.ok(captureBytes.includes(CANARY_EMAIL), "the OPT-IN full capture carries the raw body (operator-owned)");
  // The signed rail is STILL masked — the raw value lives ONLY in the opt-in capture.
  assert.ok(!signedRailBytes(domain).includes(CANARY_EMAIL), "the signed rail must stay masked even with full capture on");
}));

test("the agent cannot enable full capture: owner_authorized is a forbidden input", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  delete process.env[OWNER_AUTHORIZED_ENV];
  const { driver } = makeDriver();
  // Supplying owner_authorized as an arg must be rejected (forbidden input), not silently honored.
  await assert.rejects(() => massreadConfirm(
    { target_domain: domain, surface_id: SURFACE_ID, owner_authorized: true },
    { driver },
  ));
}));

// ───────────────────────── soundness hardening (false-mint prevention) ──────────────────────────

test("truncation: a truncated CONTROL body → fail closed (a truncated control mis-scores as denied)", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  const { driver } = makeDriver({ control: { status: 200, body: bulkBody(3), final_url: null, body_truncated: true } });
  const result = await run(domain, { driver });
  assertNoRow(domain, result, "blocked_by_infra", "response_truncated_unreliable");
}));

test("truncation: a truncated ATTACKER body → fail closed", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  const { driver } = makeDriver({ attacker: { status: 200, body: bulkBody(3), final_url: null, body_truncated: true } });
  const result = await run(domain, { driver });
  assertNoRow(domain, result, "blocked_by_infra", "response_truncated_unreliable");
}));

test("cache-buster: each arm's fetch URL carries a DISTINCT _cb (no cross-arm cache serving)", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  const { driver, calls } = makeDriver();
  const result = await run(domain, { driver });
  assert.equal(result.confirmed, true);
  assert.equal(calls.fetches.length, 2);
  const cbOf = (u) => new URL(u).searchParams.get("_cb");
  const a = cbOf(calls.fetches[0].fetchArgs.url);
  const c = cbOf(calls.fetches[1].fetchArgs.url);
  assert.ok(a && c, "both arms carry a _cb cache-buster");
  assert.notEqual(a, c, "the two arms' _cb must differ so a shared cache can't cross-serve");
}));

test("control WAF/503 → fail closed (a throttled control is not a clean 'denied')", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  const { driver } = makeDriver({ control: { status: 503, body: "", final_url: null, body_truncated: false } });
  const result = await run(domain, { driver });
  assertNoRow(domain, result, "blocked_by_defense", "control_waf_or_rate_limit");
}));

test("ambiguous control (5xx) → control_inconclusive, not 'denied' and not 'also reads'", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  const { driver } = makeDriver({ control: { status: 500, body: "oops", final_url: null, body_truncated: false } });
  const result = await run(domain, { driver });
  assertNoRow(domain, result, "blocked_by_infra", "control_inconclusive");
}));

test("ambiguous control (404) → control_inconclusive", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  const { driver } = makeDriver({ control: { status: 404, body: "not found", final_url: null, body_truncated: false } });
  const result = await run(domain, { driver });
  assertNoRow(domain, result, "blocked_by_infra", "control_inconclusive");
}));

test("MINT GATE requires a real PII VALUE: a field merely NAMED like PII (emailVerified:true) does NOT mint", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  const nameOnly = JSON.stringify({ data: [{ id: 1, emailVerified: true }, { id: 2, emailVerified: false }, { id: 3, emailVerified: true }] });
  // record_count is 3, but the "email"-NAMED field (emailVerified) carries a boolean, not an email VALUE,
  // so the bucket is NOT confirmed (value↔field binding) and there is no distinct PII → no mint.
  const s = deriveMaskedSummary(nameOnly);
  assert.deepEqual(s.sensitive_field_names, []);
  assert.equal(s.pii_shape_present.email, false);
  assert.equal(s.distinct_pii_count, 0);
  const { driver } = makeDriver({ attacker: { status: 200, body: nameOnly, final_url: null, body_truncated: false } });
  const result = await run(domain, { driver });
  assertNoRow(domain, result, "blocked_by_defense", "attacker_did_not_read_bulk_pii");
}));

test("attacker 2xx body that does not parse to a collection → fail closed", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  const { driver } = makeDriver({ attacker: { status: 200, body: "<html>not json</html>", final_url: null, body_truncated: false } });
  const result = await run(domain, { driver });
  assertNoRow(domain, result, "blocked_by_defense", "attacker_body_not_a_countable_collection");
}));

test("HONEST relationBooleans: the signed witness asserts only what's proven, never a bare bfla_proven", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  const { driver } = makeDriver();
  const result = await run(domain, { driver });
  assert.equal(result.confirmed, true);
  const rel = result.masked_oracle.relation;
  assert.deepEqual(
    Object.keys(rel).sort(),
    ["credentialed_bulk_pii_read", "pii_value_shapes_present", "unauthenticated_control_denied"],
  );
  for (const forbidden of ["bfla_proven", "under_privileged", "cross_tenant", "attacker_reads_bulk_pii"]) {
    assert.ok(!(forbidden in rel), `must NOT assert ${forbidden} (the authed-vs-unauth oracle can't establish it)`);
  }
}));

test("symlinked massread-evidence dir → refused (not followed); the masked row still mints", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  process.env[OWNER_AUTHORIZED_ENV] = domain; // gate is bound to THIS target (#904)
  process.env.BOB_READ_GUARD = "1"; // read-guard present so the capture is ATTEMPTED (then refused by the symlink guard) (#916)
  const evilTarget = fs.mkdtempSync(path.join(os.tmpdir(), "bob-massread-evil-"));
  try {
    const sdir = sessionDir(domain);
    fs.mkdirSync(sdir, { recursive: true });
    fs.symlinkSync(evilTarget, path.join(sdir, "massread-evidence"));
    const { driver } = makeDriver();
    const result = await run(domain, { driver });
    assert.equal(result.confirmed, true, "the signed (masked) row still mints");
    assert.equal(result.owner_authorized_capture, false, "a symlinked evidence dir must be refused");
    assert.equal(fs.readdirSync(evilTarget).length, 0, "nothing may be written through the symlink");
    assert.ok(!signedRailBytes(domain).includes(CANARY_EMAIL), "the signed rail stays masked");
  } finally {
    fs.rmSync(evilTarget, { recursive: true, force: true });
  }
}));

test("malformed cookie (a value with a literal ;) is handled fail-soft — the producer still runs", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain, { attackerCookies: { sid: "abc;def", other: "ok" } });
  const { driver, calls } = makeDriver();
  const result = await run(domain, { driver });
  // The structured cookie_jar issues sid's value VERBATIM ("abc;def") — no truncation, no crash, and
  // (critically) no forged extra cookie out of the embedded ';'. The run proceeds and mints.
  assert.equal(result.confirmed, true);
  const attackerStart = calls.starts.find((s) => s.isAttacker);
  const sid = attackerStart.authCookies.find((c) => c.name === "sid");
  assert.equal(sid.value, "abc;def");
}));

// ── round-2 soundness (bot-review): bind the three mint signals to the SAME counted records ──────

test("FALSE-MINT closed: a metadata email + benign records does NOT mint (PII is not in a counted record)", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  // records = [{id:1},{id:2}] — no sensitive field, no PII value; the email lives in response METADATA.
  const attacker = { status: 200, body: JSON.stringify({ data: [{ id: 1 }, { id: 2 }], support_email: "help@vendor.example" }), final_url: null, body_truncated: false };
  const { driver } = makeDriver({ attacker });
  const result = await run(domain, { driver });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "attacker_did_not_read_bulk_pii");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("a top-level array of SCALARS is not a record collection → record_count 0, no mint", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  assert.equal(deriveMaskedSummary(JSON.stringify({ data: ["a", "b", "c"] })).record_count, 0);
  assert.equal(extractRecords({ tags: ["x", "y"] }).length, 0);
  const attacker = { status: 200, body: JSON.stringify({ data: ["a", "b", "c"] }), final_url: null, body_truncated: false };
  const { driver } = makeDriver({ attacker });
  const result = await run(domain, { driver });
  assert.equal(result.confirmed, false);
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("extractRecords picks the OBJECT array, not a larger SCALAR array", () => {
  const parsed = { results: [{ id: 1, email: "a@b.example" }, { id: 2, email: "c@d.example" }], tags: ["x", "y", "z", "w", "v"] };
  assert.equal(extractRecords(parsed).length, 2);
  assert.equal(deriveMaskedSummary(JSON.stringify(parsed)).record_count, 2);
});

test("widened vocab: an SSN mass-read mints MEDIUM (the former email/phone/iban vocab missed it)", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  const body = JSON.stringify({ data: [
    { id: 1, ssn: "123-45-6789", full_name: "A" },
    { id: 2, ssn: "987-65-4321", full_name: "B" },
  ] });
  const { driver } = makeDriver({ attacker: { status: 200, body, final_url: null, body_truncated: false } });
  const result = await run(domain, { driver });
  assert.equal(result.confirmed, true);
  assert.equal(result.row_written, true);
  assert.ok(result.masked_oracle.sensitive_field_names.includes("government_id"));
  assert.equal(result.masked_oracle.pii_shape_present.ssn, true);
  assert.ok(!signedRailBytes(domain).includes("123-45-6789"), "raw SSN must never reach the signed rail");
}));

test("widened vocab: a credit-card collection (with a per-subject email) mints MEDIUM and records the card shape", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  // Two DISTINCT subjects (distinct EMAILS drive the floor); each also carries a card. The card shape +
  // financial bucket are recorded, but the SUBJECT count comes from email — cards are not subject keys.
  const body = JSON.stringify({ data: [
    { id: 1, email: "a@a.example", card_number: "4111111111111111" },
    { id: 2, email: "b@b.example", card_number: "4012888888881881" },
  ] });
  const { driver } = makeDriver({ attacker: { status: 200, body, final_url: null, body_truncated: false } });
  const result = await run(domain, { driver });
  assert.equal(result.confirmed, true);
  assert.equal(result.masked_oracle.pii_shape_present.credit_card, true);
  assert.ok(result.masked_oracle.sensitive_field_names.includes("financial"));
}));

test("card is NOT a subject key: a CARD-ONLY list of two cards (no email/SSN) does NOT mint — one person has several", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  // The /me/payment-methods false-mint the multiplicity review caught: two DIFFERENT card values, no
  // per-subject email/SSN. Two cards could be ONE person's two instruments, so distinct_pii_count stays
  // 0 → below the floor → no mint (under-counting, the safe direction). The card shape is still recorded.
  const body = JSON.stringify({ data: [
    { id: 1, card_number: "4111111111111111" },
    { id: 2, card_number: "4012888888881881" },
  ] });
  const s = deriveMaskedSummary(body);
  assert.equal(s.distinct_pii_count, 0, "cards are not subject identifiers — no distinct subjects");
  assert.equal(s.pii_shape_present.credit_card, true, "the card shape is still detected + recorded");
  assert.ok(s.sensitive_field_names.includes("financial"));
  const { driver } = makeDriver({ attacker: { status: 200, body, final_url: null, body_truncated: false } });
  const result = await run(domain, { driver });
  assertNoRow(domain, result, "blocked_by_defense", "attacker_did_not_read_bulk_pii");
}));

test("IBAN is NOT a subject key: an IBAN-only list of two IBANs (no email/SSN) does NOT mint — one person has several", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  // Same multiplicity property as cards — a person holds several bank accounts. Two distinct IBAN values
  // are not two provable subjects. The IBAN shape is still detected; it just doesn't form a subject key.
  const body = JSON.stringify({ data: [
    { id: 1, iban: "GB82WEST12345698765432" },
    { id: 2, iban: "DE89370400440532013000" },
  ] });
  const s = deriveMaskedSummary(body);
  assert.equal(s.distinct_pii_count, 0, "IBANs are not subject identifiers — no distinct subjects");
  assert.equal(s.pii_shape_present.iban, true, "the IBAN shape is still detected + recorded");
  const { driver } = makeDriver({ attacker: { status: 200, body, final_url: null, body_truncated: false } });
  const result = await run(domain, { driver });
  assertNoRow(domain, result, "blocked_by_defense", "attacker_did_not_read_bulk_pii");
}));

test("field-name requirement: a PII value in a non-sensitive field (no sensitive field NAME) does NOT mint", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  const body = JSON.stringify({ data: [
    { id: 1, comment: "reach me at a@b.example" },
    { id: 2, comment: "or c@d.example" },
  ] });
  const { driver } = makeDriver({ attacker: { status: 200, body, final_url: null, body_truncated: false } });
  const result = await run(domain, { driver });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "attacker_did_not_read_bulk_pii");
}));

test("cookie forge prevented: a value with '; k=v' stays ONE cookie (structured jar, no identity mutation)", () => {
  const jar = cookieObjectsFromProfile({ cookie_jar: { sid: "abc; role=admin" }, Cookie: "sid=abc; role=admin" }, "https://x.example/");
  assert.equal(jar.length, 1);
  assert.equal(jar[0].name, "sid");
  assert.equal(jar[0].value, "abc; role=admin"); // verbatim — NOT re-split into a forged role=admin cookie
  // legacy fallback (no jar): a stale profile's flat header still parses best-effort.
  const legacy = cookieObjectsFromProfile({ Cookie: "a=1; b=2" }, "https://x.example/");
  assert.equal(legacy.length, 2);
});

test("control 403 WAF block page (non-JSON) → control_inconclusive, not a clean denial", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  const control = { status: 403, body: "<html><body>Access Denied (Ray ID: 8a...)</body></html>", final_url: null, body_truncated: false };
  const { driver } = makeDriver({ control });
  const result = await run(domain, { driver });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "control_inconclusive");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("control 403 is AMBIGUOUS even with a JSON body → inconclusive, never a clean denial (#675)", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  // A JSON 403 can be a real authz error OR a WAF/bot-challenge that JSON-encodes its block. Parseability
  // is not an auth-denial oracle, so a 403 is NEVER scored "denied" — only an explicit 401 (or 2xx-empty) is.
  const control = { status: 403, body: JSON.stringify({ error: "forbidden" }), final_url: null, body_truncated: false };
  const { driver } = makeDriver({ control });
  const result = await run(domain, { driver });
  assertNoRow(domain, result, "blocked_by_infra", "control_inconclusive");
}));

test("control 401 is the clean explicit unauthenticated denial → mints", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  const control = { status: 401, body: JSON.stringify({ error: "unauthorized" }), final_url: null, body_truncated: false };
  const { driver } = makeDriver({ control });
  const result = await run(domain, { driver });
  assert.equal(result.confirmed, true);
  assert.equal(result.row_written, true);
}));

// ── round-3: distinct-subject binding + status-agnostic control-reads-bulk ────────────────────────

test("constant boilerplate field across records does NOT mint (one distinct value < floor) (#658)", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  // Every record carries the SAME constant support email + store address — no per-subject PII.
  const body = JSON.stringify({ data: [
    { id: 1, email: "help@vendor.example", address: "1 Store St" },
    { id: 2, email: "help@vendor.example", address: "1 Store St" },
    { id: 3, email: "help@vendor.example", address: "1 Store St" },
  ] });
  const s = deriveMaskedSummary(body);
  assert.equal(s.distinct_pii_count, 1); // one distinct email value across all rows
  const { driver } = makeDriver({ attacker: { status: 200, body, final_url: null, body_truncated: false } });
  const result = await run(domain, { driver });
  assertNoRow(domain, result, "blocked_by_defense", "attacker_did_not_read_bulk_pii");
}));

test("a single PII-bearing record (caller's own row) among benign rows does NOT mint (#657)", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  const body = JSON.stringify({ data: [
    { id: 1, email: "me@self.example" }, // the caller's own row
    { id: 2, status: "ok" },             // benign, no PII
    { id: 3, status: "pending" },        // benign, no PII
  ] });
  const s = deriveMaskedSummary(body);
  assert.equal(s.pii_bearing_count, 1);
  const { driver } = makeDriver({ attacker: { status: 200, body, final_url: null, body_truncated: false } });
  const result = await run(domain, { driver });
  assertNoRow(domain, result, "blocked_by_defense", "attacker_did_not_read_bulk_pii");
}));

test("a self-record with a nested collection of its OWN repeated PII does NOT mint (#268)", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  // One user's response: extractRecords may promote the nested `items`, but every order repeats the
  // SAME owner email → one distinct value → below the floor.
  const body = JSON.stringify({ results: { items: [
    { order: 1, email: "owner@self.example" },
    { order: 2, email: "owner@self.example" },
  ] } });
  const { driver } = makeDriver({ attacker: { status: 200, body, final_url: null, body_truncated: false } });
  const result = await run(domain, { driver });
  assertNoRow(domain, result, "blocked_by_defense", "attacker_did_not_read_bulk_pii");
}));

test("control 401 that STILL returns the bulk PII body is NOT denied → public, no mint (#669)", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  // Status 401 but the body still contains the bulk collection → the client CAN read it → not denied.
  const control = { status: 401, body: bulkBody(3), final_url: null, body_truncated: false };
  const { driver } = makeDriver({ control });
  const result = await run(domain, { driver });
  assertNoRow(domain, result, "blocked_by_design", "control_also_reads_bulk_pii");
}));

test("control 2xx that read >= MIN REDACTED records (no PII shape) → inconclusive, not minted, not 'public' (#677/#914)", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  // Control 2xx returns >= MIN records but trips no PII shape (redacted listing). It still READ the
  // collection, so it never mints (#677); but it is no longer mislabeled "public" — anon saw only redacted
  // rows while the attacker got PII, which is a field-level differential v1 conservatively declines (#914).
  const control = { status: 200, body: JSON.stringify({ data: [{ id: 1 }, { id: 2 }, { id: 3 }] }), final_url: null, body_truncated: false };
  const { driver } = makeDriver({ control });
  const result = await run(domain, { driver });
  assertNoRow(domain, result, "blocked_by_infra", "control_inconclusive_redacted_bulk");
}));

// ── round-4: per-bucket subject count + empty-2xx control denial ───────────────────────────────────

test("one subject carrying SEVERAL PII fields (email+ssn) across rows does NOT mint (#387)", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  // Two order rows for ONE subject, each repeating the SAME email AND ssn. The OLD cross-bucket count
  // reached 2 from (email,v)+(ssn,v) and would have minted; the per-bucket floor sees ONE distinct
  // value in each bucket → max cardinality 1 → below the floor.
  const body = JSON.stringify({ data: [
    { order: 1, email: "one@self.example", ssn: "123-45-6789" },
    { order: 2, email: "one@self.example", ssn: "123-45-6789" },
  ] });
  const s = deriveMaskedSummary(body);
  assert.equal(s.pii_bearing_count, 2);   // both rows carry sensitive PII
  assert.equal(s.distinct_pii_count, 1);  // but only ONE distinct subject (max single-bucket cardinality)
  assert.equal(s.pii_shape_present.email, true);
  assert.equal(s.pii_shape_present.ssn, true); // both buckets populated — this is a true multi-bucket case
  const { driver } = makeDriver({ attacker: { status: 200, body, final_url: null, body_truncated: false } });
  const result = await run(domain, { driver });
  assertNoRow(domain, result, "blocked_by_defense", "attacker_did_not_read_bulk_pii");
}));

test("two DISTINCT subjects in one bucket (2 emails) mints — the per-bucket floor still passes real leaks", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  // Two subjects, distinct emails → email bucket cardinality 2 → at the floor → mints.
  const body = JSON.stringify({ data: [
    { id: 1, email: "alice@canary.example.test" },
    { id: 2, email: "bob@canary.example.test" },
  ] });
  assert.equal(deriveMaskedSummary(body).distinct_pii_count, 2);
  const { driver } = makeDriver({ attacker: { status: 200, body, final_url: null, body_truncated: false } });
  const result = await run(domain, { driver });
  assert.equal(result.confirmed, true, JSON.stringify(result));
  assert.equal(result.row_written, true);
}));

test("empty 2xx control (204 / empty 200) read NO bulk → denied → mints (#706)", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  for (const status of [200, 204]) {
    const control = { status, body: "", final_url: null, body_truncated: false };
    const { driver } = makeDriver({ control });
    const result = await run(domain, { driver });
    assert.equal(result.confirmed, true, `empty ${status} control must be a clean denial: ${JSON.stringify(result)}`);
    assert.equal(result.row_written, true);
  }
}));

test("unparseable NON-empty 2xx control (HTML shell) stays inconclusive — not a denial (#706 boundary)", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  // A 2xx with a non-empty, non-JSON body (app shell / WAF interstitial) is ambiguous — NOT a clean
  // denial — so it must fail closed, never mint off an inconclusive baseline.
  const control = { status: 200, body: "<!doctype html><html><body>app</body></html>", final_url: null, body_truncated: false };
  const { driver } = makeDriver({ control });
  const result = await run(domain, { driver });
  assertNoRow(domain, result, "blocked_by_infra", "control_inconclusive");
}));

// ── round-5: normalized per-(field,shape) subject count + status-0 control ─────────────────────────

test("case/format variants of ONE subject's value do NOT mint (normalized) (#394)", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  // Same person across two rows, email cased differently and phone formatted differently.
  const body = JSON.stringify({ data: [
    { id: 1, email: "Alice@Example.com", phone: "(555) 123-4567" },
    { id: 2, email: "alice@example.com", phone: "555-123-4567" },
  ] });
  const s = deriveMaskedSummary(body);
  assert.equal(s.pii_bearing_count, 2);
  assert.equal(s.distinct_pii_count, 1); // normalized email/phone collapse → one subject
  const { driver } = makeDriver({ attacker: { status: 200, body, final_url: null, body_truncated: false } });
  const result = await run(domain, { driver });
  assertNoRow(domain, result, "blocked_by_defense", "attacker_did_not_read_bulk_pii");
}));

test("intra-bucket multi-field for ONE subject (email + recovery_email) does NOT mint (#393/#405)", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  // Both `email` and `recovery_email` map to the `email` BUCKET, but they are distinct concrete FIELDS.
  // One subject echoed across two rows must stay at cardinality 1 per field → no mint.
  const body = JSON.stringify({ data: [
    { id: 1, email: "owner@self.example", recovery_email: "owner.alt@self.example" },
    { id: 2, email: "owner@self.example", recovery_email: "owner.alt@self.example" },
  ] });
  const s = deriveMaskedSummary(body);
  assert.equal(s.distinct_pii_count, 1); // per-FIELD, not per-bucket — fields don't sum
  const { driver } = makeDriver({ attacker: { status: 200, body, final_url: null, body_truncated: false } });
  const result = await run(domain, { driver });
  assertNoRow(domain, result, "blocked_by_defense", "attacker_did_not_read_bulk_pii");
}));

test("structured field value: only the extracted PII token counts, not the whole JSON (#394 P1)", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  // Same subject's email wrapped with a VARYING non-PII sibling (label) per row. Keying on the whole
  // serialized object would inflate to 2; extracting `a@x.com` keeps it at 1.
  const body = JSON.stringify({ data: [
    { id: 1, email: { value: "owner@self.example", label: "billing" } },
    { id: 2, email: { value: "owner@self.example", label: "shipping" } },
  ] });
  const s = deriveMaskedSummary(body);
  assert.equal(s.pii_bearing_count, 2);
  assert.equal(s.distinct_pii_count, 1);
  const { driver } = makeDriver({ attacker: { status: 200, body, final_url: null, body_truncated: false } });
  const result = await run(domain, { driver });
  assertNoRow(domain, result, "blocked_by_defense", "attacker_did_not_read_bulk_pii");
}));

test("two shapes in ONE field for one subject are NOT summed to 2 subjects", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  // A single sensitive field carrying ONE subject's email AND phone, repeated across rows. Per-(field,
  // shape) partitioning keeps each shape at cardinality 1 → max 1 → no mint (no shape-summing defeat).
  const body = JSON.stringify({ data: [
    { id: 1, email: "owner@self.example tel 555-123-4567" },
    { id: 2, email: "owner@self.example tel 555-123-4567" },
  ] });
  const s = deriveMaskedSummary(body);
  assert.equal(s.distinct_pii_count, 1);
  const { driver } = makeDriver({ attacker: { status: 200, body, final_url: null, body_truncated: false } });
  const result = await run(domain, { driver });
  assertNoRow(domain, result, "blocked_by_defense", "attacker_did_not_read_bulk_pii");
}));

test("status-0 opaqueredirect control does NOT crash the audit → fail closed inconclusive (#448)", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  // authed_fetch surfaces a manual redirect-to-login as status 0; it must be coerced to null before
  // the http-audit normalizer (which rejects out-of-range statuses) and fall to control_inconclusive,
  // NOT throw probe_audit_failed and abort the run.
  const control = { status: 0, body: "", final_url: "https://login.example/sso", body_truncated: false };
  const { driver } = makeDriver({ control });
  const result = await run(domain, { driver });
  assertNoRow(domain, result, "blocked_by_infra", "control_inconclusive");
}));

// ── round-6: subject-key model (phone/address excluded), multi-token-one-record, IBAN target ──────

test("phone-only collection does NOT mint — phone is labeled but not a subject identifier (#183)", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  // Two distinct phones, no email/SSN/card/IBAN. Phones are recorded (sensitive_field_names) but a
  // subject can have several, so they don't form subject keys → distinct_pii_count 0 → no mint.
  const body = JSON.stringify({ data: [
    { id: 1, phone: "555-111-2222" },
    { id: 2, phone: "555-333-4444" },
  ] });
  const s = deriveMaskedSummary(body);
  assert.equal(s.pii_bearing_count, 2);          // phones ARE detected + labeled
  assert.deepEqual(s.sensitive_field_names, ["phone"]);
  assert.equal(s.distinct_pii_count, 0);          // but they are NOT subject identifiers
  const { driver } = makeDriver({ attacker: { status: 200, body, final_url: null, body_truncated: false } });
  const result = await run(domain, { driver });
  assertNoRow(domain, result, "blocked_by_defense", "attacker_did_not_read_bulk_pii");
}));

test("one record listing two of its OWN emails in one field is ONE subject key (#419)", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  // A self/history view: each row lists the SAME subject's two emails in one field. One record = one
  // subject key (its sorted identifier set), so two identical rows are ONE distinct key, not two.
  const body = JSON.stringify({ data: [
    { id: 1, email: "owner@self.example alt@self.example" },
    { id: 2, email: "owner@self.example alt@self.example" },
  ] });
  const s = deriveMaskedSummary(body);
  assert.equal(s.distinct_pii_count, 1); // one subject key {owner, alt}, not two tokens
  const { driver } = makeDriver({ attacker: { status: 200, body, final_url: null, body_truncated: false } });
  const result = await run(domain, { driver });
  assertNoRow(domain, result, "blocked_by_defense", "attacker_did_not_read_bulk_pii");
}));

test("an IBAN in the routed target path is screened → no raw PII in the signed rail (#643)", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  // Re-route the surface to an endpoint whose PATH embeds an IBAN. canonicalizeExploitTarget keeps the
  // path, so without the IBAN screen the raw IBAN would persist into the signed row target.
  seedRoutedSurface(domain, { endpoints: [`https://${domain}/accounts/GB82WEST12345698765432/transactions`] });
  const { driver } = makeDriver();
  const result = await run(domain, { driver });
  assertNoRow(domain, result, "blocked_operator_pii", "proof_target_contains_sensitive_value");
}));

// ── round-7: priority-shape subject key, control-with-PII, IBAN case/encoding + checksum ───────────

test("records sharing one identifier are ONE subject even if one has an extra identifier (#432)", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  // Same subject in two rows: both share the email; one row also carries an SSN. Keying on the dominant
  // identifier (email) merges them → one subject key, not two.
  const body = JSON.stringify({ data: [
    { id: 1, email: "owner@self.example" },
    { id: 2, email: "owner@self.example", ssn: "123-45-6789" },
  ] });
  assert.equal(deriveMaskedSummary(body).distinct_pii_count, 1);
  const { driver } = makeDriver({ attacker: { status: 200, body, final_url: null, body_truncated: false } });
  const result = await run(domain, { driver });
  assertNoRow(domain, result, "blocked_by_defense", "attacker_did_not_read_bulk_pii");
}));

test("a control that itself reads ONE subject's PII is NOT a clean denial → inconclusive (#784)", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  // Attacker reads bulk (default 3 distinct subjects); the unauthenticated control returns a 2xx with
  // ONE PII-bearing record. The control surfaced a real subject's PII, so "anon is denied PII" fails —
  // a public teaser / partial-public endpoint, not a clean authz differential → fail closed.
  const control = { status: 200, body: JSON.stringify({ data: [{ id: 1, email: "teaser@public.example" }] }), final_url: null, body_truncated: false };
  const { driver } = makeDriver({ control });
  const result = await run(domain, { driver });
  assertNoRow(domain, result, "blocked_by_infra", "control_inconclusive");
}));

test("a LOWERCASE IBAN in the target path is still screened (case-folded) (#650)", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  // Same valid IBAN as above, lowercased. The bare uppercase regex would have missed it.
  seedRoutedSurface(domain, { endpoints: [`https://${domain}/accounts/gb82west12345698765432/transactions`] });
  const { driver } = makeDriver();
  const result = await run(domain, { driver });
  assertNoRow(domain, result, "blocked_operator_pii", "proof_target_contains_sensitive_value");
}));

test("a hex-ish path segment that FAILS the IBAN checksum is NOT a false positive → mints (#650 precision)", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  // Same IBAN SHAPE but check digits 00 (never valid) — a stand-in for any hex-ish id/path segment. The
  // checksum rejects it, so the screen does NOT fail-closed and spuriously block a legit listing run.
  seedRoutedSurface(domain, { endpoints: [`https://${domain}/items/gb00west12345698765432/list`] });
  const { driver } = makeDriver();
  const result = await run(domain, { driver });
  assert.equal(result.confirmed, true, `non-IBAN hex path must not be screened: ${JSON.stringify(result)}`);
  assert.equal(result.row_written, true);
}));

// ── round-8: union-find subjects, control-any-PII, formatted-IBAN ──────────────────────────────────

test("overlapping same-shape identifiers for one subject are unioned to ONE subject (#473)", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  // Same subject twice: row 2 lists an extra alias email. The rows SHARE owner@self → union-find merges
  // them into one subject component, even though row 2's value-set is a superset of row 1's.
  const body = JSON.stringify({ data: [
    { id: 1, email: "owner@self.example" },
    { id: 2, email: "owner@self.example alt@self.example" },
  ] });
  assert.equal(deriveMaskedSummary(body).distinct_pii_count, 1);
  const { driver } = makeDriver({ attacker: { status: 200, body, final_url: null, body_truncated: false } });
  const result = await run(domain, { driver });
  assertNoRow(domain, result, "blocked_by_defense", "attacker_did_not_read_bulk_pii");
}));

test("a control returning ONE phone/address PII record is NOT a clean denial → inconclusive (#819)", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  // Phone is NOT a subject identifier (distinct_pii_count stays 0), but it IS real PII the anon client
  // read — so the control is not cleanly denied. Uses pii_bearing_count, not distinct_pii_count.
  const control = { status: 200, body: JSON.stringify({ data: [{ id: 1, phone: "555-123-4567" }] }), final_url: null, body_truncated: false };
  const cs = deriveMaskedSummary(control.body);
  assert.equal(cs.pii_bearing_count, 1);
  assert.equal(cs.distinct_pii_count, 0);
  const { driver } = makeDriver({ control });
  const result = await run(domain, { driver });
  assertNoRow(domain, result, "blocked_by_infra", "control_inconclusive");
}));

test("a space-formatted, URL-encoded IBAN in the target path is still screened (#230)", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  // %20-separated IBAN decodes to "GB82 WEST 1234 5698 7654 32"; separator-stripping makes it contiguous.
  seedRoutedSurface(domain, { endpoints: [`https://${domain}/accounts/GB82%20WEST%201234%205698%207654%2032/transactions`] });
  const { driver } = makeDriver();
  const result = await run(domain, { driver });
  assertNoRow(domain, result, "blocked_operator_pii", "proof_target_contains_sensitive_value");
}));

// ── round-10: Gmail-alias normalize, double-encoded IBAN, singleton control PII, target-bound capture ──

test("Gmail dot/plus aliases of one mailbox are ONE subject (#203)", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  // Same Gmail mailbox, two alias spellings → canonicalize equal → union-find merges → one subject.
  const body = JSON.stringify({ data: [
    { id: 1, email: "alice.smith+orders@gmail.com" },
    { id: 2, email: "alicesmith@gmail.com" },
  ] });
  assert.equal(deriveMaskedSummary(body).distinct_pii_count, 1);
  const { driver } = makeDriver({ attacker: { status: 200, body, final_url: null, body_truncated: false } });
  const result = await run(domain, { driver });
  assertNoRow(domain, result, "blocked_by_defense", "attacker_did_not_read_bulk_pii");
}));

test("a DOUBLE-encoded IBAN in the target path is still screened (decode to fixed point) (#224)", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  // %2520 → %20 → space; one decodeURIComponent pass leaves %20, so the screen must decode to a fixed point.
  seedRoutedSurface(domain, { endpoints: [`https://${domain}/accounts/GB82%2520WEST%25201234%25205698%25207654%252032/x`] });
  const { driver } = makeDriver();
  const result = await run(domain, { driver });
  assertNoRow(domain, result, "blocked_operator_pii", "proof_target_contains_sensitive_value");
}));

test("a singleton-object control carrying PII is NOT a clean denial → inconclusive (#821)", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  // The control returns a non-array JSON object with PII (a teaser / error object). deriveMaskedSummary
  // extracts no records from it, but controlBodyExposesPii catches the field-bound PII → not denied.
  const control = { status: 200, body: JSON.stringify({ email: "teaser@public.example" }), final_url: null, body_truncated: false };
  assert.equal(deriveMaskedSummary(control.body).pii_bearing_count, 0); // not extracted as a record...
  const { driver } = makeDriver({ control });
  const result = await run(domain, { driver });
  assertNoRow(domain, result, "blocked_by_infra", "control_inconclusive"); // ...but still blocks the mint
}));

test("raw capture is bound to the target: env naming a DIFFERENT domain does NOT capture (#904)", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  process.env[OWNER_AUTHORIZED_ENV] = "some-other-engagement.example"; // authorized for a DIFFERENT target
  const { driver } = makeDriver();
  const result = await run(domain, { driver });
  assert.equal(result.confirmed, true);
  assert.equal(result.owner_authorized_capture, false, "capture must NOT fire for an unauthorized target");
  assert.ok(!fs.existsSync(path.join(sessionDir(domain), "massread-evidence")), "no evidence dir for a different-target gate");
}));

// ── round-11: raw capture default-denied on adapters without a read-guard (#916) ──
test("raw capture is DEFAULT-DENIED without a read-guard: owner gate ON but BOB_READ_GUARD=0 → no capture (#916)", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  process.env[OWNER_AUTHORIZED_ENV] = domain; // operator authorized this target...
  process.env.BOB_READ_GUARD = "0"; // ...but this install has NO read-guard (Codex / generic-mcp) → deny
  const { driver } = makeDriver();
  const result = await run(domain, { driver });
  assert.equal(result.confirmed, true, "the signed (masked) row still mints regardless");
  assert.equal(result.owner_authorized_capture, false, "no raw capture where the agent could read it back");
  assert.ok(!fs.existsSync(path.join(sessionDir(domain), "massread-evidence")), "no evidence dir without a read-guard");
  assert.ok(!signedRailBytes(domain).includes(CANARY_EMAIL), "the signed rail stays masked either way");
}));

test("read-guard is EXPLICIT-only: owner gate ON but BOB_READ_GUARD unset → no capture (no file auto-detect) (#916 round-2)", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  process.env[OWNER_AUTHORIZED_ENV] = domain;
  delete process.env.BOB_READ_GUARD; // unset → default-DENY. The framework ships the hook file, so file
  // existence is NOT a sound proxy for an enforced guard; the operator must explicitly assert it.
  const { driver } = makeDriver();
  const result = await run(domain, { driver });
  assert.equal(result.confirmed, true, "the signed (masked) row still mints");
  assert.equal(result.owner_authorized_capture, false, "no capture without an explicit read-guard assertion");
  assert.ok(!fs.existsSync(path.join(sessionDir(domain), "massread-evidence")), "no evidence dir when BOB_READ_GUARD is unset");
}));

// ── round-11: a 401 control whose NON-JSON body still ships BULK PII is not a clean denial (#837) ──
test("a 401 control with a CSV/plaintext body carrying BULK PII is NOT a clean denial → inconclusive (#837)", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  // 401 + a NON-JSON (CSV) body that deriveMaskedSummary/controlBodyExposesPii cannot parse, but which
  // still hands the anon client >= MIN distinct PII values. distinctPiiValuesInText must catch it.
  const control = { status: 401, body: "email,name\nalice@a.example,Alice\nbob@b.example,Bob\n", final_url: null, body_truncated: false };
  assert.equal(deriveMaskedSummary(control.body).parse_ok, false, "the CSV body is not JSON-parseable");
  const { driver } = makeDriver({ control });
  const result = await run(domain, { driver });
  assertNoRow(domain, result, "blocked_by_infra", "control_inconclusive");
}));

test("a 401 control with a LONE support email in free text IS still a clean denial → mints (#837 threshold)", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  // One contact email (< MIN distinct subjects) in a denial page must NOT trip the raw-text bulk check —
  // preserves the round-10 field-bound free-text robustness while #837 catches genuine bulk exports.
  const control = { status: 401, body: "Access denied. Contact support@vendor.example for help.", final_url: null, body_truncated: false };
  const { driver } = makeDriver({ control });
  const result = await run(domain, { driver });
  assert.equal(result.confirmed, true, "a lone support email at 401 is a clean denial → the differential mints");
  assert.equal(result.demonstrated_severity, "medium",
    "the authn-vs-anon differential alone mints the registry-stamped MEDIUM tier (no cross-tenant victim arm ran)");
  assert.equal(result.cross_tenant_proven, false,
    "with no victim arm the run is NOT elevated to cross-tenant HIGH");
}));

// ── round-12: nested-record PII, non-identifier bulk control PII ──
test("nested-record PII is detected: { user: { email } } per row mints MEDIUM (#512)", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  // Real API shape — PII under a non-sensitive top-level key (`user`). The bounded record walk must reach
  // the nested `email`/`ssn` fields; a top-level-only scan would miss them entirely (false negative).
  const body = JSON.stringify({ data: [
    { id: 1, user: { email: "a@a.example", profile: { ssn: "123-45-6789" } } },
    { id: 2, user: { email: "b@b.example", profile: { ssn: "987-65-4321" } } },
  ] });
  const s = deriveMaskedSummary(body);
  assert.equal(s.distinct_pii_count, 2, "two nested subjects are counted");
  assert.equal(s.pii_shape_present.email, true);
  assert.equal(s.pii_shape_present.ssn, true);
  const { driver } = makeDriver({ attacker: { status: 200, body, final_url: null, body_truncated: false } });
  const result = await run(domain, { driver });
  assert.equal(result.confirmed, true);
  assert.ok(!signedRailBytes(domain).includes("a@a.example"), "nested raw PII never reaches the signed rail");
}));

test("one record's nested email list is ONE subject, not many (#512 + #419 across nesting)", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  // A single subject whose nested object carries primary + recovery emails. Within-record union must hold
  // across nesting → ONE subject → below the floor → no mint (no nested-multiplicity inflation).
  const body = JSON.stringify({ data: [
    { id: 1, contact: { email: "owner@self.example", recovery_email: "owner.alt@self.example" } },
  ] });
  assert.equal(deriveMaskedSummary(body).distinct_pii_count, 1);
  const { driver } = makeDriver({ attacker: { status: 200, body, final_url: null, body_truncated: false } });
  const result = await run(domain, { driver });
  assertNoRow(domain, result, "blocked_by_defense", "attacker_did_not_read_bulk_pii");
}));

test("a 401 control whose non-JSON body ships BULK non-identifier PII (phones) is NOT a clean denial → inconclusive (#581)", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  // CSV of phone numbers only (no email/SSN). Phones are not subject KEYS, but they ARE raw PII the anon
  // client received — distinctPiiValuesInText counts ALL shapes, so this forces inconclusive, not a mint.
  const control = { status: 401, body: "phone\n+1-202-555-0143\n+1-202-555-0178\n+1-202-555-0199\n", final_url: null, body_truncated: false };
  const { driver } = makeDriver({ control });
  const result = await run(domain, { driver });
  assertNoRow(domain, result, "blocked_by_infra", "control_inconclusive");
}));

// ═══════════════════════ v2 victim arm (cross-principal HIGH) ═══════════════════════
// A SECOND authenticated identity reads its OWN private scope; the attacker's bulk read overlapping it,
// while a fresh anon client is denied that scope, is a categorical cross-PRINCIPAL break → HIGH. The arm
// is ELEVATING only: any failure leaves the proven v1 MEDIUM intact.

const VICTIM_SURFACE_ID = "surface:victim-me";
// A DIFFERENT surface id that resolves to the SAME endpoint as the bulk listing (alias-replay fixture, #H).
const VICTIM_ALIAS_SURFACE_ID = "surface:victim-alias";

// Routed surfaces: the bulk listing (attacker + anon control), the victim's own-scope /api/me, and an
// alias surface pointing at the listing endpoint (to exercise the resolved-endpoint replay guard).
function seedV2Surfaces(domain) {
  fs.mkdirSync(path.dirname(attackSurfacePath(domain)), { recursive: true });
  fs.writeFileSync(attackSurfacePath(domain), `${JSON.stringify({
    surfaces: [
      {
        id: SURFACE_ID, title: "Synthetic listing surface", surface_type: "web", hosts: [domain],
        endpoints: [`https://${domain}/api/listing`], tech_stack: ["fixture"], priority: "HIGH",
      },
      {
        id: VICTIM_SURFACE_ID, title: "Victim own-scope surface", surface_type: "web", hosts: [domain],
        endpoints: [`https://${domain}/api/me`], tech_stack: ["fixture"], priority: "HIGH",
      },
      {
        id: VICTIM_ALIAS_SURFACE_ID, title: "Alias of the listing endpoint", surface_type: "web", hosts: [domain],
        endpoints: [`https://${domain}/api/listing`], tech_stack: ["fixture"], priority: "HIGH",
      },
    ],
  }, null, 2)}\n`, "utf8");
  JSON.parse(routeSurfaces({ target_domain: domain }));
}

// The victim's KNOWN account identity — also record 0 of the attacker bulk (bulkBody) so the attacker's
// read overlaps it. profile.email is persisted ONLY for a SYNTHETIC profile (the in-process signup path),
// so a v2 victim is minted with that provenance (mirrors a bob_auto_signup-provisioned victim).
const VICTIM_EMAIL = CANARY_EMAIL;
function setupV2Session(domain, {
  victimCookies = { sid: "victim-session-token" }, attackerCookies, victimSynthetic = true, victimEmail = VICTIM_EMAIL,
} = {}) {
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/`, block_internal_hosts: false }));
  seedV2Surfaces(domain);
  ensureHandoffSigningKey(domain);
  authStore({ target_domain: domain, profile_name: "attacker", cookies: attackerCookies || { sid: "leaked-session-token" } });
  // A SYNTHETIC victim carries profile.email + provenance (passed as the 2nd positional arg — the seam the
  // MCP dispatcher never supplies, so the public tool can never forge it). Default; opt out with victimSynthetic:false.
  const opts = victimSynthetic
    ? { provenance: { synthetic: true, email_origin: "temp_email", provisioned_via: "bob_auto_signup", email: victimEmail } }
    : {};
  authStore({ target_domain: domain, profile_name: "victim", cookies: victimCookies }, opts);
}

// The victim's own-scope body (a /me-style singleton object), bearing the victim's OWN email.
function victimBody(email = CANARY_EMAIL) { return JSON.stringify({ id: 1, email, full_name: "Victim Zero" }); }

// A 4-arm driver: (cookies?) × (listing vs /api/me path) → one of four seeded responses.
function makeV2Driver(opts = {}) {
  const {
    available = true,
    attacker = { status: 200, body: bulkBody(3), final_url: null, body_truncated: false },
    control = { status: 401, body: "", final_url: null, body_truncated: false },
    victim = { status: 200, body: victimBody(CANARY_EMAIL), final_url: null, body_truncated: false },
    anonVictim = { status: 401, body: "", final_url: null, body_truncated: false },
  } = opts;
  const bodies = { "ms-attacker": attacker, "ms-control": control, "ms-victim": victim, "ms-anon-victim": anonVictim };
  const calls = { starts: [], fetches: [], closed: 0 };
  const driver = {
    isAvailable: () => available,
    start: async (o) => {
      const hasCookies = Array.isArray(o.authCookies) && o.authCookies.length > 0;
      const isVictimPath = String(o.targetUrl || "").includes("/api/me");
      const sid = isVictimPath ? (hasCookies ? "ms-victim" : "ms-anon-victim") : (hasCookies ? "ms-attacker" : "ms-control");
      calls.starts.push({ sid, hasCookies, targetUrl: o.targetUrl, authCookies: o.authCookies || null });
      return { session_id: sid };
    },
    authedFetch: async (sessionId, fetchArgs) => { calls.fetches.push({ sessionId, fetchArgs }); return bodies[sessionId]; },
    close: async () => { calls.closed += 1; return { closed: true }; },
  };
  return { driver, calls };
}

async function runV2(domain, { driver, victimProfile = "victim", victimSurface = VICTIM_SURFACE_ID } = {}) {
  return massreadConfirm({
    target_domain: domain, surface_id: SURFACE_ID,
    victim_surface_id: victimSurface, victim_auth_profile: victimProfile,
  }, { driver });
}

test("v2 HIGH: victim reads its own private subject, anon is denied it, attacker's bulk read overlaps → signed HIGH", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupV2Session(domain);
  const { driver, calls } = makeV2Driver();
  const result = await runV2(domain, { driver });

  assert.equal(result.confirmed, true, JSON.stringify(result));
  assert.equal(result.cross_tenant_proven, true);
  assert.equal(result.victim_elevation, "cross_principal_break_proven");
  assert.equal(result.demonstrated_severity, "high");
  assert.equal(result.masked_oracle.victim_overlap_count, 1);
  assert.equal(result.masked_oracle.relation.victim_read_own_private_scope, true);
  assert.equal(result.masked_oracle.relation.victim_scope_anon_denied, true);
  assert.equal(result.masked_oracle.relation.attacker_read_victim_subject, true);
  assert.equal(result.masked_oracle.relation.victim_distinct_session, true);
  // Four arms ran (attacker + control + victim + anon-victim), each closed.
  assert.equal(calls.starts.length, 4);
  assert.equal(calls.closed, 4);

  const rows = readOffensiveRunRecords(domain);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].demonstrated_severity, "high");
  assert.equal(rows[0].victim_read_own_private_scope, true);
  assert.equal(rows[0].attacker_read_victim_subject, true);
  assert.equal(rows[0].row_mac.version, 2, "producer-minted rows are the v2 ed25519 envelope");
  assert.ok(verifyRowWithMac(OFFENSIVE_ROW_MAC_CONTEXT, rows[0], resolveOffensiveRowVerifier(domain)), "HIGH row MAC must verify");

  // Masked rail invariant STILL holds with the victim arm: the SIGNED offensive proof (the row + its
  // stdout/stderr captures) never carries the raw overlapping email. (The victim's email legitimately lives
  // in the auth profile store — that is credential storage, not the signed rail — so this checks the
  // offensive-runs artifacts specifically rather than the whole session dir.)
  const runsJsonl = offensiveRunsJsonlPath(domain);
  assert.ok(!fs.readFileSync(runsJsonl, "utf8").includes(CANARY_EMAIL), "the signed offensive row must NOT contain a raw subject value");
  const runsDir = path.join(path.dirname(runsJsonl), "offensive-runs");
  let captureBytes = "";
  for (const f of fs.readdirSync(runsDir)) captureBytes += fs.readFileSync(path.join(runsDir, f), "utf8");
  assert.ok(!captureBytes.includes(CANARY_EMAIL), "the signed offensive captures must NOT contain a raw subject value");
  // #I: the HIGH elevation MAC-covers WHICH victim scope established it (the stderr capture folds into stderr_hash).
  assert.ok(captureBytes.includes(VICTIM_SURFACE_ID), "the signed captures must record the victim surface id");
  assert.ok(captureBytes.includes(`https://${domain}/api/me`), "the signed captures must record the victim canonical target");
}));

test("v2 HIGH round-trip: the HIGH row backs an exploited_safely HIGH claim and re-hashes stable", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupV2Session(domain);
  const { driver } = makeV2Driver();
  const result = await runV2(domain, { driver });
  assert.equal(result.demonstrated_severity, "high");

  const claim = appendCandidateClaim({
    target_domain: domain,
    title: "Cross-tenant BFLA mass-read",
    summary: "An under-authorized identity bulk-read a collection that includes a distinct victim's private records.",
    severity: "high",
    exploit_outcome: { outcome: "exploited_safely", safe_oracle: { kind: "differential_response" } },
    surface_ids: [SURFACE_ID],
    evidence_refs: [{
      kind: "exploit_run", run_id: result.run_id, tool_id: result.tool_id, target: result.target,
      offensive_outcome: "exploited_safely", command_hash: result.command_hash, exit_code: result.exit_code,
      stdout_hash: result.stdout_hash, stderr_hash: result.stderr_hash,
    }],
  });
  assert.equal(claim.severity, "high");
  const row = readOffensiveRunRecords(domain)[0];
  assert.equal(row.demonstrated_severity, "high");
  for (let i = 0; i < 3; i += 1) {
    const observed = projectExploitRunObservedRef(domain, { kind: "exploit_run", run_id: row.run_id });
    assert.equal(observed.stdout_hash, row.stdout_hash, `verify round ${i + 1} re-hash must match`);
  }
}));

test("v2 HIGH: a NESTED victim identifier ({profile:{email}}) is still extracted and overlaps → HIGH", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupV2Session(domain);
  const victim = { status: 200, body: JSON.stringify({ id: 1, profile: { contact: { email: CANARY_EMAIL } } }), final_url: null, body_truncated: false };
  const { driver } = makeV2Driver({ victim });
  const result = await runV2(domain, { driver });
  assert.equal(result.cross_tenant_proven, true);
  assert.equal(result.demonstrated_severity, "high");
}));

test("v2 → MEDIUM: the attacker's bulk read does NOT contain the victim's known identity (no anchored overlap)", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupV2Session(domain);
  // Victim reads its own identity (default victimBody = VICTIM_EMAIL), anon denied — but the attacker's bulk
  // read does not include the victim's known email, so the anchored overlap is empty.
  const attacker = { status: 200, body: JSON.stringify({ data: [{ id: 1, email: "u1@canary.example.test" }, { id: 2, email: "u2@canary.example.test" }] }), final_url: null, body_truncated: false };
  const { driver } = makeV2Driver({ attacker });
  const result = await runV2(domain, { driver });
  assert.equal(result.confirmed, true);
  assert.equal(result.cross_tenant_proven, false);
  assert.equal(result.victim_elevation, "attacker_did_not_read_victim_subject");
  assert.equal(result.demonstrated_severity, "medium");
  assert.equal(readOffensiveRunRecords(domain)[0].demonstrated_severity, "medium");
}));

test("v2 → MEDIUM: the victim arm does NOT read its own known identity (scope is not the victim's /me)", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupV2Session(domain);
  // The victim_surface_id returns a DIFFERENT subject (not the victim's own profile email) — so it is not the
  // victim's own scope. Ownership is anchored to the profile identity, so this is NOT a victim-owned read.
  const victim = { status: 200, body: victimBody("someone-else@canary.example.test"), final_url: null, body_truncated: false };
  const { driver } = makeV2Driver({ victim });
  const result = await runV2(domain, { driver });
  assert.equal(result.cross_tenant_proven, false);
  assert.equal(result.victim_elevation, "victim_did_not_read_own_identity");
  assert.equal(result.demonstrated_severity, "medium");
}));

test("v2 → MEDIUM: anon is NOT denied the victim scope (scope is public, not private)", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupV2Session(domain);
  // anon reads /api/me too (200 with the victim's record) → the scope is not private → no elevation.
  const anonVictim = { status: 200, body: victimBody(CANARY_EMAIL), final_url: null, body_truncated: false };
  const { driver } = makeV2Driver({ anonVictim });
  const result = await runV2(domain, { driver });
  assert.equal(result.cross_tenant_proven, false);
  assert.equal(result.victim_elevation, "victim_scope_anon_not_denied");
  assert.equal(result.demonstrated_severity, "medium");
}));

test("v2 → MEDIUM: victim profile NAME equals the attacker profile (not a distinct principal); victim arms do not run", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupV2Session(domain);
  const { driver, calls } = makeV2Driver();
  const result = await runV2(domain, { driver, victimProfile: "attacker" });
  assert.equal(result.cross_tenant_proven, false);
  assert.equal(result.victim_elevation, "victim_profile_not_distinct");
  assert.equal(result.demonstrated_severity, "medium");
  assert.equal(calls.starts.length, 2, "victim arms must not run when the profile is not distinct");
}));

test("v2 → MEDIUM: victim has an IDENTICAL cookie jar to the attacker (same session, not a distinct principal)", () => withTempHome(async () => {
  const domain = uniqueDomain();
  // Distinct profile NAMES but the same cookie value → same session → declines.
  setupV2Session(domain, { victimCookies: { sid: "leaked-session-token" } });
  const { driver, calls } = makeV2Driver();
  const result = await runV2(domain, { driver });
  assert.equal(result.cross_tenant_proven, false);
  assert.equal(result.victim_elevation, "victim_session_not_distinct");
  assert.equal(result.demonstrated_severity, "medium");
  assert.equal(calls.starts.length, 2, "victim arms must not run when the session is not distinct");
}));

test("v2 → MEDIUM: victim auth profile not found", () => withTempHome(async () => {
  const domain = uniqueDomain();
  // Seed only the attacker profile (no "victim" profile).
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/`, block_internal_hosts: false }));
  seedV2Surfaces(domain);
  ensureHandoffSigningKey(domain);
  authStore({ target_domain: domain, profile_name: "attacker", cookies: { sid: "leaked-session-token" } });
  const { driver, calls } = makeV2Driver();
  const result = await runV2(domain, { driver });
  assert.equal(result.cross_tenant_proven, false);
  assert.equal(result.victim_elevation, "victim_auth_profile_not_found");
  assert.equal(result.demonstrated_severity, "medium");
  assert.equal(calls.starts.length, 2);
}));

test("v2 → MEDIUM: a WAF/throttle on the victim arm leaves the proven MEDIUM intact", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupV2Session(domain);
  const victim = { status: 429, body: "", final_url: null, body_truncated: false };
  const { driver } = makeV2Driver({ victim });
  const result = await runV2(domain, { driver });
  assert.equal(result.cross_tenant_proven, false);
  assert.equal(result.victim_elevation, "victim_arm_waf_or_rate_limit");
  assert.equal(result.demonstrated_severity, "medium");
  assert.equal(readOffensiveRunRecords(domain)[0].demonstrated_severity, "medium");
}));

test("v2 → MEDIUM: an unroutable victim_surface_id is caught and never fails the proven MEDIUM run", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupV2Session(domain);
  const { driver } = makeV2Driver();
  const result = await runV2(domain, { driver, victimSurface: "surface:does-not-exist" });
  assert.equal(result.confirmed, true);
  assert.equal(result.cross_tenant_proven, false);
  assert.equal(result.victim_elevation, "victim_arm_error");
  assert.equal(result.demonstrated_severity, "medium");
}));

test("v1 (victim absent): cross_tenant_proven false, not_requested, two arms, MEDIUM (unchanged)", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  const { driver, calls } = makeDriver();
  const result = await run(domain, { driver });
  assert.equal(result.cross_tenant_proven, false);
  assert.equal(result.victim_elevation, "not_requested");
  assert.equal(result.demonstrated_severity, "medium");
  assert.equal(calls.starts.length, 2);
}));

// ── v2 victim-arm soundness fixes (pre-merge bot review) ──

test("v2 → MEDIUM (#A): a SHARED session cookie plus an incidental cookie still declines (no full-jar-equality bypass)", () => withTempHome(async () => {
  const domain = uniqueDomain();
  // The exact bot finding: attacker {sid:TOK}, victim {sid:TOK, csrf:Z}. The jars are UNEQUAL but share the
  // SAME session token — the same principal. Token-value distinctness fails closed (the old full-set
  // equality would have permitted HIGH here).
  setupV2Session(domain, { attackerCookies: { sid: "shared-session-tok-XYZ" }, victimCookies: { sid: "shared-session-tok-XYZ", csrf: "Z" } });
  const { driver, calls } = makeV2Driver();
  const result = await runV2(domain, { driver });
  assert.equal(result.cross_tenant_proven, false);
  assert.equal(result.victim_elevation, "victim_session_not_distinct");
  assert.equal(result.demonstrated_severity, "medium");
  assert.equal(calls.starts.length, 2, "victim arms must not run on a shared session cookie");
}));

test("v2 → MEDIUM (#B): a non-synthetic victim (no KNOWN identity) cannot anchor ownership", () => withTempHome(async () => {
  const domain = uniqueDomain();
  // The victim profile has no synthetic provenance, so no profile.email → ownership cannot be anchored to a
  // known identity, so the response-inferred path is refused.
  setupV2Session(domain, { victimSynthetic: false });
  const { driver, calls } = makeV2Driver();
  const result = await runV2(domain, { driver });
  assert.equal(result.cross_tenant_proven, false);
  assert.equal(result.victim_elevation, "victim_profile_no_synthetic_identity");
  assert.equal(result.demonstrated_severity, "medium");
  assert.equal(calls.starts.length, 2, "victim arms must not run without a known victim identity");
}));

test("v2 → MEDIUM (#C): victim_surface_id equal to the bulk listing is refused (own-scope must differ)", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupV2Session(domain);
  const { driver, calls } = makeV2Driver();
  const result = await runV2(domain, { driver, victimSurface: SURFACE_ID });
  assert.equal(result.cross_tenant_proven, false);
  assert.equal(result.victim_elevation, "victim_surface_equals_listing");
  assert.equal(result.demonstrated_severity, "medium");
  assert.equal(calls.starts.length, 2, "a replayed listing surface must not run the victim arms");
}));

test("v2 → MEDIUM (#F): an anon denial that LEAKS the victim identity in unstructured text is not 'private'", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupV2Session(domain);
  // 401 with the victim's email in free text — controlReadsAnyPii (>= MIN) and field-bound scans both miss
  // a single unstructured value, so the arm is scored "denied"; the raw-text identity scan catches it.
  const anonVictim = { status: 401, body: `login required for ${CANARY_EMAIL}`, final_url: null, body_truncated: false };
  const { driver } = makeV2Driver({ anonVictim });
  const result = await runV2(domain, { driver });
  assert.equal(result.cross_tenant_proven, false);
  assert.equal(result.victim_elevation, "victim_identity_visible_to_anon");
  assert.equal(result.demonstrated_severity, "medium");
}));

test("sign guard (#G): buildAndSignOffensiveRow with requireExplicitSeverity THROWS when the override is omitted", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain); // seeds session + signing key
  const { buildAndSignOffensiveRow } = require("../mcp/domains/web/offensive-capture-writer.js");
  assert.throws(() => buildAndSignOffensiveRow(domain, {
    runIdPrefix: "massread", toolId: TOOL_ID, method: "GET",
    canonicalTarget: `https://${domain}/api/listing`, surfaceId: SURFACE_ID,
    identityTag: "massread-attacker", stdoutContent: "{}", stderrContent: "{}",
    relationBooleans: {}, requireExplicitSeverity: true, // no demonstratedSeverityOverride → fail closed
  }), /requires an explicit demonstratedSeverityOverride/);
  assert.ok(!fs.existsSync(offensiveRunsJsonlPath(domain)), "no row may be written when the guard throws");
}));

test("v2 → MEDIUM (#H): a DIFFERENT victim_surface_id that RESOLVES to the listing endpoint is refused (alias replay)", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupV2Session(domain);
  const { driver, calls } = makeV2Driver();
  // The alias surface id differs from SURFACE_ID but routes to the SAME /api/listing endpoint.
  const result = await runV2(domain, { driver, victimSurface: VICTIM_ALIAS_SURFACE_ID });
  assert.equal(result.cross_tenant_proven, false);
  assert.equal(result.victim_elevation, "victim_endpoint_equals_listing");
  assert.equal(result.demonstrated_severity, "medium");
  assert.equal(calls.starts.length, 2, "an aliased listing endpoint must not run the victim arms");
}));

test("v2 → MEDIUM (#J): the SAME session token under a DIFFERENT cookie name is not 'distinct'", () => withTempHome(async () => {
  const domain = uniqueDomain();
  // Same opaque session-token VALUE (>= 16 chars), different cookie NAME → same session, must decline.
  const token = "abc123def456ghi789jkl"; // 21 chars
  setupV2Session(domain, { attackerCookies: { sid: token }, victimCookies: { session_token: token } });
  const { driver, calls } = makeV2Driver();
  const result = await runV2(domain, { driver });
  assert.equal(result.cross_tenant_proven, false);
  assert.equal(result.victim_elevation, "victim_session_not_distinct");
  assert.equal(result.demonstrated_severity, "medium");
  assert.equal(calls.starts.length, 2, "a reused session token under a different name must not run the victim arms");
}));

test("v2 → MEDIUM (#L): a multi-subject victim scope (org/team listing incl. the victim) is not the victim's own /me", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupV2Session(domain);
  // The victim_surface_id returns the victim's email AMONG OTHER subjects (a private org-members page the
  // victim can access). The known email appears, anon is denied, and the attacker reads it — but the scope
  // is multi-subject, so the victim does not OWN it: must decline rather than sign victim_read_own_private_scope.
  const victim = { status: 200, body: JSON.stringify({ data: [
    { id: 1, email: CANARY_EMAIL }, { id: 2, email: "teammate1@canary.example.test" }, { id: 3, email: "teammate2@canary.example.test" },
  ] }), final_url: null, body_truncated: false };
  const { driver } = makeV2Driver({ victim });
  const result = await runV2(domain, { driver });
  assert.equal(result.cross_tenant_proven, false);
  assert.equal(result.victim_elevation, "victim_scope_multi_subject");
  assert.equal(result.demonstrated_severity, "medium");
}));

test("v2 HIGH: a /me carrying MULTIPLE identifier shapes for ONE person (email+ssn) is single-subject (distinct-subject count, not key-count)", () => withTempHome(async () => {
  // LIVE-VALIDATION regression: the single-subject gate counts distinct SUBJECTS (max distinct values per
  // subject shape), NOT distinct identifier KEYS. One person's /me carries several shapes (email AND ssn) → a
  // key-count saw 2 and wrongly declined "victim_scope_multi_subject"; distinctSubjectCount sees 1 (one email,
  // one ssn) → the victim's own /me. (Found by the first live fire; all prior unit tests used email-only bodies.)
  const domain = uniqueDomain();
  setupV2Session(domain);
  const victim = { status: 200, body: JSON.stringify({ id: 1, email: CANARY_EMAIL, ssn: "111-22-9000", phone: "+1-202-555-0150" }), final_url: null, body_truncated: false };
  const { driver } = makeV2Driver({ victim });
  const result = await runV2(domain, { driver });
  assert.equal(result.cross_tenant_proven, true, JSON.stringify(result));
  assert.equal(result.victim_elevation, "cross_principal_break_proven");
  assert.equal(result.demonstrated_severity, "high");
}));

test("v2 → MEDIUM (#M): a singleton WRAPPER around a multi-subject collection (unrecognized key) is NOT single-subject", () => withTempHome(async () => {
  // {members:[{email:victim},{email:other}]} — `members` isn't a recognized collection key, so a record-count
  // would see ONE top-level object and falsely pass. distinctSubjectCount sees 2 distinct EMAILS → rejected.
  const domain = uniqueDomain();
  setupV2Session(domain);
  const victim = { status: 200, body: JSON.stringify({ team_id: 7, members: [{ email: CANARY_EMAIL }, { email: "teammate@canary.example.test" }] }), final_url: null, body_truncated: false };
  const { driver } = makeV2Driver({ victim });
  const result = await runV2(domain, { driver });
  assert.equal(result.cross_tenant_proven, false);
  assert.equal(result.victim_elevation, "victim_scope_multi_subject");
  assert.equal(result.demonstrated_severity, "medium");
}));

test("v2 → MEDIUM (CodeRabbit): an OBJECT-MAP of multiple subjects (no array) is NOT single-subject", () => withTempHome(async () => {
  // {user1:{email:victim}, user2:{email:other}} — an object map, not an array; a record-count of top-level
  // objects would pass. distinctSubjectCount sees 2 distinct emails → rejected.
  const domain = uniqueDomain();
  setupV2Session(domain);
  const victim = { status: 200, body: JSON.stringify({ user1: { email: CANARY_EMAIL }, user2: { email: "other@canary.example.test" } }), final_url: null, body_truncated: false };
  const { driver } = makeV2Driver({ victim });
  const result = await runV2(domain, { driver });
  assert.equal(result.cross_tenant_proven, false);
  assert.equal(result.victim_elevation, "victim_scope_multi_subject");
  assert.equal(result.demonstrated_severity, "medium");
}));

test("v2 HIGH (#N): a /me with a SELF-OWNED child collection (no extra subjects) stays single-subject", () => withTempHome(async () => {
  // {email:victim, items:[...]} — `items` IS a recognized collection key, so a record-count would return the
  // child length and falsely decline. The child items carry NO subject identifiers → distinctSubjectCount 1 → HIGH.
  const domain = uniqueDomain();
  setupV2Session(domain);
  const victim = { status: 200, body: JSON.stringify({ id: 1, email: CANARY_EMAIL, items: [{ sku: "A1", qty: 2 }, { sku: "B2", qty: 1 }, { sku: "C3", qty: 5 }] }), final_url: null, body_truncated: false };
  const { driver } = makeV2Driver({ victim });
  const result = await runV2(domain, { driver });
  assert.equal(result.cross_tenant_proven, true, JSON.stringify(result));
  assert.equal(result.demonstrated_severity, "high");
}));

test("v2 → MEDIUM (Codex P1): a MIXED-SHAPE multi-subject scope ({email:victim}+{ssn:other}) is NOT single-subject", () => withTempHome(async () => {
  // Two DIFFERENT people exposing DISJOINT identifier shapes — the victim as {email} and a second subject as
  // {ssn}. The prior max-per-shape count saw max(1 email, 1 ssn) = 1 and FALSELY passed the single-subject gate
  // → a signed HIGH on a 2-person listing. Object-node grouping sees two separate subject nodes → 2 → rejected.
  // (Contrast the flat email+ssn /me test above: ONE person's email+ssn are siblings of one node → 1 → HIGH.)
  const domain = uniqueDomain();
  setupV2Session(domain);
  const victim = { status: 200, body: JSON.stringify({ members: [{ email: CANARY_EMAIL }, { ssn: "987-65-4321" }] }), final_url: null, body_truncated: false };
  const { driver } = makeV2Driver({ victim });
  const result = await runV2(domain, { driver });
  assert.equal(result.cross_tenant_proven, false, JSON.stringify(result));
  assert.equal(result.victim_elevation, "victim_scope_multi_subject");
  assert.equal(result.demonstrated_severity, "medium");
}));

test("v2 → MEDIUM (Codex P1): the attacker overlap is RECORD-bound — a victim email in response METADATA does not count", () => withTempHome(async () => {
  // The victim's known email appears ONLY in a top-level metadata field (requested_by_email), not in any bulk
  // RECORD the attacker read; the attacker read only OTHER subjects' rows. Whole-body matching would falsely
  // satisfy the overlap and sign attacker_read_victim_subject HIGH; record-bound matching scans only the `data`
  // rows → no overlap → stays MEDIUM.
  const domain = uniqueDomain();
  setupV2Session(domain);
  const attacker = { status: 200, body: JSON.stringify({ requested_by_email: CANARY_EMAIL, data: [{ id: 1, email: "other1@canary.example.test" }, { id: 2, email: "other2@canary.example.test" }] }), final_url: null, body_truncated: false };
  const { driver } = makeV2Driver({ attacker });
  const result = await runV2(domain, { driver });
  assert.equal(result.confirmed, true, JSON.stringify(result));
  assert.equal(result.cross_tenant_proven, false);
  assert.equal(result.victim_elevation, "attacker_did_not_read_victim_subject");
  assert.equal(result.demonstrated_severity, "medium");
}));

test("v2 → MEDIUM (Codex P1): two DIFFERENT people in SIBLING fields of ONE object ({email:victim,teammate_email:other}) is NOT single-subject", () => withTempHome(async () => {
  // A single object whose sibling sensitive fields name TWO people — the victim's `email` and another subject's
  // `teammate_email`. Object-node UNION (round-2) collapsed both same-shape identifiers into one subject → false
  // HIGH; per-node MAX-over-shape counts 2 distinct emails in the node → 2 → rejected.
  const domain = uniqueDomain();
  setupV2Session(domain);
  const victim = { status: 200, body: JSON.stringify({ id: 1, email: CANARY_EMAIL, teammate_email: "teammate@canary.example.test" }), final_url: null, body_truncated: false };
  const { driver } = makeV2Driver({ victim });
  const result = await runV2(domain, { driver });
  assert.equal(result.cross_tenant_proven, false, JSON.stringify(result));
  assert.equal(result.victim_elevation, "victim_scope_multi_subject");
  assert.equal(result.demonstrated_severity, "medium");
}));

test("v2 → MEDIUM (Codex P1): another subject's identifier in a NON-SCALAR sensitive field ({email:victim,secondary_email:[other]}) is counted", () => withTempHome(async () => {
  // The victim's own scalar `email` plus a SECOND subject under a sensitively-named ARRAY field. The scalar-only
  // gate (round-2) skipped the array entirely → counted 1 → false HIGH; serialize-extracting the container under
  // max-per-shape sees 2 distinct emails in the node → 2 → rejected.
  const domain = uniqueDomain();
  setupV2Session(domain);
  const victim = { status: 200, body: JSON.stringify({ id: 1, email: CANARY_EMAIL, secondary_email: ["other-subject@canary.example.test"] }), final_url: null, body_truncated: false };
  const { driver } = makeV2Driver({ victim });
  const result = await runV2(domain, { driver });
  assert.equal(result.cross_tenant_proven, false, JSON.stringify(result));
  assert.equal(result.victim_elevation, "victim_scope_multi_subject");
  assert.equal(result.demonstrated_severity, "medium");
}));

test("v2 → MEDIUM (Codex P1/CodeRabbit): the victim only as IN-ROW METADATA (viewer_email constant across records) is not the row's subject", () => withTempHome(async () => {
  // The attacker's bulk rows are about OTHER subjects (`email` varies: other1/2/3). The victim's email sits only
  // in `viewer_email`, CONSTANT across the rows that carry it — it names who is viewing, not a row's subject.
  // Subject-binding (cross-record variance + field-consistency): the victim is not a value of any VARYING
  // subject field → no overlap → MEDIUM (a record-bound any-sensitive-field match would have falsely signed
  // HIGH). The third row (no viewer_email) keeps base distinct subjects >= MIN despite the shared metadata value.
  const domain = uniqueDomain();
  setupV2Session(domain);
  const attacker = { status: 200, body: JSON.stringify({ data: [
    { id: 1, email: "other1@canary.example.test", viewer_email: CANARY_EMAIL },
    { id: 2, email: "other2@canary.example.test", viewer_email: CANARY_EMAIL },
    { id: 3, email: "other3@canary.example.test" },
  ] }), final_url: null, body_truncated: false };
  const { driver } = makeV2Driver({ attacker });
  const result = await runV2(domain, { driver });
  assert.equal(result.confirmed, true, JSON.stringify(result));
  assert.equal(result.cross_tenant_proven, false);
  assert.equal(result.victim_elevation, "attacker_did_not_read_victim_subject");
  assert.equal(result.demonstrated_severity, "medium");
}));

test("v2 → MEDIUM (Codex P1): a VARYING relational-metadata field (manager_email) is not a subject field — the victim as a manager does not overlap", () => withTempHome(async () => {
  // `manager_email` VARIES per row (different managers), so a variance-only test would treat it as a subject
  // field and sign HIGH if the victim is one manager. Field-consistency rejects it: the victim's own /me carries
  // its identity under `email`, not `manager_email`, so a match under `manager_email` is metadata, not the row's
  // subject. The victim is NOT in the `email` (real subject) values → no overlap → MEDIUM.
  const domain = uniqueDomain();
  setupV2Session(domain);
  const attacker = { status: 200, body: JSON.stringify({ data: [
    { id: 1, email: "other1@canary.example.test", manager_email: CANARY_EMAIL },
    { id: 2, email: "other2@canary.example.test", manager_email: "boss2@canary.example.test" },
  ] }), final_url: null, body_truncated: false };
  const { driver } = makeV2Driver({ attacker });
  const result = await runV2(domain, { driver });
  assert.equal(result.confirmed, true, JSON.stringify(result));
  assert.equal(result.cross_tenant_proven, false);
  assert.equal(result.victim_elevation, "attacker_did_not_read_victim_subject");
  assert.equal(result.demonstrated_severity, "medium");
}));

test("v2 HIGH still mints when the two sessions share only a SHORT benign cookie (no over-decline)", () => withTempHome(async () => {
  const domain = uniqueDomain();
  // Distinct long session tokens, but both jars carry the same short benign cookie (locale=en) — that must
  // NOT be read as a shared session (it would gut the feature), so HIGH still mints.
  setupV2Session(domain, {
    attackerCookies: { sid: "attacker-session-token-AAA", locale: "en" },
    victimCookies: { sid: "victim-session-token-BBBBB", locale: "en" },
  });
  const { driver } = makeV2Driver();
  const result = await runV2(domain, { driver });
  assert.equal(result.cross_tenant_proven, true, JSON.stringify(result));
  assert.equal(result.demonstrated_severity, "high");
}));
