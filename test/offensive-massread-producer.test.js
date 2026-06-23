"use strict";

// bob_http_massread_confirm — broken-auth / BFLA mass-read producer.
// Seeded `driver` (no Chromium) + a stored attacker auth profile drive the attacker-vs-control
// differential. Asserts: signs HIGH only on the real differential; the signed rail is masked
// (NO raw PII) and MAC-valid; the negatives fail closed; the operator env gate alone enables the
// full raw capture; a minted row backs an exploited_safely HIGH claim.

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
} = require("../mcp/lib/offensive-massread-producer.js");
const { initSession } = require("../mcp/lib/session-state.js");
const { authStore } = require("../mcp/lib/auth.js");
const { routeSurfaces } = require("../mcp/lib/surface-router.js");
const { ensureHandoffSigningKey } = require("../mcp/lib/handoff-signing-key.js");
const { attackSurfacePath, offensiveRunsJsonlPath, sessionDir } = require("../mcp/lib/paths.js");
const { appendCandidateClaim, readOffensiveRunRecords } = require("../mcp/lib/claims.js");
const { verifyOffensiveRunRowMac } = require("../mcp/lib/offensive-row-mac.js");
const { projectExploitRunObservedRef } = require("../mcp/lib/claim-freeze.js");
const { resetForTests: resetMaterializationDebounce } = require("../mcp/lib/frontier-materialize-debounce.js");

const PRODUCER_PATH = path.join(__dirname, "..", "mcp", "lib", "offensive-massread-producer.js");
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
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-massread-producer-"));
  process.env.HOME = home;
  return Promise.resolve()
    .then(() => fn(home))
    .finally(() => {
      if (previousHome === undefined) delete process.env.HOME; else process.env.HOME = previousHome;
      if (previousOwner === undefined) delete process.env[OWNER_AUTHORIZED_ENV];
      else process.env[OWNER_AUTHORIZED_ENV] = previousOwner;
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

test("MASSREAD ceiling is a frozen hard HIGH", () => {
  assert.equal(MASSREAD_DEMONSTRATED_CEILING.bob_http_massread_confirm, "high");
  assert.equal(Object.isFrozen(MASSREAD_DEMONSTRATED_CEILING), true);
});

test("buildAndSignOffensiveRow is NOT re-exported (no gate-bypassing signed-row path)", () => {
  const mod = require("../mcp/lib/offensive-massread-producer.js");
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

// ───────────────────────── positive (signs HIGH) ──────────────────────────

test("positive: attacker bulk-reads PII a denied control cannot → signed HIGH masked row", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  const { driver, calls } = makeDriver();
  const result = await run(domain, { driver });

  assert.equal(result.confirmed, true, JSON.stringify(result));
  assert.equal(result.row_written, true);
  assert.equal(result.offensive_outcome, "exploited_safely");
  assert.equal(result.demonstrated_severity, "high");
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
  assert.equal(rows[0].demonstrated_severity, "high");
  assert.equal(verifyOffensiveRunRowMac(rows[0], ensureHandoffSigningKey(domain)), true, "row MAC must verify");

  // The signed rail carries NO raw PII value (only the field-name bucket + booleans).
  const rail = signedRailBytes(domain);
  assert.ok(!rail.includes(CANARY_EMAIL), "signed rail must NOT contain a raw record value");
  assert.ok(rail.includes("email"), "the field-name bucket is recorded (masked)");
}));

test("round-trip: the minted row backs an exploited_safely HIGH claim and re-hashes stable", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  const { driver } = makeDriver();
  const result = await run(domain, { driver });
  assert.equal(result.confirmed, true);

  const claim = appendCandidateClaim({
    target_domain: domain,
    title: "Broken-auth mass-read of a bulk PII collection",
    summary: "An under-authorized identity bulk-read a sensitive collection a denied control cannot.",
    severity: "high",
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
  assert.equal(claim.severity, "high");

  const row = readOffensiveRunRecords(domain)[0];
  for (let i = 0; i < 3; i += 1) {
    const observed = projectExploitRunObservedRef(domain, { kind: "exploit_run", run_id: row.run_id });
    assert.equal(observed.stdout_hash, row.stdout_hash, `verify round ${i + 1} re-hash must match`);
  }
}));

test("a claim severity ABOVE the high ceiling is rejected", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  const { driver } = makeDriver();
  const result = await run(domain, { driver });
  assert.equal(result.confirmed, true);
  assert.throws(() => appendCandidateClaim({
    target_domain: domain,
    title: "over-severity",
    summary: "attempts critical from a high mass-read row",
    severity: "critical",
    exploit_outcome: { outcome: "exploited_safely", safe_oracle: { kind: "differential_response" } },
    surface_ids: [SURFACE_ID],
    evidence_refs: [{
      kind: "exploit_run", run_id: result.run_id, tool_id: result.tool_id, target: result.target,
      offensive_outcome: "exploited_safely", command_hash: result.command_hash, exit_code: result.exit_code,
      stdout_hash: result.stdout_hash, stderr_hash: result.stderr_hash,
    }],
  }));
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
  assertNoRow(domain, result, "blocked_by_design", "control_also_reads_bulk_not_a_privilege_break");
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
  process.env[OWNER_AUTHORIZED_ENV] = "1";
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

// ───────────────────────── soundness hardening (false-HIGH prevention) ──────────────────────────

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
  process.env[OWNER_AUTHORIZED_ENV] = "1";
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

test("FALSE-HIGH closed: a metadata email + benign records does NOT mint (PII is not in a counted record)", () => withTempHome(async () => {
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

test("widened vocab: an SSN mass-read mints HIGH (the former email/phone/iban vocab missed it)", () => withTempHome(async () => {
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

test("widened vocab: a Luhn-valid credit-card mass-read mints HIGH", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  const body = JSON.stringify({ data: [
    { id: 1, card_number: "4111111111111111", name: "A" },
    { id: 2, card_number: "4012888888881881", name: "B" },
  ] });
  const { driver } = makeDriver({ attacker: { status: 200, body, final_url: null, body_truncated: false } });
  const result = await run(domain, { driver });
  assert.equal(result.confirmed, true);
  assert.equal(result.masked_oracle.pii_shape_present.credit_card, true);
  assert.ok(result.masked_oracle.sensitive_field_names.includes("financial"));
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
  assertNoRow(domain, result, "blocked_by_design", "control_also_reads_bulk_not_a_privilege_break");
}));

test("control 2xx that read the bulk collection (no PII shape) is NOT scored denied → public, no mint (#677)", () => withTempHome(async () => {
  const domain = uniqueDomain();
  setupSession(domain);
  // Control 2xx returns >= MIN records but trips no PII shape — it still READ the collection → public.
  const control = { status: 200, body: JSON.stringify({ data: [{ id: 1 }, { id: 2 }, { id: 3 }] }), final_url: null, body_truncated: false };
  const { driver } = makeDriver({ control });
  const result = await run(domain, { driver });
  assertNoRow(domain, result, "blocked_by_design", "control_also_reads_bulk_not_a_privilege_break");
}));
