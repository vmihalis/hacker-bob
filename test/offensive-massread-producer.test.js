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
      calls.starts.push({ isAttacker, targetUrl: o.targetUrl, cookieCount: o.authCookies ? o.authCookies.length : 0 });
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
