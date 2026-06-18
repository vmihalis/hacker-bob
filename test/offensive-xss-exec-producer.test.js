"use strict";

// SEEDED test matrix for the bob_http_xss_confirm browser-EXECUTION reflected-XSS
// CONFIRM signed-row PRODUCER (the FIRST HIGH-ceiling signed producer).
//
// Every navigation goes through an INJECTED `driver` seam (no Chromium): a fake
// driver simulates a page by returning, on the read-only `evaluate`, the
// nonce-keyed marker a real executing payload would set. The positive fires ONLY
// on the deterministic differential — marker ABSENT on the control page AND marker
// === the server-minted nonce on the probe page. The surface + a query-bearing
// recorded endpoint are seeded directly.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const PRODUCER_PATH = path.join(__dirname, "..", "mcp", "lib", "offensive-xss-exec-producer.js");
const {
  confirmXssExecution,
  XSS_EXEC_DEMONSTRATED_CEILING,
} = require("../mcp/lib/offensive-xss-exec-producer.js");
const { initSession } = require("../mcp/lib/session-state.js");
const { routeSurfaces } = require("../mcp/lib/surface-router.js");
const { ensureHandoffSigningKey } = require("../mcp/lib/handoff-signing-key.js");
const { attackSurfacePath, offensiveRunsJsonlPath } = require("../mcp/lib/paths.js");
const {
  appendCandidateClaim,
  readCandidateClaims,
  readOffensiveRunRecords,
  canonicalizeExploitTarget,
} = require("../mcp/lib/claims.js");
const { verifyOffensiveRunRowMac } = require("../mcp/lib/offensive-row-mac.js");
const { projectExploitRunObservedRef } = require("../mcp/lib/claim-freeze.js");
const {
  resetForTests: resetMaterializationDebounce,
} = require("../mcp/lib/frontier-materialize-debounce.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-xss-exec-producer-"));
  process.env.HOME = home;
  return Promise.resolve()
    .then(() => fn(home))
    .finally(() => {
      if (previousHome === undefined) delete process.env.HOME;
      else process.env.HOME = previousHome;
      resetMaterializationDebounce();
      fs.rmSync(home, { recursive: true, force: true });
    });
}

const SURFACE_ID = "surface:search";
const LOCUS = "q";

function seedRoutedSurface(domain, { endpoint, hosts, endpoints } = {}) {
  fs.mkdirSync(path.dirname(attackSurfacePath(domain)), { recursive: true });
  fs.writeFileSync(attackSurfacePath(domain), `${JSON.stringify({
    surfaces: [{
      id: SURFACE_ID,
      title: "Synthetic reflected-search surface",
      surface_type: "web",
      hosts: hosts || [domain],
      endpoints: endpoints || [endpoint || `https://${domain}/search?${LOCUS}=test`],
      tech_stack: ["fixture"],
      priority: "HIGH",
    }],
  }, null, 2)}\n`, "utf8");
  JSON.parse(routeSurfaces({ target_domain: domain }));
}

function setupSession(domain, opts = {}) {
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/` }));
  seedRoutedSurface(domain, opts);
  ensureHandoffSigningKey(domain);
}

function baseArgs(domain, overrides = {}) {
  return {
    target_domain: domain,
    surface_id: SURFACE_ID,
    param_locus: "0",
    oracle_kind: "script_execution",
    ...overrides,
  };
}

// A fake browser driver. It simulates a page by deciding control-vs-probe from the
// last navigated URL (the probe URL carries the "><svg onload=…> payload) and, for
// the probe, returns the nonce-keyed marker value the executing payload would set
// (the nonce is recovered from the read-back expression `window["__bobxe_<nonce>"]`).
function makeDriver(opts = {}) {
  const {
    available = true,
    vulnerable = true,
    controlMarker = null,
    wafStatus = null,
    navError = null,
    startReturnsNoSession = false,
    finalUrl = null,
  } = opts;
  const calls = { started: 0, navigate: [], evaluate: [], closed: false };
  let lastUrl = null;
  return {
    calls,
    isAvailable: () => available,
    start: async () => { calls.started += 1; return startReturnsNoSession ? {} : { session_id: "bs-xss-test" }; },
    navigate: async (_sessionId, url) => {
      lastUrl = url;
      calls.navigate.push(url);
      if (navError) throw navError;
      return { status: wafStatus || 200, final_url: finalUrl || url };
    },
    evaluate: async (_sessionId, expression) => {
      calls.evaluate.push(expression);
      const decoded = decodeURIComponent(lastUrl || "");
      const isProbe = /<svg/i.test(decoded);
      if (!isProbe) return { result: controlMarker };
      const m = /__bobxe_(bxe[0-9a-f]{32})/.exec(expression);
      return { result: vulnerable ? (m ? m[1] : null) : null };
    },
    close: async () => { calls.closed = true; return { closed: true }; },
  };
}

async function run(domain, { driver, args } = {}) {
  return confirmXssExecution(args || baseArgs(domain), { driver: driver || makeDriver() });
}

// ───────────────────────── wiring / invariants ──────────────────────────

test("XSS_EXEC ceiling is a frozen hard HIGH", () => {
  assert.equal(XSS_EXEC_DEMONSTRATED_CEILING.script_execution, "high");
  assert.equal(Object.isFrozen(XSS_EXEC_DEMONSTRATED_CEILING), true);
});

test("buildAndSignOffensiveRow is NOT re-exported (no gate-bypassing signed-row path)", () => {
  const mod = require("../mcp/lib/offensive-xss-exec-producer.js");
  assert.equal(typeof mod.buildAndSignOffensiveRow, "undefined");
});

test("the producer drives the browser subsystem in-process (no spawn of its own)", () => {
  // Unlike the reflect finder, this producer legitimately uses the established
  // subprocess-backed browser subsystem via browser-tools-shared — it must NOT
  // spawn its own child_process directly.
  const src = fs.readFileSync(PRODUCER_PATH, "utf8");
  assert.ok(!/require\(\s*['"]child_process['"]\s*\)/.test(src), "must not require child_process directly");
});

// ───────────────────────── positive (signs HIGH) ──────────────────────────

test("positive: benign marker executes in the browser → signed HIGH row", () => withTempHome(async () => {
  const domain = "xss-exec-positive.example.test";
  setupSession(domain);
  const driver = makeDriver();
  const result = await run(domain, { driver });

  assert.equal(result.confirmed, true, JSON.stringify(result));
  assert.equal(result.row_written, true);
  assert.equal(result.offensive_outcome, "exploited_safely");
  assert.equal(result.demonstrated_severity, "high");
  assert.equal(result.tool_id, "bob_http_xss_confirm");
  assert.equal(result.surface_id, SURFACE_ID);
  assert.equal(result.masked_oracle.param, LOCUS);
  assert.equal(result.masked_oracle.oracle, "script_execution");

  // Two audited navigations (control + probe) and the session is always closed.
  assert.equal(driver.calls.navigate.length, 2);
  assert.equal(driver.calls.closed, true);

  const rows = readOffensiveRunRecords(domain);
  assert.equal(rows.length, 1);
  const row = rows[0];
  assert.equal(row.demonstrated_severity, "high");
  assert.equal(row.surface_id, SURFACE_ID);
  assert.equal(row.tool_id, "bob_http_xss_confirm");
  assert.equal(row.offensive_outcome, "exploited_safely");
  assert.equal(row.dry_run, false);
  assert.equal(row.timed_out, false);
  // value-blind target: query stripped to origin+path.
  assert.equal(row.target, `https://${domain}/search`);
  assert.equal(row.target, canonicalizeExploitTarget(`https://${domain}/search?${LOCUS}=x`));
  // well-formed + MAC-valid.
  assert.ok(row.row_mac && row.row_mac.digest, "row must be MAC-signed");
  assert.equal(verifyOffensiveRunRowMac(row, ensureHandoffSigningKey(domain)), true, "row MAC must verify");
  for (const h of ["command_hash", "stdout_hash", "stderr_hash"]) {
    assert.match(result[h], /^[0-9a-f]{64}$/);
    assert.equal(result[h], row[h]);
  }
  // capture file on disk re-hashes to the row's stdout_hash (freeze re-hash path).
  const observed = projectExploitRunObservedRef(domain, { kind: "exploit_run", run_id: row.run_id });
  assert.equal(observed.stdout_hash, row.stdout_hash);
}));

test("host binding: a relative endpoint on a subdomain surface signs the SUBDOMAIN target", () => withTempHome(async () => {
  const domain = "xss-exec-hostbind.example.test";
  setupSession(domain, { hosts: [`api.${domain}`], endpoints: [`/search?${LOCUS}=test`] });
  const result = await run(domain);
  assert.equal(result.confirmed, true, JSON.stringify(result));
  const rows = readOffensiveRunRecords(domain);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].target, `https://api.${domain}/search`);
}));

// ───────────────────────── negative matrix (sign nothing) ──────────────────────────

test("negative: payload does NOT execute (escaped/sanitized) → script_did_not_execute, session closed", () => withTempHome(async () => {
  const domain = "xss-exec-neg-noexec.example.test";
  setupSession(domain);
  const driver = makeDriver({ vulnerable: false });
  const result = await run(domain, { driver });
  assert.equal(result.confirmed, false, JSON.stringify(result));
  assert.equal(result.reason, "script_did_not_execute");
  assert.equal(result.row_written, false);
  assert.equal(driver.calls.closed, true, "session must close even on a fail-closed path");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("negative: control marker already present (page default) → control_marker_present", () => withTempHome(async () => {
  const domain = "xss-exec-neg-control.example.test";
  setupSession(domain);
  // Control returns a non-null marker → not a clean differential.
  const result = await run(domain, { driver: makeDriver({ controlMarker: "preexisting" }) });
  assert.equal(result.confirmed, false, JSON.stringify(result));
  assert.equal(result.reason, "control_marker_present");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("negative: an off-origin redirect (final_url leaves the surface) → redirect_off_surface, session closed", () => withTempHome(async () => {
  const domain = "xss-exec-neg-redirect.example.test";
  setupSession(domain);
  // The navigation succeeds (200) but the page ends on a different origin — the
  // marker must not be attributed to this surface; fail closed before reading it.
  const driver = makeDriver({ finalUrl: "https://evil.example.test/landing" });
  const result = await run(domain, { driver });
  assert.equal(result.confirmed, false, JSON.stringify(result));
  assert.equal(result.reason, "redirect_off_surface");
  assert.equal(result.row_written, false);
  assert.equal(driver.calls.closed, true);
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("negative: WAF status on navigation → waf_or_rate_limit", () => withTempHome(async () => {
  const domain = "xss-exec-neg-waf.example.test";
  setupSession(domain);
  const result = await run(domain, { driver: makeDriver({ wafStatus: 429 }) });
  assert.equal(result.confirmed, false, JSON.stringify(result));
  assert.equal(result.reason, "waf_or_rate_limit");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("negative: a navigation transport error → browser_error, session closed", () => withTempHome(async () => {
  const domain = "xss-exec-neg-naverr.example.test";
  setupSession(domain);
  const driver = makeDriver({ navError: new Error("net::ERR_CONNECTION_REFUSED") });
  const result = await run(domain, { driver });
  assert.equal(result.confirmed, false, JSON.stringify(result));
  assert.equal(result.reason, "browser_error");
  assert.equal(driver.calls.closed, true);
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("negative: no browser available → browser_unavailable, no session started", () => withTempHome(async () => {
  const domain = "xss-exec-neg-nobrowser.example.test";
  setupSession(domain);
  const driver = makeDriver({ available: false });
  const result = await run(domain, { driver });
  assert.equal(result.confirmed, false, JSON.stringify(result));
  assert.equal(result.reason, "browser_unavailable");
  assert.equal(driver.calls.started, 0, "must not start a session when no browser is available");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("ssrf safety: block_internal_hosts on → refuses (fails closed), no session started", () => withTempHome(async () => {
  const domain = "xss-exec-neg-ssrf.example.test";
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/`, block_internal_hosts: true }));
  seedRoutedSurface(domain);
  ensureHandoffSigningKey(domain);
  const driver = makeDriver();
  const result = await confirmXssExecution(baseArgs(domain), { driver });
  assert.equal(result.confirmed, false, JSON.stringify(result));
  assert.equal(result.reason, "block_internal_hosts_unsupported_for_browser");
  assert.equal(driver.calls.started, 0);
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("pii safety: a percent-encoded PII shape in a recorded path segment blocks the signed row", () => withTempHome(async () => {
  const domain = "xss-exec-pii-path.example.test";
  setupSession(domain, { endpoints: [`https://${domain}/u/alice%40corp.com/search?${LOCUS}=test`] });
  const result = await run(domain);
  assert.equal(result.confirmed, false, JSON.stringify(result));
  assert.equal(result.reason, "proof_target_contains_sensitive_value");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

// ───────────────────────── locus + scope safety ──────────────────────────

test("locus safety: a surface with NO recorded query param → no_recorded_query_param", () => withTempHome(async () => {
  const domain = "xss-exec-noquery.example.test";
  setupSession(domain, { endpoint: `https://${domain}/search` });
  const result = await run(domain);
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "no_recorded_query_param");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("locus safety: an action-shaped RECORDED query param (?_method=) is declined before any navigation", () => withTempHome(async () => {
  const domain = "xss-exec-action-param.example.test";
  setupSession(domain, { endpoint: `https://${domain}/search?_method=DELETE&${LOCUS}=test` });
  const driver = makeDriver();
  await assert.rejects(
    () => confirmXssExecution(baseArgs(domain), { driver }),
    /_method|not allowed/i,
  );
  assert.equal(driver.calls.started, 0, "no session may start when the recorded param is action-shaped");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("locus safety: param_locus ordinal out of range is rejected", () => withTempHome(async () => {
  const domain = "xss-exec-locus-oob.example.test";
  setupSession(domain);
  await assert.rejects(
    () => run(domain, { args: baseArgs(domain, { param_locus: "1" }) }),
    /out of range/i,
  );
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("input safety: raw url / param_value / canary / payload / session_id smuggling fields are rejected", () => withTempHome(async () => {
  const domain = "xss-exec-forbidden-input.example.test";
  setupSession(domain);
  for (const bad of [
    { url: "https://evil.test/x" },
    { param_value: "1" },
    { canary: "x" },
    { param_name: "q" },
    { payload: "<svg onload=alert(1)>" },
    { session_id: "bs-attacker" },
  ]) {
    await assert.rejects(
      () => confirmXssExecution(baseArgs(domain, bad), { driver: makeDriver() }),
      /does not accept/i,
      `must reject smuggling field ${Object.keys(bad)[0]}`,
    );
  }
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

// ───────────────────────── round-trip: record HIGH → freeze re-hash → ceiling ──────────────────────────

function exploitRunRefFrom(result) {
  return {
    kind: "exploit_run",
    run_id: result.run_id,
    tool_id: result.tool_id,
    target: result.target,
    offensive_outcome: "exploited_safely",
    command_hash: result.command_hash,
    exit_code: result.exit_code,
    stdout_hash: result.stdout_hash,
    stderr_hash: result.stderr_hash,
  };
}

test("round-trip: the minted row backs an exploited_safely claim at HIGH, then re-hashes at freeze", () => withTempHome(async () => {
  const domain = "xss-exec-roundtrip.example.test";
  setupSession(domain);
  const result = await run(domain);
  assert.equal(result.confirmed, true, JSON.stringify(result));

  const claim = appendCandidateClaim({
    target_domain: domain,
    title: "Reflected XSS proven by browser execution",
    summary: "A benign nonce-keyed marker executed in a real browser engine via a reflected query param.",
    severity: "high",
    exploit_outcome: { outcome: "exploited_safely", safe_oracle: { kind: "reflected_canary" } },
    surface_ids: [SURFACE_ID],
    evidence_refs: [exploitRunRefFrom(result)],
  });
  assert.equal(claim.exploit_outcome.outcome, "exploited_safely");
  assert.equal(claim.severity, "high");

  const [readBack] = readCandidateClaims(domain);
  assert.equal(readBack.claim_hash, claim.claim_hash);

  const row = readOffensiveRunRecords(domain)[0];
  for (let i = 0; i < 3; i += 1) {
    const observed = projectExploitRunObservedRef(domain, { kind: "exploit_run", run_id: row.run_id });
    assert.equal(observed.stdout_hash, row.stdout_hash, `verify round ${i + 1} re-hash must match`);
  }
}));

test("round-trip: a claim severity ABOVE the high ceiling (critical) is rejected", () => withTempHome(async () => {
  const domain = "xss-exec-ceiling.example.test";
  setupSession(domain);
  const result = await run(domain);
  assert.equal(result.confirmed, true);
  let caught;
  try {
    appendCandidateClaim({
      target_domain: domain,
      title: "Over-severity claim",
      summary: "Attempts to claim critical from a high browser-execution XSS row.",
      severity: "critical",
      exploit_outcome: { outcome: "exploited_safely", safe_oracle: { kind: "reflected_canary" } },
      surface_ids: [SURFACE_ID],
      evidence_refs: [exploitRunRefFrom(result)],
    });
  } catch (error) { caught = error; }
  assert.ok(caught, "over-severity must be rejected");
  assert.equal(caught.details.code, "exploit_proof_severity_exceeds_demonstrated");
}));
