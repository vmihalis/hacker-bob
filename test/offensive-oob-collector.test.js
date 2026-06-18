"use strict";

// SEEDED test matrix for the PR6 OOB collector (bob_oob_mint + bob_oob_poll).
//
// No live external callback and no live target: the sink response is supplied
// through an injected interaction_source seam, the env config through an injected
// config seam (loadOobConfig with an explicit env), and the routed surface +
// in-scope endpoint are seeded directly. The positive fires ONLY on an exact
// token-match interaction at Bob's OWN sink; the signed row's target is the
// IN-SCOPE injection endpoint resolved at mint, NEVER the constant OOB host.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const COLLECTOR_PATH = path.join(__dirname, "..", "mcp", "lib", "oob-collector.js");
const {
  oobMint,
  oobPoll,
  loadOobConfig,
  resolveBinding,
  readOobTokenRecords,
  POLL_TOOL_ID,
  MINT_TOOL_ID,
} = require("../mcp/lib/oob-collector.js");
const { initSession } = require("../mcp/lib/session-state.js");
const { routeSurfaces } = require("../mcp/lib/surface-router.js");
const { ensureHandoffSigningKey } = require("../mcp/lib/handoff-signing-key.js");
const {
  attackSurfacePath,
  offensiveRunsJsonlPath,
  offensiveRunsDir,
  oobTokensJsonlPath,
} = require("../mcp/lib/paths.js");
const {
  appendCandidateClaim,
  readOffensiveRunRecords,
  canonicalizeExploitTarget,
  OFFENSIVE_TOOL_DEMONSTRATED_CEILING,
} = require("../mcp/lib/claims.js");
const { signOffensiveRunRow, verifyOffensiveRunRowMac } = require("../mcp/lib/offensive-row-mac.js");
const { projectExploitRunObservedRef } = require("../mcp/lib/claim-freeze.js");
const {
  resetForTests: resetMaterializationDebounce,
} = require("../mcp/lib/frontier-materialize-debounce.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-oob-collector-"));
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

const SURFACE_ID = "surface:fetch";
const ENDPOINT_PATH = "/api/fetch";
const OOB_HOST = "sink.example.com";
const POLL_URL = "https://poll.sink.example.com";
const CONFIG = loadOobConfig({ BOB_OOB_HOST: OOB_HOST, BOB_OOB_POLL_URL: POLL_URL });
const SELF_IP = "203.0.113.99";
const CONFIG_SELF = loadOobConfig({ BOB_OOB_HOST: OOB_HOST, BOB_OOB_POLL_URL: POLL_URL, BOB_OOB_SELF_EGRESS_IP: SELF_IP });

function seedRoutedSurface(domain) {
  fs.mkdirSync(path.dirname(attackSurfacePath(domain)), { recursive: true });
  fs.writeFileSync(attackSurfacePath(domain), `${JSON.stringify({
    surfaces: [{
      id: SURFACE_ID,
      title: "Synthetic SSRF/OOB surface",
      surface_type: "web",
      hosts: [domain],
      endpoints: [`https://${domain}${ENDPOINT_PATH}`],
      tech_stack: ["fixture"],
      priority: "HIGH",
    }],
  }, null, 2)}\n`, "utf8");
  JSON.parse(routeSurfaces({ target_domain: domain }));
}

function setupSession(domain) {
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/` }));
  seedRoutedSurface(domain);
  ensureHandoffSigningKey(domain);
}

function mintArgs(domain, overrides = {}) {
  return {
    target_domain: domain,
    surface_id: SURFACE_ID,
    oracle_kind: "out_of_band_interaction",
    ...overrides,
  };
}

function tokenFor(domain, handle) {
  const { binding } = resolveBinding(domain, handle);
  return binding ? binding.token : null;
}

// An injected sink response: an array of interactions for the polled token.
function hitSource(token, { protocol = "http", source_ip = "198.51.100.23", count = 1, first_seen_ts = 1000 } = {}) {
  return () => ({
    interactions: Array.from({ length: count }, () => ({ token, protocol, source_ip, first_seen_ts })),
  });
}
const emptySource = () => () => ({ interactions: [] });
const mismatchSource = () => () => ({ interactions: [{ token: "oobdeadbeefdeadbeefdeadbeefdeadbeef", protocol: "http", source_ip: "198.51.100.9" }] });

// ───────────────────────── pure / registry unit tests ──────────────────────

test("ceiling registry: bob_oob_poll is a hard MEDIUM; bob_oob_mint is deliberately absent", () => {
  assert.equal(OFFENSIVE_TOOL_DEMONSTRATED_CEILING.bob_oob_poll, "medium");
  assert.equal(OFFENSIVE_TOOL_DEMONSTRATED_CEILING.bob_oob_mint, undefined);
});

test("loadOobConfig: absent / internal / non-https env all fail closed to inert", () => {
  assert.equal(loadOobConfig({}).configured, false);
  assert.equal(loadOobConfig({ BOB_OOB_HOST: OOB_HOST }).configured, false);
  assert.equal(loadOobConfig({ BOB_OOB_HOST: "localhost", BOB_OOB_POLL_URL: POLL_URL }).configured, false);
  assert.equal(loadOobConfig({ BOB_OOB_HOST: "169.254.169.254", BOB_OOB_POLL_URL: POLL_URL }).configured, false);
  assert.equal(loadOobConfig({ BOB_OOB_HOST: OOB_HOST, BOB_OOB_POLL_URL: "http://poll.sink.example.com" }).configured, false);
  const ok = loadOobConfig({ BOB_OOB_HOST: OOB_HOST, BOB_OOB_POLL_URL: POLL_URL });
  assert.equal(ok.configured, true);
  assert.equal(Object.isFrozen(ok), true);
});

test("the collector module never requires child_process (strictly in-process + safeFetch)", () => {
  const src = fs.readFileSync(COLLECTOR_PATH, "utf8");
  assert.ok(!/child_process/.test(src), "must not reference child_process");
});

// ───────────────────────── inert (unconfigured) ────────────────────────────

test("inert: unconfigured sink → mint and poll write nothing, no network", () => withTempHome(async () => {
  const domain = "oob-inert.example.test";
  setupSession(domain);
  const inert = loadOobConfig({});
  const mintResult = await oobMint(mintArgs(domain), { config: inert });
  assert.equal(mintResult.minted, false);
  assert.equal(mintResult.reason, "oob_sink_not_configured");
  assert.equal(fs.existsSync(oobTokensJsonlPath(domain)), false);

  const pollResult = await oobPoll({ target_domain: domain, token_handle: "oobh-nope" }, { config: inert });
  assert.equal(pollResult.confirmed, false);
  assert.equal(pollResult.available, false);
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

// ───────────────────────── mint ────────────────────────────────────────────

test("mint: writes ONE in-scope binding + returns benign token payloads + no offensive row", () => withTempHome(async () => {
  const domain = "oob-mint.example.test";
  setupSession(domain);
  const result = await oobMint(mintArgs(domain), { config: CONFIG });
  assert.equal(result.minted, true);
  assert.ok(result.token_handle, "must return a token_handle");
  assert.equal(result.payload_dns.endsWith(`.${OOB_HOST}`), true, result.payload_dns);
  assert.equal(result.payload_http.startsWith(`https://${OOB_HOST}/`), true, result.payload_http);

  const bindings = readOobTokenRecords(domain).filter((r) => r.kind === "binding");
  assert.equal(bindings.length, 1);
  const binding = bindings[0];
  // The bound proof target is the IN-SCOPE endpoint, NEVER the OOB host.
  assert.equal(binding.canonical_target, canonicalizeExploitTarget(`https://${domain}${ENDPOINT_PATH}`));
  assert.equal(new URL(binding.canonical_target).host, domain);
  assert.notEqual(new URL(binding.canonical_target).host, OOB_HOST);
  // mint is non-signing: no offensive-runs row.
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("mint: per-session token cap is enforced", () => withTempHome(async () => {
  const domain = "oob-cap.example.test";
  setupSession(domain);
  let lastBlocked = null;
  for (let i = 0; i < 66; i += 1) {
    const r = await oobMint(mintArgs(domain), { config: CONFIG });
    if (r.minted === false) { lastBlocked = r; break; }
  }
  assert.ok(lastBlocked, "cap must eventually block minting");
  assert.equal(lastBlocked.reason, "oob_token_cap_reached");
}));

test("forbidden inputs: mint and poll reject server-controlled fields", () => withTempHome(async () => {
  const domain = "oob-forbidden.example.test";
  setupSession(domain);
  await assert.rejects(() => oobMint(mintArgs(domain, { oob_host: "evil.example.com" }), { config: CONFIG }), /oob_host|forbidden|not allowed|unexpected/i);
  await assert.rejects(() => oobMint(mintArgs(domain, { token: "oobx" }), { config: CONFIG }), /token|forbidden|not allowed|unexpected/i);
  await assert.rejects(() => oobPoll({ target_domain: domain, token_handle: "h", sink_url: "https://evil" }, { config: CONFIG }), /sink|forbidden|not allowed|unexpected/i);
}));

// ───────────────────────── poll: the positive ──────────────────────────────

test("poll HIT (http): signed MEDIUM row bound to the in-scope endpoint, not the OOB host", () => withTempHome(async () => {
  const domain = "oob-hit.example.test";
  setupSession(domain);
  const mintResult = await oobMint(mintArgs(domain), { config: CONFIG });
  const token = tokenFor(domain, mintResult.token_handle);

  const result = await oobPoll(
    { target_domain: domain, token_handle: mintResult.token_handle },
    { config: CONFIG, interaction_source: hitSource(token) },
  );
  assert.equal(result.confirmed, true, JSON.stringify(result));
  assert.equal(result.row_written, true);
  assert.equal(result.offensive_outcome, "exploited_safely");
  assert.equal(result.demonstrated_severity, "medium");
  assert.equal(result.tool_id, POLL_TOOL_ID);
  assert.equal(result.surface_id, SURFACE_ID);

  const rows = readOffensiveRunRecords(domain);
  assert.equal(rows.length, 1);
  const row = rows[0];
  assert.equal(row.tool_id, "bob_oob_poll");
  assert.equal(row.demonstrated_severity, "medium");
  assert.equal(row.surface_id, SURFACE_ID);
  assert.equal(row.offensive_outcome, "exploited_safely");
  assert.equal(row.dry_run, false);
  assert.equal(row.timed_out, false);
  // THE binding: row.target is the in-scope endpoint, NEVER the OOB host.
  assert.equal(row.target, canonicalizeExploitTarget(`https://${domain}${ENDPOINT_PATH}`));
  assert.equal(new URL(row.target).host, domain);
  assert.notEqual(new URL(row.target).host, OOB_HOST);
  // MAC valid + capture re-hashes (freeze re-hash path).
  assert.equal(verifyOffensiveRunRowMac(row, ensureHandoffSigningKey(domain)), true);
  const observed = projectExploitRunObservedRef(domain, { kind: "exploit_run", run_id: row.run_id });
  assert.equal(observed.stdout_hash, row.stdout_hash);

  // The capture carries ONLY Bob's own observation (token + host + protocol +
  // surface), never a raw target body or the prepended FQDN labels.
  const captureStdout = fs.readFileSync(path.join(offensiveRunsDir(domain), `${row.run_id}.stdout`), "utf8");
  const capture = JSON.parse(captureStdout);
  assert.deepEqual(Object.keys(capture).sort(), ["bound_surface_id", "first_seen_ts", "oob_host", "protocol", "token"]);
  assert.equal(capture.oob_host, OOB_HOST);
  assert.equal(capture.bound_surface_id, SURFACE_ID);
}));

test("poll EMPTY: signs nothing", () => withTempHome(async () => {
  const domain = "oob-empty.example.test";
  setupSession(domain);
  const mintResult = await oobMint(mintArgs(domain), { config: CONFIG });
  const result = await oobPoll(
    { target_domain: domain, token_handle: mintResult.token_handle },
    { config: CONFIG, interaction_source: emptySource() },
  );
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "no_matching_interaction");
  assert.equal(result.row_written, false);
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("poll MISMATCH (stray non-minted token): signs nothing", () => withTempHome(async () => {
  const domain = "oob-mismatch.example.test";
  setupSession(domain);
  const mintResult = await oobMint(mintArgs(domain), { config: CONFIG });
  const result = await oobPoll(
    { target_domain: domain, token_handle: mintResult.token_handle },
    { config: CONFIG, interaction_source: mismatchSource() },
  );
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "no_matching_interaction");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("poll DNS-only hit: a sufficient MEDIUM positive flagged dns_only_attribution_weak", () => withTempHome(async () => {
  const domain = "oob-dns.example.test";
  setupSession(domain);
  const mintResult = await oobMint(mintArgs(domain), { config: CONFIG });
  const token = tokenFor(domain, mintResult.token_handle);
  const result = await oobPoll(
    { target_domain: domain, token_handle: mintResult.token_handle },
    { config: CONFIG, interaction_source: hitSource(token, { protocol: "dns", source_ip: undefined }) },
  );
  assert.equal(result.confirmed, true, JSON.stringify(result));
  assert.equal(result.row_written, true);
  const row = readOffensiveRunRecords(domain)[0];
  assert.equal(row.dns_only_attribution_weak, true);
  assert.equal(row.demonstrated_severity, "medium");
}));

test("poll SELF-HIT (http source == configured egress IP): withholds the signed row", () => withTempHome(async () => {
  const domain = "oob-selfhit.example.test";
  setupSession(domain);
  const mintResult = await oobMint(mintArgs(domain), { config: CONFIG_SELF });
  const token = tokenFor(domain, mintResult.token_handle);
  const result = await oobPoll(
    { target_domain: domain, token_handle: mintResult.token_handle },
    { config: CONFIG_SELF, interaction_source: hitSource(token, { source_ip: SELF_IP }) },
  );
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "self_hit_suspected");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("poll IDEMPOTENT re-poll: returns the prior run_id, mints no second row", () => withTempHome(async () => {
  const domain = "oob-idem.example.test";
  setupSession(domain);
  const mintResult = await oobMint(mintArgs(domain), { config: CONFIG });
  const token = tokenFor(domain, mintResult.token_handle);
  const first = await oobPoll(
    { target_domain: domain, token_handle: mintResult.token_handle },
    { config: CONFIG, interaction_source: hitSource(token) },
  );
  assert.equal(first.row_written, true);
  const second = await oobPoll(
    { target_domain: domain, token_handle: mintResult.token_handle },
    { config: CONFIG, interaction_source: hitSource(token) },
  );
  assert.equal(second.confirmed, true);
  assert.equal(second.idempotent, true);
  assert.equal(second.row_written, false);
  assert.equal(second.run_id, first.run_id);
  assert.equal(readOffensiveRunRecords(domain).length, 1);
}));

test("poll TTL expired: blocked, signs nothing", () => withTempHome(async () => {
  const domain = "oob-ttl.example.test";
  setupSession(domain);
  const mintResult = await oobMint(mintArgs(domain), { config: CONFIG, clock: () => 1_000 });
  const token = tokenFor(domain, mintResult.token_handle);
  const result = await oobPoll(
    { target_domain: domain, token_handle: mintResult.token_handle },
    { config: CONFIG, interaction_source: hitSource(token), clock: () => 1_000 + 49 * 60 * 60 * 1000 },
  );
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "token_expired");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("poll unknown token_handle: blocked", () => withTempHome(async () => {
  const domain = "oob-unknown.example.test";
  setupSession(domain);
  const result = await oobPoll({ target_domain: domain, token_handle: "oobh-never-minted" }, { config: CONFIG, interaction_source: hitSource("x") });
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "unknown_token_handle");
}));

// ───────────────────────── claim round-trip + ceiling ──────────────────────

function exploitRefFromRow(row) {
  return {
    kind: "exploit_run",
    run_id: row.run_id,
    tool_id: row.tool_id,
    target: row.target,
    offensive_outcome: "exploited_safely",
    command_hash: row.command_hash,
    exit_code: row.exit_code,
    stdout_hash: row.stdout_hash,
    stderr_hash: row.stderr_hash,
  };
}

function oobClaim(domain, row, overrides = {}) {
  return {
    target_domain: domain,
    title: "Blind SSRF proven via out-of-band callback",
    summary: "The target backend reached Bob's OOB sink with the minted token.",
    severity: "medium",
    exploit_outcome: { outcome: "exploited_safely", safe_oracle: { kind: "out_of_band_interaction" } },
    evidence_refs: [exploitRefFromRow(row)],
    surface_ids: [SURFACE_ID],
    ...overrides,
  };
}

test("round-trip: an OOB-backed claim records at MEDIUM and is rejected at HIGH (dual-enforcement ceiling)", () => withTempHome(async () => {
  const domain = "oob-claim.example.test";
  setupSession(domain);
  const mintResult = await oobMint(mintArgs(domain), { config: CONFIG });
  const token = tokenFor(domain, mintResult.token_handle);
  const pollResult = await oobPoll(
    { target_domain: domain, token_handle: mintResult.token_handle },
    { config: CONFIG, interaction_source: hitSource(token) },
  );
  assert.equal(pollResult.row_written, true);
  const row = readOffensiveRunRecords(domain)[0];

  // MEDIUM claim citing the real signed row → accepted.
  const ok = appendCandidateClaim(oobClaim(domain, row, { severity: "medium" }));
  assert.ok(ok, "MEDIUM OOB claim must record");

  // HIGH claim citing the same MEDIUM-ceiling row → rejected by the proof gate.
  let threw = null;
  try {
    appendCandidateClaim(oobClaim(domain, row, { severity: "high", title: "overclaim" }));
  } catch (e) {
    threw = e;
  }
  assert.ok(threw, "a HIGH claim over a MEDIUM-ceiling OOB row must be rejected");
}));

test("negative gate: a row stamped target == the OOB host is unbacked (proves the in-scope binding is load-bearing)", () => withTempHome(async () => {
  const domain = "oob-negbind.example.test";
  setupSession(domain);
  // Hand-build an OOB row that WRONGLY stamps the OOB host as the target.
  const badTarget = canonicalizeExploitTarget(`https://${OOB_HOST}/oobdeadbeef`);
  const row = {
    version: 1,
    target_domain: domain,
    run_id: "oob-negbind-1",
    tool_id: "bob_oob_poll",
    target: badTarget,
    offensive_outcome: "exploited_safely",
    dry_run: false,
    timed_out: false,
    command_hash: "a".repeat(64),
    exit_code: 0,
    stdout_hash: "b".repeat(64),
    stderr_hash: "c".repeat(64),
    demonstrated_severity: "medium",
    surface_id: SURFACE_ID,
  };
  signOffensiveRunRow(row, ensureHandoffSigningKey(domain));
  fs.mkdirSync(path.dirname(offensiveRunsJsonlPath(domain)), { recursive: true });
  fs.appendFileSync(offensiveRunsJsonlPath(domain), `${JSON.stringify(row)}\n`);

  let threw = null;
  try {
    appendCandidateClaim(oobClaim(domain, row));
  } catch (e) {
    threw = e;
  }
  assert.ok(threw, "a claim citing an OOB-host-targeted row must be unbacked (out of scope)");
}));
