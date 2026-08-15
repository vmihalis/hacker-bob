"use strict";

// SEEDED test matrix for the second-order / stored-effect re-read collector
// (bob_secondorder_mint + bob_secondorder_reread).
//
// No live target: the re-read response is supplied through an injected
// observation_source seam (a channel Bob controls in production via safeFetch), and
// the routed surface + its two in-scope endpoints are seeded directly. The positive
// fires ONLY when the EXACT server-minted canary appears as a parsed LEAF at the
// DISTINCT observation endpoint AND the silent decoy stays absent; the signed row's
// target is the in-scope observation endpoint, re-derived from the routed surface.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  secondorderMint,
  secondorderReread,
  resolveBinding,
  ORACLE_KIND_VALUES,
  MINT_TOOL_ID,
  REREAD_TOOL_ID,
} = require("../mcp/domains/web/offensive-secondorder-producer.js");
const { initSession } = require("../mcp/core/session/session-state.js");
const { routeSurfaces } = require("../mcp/core/frontier/surface-router.js");
const { ensureHandoffSigningKey } = require("../mcp/core/ledger-integrity/index.js");
const {
  attackSurfacePath,
  offensiveRunsJsonlPath,
  secondorderTokensJsonlPath,
} = require("../mcp/core/io/paths.js");
const {
  readOffensiveRunRecords,
  canonicalizeExploitTarget,
  OFFENSIVE_TOOL_DEMONSTRATED_CEILING,
} = require("../mcp/core/claims/claims.js");
const { verifyRowWithMac, OFFENSIVE_ROW_MAC_CONTEXT } = require("../mcp/core/ledger-integrity/index.js");
const { resolveOffensiveRowVerifier } = require("../mcp/core/ledger-integrity/index.js");
const { verifyFindingDifferential } = require("../mcp/core/differential/index.js");
const {
  resetForTests: resetMaterializationDebounce,
} = require("../mcp/core/frontier/frontier-materialize-debounce.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-secondorder-"));
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

const SURFACE_ID = "surface:stored";
const INJECT_PATH = "/api/inject";
const READ_PATH = "/api/read";

function seedRoutedSurface(domain, endpoints) {
  fs.mkdirSync(path.dirname(attackSurfacePath(domain)), { recursive: true });
  fs.writeFileSync(attackSurfacePath(domain), `${JSON.stringify({
    surfaces: [{
      id: SURFACE_ID,
      title: "Synthetic stored-effect surface",
      surface_type: "web",
      hosts: [domain],
      endpoints,
      tech_stack: ["fixture"],
      priority: "HIGH",
    }],
  }, null, 2)}\n`, "utf8");
  JSON.parse(routeSurfaces({ target_domain: domain }));
}

function setupSession(domain, { endpoints } = {}) {
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/` }));
  seedRoutedSurface(domain, endpoints || [`https://${domain}${INJECT_PATH}`, `https://${domain}${READ_PATH}`]);
  ensureHandoffSigningKey(domain);
}

function mintArgs(domain, overrides = {}) {
  return {
    target_domain: domain,
    surface_id: SURFACE_ID,
    oracle_kind: ORACLE_KIND_VALUES[0],
    ...overrides,
  };
}

function canaryFor(domain, handle) {
  const { binding } = resolveBinding(domain, handle);
  return binding ? binding.canary : null;
}
function decoyFor(domain, handle) {
  const { binding } = resolveBinding(domain, handle);
  return binding ? binding.decoy : null;
}

// An injected re-read response: a JSON body reflected at the observation endpoint. The
// seam ignores the URL (Bob-controlled channel) and returns a response-like { status,
// bodyBytes }, so the producer runs its real parse + exact-leaf oracle.
function jsonSource(obj, { status = 200 } = {}) {
  return () => ({ status, bodyBytes: Buffer.from(JSON.stringify(obj), "utf8") });
}
function rawSource(text, { status = 200 } = {}) {
  return () => ({ status, bodyBytes: Buffer.from(String(text), "utf8") });
}

// ───────────────────────── pure / registry unit tests ──────────────────────

test("ceiling registry: bob_secondorder_reread is a hard MEDIUM; bob_secondorder_mint is absent", () => {
  assert.equal(OFFENSIVE_TOOL_DEMONSTRATED_CEILING.bob_secondorder_reread, "medium");
  assert.equal(OFFENSIVE_TOOL_DEMONSTRATED_CEILING.bob_secondorder_mint, undefined);
});

test("the module never requires child_process (strictly in-process + safeFetch)", () => {
  const src = fs.readFileSync(path.join(__dirname, "..", "mcp", "domains", "web", "offensive-secondorder-producer.js"), "utf8");
  assert.ok(!/child_process/.test(src), "must not reference child_process");
});

// ───────────────────────── mint ────────────────────────────────────────────

test("mint: writes ONE binding, returns the canary payload + distinct endpoints, no offensive row", () => withTempHome(async () => {
  const domain = "so-mint.example.test";
  setupSession(domain);
  const result = await secondorderMint(mintArgs(domain));
  assert.equal(result.minted, true);
  assert.ok(result.token_handle, "must return a token_handle");
  assert.ok(typeof result.canary_payload === "string" && result.canary_payload.length > 40, "returns the canary to inject");
  assert.equal(new URL(result.injection_endpoint).pathname, INJECT_PATH);
  assert.equal(new URL(result.observation_endpoint).pathname, READ_PATH);
  assert.notEqual(result.injection_endpoint, result.observation_endpoint);

  const bindings = fs.readFileSync(secondorderTokensJsonlPath(domain), "utf8").trim().split("\n").map(JSON.parse);
  assert.equal(bindings.length, 1);
  const binding = bindings[0];
  // The decoy is server-secret — minted but NEVER returned to the agent.
  assert.equal(binding.canary, result.canary_payload);
  assert.ok(typeof binding.decoy === "string" && binding.decoy !== binding.canary, "distinct decoy minted, not returned");
  assert.equal(binding.surface_id, SURFACE_ID);
  // mint is non-signing: no offensive-runs row.
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("mint: refuses when injection and observation loci are equal (would degenerate to reflect)", () => withTempHome(async () => {
  const domain = "so-equal.example.test";
  setupSession(domain);
  const result = await secondorderMint(mintArgs(domain, { injection_locus: 0, observation_locus: 0 }));
  assert.equal(result.minted, false);
  assert.equal(result.reason, "injection_and_observation_endpoint_must_differ");
  assert.equal(fs.existsSync(secondorderTokensJsonlPath(domain)), false);
}));

test("mint: refuses when the observation locus is out of range (single-endpoint surface)", () => withTempHome(async () => {
  const domain = "so-single.example.test";
  setupSession(domain, { endpoints: [`https://${domain}${READ_PATH}`] });
  const result = await secondorderMint(mintArgs(domain)); // default observation_locus=1
  assert.equal(result.minted, false);
  assert.equal(result.reason, "observation_locus_out_of_range");
  assert.equal(fs.existsSync(secondorderTokensJsonlPath(domain)), false);
}));

// ───────────────────────── reread: the positive ─────────────────────────────

test("reread HIT: exact canary leaf + silent decoy → signed MEDIUM positive bound to the observation endpoint", () => withTempHome(async () => {
  const domain = "so-hit.example.test";
  setupSession(domain);
  const mintResult = await secondorderMint(mintArgs(domain));
  const canary = canaryFor(domain, mintResult.token_handle);

  const result = await secondorderReread(
    { target_domain: domain, token_handle: mintResult.token_handle, expect: "interaction" },
    { observation_source: jsonSource({ data: { comment: { body: canary } } }) },
  );
  assert.equal(result.confirmed, true, JSON.stringify(result));
  assert.equal(result.row_written, true);
  assert.equal(result.offensive_outcome, "exploited_safely");
  assert.equal(result.demonstrated_severity, "medium");
  assert.equal(result.tool_id, REREAD_TOOL_ID);
  assert.equal(result.surface_id, SURFACE_ID);
  assert.equal(result.oracle_kind, ORACLE_KIND_VALUES[0]);
  // Masked oracle: booleans/hashes only, never the raw response body or the canary value.
  assert.equal(result.masked_oracle.canary_present, true);
  assert.equal(result.masked_oracle.decoy_present, false);
  const maskedText = JSON.stringify(result.masked_oracle);
  assert.ok(!maskedText.includes(canary), "masked oracle must not leak the raw canary value");

  const rows = readOffensiveRunRecords(domain);
  assert.equal(rows.length, 1);
  const row = rows[0];
  assert.equal(row.tool_id, REREAD_TOOL_ID);
  assert.equal(row.demonstrated_severity, "medium");
  assert.equal(row.surface_id, SURFACE_ID);
  assert.equal(row.offensive_outcome, "exploited_safely");
  assert.equal(row.oracle_kind, ORACLE_KIND_VALUES[0]);
  assert.equal(row.dry_run, false);
  assert.equal(row.timed_out, false);
  // row.target is the in-scope OBSERVATION endpoint (where Bob read the evidence).
  assert.equal(row.target, canonicalizeExploitTarget(`https://${domain}${READ_PATH}`));
  assert.equal(new URL(row.target).host, domain);
  // MAC valid (producer rows are ed25519 v2, verified via the bundle's public key).
  assert.equal(verifyRowWithMac(OFFENSIVE_ROW_MAC_CONTEXT, row, resolveOffensiveRowVerifier(domain)), true);
}));

test("reread NEGATIVE: canary absent → no row", () => withTempHome(async () => {
  const domain = "so-absent.example.test";
  setupSession(domain);
  const mintResult = await secondorderMint(mintArgs(domain));
  const result = await secondorderReread(
    { target_domain: domain, token_handle: mintResult.token_handle, expect: "interaction" },
    { observation_source: jsonSource({ data: { comment: { body: "nothing here" } } }) },
  );
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "canary_absent");
  assert.equal(result.row_written, false);
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("reread NEGATIVE: decoy ALSO surfaces → fail closed (ambient echo), no row", () => withTempHome(async () => {
  const domain = "so-decoy-fires.example.test";
  setupSession(domain);
  const mintResult = await secondorderMint(mintArgs(domain));
  const canary = canaryFor(domain, mintResult.token_handle);
  const decoy = decoyFor(domain, mintResult.token_handle);
  const result = await secondorderReread(
    { target_domain: domain, token_handle: mintResult.token_handle, expect: "interaction" },
    { observation_source: jsonSource({ data: { a: canary, b: decoy } }) },
  );
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "decoy_surfaced");
  assert.equal(result.row_written, false);
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("reread NEGATIVE: substring-only match never signs (exact parsed-leaf only)", () => withTempHome(async () => {
  const domain = "so-substr.example.test";
  setupSession(domain);
  const mintResult = await secondorderMint(mintArgs(domain));
  const canary = canaryFor(domain, mintResult.token_handle);
  const result = await secondorderReread(
    { target_domain: domain, token_handle: mintResult.token_handle, expect: "interaction" },
    { observation_source: jsonSource({ data: { note: `prefix-${canary}-suffix` } }) },
  );
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "canary_absent");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("reread NEGATIVE: a non-parsing (non-JSON) body never signs", () => withTempHome(async () => {
  const domain = "so-nonjson.example.test";
  setupSession(domain);
  const mintResult = await secondorderMint(mintArgs(domain));
  const canary = canaryFor(domain, mintResult.token_handle);
  const result = await secondorderReread(
    { target_domain: domain, token_handle: mintResult.token_handle, expect: "interaction" },
    { observation_source: rawSource(`<html><body>${canary}</body></html>`) },
  );
  assert.equal(result.confirmed, false);
  assert.equal(result.reason, "canary_absent");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

// ───────────────────────── decoy-silent control arm ─────────────────────────

test("expect=silence: a decoy silent against a reachable endpoint signs a blocked_by_defense control", () => withTempHome(async () => {
  const domain = "so-control.example.test";
  setupSession(domain);
  const mintResult = await secondorderMint(mintArgs(domain));
  const res = await secondorderReread(
    { target_domain: domain, token_handle: mintResult.token_handle, expect: "silence" },
    { observation_source: jsonSource({ data: { comment: { body: "unrelated" } } }) },
  );
  assert.equal(res.control, true);
  assert.equal(res.confirmed, false);
  assert.equal(res.offensive_outcome, "blocked_by_defense");
  assert.equal(res.row_written, true);
  assert.equal(res.oracle_kind, ORACLE_KIND_VALUES[0]);
  const ctl = readOffensiveRunRecords(domain).find((r) => r.run_id === res.run_id);
  assert.ok(ctl, "control row persisted");
  assert.equal(ctl.offensive_outcome, "blocked_by_defense");
  assert.equal(ctl.oracle_kind, ORACLE_KIND_VALUES[0]);
  assert.equal(ctl.surface_id, SURFACE_ID);
}));

test("expect=silence: a decoy that DID surface is refused as a control (never signed)", () => withTempHome(async () => {
  const domain = "so-control-fired.example.test";
  setupSession(domain);
  const mintResult = await secondorderMint(mintArgs(domain));
  const decoy = decoyFor(domain, mintResult.token_handle);
  const res = await secondorderReread(
    { target_domain: domain, token_handle: mintResult.token_handle, expect: "silence" },
    { observation_source: jsonSource({ data: { leaked: decoy } }) },
  );
  assert.equal(res.confirmed, false);
  assert.equal(res.reason, "decoy_surfaced");
  assert.equal(res.row_written, false);
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

// ───────────────────────── forbidden inputs ─────────────────────────────────

test("forbidden inputs: mint and reread reject server-owned canary / decoy / severity", () => withTempHome(async () => {
  const domain = "so-forbidden.example.test";
  setupSession(domain);
  await assert.rejects(() => secondorderMint(mintArgs(domain, { canary: "socanx" })), /canary|forbidden|not accept|unexpected/i);
  await assert.rejects(() => secondorderMint(mintArgs(domain, { decoy: "sodecx" })), /decoy|forbidden|not accept|unexpected/i);
  await assert.rejects(() => secondorderMint(mintArgs(domain, { severity: "critical" })), /severity|forbidden|not accept|unexpected/i);
  await assert.rejects(() => secondorderMint(mintArgs(domain, { demonstrated_severity: "high" })), /severity|forbidden|not accept|unexpected/i);
  await assert.rejects(
    () => secondorderReread({ target_domain: domain, token_handle: "soh-x", canary_payload: "socanx" }),
    /canary|forbidden|not accept|unexpected/i,
  );
}));

test("reread: unknown token_handle → blocked, no row", () => withTempHome(async () => {
  const domain = "so-unknown.example.test";
  setupSession(domain);
  const res = await secondorderReread(
    { target_domain: domain, token_handle: "soh-never-minted", expect: "interaction" },
    { observation_source: jsonSource({ data: { x: 1 } }) },
  );
  assert.equal(res.confirmed, false);
  assert.equal(res.reason, "unknown_token_handle");
  assert.equal(fs.existsSync(offensiveRunsJsonlPath(domain)), false);
}));

test("reread IDEMPOTENT re-read: returns the prior run_id, mints no second row", () => withTempHome(async () => {
  const domain = "so-idem.example.test";
  setupSession(domain);
  const mintResult = await secondorderMint(mintArgs(domain));
  const canary = canaryFor(domain, mintResult.token_handle);
  const first = await secondorderReread(
    { target_domain: domain, token_handle: mintResult.token_handle, expect: "interaction" },
    { observation_source: jsonSource({ data: { body: canary } }) },
  );
  assert.equal(first.row_written, true);
  const second = await secondorderReread(
    { target_domain: domain, token_handle: mintResult.token_handle, expect: "interaction" },
    { observation_source: jsonSource({ data: { body: canary } }) },
  );
  assert.equal(second.confirmed, true);
  assert.equal(second.idempotent, true);
  assert.equal(second.row_written, false);
  assert.equal(second.run_id, first.run_id);
  assert.equal(readOffensiveRunRecords(domain).length, 1);
}));

// ───────────────────────── finding-differential flip (non-self-closing) ─────

test("the surfaced positive + the decoy-silent control flip to a verified_pass (NOT self-closing, NOT OOB-attribution-capped)", () => withTempHome(async () => {
  const domain = "so-flip.example.test";
  setupSession(domain);
  // POSITIVE — a real canary surfaces at the distinct observation endpoint, decoy silent.
  const m1 = await secondorderMint(mintArgs(domain));
  const c1 = canaryFor(domain, m1.token_handle);
  const pos = await secondorderReread(
    { target_domain: domain, token_handle: m1.token_handle, expect: "interaction" },
    { observation_source: jsonSource({ data: { comment: { body: c1 } } }) },
  );
  assert.equal(pos.offensive_outcome, "exploited_safely");
  // CONTROL — a SEPARATE binding, never injected, its decoy stays silent.
  const m2 = await secondorderMint(mintArgs(domain));
  const ctl = await secondorderReread(
    { target_domain: domain, token_handle: m2.token_handle, expect: "silence" },
    { observation_source: jsonSource({ data: { comment: { body: "unrelated" } } }) },
  );
  assert.equal(ctl.offensive_outcome, "blocked_by_defense");
  // The FLIP — the mechanism-agnostic finding-differential verifier mints verified_pass:
  // positive exploited, control blocked, same surface, distinct executed identities. The
  // second_order_reread oracle_kind is NOT the OOB kind, so the OOB attribution gate does
  // not cap it (the re-read channel is Bob-controlled, no self-hit weakness).
  const verdict = verifyFindingDifferential({
    target_domain: domain,
    finding_id: "F-1",
    surface_id: SURFACE_ID,
    positive_run_ref: { ledger: "offensive_runs", row_id: pos.run_id },
    control_run_ref: { ledger: "offensive_runs", row_id: ctl.run_id },
  });
  assert.equal(verdict.result, "verified_pass", JSON.stringify(verdict));
}));
