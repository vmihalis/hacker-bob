"use strict";

// Composition LIVE verifier — SC1 confirm-half for object-auth/HTTP guard edges.
//
// The offline harness is a shape gate that executes nothing, so a self-consistent
// counterfeit observation passes it. This verifier RE-EXECUTES each guard leaf's
// CB-D1 control battery and mints a verified_pass only when the flip reproduces.
// THE decisive test: an observation that passes the offline gate but whose live
// target is not actually vulnerable is REFUTED. Producer-independence is enforced
// at the integrity boundary — the verified ledger is audit-graded (Write-forge
// blocked) and is the sole SC1 grading source (no frontier event is emitted).

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const { appendFrontierEvent } = require("../mcp/core/frontier/frontier-events.js");
const { hashCanonicalJson } = require("../mcp/core/verification/verification-contracts.js");
const {
  compositionVerifiedJsonlPath,
  isAuditGradedPath,
} = require("../mcp/core/io/paths.js");
const {
  verifyCompositionPath,
  readCompositionVerifiedSummary,
  RESULT_VERIFIED_PASS,
  RESULT_REFUTED,
  RESULT_INCONCLUSIVE,
  RESULT_OFFLINE_REFUSED,
} = require("../mcp/core/differential/index.js");
const { TOOL_MANIFEST } = require("../mcp/tools/tool-registry.js");

// example.com is a real registrable domain, so validateHttpScanScope accepts
// https://example.com/... as first-party — the verifier exercises real scope.
const DOMAIN = "example.com";
const BASE_URL = "https://example.com";

const VICTIM_BODY = { id: "victim-7", email: "victim@example.com", ssn: "111-22-3333" };
const ATTACKER_BODY = { id: "attacker-1", email: "attacker@example.com" };

// Async-aware: the verifier is async, so the temp HOME must stay in place until
// the awaited work completes — a synchronous finally would restore HOME and delete
// the temp dir mid-write, leaking writes to the real session root.
async function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-live-verifier-"));
  process.env.HOME = home;
  try {
    return await fn(home);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

// Seed the offline observation.recorded a guard leaf binds to (edge_type guard,
// claimed verdict confirmed, a discriminating verdict-flipping negative control,
// a recomputing replay_hash) — exactly what the offline gate accepts.
function seedGuardObservation(domain, edgeType = "guard", victimUrl = "/api/objects/victim") {
  const request = { method: "GET", url: victimUrl, principal: "attacker" };
  const response = { status: 200, body: "victim-object" };
  const negative_control = {
    request: { ...request, principal: "owner" },
    response: { status: 403, body: "forbidden" },
    verdict: "denied",
  };
  const decisive = { edge_type: edgeType, request, response, verdict: "confirmed", negative_control };
  const payload = { ...decisive, replay_hash: hashCanonicalJson(decisive) };
  const event = appendFrontierEvent({
    target_domain: domain,
    kind: "observation.recorded",
    ts: "2026-06-01T00:00:00.000Z",
    surface_id: `surface:${edgeType}`,
    payload,
  });
  return event.event_id;
}

// Seed an observation whose replay_hash is tampered — the offline gate refuses it.
function seedTamperedObservation(domain) {
  const request = { method: "GET", url: "/api/objects/victim", principal: "attacker" };
  const response = { status: 200, body: "victim-object" };
  const negative_control = {
    request: { ...request, principal: "owner" },
    response: { status: 403, body: "forbidden" },
    verdict: "denied",
  };
  const payload = { edge_type: "guard", request, response, verdict: "confirmed", negative_control, replay_hash: "0".repeat(64) };
  const event = appendFrontierEvent({
    target_domain: domain,
    kind: "observation.recorded",
    ts: "2026-06-01T00:00:00.000Z",
    surface_id: "surface:guard",
    payload,
  });
  return event.event_id;
}

function ok(body) { return { status: 200, body }; }
function blocked(status = 401) { return { status, body: { error: "unauthorized" } }; }

// A live httpScan whose target IS a genuine IDOR (attacker reads the victim's
// private object). `overrides` injects a divergent response by `${ap} ${url}`.
function makeFakeHttpScan(overrides = {}) {
  return async function httpScanFn(args) {
    const url = args.url;
    const ap = args.auth_profile || "anon";
    const key = `${ap} ${url}`;
    if (Object.prototype.hasOwnProperty.call(overrides, key)) return overrides[key];
    if (url.includes("/objects/ghost")) return blocked(404);
    if (url.includes("/objects/attacker")) return ap === "attacker" ? ok(ATTACKER_BODY) : blocked();
    if (url.includes("/objects/public")) return blocked();
    if (url.includes("/objects/victim")) return (ap === "victim" || ap === "attacker") ? ok(VICTIM_BODY) : blocked();
    return blocked();
  };
}

function guardLeaf(eventId) {
  return {
    evidence_ref: `frontier_event:${eventId}`,
    edge_id: "e-guard",
    primary: { method: "GET", url: "/api/objects/victim", auth_profile: "attacker" },
    control_plan: [
      { control: "attacker_owned_control", method: "GET", url: "/api/objects/attacker", auth_profile: "attacker" },
      { control: "victim_auth_same_object", method: "GET", url: "/api/objects/victim", auth_profile: "victim" },
      { control: "no_auth_same_object", method: "GET", url: "/api/objects/victim" },
      { control: "public_object_check", method: "GET", url: "/api/objects/public" },
      { control: "nonexistent_object", method: "GET", url: "/api/objects/ghost", auth_profile: "attacker" },
      { control: "stale_session_check", method: "GET", url: "/api/objects/victim", auth_profile: "stale" },
      { control: "cache_nonce_check", method: "GET", url: "/api/objects/victim?cb=1", auth_profile: "attacker" },
    ],
  };
}

// A query-selected-object IDOR: the object id lives in ?id=, so DIFF_OBJECT
// controls share the /api/document path and differ only by query.
const DOC_VICTIM_BODY = { id: "victim", content: "victim-private-document" };
const DOC_ATTACKER_BODY = { id: "attacker", content: "attacker-document" };
function makeDocFakeHttpScan(overrides = {}) {
  return async function httpScanFn(args) {
    const url = args.url;
    const ap = args.auth_profile || "anon";
    const key = `${ap} ${url}`;
    if (Object.prototype.hasOwnProperty.call(overrides, key)) return overrides[key];
    if (!url.includes("/api/document")) return blocked();
    let id = null;
    try { id = new URL(url).searchParams.get("id"); } catch { id = null; }
    if (id === "ghost") return blocked(404);
    if (id === "public") return blocked();
    if (id === "attacker") return ap === "attacker" ? ok(DOC_ATTACKER_BODY) : blocked();
    if (id === "victim") return (ap === "victim" || ap === "attacker") ? ok(DOC_VICTIM_BODY) : blocked();
    return blocked();
  };
}
function docLeaf(eventId) {
  return {
    evidence_ref: `frontier_event:${eventId}`,
    edge_id: "e-doc",
    primary: { method: "GET", url: "/api/document?id=victim", auth_profile: "attacker" },
    control_plan: [
      { control: "attacker_owned_control", method: "GET", url: "/api/document?id=attacker", auth_profile: "attacker" },
      { control: "victim_auth_same_object", method: "GET", url: "/api/document?id=victim", auth_profile: "victim" },
      { control: "no_auth_same_object", method: "GET", url: "/api/document?id=victim" },
      { control: "public_object_check", method: "GET", url: "/api/document?id=public" },
      { control: "nonexistent_object", method: "GET", url: "/api/document?id=ghost", auth_profile: "attacker" },
      { control: "stale_session_check", method: "GET", url: "/api/document?id=victim", auth_profile: "stale" },
      { control: "cache_nonce_check", method: "GET", url: "/api/document?id=victim&cb=1", auth_profile: "attacker" },
    ],
  };
}

function readVerifiedLedger(domain) {
  const filePath = compositionVerifiedJsonlPath(domain);
  if (!fs.existsSync(filePath)) return [];
  return fs.readFileSync(filePath, "utf8").split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l));
}

test("HAPPY PATH: a genuine live IDOR mints verified_pass + writes the protected ledger", async () => {
  await withTempHome(async () => {
    const eventId = seedGuardObservation(DOMAIN);
    const out = await verifyCompositionPath(
      { target_domain: DOMAIN, base_url: BASE_URL, path: [guardLeaf(eventId)] },
      { httpScanFn: makeFakeHttpScan() },
    );
    assert.equal(out.result, RESULT_VERIFIED_PASS);
    assert.equal(out.verified_leaf_count, 1);
    assert.equal(out.leaves[0].leaf_status, "verified");
    assert.equal(out.leaves[0].disposition, "confirmed");

    const ledger = readVerifiedLedger(DOMAIN);
    assert.equal(ledger.length, 1);
    assert.equal(ledger[0].result, RESULT_VERIFIED_PASS);
    assert.equal(ledger[0].path_hash, out.path_hash);
    assert.ok(typeof ledger[0].results_hash === "string" && ledger[0].results_hash.length > 0);
  });
});

test("COUNTERFEIT REFUTED: an observation that passes the offline gate but whose live target is patched is refuted", async () => {
  await withTempHome(async () => {
    const eventId = seedGuardObservation(DOMAIN); // shape-valid, claims confirmed
    // The live target is NOT vulnerable: the attacker is blocked on the victim object.
    const patched = makeFakeHttpScan({ "attacker https://example.com/api/objects/victim": blocked(403) });
    const out = await verifyCompositionPath(
      { target_domain: DOMAIN, base_url: BASE_URL, path: [guardLeaf(eventId)] },
      { httpScanFn: patched },
    );
    assert.equal(out.result, RESULT_REFUTED);
    assert.equal(out.verified_leaf_count, 0);
    assert.equal(out.leaves[0].leaf_status, "refuted");
    assert.equal(out.leaves[0].disposition, "denied");
  });
});

test("OFFLINE PRECONDITION: a tampered observation is offline_refused — nothing is re-executed", async () => {
  await withTempHome(async () => {
    const eventId = seedTamperedObservation(DOMAIN);
    let executed = false;
    const trace = async (args) => { executed = true; return makeFakeHttpScan()(args); };
    const out = await verifyCompositionPath(
      { target_domain: DOMAIN, base_url: BASE_URL, path: [guardLeaf(eventId)] },
      { httpScanFn: trace },
    );
    assert.equal(out.result, RESULT_OFFLINE_REFUSED);
    assert.equal(out.offline_result, "fail");
    assert.equal(executed, false); // never re-executes an unshaped path
  });
});

test("NO-TEMPLATE RAIL: a non-guard (sink) leaf with no registered template returns inconclusive — never verified_pass, never a producer-string fallback", async () => {
  await withTempHome(async () => {
    const eventId = seedGuardObservation(DOMAIN, "sink"); // shape-valid sink observation
    const out = await verifyCompositionPath(
      { target_domain: DOMAIN, base_url: BASE_URL, path: [guardLeaf(eventId)] },
      { httpScanFn: makeFakeHttpScan() },
    );
    assert.equal(out.result, RESULT_INCONCLUSIVE);
    assert.equal(out.verified_leaf_count, 0);
    assert.equal(out.leaves[0].leaf_status, "inconclusive");
    assert.match(out.leaves[0].reason, /no registered verifier template/);
  });
});

test("INTEGRITY (F1 closure): the verified ledger is audit-graded so agents cannot Write-forge a verified_pass", async () => {
  await withTempHome(() => {
    assert.equal(isAuditGradedPath(compositionVerifiedJsonlPath(DOMAIN), DOMAIN), true);
    // The advisory frontier stream is NOT the grading source; the ledger is.
  });
});

test("BINDING (Finding 1): a control plan aimed at a DIFFERENT object than the leaf's is inconclusive, not verified", async () => {
  await withTempHome(async () => {
    const eventId = seedGuardObservation(DOMAIN); // offline leaf names /api/objects/victim
    // The agent points the live plan at an unrelated authenticated endpoint.
    const leaf = guardLeaf(eventId);
    leaf.primary = { method: "GET", url: "/api/me", auth_profile: "attacker" };
    const drifted = makeFakeHttpScan({ "attacker https://example.com/api/me": ok(ATTACKER_BODY) });
    const out = await verifyCompositionPath(
      { target_domain: DOMAIN, base_url: BASE_URL, path: [leaf] },
      { httpScanFn: drifted },
    );
    assert.equal(out.result, RESULT_INCONCLUSIVE);
    assert.equal(out.verified_leaf_count, 0);
    assert.match(out.leaves[0].reason, /same-object battery bound to the leaf/);
  });
});

test("QUERY-SELECTOR (Finding 2 fix): a same-path query-id IDOR verifies — DIFF controls differ by query, not path", async () => {
  await withTempHome(async () => {
    const eventId = seedGuardObservation(DOMAIN, "guard", "/api/document?id=victim");
    const out = await verifyCompositionPath(
      { target_domain: DOMAIN, base_url: BASE_URL, path: [docLeaf(eventId)] },
      { httpScanFn: makeDocFakeHttpScan() },
    );
    assert.equal(out.result, RESULT_VERIFIED_PASS);
    assert.equal(out.leaves[0].leaf_status, "verified");
  });
});

test("QUERY BINDING (Finding 1 fix): a primary swapped to a different ?id than the offline leaf is inconclusive", async () => {
  await withTempHome(async () => {
    const eventId = seedGuardObservation(DOMAIN, "guard", "/api/document?id=victim");
    const leaf = docLeaf(eventId);
    leaf.primary = { method: "GET", url: "/api/document?id=other", auth_profile: "attacker" };
    const out = await verifyCompositionPath(
      { target_domain: DOMAIN, base_url: BASE_URL, path: [leaf] },
      { httpScanFn: makeDocFakeHttpScan() },
    );
    assert.equal(out.result, RESULT_INCONCLUSIVE);
    assert.match(out.leaves[0].reason, /victim object/);
  });
});

test("KEY COLLISION (round-3 Finding 1): a duplicate-param reordering of the object key is inconclusive, not a collision", async () => {
  await withTempHome(async () => {
    const eventId = seedGuardObservation(DOMAIN, "guard", "/api/document?id=victim");
    const leaf = docLeaf(eventId);
    // Duplicate-param trick: raw key differs from the offline leaf, so a last-wins
    // backend object cannot be credited to this leaf.
    leaf.primary = { method: "GET", url: "/api/document?id=other&id=victim", auth_profile: "attacker" };
    const out = await verifyCompositionPath(
      { target_domain: DOMAIN, base_url: BASE_URL, path: [leaf] },
      { httpScanFn: makeDocFakeHttpScan() },
    );
    assert.equal(out.result, RESULT_INCONCLUSIVE);
    assert.match(out.leaves[0].reason, /victim object/);
  });
});

test("CACHE-NONCE OVERRIDE (round-3 Finding 2): a cache_nonce that duplicates the selector key is inconclusive", async () => {
  await withTempHome(async () => {
    const eventId = seedGuardObservation(DOMAIN, "guard", "/api/document?id=victim");
    const leaf = docLeaf(eventId);
    leaf.control_plan = leaf.control_plan.map((c) =>
      c.control === "cache_nonce_check"
        ? { ...c, url: "/api/document?id=victim&id=attacker&cb=1" }
        : c);
    const out = await verifyCompositionPath(
      { target_domain: DOMAIN, base_url: BASE_URL, path: [leaf] },
      { httpScanFn: makeDocFakeHttpScan() },
    );
    assert.equal(out.result, RESULT_INCONCLUSIVE);
    assert.match(out.leaves[0].reason, /cache_nonce_check must target the same victim object/);
  });
});

test("OFFLINE ORIGIN (round-4 Finding 1): an offline leaf naming a different first-party host is inconclusive", async () => {
  await withTempHome(async () => {
    // The offline observation names debug.example.com; the live plan runs on app's origin.
    const eventId = seedGuardObservation(DOMAIN, "guard", "https://debug.example.com/api/document?id=victim");
    const out = await verifyCompositionPath(
      { target_domain: DOMAIN, base_url: BASE_URL, path: [docLeaf(eventId)] },
      { httpScanFn: makeDocFakeHttpScan() },
    );
    assert.equal(out.result, RESULT_INCONCLUSIVE);
    assert.match(out.leaves[0].reason, /different origin/);
  });
});

test("CACHE-NONCE ENCODED-KEY (round-4 Finding 2): a percent-encoded duplicate selector key is rejected", async () => {
  await withTempHome(async () => {
    const eventId = seedGuardObservation(DOMAIN, "guard", "/api/document?id=victim");
    const leaf = docLeaf(eventId);
    // i%64 decodes to "id" — a name-decoding last-wins backend would serve attacker.
    leaf.control_plan = leaf.control_plan.map((c) =>
      c.control === "cache_nonce_check"
        ? { ...c, url: "/api/document?id=victim&i%64=attacker&cb=1" }
        : c);
    const out = await verifyCompositionPath(
      { target_domain: DOMAIN, base_url: BASE_URL, path: [leaf] },
      { httpScanFn: makeDocFakeHttpScan() },
    );
    assert.equal(out.result, RESULT_INCONCLUSIVE);
    assert.match(out.leaves[0].reason, /cache_nonce_check must target the same victim object/);
  });
});

test("PRINCIPAL (Finding 2): attacker == victim profile is inconclusive — no cross-principal differential", async () => {
  await withTempHome(async () => {
    const eventId = seedGuardObservation(DOMAIN);
    const leaf = guardLeaf(eventId);
    // Collapse the victim principal into the attacker's — "attacker reads its own object".
    leaf.control_plan = leaf.control_plan.map((c) =>
      c.control === "victim_auth_same_object" ? { ...c, auth_profile: "attacker" } : c);
    const out = await verifyCompositionPath(
      { target_domain: DOMAIN, base_url: BASE_URL, path: [leaf] },
      { httpScanFn: makeFakeHttpScan() },
    );
    assert.equal(out.result, RESULT_INCONCLUSIVE);
    assert.match(out.leaves[0].reason, /DISTINCT principal/);
  });
});

test("ORIGIN (Finding 4): a control drifting to a different first-party host is inconclusive", async () => {
  await withTempHome(async () => {
    const eventId = seedGuardObservation(DOMAIN);
    const leaf = guardLeaf(eventId);
    // nonexistent_object drifts to a sibling first-party host (debug.example.com).
    leaf.control_plan = leaf.control_plan.map((c) =>
      c.control === "nonexistent_object" ? { ...c, url: "https://debug.example.com/api/objects/ghost" } : c);
    const out = await verifyCompositionPath(
      { target_domain: DOMAIN, base_url: BASE_URL, path: [leaf] },
      { httpScanFn: makeFakeHttpScan() },
    );
    assert.equal(out.result, RESULT_INCONCLUSIVE);
    assert.match(out.leaves[0].reason, /different origin/);
  });
});

test("SC1 GRADING (LV-3): a shape-pass-only session reports verified_pass_count:0 — SC1 not satisfied", async () => {
  await withTempHome(async () => {
    // A fresh session with no verified ledger.
    const summary = readCompositionVerifiedSummary(DOMAIN);
    assert.equal(summary.verified_pass_count, 0);
    assert.equal(summary.sc1_confirm_half_satisfied, false);
    assert.equal(summary.last_verified_path_hash, null);
    assert.deepEqual(summary.verified_path_hashes, []);
  });
});

test("SC1 GRADING (LV-3): a live verified_pass advances the count and binds the path_hash", async () => {
  await withTempHome(async () => {
    const eventId = seedGuardObservation(DOMAIN);
    const out = await verifyCompositionPath(
      { target_domain: DOMAIN, base_url: BASE_URL, path: [guardLeaf(eventId)] },
      { httpScanFn: makeFakeHttpScan() },
    );
    assert.equal(out.result, RESULT_VERIFIED_PASS);
    const summary = readCompositionVerifiedSummary(DOMAIN);
    assert.equal(summary.verified_pass_count, 1);
    assert.equal(summary.sc1_confirm_half_satisfied, true);
    assert.equal(summary.last_verified_path_hash, out.path_hash);
    // The authoritative per-path membership set carries this executed hash, drawn
    // from the SAME verified rows as the count (no recomputation).
    assert.deepEqual(summary.verified_path_hashes, [out.path_hash]);
  });
});

test("SC1 GRADING (LV-3): verified_path_hashes holds EVERY executed verified_pass hash (precise binding source)", async () => {
  await withTempHome(async () => {
    // First verified path: a guard-leaf object IDOR.
    const guardEventId = seedGuardObservation(DOMAIN);
    const first = await verifyCompositionPath(
      { target_domain: DOMAIN, base_url: BASE_URL, path: [guardLeaf(guardEventId)] },
      { httpScanFn: makeFakeHttpScan() },
    );
    // Second verified path: a query-selected document IDOR → a distinct path_hash.
    const docEventId = seedGuardObservation(DOMAIN, "guard", "/api/document?id=victim");
    const second = await verifyCompositionPath(
      { target_domain: DOMAIN, base_url: BASE_URL, path: [docLeaf(docEventId)] },
      { httpScanFn: makeDocFakeHttpScan() },
    );
    assert.equal(first.result, RESULT_VERIFIED_PASS);
    assert.equal(second.result, RESULT_VERIFIED_PASS);
    assert.notEqual(first.path_hash, second.path_hash);
    const summary = readCompositionVerifiedSummary(DOMAIN);
    assert.equal(summary.verified_pass_count, 2);
    // Both executed hashes are members, not just the last — this is what lets the
    // consumer bind a non-last path precisely instead of via the coarse last hash.
    assert.ok(summary.verified_path_hashes.includes(first.path_hash));
    assert.ok(summary.verified_path_hashes.includes(second.path_hash));
    assert.equal(summary.last_verified_path_hash, second.path_hash);
  });
});

test("SC1 GRADING (LV-3): a refuted counterfeit does NOT advance verified_pass_count", async () => {
  await withTempHome(async () => {
    const eventId = seedGuardObservation(DOMAIN);
    const patched = makeFakeHttpScan({ "attacker https://example.com/api/objects/victim": blocked(403) });
    await verifyCompositionPath(
      { target_domain: DOMAIN, base_url: BASE_URL, path: [guardLeaf(eventId)] },
      { httpScanFn: patched },
    );
    const summary = readCompositionVerifiedSummary(DOMAIN);
    assert.equal(summary.verified_pass_count, 0);
    assert.equal(summary.refuted_count, 1);
    assert.equal(summary.sc1_confirm_half_satisfied, false);
  });
});

test("REGISTRY: bob_verify_composition_path is a scoped, network-capable orchestrator tool", () => {
  const tool = TOOL_MANIFEST.bob_verify_composition_path;
  assert.ok(tool, "tool registered");
  assert.equal(tool.network_access, true);
  assert.equal(tool.scope_required, true);
  assert.deepEqual(tool.scope_url_fields, ["base_url"]);
  assert.ok(tool.session_artifacts_written.includes("composition-verified.jsonl"));
});
