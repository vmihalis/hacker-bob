"use strict";

// ─────────────────────────────────────────────────────────────────────────────
// OFFLINE firing-rate measurement for the bob_http_idor_confirm signed-row
// PRODUCER (mcp/lib/offensive-idor-producer.js).
//
// WHY this exists: a red-team (wf_64d80847-da6) warned the oracle may fire on only
// a low-single-digit-% of real IDORs. That number was unmeasurable — no live IDOR
// had ever fed the oracle. This harness converts "will it ever fire?" into DATA by
// driving the FULL oracle through its existing injected-`fetch_fn`/`provision` seam
// (the same seam the 96 unit tests use), against a corpus whose response semantics
// are transcribed from known-true IDOR/BOLA targets. No live target, no signup, no
// real PII. The output is a per-gate block-reason histogram that tells us WHICH
// gates kill real IDORs, so we demote the over-strict ones FROM THE DATA.
//
// FIDELITY DISCIPLINE (per the measurement design): the corpus fetch_fns encode the
// DOCUMENTED behaviour of crAPI / VAmPI / PortSwigger (status codes, auth-or-not,
// whether a third tenant is denied, whether a tenant key is echoed, JSON-or-text),
// NOT a live observation in this run. The narrow-tenant fixtures are explicitly
// SYNTHETIC constructs that isolate one gate each. Live docker validation (crAPI +
// VAmPI) is the planned follow-up; until then read recall as "documented-semantics
// recall", and never tune a gate so a fixture passes — that makes the histogram
// self-fulfilling.
//
// Run: node scripts/measure-idor-oracle.js
// ─────────────────────────────────────────────────────────────────────────────

const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { idorConfirm } = require("../mcp/lib/offensive-idor-producer.js");
const { initSession } = require("../mcp/lib/session-state.js");
const { routeSurfaces } = require("../mcp/lib/surface-router.js");
const { writeAuthFile, resolveAuthJsonPath } = require("../mcp/lib/auth.js");
const { ensureHandoffSigningKey } = require("../mcp/lib/handoff-signing-key.js");
const { attackSurfacePath } = require("../mcp/lib/paths.js");
const { readOffensiveRunRecords } = require("../mcp/lib/claims.js");

// Distinct 256-bit hex canaries (pass /^[0-9a-f]{64}$/, pairwise-distinct).
const CANARY_A = "a".repeat(64);
const CANARY_B = "b".repeat(64);
const CANARY_C = "c".repeat(64);

// Server-minted ids (clean single path segments, canary-disjoint).
const OBJ_A = "obj-a-100";
const OBJ_B = "obj-b-200";
const OBJ_C = "obj-c-300";

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-idor-measure-"));
  process.env.HOME = home;
  return Promise.resolve()
    .then(() => fn(home))
    .finally(() => {
      if (previousHome === undefined) delete process.env.HOME;
      else process.env.HOME = previousHome;
      fs.rmSync(home, { recursive: true, force: true });
    });
}

function seedRoutedSurface(domain, surfaceId, endpoint) {
  fs.mkdirSync(path.dirname(attackSurfacePath(domain)), { recursive: true });
  fs.writeFileSync(attackSurfacePath(domain), `${JSON.stringify({
    surfaces: [{
      id: surfaceId,
      title: "Corpus API surface",
      surface_type: "web",
      hosts: [domain],
      endpoints: [endpoint],
      tech_stack: ["fixture"],
      priority: "HIGH",
    }],
  }, null, 2)}\n`, "utf8");
  JSON.parse(routeSurfaces({ target_domain: domain }));
}

function seedSyntheticProfiles(domain) {
  const flags = { synthetic: true, email_origin: "temp_email", provisioned_via: "bob_auto_signup" };
  const mk = (tag) => ({ Authorization: `Bearer eyJ${tag}token`, email: `eval_${tag}@example.test`, ...flags });
  writeAuthFile(resolveAuthJsonPath(domain), `${JSON.stringify({
    version: 2,
    profiles: { identity_a: mk("a"), identity_b: mk("b"), identity_c: mk("c") },
  }, null, 2)}\n`);
}

function setupSession(domain, { surfaceId, endpoint }) {
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}/` }));
  seedRoutedSurface(domain, surfaceId, endpoint);
  seedSyntheticProfiles(domain);
  ensureHandoffSigningKey(domain);
}

// A JSON resource body with REAL per-viewer variance (so two reads by the SAME
// viewer are byte-identical — P0 stable — while different viewers differ) and the
// canary at a nested leaf details.secret.token. `scope` is OMITTED when falsy
// (models an API that echoes no owning-scope key → #13 own_scope_not_private).
function resourceBody({ canary, scope, viewer, objId, includeCanary = true }) {
  const seed = crypto.createHash("sha256").update(`${viewer}|${objId}`).digest("hex");
  const body = {
    id: objId,
    kind: "account",
    name: "synthetic record",
    viewer_id: viewer,
    server_ts: `2026-06-16T00:00:${seed.slice(0, 2)}.${seed.slice(2, 5)}Z`,
    csrf: seed.slice(0, 16),
    details: { secret: { token: includeCanary ? canary : "no-canary" } },
  };
  if (scope) body.owner_scope = scope;
  return body;
}

function jsonResponse(status, bodyObj, headers = {}) {
  const lower = {};
  for (const [k, v] of Object.entries(headers)) lower[String(k).toLowerCase()] = v;
  const body = typeof bodyObj === "string" ? bodyObj : JSON.stringify(bodyObj);
  const bytes = Buffer.from(body, "utf8");
  return {
    status,
    headers: { get(name) { return lower[String(name).toLowerCase()] ?? null; } },
    bodyBytes: bytes,
    bodyByteLength: bytes.length,
    bodyTruncated: false,
  };
}

function textResponse(status, text) {
  const bytes = Buffer.from(text, "utf8");
  return {
    status,
    headers: { get() { return null; } },
    bodyBytes: bytes,
    bodyByteLength: bytes.length,
    bodyTruncated: false,
  };
}

function challenge(status = 403) {
  const bytes = Buffer.from(JSON.stringify({ error: "forbidden" }), "utf8");
  return { status, headers: { get: () => null }, bodyBytes: bytes, bodyByteLength: bytes.length, bodyTruncated: false };
}

function whoAndWhat(url, headers) {
  const auth = headers && headers.Authorization ? String(headers.Authorization) : "";
  const u = new URL(url);
  return {
    isA: auth.includes("eyJatoken"),
    isB: auth.includes("eyJbtoken"),
    isC: auth.includes("eyJctoken"),
    anon: !auth,
    wantsOB: u.pathname.includes(OBJ_B),
    wantsOA: u.pathname.includes(OBJ_A),
    wantsOC: u.pathname.includes(OBJ_C),
  };
}

function provisionFor({ readbackScope = "tenant-B" } = {}) {
  const readback = { id: OBJ_B, details: { secret: { token: CANARY_B } } };
  if (readbackScope) readback.owner_scope = readbackScope;
  return {
    object_a: OBJ_A, object_b: OBJ_B, object_c: OBJ_C,
    canary_a: CANARY_A, canary_b: CANARY_B, canary_c: CANARY_C,
    owner_readback_b: readback,
  };
}

function baseArgs(domain, surfaceId, pathTemplate) {
  return {
    target_domain: domain,
    surface_id: surfaceId,
    oracle_kind: "differential_response",
    path_template: pathTemplate,
    method: "GET",
    identity_a_profile: "identity_a",
    identity_b_profile: "identity_b",
    identity_c_profile: "identity_c",
  };
}

// Standard "C authenticates" legs shared by the fixtures that reach P5+: O_C is
// auth-gated (anon P8 → 401) and C reads its own O_C → 200 + canary_c. Returns a
// response if the request is for O_C, else null (caller handles O_A/O_B).
function ocLegs({ isC, anon, wantsOC }) {
  if (!wantsOC) return null;
  if (anon) return challenge(401); // P8: anon read of O_C → denied
  if (isC) return jsonResponse(200, resourceBody({ canary: CANARY_C, scope: "tenant-C", viewer: "viewer-C", objId: OBJ_C }));
  return challenge(403); // A/B reading O_C → partitioned
}

// ───────────────────────────── THE CORPUS ──────────────────────────────────
// Each fixture transcribes one target's read semantics. `predicted` is my model's
// hypothesis for the gate that fires; a mismatch is itself a finding (bad model or
// bad fixture). known_true + in_scope drive the recall denominator.

const CORPUS = [
  {
    id: "T1", name: "crAPI orders /workshop/api/shop/orders/{id}",
    klass: "true-idor", fidelity: "documented", known_true: true, in_scope: true,
    pathTemplate: "/workshop/api/shop/orders/{id}",
    endpointPath: `/workshop/api/shop/orders/${OBJ_B}`,
    note: "Authed BOLA, authorization MISSING globally → ANY authenticated user reads any order by id. So a third tenant C can also read O_B.",
    predicted: "p5_authenticated_shared",
    fetchFn: (domain) => async ({ url, headers }) => {
      const w = whoAndWhat(url, headers);
      if (w.anon) return challenge(401); // orders require auth
      const oc = ocLegs(w);
      if (oc) return oc;
      if (w.wantsOB) {
        const viewer = w.isB ? "viewer-B" : w.isA ? "viewer-A" : "viewer-C";
        return jsonResponse(200, resourceBody({ canary: CANARY_B, scope: "tenant-B", viewer, objId: OBJ_B }));
      }
      if (w.wantsOA) {
        const viewer = w.isA ? "viewer-A" : w.isB ? "viewer-B" : "viewer-C";
        return jsonResponse(200, resourceBody({ canary: CANARY_A, scope: "tenant-A", viewer, objId: OBJ_A }));
      }
      return challenge(404);
    },
    provision: () => provisionFor(),
  },
  {
    id: "T2", name: "VAmPI users /users/v1/{id}",
    klass: "true-idor", fidelity: "documented", known_true: true, in_scope: true,
    pathTemplate: "/users/v1/{id}",
    endpointPath: `/users/v1/${OBJ_B}`,
    note: "VAmPI user-read is UNAUTHENTICATED → anon can read any user record by id. The object is effectively public.",
    predicted: "canary_leaked_unauthenticated",
    fetchFn: (domain) => async ({ url, headers }) => {
      const w = whoAndWhat(url, headers); // everything public (no auth)
      if (w.wantsOB) {
        const viewer = w.isB ? "viewer-B" : w.isA ? "viewer-A" : w.isC ? "viewer-C" : "viewer-anon";
        return jsonResponse(200, resourceBody({ canary: CANARY_B, scope: "tenant-B", viewer, objId: OBJ_B }));
      }
      if (w.wantsOA) {
        const viewer = w.isA ? "viewer-A" : "viewer-other";
        return jsonResponse(200, resourceBody({ canary: CANARY_A, scope: "tenant-A", viewer, objId: OBJ_A }));
      }
      if (w.wantsOC) {
        const viewer = w.isC ? "viewer-C" : "viewer-other";
        return jsonResponse(200, resourceBody({ canary: CANARY_C, scope: "tenant-C", viewer, objId: OBJ_C }));
      }
      return challenge(404);
    },
    provision: () => provisionFor(),
  },
  {
    id: "T3", name: "PortSwigger transcript /download-transcript/{id} (text/plain)",
    klass: "true-idor", fidelity: "documented", known_true: true, in_scope: true,
    pathTemplate: "/download-transcript/{id}",
    endpointPath: `/download-transcript/${OBJ_B}`,
    note: "A genuine A-only IDOR but the endpoint returns text/plain (a transcript), not JSON — a very common real shape (CSV/PDF/TXT exports).",
    predicted: "body_not_parseable",
    fetchFn: (domain) => async ({ url, headers }) => {
      const w = whoAndWhat(url, headers);
      if (w.anon) return challenge(401);
      const oc = ocLegs(w);
      if (oc) return oc;
      if (w.wantsOB) {
        // A and B can both read O_B; C cannot (narrow). Body is plain text w/ canary.
        if (w.isC) return challenge(403);
        const viewer = w.isB ? "viewer-B" : "viewer-A";
        return textResponse(200, `Transcript for ${OBJ_B} viewer=${viewer}\ntoken: ${CANARY_B}\n`);
      }
      if (w.wantsOA) {
        if (w.isA) return textResponse(200, `Transcript for ${OBJ_A} viewer=viewer-A\ntoken: ${CANARY_A}\n`);
        return challenge(403);
      }
      return challenge(404);
    },
    provision: () => provisionFor(),
  },
  {
    id: "T4", name: "PortSwigger user_id query param /my-account?id={id}",
    klass: "true-idor", fidelity: "documented", known_true: true, in_scope: false,
    pathTemplate: "/my-account?id={id}",
    endpointPath: "/my-account",
    note: "Classic IDOR but keyed by a QUERY param, not a path segment. v1 path_template requires {id} as the final PATH segment → structurally out of scope.",
    predicted: "THROW:path_template",
    fetchFn: (domain) => async () => challenge(404),
    provision: () => provisionFor(),
  },
  {
    id: "T5", name: "narrow tenant-isolation IDOR /api/accounts/{id} (full tenant keys)",
    klass: "true-idor", fidelity: "synthetic", known_true: true, in_scope: true,
    pathTemplate: "/api/accounts/{id}",
    endpointPath: `/api/accounts/${OBJ_B}`,
    note: "The oracle's INTENDED class: A (org-A) reads org-B's PRIVATE record cross-tenant; anon denied, third tenant C denied, partition symmetric, both A and B echo owner_scope. Should FIRE.",
    predicted: "FIRE",
    fetchFn: (domain) => async ({ url, headers }) => {
      const w = whoAndWhat(url, headers);
      if (w.anon) return challenge(403);
      const oc = ocLegs(w);
      if (oc) return oc;
      if (w.wantsOB) {
        if (w.isB) return jsonResponse(200, resourceBody({ canary: CANARY_B, scope: "tenant-B", viewer: "viewer-B", objId: OBJ_B }));
        if (w.isA) return jsonResponse(200, resourceBody({ canary: CANARY_B, scope: "tenant-B", viewer: "viewer-A", objId: OBJ_B }));
        if (w.isC) return challenge(403); // third tenant denied → true cross-tenant
      }
      if (w.wantsOA) {
        if (w.isA) return jsonResponse(200, resourceBody({ canary: CANARY_A, scope: "tenant-A", viewer: "viewer-A", objId: OBJ_A }));
        return challenge(403); // B reading A's object → partitioned
      }
      return challenge(404);
    },
    provision: () => provisionFor(),
  },
  {
    id: "T6", name: "narrow tenant-isolation IDOR, NO owner_scope key echoed",
    klass: "true-idor", fidelity: "synthetic", known_true: true, in_scope: true,
    pathTemplate: "/api/records/{id}",
    endpointPath: `/api/records/${OBJ_B}`,
    note: "Identical A-only IDOR to T5 but the API echoes NO owning-scope key in the body — the only difference. Now FIRES carrying BOTH #13 (own_scope_not_private) and #14 (identities_collided) as non-blocking confidence signals.",
    predicted: "FIRE",
    expected_signals: ["identities_collided_not_provable", "own_scope_not_private"],
    fetchFn: (domain) => async ({ url, headers }) => {
      const w = whoAndWhat(url, headers);
      if (w.anon) return challenge(403);
      const oc = ocLegs(w);
      if (oc) return oc;
      if (w.wantsOB) {
        if (w.isB) return jsonResponse(200, resourceBody({ canary: CANARY_B, scope: null, viewer: "viewer-B", objId: OBJ_B }));
        if (w.isA) return jsonResponse(200, resourceBody({ canary: CANARY_B, scope: null, viewer: "viewer-A", objId: OBJ_B }));
        if (w.isC) return challenge(403);
      }
      if (w.wantsOA) {
        if (w.isA) return jsonResponse(200, resourceBody({ canary: CANARY_A, scope: null, viewer: "viewer-A", objId: OBJ_A }));
        return challenge(403);
      }
      return challenge(404);
    },
    provision: () => provisionFor({ readbackScope: null }),
  },
  {
    id: "T7", name: "narrow tenant-isolation IDOR, B echoes a tenant key but A's object does not",
    klass: "true-idor", fidelity: "synthetic", known_true: true, in_scope: true,
    pathTemplate: "/api/objects/{id}",
    endpointPath: `/api/objects/${OBJ_B}`,
    note: "A-only IDOR; O_B echoes owner_scope (passes #13) but A's own object O_A echoes no tenant key, so A and B can't be shown distinct at the same key. Now FIRES carrying a #14 (identities_collided) confidence signal.",
    predicted: "FIRE",
    expected_signals: ["identities_collided_not_provable"],
    fetchFn: (domain) => async ({ url, headers }) => {
      const w = whoAndWhat(url, headers);
      if (w.anon) return challenge(403);
      const oc = ocLegs(w);
      if (oc) return oc;
      if (w.wantsOB) {
        if (w.isB) return jsonResponse(200, resourceBody({ canary: CANARY_B, scope: "tenant-B", viewer: "viewer-B", objId: OBJ_B }));
        if (w.isA) return jsonResponse(200, resourceBody({ canary: CANARY_B, scope: "tenant-B", viewer: "viewer-A", objId: OBJ_B }));
        if (w.isC) return challenge(403);
      }
      if (w.wantsOA) {
        if (w.isA) return jsonResponse(200, resourceBody({ canary: CANARY_A, scope: null, viewer: "viewer-A", objId: OBJ_A }));
        return challenge(403);
      }
      return challenge(404);
    },
    provision: () => provisionFor(),
  },
  {
    id: "C1", name: "CONTROL: public catalog /api/products/{id} (anon-readable)",
    klass: "control", fidelity: "documented", known_true: false, in_scope: true,
    pathTemplate: "/api/products/{id}",
    endpointPath: `/api/products/${OBJ_B}`,
    note: "Shared-by-design public object — NOT an IDOR. The oracle must NOT mint (anon can read it).",
    predicted: "canary_leaked_unauthenticated",
    fetchFn: (domain) => async ({ url, headers }) => {
      const w = whoAndWhat(url, headers); // public
      if (w.wantsOB) return jsonResponse(200, resourceBody({ canary: CANARY_B, scope: "catalog", viewer: "any", objId: OBJ_B }));
      if (w.wantsOA) return jsonResponse(200, resourceBody({ canary: CANARY_A, scope: "catalog", viewer: "any", objId: OBJ_A }));
      if (w.wantsOC) return jsonResponse(200, resourceBody({ canary: CANARY_C, scope: "catalog", viewer: "any", objId: OBJ_C }));
      return challenge(404);
    },
    provision: () => provisionFor({ readbackScope: "catalog" }),
  },
  {
    id: "C2", name: "CONTROL: authenticated-shared doc /api/documents/{id} (all org members read)",
    klass: "control", fidelity: "synthetic", known_true: false, in_scope: true,
    pathTemplate: "/api/documents/{id}",
    endpointPath: `/api/documents/${OBJ_B}`,
    note: "Shared-to-all-authenticated by design — NOT an IDOR. anon denied, but a third tenant C CAN read it. The oracle must NOT mint.",
    predicted: "p5_authenticated_shared",
    fetchFn: (domain) => async ({ url, headers }) => {
      const w = whoAndWhat(url, headers);
      if (w.anon) return challenge(403);
      // O_C legs so C is provably authenticated, then C can also read O_B (by design).
      if (w.wantsOC) {
        if (w.isC) return jsonResponse(200, resourceBody({ canary: CANARY_C, scope: "tenant-C", viewer: "viewer-C", objId: OBJ_C }));
        return challenge(403);
      }
      if (w.wantsOB) {
        const viewer = w.isB ? "viewer-B" : w.isA ? "viewer-A" : "viewer-C";
        return jsonResponse(200, resourceBody({ canary: CANARY_B, scope: "tenant-B", viewer, objId: OBJ_B }));
      }
      if (w.wantsOA) {
        if (w.isA) return jsonResponse(200, resourceBody({ canary: CANARY_A, scope: "tenant-A", viewer: "viewer-A", objId: OBJ_A }));
        return challenge(403);
      }
      return challenge(404);
    },
    provision: () => provisionFor(),
  },
  {
    id: "C3", name: "CONTROL: PROVABLY same tenant (A and B share owner_scope) — Codex P2 guard",
    klass: "control", fidelity: "synthetic", known_true: false, in_scope: true,
    pathTemplate: "/api/items/{id}",
    endpointPath: `/api/items/${OBJ_B}`,
    note: "A reads O_B's canary and anon + 3rd-tenant C are denied, BUT O_B and O_A both report the SAME owner_scope value — A and B are PROVABLY one tenant. NOT a cross-tenant IDOR; #14 must HARD-block (not demote to a signal). Locks the Codex P2 fix.",
    predicted: "identities_collided_same_tenant",
    fetchFn: (domain) => async ({ url, headers }) => {
      const w = whoAndWhat(url, headers);
      if (w.anon) return challenge(403);
      const oc = ocLegs(w);
      if (oc) return oc;
      if (w.wantsOB) {
        if (w.isB) return jsonResponse(200, resourceBody({ canary: CANARY_B, scope: "tenant-same", viewer: "viewer-B", objId: OBJ_B }));
        if (w.isA) return jsonResponse(200, resourceBody({ canary: CANARY_B, scope: "tenant-same", viewer: "viewer-A", objId: OBJ_B }));
        if (w.isC) return challenge(403);
      }
      if (w.wantsOA) {
        if (w.isA) return jsonResponse(200, resourceBody({ canary: CANARY_A, scope: "tenant-same", viewer: "viewer-A", objId: OBJ_A }));
        return challenge(403);
      }
      return challenge(404);
    },
    provision: () => provisionFor({ readbackScope: "tenant-same" }),
  },
];

const GATE_LABEL = {
  p5_authenticated_shared: "#11 authenticated-but-shared exclusion (a 3rd tenant C can also read O_B)",
  canary_leaked_unauthenticated: "#9 anon read of O_B leaks the canary (object is public)",
  body_not_parseable: "#2 P1/P2 body is not JSON (text/CSV/PDF export)",
  own_scope_not_private: "#13 P1 echoes no private owning-scope key",
  identities_collided_not_provable: "#14 A and B not distinguishable at the same tenant key (unprovable)",
  identities_collided_same_tenant: "#14 A and B PROVABLY the same tenant (positive evidence against cross-tenant)",
  object_not_access_controlled: "#10 anon read of O_B is not 401/403",
  "p5_not_found_ambiguous": "#11 a 3rd tenant C gets 404 (existence-ambiguous)",
};

async function runFixture(fx) {
  const domain = `${fx.id.toLowerCase()}.measure.test`;
  return withTempHome(async () => {
    setupSession(domain, { surfaceId: `surface:${fx.id}`, endpoint: `https://${domain}${fx.endpointPath}` });
    const args = baseArgs(domain, `surface:${fx.id}`, fx.pathTemplate);
    try {
      const result = await idorConfirm(args, { fetch_fn: fx.fetchFn(domain), provision: fx.provision() });
      if (result && result.confirmed === true && result.row_written === true) {
        const rows = readOffensiveRunRecords(domain);
        const signals = Array.isArray(result.confidence_signals) ? result.confidence_signals.map((s) => s.gate) : [];
        return { outcome: "FIRE", detail: `${result.demonstrated_severity} row, ${rows.length} row(s), signals=[${signals.join(",")}]`, severity: result.demonstrated_severity, signals };
      }
      return { outcome: result.reason || result.offensive_outcome || "non-fire", detail: result.offensive_outcome || "" };
    } catch (err) {
      return { outcome: `THROW:${err && err.code ? err.code : "?"}`, detail: (err && err.message ? err.message : String(err)).slice(0, 120) };
    }
  });
}

function matches(predicted, actual) {
  if (predicted === "FIRE") return actual === "FIRE";
  if (predicted.startsWith("THROW:")) return actual.startsWith("THROW:");
  return actual === predicted;
}

(async () => {
  const results = [];
  for (const fx of CORPUS) {
    // eslint-disable-next-line no-await-in-loop
    const r = await runFixture(fx);
    results.push({ fx, r });
  }

  const W = (s, n) => String(s).padEnd(n).slice(0, n);
  console.log("");
  console.log("══════════════════════════════════════════════════════════════════════════════");
  console.log("  bob_http_idor_confirm — OFFLINE firing-rate measurement (v1, documented-semantics)");
  console.log("══════════════════════════════════════════════════════════════════════════════");
  console.log("  Drives the FULL oracle via its injected fetch_fn/provision seam. No live target.");
  console.log("  Fidelity: crAPI/VAmPI/PortSwigger = transcribed documented semantics (pending live");
  console.log("  docker validation); narrow-tenant T5/T6/T7 = synthetic gate-isolation constructs.");
  console.log("");
  console.log(`  ${W("FIXTURE", 56)} ${W("PREDICTED", 30)} ${W("ACTUAL", 30)} OK`);
  console.log(`  ${"-".repeat(56)} ${"-".repeat(30)} ${"-".repeat(30)} --`);
  for (const { fx, r } of results) {
    const ok = matches(fx.predicted, r.outcome) ? "✓" : "✗";
    const tag = fx.klass === "control" ? "[ctrl]" : fx.in_scope ? "[true]" : "[oos ]";
    console.log(`  ${tag} ${W(fx.id + " " + fx.name, 49)} ${W(fx.predicted, 30)} ${W(r.outcome, 30)} ${ok}`);
  }

  const inScopeTrue = results.filter(({ fx }) => fx.known_true && fx.in_scope);
  const fires = results.filter(({ r }) => r.outcome === "FIRE");
  const trueFires = inScopeTrue.filter(({ r }) => r.outcome === "FIRE");
  const controls = results.filter(({ fx }) => fx.klass === "control");
  const controlFires = controls.filter(({ r }) => r.outcome === "FIRE");
  const oos = results.filter(({ fx }) => fx.known_true && !fx.in_scope);
  const predOk = results.filter(({ fx, r }) => matches(fx.predicted, r.outcome)).length;

  console.log("");
  console.log("  ── METRICS ───────────────────────────────────────────────────────────────");
  console.log(`  RECALL (in-scope known-true IDOR)  : ${trueFires.length}/${inScopeTrue.length}  = ${(100 * trueFires.length / inScopeTrue.length).toFixed(1)}%`);
  const prec = fires.length === 0 ? "n/a (0 mints)" : `${(100 * trueFires.length / fires.length).toFixed(1)}%`;
  console.log(`  PRECISION (mints that are real)    : ${prec}   [false mints on controls: ${controlFires.length}/${controls.length}]`);
  console.log(`  OUT-OF-SCOPE by path shape         : ${oos.length}  (counted separately, not in recall)`);
  console.log(`  MODEL ACCURACY (predicted == actual): ${predOk}/${results.length}`);

  console.log("");
  console.log("  ── BLOCK-REASON HISTOGRAM (in-scope known-true IDOR misses) ────────────────");
  const hist = {};
  for (const { fx, r } of inScopeTrue) {
    if (r.outcome === "FIRE") continue;
    hist[r.outcome] = (hist[r.outcome] || 0) + 1;
  }
  const sorted = Object.entries(hist).sort((a, b) => b[1] - a[1]);
  if (sorted.length === 0) console.log("  (none — every in-scope true IDOR fired)");
  for (const [reason, n] of sorted) {
    console.log(`  ${W(reason, 36)} ${n}   ${GATE_LABEL[reason] || ""}`);
  }

  console.log("");
  console.log("  ── CONTROLS (must NOT mint) ────────────────────────────────────────────────");
  for (const { fx, r } of controls) {
    console.log(`  ${W(fx.id + " " + fx.name, 56)} → ${r.outcome} ${r.outcome === "FIRE" ? "  ⚠️ FALSE MINT" : "✓ declined"}`);
  }

  console.log("");
  console.log("  ── CONFIDENCE-SIGNAL CHECK (soft-gated fires carry the RIGHT signals) ──────");
  const signalFixtures = results.filter(({ fx }) => Array.isArray(fx.expected_signals));
  const signalMismatches = [];
  for (const { fx, r } of signalFixtures) {
    const got = JSON.stringify([...(r.signals || [])].sort());
    const want = JSON.stringify([...fx.expected_signals].sort());
    const ok = r.outcome === "FIRE" && got === want;
    if (!ok) signalMismatches.push(fx.id);
    console.log(`  ${W(fx.id, 4)} want=${want} got=${got} ${ok ? "✓" : "✗ MISMATCH"}`);
  }
  if (signalFixtures.length === 0) console.log("  (no fixtures declare expected_signals)");

  console.log("");
  console.log("  ── READ-OUT ────────────────────────────────────────────────────────────────");
  console.log("  • The oracle is SOUND on this corpus (0 false mints) and now fires on an A-only");
  console.log("    cross-tenant read EVEN when the bodies don't echo a private owning-scope key or");
  console.log("    a distinct tenant key — #13/#14 are DEMOTED to non-blocking confidence_signals.");
  console.log("  • A soft-gated fire carries confidence_signals (hash-bound via stderr_hash) so the");
  console.log("    3-round blind verification + grader corroborate or discount the tenant attribution;");
  console.log("    the demonstrated_severity ceiling stays medium (Option A).");
  console.log("  • The remaining in-scope misses are the SOUNDNESS FLOOR: p5_authenticated_shared +");
  console.log("    canary_leaked_unauthenticated (textbook BOLAs broken for everyone, declined as");
  console.log("    'shared/public') and body_not_parseable (non-JSON export bodies). NOT demoted.");
  console.log("  • NEXT: live-validate on docker (crAPI/VAmPI); then consider whether a private-O_B +");
  console.log("    C-can-also-read should CORROBORATE (C has the IDOR too) rather than refute (#11).");
  console.log("");
  const expectedFiresMissed = results.filter(({ fx, r }) => fx.predicted === "FIRE" && r.outcome !== "FIRE");
  const hardFail = controlFires.length > 0 || signalMismatches.length > 0 || expectedFiresMissed.length > 0;
  console.log(`  ── REGRESSION GATE: ${hardFail ? "❌ FAIL" : "✅ PASS"} — 0 control mints, 0 signal mismatches, every FIRE-predicted fixture fired ──`);
  if (controlFires.length) console.log(`     control false-mint(s): ${controlFires.map(({ fx }) => fx.id).join(", ")}`);
  if (signalMismatches.length) console.log(`     signal mismatch(es): ${signalMismatches.join(", ")}`);
  if (expectedFiresMissed.length) console.log(`     FIRE-predicted but declined: ${expectedFiresMissed.map(({ fx }) => fx.id).join(", ")}`);
  if (hardFail) process.exitCode = 1;
  console.log("");
})().catch((e) => { console.error(e); process.exit(1); });
