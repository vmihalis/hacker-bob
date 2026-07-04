"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  WAVE_ARTIFACT_KEYS,
  buildWaveHandoffsDocument,
  buildWaveReadiness,
  loadWaveArtifacts,
  mergeWaveHandoffs,
} = require("../mcp/lib/wave-handoff-store.js");
const {
  liveDeadEndsJsonlPath,
  sessionDir,
  techniqueAttemptsJsonlPath,
  waveAssignmentsPath,
} = require("../mcp/lib/paths.js");
const {
  writeFileAtomic,
} = require("../mcp/lib/storage.js");
const {
  loadWaveAssignments,
} = require("../mcp/lib/assignments.js");
const {
  prepareWaveAssignments,
  writeWaveAssignmentsDocument,
} = require("../mcp/lib/waves/wave-assignment-store.js");
const {
  waveStatus,
} = require("../mcp/lib/waves/wave-prereq-snapshots.js");
const {
  ensureHandoffSigningKey,
  readHandoffSigningKey,
} = require("../mcp/lib/handoff-signing-key.js");
const {
  sha256Hex,
  signHandoffProvenance,
} = require("../mcp/lib/wave-handoff-contracts.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bob-wave-store-"));
  process.env.HOME = tempHome;
  try {
    return fn(tempHome);
  } finally {
    if (previousHome === undefined) {
      delete process.env.HOME;
    } else {
      process.env.HOME = previousHome;
    }
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
}

function seededHandoffToken(domain, waveNumber, agent) {
  return `test-handoff-token:${domain}:w${waveNumber}:${agent}`;
}

function writeAssignments(
  domain,
  waveNumber,
  assignments,
  { ensureSigningKey = true, handoffTokensRequired = true } = {},
) {
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  const persistedAssignments = assignments.map((assignment) => {
    const persisted = { ...assignment };
    const tokenRequired = persisted.handoff_token_required !== false;
    if (tokenRequired && persisted.handoff_token_required == null) {
      persisted.handoff_token_required = true;
    }
    if (tokenRequired && persisted.handoff_token_sha256 == null) {
      persisted.handoff_token_sha256 = sha256Hex(
        seededHandoffToken(domain, waveNumber, persisted.agent),
      );
    }
    return persisted;
  });
  writeFileAtomic(waveAssignmentsPath(domain, waveNumber), `${JSON.stringify({
    wave_number: waveNumber,
    handoff_tokens_required: handoffTokensRequired,
    assignments: persistedAssignments,
  }, null, 2)}\n`);
  if (ensureSigningKey) {
    ensureHandoffSigningKey(domain);
  }
}

// Web/OSS surfaces carry attempt_log_required, so the merge gate requires a
// completion-status technique attempt for the surface. These fixtures write
// assignments directly (no attack_surface.json to route through
// bob_log_technique_attempt), so seed the technique-attempts.jsonl record the
// merge-side check reads. It keys on target_domain + surface_id, independent of
// wave/agent, so an omitted wave/agent matches any run on the surface.
function seedTechniqueAttempt(domain, surfaceId) {
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  const record = {
    version: 1,
    ts: new Date().toISOString(),
    target_domain: domain,
    surface_id: surfaceId,
    pack_id: "generic-rest-api",
    status: "attempted",
    outcome: "no_finding",
    evidence: `probed authz on ${surfaceId}; no issue observed`,
  };
  fs.appendFileSync(techniqueAttemptsJsonlPath(domain), `${JSON.stringify(record)}\n`);
}

function assignmentForHandoff(domain, waveNumber, agent) {
  try {
    return loadWaveAssignments(domain, waveNumber).assignmentByAgent.get(agent) || null;
  } catch {
    return null;
  }
}

function writeHandoff(domain, wave, agent, surfaceId, fields = {}) {
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  const waveNumber = Number(String(wave).replace(/^w/i, ""));
  const payload = {
    target_domain: domain,
    wave,
    agent,
    surface_id: surfaceId,
    surface_type: null,
    surface_status: "complete",
    summary: `${agent} completed ${surfaceId}.`,
    chain_notes: [],
    blocked_harness_runs: [],
    blocked_prereqs: [],
    bypass_attempts: [],
    dead_ends: [],
    waf_blocked_endpoints: [],
    lead_surface_ids: [],
    ...fields,
  };
  let document = payload;
  const assignment = Number.isInteger(waveNumber) ? assignmentForHandoff(domain, waveNumber, agent) : null;
  if (assignment) {
    try {
      document = signHandoffProvenance(
        payload.provenance == null ? { ...payload, provenance: "verified" } : payload,
        readHandoffSigningKey(domain),
        { assignment },
      );
    } catch {
      document = payload;
    }
  }
  writeFileAtomic(
    path.join(sessionDir(domain), `handoff-${wave}-${agent}.json`),
    `${JSON.stringify(document, null, 2)}\n`,
  );
}

// Build an attackSurfaceInfo the shape prepareWaveAssignments/routeSurfacesInternal
// read: a non-"missing" source, document.surfaces, surface_ids, and a surface_id_set
// Set. Drives partition through the REAL router (routeSurfacesInternal → classify).
function attackSurfaceInfoForSurfaces(surfaces) {
  const surfaceIdSet = new Set(surfaces.map((s) => s.id));
  return {
    source: "test",
    path: "test://attack-surface",
    document: { surfaces },
    surface_ids: Array.from(surfaceIdSet),
    surface_id_set: surfaceIdSet,
  };
}

test("prepareWaveAssignments partitions an unroutable SC surface out of the executable assignments", () => {
  withTempHome(() => {
    const domain = "unroutable-mix.example.com";
    fs.mkdirSync(sessionDir(domain), { recursive: true });
    // A routable web surface and an unroutable smart_contract surface (unknown
    // chain_family → classifySurfaceCapability returns routable:false).
    const attackSurfaceInfo = attackSurfaceInfoForSurfaces([
      { id: "surface-web", surface_type: "api", hosts: ["api.example.com"], endpoints: [] },
      { id: "surface-sc", surface_type: "smart_contract", chain_family: "cardano", hosts: [], endpoints: [] },
    ]);

    const prepared = prepareWaveAssignments({
      domain,
      waveNumber: 1,
      assignments: [
        { agent: "a1", surface_id: "surface-web", task_lens: "surface_scout" },
        { agent: "a2", surface_id: "surface-sc", task_lens: "surface_scout" },
      ],
      attackSurfaceInfo,
    });

    // Executable assignments contain ONLY the routable surface; no SC+null-pack row.
    assert.deepEqual(
      prepared.assignmentsDocument.assignments.map((a) => a.surface_id),
      ["surface-web"],
    );
    assert.deepEqual(
      prepared.persistedAssignments.map((a) => a.surface_id),
      ["surface-web"],
    );
    // The unroutable surface is recorded, never silently dropped.
    assert.equal(prepared.assignmentsDocument.unroutable_surfaces.length, 1);
    const parked = prepared.assignmentsDocument.unroutable_surfaces[0];
    assert.equal(parked.surface_id, "surface-sc");
    assert.equal(parked.agent, "a2");
    assert.equal(parked.surface_type, "smart_contract");
    assert.equal(typeof parked.unroutable_reason, "string");
    assert.ok(parked.unroutable_reason.length > 0);

    // Persist it, then loadWaveAssignments (which calls normalizeAssignmentRouteMetadata
    // per assignment) does NOT throw and the unroutable agent is not in the map.
    writeWaveAssignmentsDocument(prepared.assignmentsPath, prepared.assignmentsDocument);
    const loaded = loadWaveAssignments(domain, 1);
    assert.deepEqual(loaded.assignments.map((a) => a.surface_id), ["surface-web"]);
    assert.equal(loaded.assignmentByAgent.has("a2"), false);
    assert.ok(loaded.assignmentByAgent.has("a1"));
  });
});

test("prepareWaveAssignments handles an ALL-unroutable wave (empty executable set stays non-halting)", () => {
  withTempHome(() => {
    const domain = "unroutable-all.example.com";
    fs.mkdirSync(sessionDir(domain), { recursive: true });
    // Every assigned surface is an unroutable smart_contract (unknown chain_family).
    const attackSurfaceInfo = attackSurfaceInfoForSurfaces([
      { id: "sc-1", surface_type: "smart_contract", chain_family: "cardano", hosts: [], endpoints: [] },
      { id: "sc-2", surface_type: "smart_contract", chain_family: "tezos", hosts: [], endpoints: [] },
    ]);

    const prepared = prepareWaveAssignments({
      domain,
      waveNumber: 1,
      assignments: [
        { agent: "a1", surface_id: "sc-1", task_lens: "surface_scout" },
        { agent: "a2", surface_id: "sc-2", task_lens: "surface_scout" },
      ],
      attackSurfaceInfo,
    });

    // No executable assignment is minted; BOTH surfaces are parked, never dropped.
    assert.deepEqual(prepared.assignmentsDocument.assignments, []);
    assert.deepEqual(prepared.persistedAssignments, []);
    assert.equal(prepared.assignmentsDocument.unroutable_surfaces.length, 2);

    // loadWaveAssignments over an empty executable set does NOT throw or deadlock.
    writeWaveAssignmentsDocument(prepared.assignmentsPath, prepared.assignmentsDocument);
    const loaded = loadWaveAssignments(domain, 1);
    assert.deepEqual(loaded.assignments, []);
    assert.equal(loaded.assignmentByAgent.has("a1"), false);
    assert.equal(loaded.assignmentByAgent.has("a2"), false);
  });
});

test("prepareWaveAssignments accepts a routable EVM smart_contract surface (partition is disposition-keyed)", () => {
  withTempHome(() => {
    const domain = "routable-sc.example.com";
    fs.mkdirSync(sessionDir(domain), { recursive: true });
    const attackSurfaceInfo = attackSurfaceInfoForSurfaces([
      { id: "surface-evm", surface_type: "smart_contract", chain_family: "evm", hosts: [], endpoints: [] },
    ]);

    const prepared = prepareWaveAssignments({
      domain,
      waveNumber: 1,
      assignments: [{ agent: "a1", surface_id: "surface-evm", task_lens: "surface_scout" }],
      attackSurfaceInfo,
    });

    // A resolved-chain SC is routable → it stays an executable assignment.
    assert.deepEqual(
      prepared.assignmentsDocument.assignments.map((a) => a.surface_id),
      ["surface-evm"],
    );
    assert.deepEqual(prepared.assignmentsDocument.unroutable_surfaces, []);
  });
});

test("bob_wave_status surfaces the unroutable surface as an actionable coverage gap", () => {
  withTempHome(() => {
    const domain = "unroutable-status.example.com";
    fs.mkdirSync(sessionDir(domain), { recursive: true });
    const attackSurfaceInfo = attackSurfaceInfoForSurfaces([
      { id: "surface-web", surface_type: "api", hosts: ["api.example.com"], endpoints: [] },
      { id: "surface-sc", surface_type: "smart_contract", chain_family: "cardano", hosts: [], endpoints: [] },
    ]);
    const prepared = prepareWaveAssignments({
      domain,
      waveNumber: 1,
      assignments: [
        { agent: "a1", surface_id: "surface-web", task_lens: "surface_scout" },
        { agent: "a2", surface_id: "surface-sc", task_lens: "surface_scout" },
      ],
      attackSurfaceInfo,
    });
    writeWaveAssignmentsDocument(prepared.assignmentsPath, prepared.assignmentsDocument);

    const status = JSON.parse(waveStatus({ target_domain: domain }));
    assert.ok(Array.isArray(status.unroutable_surfaces));
    assert.equal(status.unroutable_surfaces.length, 1);
    assert.equal(status.unroutable_surfaces[0].surface_id, "surface-sc");
    assert.ok(status.unroutable_surfaces[0].unroutable_reason.length > 0);
  });
});

test("bob_wave_status reads unroutable_surfaces as [] for an old wave doc without the field", () => {
  withTempHome(() => {
    const domain = "unroutable-backcompat.example.com";
    // writeAssignments writes a wave doc with NO unroutable_surfaces field.
    writeAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    const status = JSON.parse(waveStatus({ target_domain: domain }));
    assert.deepEqual(status.unroutable_surfaces, []);
  });
});

test("wave completes on its routable surface without waiting for the partitioned-out unroutable surface", () => {
  withTempHome(() => {
    const domain = "unroutable-complete.example.com";
    fs.mkdirSync(sessionDir(domain), { recursive: true });
    const attackSurfaceInfo = attackSurfaceInfoForSurfaces([
      { id: "surface-web", surface_type: "api", hosts: ["api.example.com"], endpoints: [] },
      { id: "surface-sc", surface_type: "smart_contract", chain_family: "cardano", hosts: [], endpoints: [] },
    ]);
    const prepared = prepareWaveAssignments({
      domain,
      waveNumber: 2,
      assignments: [
        { agent: "a1", surface_id: "surface-web", task_lens: "surface_scout" },
        { agent: "a2", surface_id: "surface-sc", task_lens: "surface_scout" },
      ],
      attackSurfaceInfo,
    });
    // Persist the prepared doc directly (it carries unroutable_surfaces), and
    // seed a matching handoff-token sha for the routable agent so its handoff
    // verifies against the seeded token.
    const routableAssignment = prepared.assignmentsDocument.assignments.find((a) => a.agent === "a1");
    routableAssignment.handoff_token_sha256 = sha256Hex(seededHandoffToken(domain, 2, "a1"));
    routableAssignment.handoff_token_required = true;
    writeWaveAssignmentsDocument(prepared.assignmentsPath, prepared.assignmentsDocument);
    ensureHandoffSigningKey(domain);

    writeHandoff(domain, "w2", "a1", "surface-web");
    seedTechniqueAttempt(domain, "surface-web");

    const document = buildWaveHandoffsDocument(domain, [2]);
    // The unroutable surface is never in missing_handoffs — it was never an
    // executable assignment, so completion does not wait on a handoff for it.
    assert.deepEqual(document.missing_handoffs, []);
    assert.ok(!document.missing_handoffs.some((m) => m.surface_id === "surface-sc"));

    const artifacts = loadWaveArtifacts(domain, 2);
    const readiness = buildWaveReadiness(artifacts);
    assert.equal(readiness.assignments_total, 1);
    assert.deepEqual(readiness.missing_agents, []);
    assert.equal(readiness.is_complete, true);
  });
});

test("prepareWaveAssignments still errors for a genuinely un-routed surface (no route at all)", () => {
  withTempHome(() => {
    const domain = "unrouted-error.example.com";
    fs.mkdirSync(sessionDir(domain), { recursive: true });
    // A surface that exists in the surface set (passes the Unknown surface_id
    // guard) but whose id is not in the routed set — simulate by routing a set
    // that omits it, then referencing it. prepareWaveAssignments routes the
    // passed attackSurfaceInfo, so include the surface in surface_id_set but NOT
    // in document.surfaces so the router never emits a route for it.
    const surfaceIdSet = new Set(["surface-routed", "surface-unrouted"]);
    const attackSurfaceInfo = {
      source: "test",
      path: "test://attack-surface",
      document: {
        surfaces: [
          { id: "surface-routed", surface_type: "api", hosts: ["api.example.com"], endpoints: [] },
        ],
      },
      surface_ids: Array.from(surfaceIdSet),
      surface_id_set: surfaceIdSet,
    };

    assert.throws(
      () => prepareWaveAssignments({
        domain,
        waveNumber: 1,
        assignments: [
          { agent: "a1", surface_id: "surface-routed", task_lens: "surface_scout" },
          { agent: "a2", surface_id: "surface-unrouted", task_lens: "surface_scout" },
        ],
        attackSurfaceInfo,
      }),
      /Missing route for surface_id/,
    );
  });
});

test("wave handoff store readiness indexes structured JSON without parsing payloads", () => {
  withTempHome(() => {
    const domain = "example.com";
    writeAssignments(domain, 1, [
      { agent: "a1", surface_id: "surface-a" },
      { agent: "a2", surface_id: "surface-b" },
    ]);
    writeFileAtomic(path.join(sessionDir(domain), "handoff-w1-a1.json"), "{bad json");
    writeFileAtomic(path.join(sessionDir(domain), "handoff-w1-a2.md"), "# markdown only\n");
    writeHandoff(domain, "w1", "a9", "surface-z");

    const artifacts = loadWaveArtifacts(domain, 1);
    for (const key of WAVE_ARTIFACT_KEYS) {
      assert.ok(Object.prototype.hasOwnProperty.call(artifacts, key), `missing artifact key ${key}`);
    }
    // buildWaveReadiness without a `domain` argument runs in file-presence-only
    // mode (no validation), so a1 with a malformed JSON file still shows as
    // received here. The apply_wave_merge gate calls it with { domain }, which
    // is what triggers full validation — covered in mcp-server.test.js.
    assert.deepEqual(buildWaveReadiness(artifacts), {
      assignments_total: 2,
      handoffs_total: 2,
      received_agents: ["a1"],
      missing_agents: ["a2"],
      invalid_agents: [],
      unexpected_agents: ["a9"],
      is_complete: false,
    });
  });
});

test("wave handoff store read document reports invalid JSON and ignores markdown", () => {
  withTempHome(() => {
    const domain = "example.com";
    writeAssignments(domain, 1, [
      { agent: "a1", surface_id: "surface-a" },
      { agent: "a2", surface_id: "surface-b" },
    ]);
    writeFileAtomic(path.join(sessionDir(domain), "handoff-w1-a1.json"), "{bad json");
    writeFileAtomic(path.join(sessionDir(domain), "handoff-w1-a2.md"), "# markdown only\n");
    writeHandoff(domain, "w1", "a9", "surface-z");

    const document = buildWaveHandoffsDocument(domain, [1]);

    assert.deepEqual(document.handoffs, []);
    assert.deepEqual(document.missing_handoffs, [{ wave: "w1", agent: "a2", surface_id: "surface-b" }]);
    assert.deepEqual(document.unexpected_handoffs, [{ wave: "w1", agent: "a9" }]);
    assert.equal(document.invalid_handoffs.length, 1);
    assert.equal(document.invalid_handoffs[0].agent, "a1");
    assert.equal(document.invalid_handoffs[0].surface_id, "surface-a");
    assert.match(document.invalid_handoffs[0].error, /JSON|property name|position|Unexpected/);
  });
});

test("wave handoff store merge reads live dead-end logs through the shared path helper", () => {
  withTempHome(() => {
    const domain = "example.com";
    writeAssignments(domain, 2, [{ agent: "a1", surface_id: "surface-a" }]);
    writeHandoff(domain, "w2", "a1", "surface-a", { dead_ends: ["/handoff"] });
    seedTechniqueAttempt(domain, "surface-a");
    writeFileAtomic(liveDeadEndsJsonlPath(domain, "w2", "a1"), [
      JSON.stringify({ surface_id: "surface-a", dead_ends: ["/live", "/handoff"], waf_blocked_endpoints: ["/waf"] }),
      "{bad json",
      JSON.stringify({ surface_id: "surface-other", dead_ends: ["/ignored"] }),
      "",
    ].join("\n"));

    const result = JSON.parse(mergeWaveHandoffs({ target_domain: domain, wave_number: 2 }));

    assert.deepEqual(result.dead_ends, ["/handoff", "/live"]);
    assert.deepEqual(result.waf_blocked_endpoints, ["/waf"]);
    assert.deepEqual(result.invalid_handoffs, []);
  });
});

test("wave handoff store rejects tokenized handoffs when the signing key is missing", () => {
  withTempHome(() => {
    const domain = "example.com";
    writeAssignments(domain, 3, [
      {
        agent: "a1",
        surface_id: "surface-a",
        handoff_token_required: true,
        handoff_token_sha256: "a".repeat(64),
      },
      { agent: "a2", surface_id: "surface-b", handoff_token_required: false },
    ], { ensureSigningKey: false, handoffTokensRequired: false });
    writeHandoff(domain, "w3", "a1", "surface-a");
    writeHandoff(domain, "w3", "a2", "surface-b");

    assert.throws(
      () => mergeWaveHandoffs({ target_domain: domain, wave_number: 3 }),
      /Missing handoff signing key/,
    );

    const document = buildWaveHandoffsDocument(domain, [3]);
    assert.deepEqual(document.handoffs, []);
    assert.deepEqual(document.invalid_handoffs.map((handoff) => handoff.agent), ["a1", "a2"]);
    assert.match(document.invalid_handoffs[0].error, /Missing handoff signing key/);
    assert.match(document.invalid_handoffs[1].error, /lacks token metadata/);
  });
});
