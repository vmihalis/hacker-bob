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
  waveAssignmentsPath,
} = require("../mcp/lib/paths.js");
const {
  writeFileAtomic,
} = require("../mcp/lib/storage.js");
const {
  loadWaveAssignments,
} = require("../mcp/lib/assignments.js");
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
