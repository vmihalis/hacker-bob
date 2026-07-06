"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  evaluateAgentCompletion,
  evaluateAuthDifferentialCompletionCoverage,
} = require("../mcp/lib/agent-run-completion.js");
const {
  buildWaveReadiness,
  loadWaveArtifacts,
  mergeWaveHandoffs,
} = require("../mcp/lib/wave-handoff-store.js");
const {
  attackSurfacePath,
  authDifferentialResultsPath,
  sessionDir,
  techniqueAttemptsJsonlPath,
  waveAssignmentsPath,
} = require("../mcp/lib/paths.js");
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
const {
  writeFileAtomic,
} = require("../mcp/lib/storage.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "bob-auth-diff-gate-"));
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

function writeJson(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  writeFileAtomic(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

function handoffToken(domain, waveNumber, agent) {
  return `auth-diff-token:${domain}:w${waveNumber}:${agent}`;
}

function writeAssignments(domain, waveNumber, assignments) {
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  writeJson(waveAssignmentsPath(domain, waveNumber), {
    wave_number: waveNumber,
    handoff_tokens_required: true,
    assignments: assignments.map((assignment) => ({
      task_lens: "surface_scout",
      handoff_token_required: true,
      handoff_token_sha256: sha256Hex(handoffToken(domain, waveNumber, assignment.agent)),
      ...assignment,
    })),
  });
  ensureHandoffSigningKey(domain);
}

function writeSignedHandoff(domain, waveNumber, agent, surfaceId, fields = {}) {
  const wave = `w${waveNumber}`;
  const assignment = loadWaveAssignments(domain, waveNumber).assignmentByAgent.get(agent);
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
  const signed = signHandoffProvenance(
    { ...payload, provenance: "verified" },
    readHandoffSigningKey(domain),
    { assignment },
  );
  writeJson(path.join(sessionDir(domain), `handoff-${wave}-${agent}.json`), signed);
}

function writeAttackSurface(domain) {
  writeJson(attackSurfacePath(domain), {
    surfaces: [{
      id: "surface-auth",
      surface_type: "api",
      hosts: ["api.example.test"],
      endpoints: ["/api/accounts/789"],
    }],
  });
}

function writeAuthDifferentialResults(domain) {
  writeJson(authDifferentialResultsPath(domain), {
    schema_version: 1,
    per_endpoint: [{
      surface_id: "surface-auth",
      endpoint: "/api/accounts/789",
      method: "GET",
      signatures_by_profile: {
        tenant_a: { response_class: "ok" },
        tenant_b: { response_class: "forbidden" },
      },
      divergences: [],
      distinct_principal_count: 2,
    }],
  });
}

function seedTechniqueAttempt(domain, surfaceId) {
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  fs.appendFileSync(techniqueAttemptsJsonlPath(domain), `${JSON.stringify({
    version: 1,
    ts: new Date().toISOString(),
    target_domain: domain,
    surface_id: surfaceId,
    pack_id: "generic-rest-api",
    status: "attempted",
    outcome: "no_finding",
    evidence: `attempted authorization checks for ${surfaceId}`,
  })}\n`);
}

test("auth differential completion evaluator is self-activating and credits MCP ledgers", () => {
  withTempHome(() => {
    const domain = "auth-diff-eval.example.com";
    const marker = {
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-auth",
    };
    const assignment = { agent: "a1", surface_id: "surface-auth", auth_differential_required: true };
    const handoff = { surface_status: "complete", blocked_prereqs: [], blocked_harness_runs: [] };

    assert.equal(evaluateAuthDifferentialCompletionCoverage(marker, null, handoff), null);
    assert.equal(evaluateAuthDifferentialCompletionCoverage(marker, {
      agent: "a1",
      surface_id: "surface-auth",
    }, handoff), null);
    assert.equal(evaluateAuthDifferentialCompletionCoverage(marker, assignment, {
      surface_status: "partial",
    }), null);

    const blocked = evaluateAuthDifferentialCompletionCoverage(marker, assignment, handoff);
    assert.equal(blocked.block_code, "missing_auth_differential");

    writeAttackSurface(domain);
    writeAuthDifferentialResults(domain);
    assert.equal(evaluateAuthDifferentialCompletionCoverage(marker, assignment, handoff), null);
  });
});

test("auth differential completion evaluator BLOCKS a complete id-bearing surface backed only by a blocker (must be partial)", () => {
  withTempHome(() => {
    const marker = {
      target_domain: "auth-diff-blocker.example.com",
      wave: "w1",
      agent: "a1",
      surface_id: "surface-auth",
    };
    const assignment = { agent: "a1", surface_id: "surface-auth", auth_differential_required: true };
    // A substantive blocker on a COMPLETE id-bearing handoff must NOT earn completion:
    // the grade-time gate rejects a complete surface backed only by a blocker, so the
    // wave gate forces partial (evaluating.md: a blocked surface is recorded partial).
    const handoff = {
      surface_status: "complete",
      blocked_prereqs: [{
        kind: "external_credential_missing",
        reason: "Cannot run the cross-tenant auth differential for /api/accounts/789 because the second tenant credential has not been provisioned.",
        needed_for: "cross-tenant auth differential sweep across two tenant profiles for /api/accounts/789",
      }],
      blocked_harness_runs: [],
    };

    const result = evaluateAuthDifferentialCompletionCoverage(marker, assignment, handoff);
    assert.ok(result && result.ok === false, "a blocked complete id-bearing surface must be refused");
    assert.equal(result.block_code, "missing_auth_differential");
  });
});

test("auth differential completion gate is enforced at finalize and merge", () => {
  withTempHome(() => {
    const domain = "auth-diff-merge.example.com";
    writeAssignments(domain, 1, [{
      agent: "a1",
      surface_id: "surface-auth",
      auth_differential_required: true,
    }]);
    writeAttackSurface(domain);
    seedTechniqueAttempt(domain, "surface-auth");
    writeSignedHandoff(domain, 1, "a1", "surface-auth");

    const finalizeBlocked = evaluateAgentCompletion({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-auth",
    });
    assert.equal(finalizeBlocked.ok, false);
    assert.equal(finalizeBlocked.block_code, "missing_auth_differential");

    const readinessBlocked = buildWaveReadiness(loadWaveArtifacts(domain, 1), { domain });
    assert.deepEqual(readinessBlocked.received_agents, []);
    assert.deepEqual(readinessBlocked.missing_agents, ["a1"]);

    const mergeBlocked = JSON.parse(mergeWaveHandoffs({ target_domain: domain, wave_number: 1 }));
    assert.deepEqual(mergeBlocked.completed_surface_ids, []);
    assert.deepEqual(mergeBlocked.missing_surface_ids, ["surface-auth"]);

    writeAuthDifferentialResults(domain);
    const finalizeAllowed = evaluateAgentCompletion({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-auth",
    });
    assert.equal(finalizeAllowed.ok, true);

    const readinessAllowed = buildWaveReadiness(loadWaveArtifacts(domain, 1), { domain });
    assert.deepEqual(readinessAllowed.received_agents, ["a1"]);
    assert.deepEqual(readinessAllowed.missing_agents, []);
  });
});
