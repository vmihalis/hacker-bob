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

function buildFlipRow() {
  return {
    surface_id: "surface-auth",
    endpoint: "/api/accounts/789",
    method: "GET",
    signatures_by_profile: {
      tenant_a: { response_class: "ok" },
      tenant_b: { response_class: "forbidden" },
    },
    divergences: [],
    distinct_principal_count: 2,
    // tenant_a accessed (ok) while a distinct validated tenant_b was denied (forbidden) — a flip.
    cross_tenant_flip: true,
  };
}

function writeAuthDifferentialResultsRows(domain, rows) {
  writeJson(authDifferentialResultsPath(domain), {
    schema_version: 1,
    per_endpoint: rows,
  });
}

function writeAuthDifferentialResults(domain) {
  const {
    signRowViaIsolatedSignerOrLocal,
  } = require("../mcp/lib/handoff-signing-key.js");
  const { AUTH_DIFFERENTIAL_ROW_MAC_CONTEXT } = require("../mcp/lib/offensive-row-mac.js");
  const row = buildFlipRow();
  // Sign the flipped row under the auth-differential context exactly as the runner does, so the
  // MAC-verifying finalize consumer (hasAuthDifferentialSweepForSurface) credits a genuine flip.
  signRowViaIsolatedSignerOrLocal(domain, AUTH_DIFFERENTIAL_ROW_MAC_CONTEXT, row);
  writeAuthDifferentialResultsRows(domain, [row]);
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

// A genuine cross-tenant flip whose effective_url (the URL actually fetched, joinUrl(base_url,
// endpoint)) is STAMPED before signing so the row_mac covers it — exactly as the runner does. Vary
// effectiveUrl to exercise the B3 host+endpoint resolution mirror.
function writeSignedFlipRowWithEffectiveUrl(domain, effectiveUrl) {
  const {
    signRowViaIsolatedSignerOrLocal,
  } = require("../mcp/lib/handoff-signing-key.js");
  const { AUTH_DIFFERENTIAL_ROW_MAC_CONTEXT } = require("../mcp/lib/offensive-row-mac.js");
  const row = buildFlipRow();
  row.effective_url = effectiveUrl;
  signRowViaIsolatedSignerOrLocal(domain, AUTH_DIFFERENTIAL_ROW_MAC_CONTEXT, row);
  writeAuthDifferentialResultsRows(domain, [row]);
  return row;
}

// Record a recorded-claim finding for the crown surface carrying a chosen CWE (the class the
// B1 mirror resolves the finding by), returning nothing — the first finding in a session mints id
// "F-1". No exploit proof is required at record time.
function recordCrownFinding(domain, cwe) {
  const recordFindingTool = require("../mcp/lib/tools/record-candidate-claim.js");
  recordFindingTool.handler({
    target_domain: domain,
    title: `finding ${cwe}`,
    severity: "high",
    cwe,
    endpoint: `https://${domain}/api/accounts/789`,
    description: "recorded finding for the crown surface",
    proof_of_concept: "GET /api/accounts/789 returns an object",
    response_evidence: "response body observed",
    impact: "object access on the crown surface",
    validated: true,
    auth_profile: "attacker",
    surface_id: "surface-auth",
    cvss_inputs: { attack_vector: "network", privileges_required: "low", confidentiality: "high" },
  });
}

// Seed a real MAC-signed flipping offensive pair (exploited_safely positive + blocked_by_defense
// control, same surface, distinct command_hash) AND the verified_pass finding-differential line that
// binds them by finding_id. readFindingDifferentialVerifiedSummary RE-RESOLVES the record against
// these MAC-covered rows, so this is a genuine executed differential — its entry.surface_id is
// re-derived from the signed positive row's surface_id.
function seedVerifiedFindingDifferential(domain, findingId, surfaceId) {
  const { canonicalizeExploitTarget } = require("../mcp/lib/claims.js");
  const { signOffensiveRunRow } = require("../mcp/lib/offensive-row-mac.js");
  const {
    offensiveRowHash,
  } = require("../mcp/lib/finding-differential-verifier.js");
  const {
    offensiveRunsJsonlPath,
    findingDifferentialVerifiedJsonlPath,
  } = require("../mcp/lib/paths.js");
  const { appendJsonlLine } = require("../mcp/lib/storage.js");
  const key = ensureHandoffSigningKey(domain);
  const hex = (c) => c.repeat(64);
  const buildRow = (runId, outcome, cmd) => {
    const row = {
      version: 1,
      target_domain: domain,
      run_id: runId,
      tool_id: "bob_http_idor_confirm",
      target: canonicalizeExploitTarget(`https://${domain}/api/accounts/789`),
      offensive_outcome: outcome,
      dry_run: false,
      timed_out: false,
      command_hash: cmd,
      exit_code: 0,
      stdout_hash: hex("b"),
      stderr_hash: hex("c"),
      demonstrated_severity: "high",
      surface_id: surfaceId,
    };
    signOffensiveRunRow(row, key);
    fs.mkdirSync(sessionDir(domain), { recursive: true });
    fs.appendFileSync(offensiveRunsJsonlPath(domain), `${JSON.stringify(row)}\n`);
    return row;
  };
  const positive = buildRow("fd-positive-1", "exploited_safely", hex("1"));
  const control = buildRow("fd-control-1", "blocked_by_defense", hex("2"));
  appendJsonlLine(findingDifferentialVerifiedJsonlPath(domain), {
    version: 1,
    target_domain: domain,
    finding_id: findingId,
    result: "verified_pass",
    reason: "executed_finding_differential_flip",
    surface_id: surfaceId,
    source: "offensive_runs",
    positive_run_id: "fd-positive-1",
    positive_row_hash: offensiveRowHash(positive),
    control_run_id: "fd-control-1",
    control_row_hash: offensiveRowHash(control),
  });
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
    const assignment = { agent: "a1", surface_id: "surface-auth", auth_differential_required: true, id_bearing_endpoints: ["/api/accounts/{id}"] };
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
    const assignment = { agent: "a1", surface_id: "surface-auth", auth_differential_required: true, id_bearing_endpoints: ["/api/accounts/{id}"] };
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

test("an UNSIGNED flipped row does NOT clear the id-bearing surface at finalize (row MAC fails closed)", () => {
  withTempHome(() => {
    const domain = "auth-diff-unsigned.example.com";
    const marker = {
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-auth",
    };
    const assignment = { agent: "a1", surface_id: "surface-auth", auth_differential_required: true, id_bearing_endpoints: ["/api/accounts/{id}"] };
    const handoff = { surface_status: "complete", blocked_prereqs: [], blocked_harness_runs: [] };

    writeAttackSurface(domain);
    // A well-formed cross-tenant flip written straight to disk with NO row_mac — the Bash-forged
    // row the MAC layer must reject. It must not clear the id-bearing surface.
    writeAuthDifferentialResultsRows(domain, [buildFlipRow()]);
    const blocked = evaluateAuthDifferentialCompletionCoverage(marker, assignment, handoff);
    assert.ok(blocked && blocked.ok === false, "an unsigned flipped row must not clear the surface");
    assert.equal(blocked.block_code, "missing_auth_differential");
  });
});

test("a TAMPERED flipped row does NOT clear the id-bearing surface at finalize (mutation invalidates the MAC)", () => {
  withTempHome(() => {
    const domain = "auth-diff-tampered.example.com";
    const marker = {
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-auth",
    };
    const assignment = { agent: "a1", surface_id: "surface-auth", auth_differential_required: true, id_bearing_endpoints: ["/api/accounts/{id}"] };
    const handoff = { surface_status: "complete", blocked_prereqs: [], blocked_harness_runs: [] };
    const {
      signRowViaIsolatedSignerOrLocal,
    } = require("../mcp/lib/handoff-signing-key.js");
    const { AUTH_DIFFERENTIAL_ROW_MAC_CONTEXT } = require("../mcp/lib/offensive-row-mac.js");

    writeAttackSurface(domain);
    // Sign a genuine flip, then MUTATE surface_id after signing (the row_mac binds every field,
    // so the tampered content no longer verifies). Fail closed: the surface stays blocked.
    const row = buildFlipRow();
    signRowViaIsolatedSignerOrLocal(domain, AUTH_DIFFERENTIAL_ROW_MAC_CONTEXT, row);
    row.distinct_principal_count = 3;
    writeAuthDifferentialResultsRows(domain, [row]);
    const blocked = evaluateAuthDifferentialCompletionCoverage(marker, assignment, handoff);
    assert.ok(blocked && blocked.ok === false, "a tampered flipped row must not clear the surface");
    assert.equal(blocked.block_code, "missing_auth_differential");
  });
});

test("auth differential completion gate is enforced at finalize and merge", () => {
  withTempHome(() => {
    const domain = "auth-diff-merge.example.com";
    writeAssignments(domain, 1, [{
      agent: "a1",
      surface_id: "surface-auth",
      auth_differential_required: true,
      id_bearing_endpoints: ["/api/accounts/{id}"],
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

// ---- B3: effective_url host+endpoint resolution mirror (mirrors the grade-time gate in claims.js) ----

test("B3: a flip row whose effective_url resolves IN-SCOPE to a frozen id-bearing endpoint CLEARS the surface", () => {
  withTempHome(() => {
    const domain = "auth-diff-b3-ok.example.com";
    const marker = { target_domain: domain, wave: "w1", agent: "a1", surface_id: "surface-auth" };
    const assignment = { agent: "a1", surface_id: "surface-auth", auth_differential_required: true, id_bearing_endpoints: ["/api/accounts/{id}"] };
    const handoff = { surface_status: "complete", blocked_prereqs: [], blocked_harness_runs: [] };

    writeAttackSurface(domain);
    // Real tested URL is the in-scope crown path — host is the target domain, path templatizes to
    // the frozen id-bearing endpoint. Both the signed endpoint AND effective_url pass.
    writeSignedFlipRowWithEffectiveUrl(domain, `https://${domain}/api/accounts/789`);
    assert.equal(evaluateAuthDifferentialCompletionCoverage(marker, assignment, handoff), null);
  });
});

test("B3: a flip row whose effective_url is OFF-SCOPE does NOT clear the surface (host relabel defeated)", () => {
  withTempHome(() => {
    const domain = "auth-diff-b3-offscope.example.com";
    const marker = { target_domain: domain, wave: "w1", agent: "a1", surface_id: "surface-auth" };
    const assignment = { agent: "a1", surface_id: "surface-auth", auth_differential_required: true, id_bearing_endpoints: ["/api/accounts/{id}"] };
    const handoff = { surface_status: "complete", blocked_prereqs: [], blocked_harness_runs: [] };

    writeAttackSurface(domain);
    // The signed `endpoint` alone still templatizes to the frozen crown path, but the row was
    // actually fetched under an OFF-SCOPE host — the MAC-covered effective_url exposes the relabel.
    writeSignedFlipRowWithEffectiveUrl(domain, "https://accounts.attacker-evil.test/api/accounts/789");
    const blocked = evaluateAuthDifferentialCompletionCoverage(marker, assignment, handoff);
    assert.ok(blocked && blocked.ok === false, "an off-scope effective_url must not clear the crown");
    assert.equal(blocked.block_code, "missing_auth_differential");
  });
});

test("B3: a flip row whose effective_url is a benign PATH-PREFIX relabel does NOT clear the surface", () => {
  withTempHome(() => {
    const domain = "auth-diff-b3-prefix.example.com";
    const marker = { target_domain: domain, wave: "w1", agent: "a1", surface_id: "surface-auth" };
    const assignment = { agent: "a1", surface_id: "surface-auth", auth_differential_required: true, id_bearing_endpoints: ["/api/accounts/{id}"] };
    const handoff = { surface_status: "complete", blocked_prereqs: [], blocked_harness_runs: [] };

    writeAttackSurface(domain);
    // In-scope host, but a benign /safe-prefix was prepended so the arm hit a DIFFERENT (easier)
    // path — effective_url templatizes to /safe-prefix/api/accounts/{id}, NOT the frozen endpoint.
    writeSignedFlipRowWithEffectiveUrl(domain, `https://${domain}/safe-prefix/api/accounts/789`);
    const blocked = evaluateAuthDifferentialCompletionCoverage(marker, assignment, handoff);
    assert.ok(blocked && blocked.ok === false, "a path-prefix-relabeled effective_url must not clear the crown");
    assert.equal(blocked.block_code, "missing_auth_differential");
  });
});

test("B3 back-compat: a legacy flip row with NO effective_url still clears the surface", () => {
  withTempHome(() => {
    const domain = "auth-diff-b3-legacy.example.com";
    const marker = { target_domain: domain, wave: "w1", agent: "a1", surface_id: "surface-auth" };
    const assignment = { agent: "a1", surface_id: "surface-auth", auth_differential_required: true, id_bearing_endpoints: ["/api/accounts/{id}"] };
    const handoff = { surface_status: "complete", blocked_prereqs: [], blocked_harness_runs: [] };

    writeAttackSurface(domain);
    // buildFlipRow carries NO effective_url (pre-urlbind): the extra check is skipped and the MAC,
    // flip, surface_id-bind, and endpoint-template checks stand — the surface clears.
    writeAuthDifferentialResults(domain);
    assert.equal(evaluateAuthDifferentialCompletionCoverage(marker, assignment, handoff), null);
  });
});

// ---- B1: id-bearing independence — a clearing finding-differential must be access-control class ----

test("B1: a verified finding-differential of an ACCESS-CONTROL class (CWE-639) CLEARS the id-bearing surface", () => {
  withTempHome(() => {
    const domain = "auth-diff-b1-ac.example.com";
    const marker = { target_domain: domain, wave: "w1", agent: "a1", surface_id: "surface-auth" };
    const assignment = { agent: "a1", surface_id: "surface-auth", id_bearing: true, auth_differential_required: true, id_bearing_endpoints: ["/api/accounts/{id}"] };
    const handoff = { surface_status: "complete", blocked_prereqs: [], blocked_harness_runs: [] };

    recordCrownFinding(domain, "CWE-639");
    seedVerifiedFindingDifferential(domain, "F-1", "surface-auth");
    assert.equal(evaluateAuthDifferentialCompletionCoverage(marker, assignment, handoff), null);
  });
});

test("B1: a verified finding-differential of a NON-access-control class (CWE-79 XSS) does NOT clear the id-bearing surface", () => {
  withTempHome(() => {
    const domain = "auth-diff-b1-xss.example.com";
    const marker = { target_domain: domain, wave: "w1", agent: "a1", surface_id: "surface-auth" };
    const assignment = { agent: "a1", surface_id: "surface-auth", id_bearing: true, auth_differential_required: true, id_bearing_endpoints: ["/api/accounts/{id}"] };
    const handoff = { surface_status: "complete", blocked_prereqs: [], blocked_harness_runs: [] };

    // A same-surface executed XSS proves impact but never the cross-tenant object-authorization
    // obligation, so it must NOT discharge the crown — the flip/access-control finding still does.
    recordCrownFinding(domain, "CWE-79");
    seedVerifiedFindingDifferential(domain, "F-1", "surface-auth");
    const blocked = evaluateAuthDifferentialCompletionCoverage(marker, assignment, handoff);
    assert.ok(blocked && blocked.ok === false, "a non-access-control finding-differential must not clear the crown");
    assert.equal(blocked.block_code, "missing_auth_differential");
  });
});
