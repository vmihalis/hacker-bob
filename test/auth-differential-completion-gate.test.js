"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const {
  evaluateAgentCompletion,
  evaluateAuthDifferentialCompletionCoverage,
} = require("../mcp/core/session/agent-run-completion.js");
const {
  buildWaveReadiness,
  loadWaveArtifacts,
  mergeWaveHandoffs,
} = require("../mcp/core/waves/wave-handoff-store.js");
const {
  attackSurfacePath,
  authDifferentialResultsPath,
  sessionDir,
  surfaceRoutesPath,
  techniqueAttemptsJsonlPath,
  waveAssignmentsPath,
} = require("../mcp/core/io/paths.js");
const {
  SURFACE_ROUTES_VERSION,
  SURFACE_ROUTE_VERSION,
} = require("../mcp/core/frontier/surface-router.js");
const { classifySurfaceCapability } = require("../mcp/core/capability/capability-packs.js");
const {
  loadWaveAssignments,
} = require("../mcp/core/session/assignments.js");
const {
  ensureHandoffSigningKey,
  readHandoffSigningKey,
} = require("../mcp/core/ledger-integrity/handoff-signing-key.js");
const {
  sha256Hex,
  signHandoffProvenance,
} = require("../mcp/core/waves/wave-handoff-contracts.js");
const {
  writeFileAtomic,
} = require("../mcp/core/io/storage.js");

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

// A current-schema, validator-clean route row (pack fields DERIVED, never hardcoded, so it
// survives pack edits) — the MCP-owned document the grade-time gate re-reads to re-establish the
// id-bearing predicate. Every wave assignment required one of these at wave start
// (wave-assignment-store's "Missing route" guard), so an id-bearing surface WITHOUT one at
// finalize is an integrity anomaly, not a legitimate state.
function validRouteRow(surfaceId, { idBearing = true, endpoints = ["/api/accounts/{id}"] } = {}) {
  const classification = classifySurfaceCapability({
    id: surfaceId,
    surface_type: "web",
    hosts: [`${surfaceId}.example.test`],
    endpoints: [`https://${surfaceId}.example.test/api/accounts/789`],
  });
  return {
    surface_id: surfaceId,
    surface_type: classification.surface_type,
    capability_pack: classification.capability_pack,
    capability_pack_version: classification.capability_pack_version,
    evaluator_agent: classification.evaluator_agent,
    brief_profile: classification.brief_profile,
    context_budget: classification.context_budget,
    id_bearing: idBearing,
    auth_differential_required: idBearing,
    id_bearing_endpoints: endpoints,
  };
}

function writeSurfaceRoutes(domain, routes = [validRouteRow("surface-auth")]) {
  writeJson(surfaceRoutesPath(domain), {
    version: SURFACE_ROUTES_VERSION,
    route_version: SURFACE_ROUTE_VERSION,
    routes,
  });
}

// A route exactly as a PRE-rename framework version persisted it (evaluator_agent absent,
// hunter_agent present): the resilient reader QUARANTINES it into malformed_routes[] keyed by its
// surface_id, so the surface has no row in document.routes — the same state grade fails closed on.
function staleQuarantinedRouteRow(surfaceId) {
  const route = validRouteRow(surfaceId);
  delete route.evaluator_agent;
  route.hunter_agent = "hunter-agent";
  return route;
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
  } = require("../mcp/core/ledger-integrity/handoff-signing-key.js");
  const { AUTH_DIFFERENTIAL_ROW_MAC_CONTEXT } = require("../mcp/core/ledger-integrity/offensive-row-mac.js");
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
  } = require("../mcp/core/ledger-integrity/handoff-signing-key.js");
  const { AUTH_DIFFERENTIAL_ROW_MAC_CONTEXT } = require("../mcp/core/ledger-integrity/offensive-row-mac.js");
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
  const recordFindingTool = require("../mcp/tools/record-candidate-claim.js");
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
  const { canonicalizeExploitTarget } = require("../mcp/core/claims/claims.js");
  const { signOffensiveRunRow } = require("../mcp/core/ledger-integrity/offensive-row-mac.js");
  const {
    offensiveRowHash,
  } = require("../mcp/core/differential/finding-differential-verifier.js");
  const {
    offensiveRunsJsonlPath,
    findingDifferentialVerifiedJsonlPath,
  } = require("../mcp/core/io/paths.js");
  const { appendJsonlLine } = require("../mcp/core/io/storage.js");
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
    writeSurfaceRoutes(domain);
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
    } = require("../mcp/core/ledger-integrity/handoff-signing-key.js");
    const { AUTH_DIFFERENTIAL_ROW_MAC_CONTEXT } = require("../mcp/core/ledger-integrity/offensive-row-mac.js");

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
    writeSurfaceRoutes(domain);
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
    writeSurfaceRoutes(domain);
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
    writeSurfaceRoutes(domain);
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

// ---- FINALIZE/GRADE PARITY: the routes-integrity condition (deadlock, not false-clear) ----
//
// The grade-time gate (claims.js completionDepthGapForCompleteSurfaces) re-reads the MCP-owned
// surface-routes.json to re-establish the id-bearing predicate, and fails CLOSED when that
// document cannot speak for the surface (unreadable / this surface's route quarantined / no row
// for the surface at all): the surface then clears at grade ONLY on executed access-control
// evidence or a re-verified cross-stack composition — never on the auth-differential flip, whose
// frozen endpoint basis lives in that same unreadable document. Finalize reads the FROZEN wave
// assignment instead, so before this mirror a run settled here on a MAC-verified flip and was then
// permanently held at GRADE with no artifact the agent could still add.

function idBearingCrownFixture(domain) {
  return {
    marker: { target_domain: domain, wave: "w1", agent: "a1", surface_id: "surface-auth" },
    assignment: {
      agent: "a1",
      surface_id: "surface-auth",
      id_bearing: true,
      auth_differential_required: true,
      id_bearing_endpoints: ["/api/accounts/{id}"],
    },
    handoff: { surface_status: "complete", blocked_prereqs: [], blocked_harness_runs: [] },
  };
}

test("PARITY: ABSENT surface-routes.json blocks a MAC-verified flip from settling an id-bearing complete surface (was: settled, then deadlocked at grade)", () => {
  withTempHome(() => {
    const domain = "auth-diff-routes-absent.example.com";
    const { marker, assignment, handoff } = idBearingCrownFixture(domain);

    writeAttackSurface(domain);
    // A genuine, MAC-verified cross-tenant flip — the exact evidence that used to settle here.
    writeAuthDifferentialResults(domain);
    // ...but NO routes document: grade cannot re-establish the id-bearing predicate and holds the
    // surface, so settling it here would deadlock the run.
    assert.equal(fs.existsSync(surfaceRoutesPath(domain)), false);

    const blocked = evaluateAuthDifferentialCompletionCoverage(marker, assignment, handoff);
    assert.ok(blocked && blocked.ok === false, "an unverifiable route must not settle the crown");
    assert.equal(blocked.block_code, "unverifiable_surface_route");
    assert.match(blocked.reason, /routes_unreadable/);
    assert.match(blocked.reason, /bob_route_surfaces/);
    assert.match(blocked.reason, /partial/);
  });
});

test("PARITY: CORRUPT surface-routes.json blocks a MAC-verified flip from settling an id-bearing complete surface", () => {
  withTempHome(() => {
    const domain = "auth-diff-routes-corrupt.example.com";
    const { marker, assignment, handoff } = idBearingCrownFixture(domain);

    writeAttackSurface(domain);
    writeAuthDifferentialResults(domain);
    fs.mkdirSync(sessionDir(domain), { recursive: true });
    writeFileAtomic(surfaceRoutesPath(domain), "{ this is not valid json ]");

    const blocked = evaluateAuthDifferentialCompletionCoverage(marker, assignment, handoff);
    assert.ok(blocked && blocked.ok === false, "a corrupt routes document must not settle the crown");
    assert.equal(blocked.block_code, "unverifiable_surface_route");
    assert.match(blocked.reason, /routes_unreadable/);
  });
});

test("PARITY: this surface's own QUARANTINED route blocks the flip from settling it (per-route drift, no attacker needed)", () => {
  withTempHome(() => {
    const domain = "auth-diff-routes-quarantined.example.com";
    const { marker, assignment, handoff } = idBearingCrownFixture(domain);

    writeAttackSurface(domain);
    writeAuthDifferentialResults(domain);
    // The envelope parses, but this surface's row fails route validation and is quarantined into
    // malformed_routes[] — grade's per-surface fail-closed arm, mirrored here.
    writeSurfaceRoutes(domain, [staleQuarantinedRouteRow("surface-auth")]);

    const blocked = evaluateAuthDifferentialCompletionCoverage(marker, assignment, handoff);
    assert.ok(blocked && blocked.ok === false, "a quarantined route must not settle the crown");
    assert.equal(blocked.block_code, "unverifiable_surface_route");
    assert.match(blocked.reason, /route_quarantined/);
  });
});

test("PARITY: a readable routes document carrying NO row for the surface blocks the flip (totality anomaly)", () => {
  withTempHome(() => {
    const domain = "auth-diff-routes-missing-row.example.com";
    const { marker, assignment, handoff } = idBearingCrownFixture(domain);

    writeAttackSurface(domain);
    writeAuthDifferentialResults(domain);
    // Every assignment required a route at wave start, so a complete id-bearing surface with no
    // row is an integrity anomaly — grade holds it, and so must finalize.
    writeSurfaceRoutes(domain, [validRouteRow("surface-other", { idBearing: false, endpoints: [] })]);

    const blocked = evaluateAuthDifferentialCompletionCoverage(marker, assignment, handoff);
    assert.ok(blocked && blocked.ok === false, "a routeless crown must not settle");
    assert.equal(blocked.block_code, "unverifiable_surface_route");
    assert.match(blocked.reason, /route_absent/);
  });
});

test("PARITY: an INTACT routes document + a MAC-verified flip still CLEARS the id-bearing surface", () => {
  withTempHome(() => {
    const domain = "auth-diff-routes-intact.example.com";
    const { marker, assignment, handoff } = idBearingCrownFixture(domain);

    writeAttackSurface(domain);
    writeSurfaceRoutes(domain);
    writeAuthDifferentialResults(domain);
    assert.equal(
      evaluateAuthDifferentialCompletionCoverage(marker, assignment, handoff),
      null,
      "the routes mirror must not disturb the earned clear",
    );
  });
});

test("PARITY: finalize is not STRICTER than grade — an unattributable quarantine elsewhere does not block a surface whose own route is intact", () => {
  withTempHome(() => {
    const domain = "auth-diff-routes-other-quarantine.example.com";
    const { marker, assignment, handoff } = idBearingCrownFixture(domain);

    writeAttackSurface(domain);
    writeAuthDifferentialResults(domain);
    // A malformed row that LOST its surface_id raises grade's GLOBAL routesUnverifiable flag, but
    // a surface whose own route is intact and id_bearing still takes grade's id-bearing branch and
    // clears on the flip. Blocking here would trade the deadlock for a false block.
    writeSurfaceRoutes(domain, [validRouteRow("surface-auth"), { surface_type: "web" }]);
    assert.equal(evaluateAuthDifferentialCompletionCoverage(marker, assignment, handoff), null);
  });
});

test("PARITY: an executed ACCESS-CONTROL finding-differential clears the surface even with routes absent (grade clears that branch too)", () => {
  withTempHome(() => {
    const domain = "auth-diff-routes-absent-ac.example.com";
    const { marker, assignment, handoff } = idBearingCrownFixture(domain);

    // Grade's fail-closed routes branch clears on an executed access-control finding, so finalize
    // must clear on it as well — the block is scoped to the flip-only basis.
    recordCrownFinding(domain, "CWE-639");
    seedVerifiedFindingDifferential(domain, "F-1", "surface-auth");
    assert.equal(fs.existsSync(surfaceRoutesPath(domain)), false);
    assert.equal(evaluateAuthDifferentialCompletionCoverage(marker, assignment, handoff), null);
  });
});

test("PARITY: a PARTIAL surface is unaffected by an unreadable routes document", () => {
  withTempHome(() => {
    const domain = "auth-diff-routes-partial.example.com";
    const { marker, assignment } = idBearingCrownFixture(domain);

    writeAttackSurface(domain);
    writeAuthDifferentialResults(domain);
    fs.mkdirSync(sessionDir(domain), { recursive: true });
    writeFileAtomic(surfaceRoutesPath(domain), "{ corrupt");

    // The honest-partial fallback is the point of the block, so it must stay reachable.
    assert.equal(evaluateAuthDifferentialCompletionCoverage(marker, assignment, {
      surface_status: "partial",
      blocked_prereqs: [],
      blocked_harness_runs: [],
    }), null);
  });
});

test("PARITY: end-to-end finalize refuses the settle with routes absent and allows it once the routes document is restored", () => {
  withTempHome(() => {
    const domain = "auth-diff-routes-e2e.example.com";
    writeAssignments(domain, 1, [{
      agent: "a1",
      surface_id: "surface-auth",
      id_bearing: true,
      auth_differential_required: true,
      id_bearing_endpoints: ["/api/accounts/{id}"],
    }]);
    writeAttackSurface(domain);
    seedTechniqueAttempt(domain, "surface-auth");
    writeSignedHandoff(domain, 1, "a1", "surface-auth");
    writeAuthDifferentialResults(domain);

    const finalizeArgs = {
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-auth",
    };
    const blocked = evaluateAgentCompletion(finalizeArgs);
    assert.equal(blocked.ok, false);
    assert.equal(blocked.block_code, "unverifiable_surface_route");

    const readinessBlocked = buildWaveReadiness(loadWaveArtifacts(domain, 1), { domain });
    assert.deepEqual(readinessBlocked.received_agents, []);
    assert.deepEqual(readinessBlocked.missing_agents, ["a1"]);

    // bob_route_surfaces regenerates the document; the same executed flip now settles.
    writeSurfaceRoutes(domain);
    const allowed = evaluateAgentCompletion(finalizeArgs);
    assert.equal(allowed.ok, true);
    const readinessAllowed = buildWaveReadiness(loadWaveArtifacts(domain, 1), { domain });
    assert.deepEqual(readinessAllowed.received_agents, ["a1"]);
  });
});

test("PARITY: a route whose id-bearing endpoint set DRIFTED away from the assignment does not settle the crown", () => {
  withTempHome(() => {
    const domain = "auth-diff-endpoint-drift.example.com";
    const { marker, assignment, handoff } = idBearingCrownFixture(domain);

    writeAttackSurface(domain);
    writeAuthDifferentialResults(domain);
    writeSurfaceRoutes(domain);

    // Readable, validator-clean, still id_bearing — but the frozen endpoint set no longer covers
    // the endpoint this wave was assigned. Grade binds a credited flip through THAT set
    // (claims.js endpoints.has(rowTemplate)), so it can never credit the sweep; settling here
    // would strand the run with no way back.
    const doc = JSON.parse(fs.readFileSync(surfaceRoutesPath(domain), "utf8"));
    doc.routes = doc.routes.map((route) => (route && route.surface_id === marker.surface_id
      ? { ...route, id_bearing: true, id_bearing_endpoints: ["/api/somewhere-else/{id}"] }
      : route));
    fs.writeFileSync(surfaceRoutesPath(domain), `${JSON.stringify(doc, null, 2)}\n`);

    const blocked = evaluateAuthDifferentialCompletionCoverage(marker, assignment, handoff);
    assert.ok(blocked && blocked.ok === false, "a drifted endpoint set must not settle the crown");
    assert.equal(blocked.block_code, "unverifiable_surface_route");
    assert.match(blocked.reason, /route_endpoints_drifted|no longer lists/);
  });
});

test("PARITY: finalize is not STRICTER than grade — a non-id_bearing route still settles", () => {
  withTempHome(() => {
    const domain = "auth-diff-not-idbearing.example.com";
    const { marker, assignment, handoff } = idBearingCrownFixture(domain);

    writeAttackSurface(domain);
    writeAuthDifferentialResults(domain);
    writeSurfaceRoutes(domain);

    // When the route is no longer id_bearing, grade does not require a flip at all and clears on
    // ordinary evidence. Blocking here would trade the deadlock for a false block.
    const doc = JSON.parse(fs.readFileSync(surfaceRoutesPath(domain), "utf8"));
    doc.routes = doc.routes.map((route) => (route && route.surface_id === marker.surface_id
      ? { ...route, id_bearing: false, id_bearing_endpoints: [] }
      : route));
    fs.writeFileSync(surfaceRoutesPath(domain), `${JSON.stringify(doc, null, 2)}\n`);

    assert.equal(evaluateAuthDifferentialCompletionCoverage(marker, assignment, handoff), null);
  });
});
