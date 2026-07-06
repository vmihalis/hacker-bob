"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const recordCandidateClaimTool = require("../mcp/lib/tools/record-candidate-claim.js");
const { completionDepthGapForCompleteSurfaces } = require("../mcp/lib/claims.js");
const { logCoverage } = require("../mcp/lib/coverage.js");
const { initSession, advanceSession } = require("../mcp/lib/session-state.js");
const { startWave, writeWaveHandoff: writeWaveHandoffRaw } = require("../mcp/lib/waves.js");
const {
  attackSurfacePath,
  authDifferentialResultsPath,
  surfaceRoutesPath,
} = require("../mcp/lib/paths.js");
const { writeFileAtomic } = require("../mcp/lib/storage.js");
const { withIsolatedSigner } = require("./helpers/sandbox-isolated-signer.js");

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-test-"));
  process.env.HOME = tempHome;

  const cleanup = () => {
    if (previousHome === undefined) {
      delete process.env.HOME;
    } else {
      process.env.HOME = previousHome;
    }
    fs.rmSync(tempHome, { recursive: true, force: true });
  };

  try {
    const result = fn(tempHome);
    if (result && typeof result.then === "function") {
      return result.finally(cleanup);
    }
    cleanup();
    return result;
  } catch (error) {
    cleanup();
    throw error;
  }
}

function seedAttackSurface(domain, surfaceId) {
  const endpoint = "/api/orders/12345";
  const surfaces = [{
    id: surfaceId,
    uri: `https://${domain}${endpoint}`,
    hosts: [`https://${domain}`],
    endpoints: [endpoint],
    priority: "HIGH",
  }];
  writeFileAtomic(attackSurfacePath(domain), `${JSON.stringify({ surfaces }, null, 2)}\n`);
  return { endpoint };
}

function setAuthDifferentialRequired(domain, surfaceId, required) {
  const document = JSON.parse(fs.readFileSync(surfaceRoutesPath(domain), "utf8"));
  document.routes = (document.routes || []).map((route) => (
    route && route.surface_id === surfaceId
      ? { ...route, auth_differential_required: required }
      : route
  ));
  writeFileAtomic(surfaceRoutesPath(domain), `${JSON.stringify(document, null, 2)}\n`);
}

function recordFinding(args) {
  return recordCandidateClaimTool.handler({
    ...args,
    cvss_inputs: {
      attack_vector: "network",
      privileges_required: "low",
      confidentiality: "high",
    },
  });
}

function seedCompleteSurface(domain, { surfaceId = "surface-a", idBearing = false } = {}) {
  JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}` }));
  const { endpoint } = seedAttackSurface(domain, surfaceId);
  JSON.parse(advanceSession({ target_domain: domain, to_state: "OPEN_FRONTIER" }));
  const started = JSON.parse(startWave({
    target_domain: domain,
    wave_number: 1,
    assignments: [{ agent: "a1", surface_id: surfaceId }],
  }));
  setAuthDifferentialRequired(domain, surfaceId, idBearing);
  JSON.parse(recordFinding({
    target_domain: domain,
    title: "IDOR on export",
    severity: "high",
    cwe: "CWE-639",
    endpoint,
    description: "Cross-account export is possible.",
    proof_of_concept: "poc",
    response_evidence: "evidence",
    impact: "PII disclosure.",
    validated: true,
    wave: "w1",
    agent: "a1",
    surface_id: surfaceId,
  }));
  JSON.parse(writeWaveHandoffRaw({
    target_domain: domain,
    wave: "w1",
    agent: "a1",
    surface_id: surfaceId,
    surface_status: "complete",
    handoff_token: started.assignments[0].handoff_token,
    summary: "surface complete",
    content: "# Handoff\n\nbody",
  }));
  return { endpoint, surfaceId };
}

function writeCoverageRow(domain, surfaceId, endpoint) {
  JSON.parse(logCoverage({
    target_domain: domain,
    wave: "w1",
    agent: "a1",
    surface_id: surfaceId,
    entries: [{
      endpoint,
      method: "GET",
      bug_class: "idor",
      status: "tested",
      evidence_summary: "probed cross-account export",
    }],
  }));
}

function writeAuthDifferentialResults(domain, endpoint, { distinctPrincipalCount = 2, authenticatedAccess = true } = {}) {
  writeFileAtomic(authDifferentialResultsPath(domain), `${JSON.stringify({
    version: 1,
    target_domain: domain,
    per_endpoint: [{
      endpoint,
      signatures_by_profile: {
        // authenticatedAccess=false models the fabricated-cookie attack: two distinct
        // credentials that BOTH get denied (no 2xx, no divergence) — never a real test.
        alice: authenticatedAccess
          ? { status: 200, response_class: "ok", sent_with_auth: true }
          : { status: 403, response_class: "forbidden", sent_with_auth: true },
        bob: { status: 403, response_class: "forbidden", sent_with_auth: true },
      },
      divergences: [],
      distinct_principal_count: distinctPrincipalCount,
    }],
  }, null, 2)}\n`);
}

test("id-bearing complete surface does not clear on a hand-written coverage row alone", () => {
  withTempHome(() => withIsolatedSigner(() => {
    const domain = "idbearing-forged-coverage.example.com";
    const { endpoint, surfaceId } = seedCompleteSurface(domain, { idBearing: true });
    writeCoverageRow(domain, surfaceId, endpoint);

    const gap = completionDepthGapForCompleteSurfaces(domain);
    assert.deepEqual(gap.missing, [{
      surface_id: surfaceId,
      finding_id: "F-1",
      reason: "complete_idbearing_surface_no_differential",
    }]);
  }));
});

test("id-bearing complete surface clears with auth-differential coverage from two profiles", () => {
  withTempHome(() => withIsolatedSigner(() => {
    const domain = "idbearing-auth-diff.example.com";
    const { endpoint, surfaceId } = seedCompleteSurface(domain, { idBearing: true });
    writeCoverageRow(domain, surfaceId, endpoint);
    writeAuthDifferentialResults(domain, endpoint);

    assert.equal(completionDepthGapForCompleteSurfaces(domain).missing.length, 0);
  }));
});

test("id-bearing complete surface does NOT clear on a same-principal two-name sweep (distinct_principal_count < 2)", () => {
  withTempHome(() => withIsolatedSigner(() => {
    const domain = "idbearing-same-principal.example.com";
    const { endpoint, surfaceId } = seedCompleteSurface(domain, { idBearing: true });
    writeCoverageRow(domain, surfaceId, endpoint);
    // The forgeability attack: two profile NAMES bound to the same session collapse to
    // ONE principal fingerprint, so the runner records distinct_principal_count: 1 — a
    // sweep that never actually tested cross-tenant. It must not clear the id-bearing gate.
    writeAuthDifferentialResults(domain, endpoint, { distinctPrincipalCount: 1 });

    assert.deepEqual(completionDepthGapForCompleteSurfaces(domain).missing, [{
      surface_id: surfaceId,
      finding_id: "F-1",
      reason: "complete_idbearing_surface_no_differential",
    }]);
  }));
});

test("id-bearing complete surface does NOT clear on a two-fabricated-cookie sweep (distinct fingerprints, both denied, no flip)", () => {
  withTempHome(() => withIsolatedSigner(() => {
    const domain = "idbearing-fabricated-cookies.example.com";
    const { endpoint, surfaceId } = seedCompleteSurface(domain, { idBearing: true });
    writeCoverageRow(domain, surfaceId, endpoint);
    // The attack: two throwaway cookies mint distinct fingerprints (distinct_principal_count:2)
    // but neither is a real account — both requests are denied and divergences[] is empty, so
    // the sweep never tested cross-tenant isolation. The gate must NOT count it as coverage.
    writeAuthDifferentialResults(domain, endpoint, { distinctPrincipalCount: 2, authenticatedAccess: false });

    assert.deepEqual(completionDepthGapForCompleteSurfaces(domain).missing, [{
      surface_id: surfaceId,
      finding_id: "F-1",
      reason: "complete_idbearing_surface_no_differential",
    }]);
  }));
});

test("non-id-bearing complete surface keeps the existing coverage-row completion behavior", () => {
  withTempHome(() => withIsolatedSigner(() => {
    const domain = "legacy-coverage.example.com";
    const { endpoint, surfaceId } = seedCompleteSurface(domain, { idBearing: false });
    writeCoverageRow(domain, surfaceId, endpoint);

    assert.equal(completionDepthGapForCompleteSurfaces(domain).missing.length, 0);
  }));
});

test("malformed auth-differential results fail closed for an id-bearing coverage-only surface", () => {
  withTempHome(() => withIsolatedSigner(() => {
    const domain = "idbearing-malformed-auth-diff.example.com";
    const { endpoint, surfaceId } = seedCompleteSurface(domain, { idBearing: true });
    writeCoverageRow(domain, surfaceId, endpoint);
    writeFileAtomic(authDifferentialResultsPath(domain), "{not valid json");

    const gap = completionDepthGapForCompleteSurfaces(domain);
    assert.deepEqual(gap.missing, [{
      surface_id: surfaceId,
      finding_id: "F-1",
      reason: "complete_idbearing_surface_no_differential",
    }]);
  }));
});
