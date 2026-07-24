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
      ? {
        ...route,
        // Mirror the router: id_bearing (detector, principal-independent) drives the strong
        // no-bypass branch; auth_differential_required (the FLIP obligation) additionally needs
        // >=2 principals. This helper models both as the same `required` toggle.
        id_bearing: required,
        auth_differential_required: required,
        id_bearing_endpoints: required ? ["/api/orders/{id}"] : [],
      }
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

function seedCompleteSurface(domain, { surfaceId = "surface-a", idBearing = false, cwe = "CWE-639" } = {}) {
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
    cwe,
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

function setRouteFlags(domain, surfaceId, { idBearing, authDiff, endpoints = [] }) {
  const document = JSON.parse(fs.readFileSync(surfaceRoutesPath(domain), "utf8"));
  document.routes = (document.routes || []).map((route) => (
    route && route.surface_id === surfaceId
      ? { ...route, id_bearing: idBearing, auth_differential_required: authDiff, id_bearing_endpoints: endpoints }
      : route
  ));
  writeFileAtomic(surfaceRoutesPath(domain), `${JSON.stringify(document, null, 2)}\n`);
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

function buildAuthDifferentialRow(domain, endpoint, { distinctPrincipalCount = 2, authenticatedAccess = true, surfaceId = "surface-a", effectiveUrl } = {}) {
  const normalizedPath = endpoint.startsWith("/") ? endpoint : `/${endpoint}`;
  const row = {
    surface_id: surfaceId,
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
    // The runner computes this; here we model it per scenario: a cross-tenant FLIP needs a
    // real accessor (alice 2xx) AND a distinct validated denied principal (>=2). Both-denied
    // (authenticatedAccess=false) or same-principal (distinct<2) => no flip.
    cross_tenant_flip: authenticatedAccess && distinctPrincipalCount >= 2,
  };
  // Model the runner's urlbind: effective_url = joinUrl(base_url, endpoint) is stamped on every
  // production row and enters the row_mac preimage. Default to the in-scope join; an explicit
  // null models a legacy/pre-urlbind row (the gate's back-compat skip); an explicit string
  // models a base_url relabel (an off-scope host, or a benign path prefix).
  if (effectiveUrl === undefined) {
    row.effective_url = `https://${domain}${normalizedPath}`;
  } else if (effectiveUrl !== null) {
    row.effective_url = effectiveUrl;
  }
  return row;
}

function writeAuthDifferentialRows(domain, rows) {
  writeFileAtomic(authDifferentialResultsPath(domain), `${JSON.stringify({
    version: 1,
    target_domain: domain,
    per_endpoint: rows,
  }, null, 2)}\n`);
}

function writeAuthDifferentialResults(domain, endpoint, opts = {}) {
  const { signRowViaIsolatedSignerOrLocal } = require("../mcp/lib/handoff-signing-key.js");
  const { AUTH_DIFFERENTIAL_ROW_MAC_CONTEXT } = require("../mcp/lib/offensive-row-mac.js");
  const row = buildAuthDifferentialRow(domain, endpoint, opts);
  // Sign the row the way the runner does (each persisted row carries a row_mac under the
  // auth-differential context) so the MAC-verifying grade-time consumer credits a genuine flip.
  signRowViaIsolatedSignerOrLocal(domain, AUTH_DIFFERENTIAL_ROW_MAC_CONTEXT, row);
  writeAuthDifferentialRows(domain, [row]);
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

test("a server-derived capability-pack completion binding counts as executed depth for its exact finding", () => {
  withTempHome(() => withIsolatedSigner(() => {
    const domain = "pack-completion-depth.example.com";
    const { endpoint, surfaceId } = seedCompleteSurface(domain, { idBearing: true });
    writeCoverageRow(domain, surfaceId, endpoint);

    assert.equal(completionDepthGapForCompleteSurfaces(domain).missing.length, 1);
    assert.deepEqual(
      completionDepthGapForCompleteSurfaces(domain, {
        packExecutedFindingIds: new Set(["F-1"]),
      }).missing,
      [],
    );
    assert.equal(
      completionDepthGapForCompleteSurfaces(domain, {
        packExecutedFindingIds: new Set(["F-999"]),
      }).missing.length,
      1,
      "a pack binding for another finding cannot clear this surface",
    );
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

test("id-bearing complete surface does NOT clear on an UNSIGNED flipped row (row MAC fails closed)", () => {
  withTempHome(() => withIsolatedSigner(() => {
    const domain = "idbearing-unsigned-flip.example.com";
    const { endpoint, surfaceId } = seedCompleteSurface(domain, { idBearing: true });
    writeCoverageRow(domain, surfaceId, endpoint);
    // A genuine-looking cross-tenant flip written straight to disk with NO row_mac — the exact
    // Bash-forged row the audit-grade + MAC layer must reject. assertRowMac is STRICT, so an
    // unsigned row throws and is skipped: the surface earns no auth-differential coverage.
    writeAuthDifferentialRows(domain, [buildAuthDifferentialRow(domain, endpoint)]);

    assert.deepEqual(completionDepthGapForCompleteSurfaces(domain).missing, [{
      surface_id: surfaceId,
      finding_id: "F-1",
      reason: "complete_idbearing_surface_no_differential",
    }]);
  }));
});

test("id-bearing complete surface does NOT clear on a TAMPERED flip (content mutated after signing invalidates the MAC)", () => {
  withTempHome(() => withIsolatedSigner(() => {
    const domain = "idbearing-tampered-flip.example.com";
    const { endpoint, surfaceId } = seedCompleteSurface(domain, { idBearing: true });
    writeCoverageRow(domain, surfaceId, endpoint);
    const { signRowViaIsolatedSignerOrLocal } = require("../mcp/lib/handoff-signing-key.js");
    const { AUTH_DIFFERENTIAL_ROW_MAC_CONTEXT } = require("../mcp/lib/offensive-row-mac.js");
    // Sign a NON-flip row (cross_tenant_flip:false), then MUTATE it to flip true AFTER signing.
    // The row_mac binds cross_tenant_flip, so the mutated field no longer verifies -> fail closed.
    const row = buildAuthDifferentialRow(domain, endpoint, { authenticatedAccess: false });
    signRowViaIsolatedSignerOrLocal(domain, AUTH_DIFFERENTIAL_ROW_MAC_CONTEXT, row);
    row.cross_tenant_flip = true;
    writeAuthDifferentialRows(domain, [row]);

    assert.deepEqual(completionDepthGapForCompleteSurfaces(domain).missing, [{
      surface_id: surfaceId,
      finding_id: "F-1",
      reason: "complete_idbearing_surface_no_differential",
    }]);
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

test("id-bearing complete surface does NOT clear on a sweep bound to a DIFFERENT surface_id (no endpoint-string bleed)", () => {
  withTempHome(() => withIsolatedSigner(() => {
    const domain = "idbearing-cross-surface.example.com";
    const { endpoint, surfaceId } = seedCompleteSurface(domain, { idBearing: true });
    writeCoverageRow(domain, surfaceId, endpoint);
    // A genuine distinct-principal, real-access sweep on the SAME endpoint string, but the
    // row is stamped for a different surface (the sweep was run for "surface-other"). It
    // must not clear this surface — coverage binds by surface_id, not raw endpoint string.
    writeAuthDifferentialResults(domain, endpoint, { surfaceId: "surface-other" });

    assert.deepEqual(completionDepthGapForCompleteSurfaces(domain).missing, [{
      surface_id: surfaceId,
      finding_id: "F-1",
      reason: "complete_idbearing_surface_no_differential",
    }]);
  }));
});

test("id-bearing complete surface does NOT clear on a real flip hitting an endpoint outside the FROZEN route set (attack_surface relabel is ignored)", () => {
  withTempHome(() => withIsolatedSigner(() => {
    const domain = "idbearing-frozen-endpoint.example.com";
    const { surfaceId } = seedCompleteSurface(domain, { idBearing: true });
    writeCoverageRow(domain, surfaceId, "/api/orders/12345");
    // A GENUINE cross-tenant flip, stamped surface_id=surface-a, but executed against an easy
    // endpoint (/notes/999) that is NOT in the surface's FROZEN (MCP-owned route) id-bearing
    // set (/api/orders/{id}). An agent relabeling attack_surface.json to add /notes/{id} under
    // surface-a cannot help: the gate binds to the frozen route endpoints, never agent scratch.
    writeAuthDifferentialResults(domain, "/notes/999", { surfaceId });
    assert.deepEqual(completionDepthGapForCompleteSurfaces(domain).missing, [{
      surface_id: surfaceId,
      finding_id: "F-1",
      reason: "complete_idbearing_surface_no_differential",
    }]);
  }));
});

test("single-account id-bearing surface (id_bearing true, auth_differential_required false) does NOT launder to complete via a coverage/bypass narrative", () => {
  withTempHome(() => withIsolatedSigner(() => {
    const domain = "single-account-idbearing.example.com";
    const { endpoint, surfaceId } = seedCompleteSurface(domain, { idBearing: true });
    // A single-account run: the detector fired (id_bearing) but there are <2 distinct principals,
    // so the cross-tenant flip obligation is unsatisfiable. The surface must NOT clear on a
    // coverage row / bypass narrative — it needs a real finding, else it stays an honest partial.
    setRouteFlags(domain, surfaceId, { idBearing: true, authDiff: false });
    writeCoverageRow(domain, surfaceId, endpoint);
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

test("present-but-unreadable surface-routes.json fails CLOSED: a complete surface cannot clear on a coverage row alone", () => {
  withTempHome(() => withIsolatedSigner(() => {
    const domain = "routes-corrupt-failclosed.example.com";
    // A NON-id-bearing complete surface that would normally clear on a concrete coverage row.
    const { endpoint, surfaceId } = seedCompleteSurface(domain, { idBearing: false });
    writeCoverageRow(domain, surfaceId, endpoint);
    // Sanity: with intact routes it clears.
    assert.equal(completionDepthGapForCompleteSurfaces(domain).missing.length, 0);

    // Corrupt the routes file (present but unparseable): the id-bearing predicate can no longer
    // be established, so the surface must NOT silently drop to the non-id-bearing bypass path.
    writeFileAtomic(surfaceRoutesPath(domain), "{ this is not valid json ]");

    const gap = completionDepthGapForCompleteSurfaces(domain);
    assert.deepEqual(gap.missing, [{
      surface_id: surfaceId,
      finding_id: "F-1",
      reason: "complete_surface_routes_unverifiable",
    }]);
  }));
});

test("present-but-unreadable surface-routes.json still clears a surface backed by executed evidence", () => {
  withTempHome(() => withIsolatedSigner(() => {
    const domain = "routes-corrupt-executed.example.com";
    const { surfaceId } = seedCompleteSurface(domain, { idBearing: false });
    writeFileAtomic(surfaceRoutesPath(domain), "{ corrupt");

    // Real executed evidence (a pack-executed finding) clears even when the predicate is
    // unverifiable — fail-closed holds bypass narratives, not genuine executed proof.
    assert.equal(
      completionDepthGapForCompleteSurfaces(domain, {
        packExecutedFindingIds: new Set(["F-1"]),
      }).missing.length,
      0,
    );
  }));
});

test("ABSENT surface-routes.json with a complete surface fails CLOSED (routing must have run to assign it — an integrity anomaly, not benign)", () => {
  withTempHome(() => withIsolatedSigner(() => {
    const domain = "routes-absent-failclosed.example.com";
    const { endpoint, surfaceId } = seedCompleteSurface(domain, { idBearing: false });
    writeCoverageRow(domain, surfaceId, endpoint);
    // A complete surface was assigned, which REQUIRED a route; so an ABSENT routes file at grade is an
    // integrity anomaly (deletion / torn write), NOT the benign no-routing case (which has no complete
    // surface to grade and returns early). It must fail CLOSED — never launder on a coverage row.
    fs.rmSync(surfaceRoutesPath(domain));
    assert.deepEqual(completionDepthGapForCompleteSurfaces(domain).missing, [{
      surface_id: surfaceId, finding_id: "F-1", reason: "complete_surface_routes_unverifiable",
    }]);
  }));
});

test("ABSENT surface-routes.json does NOT let an id-bearing crown clear on a coverage row (reproduced whole-file-absent false-CLEAR, now closed)", () => {
  withTempHome(() => withIsolatedSigner(() => {
    const domain = "routes-absent-crown.example.com";
    const { endpoint, surfaceId } = seedCompleteSurface(domain, { idBearing: true });
    writeCoverageRow(domain, surfaceId, endpoint);
    assert.equal(completionDepthGapForCompleteSurfaces(domain).missing.length, 1, "route present: crown held");
    // Deleting the whole routes file must NOT collapse the crown to "not id-bearing" and clear it on
    // the coverage row — it stays held as routes-unverifiable (fail closed).
    fs.rmSync(surfaceRoutesPath(domain));
    assert.deepEqual(completionDepthGapForCompleteSurfaces(domain).missing, [{
      surface_id: surfaceId, finding_id: "F-1", reason: "complete_surface_routes_unverifiable",
    }]);
  }));
});

test("routes-unverifiable holds on a NON-access-control executed finding (a possibly-crown obligation is not discharged by an XSS)", () => {
  withTempHome(() => withIsolatedSigner(() => {
    // CWE-79 (XSS) is NOT an access-control class. On a corrupt/unverifiable routes doc the surface
    // could be an id-bearing crown, so an executed XSS must NOT clear it (only an access-control
    // finding / flip / composition does) — the access-control obligation must not leak on this branch.
    const xssDomain = "routes-unverifiable-xss.example.com";
    const { surfaceId: xssSurface } = seedCompleteSurface(xssDomain, { idBearing: false, cwe: "CWE-79" });
    writeFileAtomic(surfaceRoutesPath(xssDomain), "{ corrupt");
    assert.deepEqual(completionDepthGapForCompleteSurfaces(xssDomain, {
      packExecutedFindingIds: new Set(["F-1"]),
    }).missing, [{ surface_id: xssSurface, finding_id: "F-1", reason: "complete_surface_routes_unverifiable" }]);

    // Contrast: an executed ACCESS-CONTROL finding (CWE-639) DOES clear an unverifiable surface.
    const acDomain = "routes-unverifiable-ac.example.com";
    seedCompleteSurface(acDomain, { idBearing: false, cwe: "CWE-639" });
    writeFileAtomic(surfaceRoutesPath(acDomain), "{ corrupt");
    assert.equal(completionDepthGapForCompleteSurfaces(acDomain, {
      packExecutedFindingIds: new Set(["F-1"]),
    }).missing.length, 0);
  }));
});

test("a per-route QUARANTINED id-bearing route fails CLOSED (valid envelope, route silently dropped): no bypass laundering", () => {
  withTempHome(() => withIsolatedSigner(() => {
    const domain = "routes-quarantine-failclosed.example.com";
    const { endpoint, surfaceId } = seedCompleteSurface(domain, { idBearing: true });
    writeCoverageRow(domain, surfaceId, endpoint);
    // Intact id-bearing route: held as an id-bearing surface (needs a flip, not a coverage row).
    assert.deepEqual(completionDepthGapForCompleteSurfaces(domain).missing, [{
      surface_id: surfaceId, finding_id: "F-1", reason: "complete_idbearing_surface_no_differential",
    }]);

    // Corrupt ONE field so the route is per-route QUARANTINED (valid top-level envelope, a plain-Error
    // route-validation failure) while keeping surface_id + id_bearing — the cross-version route-field
    // drift case the resilient reader silently drops into malformed_routes[].
    const doc = JSON.parse(fs.readFileSync(surfaceRoutesPath(domain), "utf8"));
    doc.routes = doc.routes.map((r) => (r && r.surface_id === surfaceId
      ? { ...r, auth_differential_required: "not-a-boolean" } : r));
    writeFileAtomic(surfaceRoutesPath(domain), `${JSON.stringify(doc, null, 2)}\n`);

    // The crown's route is now dropped from document.routes; it must NOT silently launder to the
    // non-id-bearing bypass branch — it is held as routes-unverifiable via its quarantined surface_id.
    assert.deepEqual(completionDepthGapForCompleteSurfaces(domain).missing, [{
      surface_id: surfaceId, finding_id: "F-1", reason: "complete_surface_routes_unverifiable",
    }]);
  }));
});

test("a DANGLING SYMLINK at surface-routes.json fails CLOSED (present-but-unreadable, not benign-absent)", () => {
  withTempHome(() => withIsolatedSigner(() => {
    const domain = "routes-symlink-failclosed.example.com";
    const { endpoint, surfaceId } = seedCompleteSurface(domain, { idBearing: false });
    writeCoverageRow(domain, surfaceId, endpoint);
    const routesPath = surfaceRoutesPath(domain);
    fs.rmSync(routesPath);
    // A broken symlink reads as unreadable to readSurfaceRoutesStrict -> the catch fails CLOSED for
    // every complete surface (routing must have run to assign one), not laundered on the coverage row.
    fs.symlinkSync(path.join(path.dirname(routesPath), "does-not-exist.json"), routesPath);
    assert.deepEqual(completionDepthGapForCompleteSurfaces(domain).missing, [{
      surface_id: surfaceId, finding_id: "F-1", reason: "complete_surface_routes_unverifiable",
    }]);
  }));
});

// --- (B1) id-bearing independence: the clearing EXECUTED finding must be access-control ---

test("id-bearing crown does NOT clear on an executed NON-access-control finding (XSS/CWE-79)", () => {
  withTempHome(() => withIsolatedSigner(() => {
    const domain = "idbearing-xss-executed.example.com";
    // An executed XSS on the crown surface proves impact but never the cross-tenant object-auth
    // test, so it must NOT discharge the id-bearing obligation — held as an honest partial.
    const { surfaceId } = seedCompleteSurface(domain, { idBearing: true, cwe: "CWE-79" });
    assert.deepEqual(
      completionDepthGapForCompleteSurfaces(domain, { packExecutedFindingIds: new Set(["F-1"]) }).missing,
      [{ surface_id: surfaceId, finding_id: "F-1", reason: "complete_idbearing_surface_no_differential" }],
    );
  }));
});

test("id-bearing crown DOES clear on an executed ACCESS-CONTROL finding (IDOR/CWE-639)", () => {
  withTempHome(() => withIsolatedSigner(() => {
    const domain = "idbearing-ac-executed.example.com";
    // The same executed binding on an access-control finding IS the cross-tenant proof, so it
    // discharges the crown obligation. (Contrast the CWE-79 case above — same execution, held.)
    seedCompleteSurface(domain, { idBearing: true, cwe: "CWE-639" });
    assert.equal(
      completionDepthGapForCompleteSurfaces(domain, { packExecutedFindingIds: new Set(["F-1"]) }).missing.length,
      0,
    );
  }));
});

test("id-bearing crown with an executed non-access-control finding STILL clears via a real auth-differential flip", () => {
  withTempHome(() => withIsolatedSigner(() => {
    const domain = "idbearing-xss-plus-flip.example.com";
    // A non-access-control executed finding does not clear the crown by itself, but a genuine
    // cross-tenant flip on the frozen endpoint still does — the auth-differential path is
    // independent of the finding class.
    const { endpoint } = seedCompleteSurface(domain, { idBearing: true, cwe: "CWE-79" });
    writeAuthDifferentialResults(domain, endpoint);
    assert.equal(
      completionDepthGapForCompleteSurfaces(domain, { packExecutedFindingIds: new Set(["F-1"]) }).missing.length,
      0,
    );
  }));
});

// --- (TOTALITY) a complete surface absent from the readable routes document ---

test("a complete surface ABSENT from the readable routes document is held as routes-unverifiable (not laundered on a coverage row)", () => {
  withTempHome(() => withIsolatedSigner(() => {
    const domain = "complete-surface-no-route.example.com";
    const { endpoint, surfaceId } = seedCompleteSurface(domain, { idBearing: false });
    writeCoverageRow(domain, surfaceId, endpoint);
    // Sanity: with its route present it clears on the concrete coverage row.
    assert.equal(completionDepthGapForCompleteSurfaces(domain).missing.length, 0);
    // Drop this surface's route entry while keeping a VALID routes envelope. Every complete
    // surface is assigned and every assignment requires a route, so an absent route is an
    // integrity anomaly — the surface must NOT silently drop to the non-id-bearing bypass branch.
    const doc = JSON.parse(fs.readFileSync(surfaceRoutesPath(domain), "utf8"));
    doc.routes = (doc.routes || []).filter((r) => r && r.surface_id !== surfaceId);
    writeFileAtomic(surfaceRoutesPath(domain), `${JSON.stringify(doc, null, 2)}\n`);
    assert.deepEqual(completionDepthGapForCompleteSurfaces(domain).missing, [{
      surface_id: surfaceId, finding_id: "F-1", reason: "complete_surface_routes_unverifiable",
    }]);
  }));
});

test("a routeless complete surface still clears on genuine executed evidence", () => {
  withTempHome(() => withIsolatedSigner(() => {
    const domain = "complete-surface-no-route-executed.example.com";
    const { surfaceId } = seedCompleteSurface(domain, { idBearing: false });
    const doc = JSON.parse(fs.readFileSync(surfaceRoutesPath(domain), "utf8"));
    doc.routes = (doc.routes || []).filter((r) => r && r.surface_id !== surfaceId);
    writeFileAtomic(surfaceRoutesPath(domain), `${JSON.stringify(doc, null, 2)}\n`);
    // Real executed evidence clears even when the route is missing — the totality hold blocks
    // bypass narratives, not genuine executed proof.
    assert.equal(
      completionDepthGapForCompleteSurfaces(domain, { packExecutedFindingIds: new Set(["F-1"]) }).missing.length,
      0,
    );
  }));
});

// --- (B3) effective_url gate-check: base_url relabel must not credit a flip ---

test("id-bearing crown does NOT clear on a flip whose effective_url host is OFF-SCOPE (base_url host relabel)", () => {
  withTempHome(() => withIsolatedSigner(() => {
    const domain = "idbearing-effurl-offhost.example.com";
    const { endpoint, surfaceId } = seedCompleteSurface(domain, { idBearing: true });
    writeCoverageRow(domain, surfaceId, endpoint);
    // A genuine signed flip with the correct endpoint + surface_id + template, but effective_url
    // shows the arm actually hit an OFF-SCOPE host (base_url relabel). Not credited -> held.
    writeAuthDifferentialResults(domain, endpoint, { effectiveUrl: `https://evil-relabel.com${endpoint}` });
    assert.deepEqual(completionDepthGapForCompleteSurfaces(domain).missing, [{
      surface_id: surfaceId, finding_id: "F-1", reason: "complete_idbearing_surface_no_differential",
    }]);
  }));
});

test("id-bearing crown does NOT clear on a flip whose effective_url carries a benign PATH PREFIX (base_url path relabel)", () => {
  withTempHome(() => withIsolatedSigner(() => {
    const domain = "idbearing-effurl-prefix.example.com";
    const { endpoint, surfaceId } = seedCompleteSurface(domain, { idBearing: true });
    writeCoverageRow(domain, surfaceId, endpoint);
    // effective_url path is /safe-prefix + endpoint, which templatizes to /safe-prefix/api/orders/{id}
    // — NOT in the surface's frozen id-bearing set. The signed `endpoint` alone matches, but the
    // real tested URL was an easy same-host path under a relabeled base_url. Not credited -> held.
    writeAuthDifferentialResults(domain, endpoint, { effectiveUrl: `https://${domain}/safe-prefix${endpoint}` });
    assert.deepEqual(completionDepthGapForCompleteSurfaces(domain).missing, [{
      surface_id: surfaceId, finding_id: "F-1", reason: "complete_idbearing_surface_no_differential",
    }]);
  }));
});

test("id-bearing crown clears on an in-scope effective_url that matches the frozen endpoint (subdomain host is in scope)", () => {
  withTempHome(() => withIsolatedSigner(() => {
    const domain = "idbearing-effurl-ok.example.com";
    const { endpoint, surfaceId } = seedCompleteSurface(domain, { idBearing: true });
    writeCoverageRow(domain, surfaceId, endpoint);
    // effective_url on an IN-SCOPE subdomain, hitting the same crown endpoint path -> credited.
    writeAuthDifferentialResults(domain, endpoint, { effectiveUrl: `https://api.${domain}${endpoint}` });
    assert.equal(completionDepthGapForCompleteSurfaces(domain).missing.length, 0);
  }));
});

test("id-bearing crown clears on a legacy flip row with NO effective_url (back-compat skip of the B3 check)", () => {
  withTempHome(() => withIsolatedSigner(() => {
    const domain = "idbearing-effurl-legacy.example.com";
    const { endpoint, surfaceId } = seedCompleteSurface(domain, { idBearing: true });
    writeCoverageRow(domain, surfaceId, endpoint);
    // A pre-urlbind row carries no effective_url; the B3 check is skipped and the existing
    // MAC + flip + endpoint-template checks still credit the genuine flip.
    writeAuthDifferentialResults(domain, endpoint, { effectiveUrl: null });
    assert.equal(completionDepthGapForCompleteSurfaces(domain).missing.length, 0);
  }));
});
