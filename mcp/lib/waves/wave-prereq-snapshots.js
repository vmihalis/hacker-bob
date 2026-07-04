"use strict";

const { assertNonEmptyString } = require("../validation.js");
const { listAuthProfiles } = require("../auth.js");
const { listEgressProfiles } = require("../egress-profiles.js");
const { ERROR_CODES, ToolError } = require("../envelope.js");
const {
  readSessionStateStrict,
} = require("../session-state-store.js");
const {
  computeFrontierReadiness,
} = require("../frontier-readiness.js");
const {
  findingPayloadsFromClaims,
} = require("../tools/record-candidate-claim.js");
const {
  summarizeFindings,
} = require("../finding-contracts.js");
const {
  buildCircuitBreakerSummary,
  readHttpAuditRecordsFromJsonl,
  readTrafficRecordsFromJsonl,
  summarizeHttpAuditRecords,
  summarizeTrafficRecords,
} = require("../http-records.js");
const {
  isAssignableSurfaceLead,
  readSurfaceLeadsDocument,
} = require("../surface-leads.js");

// Snapshot registry HANDLE SETS at wave start so the loop detector can reason
// about whether the SPECIFIC material a stuck blocker named was added since.
// Counts collapse unrelated additions into "growth" and give the original
// blocker permanent amnesty (e.g., adding `victim` would silently satisfy
// `auth_missing: attacker`). Failures throw rather than fail-open because the
// caller (start_wave) cannot make a trustworthy snapshot without registry
// visibility — better to refuse the wave than to record a lying snapshot.
function snapshotPrereqRegistries(domain) {
  let authHandles;
  try {
    const result = JSON.parse(listAuthProfiles({ target_domain: domain }));
    authHandles = Array.isArray(result.profiles)
      ? result.profiles.map((p) => p && typeof p.profile_name === "string" ? p.profile_name : null).filter(Boolean)
      : [];
  } catch (error) {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `Could not snapshot auth-profile registry for ${domain}: ${error.message || String(error)}`,
    );
  }
  let egressHandles;
  try {
    const profiles = listEgressProfiles();
    egressHandles = profiles
      .filter((p) => p && p.enabled)
      .map((p) => p && typeof p.name === "string" ? p.name : null)
      .filter(Boolean);
  } catch (error) {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `Could not snapshot egress-profile registry: ${error.message || String(error)}`,
    );
  }
  return {
    auth_handles: Array.from(new Set(authHandles)).sort(),
    egress_handles: Array.from(new Set(egressHandles)).sort(),
  };
}

function waveStatus(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const findings = findingPayloadsFromClaims(domain);
  const summary = summarizeFindings(findings);

  // Compute frontier-readiness analytics for deterministic wave decisions.
  let coverage = null;
  let transitionBlockers = [];
  try {
    const { state } = readSessionStateStrict(domain);
    const readiness = computeFrontierReadiness(domain, state);
    coverage = readiness.coverage;
    transitionBlockers = readiness.transition_blockers;
  } catch (error) {
    transitionBlockers = [{
      code: "state_unavailable",
      message: "session state could not be read for frontier readiness",
      error: error && error.message ? error.message : String(error),
    }];
  }

  // Surface the parked, unroutable surfaces from the DURABLE surface-routes.json
  // (`route.disposition === "unroutable"`), NOT a transient wave-assignment doc.
  // The routes file is written at route time and persists across waves, so this
  // coverage gap stays visible even after a later wave whose assignment doc
  // carries no unroutable surfaces (fixes the cross-wave amnesia). Back-compat:
  // a missing routes file reads as []. A genuinely corrupt/unreadable routes
  // file is NOT masked to a silent [] — it surfaces a distinct diagnostic so a
  // coverage gap is never under-reported by a swallowed read error.
  let unroutableSurfaces = [];
  let unroutableSurfacesError = null;
  let unroutableSurfacesQuarantine = null;
  try {
    const { readSurfaceRoutesStrict } = require("../surface-router.js");
    const routesResult = readSurfaceRoutesStrict(domain);
    const routes = routesResult && routesResult.document && Array.isArray(routesResult.document.routes)
      ? routesResult.document.routes
      : [];
    unroutableSurfaces = routes
      .filter((route) => route && route.disposition === "unroutable")
      .map((route) => ({
        surface_id: route.surface_id,
        surface_type: route.surface_type,
        unroutable_reason: route.reason,
      }));
    // Per-route corruption (a single stale/malformed row) is quarantined by the
    // reader, not thrown. Surface a count + repair hint so a per-route drop is
    // not under-reported either.
    if (Array.isArray(routesResult.malformed_routes) && routesResult.malformed_routes.length > 0) {
      unroutableSurfacesQuarantine = {
        code: "routes_quarantined",
        malformed_route_count: routesResult.malformed_routes.length,
        repair_hint: routesResult.repair_hint
          || "re-run bob_route_surfaces to regenerate surface-routes.json from the current surface index",
      };
    }
  } catch (error) {
    // A missing routes file (no routing yet) is the expected back-compat path,
    // NOT corruption: read as [] with no error. Any other hard failure
    // (unparseable JSON, version mismatch, routes-not-an-array) is genuinely
    // unrecoverable — surface a distinct diagnostic instead of masking a
    // coverage gap to a silent zero.
    const message = error && error.message ? error.message : String(error);
    if (!/^Missing surface routes JSON:/.test(message)) {
      unroutableSurfacesError = { code: "routes_unreadable", message };
    }
  }

  let auditSummary = null;
  let trafficSummary = null;
  let circuitBreakerSummary = null;
  let surfaceLeadsSummary = null;
  try {
    const auditRecords = readHttpAuditRecordsFromJsonl(domain);
    auditSummary = summarizeHttpAuditRecords(auditRecords, { limit: 0 });
    circuitBreakerSummary = buildCircuitBreakerSummary(auditRecords);
  } catch {}
  try {
    trafficSummary = summarizeTrafficRecords(readTrafficRecordsFromJsonl(domain), { limit: 0 });
  } catch {}
  try {
    const surfaceLeads = readSurfaceLeadsDocument(domain);
    surfaceLeadsSummary = {
      total: surfaceLeads.leads.length,
      high_confidence_unpromoted: surfaceLeads.leads.filter(
        (lead) => lead.status !== "promoted" && lead.confidence === "high" && isAssignableSurfaceLead(lead),
      ).length,
      promoted: surfaceLeads.leads.filter((lead) => lead.status === "promoted").length,
    };
  } catch {}

  const response = {
    ...summary,
    coverage,
    transition_blockers: transitionBlockers,
    http_audit: auditSummary,
    traffic: trafficSummary,
    circuit_breaker: circuitBreakerSummary,
    surface_leads: surfaceLeadsSummary,
    unroutable_surfaces: unroutableSurfaces,
    findings_summary: findings.map((finding) => ({
      id: finding.id,
      severity: finding.severity,
      title: finding.title,
      endpoint: finding.endpoint,
      wave_agent: finding.wave || finding.agent ? `${finding.wave || "?"}/${finding.agent || "?"}` : null,
    })),
  };
  // Additive diagnostics: only present when a read error or per-route
  // quarantine occurred, so the "no unroutable surfaces" (empty routes, no
  // error) case stays distinguishable from "could not read routes".
  if (unroutableSurfacesError) response.unroutable_surfaces_error = unroutableSurfacesError;
  if (unroutableSurfacesQuarantine) response.unroutable_surfaces_quarantine = unroutableSurfacesQuarantine;
  return JSON.stringify(response);
}

module.exports = {
  snapshotPrereqRegistries,
  waveStatus,
};
