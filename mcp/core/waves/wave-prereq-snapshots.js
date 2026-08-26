"use strict";

const { assertNonEmptyString } = require("../io/validation.js");
const { listAuthProfiles } = require("../auth/index.js");
const { listEgressProfiles } = require("../egress-profiles.js");
const { ERROR_CODES, ToolError } = require("../io/envelope.js");
const {
  readSessionStateStrict,
} = require("../session/session-state-store.js");
const {
  computeFrontierReadiness,
} = require("../frontier/frontier-readiness.js");
const {
  findingPayloadsFromClaims,
} = require("../claims/candidate-claim-recorder.js");
const {
  summarizeFindings,
} = require("../finding-contracts.js");
const {
  buildCircuitBreakerSummary,
  readHttpAuditRecordsFromJsonl,
  readTrafficRecordsFromJsonl,
  summarizeHttpAuditRecords,
  summarizeTrafficRecords,
} = require("../io/http-records.js");
const {
  isAssignableSurfaceLead,
  readSurfaceLeadsDocument,
} = require("../frontier/surface-leads.js");

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
  // (the canonical isUnroutableRoute predicate: disposition marker OR null pack),
  // NOT a transient wave-assignment doc.
  // The routes file is written at route time and persists across waves, so this
  // coverage gap stays visible even after a later wave whose assignment doc
  // carries no unroutable surfaces (fixes the cross-wave amnesia). This shares
  // the SINGLE derivation (deriveUnroutableSurfacesFromRoutes) with planNextWave,
  // so status and the planner never disagree on which surfaces are parked or on
  // the corruption policy. Back-compat: a missing routes file reads as []. A
  // genuinely corrupt/unreadable routes file is NOT masked to a silent [] — it
  // surfaces a distinct diagnostic so a coverage gap is never under-reported by a
  // swallowed read error.
  const { deriveUnroutableSurfacesFromRoutes } = require("../frontier/surface-router.js");
  const routesDerivation = deriveUnroutableSurfacesFromRoutes(domain);
  const unroutableSurfaces = routesDerivation.surfaces;
  const unroutableSurfacesError = routesDerivation.error;
  // Per-route corruption (a single stale/malformed row) is quarantined by the
  // reader, not thrown. Surface a count + repair hint so a per-route drop is not
  // under-reported either.
  const unroutableSurfacesQuarantine = routesDerivation.malformed_route_count > 0
    ? {
        code: "routes_quarantined",
        malformed_route_count: routesDerivation.malformed_route_count,
        repair_hint: routesDerivation.repair_hint,
      }
    : null;

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
