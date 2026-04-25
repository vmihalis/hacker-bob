"use strict";

const fs = require("fs");
const {
  assertNonEmptyString,
} = require("./validation.js");
const {
  attackSurfacePath,
} = require("./paths.js");
const {
  writeFileAtomic,
} = require("./storage.js");
const {
  readTrafficRecordsFromJsonl,
  summarizeTrafficRecords,
} = require("./http-records.js");
const {
  summarizePublicIntelForSurface,
} = require("./public-intel.js");
const {
  readAttackSurfaceStrict,
} = require("./attack-surface.js");

function stringArray(value) {
  if (value == null) return [];
  const values = Array.isArray(value) ? value : [value];
  return values
    .filter((item) => item != null)
    .map((item) => String(item));
}

function priorityRank(priority) {
  const value = String(priority || "").toUpperCase();
  if (value === "CRITICAL") return 4;
  if (value === "HIGH") return 3;
  if (value === "MEDIUM") return 2;
  if (value === "LOW") return 1;
  return 0;
}

function priorityFromScore(score) {
  if (score >= 80) return "CRITICAL";
  if (score >= 50) return "HIGH";
  if (score >= 25) return "MEDIUM";
  return "LOW";
}

function scoreSurfaceRanking(surface, { trafficSummary = null, intelSummary = null } = {}) {
  const reasons = [];
  let score = 0;
  const text = [
    surface.id,
    ...stringArray(surface.hosts),
    ...stringArray(surface.tech_stack),
    ...stringArray(surface.endpoints),
    ...stringArray(surface.interesting_params),
    ...stringArray(surface.nuclei_hits),
    ...stringArray(surface.js_hints),
    ...stringArray(surface.leaked_secrets),
    ...stringArray(surface.surface_type),
    ...stringArray(surface.bug_class_hints),
    ...stringArray(surface.high_value_flows),
    ...stringArray(surface.evidence),
  ].join("\n").toLowerCase();

  const add = (points, reason) => {
    score += points;
    reasons.push(reason);
  };

  if (/(^|\W)(api|json|swagger|openapi|mobile|graphql|rest)(\W|$)|\/api\/|\/v\d+\//.test(text)) {
    add(22, "api_or_mobile_surface");
  }
  if (/(auth|login|signup|reset|invite|admin|billing|checkout|refund|subscription|invoice|wallet|export|report|team|organization|apikey|api key|webhook)/.test(text)) {
    add(24, "auth_admin_billing_or_data_flow");
  }
  if (/(graphql|graphiql|apollo|hasura|operationname|variables|websocket|socket\.io|\/ws\b|\/wss\b)/.test(text)) {
    add(18, "graphql_or_websocket");
  }
  if (/(^|[_?&/\W])(id|user_id|account_id|org_id|organization_id|team_id|tenant_id|uuid|guid|object_id)(\W|$)/.test(text)) {
    add(16, "object_identifier_params");
  }
  if (stringArray(surface.nuclei_hits).length > 0) {
    add(14, "nuclei_hits");
  }
  if (/(secret|token|apikey|api_key|authorization|bearer|client_secret|private key|akia|sk_live)/.test(text)) {
    add(24, "js_secret_or_key_material");
  }
  if (trafficSummary && trafficSummary.total > 0) {
    add(Math.min(20, 8 + trafficSummary.total), "imported_traffic");
    if (trafficSummary.authenticated_count > 0) {
      add(14, "authenticated_observed_traffic");
    }
  }
  if (intelSummary && intelSummary.available && intelSummary.reports && intelSummary.reports.length > 0) {
    add(12, "disclosed_report_hints");
  }

  return {
    score,
    priority: priorityFromScore(score),
    reasons: reasons.slice(0, 10),
  };
}

function rankAttackSurfaces(domain, { write = false } = {}) {
  const filePath = attackSurfacePath(domain);
  if (!fs.existsSync(filePath)) return null;
  const attackSurface = readAttackSurfaceStrict(domain);
  const trafficRecords = readTrafficRecordsFromJsonl(domain);
  let changed = false;
  const rankedSurfaces = attackSurface.document.surfaces.map((surface) => {
    const trafficSummary = summarizeTrafficRecords(trafficRecords, { surface, limit: 0 });
    const intelSummary = summarizePublicIntelForSurface(domain, surface, 3);
    const ranking = scoreSurfaceRanking(surface, { trafficSummary, intelSummary });
    const currentRanking = surface.ranking && typeof surface.ranking === "object" ? surface.ranking : null;
    const nextSurface = { ...surface };
    const existingPriority = assertNonEmptyString(nextSurface.priority || "LOW", "priority").toUpperCase();
    const rankedPriority = priorityRank(ranking.priority) > priorityRank(existingPriority)
      ? ranking.priority
      : existingPriority;

    const nextRanking = {
      version: 1,
      score: ranking.score,
      priority: ranking.priority,
      reasons: ranking.reasons,
    };
    if (JSON.stringify(currentRanking) !== JSON.stringify(nextRanking)) {
      nextSurface.ranking = nextRanking;
      changed = true;
    }
    if (rankedPriority !== existingPriority) {
      if (!nextSurface.original_priority) nextSurface.original_priority = existingPriority;
      nextSurface.priority = rankedPriority;
      changed = true;
    }
    return nextSurface;
  });

  if (changed && write) {
    writeFileAtomic(filePath, `${JSON.stringify({
      ...attackSurface.document,
      surfaces: rankedSurfaces,
    }, null, 2)}\n`);
  }

  return {
    path: filePath,
    surfaces: rankedSurfaces,
  };
}

module.exports = {
  priorityFromScore,
  priorityRank,
  rankAttackSurfaces,
  scoreSurfaceRanking,
};
