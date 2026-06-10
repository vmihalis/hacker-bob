"use strict";

const {
  mapSarifResultToSurfaceLead,
  normalizeRepoPath,
} = require("./static-analysis-index.js");

const STATIC_LEAD_SOURCE = "bob_static_scan";
const STATIC_LEAD_SURFACE_TYPE = "oss_static_sink";
const STATIC_LEAD_TEXT_MAX_CHARS = 500;

function isObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

function compactText(value, maxChars = STATIC_LEAD_TEXT_MAX_CHARS) {
  const text = String(value == null ? "" : value).replace(/\s+/g, " ").trim();
  if (!text) return "";
  return text.length > maxChars ? text.slice(0, maxChars) : text;
}

function locationForFinding(finding) {
  if (!isObject(finding)) return null;
  const location = isObject(finding.location) ? finding.location : {};
  const file = normalizeRepoPath(
    location.path || finding.file || finding.artifact_uri,
  );
  const line = Number.isInteger(location.line)
    ? location.line
    : (Number.isInteger(finding.start_line) ? finding.start_line : null);
  if (!file || !Number.isInteger(line) || line < 1) return null;
  return { file, line };
}

function arrayStrings(value) {
  const values = Array.isArray(value) ? value : [value];
  return values
    .filter((item) => item != null)
    .map((item) => compactText(item, 120))
    .filter(Boolean);
}

function familyLabelForFinding(finding, family) {
  if (typeof family === "string" && family.trim()) return compactText(family, 120);
  if (isObject(family) && typeof family.family === "string" && family.family.trim()) {
    return compactText(family.family, 120);
  }
  if (isObject(family) && typeof family.name === "string" && family.name.trim()) {
    return compactText(family.name, 120);
  }
  const cwe = arrayStrings(finding && finding.cwe);
  if (cwe.length > 0) return cwe[0];
  return compactText(finding && finding.rule_id, 120) || "static_analysis";
}

function reachabilityFlowHints(reachability) {
  if (!isObject(reachability)) return [];
  return [
    typeof reachability.attack_vector === "string" ? `attack_vector=${reachability.attack_vector}` : null,
    typeof reachability.network_reachable === "boolean" ? `network_reachable=${reachability.network_reachable}` : null,
    typeof reachability.severity_ceiling === "string" ? `severity_ceiling=${reachability.severity_ceiling}` : null,
  ].filter(Boolean);
}

function reachabilityMeta(reachability) {
  if (!isObject(reachability)) return null;
  const meta = {};
  if (typeof reachability.attack_vector === "string" && reachability.attack_vector.trim()) {
    meta.attack_vector = compactText(reachability.attack_vector, 40);
  }
  if (typeof reachability.network_reachable === "boolean") {
    meta.network_reachable = reachability.network_reachable;
  }
  if (typeof reachability.severity_ceiling === "string" && reachability.severity_ceiling.trim()) {
    meta.severity_ceiling = compactText(reachability.severity_ceiling, 40);
  }
  return Object.keys(meta).length > 0 ? meta : null;
}

function normalizeViaI10(finding) {
  try {
    return mapSarifResultToSurfaceLead(finding);
  } catch {
    return null;
  }
}

function staticFindingToSurfaceLead(sarifFinding, reachability = {}, family = null) {
  if (!isObject(sarifFinding)) return null;
  const location = locationForFinding(sarifFinding);
  if (!location) return null;
  const i10Lead = normalizeViaI10(sarifFinding);
  const ruleId = compactText(sarifFinding.rule_id, 160) || "static-analysis";
  const endpoint = `${location.file}:${location.line}`;
  const message = compactText(sarifFinding.message, STATIC_LEAD_TEXT_MAX_CHARS);
  const familyLabel = familyLabelForFinding(sarifFinding, family);
  const evidence = message
    ? `${endpoint} - ${ruleId}: ${message}`
    : `${endpoint} - ${ruleId}`;
  return {
    title: ruleId,
    source: STATIC_LEAD_SOURCE,
    source_surface_id: sarifFinding.surface_id || (i10Lead && i10Lead.source_surface_id) || undefined,
    status: "new",
    promote: false,
    surface_type: STATIC_LEAD_SURFACE_TYPE,
    endpoints: [endpoint],
    bug_class_hints: [familyLabel],
    reachability_meta: reachabilityMeta(reachability),
    high_value_flows: reachabilityFlowHints(reachability),
    evidence: [evidence],
    rationale:
      "Static analysis lead is an unverified source-audit hypothesis; evaluator must trace source to sink and replay before any finding.",
  };
}

module.exports = {
  STATIC_LEAD_SOURCE,
  STATIC_LEAD_SURFACE_TYPE,
  staticFindingToSurfaceLead,
};
