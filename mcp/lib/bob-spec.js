"use strict";

const fs = require("fs");
const { bobSpecPath } = require("./paths.js");
const {
  readFileUtf8,
} = require("./storage.js");

const KNOWN_PLATFORMS = Object.freeze(["immunefi", "sherlock", "code4rena", "cantina", "custom"]);
const KNOWN_SEVERITY_SYSTEMS = Object.freeze(["immunefi-v2.3", "sherlock", "code4rena", "cantina", "custom"]);
const KNOWN_ADMIN_RULE_TREATMENTS = Object.freeze([
  "out_of_scope",
  "low_severity_max",
  "trusted_unless_restricted",
  "privilege_escalation_valid",
  "resilience_dependent",
]);

function isPlainObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

function asString(value) {
  return typeof value === "string" ? value : null;
}

function asStringArray(value) {
  if (!Array.isArray(value)) return [];
  return value.filter((item) => typeof item === "string");
}

function validateProgram(program, errors, warnings) {
  if (!isPlainObject(program)) {
    errors.push("program is required and must be an object");
    return null;
  }
  const platform = asString(program.platform);
  if (!platform) errors.push("program.platform is required");
  else if (!KNOWN_PLATFORMS.includes(platform)) {
    warnings.push(`program.platform "${platform}" is not a known platform; treating as custom`);
  }

  const severitySystem = isPlainObject(program.severity_system) ? program.severity_system : null;
  if (!severitySystem) {
    errors.push("program.severity_system is required and must be an object");
  } else {
    if (!asString(severitySystem.id)) {
      errors.push("program.severity_system.id is required");
    } else if (!KNOWN_SEVERITY_SYSTEMS.includes(severitySystem.id)) {
      warnings.push(`program.severity_system.id "${severitySystem.id}" is not a known system`);
    }
    if (!Array.isArray(severitySystem.tiers) || severitySystem.tiers.length === 0) {
      errors.push("program.severity_system.tiers must be a non-empty array");
    }
    const adminRule = isPlainObject(severitySystem.admin_rule) ? severitySystem.admin_rule : null;
    if (adminRule) {
      const treatment = asString(adminRule.treatment);
      if (treatment && !KNOWN_ADMIN_RULE_TREATMENTS.includes(treatment)) {
        warnings.push(`program.severity_system.admin_rule.treatment "${treatment}" is not a known value`);
      }
    } else {
      warnings.push("program.severity_system.admin_rule is missing; anti-stop bypass conditions cannot be platform-tuned");
    }
  }

  return {
    platform,
    source_url: asString(program.source_url),
    severity_system: severitySystem,
    poc_required: program.poc_required !== undefined ? program.poc_required : null,
  };
}

function validateAssets(assets, errors) {
  if (!Array.isArray(assets)) {
    errors.push("assets must be an array");
    return [];
  }
  const normalized = [];
  for (const [index, asset] of assets.entries()) {
    if (!isPlainObject(asset)) {
      errors.push(`assets[${index}] must be an object`);
      continue;
    }
    const chain = asString(asset.chain);
    const address = asString(asset.address);
    if (!chain) errors.push(`assets[${index}].chain is required`);
    if (!address) errors.push(`assets[${index}].address is required`);
    if (chain && address) {
      normalized.push({
        chain,
        chain_id: typeof asset.chain_id === "number" ? asset.chain_id : null,
        address,
        name: asString(asset.name),
        role_in_protocol: asString(asset.role_in_protocol),
        contract_type: asString(asset.contract_type),
        deployed_block: typeof asset.deployed_block === "number" ? asset.deployed_block : null,
        audit_links: asStringArray(asset.audit_links),
      });
    }
  }
  return normalized;
}

function validateTrustAssumptions(trustAssumptions, warnings) {
  if (trustAssumptions == null) {
    return { trusted_roles: [], trusted_externals: [] };
  }
  if (!isPlainObject(trustAssumptions)) {
    warnings.push("trust_assumptions must be an object; ignoring");
    return { trusted_roles: [], trusted_externals: [] };
  }
  const trustedRoles = Array.isArray(trustAssumptions.trusted_roles) ? trustAssumptions.trusted_roles : [];
  const trustedExternals = Array.isArray(trustAssumptions.trusted_externals) ? trustAssumptions.trusted_externals : [];
  return {
    trusted_roles: trustedRoles
      .filter(isPlainObject)
      .map((role) => ({
        role: asString(role.role),
        contracts: Array.isArray(role.contracts) ? role.contracts : [],
        stated_by: asString(role.stated_by) || "inferred",
        bypass_conditions: asStringArray(role.bypass_conditions),
      }))
      .filter((role) => role.role),
    trusted_externals: trustedExternals
      .filter(isPlainObject)
      .map((external) => ({
        protocol: asString(external.protocol),
        role: asString(external.role),
        address: asString(external.address),
        bypass_conditions: asStringArray(external.bypass_conditions),
      }))
      .filter((external) => external.protocol || external.role),
  };
}

function validateInvariants(invariants, errors) {
  if (invariants == null) return [];
  if (!Array.isArray(invariants)) {
    errors.push("invariants must be an array");
    return [];
  }
  return invariants
    .filter(isPlainObject)
    .map((inv) => ({
      id: asString(inv.id),
      statement: asString(inv.statement),
      source: asString(inv.source),
      surface_ids: asStringArray(inv.surface_ids),
      expected_break_classes: asStringArray(inv.expected_break_classes),
      poc_hint: asString(inv.poc_hint),
    }))
    .filter((inv) => inv.statement);
}

function validateAuditIndex(auditIndex, errors) {
  if (auditIndex == null) return [];
  if (!Array.isArray(auditIndex)) {
    errors.push("audit_index must be an array");
    return [];
  }
  return auditIndex
    .filter(isPlainObject)
    .map((entry) => ({
      audit: isPlainObject(entry.audit) ? entry.audit : null,
      issues: Array.isArray(entry.issues)
        ? entry.issues
            .filter(isPlainObject)
            .map((issue) => ({
              id: asString(issue.id),
              title: asString(issue.title),
              severity_at_audit: asString(issue.severity_at_audit),
              fix_commit: asString(issue.fix_commit),
              status: asString(issue.status),
              bob_check: asString(issue.bob_check),
              related_invariants: asStringArray(issue.related_invariants),
            }))
        : [],
    }))
    .filter((entry) => entry.audit || entry.issues.length > 0);
}

function loadBobSpec(domain) {
  const filePath = bobSpecPath(domain);
  const errors = [];
  const warnings = [];

  if (!fs.existsSync(filePath)) {
    return {
      present: false,
      valid: false,
      path: filePath,
      reason: "missing",
      errors: [],
      warnings: [],
      document: null,
    };
  }

  let raw;
  try {
    raw = readFileUtf8(filePath, { label: "bob-spec.json" });
  } catch (error) {
    return {
      present: true,
      valid: false,
      path: filePath,
      reason: "unreadable",
      errors: [error.message || String(error)],
      warnings: [],
      document: null,
    };
  }

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    return {
      present: true,
      valid: false,
      path: filePath,
      reason: "malformed",
      errors: [`bob-spec.json parse failed: ${error.message || String(error)}`],
      warnings: [],
      document: null,
    };
  }

  if (!isPlainObject(parsed)) {
    return {
      present: true,
      valid: false,
      path: filePath,
      reason: "malformed",
      errors: ["bob-spec.json must be an object at the top level"],
      warnings: [],
      document: null,
    };
  }

  const program = validateProgram(parsed.program, errors, warnings);
  const assets = validateAssets(parsed.assets, errors);
  const trustAssumptions = validateTrustAssumptions(parsed.trust_assumptions, warnings);
  const knownIssues = Array.isArray(parsed.known_issues)
    ? parsed.known_issues.filter(isPlainObject).map((issue) => ({
        id: asString(issue.id),
        text: asString(issue.text),
        source: asString(issue.source),
        affects: asStringArray(issue.affects),
      })).filter((issue) => issue.text)
    : [];
  const outOfScopeClasses = asStringArray(parsed.out_of_scope_classes);
  const invariants = validateInvariants(parsed.invariants, errors);
  const auditIndex = validateAuditIndex(parsed.audit_index, errors);

  const valid = errors.length === 0;

  return {
    present: true,
    valid,
    path: filePath,
    reason: valid ? "ok" : "schema_errors",
    errors,
    warnings,
    document: {
      program,
      assets,
      trust_assumptions: trustAssumptions,
      known_issues: knownIssues,
      out_of_scope_classes: outOfScopeClasses,
      invariants,
      audit_index: auditIndex,
    },
  };
}

const BOB_SPEC_BRIEF_LIMITS = Object.freeze({
  bypass_conditions_per_role: 8,
  trusted_roles: 8,
  trusted_externals: 8,
  invariants: 8,
  known_issues: 8,
  out_of_scope_classes: 12,
  audit_issues: 12,
});

function summarizeBobSpecForBrief(spec, surfaceId) {
  if (!spec || !spec.present) {
    return {
      present: false,
      reason: spec && spec.reason ? spec.reason : "missing",
      message: "bob-spec.json not present in the session directory; the smart_contract anti-stop rule still applies (record at least one bypass_attempts[] entry citing the trust assumption you actually attempted to break, or record a finding).",
      errors: [],
      warnings: [],
    };
  }
  if (!spec.valid) {
    return {
      present: true,
      valid: false,
      reason: spec.reason,
      message: "bob-spec.json failed validation; evaluators should report the errors and proceed using runtime-derived heuristics for trust assumptions.",
      errors: spec.errors.slice(0, 8),
      warnings: spec.warnings.slice(0, 8),
    };
  }

  const doc = spec.document;
  const program = doc.program || {};
  const trustAssumptions = doc.trust_assumptions || { trusted_roles: [], trusted_externals: [] };

  // Filter trusted_roles by the assigned surface's address so the brief carries
  // the contract-scoped trust map, not an arbitrarily-clipped global list.
  const surfaceAssets = (doc.assets || []).filter((asset) => (
    !surfaceId || (asset.name === surfaceId) || (asset.address && asset.address.toLowerCase() === String(surfaceId).toLowerCase())
  ));
  const surfaceAddresses = new Set(surfaceAssets.map((asset) => asset.address && asset.address.toLowerCase()).filter(Boolean));

  const filteredTrustedRoles = trustAssumptions.trusted_roles.filter((role) => {
    if (!role.contracts || role.contracts.length === 0) return true;
    if (role.contracts.includes("all")) return true;
    if (surfaceAddresses.size === 0) return true;
    return role.contracts.some((contract) => typeof contract === "string" && surfaceAddresses.has(contract.toLowerCase()));
  });
  const trustedRoles = filteredTrustedRoles
    .slice(0, BOB_SPEC_BRIEF_LIMITS.trusted_roles)
    .map((role) => ({
      role: role.role,
      stated_by: role.stated_by,
      contracts: role.contracts.slice(0, 6),
      bypass_conditions: role.bypass_conditions.slice(0, BOB_SPEC_BRIEF_LIMITS.bypass_conditions_per_role),
    }));

  const filteredTrustedExternals = trustAssumptions.trusted_externals.filter((external) => {
    if (!external.address) return true;
    if (surfaceAddresses.size === 0) return true;
    return surfaceAddresses.has(external.address.toLowerCase());
  });
  const trustedExternals = filteredTrustedExternals
    .slice(0, BOB_SPEC_BRIEF_LIMITS.trusted_externals)
    .map((external) => ({
      protocol: external.protocol,
      role: external.role,
      address: external.address || null,
      bypass_conditions: external.bypass_conditions.slice(0, BOB_SPEC_BRIEF_LIMITS.bypass_conditions_per_role),
    }));

  const invariantsForSurface = (doc.invariants || []).filter((inv) => (
    inv.surface_ids.length === 0 || inv.surface_ids.includes(surfaceId)
  )).slice(0, BOB_SPEC_BRIEF_LIMITS.invariants).map((inv) => ({
    id: inv.id,
    statement: inv.statement,
    expected_break_classes: inv.expected_break_classes.slice(0, 6),
    poc_hint: inv.poc_hint,
  }));

  const knownIssuesForSurface = (doc.known_issues || []).filter((issue) => (
    issue.affects.length === 0 || issue.affects.includes(surfaceId)
  )).slice(0, BOB_SPEC_BRIEF_LIMITS.known_issues).map((issue) => ({
    id: issue.id,
    text: issue.text,
  }));

  const auditIssuesForSurface = [];
  for (const audit of doc.audit_index || []) {
    for (const issue of audit.issues || []) {
      if (issue.related_invariants.length > 0 && !invariantsForSurface.some((inv) => issue.related_invariants.includes(inv.id))) {
        continue;
      }
      auditIssuesForSurface.push({
        id: issue.id,
        title: issue.title,
        status: issue.status,
        bob_check: issue.bob_check,
      });
      if (auditIssuesForSurface.length >= BOB_SPEC_BRIEF_LIMITS.audit_issues) break;
    }
    if (auditIssuesForSurface.length >= BOB_SPEC_BRIEF_LIMITS.audit_issues) break;
  }

  return {
    present: true,
    valid: true,
    reason: "ok",
    program: {
      platform: program.platform,
      severity_system_id: program.severity_system && program.severity_system.id,
      admin_rule_treatment: program.severity_system && program.severity_system.admin_rule
        ? program.severity_system.admin_rule.treatment
        : null,
      admin_rule_exceptions: program.severity_system && program.severity_system.admin_rule
        ? asStringArray(program.severity_system.admin_rule.exceptions)
        : [],
      poc_required: program.poc_required,
    },
    assets: surfaceAssets.slice(0, 6).map((asset) => ({
      chain: asset.chain,
      chain_id: asset.chain_id,
      address: asset.address,
      name: asset.name,
      role_in_protocol: asset.role_in_protocol,
      contract_type: asset.contract_type,
    })),
    trusted_roles: trustedRoles,
    trusted_externals: trustedExternals,
    invariants: invariantsForSurface,
    known_issues: knownIssuesForSurface,
    out_of_scope_classes: (doc.out_of_scope_classes || []).slice(0, BOB_SPEC_BRIEF_LIMITS.out_of_scope_classes),
    audit_issues: auditIssuesForSurface,
    warnings: spec.warnings.slice(0, 8),
  };
}

module.exports = {
  loadBobSpec,
  summarizeBobSpecForBrief,
  KNOWN_PLATFORMS,
  KNOWN_SEVERITY_SYSTEMS,
  KNOWN_ADMIN_RULE_TREATMENTS,
};
