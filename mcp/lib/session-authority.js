"use strict";

const fs = require("fs");
const {
  ERROR_CODES,
  ToolError,
} = require("./envelope.js");
const {
  statePath,
} = require("./paths.js");
const {
  readJsonFile,
} = require("./storage.js");
const {
  assertHttpScopeDomain,
  validateHttpScanScope,
} = require("./scope.js");
const {
  normalizeSessionStateDocument,
} = require("./session-state-contracts.js");

const AUTHORITY_VERSION = 1;
const AUTHORITY_MODE_ENV = "BOB_SESSION_AUTHORITY_MODE";

const AUTHORITY_CLASSES = Object.freeze([
  "bootstrap_session",
  "initialized_session_read",
  "initialized_session_mutation",
  "scoped_http_network",
  "smart_contract_contextual",
  "optional_session_context",
  "cross_session_read",
  "mode_dependent_session",
  "global_read",
  "global_preapproval",
  "legacy_session_compat",
]);

const EXPLICIT_AUTHORITY_CLASS_BY_TOOL = Object.freeze({
  bob_anchor_run: "smart_contract_contextual",
  bob_append_chain_node: "initialized_session_mutation",
  bob_apply_wave_merge: "initialized_session_mutation",
  bob_aptos_fetch_module: "smart_contract_contextual",
  bob_aptos_fetch_resource: "smart_contract_contextual",
  bob_aptos_run: "smart_contract_contextual",
  bob_attach_contract: "initialized_session_mutation",
  bob_auth_store: "initialized_session_mutation",
  bob_auto_signup: "scoped_http_network",
  bob_browser_click: "initialized_session_mutation",
  bob_browser_console_messages: "initialized_session_mutation",
  bob_browser_evaluate: "initialized_session_mutation",
  bob_browser_fill_form: "initialized_session_mutation",
  bob_browser_flush_recorded_requests: "initialized_session_mutation",
  bob_browser_navigate: "initialized_session_mutation",
  bob_browser_network_requests: "initialized_session_mutation",
  bob_browser_press_key: "initialized_session_mutation",
  bob_browser_session_close: "initialized_session_mutation",
  bob_browser_session_start: "initialized_session_mutation",
  bob_browser_session_start_recording: "initialized_session_mutation",
  bob_browser_snapshot: "initialized_session_mutation",
  bob_browser_take_screenshot: "initialized_session_mutation",
  bob_browser_type: "initialized_session_mutation",
  bob_browser_wait_for: "initialized_session_mutation",
  bob_build_surface_graph: "initialized_session_mutation",
  bob_build_symbol_surface_index: "initialized_session_mutation",
  bob_build_verification_adjudication: "initialized_session_mutation",
  bob_chain_ancestry: "initialized_session_read",
  bob_chain_frontier: "initialized_session_read",
  bob_clear_operator_note: "initialized_session_mutation",
  bob_clear_terminal_block: "initialized_session_mutation",
  bob_cosmwasm_fetch_contract: "smart_contract_contextual",
  bob_cosmwasm_run: "smart_contract_contextual",
  bob_cosmwasm_smart_query: "smart_contract_contextual",
  bob_diff_verification_attempts: "initialized_session_read",
  bob_evaluate_capabilities: "global_read",
  bob_evm_call: "global_preapproval",
  bob_evm_fetch_source: "smart_contract_contextual",
  bob_evm_role_table: "global_preapproval",
  bob_evm_storage_read: "global_preapproval",
  bob_extract_routes: "initialized_session_read",
  bob_finalize_agent_run: "initialized_session_mutation",
  bob_foundry_run: "smart_contract_contextual",
  bob_get_context_budget: "mode_dependent_session",
  bob_halmos_run: "smart_contract_contextual",
  bob_http_scan: "scoped_http_network",
  bob_import_http_traffic: "scoped_http_network",
  bob_import_static_artifact: "initialized_session_mutation",
  bob_ingest_audit_report: "initialized_session_mutation",
  bob_ingest_schema_doc: "initialized_session_mutation",
  bob_init_session: "bootstrap_session",
  bob_init_repo_session: "bootstrap_session",
  bob_list_auth_profiles: "initialized_session_read",
  bob_list_candidate_claims: "initialized_session_read",
  bob_log_capability_friction: "initialized_session_mutation",
  bob_log_coverage: "initialized_session_mutation",
  bob_log_dead_ends: "initialized_session_mutation",
  bob_log_protocol_drift: "initialized_session_mutation",
  bob_log_technique_attempt: "initialized_session_mutation",
  // Plane Y Cycle Y.2 — Y-D13 runtime drift telemetry entry. Orchestrator-
  // only at the role-bundle layer; Y.3 added a server-internal caller
  // bundle for _write-base.js auto-emit on INVALID_ARGUMENTS retry success.
  bob_emit_runtime_drift: "initialized_session_mutation",
  bob_merge_wave_handoffs: "initialized_session_read",
  bob_promote_surface_leads: "initialized_session_mutation",
  bob_propose_friction_promotion: "initialized_session_mutation",
  // Plane Y Cycle Y.7 — adversarial transcript scan (Y-D6 + Y-P9). Pure
  // read; returns synthesized friction + drift records without appending.
  bob_scan_transcript_for_friction: "initialized_session_read",
  bob_propose_hypothesis: "initialized_session_mutation",
  bob_propose_transition: "initialized_session_mutation",
  bob_public_intel: "scoped_http_network",
  bob_query_audit_reports: "initialized_session_read",
  bob_query_chain_tree: "initialized_session_read",
  bob_query_schema_contracts: "initialized_session_read",
  bob_query_surface_graph: "initialized_session_read",
  bob_read_auth_differential_results: "initialized_session_read",
  bob_read_capability_metrics: "mode_dependent_session",
  bob_read_capability_playbook: "global_read",
  bob_read_chain_attempts: "initialized_session_read",
  bob_read_doc_delta_results: "initialized_session_read",
  bob_read_evidence_packs: "initialized_session_read",
  bob_read_candidate_claims: "initialized_session_read",
  bob_read_grade_verdict: "initialized_session_read",
  bob_read_http_audit: "initialized_session_read",
  bob_read_assignment_brief: "initialized_session_read",
  bob_read_invariant_runs: "initialized_session_read",
  bob_read_pipeline_analytics: "mode_dependent_session",
  bob_advance_session: "initialized_session_mutation",
  bob_append_frontier_event: "initialized_session_mutation",
  bob_finalize_report: "initialized_session_mutation",
  // Plane Y Cycle Y.3 — Y-D15b / Y-P13 MCP-rendered audit-graded artifacts.
  bob_compose_report: "initialized_session_mutation",
  bob_amend_report: "initialized_session_mutation",
  bob_write_chain_rollup: "initialized_session_mutation",
  bob_set_friction_scanners: "initialized_session_mutation",
  bob_materialize_frontier: "initialized_session_mutation",
  bob_materialize_task_graph: "initialized_session_mutation",
  bob_read_task_graph: "initialized_session_read",
  bob_read_queue_policy: "initialized_session_read",
  bob_read_session_nucleus: "initialized_session_read",
  bob_schedule_tasks: "initialized_session_mutation",
  // Plane X Cycle X.9: bob_schedule_graph_nodes wraps the graph-walking
  // scheduler + bob_prepare_node dispatch. Same authority class as the
  // wave-scheduler's bob_schedule_tasks.
  bob_schedule_graph_nodes: "initialized_session_mutation",
  bob_set_pack_telemetry_config: "initialized_session_mutation",
  bob_set_queue_policy: "initialized_session_mutation",
  bob_read_session_state: "initialized_session_read",
  bob_read_session_summary: "initialized_session_read",
  bob_read_state_summary: "initialized_session_read",
  bob_read_surface_leads: "initialized_session_read",
  bob_read_surface_routes: "initialized_session_read",
  bob_read_technique_pack: "mode_dependent_session",
  bob_read_tool_telemetry: "mode_dependent_session",
  bob_read_verification_context: "initialized_session_read",
  bob_read_verification_round: "initialized_session_read",
  bob_read_wave_handoffs: "initialized_session_read",
  bob_record_candidate_claim: "initialized_session_mutation",
  bob_record_surface_leads: "initialized_session_mutation",
  bob_prepare_node: "initialized_session_mutation",
  bob_finalize_node: "initialized_session_mutation",
  bob_repo_check: "initialized_session_mutation",
  bob_repo_docker_run: "initialized_session_mutation",
  bob_repo_inventory: "initialized_session_mutation",
  bob_repo_prepare_env: "initialized_session_mutation",
  bob_resolve_body: "initialized_session_read",
  bounty_report_written: "initialized_session_mutation",
  bob_route_surfaces: "initialized_session_mutation",
  bob_run_auth_differential: "scoped_http_network",
  bob_run_doc_delta: "scoped_http_network",
  bob_run_invariant_for_finding: "smart_contract_contextual",
  bob_select_technique_packs: "initialized_session_read",
  bob_set_operator_note: "initialized_session_mutation",
  bob_signup_detect: "scoped_http_network",
  bob_start_next_wave: "initialized_session_mutation",
  bob_start_wave: "initialized_session_mutation",
  bob_static_scan: "initialized_session_mutation",
  bob_substrate_fetch_runtime: "smart_contract_contextual",
  bob_substrate_fetch_storage: "smart_contract_contextual",
  bob_substrate_run: "smart_contract_contextual",
  bob_suggest_invariants: "global_read",
  bob_sui_fetch_object: "smart_contract_contextual",
  bob_sui_fetch_package: "smart_contract_contextual",
  bob_sui_run: "smart_contract_contextual",
  bob_summarize_diff_impact: "initialized_session_mutation",
  bob_svm_fetch_account: "smart_contract_contextual",
  bob_svm_fetch_program: "smart_contract_contextual",
  bob_temp_email: "global_preapproval",
  bob_wave_handoff_status: "initialized_session_read",
  bob_wave_status: "initialized_session_read",
  bob_write_chain_attempt: "initialized_session_mutation",
  bob_write_evidence_packs: "initialized_session_mutation",
  bob_write_grade_verdict: "initialized_session_mutation",
  bob_write_handoff: "initialized_session_mutation",
  bob_write_proof_bundle: "initialized_session_mutation",
  bob_write_verification_round: "initialized_session_mutation",
  bob_write_wave_handoff: "initialized_session_mutation",
});

const LEGACY_DEFAULTABLE_FIELDS = Object.freeze([
  "auth_status",
  "blocked_prereq_history",
  "dead_ends",
  "deep_mode",
  "hold_count",
  "evaluation_wave",
  "operator_note",
  "pending_wave",
  "prereq_registry_snapshots",
  "scope_exclusions",
  "terminal_block_clear_history",
  "total_findings",
  "waf_blocked_endpoints",
]);

// Fields whose absence is a hard scope/authority failure (not defaultable).
// Egress/checkpoint/verification fields are intentionally NOT in this list:
// normalizeSessionStateDocument backfills safe defaults for them so v1.3.4
// sessions can resume on v1.3.5. The fields below are scope identity and have
// no meaningful default — their per-field checks above this list (raw.target
// drift, target_url drift) emit more specific errors before this list is
// consulted, so this is belt-and-suspenders for that contract.
const LEGACY_FAIL_CLOSED_FIELDS = Object.freeze([
  "target",
  "target_url",
]);

const SESSION_AUTHORITY_CLASSES = new Set([
  "initialized_session_read",
  "initialized_session_mutation",
  "scoped_http_network",
  "smart_contract_contextual",
]);

const SHADOW_MISSING_SESSION_CLASSES = new Set([
  "initialized_session_read",
  "cross_session_read",
]);

let shadowWarningEmitted = false;

// Cycle O.1: REPO_TARGET_DOMAIN_PATTERN identifies the synthetic
// `repo-<safeName>-<sha8>` slug minted by initRepoSession. This is the
// hook the bootstrap rule uses to skip DNS validation (assertHttpScopeDomain
// rejects non-public-suffix domains) and accept target_repo in place of
// target_url. The pattern is intentionally narrow: `repo-` prefix, any
// safe-domain content, terminating in an 8-hex realpath digest.
const REPO_TARGET_DOMAIN_PATTERN = /^repo-[A-Za-z0-9][A-Za-z0-9._-]*-[0-9a-f]{8}$/;

function isRepoTargetDomain(value) {
  return typeof value === "string" && REPO_TARGET_DOMAIN_PATTERN.test(value);
}

function hasOwn(value, key) {
  return Object.prototype.hasOwnProperty.call(value, key);
}

function targetDomainPresent(args) {
  return !!(args && typeof args.target_domain === "string" && args.target_domain.trim());
}

function safeArgumentTargetDomain(args) {
  if (!targetDomainPresent(args)) return null;
  try {
    return assertHttpScopeDomain(args.target_domain);
  } catch {
    return null;
  }
}

function authorityMode(env = process.env) {
  return env[AUTHORITY_MODE_ENV] === "shadow" ? "shadow" : "enforce";
}

function classForTool(toolName) {
  if (Object.prototype.hasOwnProperty.call(EXPLICIT_AUTHORITY_CLASS_BY_TOOL, toolName)) {
    return EXPLICIT_AUTHORITY_CLASS_BY_TOOL[toolName];
  }
  // Cycle P.1: deprecation aliases inherit their primary's authority class.
  // The class map is keyed on the canonical bob_* name only; bounty_* aliases
  // resolve through the registry's primaryToolName indirection so we don't
  // double-list every entry.
  try {
    // Lazy-require to avoid a load-order cycle (tool-registry imports
    // capability-packs, which on some test paths transitively loads this
    // module before the registry has finished initializing).
    const registry = require("./tool-registry.js");
    if (!registry || typeof registry.primaryToolName !== "function") {
      // Registry module is mid-construction and has not yet attached the
      // primaryToolName export. Throw so the surrounding catch falls through
      // to the null return; dispatch will surface a STATE_CONFLICT instead
      // of crashing with an opaque TypeError.
      throw new Error(
        "tool-registry.primaryToolName unavailable during load-order cycle",
      );
    }
    const primary = registry.primaryToolName(toolName);
    if (primary && primary !== toolName) {
      return EXPLICIT_AUTHORITY_CLASS_BY_TOOL[primary] || null;
    }
  } catch {
    // If the registry is mid-construction, fall through and report missing
    // class; the dispatch path will surface the resulting STATE_CONFLICT.
  }
  return null;
}

function modeRule(toolName, args = {}) {
  if (toolName === "bob_get_context_budget") {
    if (args.surface_id != null) {
      return {
        authority_class: "initialized_session_read",
        target_domain: "required",
        target_url_policy: "validate_session_target_url",
        authority_source: "session_state",
      };
    }
    return {
      authority_class: "global_read",
      target_domain: "optional_absent",
      target_url_policy: "not_applicable",
      authority_source: "optional_absent",
    };
  }
  if (toolName === "bob_read_technique_pack") {
    if (args.mode === "full") {
      return {
        authority_class: "initialized_session_mutation",
        target_domain: "required",
        target_url_policy: "validate_session_target_url",
        authority_source: "session_state",
      };
    }
    return {
      authority_class: "global_read",
      target_domain: "optional_absent",
      target_url_policy: "not_applicable",
      authority_source: "optional_absent",
    };
  }
  if (toolName === "bob_read_tool_telemetry") {
    if (targetDomainPresent(args)) {
      return {
        authority_class: "initialized_session_read",
        target_domain: "required",
        target_url_policy: "validate_session_target_url",
        authority_source: "session_state",
      };
    }
    return {
      authority_class: "cross_session_read",
      target_domain: "optional_absent",
      target_url_policy: "index_only_no_target_url_export",
      authority_source: "cross_session",
    };
  }
  if (toolName === "bob_read_pipeline_analytics") {
    if (targetDomainPresent(args)) {
      return {
        authority_class: "initialized_session_read",
        target_domain: "required",
        target_url_policy: "validate_session_target_url",
        authority_source: "session_state",
      };
    }
    return {
      authority_class: "cross_session_read",
      target_domain: "optional_absent",
      target_url_policy: "validate_before_target_url_export",
      authority_source: "cross_session",
    };
  }
  if (toolName === "bob_read_capability_metrics") {
    if (targetDomainPresent(args)) {
      return {
        authority_class: "initialized_session_read",
        target_domain: "required",
        target_url_policy: "validate_session_target_url",
        authority_source: "session_state",
      };
    }
    return {
      authority_class: "cross_session_read",
      target_domain: "optional_absent",
      target_url_policy: "index_only_no_target_url_export",
      authority_source: "cross_session",
    };
  }
  return null;
}

function baseRuleForTool(tool, args) {
  const defaultClass = classForTool(tool && tool.name);
  if (!defaultClass) {
    return null;
  }
  if (defaultClass === "mode_dependent_session") {
    // Resolve aliases to their primary so mode rules keyed on canonical names
    // still apply when a deprecated bounty_* name is invoked.
    let resolvedName = tool.name;
    try {
      const { primaryToolName } = require("./tool-registry.js");
      resolvedName = primaryToolName(tool.name) || tool.name;
    } catch {
      // Fall back to alias name if registry not yet initialized.
    }
    return modeRule(resolvedName, args);
  }
  if (defaultClass === "bootstrap_session") {
    return {
      authority_class: defaultClass,
      target_domain: "required",
      target_url_policy: "validate_input_target_url",
      authority_source: "bootstrap",
    };
  }
  if (defaultClass === "cross_session_read") {
    return {
      authority_class: defaultClass,
      target_domain: "optional_absent",
      target_url_policy: "validate_before_target_url_export",
      authority_source: "cross_session",
    };
  }
  if (defaultClass === "global_read") {
    return {
      authority_class: defaultClass,
      target_domain: "absent",
      target_url_policy: "not_applicable",
      authority_source: "global",
    };
  }
  if (defaultClass === "global_preapproval") {
    return {
      authority_class: defaultClass,
      target_domain: "absent",
      target_url_policy: "not_applicable",
      authority_source: "preapproval_global",
    };
  }
  return {
    authority_class: defaultClass,
    target_domain: "required",
    target_url_policy: "validate_session_target_url",
    authority_source: "session_state",
  };
}

function makeDecision({
  authority_class: authorityClass,
  authority_mode: mode,
  authority_source: source,
  authority_result: result,
  authority_error_code: errorCode = "none",
  authority_block_reason: blockReason = "none",
  authority_target_domain: authorityTargetDomain = null,
  argument_target_domain: argumentTargetDomain = null,
  authority_session_present: sessionPresent = null,
  authority_match: match = null,
  authority_shadowed: shadowed = false,
} = {}) {
  return {
    authority_version: AUTHORITY_VERSION,
    authority_class: authorityClass || null,
    authority_mode: mode || "enforce",
    authority_source: source || "global",
    authority_result: result || "not_applicable",
    authority_error_code: errorCode || "none",
    authority_block_reason: blockReason || errorCode || "none",
    authority_target_domain: authorityTargetDomain || null,
    argument_target_domain: argumentTargetDomain || null,
    authority_session_present: sessionPresent,
    authority_match: match,
    authority_shadowed: shadowed === true,
  };
}

function allowedDecision(rule, args, {
  authorityTargetDomain = null,
  source = null,
  sessionPresent = null,
  match = null,
} = {}) {
  return makeDecision({
    authority_class: rule.authority_class,
    authority_mode: authorityMode(),
    authority_source: source || rule.authority_source,
    authority_result: "allowed",
    authority_target_domain: authorityTargetDomain,
    argument_target_domain: safeArgumentTargetDomain(args),
    authority_session_present: sessionPresent,
    authority_match: match,
  });
}

function blockedDecision(rule, args, {
  errorCode,
  blockReason,
  envelopeCode,
  message,
  authorityTargetDomain = null,
  sessionPresent = null,
  match = null,
  source = null,
  details = null,
}) {
  const decision = makeDecision({
    authority_class: rule && rule.authority_class,
    authority_mode: authorityMode(),
    authority_source: source || (rule && rule.authority_source) || "global",
    authority_result: "blocked",
    authority_error_code: errorCode,
    authority_block_reason: blockReason || errorCode,
    authority_target_domain: authorityTargetDomain,
    argument_target_domain: safeArgumentTargetDomain(args),
    authority_session_present: sessionPresent,
    authority_match: match,
  });
  const error = new ToolError(envelopeCode, message, {
    ...(details || {}),
    authority: decision,
  });
  error.authority = decision;
  return error;
}

function canShadowMissingSession(tool, rule) {
  if (authorityMode() !== "shadow") return false;
  if (!SHADOW_MISSING_SESSION_CLASSES.has(rule.authority_class)) return false;
  if (!tool) return false;
  if (tool.mutating || tool.network_access || tool.browser_access || tool.sensitive_output) return false;
  if (Array.isArray(tool.session_artifacts_written) && tool.session_artifacts_written.length > 0) return false;
  return true;
}

function shadowDecision(error, tool, rule) {
  if (!error || !error.authority || error.authority.authority_error_code !== "no_session") {
    return null;
  }
  if (!canShadowMissingSession(tool, rule)) {
    return null;
  }
  if (!shadowWarningEmitted) {
    shadowWarningEmitted = true;
    process.stderr.write("WARNING: BOB_SESSION_AUTHORITY_MODE=shadow is allowing a missing-session read-only authority block.\n");
  }
  return {
    ...error.authority,
    authority_result: "shadow_blocked",
    authority_shadowed: true,
  };
}

function normalizeArgumentTarget(rule, args) {
  if (rule.target_domain !== "required") {
    return null;
  }
  if (!targetDomainPresent(args)) {
    throw blockedDecision(rule, args, {
      errorCode: "normalization_failed",
      envelopeCode: ERROR_CODES.INVALID_ARGUMENTS,
      message: "target_domain is required for session authority",
      sessionPresent: null,
      match: false,
    });
  }
  // Cycle O.1: repo-shaped target_domain (repo-<name>-<sha8>) bypasses
  // assertHttpScopeDomain (which rejects non-public-suffix hosts). The
  // pattern guard prevents a maliciously-crafted target_domain from
  // smuggling repo treatment for a domain that is actually a URL.
  if (REPO_TARGET_DOMAIN_PATTERN.test(args.target_domain.trim())) {
    const trimmed = args.target_domain.trim();
    args.target_domain = trimmed;
    return trimmed;
  }
  try {
    const normalized = assertHttpScopeDomain(args.target_domain);
    args.target_domain = normalized;
    return normalized;
  } catch (error) {
    throw blockedDecision(rule, args, {
      errorCode: "normalization_failed",
      envelopeCode: ERROR_CODES.INVALID_ARGUMENTS,
      message: error.message || String(error),
      sessionPresent: null,
      match: false,
    });
  }
}

function assertLegacyFailClosedFields(raw, rule, args, authorityTargetDomain) {
  for (const field of LEGACY_FAIL_CLOSED_FIELDS) {
    if (!hasOwn(raw, field)) {
      throw blockedDecision(rule, args, {
        errorCode: "legacy_security_field_missing",
        envelopeCode: ERROR_CODES.STATE_CONFLICT,
        message: `session authority field is missing: ${field}`,
        authorityTargetDomain,
        sessionPresent: true,
        match: null,
      });
    }
  }
}

function readRawAuthorityState(authorityTargetDomain, rule, args) {
  const filePath = statePath(authorityTargetDomain);
  if (!fs.existsSync(filePath)) {
    throw blockedDecision(rule, args, {
      errorCode: "no_session",
      envelopeCode: ERROR_CODES.STATE_CONFLICT,
      message: `Session authority is missing for ${authorityTargetDomain}; call bob_init_session first`,
      authorityTargetDomain,
      sessionPresent: false,
      match: false,
    });
  }

  let raw;
  try {
    raw = readJsonFile(filePath, { label: "state.json" });
  } catch {
    throw blockedDecision(rule, args, {
      errorCode: "malformed_state",
      envelopeCode: ERROR_CODES.STATE_CONFLICT,
      message: `Session authority state is malformed for ${authorityTargetDomain}`,
      authorityTargetDomain,
      sessionPresent: true,
      match: null,
    });
  }

  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw blockedDecision(rule, args, {
      errorCode: "malformed_state",
      envelopeCode: ERROR_CODES.STATE_CONFLICT,
      message: `Session authority state is malformed for ${authorityTargetDomain}`,
      authorityTargetDomain,
      sessionPresent: true,
      match: null,
    });
  }

  if (!hasOwn(raw, "target")) {
    throw blockedDecision(rule, args, {
      errorCode: "legacy_security_field_missing",
      envelopeCode: ERROR_CODES.STATE_CONFLICT,
      message: "session authority field is missing: target",
      authorityTargetDomain,
      sessionPresent: true,
      match: false,
    });
  }

  // Cycle O.1: repo sessions use the synthetic repo-<name>-<sha8> slug.
  // assertHttpScopeDomain rejects non-public-suffix hosts, so for repo
  // sessions we validate target identity directly: raw.target must match
  // the authority domain and be a well-formed repo slug. target_url is
  // null for repo sessions; we replace the URL drift check with a
  // target_repo presence check.
  const isRepoAuthority = isRepoTargetDomain(authorityTargetDomain);
  if (isRepoAuthority) {
    if (raw.target !== authorityTargetDomain || !isRepoTargetDomain(raw.target)) {
      throw blockedDecision(rule, args, {
        errorCode: "raw_target_drift",
        envelopeCode: ERROR_CODES.SCOPE_BLOCKED,
        message: `Session authority target drift for ${authorityTargetDomain}`,
        authorityTargetDomain,
        sessionPresent: true,
        match: false,
      });
    }
    if (!hasOwn(raw, "target_repo") || raw.target_repo == null || typeof raw.target_repo !== "object") {
      throw blockedDecision(rule, args, {
        errorCode: "legacy_security_field_missing",
        envelopeCode: ERROR_CODES.STATE_CONFLICT,
        message: "session authority field is missing: target_repo",
        authorityTargetDomain,
        sessionPresent: true,
        match: true,
      });
    }
    if (!hasOwn(raw, "repo_hash") || typeof raw.repo_hash !== "string" || !/^[0-9a-f]{8,64}$/i.test(raw.repo_hash)) {
      throw blockedDecision(rule, args, {
        errorCode: "legacy_security_field_missing",
        envelopeCode: ERROR_CODES.STATE_CONFLICT,
        message: "session authority field is missing: repo_hash",
        authorityTargetDomain,
        sessionPresent: true,
        match: true,
      });
    }
  } else {
    let rawTarget;
    try {
      rawTarget = assertHttpScopeDomain(raw.target);
    } catch {
      throw blockedDecision(rule, args, {
        errorCode: "malformed_state",
        envelopeCode: ERROR_CODES.STATE_CONFLICT,
        message: `Session authority target is malformed for ${authorityTargetDomain}`,
        authorityTargetDomain,
        sessionPresent: true,
        match: false,
      });
    }

    if (rawTarget !== authorityTargetDomain) {
      throw blockedDecision(rule, args, {
        errorCode: "raw_target_drift",
        envelopeCode: ERROR_CODES.SCOPE_BLOCKED,
        message: `Session authority target drift for ${authorityTargetDomain}`,
        authorityTargetDomain,
        sessionPresent: true,
        match: false,
      });
    }

    if (!hasOwn(raw, "target_url") || typeof raw.target_url !== "string" || !raw.target_url.trim()) {
      throw blockedDecision(rule, args, {
        errorCode: "legacy_security_field_missing",
        envelopeCode: ERROR_CODES.STATE_CONFLICT,
        message: "session authority field is missing: target_url",
        authorityTargetDomain,
        sessionPresent: true,
        match: true,
      });
    }

    try {
      validateHttpScanScope(raw.target_url, authorityTargetDomain);
    } catch {
      throw blockedDecision(rule, args, {
        errorCode: "target_url_drift",
        envelopeCode: ERROR_CODES.SCOPE_BLOCKED,
        message: `Session authority target_url drift for ${authorityTargetDomain}`,
        authorityTargetDomain,
        sessionPresent: true,
        match: true,
      });
    }
  }

  assertLegacyFailClosedFields(raw, rule, args, authorityTargetDomain);

  try {
    normalizeSessionStateDocument(raw, authorityTargetDomain);
  } catch {
    throw blockedDecision(rule, args, {
      errorCode: "malformed_state",
      envelopeCode: ERROR_CODES.STATE_CONFLICT,
      message: `Session authority state is malformed for ${authorityTargetDomain}`,
      authorityTargetDomain,
      sessionPresent: true,
      match: true,
    });
  }

  return raw;
}

function normalizeRepoBootstrapTarget(rule, args) {
  if (!targetDomainPresent(args)) {
    throw blockedDecision(rule, args, {
      errorCode: "normalization_failed",
      envelopeCode: ERROR_CODES.INVALID_ARGUMENTS,
      message: "target_domain is required for session authority",
      sessionPresent: null,
      match: false,
    });
  }
  if (!isRepoTargetDomain(args.target_domain)) {
    throw blockedDecision(rule, args, {
      errorCode: "normalization_failed",
      envelopeCode: ERROR_CODES.INVALID_ARGUMENTS,
      message: `target_domain must match repo session pattern repo-<name>-<sha8>; got ${args.target_domain}`,
      sessionPresent: false,
      match: false,
    });
  }
  return args.target_domain;
}

function authorizeBootstrap(rule, args) {
  // Cycle O.1: bootstrap accepts either target_url (web sessions) or
  // repo_path / target_repo (OSS sessions). Exactly one must be present.
  // The repo path skips DNS validation because the target_domain is a
  // synthetic repo slug (validated by REPO_TARGET_DOMAIN_PATTERN).
  const hasRepoPath = args && typeof args.repo_path === "string" && args.repo_path.trim().length > 0;
  const hasRepo = (args && args.target_repo != null) || hasRepoPath;
  const hasUrl = args && typeof args.target_url === "string" && args.target_url.trim().length > 0;
  if (hasRepo && hasUrl) {
    throw blockedDecision(rule, args, {
      errorCode: "normalization_failed",
      envelopeCode: ERROR_CODES.INVALID_ARGUMENTS,
      message: "bootstrap accepts exactly one of target_url or target_repo, not both",
      sessionPresent: false,
      match: false,
    });
  }
  if (hasRepo) {
    // bob_init_repo_session lets the caller omit target_domain — the slug
    // is derived from the absolute repo path so reopening the same
    // checkout from any working directory routes to the same session.
    if (!targetDomainPresent(args) && hasRepoPath) {
      try {
        const { deriveRepoTargetDomain } = require("./repo-target.js");
        const {
          assertRepoRootPath,
        } = require("./governance-contracts.js");
        const canonicalRoot = assertRepoRootPath(args.repo_path, "repo_path");
        args.target_domain = deriveRepoTargetDomain(canonicalRoot);
      } catch (error) {
        const code = error && error.code === "repo_path_not_found" ? "repo_path_not_found"
          : error && error.code === "repo_path_not_directory" ? "repo_path_not_directory"
          : "normalization_failed";
        throw blockedDecision(rule, args, {
          errorCode: code,
          envelopeCode: ERROR_CODES.INVALID_ARGUMENTS,
          message: error.message || String(error),
          sessionPresent: false,
          match: false,
        });
      }
    }
    const authorityTargetDomain = normalizeRepoBootstrapTarget(rule, args);
    return allowedDecision(rule, args, {
      authorityTargetDomain,
      source: "bootstrap",
      sessionPresent: false,
      match: true,
    });
  }
  const authorityTargetDomain = normalizeArgumentTarget(rule, args);
  if (!hasUrl) {
    throw blockedDecision(rule, args, {
      errorCode: "normalization_failed",
      envelopeCode: ERROR_CODES.INVALID_ARGUMENTS,
      message: "target_url is required for session authority",
      authorityTargetDomain,
      sessionPresent: false,
      match: false,
    });
  }
  try {
    validateHttpScanScope(args.target_url, authorityTargetDomain);
  } catch (error) {
    throw blockedDecision(rule, args, {
      errorCode: "target_url_drift",
      envelopeCode: ERROR_CODES.SCOPE_BLOCKED,
      message: error.message || String(error),
      authorityTargetDomain,
      sessionPresent: false,
      match: false,
      details: error.details,
    });
  }
  return allowedDecision(rule, args, {
    authorityTargetDomain,
    source: "bootstrap",
    sessionPresent: false,
    match: true,
  });
}

function authorizeSessionBound(tool, rule, args) {
  const authorityTargetDomain = normalizeArgumentTarget(rule, args);
  try {
    readRawAuthorityState(authorityTargetDomain, rule, args);
  } catch (error) {
    const shadow = shadowDecision(error, tool, rule);
    if (shadow) return shadow;
    throw error;
  }
  return allowedDecision(rule, args, {
    authorityTargetDomain,
    source: "session_state",
    sessionPresent: true,
    match: true,
  });
}

function validateSessionAuthorityState(targetDomain, {
  authorityClass = "cross_session_read",
  authoritySource = "cross_session",
} = {}) {
  const args = { target_domain: targetDomain };
  const rule = {
    authority_class: authorityClass,
    target_domain: "required",
    target_url_policy: "validate_before_target_url_export",
    authority_source: authoritySource,
  };
  const authorityTargetDomain = normalizeArgumentTarget(rule, args);
  readRawAuthorityState(authorityTargetDomain, rule, args);
  return allowedDecision(rule, args, {
    authorityTargetDomain,
    source: authoritySource,
    sessionPresent: true,
    match: true,
  });
}

function authorizeToolCall(tool, args = {}) {
  const rule = baseRuleForTool(tool, args);
  if (!rule) {
    throw blockedDecision({
      authority_class: null,
      authority_source: "global",
    }, args, {
      errorCode: "class_missing",
      envelopeCode: ERROR_CODES.STATE_CONFLICT,
      message: `Missing authority class for ${tool && tool.name ? tool.name : "<unknown>"}`,
      sessionPresent: null,
      match: null,
    });
  }
  if (!AUTHORITY_CLASSES.includes(rule.authority_class)) {
    throw blockedDecision(rule, args, {
      errorCode: "class_missing",
      envelopeCode: ERROR_CODES.STATE_CONFLICT,
      message: `Unknown authority class for ${tool.name}: ${rule.authority_class}`,
      sessionPresent: null,
      match: null,
    });
  }
  if (rule.authority_class === "bootstrap_session") {
    return authorizeBootstrap(rule, args);
  }
  if (SESSION_AUTHORITY_CLASSES.has(rule.authority_class)) {
    return authorizeSessionBound(tool, rule, args);
  }
  if (rule.authority_class === "global_preapproval") {
    return allowedDecision(rule, args, {
      source: "preapproval_global",
      sessionPresent: false,
      match: null,
    });
  }
  if (rule.authority_class === "global_read") {
    return allowedDecision(rule, args, {
      source: rule.authority_source || "global",
      sessionPresent: false,
      match: null,
    });
  }
  if (rule.authority_class === "cross_session_read") {
    return allowedDecision(rule, args, {
      source: "cross_session",
      sessionPresent: null,
      match: null,
    });
  }
  throw blockedDecision(rule, args, {
    errorCode: "class_missing",
    envelopeCode: ERROR_CODES.STATE_CONFLICT,
    message: `Unhandled authority class for ${tool.name}: ${rule.authority_class}`,
    sessionPresent: null,
    match: null,
  });
}

function scopedUrlDriftError(baseDecision, field, error) {
  const decision = {
    ...baseDecision,
    authority_result: "blocked",
    authority_error_code: "scoped_url_drift",
    authority_block_reason: "scoped_url_drift",
    authority_shadowed: false,
  };
  const toolError = new ToolError(
    ERROR_CODES.SCOPE_BLOCKED,
    `${field} is outside target scope: ${error.message || String(error)}`,
    {
      ...(error.details || {}),
      authority: decision,
    },
  );
  toolError.authority = decision;
  return toolError;
}

function normalizeAuthorityTelemetry(authority) {
  if (!authority || typeof authority !== "object" || Array.isArray(authority)) {
    return null;
  }
  return makeDecision(authority);
}

module.exports = {
  AUTHORITY_CLASSES,
  AUTHORITY_MODE_ENV,
  AUTHORITY_VERSION,
  EXPLICIT_AUTHORITY_CLASS_BY_TOOL,
  LEGACY_DEFAULTABLE_FIELDS,
  LEGACY_FAIL_CLOSED_FIELDS,
  REPO_TARGET_DOMAIN_PATTERN,
  authorizeToolCall,
  baseRuleForTool,
  classForTool,
  isRepoTargetDomain,
  normalizeAuthorityTelemetry,
  scopedUrlDriftError,
  validateSessionAuthorityState,
};
