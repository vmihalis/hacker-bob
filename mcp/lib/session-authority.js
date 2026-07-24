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
  parseLabAuthorization,
  labBootstrapPolicyViolation,
} = require("./lab-target-attest.js");
const {
  normalizeSessionStateDocument,
} = require("./session-state-contracts.js");
const {
  enforcementLiveness,
} = require("./enforcement-attest.js");
const {
  sessionChainContext,
} = require("./chain-tool-identity.js");
const {
  isChainTupleInAuthority,
} = require("./chain-authority.js");
const {
  derivePhysicalSessionIdentity,
  isPhysicalSessionTargetDomain,
  PHYSICAL_SESSION_TARGET_DOMAIN_PATTERN,
} = require("./physical-session-identity.js");
const {
  readVerifiedPhysicalSessionBootstrapJournal,
} = require("./physical-session-journal.js");
const {
  readVerifiedSessionNucleus,
} = require("./governance-store.js");
const {
  sessionNucleusFromState,
} = require("./governance-contracts.js");

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
  bob_evm_call: "smart_contract_contextual",
  bob_evm_fetch_source: "smart_contract_contextual",
  bob_evm_role_table: "smart_contract_contextual",
  bob_evm_storage_read: "smart_contract_contextual",
  bob_extract_routes: "initialized_session_read",
  bob_finalize_agent_run: "initialized_session_mutation",
  bob_foundry_run: "smart_contract_contextual",
  bob_get_context_budget: "mode_dependent_session",
  bob_halmos_run: "smart_contract_contextual",
  bob_http_confirm: "scoped_http_network",
  bob_http_cors_confirm: "scoped_http_network",
  bob_http_idor_confirm: "scoped_http_network",
  bob_http_massread_confirm: "scoped_http_network",
  bob_http_scan: "scoped_http_network",
  bob_http_xss_confirm: "scoped_http_network",
  bob_http_xss_reflect: "scoped_http_network",
  bob_import_harness: "initialized_session_mutation",
  bob_import_http_traffic: "scoped_http_network",
  bob_import_seed_corpus: "initialized_session_mutation",
  bob_import_static_artifact: "initialized_session_mutation",
  bob_ingest_audit_report: "initialized_session_mutation",
  bob_ingest_schema_doc: "initialized_session_mutation",
  bob_init_session: "bootstrap_session",
  bob_init_repo_session: "bootstrap_session",
  // Smart-contract bootstrap sibling of bob_init_session (url axis) /
  // bob_init_repo_session (repo axis): it CREATES the session from the
  // contracts axis, so it must route to authorizeBootstrap, not the
  // session-bound mutation path (which would deadlock on a pre-existing
  // state.json + a target_domain argument this tool's schema does not carry).
  bob_init_contract_session: "bootstrap_session",
  bob_init_physical_session: "bootstrap_session",
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
  // Belief plane (CB-*) + composition experiment/verifier — orchestrator-only,
  // session-scoped: reads classify as initialized_session_read, writers as
  // initialized_session_mutation, the network-capable live verifier as
  // scoped_http_network (mirrors bob_run_auth_differential).
  bob_elicit_belief: "initialized_session_mutation",
  bob_plan_belief_experiment: "initialized_session_mutation",
  // Recon multi-modal sweep — SETUP recon-angle planner. A read-only planning
  // read over an initialized session (host pool + governor + deep_mode); NOT a
  // belief signal, so it has no belief/authority.js entry.
  bob_plan_recon_angles: "initialized_session_read",
  bob_query_belief_signals: "initialized_session_read",
  bob_query_belief_window: "initialized_session_read",
  bob_query_intervention_calculus: "initialized_session_read",
  bob_read_belief_model_info: "initialized_session_read",
  bob_read_belief_signals: "initialized_session_read",
  bob_run_belief_residual: "initialized_session_mutation",
  bob_run_belief_sampler: "initialized_session_mutation",
  bob_train_belief_model: "initialized_session_mutation",
  bob_read_composition_telemetry: "initialized_session_read",
  bob_run_path_composition_experiment: "initialized_session_mutation",
  bob_verify_composition_path: "scoped_http_network",
  bob_merge_wave_handoffs: "initialized_session_read",
  // PR7 nuclei detection scan — runs in the wide-open offensive container and issues
  // target traffic, so same scoped_http_network class as the other offensive producers
  // (it needs an initialized session + an in-scope target_url). DETECTION-only: never
  // signs a row.
  bob_nuclei_scan: "scoped_http_network",
  // PR6 OOB collector. Same class as the other offensive HTTP producers + the
  // scope-exempt bob_public_intel: mint writes the binding (no network), poll is
  // the one aim-exempt egress to the constant Bob-owned sink.
  bob_oob_mint: "scoped_http_network",
  bob_oob_poll: "scoped_http_network",
  // O3 second-order / stored-effect re-read producer. Same class as the other
  // offensive HTTP producers: mint writes the binding (no network), reread is the
  // scope-validated safeFetch re-read of the in-scope observation endpoint.
  bob_secondorder_mint: "scoped_http_network",
  bob_secondorder_reread: "scoped_http_network",
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
  // bob_export_security_hub_finding removed from the model-reachable tool
  // registry -- see mcp/lib/tools/index.js's comment at the same seam.
  bob_amend_report: "initialized_session_mutation",
  bob_write_chain_rollup: "initialized_session_mutation",
  bob_set_friction_scanners: "initialized_session_mutation",
  bob_materialize_frontier: "initialized_session_mutation",
  bob_materialize_task_graph: "initialized_session_mutation",
  bob_materialize_cell_floor: "initialized_session_mutation",
  bob_read_task_graph: "initialized_session_read",
  bob_read_queue_policy: "initialized_session_read",
  bob_read_session_nucleus: "initialized_session_read",
  bob_schedule_tasks: "initialized_session_mutation",
  // Plane X Cycle X.9: bob_schedule_graph_nodes wraps the graph-walking
  // scheduler + bob_prepare_node dispatch. Same authority class as the
  // wave-scheduler's bob_schedule_tasks.
  bob_schedule_graph_nodes: "initialized_session_mutation",
  bob_materialize_producer_floor: "initialized_session_mutation",
  bob_schedule_seed_producers: "initialized_session_mutation",
  bob_set_pack_telemetry_config: "initialized_session_mutation",
  bob_set_queue_policy: "initialized_session_mutation",
  bob_read_session_state: "initialized_session_read",
  bob_read_session_summary: "initialized_session_read",
  bob_read_state_summary: "initialized_session_read",
  bob_read_static_analysis_index: "initialized_session_read",
  bob_read_surface_leads: "initialized_session_read",
  bob_read_surface_routes: "initialized_session_read",
  bob_read_technique_pack: "mode_dependent_session",
  bob_read_tool_telemetry: "mode_dependent_session",
  bob_read_verification_context: "initialized_session_read",
  bob_read_verification_round: "initialized_session_read",
  bob_read_wave_handoffs: "initialized_session_read",
  bob_record_candidate_claim: "initialized_session_mutation",
  bob_record_physical_candidate_claim: "initialized_session_mutation",
  bob_record_surface_leads: "initialized_session_mutation",
  // Writes the mechanism-candidates.jsonl session ledger (a knowledge ingest like
  // bob_ingest_audit_report); it mutates session state and is not a belief signal,
  // so it carries no belief/authority.js entry.
  bob_register_mechanism_template: "initialized_session_mutation",
  bob_prepare_node: "initialized_session_mutation",
  bob_finalize_node: "initialized_session_mutation",
  bob_repo_check: "initialized_session_mutation",
  bob_repo_docker_run: "initialized_session_mutation",
  bob_verify_repro_reproduction: "initialized_session_mutation",
  bob_verify_oracle_differential: "initialized_session_mutation",
  bob_verify_invariant_differential: "initialized_session_mutation",
  bob_verify_finding_differential: "initialized_session_mutation",
  // Plane-PH read-only verdict adapter.  Explicitly session-bound so its
  // global_preapproval UI metadata can never downgrade it to a global read;
  // required_session_axes:[physical] is enforced inside authorizeSessionBound.
  bob_verify_physical_verdict: "initialized_session_read",
  bob_verify_physical_candidate_claim: "initialized_session_read",
  // PH-I1 exposes only signed, current, report-safe capability projections;
  // it is still bound to the initialized physical-session authority axis.
  bob_query_instrument_capabilities: "initialized_session_read",
  // PH-C execution adapters consume one-use server-owned execution refs and
  // can cause bounded physical effects, so every family is a session mutation.
  bob_physical_observe: "initialized_session_mutation",
  bob_credential_acquire: "initialized_session_mutation",
  bob_credential_recover: "initialized_session_mutation",
  bob_credential_emulate: "initialized_session_mutation",
  bob_credential_write: "initialized_session_mutation",
  bob_protocol_transceive: "initialized_session_mutation",
  bob_rf_trace: "initialized_session_mutation",
  bob_repo_inventory: "initialized_session_mutation",
  bob_repo_prepare_env: "initialized_session_mutation",
  bob_resolve_body: "initialized_session_read",
  bob_route_surfaces: "initialized_session_mutation",
  bob_run_auth_differential: "scoped_http_network",
  bob_run_doc_delta: "scoped_http_network",
  bob_run_invariant_for_finding: "smart_contract_contextual",
  bob_select_technique_packs: "initialized_session_read",
  bob_set_operator_note: "initialized_session_mutation",
  bob_signup_detect: "scoped_http_network",
  bob_stage_verification_round_partial: "initialized_session_mutation",
  bob_start_next_wave: "initialized_session_mutation",
  bob_start_wave: "initialized_session_mutation",
  bob_static_scan: "initialized_session_mutation",
  bob_ingest_sarif: "initialized_session_mutation",
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
  bob_temp_email: "scoped_http_network",
  bob_wave_handoff_status: "initialized_session_read",
  bob_wave_status: "initialized_session_read",
  bob_write_chain_attempt: "initialized_session_mutation",
  bob_write_evidence_packs: "initialized_session_mutation",
  bob_write_grade_verdict: "initialized_session_mutation",
  bob_write_handoff: "initialized_session_mutation",
  bob_write_proof_bundle: "initialized_session_mutation",
  bob_write_verification_round: "initialized_session_mutation",
  bob_write_wave_handoff: "initialized_session_mutation",
  bob_ws_probe: "scoped_http_network",
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

// CONTRACT_TARGET_DOMAIN_PATTERN identifies the synthetic on-chain slug minted by
// deriveContractTargetDomain for the contracts axis. A single contract yields
// `sc-<family>-<chainId>-<addr8>` (family is one of the six known chain families,
// chainId is the safeSlug alphabet, addr8 is addressSlug's [a-z0-9]{1,8}); several
// contracts collapse to `contracts-<hash8>` (the first 8 hex of the chain authority
// hash). Like the repo guard, this is the hook that lets a contract session skip
// assertHttpScopeDomain (which rejects non-public-suffix hosts). It is intentionally
// narrow and family-restricted so a maliciously-crafted target_domain cannot smuggle
// contract treatment for a host that is actually a public-suffix URL.
const CONTRACT_TARGET_DOMAIN_PATTERN =
  /^(?:sc-(?:evm|svm|aptos|sui|substrate|cosmwasm)-[a-z0-9._-]+-[a-z0-9]{1,8}|contracts-[0-9a-f]{8})$/;

function isContractTargetDomain(value) {
  return typeof value === "string" && CONTRACT_TARGET_DOMAIN_PATTERN.test(value);
}

function hasOwn(value, key) {
  return Object.prototype.hasOwnProperty.call(value, key);
}

function targetDomainPresent(args) {
  return !!(args && typeof args.target_domain === "string" && args.target_domain.trim());
}

function safeArgumentTargetDomain(args) {
  if (!targetDomainPresent(args)) return null;
  if (isPhysicalSessionTargetDomain(args.target_domain.trim())) {
    return args.target_domain.trim();
  }
  try {
    return assertHttpScopeDomain(args.target_domain);
  } catch {
    return null;
  }
}

function authorityMode(env = process.env) {
  // Honor shadow ONLY when the operator has acked the degraded posture.
  // An un-acked shadow request reports "enforce" so the kernel fails LOUD
  // (real missing-session block) instead of silently downgrading.
  return enforcementLiveness(env).shadow_active ? "shadow" : "enforce";
}

function classForTool(toolName) {
  if (Object.prototype.hasOwnProperty.call(EXPLICIT_AUTHORITY_CLASS_BY_TOOL, toolName)) {
    return EXPLICIT_AUTHORITY_CLASS_BY_TOOL[toolName];
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
    return modeRule(tool.name, args);
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
  operator_ack: operatorAck = null,
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
    operator_ack: operatorAck === true ? true : (operatorAck === false ? false : null),
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
  return {
    ...error.authority,
    authority_result: "shadow_blocked",
    authority_shadowed: true,
    // The ack is now a recorded fact on the audit-graded decision, not a
    // discardable stderr line. canShadowMissingSession only returns true when
    // authorityMode()==="shadow", which implies operator_ack.
    operator_ack: true,
  };
}

function normalizeArgumentTarget(rule, args, opts = {}) {
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
  // Contract-shaped target_domain (sc-<family>-<chainId>-<addr8> or
  // contracts-<hash8>) bypasses assertHttpScopeDomain exactly as the repo slug
  // does. The pattern guard prevents a maliciously-crafted target_domain from
  // smuggling contract treatment for a domain that is actually a URL; any
  // non-matching domain still falls through to the public-suffix check below.
  if (CONTRACT_TARGET_DOMAIN_PATTERN.test(args.target_domain.trim())) {
    const trimmed = args.target_domain.trim();
    args.target_domain = trimmed;
    return trimmed;
  }
  if (PHYSICAL_SESSION_TARGET_DOMAIN_PATTERN.test(args.target_domain.trim())) {
    const trimmed = args.target_domain.trim();
    args.target_domain = trimmed;
    return trimmed;
  }
  try {
    const normalized = assertHttpScopeDomain(args.target_domain, opts);
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
  const isContractAuthority = isContractTargetDomain(authorityTargetDomain);
  const isPhysicalAuthority = isPhysicalSessionTargetDomain(authorityTargetDomain);
  let physicalJournal = null;
  let physicalNucleus = null;
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
  } else if (isContractAuthority) {
    // Contract sessions use the synthetic on-chain slug (sc-<family>-<chainId>-<addr8>
    // or contracts-<hash8>). assertHttpScopeDomain rejects non-public-suffix hosts, so
    // for contract sessions we validate target identity directly: raw.target must equal
    // the authority domain and be a well-formed contract slug. target_url is null for
    // contract sessions; we replace the URL drift check with target_contracts +
    // chain_authority_hash presence checks (the contract-axis analogue of repo's
    // target_repo + repo_hash).
    if (raw.target !== authorityTargetDomain || !isContractTargetDomain(raw.target)) {
      throw blockedDecision(rule, args, {
        errorCode: "raw_target_drift",
        envelopeCode: ERROR_CODES.SCOPE_BLOCKED,
        message: `Session authority target drift for ${authorityTargetDomain}`,
        authorityTargetDomain,
        sessionPresent: true,
        match: false,
      });
    }
    if (!hasOwn(raw, "target_contracts") || !Array.isArray(raw.target_contracts) || raw.target_contracts.length === 0) {
      throw blockedDecision(rule, args, {
        errorCode: "legacy_security_field_missing",
        envelopeCode: ERROR_CODES.STATE_CONFLICT,
        message: "session authority field is missing: target_contracts",
        authorityTargetDomain,
        sessionPresent: true,
        match: true,
      });
    }
    if (!hasOwn(raw, "chain_authority_hash") || typeof raw.chain_authority_hash !== "string" || !/^[0-9a-f]{8,64}$/i.test(raw.chain_authority_hash)) {
      throw blockedDecision(rule, args, {
        errorCode: "legacy_security_field_missing",
        envelopeCode: ERROR_CODES.STATE_CONFLICT,
        message: "session authority field is missing: chain_authority_hash",
        authorityTargetDomain,
        sessionPresent: true,
        match: true,
      });
    }
  } else if (isPhysicalAuthority) {
    if (raw.target !== authorityTargetDomain || !isPhysicalSessionTargetDomain(raw.target)) {
      throw blockedDecision(rule, args, {
        errorCode: "raw_target_drift",
        envelopeCode: ERROR_CODES.SCOPE_BLOCKED,
        message: `Physical session authority target drift for ${authorityTargetDomain}`,
        authorityTargetDomain,
        sessionPresent: true,
        match: false,
      });
    }
    const physicalOnly = hasOwn(raw, "physical_scope") && raw.physical_scope != null
      && raw.target_url == null
      && raw.target_repo == null
      && (!Array.isArray(raw.target_contracts) || raw.target_contracts.length === 0);
    if (!physicalOnly) {
      throw blockedDecision(rule, args, {
        errorCode: "physical_scope_binding_missing",
        envelopeCode: ERROR_CODES.STATE_CONFLICT,
        message: `Physical-only session authority binding is malformed for ${authorityTargetDomain}`,
        authorityTargetDomain,
        sessionPresent: true,
        match: false,
      });
    }
    try {
      physicalJournal = readVerifiedPhysicalSessionBootstrapJournal(
        authorityTargetDomain,
        { requireComplete: true },
      );
      physicalNucleus = readVerifiedSessionNucleus(authorityTargetDomain);
    } catch (error) {
      throw blockedDecision(rule, args, {
        errorCode: "physical_bootstrap_incomplete",
        envelopeCode: ERROR_CODES.STATE_CONFLICT,
        message: `Physical session bootstrap authority is incomplete for ${authorityTargetDomain}`,
        authorityTargetDomain,
        sessionPresent: true,
        match: false,
        details: { reason: error.message || String(error) },
      });
    }
    if (!physicalNucleus.physical_scope
        || physicalNucleus.physical_scope.axis_digest !== physicalJournal.physical_scope.axis_digest) {
      throw blockedDecision(rule, args, {
        errorCode: "physical_bootstrap_drift",
        envelopeCode: ERROR_CODES.STATE_CONFLICT,
        message: `Physical session bootstrap authority drift for ${authorityTargetDomain}`,
        authorityTargetDomain,
        sessionPresent: true,
        match: false,
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

  let normalizedState;
  try {
    normalizedState = normalizeSessionStateDocument(raw, authorityTargetDomain);
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

  if (isPhysicalAuthority
      && (!normalizedState.physical_scope
        || normalizedState.physical_scope.axis_digest !== physicalJournal.physical_scope.axis_digest
        || sessionNucleusFromState(normalizedState).nucleus_hash !== physicalNucleus.nucleus_hash)) {
    throw blockedDecision(rule, args, {
      errorCode: "physical_bootstrap_drift",
      envelopeCode: ERROR_CODES.STATE_CONFLICT,
      message: `Physical session state no longer matches completed bootstrap authority for ${authorityTargetDomain}`,
      authorityTargetDomain,
      sessionPresent: true,
      match: false,
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
  if (args && args.physical_scope_import_ref != null) {
    const carriesCyberAxis = args.target_url != null
      || args.target_repo != null
      || args.repo_path != null
      || args.target_contracts != null
      || args.contracts != null
      || args.target_domain != null;
    if (carriesCyberAxis) {
      throw blockedDecision(rule, args, {
        errorCode: "normalization_failed",
        envelopeCode: ERROR_CODES.INVALID_ARGUMENTS,
        message: "physical-only bootstrap accepts only physical_scope_import_ref",
        sessionPresent: false,
        match: false,
      });
    }
    let identity;
    try {
      identity = derivePhysicalSessionIdentity(args.physical_scope_import_ref);
    } catch (error) {
      throw blockedDecision(rule, args, {
        errorCode: "normalization_failed",
        envelopeCode: ERROR_CODES.INVALID_ARGUMENTS,
        message: error.message || String(error),
        sessionPresent: false,
        match: false,
      });
    }
    return allowedDecision(rule, args, {
      authorityTargetDomain: identity.target_domain,
      source: "bootstrap",
      sessionPresent: false,
      match: true,
    });
  }
  // Cycle O.1 + O-P6 MIXED program: bootstrap accepts a target_url (web) XOR a
  // repo_path / target_repo (OSS) PRIMARY axis, plus an OPTIONAL `contracts`
  // companion that may ride either primary axis OR stand alone (pure-SC). The
  // repo / contracts paths skip DNS validation because their target_domain is a
  // synthetic slug (repo slug via REPO_TARGET_DOMAIN_PATTERN, on-chain slug via
  // the handler's deriveContractSession funnel).
  const hasRepoPath = args && typeof args.repo_path === "string" && args.repo_path.trim().length > 0;
  const hasRepo = (args && args.target_repo != null) || hasRepoPath;
  const hasUrl = args && typeof args.target_url === "string" && args.target_url.trim().length > 0;
  const hasContracts = !!(args && Array.isArray(args.contracts) && args.contracts.length > 0);
  // url and repo are the MUTUALLY EXCLUSIVE primary axes — carrying both is the
  // only multi-axis error (mirrors normalizeSessionStateDocument). A contracts
  // companion never makes the call multi-axis: it binds the chain authority
  // ALONGSIDE the resolved primary slug, so the gate authorizes the primary axis
  // and the handler seeds the companion.
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
  if (hasContracts && !hasUrl) {
    // Contracts-ALONE (pure-SC, no url/repo primary axis): derive the authority
    // domain through the SAME funnel the handler persists (normalizeContracts ->
    // chainAuthorityHash -> deriveContractTargetDomain), so the gate's
    // authority_target_domain is byte-equal to the session slug. A url+contracts
    // MIXED call falls through to the url branch below (the contracts companion
    // is seeded by the handler against the web slug, not this synthetic slug).
    // Lazy require mirrors the repo axis's lazy require('./repo-target.js') — no
    // top-level session-authority -> tool edge, so no circular import. Any
    // malformed-contract throw (Y-D21 unknown family / bad address shape) is
    // re-wrapped fail-closed, never requiring target_url for this axis.
    let domain;
    try {
      const { deriveContractSession } = require("./tools/init-contract-session.js");
      ({ domain } = deriveContractSession(args.contracts));
    } catch (error) {
      throw blockedDecision(rule, args, {
        errorCode: "normalization_failed",
        envelopeCode: ERROR_CODES.INVALID_ARGUMENTS,
        message: error.message || String(error),
        sessionPresent: false,
        match: false,
      });
    }
    return allowedDecision(rule, args, {
      authorityTargetDomain: domain,
      source: "bootstrap",
      sessionPresent: false,
      match: true,
    });
  }
  // Operator-attested lab/private-target escape: this pre-handler bootstrap gate runs FIRST, so for
  // the lab PATH it must agree with the initSession handler — otherwise a fresh private-lab init
  // either deadlocks (scope) or the gate's lab decision diverges from execution (policy). It threads
  // lab_authorization through the scope checks (assertHttpScopeDomain/validateHttpScanScope) AND runs
  // the handler's two lab POLICY checks via the SHARED labBootstrapPolicyViolation (which normalizes
  // block_internal_hosts/egress_profile with the same assertBoolean/assertNonEmptyString the handler
  // uses) — so a gate "allowed" is never a handler reject on those lab POLICY + SCOPE grounds. It is
  // NOT a full input validator: the handler still validates OTHER fields (e.g. allow_internal_hosts
  // type) after the gate, so a future fast-path trusting this decision must still reach the handler
  // for those. parseLabAuthorization requires the operator env ack, so non-lab targets are unaffected.
  const labAuthorization = parseLabAuthorization(args.lab_authorization);
  // Policy check BEFORE the scope normalization, mirroring the handler's order (block_internal is
  // checked before assertHttpScopeDomain there) so the gate and handler surface the same error first.
  const labPolicyViolation = labBootstrapPolicyViolation(args, labAuthorization);
  if (labPolicyViolation) {
    throw blockedDecision(rule, args, {
      errorCode: labPolicyViolation.code,
      envelopeCode: ERROR_CODES.INVALID_ARGUMENTS,
      message: labPolicyViolation.message,
      authorityTargetDomain: null,
      sessionPresent: false,
      match: false,
    });
  }
  const authorityTargetDomain = normalizeArgumentTarget(rule, args, { labAuthorization });
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
    validateHttpScanScope(args.target_url, authorityTargetDomain, { labAuthorization });
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
  let raw;
  try {
    raw = readRawAuthorityState(authorityTargetDomain, rule, args);
  } catch (error) {
    const shadow = shadowDecision(error, tool, rule);
    if (shadow) return shadow;
    throw error;
  }
  const physicalOnly = raw && raw.physical_scope != null
    && raw.target_url == null
    && raw.target_repo == null
    && (!Array.isArray(raw.target_contracts) || raw.target_contracts.length === 0);
  const currentAxes = [
    raw && raw.target_url != null ? "url" : null,
    raw && raw.target_repo != null ? "repo" : null,
    raw && Array.isArray(raw.target_contracts) && raw.target_contracts.length > 0 ? "contracts" : null,
    raw && raw.physical_scope != null ? "physical" : null,
  ].filter(Boolean);
  const requiredAxes = tool && Array.isArray(tool.required_session_axes)
    ? tool.required_session_axes
    : [];
  // A physical-only slug never lends authority to cyber effects. Keep this
  // denial ahead of generic axis membership so every network/browser attempt
  // reports the stronger physical boundary violation regardless of the tool's
  // URL/contracts axis declaration.
  if (physicalOnly && (
    rule.authority_class === "scoped_http_network"
    || rule.authority_class === "smart_contract_contextual"
    || (tool && (tool.network_access === true || tool.browser_access === true))
  )) {
    throw blockedDecision(rule, args, {
      errorCode: "physical_axis_effect_denied",
      envelopeCode: ERROR_CODES.SCOPE_BLOCKED,
      message: `Physical-only session ${authorityTargetDomain} cannot authorize HTTP, browser, or smart-contract effects`,
      authorityTargetDomain,
      sessionPresent: true,
      match: false,
    });
  }
  if (requiredAxes.length > 0 && !requiredAxes.every((axis) => currentAxes.includes(axis))) {
    throw blockedDecision(rule, args, {
      errorCode: "session_axis_mismatch",
      envelopeCode: ERROR_CODES.SCOPE_BLOCKED,
      message: `${tool.name} requires every session axis in ${requiredAxes.join(", ")}; current axes are ${currentAxes.join(", ") || "none"}`,
      authorityTargetDomain,
      sessionPresent: true,
      match: false,
    });
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

// Per-tool projection from a chain tool's heterogeneous arguments to the
// canonical {chain_family, chain_id, address} tuple the chain-authority
// membership test consumes. Each EVM tool's numeric chain_id and each non-EVM
// tool's network/cluster string is the chain_id axis; the address axis is the
// tool's contract/object/account argument. Tools absent from this table are
// never chain-scope-gated.
//
// This table lists target_domain-bearing chain tools that carry a concrete
// address tuple. The gate binds each tuple to the caller-selected session via
// sessionChainContext(args.target_domain). Substrate runtime/storage fetches
// remain absent because they carry no contract-address argument from which to
// form an exact tuple; their contracts-axis requirement still prevents use from
// URL/repo/physical-only sessions.
const CHAIN_SCOPE_TUPLE_BY_TOOL = Object.freeze({
  bob_evm_call: (args) => ({ chain_family: "evm", chain_id: args.chain_id, address: args.to }),
  bob_evm_fetch_source: (args) => ({ chain_family: "evm", chain_id: args.chain_id, address: args.address }),
  bob_evm_role_table: (args) => ({ chain_family: "evm", chain_id: args.chain_id, address: args.contract }),
  bob_evm_storage_read: (args) => ({ chain_family: "evm", chain_id: args.chain_id, address: args.address }),
  bob_sui_fetch_object: (args) => ({ chain_family: "sui", chain_id: args.network, address: args.object_id }),
  bob_sui_fetch_package: (args) => ({ chain_family: "sui", chain_id: args.network, address: args.package_id }),
  bob_aptos_fetch_module: (args) => ({ chain_family: "aptos", chain_id: args.network, address: args.address }),
  bob_aptos_fetch_resource: (args) => ({ chain_family: "aptos", chain_id: args.network, address: args.address }),
  bob_svm_fetch_account: (args) => ({ chain_family: "svm", chain_id: args.cluster, address: args.pubkey }),
  bob_svm_fetch_program: (args) => ({ chain_family: "svm", chain_id: args.cluster, address: args.program_id }),
  bob_cosmwasm_fetch_contract: (args) => ({ chain_family: "cosmwasm", chain_id: args.network, address: args.address }),
});

// Pre-handler chain scope gate. Fires ONLY for a recognized chain tool whose
// resolved session binds a non-empty target_contracts[]; otherwise it returns
// null so the call falls through to the existing class dispatch byte-for-
// behavior unchanged. A bound contracts session admits a tuple iff it is in the
// authority by strict exact-tuple membership (chain_family AND chain_id AND
// address all match a bound contract); every other tuple is SCOPE_BLOCKED. The
// OD3 same-chain relaxation (admit a same-(chain_family,chain_id) read at a
// different address) requires provenance, and provenance detection is not wired,
// so the gate passes provenanced:false and a same-chain different-address read
// is blocked and surfaces as a reported scope gap. The gate reads the bound set
// only through sessionChainContext and tests membership only through
// isChainTupleInAuthority — no parallel normalization, no state writes.
//
// KNOWN LIMITATION — scoped verified source-fetch is DEPTH-1 by design (an
// intentional, documented residual, not an accident). Two deferrals compound:
//   1. This gate passes provenanced:false (see the isChainTupleInAuthority call
//      below): the OD3 same-chain relaxation stays OFF until provenance
//      detection is wired, so even a same-(chain_family,chain_id) contract at a
//      DIFFERENT address is SCOPE_BLOCKED, not admitted.
//   2. The sc-recon-expander resolves proxies/facets/role-holders/linked
//      addresses at depth>1, but those discovered contracts are NOT written
//      back into the session's target_contracts[] (the expander writes scratch
//      / produced_surfaces[] only; binding target_contracts is a later init
//      node's job). Because this gate admits ONLY exact members of the bound
//      set, bob_evm_fetch_source is scope_blocked for every transitively-
//      discovered (depth>1) address.
// Net: scoped EVM reads and verified source-fetch reach only the depth-1 contracts an
// operator bound at init. This holds until the deferred provenance-detection
// node lands (which will both flip OD3 to provenanced and feed discovered
// addresses back into the bound set). Deeper addresses must first be explicitly
// rebound into session authority before any of these EVM reads can target them.
function authorizeChainScope(tool, rule, args) {
  const toTuple = tool && CHAIN_SCOPE_TUPLE_BY_TOOL[tool.name];
  if (!toTuple) return null;
  // Every listed tool requires target_domain in its schema, so this is a
  // defensive guard: with no session handle the gate cannot resolve a bound
  // authority and must fall through to the existing class dispatch.
  if (!targetDomainPresent(args)) return null;

  let ctx;
  try {
    ctx = sessionChainContext(args.target_domain);
  } catch {
    // A missing/malformed session is not this gate's failure to own: fall
    // through and let the existing class dispatch produce the canonical error.
    return null;
  }

  if (!Array.isArray(ctx.target_contracts) || ctx.target_contracts.length === 0) {
    // Web/repo/no-contract sessions: the gate adds nothing.
    return null;
  }

  const tuple = toTuple(args);
  // provenanced:false until provenance detection is wired — the OD3 same-chain
  // relaxation must not be asserted without evidence, so membership stays strict
  // exact-tuple and same-chain-different-address is blocked.
  if (isChainTupleInAuthority(tuple, ctx.target_contracts, { provenanced: false })) {
    return allowedDecision(rule, args, {
      authorityTargetDomain: ctx.target_domain,
      source: "session_state",
      sessionPresent: true,
      match: true,
    });
  }

  // PRD-3
  throw blockedDecision(rule, args, {
    errorCode: "chain_scope_blocked",
    envelopeCode: ERROR_CODES.SCOPE_BLOCKED,
    message: `chain tool ${tool.name} targets a contract outside the session's bound authority`,
    authorityTargetDomain: ctx.target_domain,
    sessionPresent: true,
    match: false,
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
  // Chain scope gate short-circuits the base path for a chain tool resolving to
  // a contracts session (whose synthetic sc-/contracts- slug the smart_contract
  // session-bound path would reject via assertHttpScopeDomain). It is a no-op on
  // every other path: returns null and the existing dispatch runs unchanged.
  const chainScope = authorizeChainScope(tool, rule, args);
  if (chainScope) return chainScope;
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
  CONTRACT_TARGET_DOMAIN_PATTERN,
  PHYSICAL_SESSION_TARGET_DOMAIN_PATTERN,
  LEGACY_DEFAULTABLE_FIELDS,
  LEGACY_FAIL_CLOSED_FIELDS,
  REPO_TARGET_DOMAIN_PATTERN,
  authorizeToolCall,
  baseRuleForTool,
  classForTool,
  isContractTargetDomain,
  isPhysicalSessionTargetDomain,
  isRepoTargetDomain,
  normalizeAuthorityTelemetry,
  scopedUrlDriftError,
  validateSessionAuthorityState,
};
