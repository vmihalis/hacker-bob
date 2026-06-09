#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");
const INVENTORY_PATH = path.join(ROOT, "docs", "refactor-authority-inventory.md");

const {
  TOOL_REGISTRY,
} = require("../mcp/lib/tool-registry.js");
const {
  EXPLICIT_AUTHORITY_CLASS_BY_TOOL: RUNTIME_AUTHORITY_CLASS_BY_TOOL,
} = require("../mcp/lib/session-authority.js");

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
  // Plane Y Cycle Y.2 — Y-D13 runtime drift telemetry entry. Mirrors the
  // session-authority registration; Y.3 added the server-internal
  // caller bundle for _write-base.js auto-emit.
  bob_emit_runtime_drift: "initialized_session_mutation",
  bob_merge_wave_handoffs: "initialized_session_read",
  bob_promote_surface_leads: "initialized_session_mutation",
  // Plane Y Cycle Y.6 — friction-to-Hypothesis promotion (Y-P6 + Y-P11).
  // Orchestrator-only at the role-bundle layer; threads friction_history
  // into the proposal's suggested_contract BEFORE bob_attach_contract.
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
  bob_read_queue_policy: "initialized_session_read",
  bob_read_task_graph: "initialized_session_read",
  bob_read_session_nucleus: "initialized_session_read",
  bob_schedule_tasks: "initialized_session_mutation",
  // Plane X Cycle X.9: bob_schedule_graph_nodes wraps the graph-walking
  // scheduler + bob_prepare_node dispatch. Same authority class as
  // bob_schedule_tasks (both append to scheduler-decisions.jsonl and
  // mutate session state via downstream tools).
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
  // Plane X Cycle X.7: bob_resolve_body is read-only — bodies are
  // pull-only via the X-D12 resolver registry. Mapped to
  // initialized_session_read because the tool reads session-bound
  // artifacts and never mutates session state.
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

const ABSENT_TARGET_CATEGORY_BY_TOOL = Object.freeze({
  bob_evaluate_capabilities: "registry_capability_introspection",
  bob_read_capability_playbook: "registry_capability_introspection",
  bob_suggest_invariants: "local_static_inspection_no_session_write",
  bob_temp_email: "explicit_no_session_global_network_side_effect",
  bob_evm_call: "explicit_no_session_global_network_read_n2_006_evm",
  bob_evm_storage_read: "explicit_no_session_global_network_read_n2_006_evm",
  bob_evm_role_table: "explicit_no_session_global_network_read_n2_006_evm",
});

const CHAIN_TRANSPORT_OWNER_BY_TOOL = Object.freeze({
  bob_evm_call: "N2-006 EVM no-target RPC transport",
  bob_evm_storage_read: "N2-006 EVM no-target RPC transport",
  bob_evm_role_table: "N2-006 EVM no-target RPC transport",
  bob_evm_fetch_source: "N2-006 EVM contextual transport",
  bob_foundry_run: "N2-006 EVM subprocess/RPC transport",
  bob_halmos_run: "N2-006 EVM symbolic-runner transport",
  bob_svm_fetch_account: "N2-006 SVM contextual transport",
  bob_svm_fetch_program: "N2-006 SVM contextual transport",
  bob_anchor_run: "N2-006 SVM subprocess/RPC transport",
  bob_aptos_fetch_resource: "N2-006 Aptos contextual transport",
  bob_aptos_fetch_module: "N2-006 Aptos contextual transport",
  bob_aptos_run: "N2-006 Aptos subprocess/RPC transport",
  bob_sui_fetch_object: "N2-006 Sui contextual transport",
  bob_sui_fetch_package: "N2-006 Sui contextual transport",
  bob_sui_run: "N2-006 Sui subprocess/RPC transport",
  bob_substrate_run: "N2-006 Substrate subprocess/RPC transport",
  bob_substrate_fetch_storage: "N2-006 Substrate contextual transport",
  bob_substrate_fetch_runtime: "N2-006 Substrate contextual transport",
  bob_cosmwasm_run: "N2-006 CosmWasm subprocess/RPC transport",
  bob_cosmwasm_fetch_contract: "N2-006 CosmWasm contextual transport",
  bob_cosmwasm_smart_query: "N2-006 CosmWasm contextual transport",
  bob_run_invariant_for_finding: "N2-006/N2-007 invariant runner transport and write path",
});

const MODE_RULES = Object.freeze({
  bob_get_context_budget: Object.freeze([
    Object.freeze({
      selector: "surface_id omitted",
      authority_class: "global_read",
      target_domain: "optional_absent",
      target_url_policy: "not_applicable",
      absent_target_category: "registry_capability_introspection",
      enforcement: "Read capability-pack budget metadata without session authority.",
      test_implication: "Direct tests assert no-session metadata read remains allowed.",
    }),
    Object.freeze({
      selector: "surface_id present",
      authority_class: "initialized_session_read",
      target_domain: "required",
      target_url_policy: "validate_session_target_url",
      enforcement: "Require initialized session before validating routed surface context.",
      test_implication: "Direct tests assert surface_id requires target_domain and initialized session.",
    }),
  ]),
  bob_read_technique_pack: Object.freeze([
    Object.freeze({
      selector: "mode omitted or mode=summary",
      authority_class: "global_read",
      target_domain: "optional_absent",
      target_url_policy: "not_applicable",
      absent_target_category: "summary_only_catalog_read",
      enforcement: "Allow summary catalog read without session authority and without artifact writes.",
      test_implication: "Direct tests assert summary mode does not require target_domain.",
    }),
    Object.freeze({
      selector: "mode=full",
      authority_class: "initialized_session_mutation",
      target_domain: "required",
      target_url_policy: "validate_session_target_url",
      enforcement: "Require initialized session, assignment validation, lock, and technique-pack read ledger write.",
      test_implication: "Direct tests assert full mode requires target_domain/wave/agent/surface_id, initialized session, and artifact write bounds.",
    }),
  ]),
  bob_read_tool_telemetry: Object.freeze([
    Object.freeze({
      selector: "target_domain present",
      authority_class: "initialized_session_read",
      target_domain: "required",
      target_url_policy: "validate_session_target_url",
      enforcement: "Require initialized session before returning target-filtered telemetry.",
      test_implication: "Direct tests assert target-filtered telemetry requires initialized session.",
    }),
    Object.freeze({
      selector: "target_domain omitted",
      authority_class: "cross_session_read",
      target_domain: "optional_absent",
      target_url_policy: "index_only_no_target_url_export",
      absent_target_category: "bounded_cross_session_enumeration",
      bounds: "Telemetry files are capped at 5,000 tool events and 5,000 agent-run events; recent-failure output is capped at 100.",
      enforcement: "Allow bounded telemetry aggregation without raw arguments or payloads.",
      test_implication: "Aggregate tests assert bounded/sanitized cross-session telemetry.",
    }),
  ]),
  bob_read_pipeline_analytics: Object.freeze([
    Object.freeze({
      selector: "target_domain present",
      authority_class: "initialized_session_read",
      target_domain: "required",
      target_url_policy: "validate_session_target_url",
      enforcement: "Require initialized session before detailed per-target analytics.",
      test_implication: "Direct tests assert detailed analytics requires initialized session.",
    }),
    Object.freeze({
      selector: "target_domain omitted",
      authority_class: "cross_session_read",
      target_domain: "optional_absent",
      target_url_policy: "validate_before_target_url_export",
      absent_target_category: "bounded_cross_session_enumeration",
      bounds: "Looks back at most 365 days, analyzes at most 200 sessions, and caps examples/events/actions at 100.",
      enforcement: "Allow bounded recent-session metadata analytics; validate per-session target_url before exporting it.",
      test_implication: "Aggregate tests assert bounded lookback and target_url validation before export.",
    }),
  ]),
  bob_read_capability_metrics: Object.freeze([
    Object.freeze({
      selector: "target_domain present",
      authority_class: "initialized_session_read",
      target_domain: "required",
      target_url_policy: "validate_session_target_url",
      enforcement: "Require initialized session before target-filtered capability metrics.",
      test_implication: "Direct tests assert target-filtered metrics require initialized session.",
    }),
    Object.freeze({
      selector: "target_domain omitted",
      authority_class: "cross_session_read",
      target_domain: "optional_absent",
      target_url_policy: "index_only_no_target_url_export",
      absent_target_category: "bounded_cross_session_enumeration",
      bounds: "Reads trimmed telemetry events capped at 5,000 records before aggregating by capability.",
      enforcement: "Allow cross-target telemetry aggregation without session mutation.",
      test_implication: "Aggregate tests assert sanitized cross-target aggregation.",
    }),
  ]),
});

const LEGACY_DEFAULT_ALLOWLIST = Object.freeze({
  owner: "N2-003",
  rule: "Only these fields may be defaulted by legacy compatibility, and only for consuming classes that do not treat the field as authority.",
  fields: Object.freeze([
    "auth_status",
    "blocked_prereq_history",
    "dead_ends",
    "deep_mode",
    "explored",
    "hold_count",
    "evaluation_wave",
    "lead_surface_ids",
    "operator_note",
    "pending_wave",
    "prereq_registry_snapshots",
    "scope_exclusions",
    "terminal_block_clear_history",
    "terminally_blocked",
    "total_findings",
    "waf_blocked_endpoints",
  ]),
});

const LEGACY_FAIL_CLOSED_FIELDS = Object.freeze([
  "target",
  "target_url",
  "checkpoint_mode",
  "block_internal_hosts",
  "block_internal_hosts_source",
  "egress_profile",
  "egress_region",
  "proxy_configured",
  "egress_profile_identity_hash",
  "egress_profile_identity_version",
  "egress_profile_identity_source",
  "egress_profile_identity_bound_at",
  "egress_profile_identity_bind_source",
  "egress_profile_legacy_migration",
  "verification_schema_version",
  "verification_attempt_id",
  "verification_snapshot_hash",
  "verification_entered_at",
]);

const LEGACY_POLICY_BY_CLASS = Object.freeze({
  bootstrap_session: Object.freeze({
    allow_default: [],
    fail_closed: [],
    note: "Not applicable; bootstrap creates the authority document.",
  }),
  initialized_session_read: Object.freeze({
    allow_default: LEGACY_DEFAULT_ALLOWLIST.fields,
    fail_closed: LEGACY_FAIL_CLOSED_FIELDS,
    note: "May default progress/presentation fields only after target, target_url, egress, internal-host, and verification authority fields pass.",
  }),
  initialized_session_mutation: Object.freeze({
    allow_default: LEGACY_DEFAULT_ALLOWLIST.fields,
    fail_closed: LEGACY_FAIL_CLOSED_FIELDS,
    note: "Same as read, before any state or artifact write.",
  }),
  scoped_http_network: Object.freeze({
    allow_default: LEGACY_DEFAULT_ALLOWLIST.fields,
    fail_closed: LEGACY_FAIL_CLOSED_FIELDS,
    note: "Same as initialized session plus scoped URL checks.",
  }),
  smart_contract_contextual: Object.freeze({
    allow_default: LEGACY_DEFAULT_ALLOWLIST.fields,
    fail_closed: LEGACY_FAIL_CLOSED_FIELDS,
    note: "Same as initialized session; chain transport guarantees remain owned by N2-006.",
  }),
  optional_session_context: Object.freeze({
    allow_default: [],
    fail_closed: [],
    note: "Resolve to a concrete per-call class before applying legacy policy.",
  }),
  cross_session_read: Object.freeze({
    allow_default: LEGACY_DEFAULT_ALLOWLIST.fields,
    fail_closed: LEGACY_FAIL_CLOSED_FIELDS,
    note: "Apply per session only when loading or exporting session state; index-only reads are exempt.",
  }),
  mode_dependent_session: Object.freeze({
    allow_default: [],
    fail_closed: [],
    note: "Resolve to the selected mode's concrete class before applying legacy policy.",
  }),
  global_read: Object.freeze({
    allow_default: [],
    fail_closed: [],
    note: "No session state loaded.",
  }),
  global_preapproval: Object.freeze({
    allow_default: [],
    fail_closed: [],
    note: "No session state loaded unless a future per-mode rule says otherwise.",
  }),
  legacy_session_compat: Object.freeze({
    allow_default: [],
    fail_closed: [],
    note: "Not a primary tool class; legacy behavior is a field policy layered on concrete classes.",
  }),
});

function relativePath(filePath) {
  return path.relative(ROOT, filePath).split(path.sep).join("/");
}

function toolFileMap() {
  const toolsDir = path.join(ROOT, "mcp", "lib", "tools");
  const result = new Map();
  for (const entry of fs.readdirSync(toolsDir, { withFileTypes: true })) {
    if (!entry.isFile() || !entry.name.endsWith(".js") || entry.name === "index.js") continue;
    const filePath = path.join(toolsDir, entry.name);
    const tool = require(filePath);
    if (tool && typeof tool.name === "string") {
      result.set(tool.name, relativePath(filePath));
    }
  }
  return result;
}

function hasTargetDomain(tool) {
  return !!(tool.inputSchema && tool.inputSchema.properties && tool.inputSchema.properties.target_domain);
}

function requiresTargetDomain(tool) {
  return !!(tool.inputSchema && Array.isArray(tool.inputSchema.required) && tool.inputSchema.required.includes("target_domain"));
}

function classifyTool(tool) {
  const authorityClass = EXPLICIT_AUTHORITY_CLASS_BY_TOOL[tool.name];
  if (!authorityClass) {
    throw new Error(`missing explicit authority class for ${tool.name}`);
  }
  return authorityClass;
}

function validateExplicitAuthorityMap(registryTools) {
  // Cycle P.1 aliases inherit authority from their primary, so they don't need
  // their own entry in EXPLICIT_AUTHORITY_CLASS_BY_TOOL. The runtime resolves
  // through the alias_of indirection.
  const primaryTools = registryTools.filter((tool) => !tool.alias_of);
  const registeredNames = new Set(primaryTools.map((tool) => tool.name));
  const mappedNames = new Set(Object.keys(EXPLICIT_AUTHORITY_CLASS_BY_TOOL));
  const missing = [...registeredNames].filter((name) => !mappedNames.has(name)).sort();
  const extra = [...mappedNames].filter((name) => !registeredNames.has(name)).sort();
  if (missing.length > 0 || extra.length > 0) {
    throw new Error(`authority class map drift; missing=[${missing.join(", ")}] extra=[${extra.join(", ")}]`);
  }
  const runtimeMappedNames = new Set(Object.keys(RUNTIME_AUTHORITY_CLASS_BY_TOOL));
  const runtimeMissing = [...mappedNames].filter((name) => !runtimeMappedNames.has(name)).sort();
  const runtimeExtra = [...runtimeMappedNames].filter((name) => !mappedNames.has(name)).sort();
  const runtimeDifferent = [...mappedNames]
    .filter((name) => RUNTIME_AUTHORITY_CLASS_BY_TOOL[name] !== EXPLICIT_AUTHORITY_CLASS_BY_TOOL[name])
    .sort();
  if (runtimeMissing.length > 0 || runtimeExtra.length > 0 || runtimeDifferent.length > 0) {
    throw new Error(
      `runtime authority map drift; missing=[${runtimeMissing.join(", ")}] ` +
      `extra=[${runtimeExtra.join(", ")}] different=[${runtimeDifferent.join(", ")}]`,
    );
  }

  for (const [toolName, authorityClass] of Object.entries(EXPLICIT_AUTHORITY_CLASS_BY_TOOL)) {
    if (!AUTHORITY_CLASSES.includes(authorityClass)) {
      throw new Error(`unknown explicit authority class for ${toolName}: ${authorityClass}`);
    }
  }

  for (const [toolName, rules] of Object.entries(MODE_RULES)) {
    const tool = registryTools.find((entry) => entry.name === toolName);
    if (!tool) {
      throw new Error(`mode rules refer to unknown tool ${toolName}`);
    }
    if (!hasTargetDomain(tool) || requiresTargetDomain(tool)) {
      throw new Error(`mode-dependent tool ${toolName} must have optional target_domain`);
    }
    if (EXPLICIT_AUTHORITY_CLASS_BY_TOOL[toolName] !== "mode_dependent_session") {
      throw new Error(`mode rules require mode_dependent_session class for ${toolName}`);
    }
    for (const rule of rules) {
      if (!AUTHORITY_CLASSES.includes(rule.authority_class)) {
        throw new Error(`unknown mode authority class for ${toolName}: ${rule.authority_class}`);
      }
      if (
        (rule.target_domain === "optional_absent" || rule.target_domain === "ignored") &&
        typeof rule.absent_target_category !== "string"
      ) {
        throw new Error(`missing absent_target_category for ${toolName} mode ${rule.selector}`);
      }
    }
  }

  for (const tool of registryTools) {
    if (tool.alias_of) continue;
    if (hasTargetDomain(tool) && !requiresTargetDomain(tool) && !Object.prototype.hasOwnProperty.call(MODE_RULES, tool.name)) {
      // bootstrap_session tools create the authority record and may accept an
      // optional target_domain (e.g. bob_init_repo_session derives the slug
      // from repo_path unless the operator pins it via --target-id). Mode
      // rules don't apply because there is no session to bind against yet.
      if (EXPLICIT_AUTHORITY_CLASS_BY_TOOL[tool.name] === "bootstrap_session") {
        continue;
      }
      throw new Error(`optional target_domain tool lacks mode rules: ${tool.name}`);
    }
  }
}

function targetUrlPolicy(authorityClass) {
  if (authorityClass === "bootstrap_session") return "validate_input_target_url";
  if (authorityClass === "cross_session_read") return "validate_before_target_url_export";
  if (authorityClass === "global_read" || authorityClass === "global_preapproval") return "not_applicable";
  if (authorityClass === "mode_dependent_session") return "per_mode";
  return "validate_session_target_url";
}

function legacyPolicy(authorityClass) {
  if (authorityClass === "global_read" || authorityClass === "global_preapproval") return "not_applicable";
  if (authorityClass === "bootstrap_session") return "not_applicable";
  if (authorityClass === "mode_dependent_session") return "per_mode";
  if (authorityClass === "cross_session_read") return "allowlist_when_loading_state";
  return "allowlist_required";
}

function classRationale(tool, authorityClass) {
  if (authorityClass === "bootstrap_session") {
    return "Creates the session authority record and is the only class allowed before state exists.";
  }
  if (authorityClass === "mode_dependent_session") {
    return "Arguments select either a session-bound mode or an allowed no-target/cross-session mode.";
  }
  if (authorityClass === "scoped_http_network") {
    return "HTTP/import/browser scope tooling needs initialized-session authority plus URL scope validation.";
  }
  if (authorityClass === "smart_contract_contextual") {
    return "Uses target_domain as session/artifact context while chain RPC transport safety is owned by N2-006.";
  }
  if (authorityClass === "initialized_session_mutation") {
    return "Writes session artifacts or mutates session state and must be bound to an initialized session.";
  }
  if (authorityClass === "initialized_session_read") {
    return "Reads target-bound session artifacts and must resolve an initialized session first.";
  }
  if (authorityClass === "global_preapproval") {
    return "No target_domain; intentional global side effect or network read requiring explicit global authority.";
  }
  if (authorityClass === "global_read") {
    return "No target_domain and no session mutation/network side effect; safe global metadata/catalog read.";
  }
  if (authorityClass === "cross_session_read") {
    return "Bounded aggregate read across sessions; no mutation.";
  }
  return `${tool.name} requires explicit authority classification.`;
}

function enforcementSummary(authorityClass) {
  if (authorityClass === "bootstrap_session") {
    return "Normalize target_domain, validate target_url, lock session, reject existing state or non-empty directory.";
  }
  if (authorityClass === "mode_dependent_session") {
    return "Resolve per-call class before authority, shadow, target_url, and legacy-default decisions.";
  }
  if (authorityClass === "scoped_http_network") {
    return "Require initialized session, target match, target_url validation, and scoped URL validation.";
  }
  if (authorityClass === "smart_contract_contextual") {
    return "Require initialized session and target_url validation; fail closed under shadow until N2-006.";
  }
  if (authorityClass === "initialized_session_mutation") {
    return "Require initialized session, target match, target_url validation, and legacy allowlist before write.";
  }
  if (authorityClass === "initialized_session_read") {
    return "Require initialized session, target match, target_url validation, and legacy allowlist before read.";
  }
  if (authorityClass === "cross_session_read") {
    return "Allow bounded cross-session read; validate target_url before exporting it.";
  }
  if (authorityClass === "global_preapproval") {
    return "No session authority; rely on explicit global preapproval and existing transport/tool policy.";
  }
  return "No session authority; local/global read only.";
}

function testImplication(authorityClass) {
  if (authorityClass === "bootstrap_session") {
    return "Direct tests for normalization, target_url scope, re-init rejection, and lock behavior.";
  }
  if (authorityClass === "mode_dependent_session") {
    return "Direct per-mode tests plus aggregate inventory coverage.";
  }
  if (authorityClass === "scoped_http_network") {
    return "Direct tests for missing session, mismatch, target_url drift, and scoped URL drift.";
  }
  if (authorityClass === "smart_contract_contextual") {
    return "Direct tests for session binding plus N2-006 transport-family coverage.";
  }
  if (authorityClass === "initialized_session_mutation") {
    return "Direct tests for missing session, mismatch, legacy fail-closed fields, and artifact write path.";
  }
  if (authorityClass === "initialized_session_read") {
    return "Direct tests for missing session, mismatch, target_url drift, and legacy allowlist.";
  }
  if (authorityClass === "cross_session_read") {
    return "Aggregate tests for bounds, no mutation, and target_url export handling.";
  }
  if (authorityClass === "global_preapproval") {
    return "Aggregate tests assert no session lookup and explicit global class.";
  }
  return "Aggregate tests assert no session lookup.";
}

function flags(tool) {
  return [
    `mutating=${tool.mutating}`,
    `global_preapproval=${tool.global_preapproval}`,
    `network_access=${tool.network_access}`,
    `browser_access=${tool.browser_access}`,
    `scope_required=${tool.scope_required}`,
    `sensitive_output=${tool.sensitive_output}`,
    `artifacts=${tool.session_artifacts_written.length === 0 ? "[]" : tool.session_artifacts_written.join("+")}`,
  ].join("<br>");
}

function scopeUrlFields(tool) {
  return Array.isArray(tool.scope_url_fields) && tool.scope_url_fields.length > 0
    ? tool.scope_url_fields.join(", ")
    : "[]";
}

function absentTargetCategory(toolName, authorityClass) {
  if (authorityClass === "mode_dependent_session") return "per_mode";
  if (authorityClass !== "global_read" && authorityClass !== "global_preapproval") return "not_applicable";
  return ABSENT_TARGET_CATEGORY_BY_TOOL[toolName] || "missing";
}

function transportOwner(toolName) {
  return CHAIN_TRANSPORT_OWNER_BY_TOOL[toolName] || "not_applicable";
}

function modeSummary(toolName) {
  const rules = MODE_RULES[toolName];
  if (!rules) return "";
  return rules
    .map((rule) => {
      const category = rule.absent_target_category ? `, absent=${rule.absent_target_category}` : "";
      return `${rule.selector}: ${rule.authority_class}, target_domain=${rule.target_domain}, target_url=${rule.target_url_policy}${category}`;
    })
    .join("<br>");
}

function buildRows() {
  validateExplicitAuthorityMap(TOOL_REGISTRY);
  const files = toolFileMap();
  return TOOL_REGISTRY.filter((tool) => !tool.alias_of).map((tool) => {
    const authorityClass = classifyTool(tool);
    if (!AUTHORITY_CLASSES.includes(authorityClass)) {
      throw new Error(`unknown authority class for ${tool.name}: ${authorityClass}`);
    }
    const handlerPath = files.get(tool.name);
    if (!handlerPath) {
      throw new Error(`missing handler path for ${tool.name}`);
    }
    if (authorityClass === "global_preapproval") {
      if (hasTargetDomain(tool) || tool.scope_required || tool.global_preapproval !== true) {
        throw new Error(`global_preapproval class invariant failed for ${tool.name}`);
      }
    }
    if (authorityClass === "global_read" && (tool.mutating || tool.network_access || tool.browser_access)) {
      throw new Error(`global_read class invariant failed for ${tool.name}`);
    }
    const category = absentTargetCategory(tool.name, authorityClass);
    if (
      (authorityClass === "global_read" || authorityClass === "global_preapproval") &&
      category === "missing"
    ) {
      throw new Error(`missing absent target category for ${tool.name}`);
    }
    for (const rule of MODE_RULES[tool.name] || []) {
      if (!AUTHORITY_CLASSES.includes(rule.authority_class)) {
        throw new Error(`unknown mode authority class for ${tool.name}: ${rule.authority_class}`);
      }
    }
    return {
      tool: tool.name,
      handler_path: handlerPath,
      authority_class: authorityClass,
      mode_rules: MODE_RULES[tool.name] || [],
      has_target_domain: hasTargetDomain(tool),
      requires_target_domain: requiresTargetDomain(tool),
      flags: flags(tool),
      scope_url_fields: scopeUrlFields(tool),
      absent_target_category: category,
      transport_owner: transportOwner(tool.name),
      rationale: classRationale(tool, authorityClass),
      target_url_policy: targetUrlPolicy(authorityClass),
      legacy_policy: legacyPolicy(authorityClass),
      enforcement: enforcementSummary(authorityClass),
      test_implication: testImplication(authorityClass),
    };
  });
}

function escapeCell(value) {
  return String(value == null ? "" : value)
    .replace(/\|/g, "\\|")
    .replace(/\n/g, "<br>");
}

function renderInventory() {
  const rows = buildRows();
  const byClass = rows.reduce((counts, row) => {
    counts[row.authority_class] = (counts[row.authority_class] || 0) + 1;
    return counts;
  }, {});
  const resolvedByClass = rows.reduce((counts, row) => {
    if (row.mode_rules.length > 0) {
      for (const rule of row.mode_rules) {
        counts[rule.authority_class] = (counts[rule.authority_class] || 0) + 1;
      }
    } else {
      counts[row.authority_class] = (counts[row.authority_class] || 0) + 1;
    }
    return counts;
  }, {});
  const modeDependent = rows.filter((row) => row.mode_rules.length > 0);
  const targetDomainTools = rows.filter((row) => row.has_target_domain).length;
  const requiredTargetDomainTools = rows.filter((row) => row.requires_target_domain).length;

  const lines = [];
  lines.push("# Refactor Authority Inventory");
  lines.push("");
  lines.push("Generated by `node scripts/authority-inventory.js --write`. This is an internal N2-003 refactor artifact and must not ship in npm packages.");
  lines.push("");
  lines.push("The `Target URL` and `Tests` columns are authority contracts for N2-004 enforcement. They do not by themselves prove runtime enforcement.");
  lines.push("");
  lines.push("## Summary");
  lines.push("");
  lines.push(`- Registered tools: ${rows.length}`);
  lines.push(`- Tools with \`target_domain\`: ${targetDomainTools}`);
  lines.push(`- Tools requiring \`target_domain\`: ${requiredTargetDomainTools}`);
  lines.push(`- Mode-dependent tools: ${modeDependent.length}`);
  lines.push("");
  lines.push("| Authority Class | Default Tool Count | Resolved Mode/Tool Count |");
  lines.push("| --- | ---: | ---: |");
  for (const authorityClass of AUTHORITY_CLASSES) {
    lines.push(`| \`${authorityClass}\` | ${byClass[authorityClass] || 0} | ${resolvedByClass[authorityClass] || 0} |`);
  }
  lines.push("");
  lines.push("## Legacy Defaults");
  lines.push("");
  lines.push("No tool's primary class is `legacy_session_compat`. Legacy behavior is applied per-field on top of the resolved concrete class.");
  lines.push("");
  lines.push(LEGACY_DEFAULT_ALLOWLIST.rule);
  lines.push("");
  lines.push(`Allow-default fields: ${LEGACY_DEFAULT_ALLOWLIST.fields.map((field) => `\`${field}\``).join(", ")}.`);
  lines.push("");
  lines.push(`Fail-closed fields: ${LEGACY_FAIL_CLOSED_FIELDS.map((field) => `\`${field}\``).join(", ")}.`);
  lines.push("");
  lines.push("| Authority Class | Allow-Default Fields | Fail-Closed Fields | Note |");
  lines.push("| --- | --- | --- | --- |");
  for (const authorityClass of AUTHORITY_CLASSES) {
    const policy = LEGACY_POLICY_BY_CLASS[authorityClass];
    lines.push([
      `\`${authorityClass}\``,
      policy.allow_default.length === 0 ? "[]" : policy.allow_default.map((field) => `\`${field}\``).join(", "),
      policy.fail_closed.length === 0 ? "[]" : policy.fail_closed.map((field) => `\`${field}\``).join(", "),
      policy.note,
    ].map(escapeCell).join(" | ").replace(/^/, "| ").replace(/$/, " |"));
  }
  lines.push("");
  lines.push("## Mode Rules");
  lines.push("");
  lines.push("| Tool | Rule | Absent-Target Category | Bounds | Enforcement | Test Implication |");
  lines.push("| --- | --- | --- | --- | --- | --- |");
  for (const row of modeDependent) {
    for (const rule of row.mode_rules) {
      lines.push([
        row.tool,
        `${rule.selector}: \`${rule.authority_class}\`, target_domain=${rule.target_domain}, target_url=${rule.target_url_policy}`,
        rule.absent_target_category || "not_applicable",
        rule.bounds || "not_applicable",
        rule.enforcement,
        rule.test_implication,
      ].map(escapeCell).join(" | ").replace(/^/, "| ").replace(/$/, " |"));
    }
  }
  lines.push("");
  lines.push("## Tool Inventory");
  lines.push("");
  lines.push("| Tool | Handler | Class / Modes | Target | Registry Flags | Scope URL Fields | Target URL | Legacy | Absent Target Category | Transport Owner | Rationale | Enforcement | Tests |");
  lines.push("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |");
  for (const row of rows) {
    const classCell = row.mode_rules.length > 0
      ? `\`${row.authority_class}\`<br>${modeSummary(row.tool)}`
      : `\`${row.authority_class}\``;
    lines.push([
      row.tool,
      row.handler_path,
      classCell,
      `has=${row.has_target_domain}<br>required=${row.requires_target_domain}`,
      row.flags,
      row.scope_url_fields,
      row.target_url_policy,
      row.legacy_policy,
      row.absent_target_category,
      row.transport_owner,
      row.rationale,
      row.enforcement,
      row.test_implication,
    ].map(escapeCell).join(" | ").replace(/^/, "| ").replace(/$/, " |"));
  }
  if (lines[lines.length - 1] === "") {
    lines.pop();
  }
  return `${lines.join("\n")}\n`;
}

function checkInventory() {
  const expected = renderInventory();
  let actual = "";
  try {
    actual = fs.readFileSync(INVENTORY_PATH, "utf8");
  } catch {
    throw new Error(`missing authority inventory: ${relativePath(INVENTORY_PATH)}`);
  }
  if (actual.replace(/\r\n/g, "\n") !== expected) {
    throw new Error(`authority inventory is stale; run node scripts/authority-inventory.js --write`);
  }
}

function main() {
  if (process.argv.includes("--write")) {
    fs.mkdirSync(path.dirname(INVENTORY_PATH), { recursive: true });
    fs.writeFileSync(INVENTORY_PATH, renderInventory(), "utf8");
    return;
  }
  if (process.argv.includes("--check")) {
    checkInventory();
    return;
  }
  process.stdout.write(renderInventory());
}

try {
  main();
} catch (error) {
  console.error(error.message || String(error));
  process.exit(1);
}
