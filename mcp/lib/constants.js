"use strict";

const FINDING_ID_RE = /^F-([1-9]\d*)$/;
const WAVE_ID_RE = /^w([1-9]\d*)$/;
const AGENT_ID_RE = /^a([1-9]\d*)$/;

const SEVERITY_VALUES = ["critical", "high", "medium", "low", "info"];
// Trust-degradation marker for a finding whose source could not be
// signature-verified. An absent (or unparseable, tolerantly dropped) marker is
// read as signature-verified; the marker is never auto-materialized.
const SIGNATURE_VERIFICATION_STATUS_VALUES = ["signed", "unsigned"];
const OFFENSIVE_OUTCOME_VALUES = ["exploited_safely", "blocked_by_defense", "blocked_by_infra"];
const SAFE_ORACLE_KINDS = [
  "out_of_band_interaction",
  "reflected_canary",
  "differential_response",
  "benign_state_change",
  "blind_boolean_timing",
  "benign_command_marker",
];
const ATTACK_VECTOR_VALUES = ["network", "local", "unknown"];
const SURFACE_TYPE_VALUES = ["web", "smart_contract"];
// X.3 / X-P6: closed enum of TaskGraph node + surface kinds. Distinct from
// SURFACE_TYPE_VALUES (web/smart_contract is the finding-level technology
// classification consumed by finding-contracts and the wave-scheduler);
// SURFACE_KIND_VALUES is the node-kind discriminator persisted in
// task-graph.json (X.2) and surface-index.json (X-P6: "transition nodes are
// persisted as kind: \"transition\"" in surface-index). `cell` is the
// coverage-cell schedulable unit (element x bug_class x auth_role). Growing
// the set requires a new cycle per X-P8.
const SURFACE_KIND_VALUES = ["surface", "transition", "hypothesis", "claim", "cell"];
// TaskGraph node-only kind. A `producer` node is materialized into task-graph.json
// but is INTENTIONALLY OUTSIDE SURFACE_KIND_VALUES: a producer node is
// never persisted to surface-index.json (it is not a scannable surface), so it
// must not appear in the closed surface-index kind discriminator above.
const PRODUCER_NODE_KIND = "producer";
const CHAIN_FAMILY_VALUES = ["evm", "svm", "aptos", "sui", "substrate", "cosmwasm"];
const SVM_CLUSTER_VALUES = ["mainnet-beta", "devnet", "testnet"];
// Aptos and Sui both identify networks by string name in tooling and RPC URLs.
// Integer chain IDs exist on Aptos (1, 2, ...), but they're used for replay
// protection — operators key RPC pools by network NAME (mainnet/testnet/etc).
// Sui has no integer chain id at all. Aptos lacks a stable persistent
// "localnet" — the local testnet has a dynamically rotating chain_id.
const APTOS_NETWORK_VALUES = ["mainnet", "testnet", "devnet"];
const SUI_NETWORK_VALUES = ["mainnet", "testnet", "devnet", "localnet"];
// Substrate parachains identify networks by name. Polkadot, Kusama, Astar,
// Shiden, and the testnets (Rococo, Westend) are the common ink! deployment
// targets in 2025-2026. Operators add private parachain chains via env
// override (BOB_SUBSTRATE_RPCS_<NAME>=...). Localnet covers `substrate-contracts-node`
// dev environments running on 127.0.0.1.
const SUBSTRATE_NETWORK_VALUES = [
  "polkadot",
  "kusama",
  "astar",
  "shiden",
  "rococo",
  "westend",
  "localnet",
];
// CosmWasm chains identify networks by chain name. The 2025-2026 active set
// ships with osmosis, juno, neutron, archway, sei, stargaze, terra (terra2),
// and kava. Localnet covers `wasmd`/`junod` dev environments. Operators add
// new chains via env override (BOB_COSMWASM_RPCS_<NAME>=...).
const COSMWASM_NETWORK_VALUES = [
  "osmosis",
  "juno",
  "neutron",
  "archway",
  "sei",
  "stargaze",
  "terra",
  "kava",
  "localnet",
];
const AUTH_STATUS_VALUES = ["pending", "authenticated", "unauthenticated"];
const CHECKPOINT_MODE_VALUES = ["normal", "paranoid", "yolo"];
const VERIFICATION_ROUND_VALUES = ["brutalist", "balanced", "final"];
const VERIFICATION_DISPOSITION_VALUES = ["confirmed", "denied", "downgraded"];
const VERIFICATION_CONFIDENCE_VALUES = ["high", "medium", "low"];
const VERIFICATION_CONFIDENCE_REASON_VALUES = [
  "fresh_replay_passed",
  "auth_expired",
  "tooling_blocked",
  "state_changed",
  "manual_inference",
  "roast_disagreement",
  "disambiguation_failed",
  "agreement_not_replayed",
  "unruled_confounder",
  "missing_control",
  "exploit_replay_confirmed",
];
const VERIFICATION_REASONING_DIVERGENCE_VALUES = [
  "none",
  "artifact_key_divergence",
  "artifact_hash_divergence",
];
const VERIFICATION_REPLAY_PURPOSE_VALUES = ["verification_replay", "evidence_replay"];
const VERIFY_SMALL_REPORTABLE_THRESHOLD = 5;
const VERIFY_QA_SAMPLE_MAX = 10;
const GRADE_VERDICT_VALUES = ["SUBMIT", "HOLD", "SKIP"];
const GRADE_HOLD_MIN_SCORE = 20;
const GRADE_SUBMIT_MIN_SCORE = 40;
const CHAIN_ATTEMPT_OUTCOME_VALUES = ["confirmed", "denied", "blocked", "inconclusive", "not_applicable"];
const CHAIN_ATTEMPT_TERMINAL_OUTCOME_VALUES = ["confirmed", "denied", "blocked", "not_applicable"];

const COVERAGE_STATUS_VALUES = ["tested", "blocked", "promising", "needs_auth", "requeue"];
const COVERAGE_UNFINISHED_STATUS_VALUES = ["promising", "needs_auth", "requeue"];
const COVERAGE_SUMMARY_MAX_ITEMS = 40;
const COVERAGE_LOG_MAX_RECORDS = 5_000;
const TECHNIQUE_ATTEMPT_STATUS_VALUES = ["selected", "attempted", "not_applicable", "promising", "validated", "failed", "skipped"];
const TECHNIQUE_ATTEMPT_LOG_MAX_RECORDS = 5_000;
const TECHNIQUE_PACK_READ_LOG_MAX_RECORDS = 5_000;
const HTTP_AUDIT_SUMMARY_MAX_ITEMS = 40;
const HTTP_AUDIT_LOG_MAX_RECORDS = 5_000;
const TRAFFIC_SUMMARY_MAX_ITEMS = 40;
const TRAFFIC_IMPORT_MAX_ENTRIES = 500;
const TRAFFIC_LOG_MAX_RECORDS = 5_000;
const PUBLIC_INTEL_MAX_ITEMS = 10;
const PUBLIC_INTEL_MAX_RESPONSE_BYTES = 300_000;
const STATIC_ARTIFACT_ID_RE = /^SA-([1-9]\d*)$/;
const STATIC_ARTIFACT_TYPE_VALUES = ["evm_token_contract", "solana_token_contract"];
const STATIC_ARTIFACT_MAX_CHARS = 200_000;
const STATIC_ARTIFACT_LOG_MAX_RECORDS = 500;
// Imported fuzz harnesses (bob_import_harness). Session-owned, MCP-write-only scratch
// (not audit-graded). One harness is a small source file; the cap matches static imports.
const HARNESS_ID_RE = /^H-([1-9]\d*)$/;
const HARNESS_MAX_CHARS = 200_000;
const HARNESS_LOG_MAX_RECORDS = 200;
// Imported grammar-generated seed corpora (bob_import_seed_corpus). Session-owned,
// MCP-write-only scratch (not audit-graded). A batch import is many small fuzz inputs.
const SEED_CORPUS_ID_RE = /^SC-([1-9]\d*)$/;
const SEED_CORPUS_IMPORT_MAX_SEEDS = 512;
const SEED_CORPUS_IMPORT_MAX_SEED_CHARS = 65_536;
const SEED_CORPUS_IMPORT_MAX_TOTAL_CHARS = 8_000_000;
const SEED_CORPUS_LOG_MAX_RECORDS = 200;
const STATIC_SCAN_RESULTS_MAX_RECORDS = 1_000;
const STATIC_SCAN_FINDING_MAX_ITEMS = 100;
const STATIC_SCAN_HINT_MAX_ITEMS = 10;
const CIRCUIT_BREAKER_THRESHOLD = 3;

// OD1 seed-producer governors (consumed by the queue-policy defaults). The
// per-pass cap and the per-expander linked-address cap are the load-bearing,
// MCP-enforced, NON-null fan-out bounds; the lifetime total is only a backstop.
const DEFAULT_MAX_TOTAL_SEED_PRODUCERS = 1024;
const DEFAULT_SEED_PRODUCER_PER_PASS_CAP = 32;
const DEFAULT_PER_EXPANDER_LINKED_ADDRESS_CAP = 16;

const SESSION_LOCK_NAME = ".session.lock";
const SESSION_LOCK_STALE_MS = 300_000;
const SESSION_PUBLIC_STATE_FIELDS = [
  "target",
  "target_url",
  // Cycle O.1: repo sessions persist target_repo + repo_hash alongside the
  // (nullable) target_url. URL sessions leave these null; the lifecycle
  // contracts treat repo and url targets as mutually exclusive bindings.
  "target_repo",
  "repo_hash",
  "deep_mode",
  "checkpoint_mode",
  "block_internal_hosts",
  "block_internal_hosts_source",
  "phase",
  "lifecycle_state",
  "evaluation_wave",
  "pending_wave",
  "total_findings",
  "prereq_registry_snapshots",
  "blocked_prereq_history",
  "terminal_block_clear_history",
  "dead_ends",
  "waf_blocked_endpoints",
  "scope_exclusions",
  "hold_count",
  "auth_status",
  "egress_profile",
  "egress_region",
  "proxy_configured",
  "egress_profile_identity_hash",
  "egress_profile_identity_version",
  "egress_profile_identity_source",
  "egress_profile_identity_bound_at",
  "egress_profile_identity_bind_source",
  "egress_profile_legacy_migration",
  "operator_note",
  "verification_schema_version",
  "verification_attempt_id",
  "verification_snapshot_hash",
  "verification_entered_at",
  "handoff_provenance_required",
  // Smart-contract sessions bind a third primary axis: target_contracts (the
  // in-scope contract addresses) plus an optional chain_authority_hash. Web and
  // repo sessions leave these at [] / null and the public projection omits them,
  // so the historical url/repo public-state shape stays byte-stable. An empty
  // target_contracts is NOT the contracts axis (the exactly-one-primary-axis
  // normalization treats [] as absent).
  "target_contracts",
  "chain_authority_hash",
];

const VERIFICATION_ROUND_FILE_MAP = {
  brutalist: { json: "brutalist.json", markdown: "brutalist.md" },
  balanced: { json: "balanced.json", markdown: "balanced.md" },
  final: { json: "verified-final.json", markdown: "verified-final.md" },
};

module.exports = {
  AGENT_ID_RE,
  APTOS_NETWORK_VALUES,
  ATTACK_VECTOR_VALUES,
  AUTH_STATUS_VALUES,
  CHAIN_ATTEMPT_OUTCOME_VALUES,
  CHAIN_ATTEMPT_TERMINAL_OUTCOME_VALUES,
  CHECKPOINT_MODE_VALUES,
  CHAIN_FAMILY_VALUES,
  CIRCUIT_BREAKER_THRESHOLD,
  COSMWASM_NETWORK_VALUES,
  COVERAGE_LOG_MAX_RECORDS,
  COVERAGE_STATUS_VALUES,
  COVERAGE_SUMMARY_MAX_ITEMS,
  COVERAGE_UNFINISHED_STATUS_VALUES,
  DEFAULT_MAX_TOTAL_SEED_PRODUCERS,
  DEFAULT_PER_EXPANDER_LINKED_ADDRESS_CAP,
  DEFAULT_SEED_PRODUCER_PER_PASS_CAP,
  FINDING_ID_RE,
  GRADE_HOLD_MIN_SCORE,
  GRADE_SUBMIT_MIN_SCORE,
  GRADE_VERDICT_VALUES,
  HTTP_AUDIT_LOG_MAX_RECORDS,
  HTTP_AUDIT_SUMMARY_MAX_ITEMS,
  OFFENSIVE_OUTCOME_VALUES,
  PRODUCER_NODE_KIND,
  PUBLIC_INTEL_MAX_ITEMS,
  PUBLIC_INTEL_MAX_RESPONSE_BYTES,
  SAFE_ORACLE_KINDS,
  SESSION_LOCK_NAME,
  SESSION_LOCK_STALE_MS,
  SESSION_PUBLIC_STATE_FIELDS,
  SEVERITY_VALUES,
  SIGNATURE_VERIFICATION_STATUS_VALUES,
  HARNESS_ID_RE,
  HARNESS_LOG_MAX_RECORDS,
  HARNESS_MAX_CHARS,
  SEED_CORPUS_ID_RE,
  SEED_CORPUS_IMPORT_MAX_SEEDS,
  SEED_CORPUS_IMPORT_MAX_SEED_CHARS,
  SEED_CORPUS_IMPORT_MAX_TOTAL_CHARS,
  SEED_CORPUS_LOG_MAX_RECORDS,
  STATIC_ARTIFACT_ID_RE,
  STATIC_ARTIFACT_LOG_MAX_RECORDS,
  STATIC_ARTIFACT_MAX_CHARS,
  STATIC_ARTIFACT_TYPE_VALUES,
  STATIC_SCAN_FINDING_MAX_ITEMS,
  STATIC_SCAN_HINT_MAX_ITEMS,
  STATIC_SCAN_RESULTS_MAX_RECORDS,
  TECHNIQUE_ATTEMPT_LOG_MAX_RECORDS,
  TECHNIQUE_ATTEMPT_STATUS_VALUES,
  TECHNIQUE_PACK_READ_LOG_MAX_RECORDS,
  SUBSTRATE_NETWORK_VALUES,
  SUI_NETWORK_VALUES,
  SURFACE_KIND_VALUES,
  SURFACE_TYPE_VALUES,
  SVM_CLUSTER_VALUES,
  TRAFFIC_IMPORT_MAX_ENTRIES,
  TRAFFIC_LOG_MAX_RECORDS,
  TRAFFIC_SUMMARY_MAX_ITEMS,
  VERIFICATION_DISPOSITION_VALUES,
  VERIFICATION_CONFIDENCE_REASON_VALUES,
  VERIFICATION_CONFIDENCE_VALUES,
  VERIFICATION_REASONING_DIVERGENCE_VALUES,
  VERIFICATION_REPLAY_PURPOSE_VALUES,
  VERIFICATION_ROUND_FILE_MAP,
  VERIFICATION_ROUND_VALUES,
  VERIFY_QA_SAMPLE_MAX,
  VERIFY_SMALL_REPORTABLE_THRESHOLD,
  WAVE_ID_RE,
};
