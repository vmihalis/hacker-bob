"use strict";

const AUTH_STATUS_VALUES = ["pending", "authenticated", "unauthenticated"];
const CHECKPOINT_MODE_VALUES = ["normal", "paranoid", "yolo"];
const SESSION_LOCK_NAME = ".session.lock";
const SESSION_LOCK_STALE_MS = 300_000;
const ENGINE_LOCK_NAME = ".engine.lock";
const SESSION_PUBLIC_STATE_FIELDS = [
  "target",
  "target_url",
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
  "target_contracts",
  "chain_authority_hash",
  "physical_scope",
];

module.exports = {
  AUTH_STATUS_VALUES,
  CHECKPOINT_MODE_VALUES,
  ENGINE_LOCK_NAME,
  SESSION_LOCK_NAME,
  SESSION_LOCK_STALE_MS,
  SESSION_PUBLIC_STATE_FIELDS,
};
