"use strict";

const {
  AUTH_STATUS_VALUES,
  CHECKPOINT_MODE_VALUES,
  LIFECYCLE_STATE_VALUES: SESSION_STATE_LIFECYCLE_VALUES,
  SESSION_PUBLIC_STATE_FIELDS,
} = require("./session-state-vocabulary.js");
const {
  assertEnumValue,
  assertBoolean,
  assertInteger,
  assertNonEmptyString,
  normalizeOptionalText,
  normalizeStringArray,
} = require("../io/validation.js");
const {
  validateNoSensitiveMaterial,
} = require("../redaction/index.js");
const {
  normalizePhysicalScopeNucleusAxis,
} = require("./physical-scope-axis-contract.js");

// SESSION_STATE_LIFECYCLE_VALUES is the shared LIFECYCLE_STATE_VALUES leaf
// import above (aliased for readability at its call site below).
// governance-contracts.js imports the same array from the same leaf rather
// than declaring its own copy, so the two lifecycle-facing modules cannot
// drift apart; requiring governance-contracts.js directly here would create
// a top-level import cycle (it depends on blockInternalHostsPolicyFields
// exported below), which is why both sides import from the leaf instead.
//
// The legacy eight-phase FSM was retired in favor of the six-state
// lifecycle authority on session-nucleus.json. state.lifecycle_state is the
// new canonical projection of nucleus.lifecycle_state into the session-state
// document. state.phase persists as a derived back-compat read for callers
// that still consume the legacy field; Cycle D.3 deletes the projection.
//
// Reverse-mapping rationale: lifecycle states are coarser than phases, so
// each lifecycle state has one canonical pre-image (the legacy phase
// readers will see when no explicit phase is on disk):
//
//   SETUP         -> SURFACE_DISCOVERY (init-session bootstrap window)
//   OPEN_FRONTIER -> EVALUATE          (the modal frontier phase under v1.x)
//   CLAIM_FREEZE  -> CHAIN             (chain assembly was the pre-verify hold)
//   VERIFY        -> VERIFY            (identity)
//   GRADE         -> GRADE             (identity)
//   REPORT        -> REPORT            (identity)
const LIFECYCLE_STATE_TO_LEGACY_PHASE = Object.freeze({
  SETUP: "SURFACE_DISCOVERY",
  OPEN_FRONTIER: "EVALUATE",
  CLAIM_FREEZE: "CHAIN",
  VERIFY: "VERIFY",
  GRADE: "GRADE",
  REPORT: "REPORT",
});

// Legacy phases that pre-date the lifecycle vocabulary still appear on disk
// in sessions created before D.1. The forward map normalizes them so the
// state-store can synthesize the lifecycle_state field on read.
const LEGACY_PHASE_TO_LIFECYCLE_STATE = Object.freeze({
  SURFACE_DISCOVERY: "SETUP",
  AUTH: "OPEN_FRONTIER",
  EVALUATE: "OPEN_FRONTIER",
  CHAIN: "OPEN_FRONTIER",
  EXPLORE: "OPEN_FRONTIER",
  VERIFY: "VERIFY",
  GRADE: "GRADE",
  REPORT: "REPORT",
  // RECON/HUNT are accepted as aliases of SURFACE_DISCOVERY/EVALUATE on the
  // read backfill path, resolving to the same lifecycle states so a session
  // persisted under those phase names stays readable rather than failing closed
  // on the legacy-phase fallback.
  RECON: "SETUP",
  HUNT: "OPEN_FRONTIER",
});

function deriveLegacyPhaseFromLifecycleState(lifecycleState) {
  return LIFECYCLE_STATE_TO_LEGACY_PHASE[lifecycleState] || null;
}

function deriveLifecycleStateFromLegacyPhase(legacyPhase) {
  return LEGACY_PHASE_TO_LIFECYCLE_STATE[legacyPhase] || null;
}

const OPERATOR_NOTE_MAX_CHARS = 1000;
const BLOCK_INTERNAL_HOSTS_SOURCE_VALUES = Object.freeze([
  "explicit_block",
  "explicit_allow",
  "paranoid_default",
  "mode_default",
  "legacy_default",
  "request_override",
]);

function validateOperatorNoteText(note, fieldName) {
  if (note.length > OPERATOR_NOTE_MAX_CHARS) {
    throw new Error(`${fieldName} must be at most ${OPERATOR_NOTE_MAX_CHARS} characters`);
  }
  validateNoSensitiveMaterial(note, fieldName, { maxTextChars: OPERATOR_NOTE_MAX_CHARS + 1 });
  return note;
}

function normalizeOperatorNote(value, fieldName = "operator_note") {
  const note = normalizeOptionalText(value, fieldName);
  return note == null ? null : validateOperatorNoteText(note, fieldName);
}

function assertOperatorNote(value, fieldName = "operator_note") {
  return validateOperatorNoteText(assertNonEmptyString(value, fieldName), fieldName);
}

// Cycle O.1: SHAPE-only validator for the persisted target_repo object.
// The strict version (with realpath + isDirectory checks) lives in
// governance-contracts.assertRepoRootPath / normalizeTargetRepo and is
// the bootstrap path; this version is reused by readers (state.json
// reload, nucleus rehydration) where the disk path may have moved
// since session init. session-state-contracts intentionally avoids fs
// and governance-contracts imports to keep its require-graph cycle-free
// (see test "session-state contract and store keep forbidden import
// boundaries").
function normalizeTargetRepoShape(value, fieldName = "target_repo") {
  if (value == null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${fieldName} must be an object`);
  }
  const rootPath = assertNonEmptyString(value.root_path, `${fieldName}.root_path`);
  validateNoSensitiveMaterial(rootPath, `${fieldName}.root_path`, { maxTextChars: 4096 });
  const result = { root_path: rootPath };
  if (value.source_url != null) {
    const sourceUrl = assertNonEmptyString(value.source_url, `${fieldName}.source_url`);
    validateNoSensitiveMaterial(sourceUrl, `${fieldName}.source_url`, { maxTextChars: 2048 });
    result.source_url = sourceUrl;
  }
  if (value.branch != null) {
    const branch = assertNonEmptyString(value.branch, `${fieldName}.branch`);
    validateNoSensitiveMaterial(branch, `${fieldName}.branch`, { maxTextChars: 256 });
    result.branch = branch;
  }
  if (value.commit != null) {
    const commit = assertNonEmptyString(value.commit, `${fieldName}.commit`);
    if (!/^[0-9a-f]{7,64}$/i.test(commit)) {
      throw new Error(`${fieldName}.commit must be a 7-64 character hex commit id`);
    }
    result.commit = commit.toLowerCase();
  }
  return result;
}

function normalizeEgressIdentitySource(value, fieldName = "egress_profile_identity_source") {
  if (value == null) {
    return {
      proxy_url_source: "none",
      proxy_env_var: null,
      proxy_url_redacted: null,
      resolved_proxy: null,
    };
  }
  if (value == null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${fieldName} must be an object`);
  }
  const proxyUrlSource = assertEnumValue(
    value.proxy_url_source == null ? "none" : value.proxy_url_source,
    ["none", "env", "inline"],
    `${fieldName}.proxy_url_source`,
  );
  const source = {
    proxy_url_source: proxyUrlSource,
    proxy_env_var: normalizeOptionalText(value.proxy_env_var, `${fieldName}.proxy_env_var`),
    proxy_url_redacted: normalizeOptionalText(value.proxy_url_redacted, `${fieldName}.proxy_url_redacted`),
    resolved_proxy: null,
  };
  if (value.resolved_proxy != null) {
    if (typeof value.resolved_proxy !== "object" || Array.isArray(value.resolved_proxy)) {
      throw new Error(`${fieldName}.resolved_proxy must be an object`);
    }
    source.resolved_proxy = {
      protocol: assertNonEmptyString(value.resolved_proxy.protocol, `${fieldName}.resolved_proxy.protocol`),
      hostname: assertNonEmptyString(value.resolved_proxy.hostname, `${fieldName}.resolved_proxy.hostname`).toLowerCase(),
      port: normalizeOptionalText(value.resolved_proxy.port, `${fieldName}.resolved_proxy.port`),
    };
  }
  return source;
}

function normalizeEgressLegacyMigration(value, fieldName = "egress_profile_legacy_migration") {
  if (value == null) return null;
  if (typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${fieldName} must be an object`);
  }
  const result = {
    migrated_at: normalizeOptionalText(value.migrated_at, `${fieldName}.migrated_at`),
    source: normalizeOptionalText(value.source, `${fieldName}.source`),
    previous_unbound: value.previous_unbound == null
      ? true
      : assertBoolean(value.previous_unbound, `${fieldName}.previous_unbound`),
    previous: null,
  };
  if (value.previous != null) {
    if (typeof value.previous !== "object" || Array.isArray(value.previous)) {
      throw new Error(`${fieldName}.previous must be an object`);
    }
    result.previous = {
      egress_profile: normalizeOptionalText(value.previous.egress_profile, `${fieldName}.previous.egress_profile`),
      egress_region: normalizeOptionalText(value.previous.egress_region, `${fieldName}.previous.egress_region`),
      proxy_configured: value.previous.proxy_configured == null
        ? false
        : assertBoolean(value.previous.proxy_configured, `${fieldName}.previous.proxy_configured`),
      egress_profile_identity_hash: normalizeOptionalText(
        value.previous.egress_profile_identity_hash,
        `${fieldName}.previous.egress_profile_identity_hash`,
      ),
      egress_profile_identity_version: value.previous.egress_profile_identity_version == null
        ? null
        : assertInteger(
          value.previous.egress_profile_identity_version,
          `${fieldName}.previous.egress_profile_identity_version`,
          { min: 1 },
        ),
    };
  }
  return result;
}

function egressProfileStateFields(profile) {
  return {
    egress_profile: profile.name,
    egress_region: profile.region,
    proxy_configured: profile.proxy_configured === true,
    egress_profile_identity_hash: profile.egress_profile_identity_hash,
    egress_profile_identity_version: profile.egress_profile_identity_version,
    egress_profile_identity_source: profile.egress_profile_identity_source,
  };
}

function normalizeCheckpointMode(value, fieldName = "checkpoint_mode") {
  return value == null
    ? "normal"
    : assertEnumValue(value, CHECKPOINT_MODE_VALUES, fieldName);
}

function normalizeBlockInternalHostsSource(value, fieldName = "block_internal_hosts_source") {
  return value == null
    ? null
    : assertEnumValue(value, BLOCK_INTERNAL_HOSTS_SOURCE_VALUES, fieldName);
}

function deriveBlockInternalHostsPolicy({
  checkpointMode = "normal",
  blockInternalHosts = null,
  allowInternalHosts = null,
  legacyDefault = false,
} = {}) {
  const mode = normalizeCheckpointMode(checkpointMode);
  const explicitBlock = blockInternalHosts == null
    ? null
    : assertBoolean(blockInternalHosts, "block_internal_hosts");
  const explicitAllow = allowInternalHosts == null
    ? null
    : assertBoolean(allowInternalHosts, "allow_internal_hosts");

  if (explicitBlock === true && explicitAllow === true) {
    throw new Error("block_internal_hosts and allow_internal_hosts cannot both be true");
  }
  if (explicitBlock === true) {
    return {
      checkpoint_mode: mode,
      block_internal_hosts: true,
      block_internal_hosts_source: "explicit_block",
    };
  }
  if (explicitAllow === true) {
    return {
      checkpoint_mode: mode,
      block_internal_hosts: false,
      block_internal_hosts_source: "explicit_allow",
    };
  }
  if (legacyDefault) {
    return {
      checkpoint_mode: mode,
      block_internal_hosts: false,
      block_internal_hosts_source: "legacy_default",
    };
  }
  if (mode === "paranoid") {
    return {
      checkpoint_mode: mode,
      block_internal_hosts: true,
      block_internal_hosts_source: "paranoid_default",
    };
  }
  return {
    checkpoint_mode: mode,
    block_internal_hosts: false,
    block_internal_hosts_source: "mode_default",
  };
}

function assertBlockInternalHostsPolicyConsistency(policy) {
  const blockInternalHosts = assertBoolean(policy.block_internal_hosts, "block_internal_hosts");
  const source = normalizeBlockInternalHostsSource(policy.block_internal_hosts_source)
    || (blockInternalHosts ? "explicit_block" : "legacy_default");
  const requiresTrue = new Set(["explicit_block", "paranoid_default", "request_override"]);
  const requiresFalse = new Set(["explicit_allow", "mode_default", "legacy_default"]);
  if (requiresTrue.has(source) && blockInternalHosts !== true) {
    throw new Error(`${source} requires block_internal_hosts to be true`);
  }
  if (requiresFalse.has(source) && blockInternalHosts !== false) {
    throw new Error(`${source} requires block_internal_hosts to be false`);
  }
  return {
    checkpoint_mode: normalizeCheckpointMode(policy.checkpoint_mode),
    block_internal_hosts: blockInternalHosts,
    block_internal_hosts_source: source,
  };
}

function normalizeBlockInternalHostsStateFields(document) {
  const checkpointModePresent = document.checkpoint_mode != null;
  const checkpointMode = normalizeCheckpointMode(document.checkpoint_mode);
  const derived = deriveBlockInternalHostsPolicy({
    checkpointMode,
    legacyDefault: !checkpointModePresent,
  });
  const blockInternalHosts = document.block_internal_hosts == null
    ? derived.block_internal_hosts
    : assertBoolean(document.block_internal_hosts, "block_internal_hosts");
  let blockInternalHostsSource = normalizeBlockInternalHostsSource(document.block_internal_hosts_source);
  if (!blockInternalHostsSource) {
    if (document.block_internal_hosts != null && blockInternalHosts === true) {
      blockInternalHostsSource = "explicit_block";
    } else if (document.block_internal_hosts != null && checkpointMode === "paranoid" && blockInternalHosts === false) {
      blockInternalHostsSource = "explicit_allow";
    } else {
      blockInternalHostsSource = derived.block_internal_hosts_source;
    }
  }
  return assertBlockInternalHostsPolicyConsistency({
    checkpoint_mode: checkpointMode,
    block_internal_hosts: blockInternalHosts,
    block_internal_hosts_source: blockInternalHostsSource,
  });
}

function blockInternalHostsPolicyFields(policy) {
  const normalized = assertBlockInternalHostsPolicyConsistency(policy);
  return {
    checkpoint_mode: normalized.checkpoint_mode,
    block_internal_hosts: normalized.block_internal_hosts,
    block_internal_hosts_source: normalized.block_internal_hosts_source,
  };
}

// Cycle D.3 deleted state.terminally_blocked from the session-state
// document. The blocker projection now derives from frontier-events.jsonl
// via frontier-projections.currentBlockers. terminallyBlockedSurfaceIds
// remains a public export because the wave planner consumes the projection
// directly; callers route the projection through this helper for symmetry
// with the legacy shape (a list of surface_ids).
function terminallyBlockedSurfaceIds(state) {
  if (!state || typeof state.target !== "string" || !state.target) return [];
  try {
    const { currentBlockers } = require("../frontier/frontier-projections.js");
    return currentBlockers(state.target).map((entry) => entry.surface_id);
  } catch {
    return [];
  }
}

function buildInitialSessionState(domain, targetUrl, {
  deepMode = false,
  egressProfile = null,
  checkpointMode = "normal",
  blockInternalHosts = null,
  allowInternalHosts = null,
  blockInternalHostsPolicy = null,
  targetRepo = null,
  repoHash = null,
  targetContracts = [],
  chainAuthorityHash = null,
  physicalScope = null,
} = {}) {
  const egressFields = egressProfileStateFields(egressProfile);
  const internalHostPolicy = blockInternalHostsPolicy
    ? blockInternalHostsPolicyFields(blockInternalHostsPolicy)
    : deriveBlockInternalHostsPolicy({
      checkpointMode,
      blockInternalHosts,
      allowInternalHosts,
      legacyDefault: false,
    });
  // Cycle O.1: repo sessions write target_repo + repo_hash; URL sessions
  // leave them null. The mutually-exclusive contract is enforced by the
  // governance scope policy and normalizeSessionStateDocument; this helper
  // is just the document constructor.
  const state = {
    target: domain,
    target_url: targetUrl,
    target_repo: targetRepo,
    repo_hash: repoHash,
    // Smart-contract sessions bind target_contracts (the in-scope contract
    // addresses) plus an optional chain_authority_hash. This axis can stand
    // alone (pure-SC) or companion the url/repo primary axis (O-P6 MIXED
    // program). Web/repo sessions with no contracts leave these at [] / null. An
    // empty target_contracts is NOT the contracts axis, so a url/repo-only
    // session stays single-axis under normalizeSessionStateDocument.
    target_contracts: Array.isArray(targetContracts) ? targetContracts : [],
    chain_authority_hash: chainAuthorityHash == null ? null : chainAuthorityHash,
    deep_mode: deepMode,
    ...internalHostPolicy,
    lifecycle_state: "SETUP",
    phase: deriveLegacyPhaseFromLifecycleState("SETUP"),
    evaluation_wave: 0,
    pending_wave: null,
    total_findings: 0,
    prereq_registry_snapshots: [],
    blocked_prereq_history: [],
    terminal_block_clear_history: [],
    dead_ends: [],
    waf_blocked_endpoints: [],
    scope_exclusions: [],
    hold_count: 0,
    auth_status: "pending",
    ...egressFields,
    egress_profile_identity_bound_at: null,
    egress_profile_identity_bind_source: null,
    egress_profile_legacy_migration: null,
    operator_note: null,
    verification_schema_version: null,
    verification_attempt_id: null,
    verification_snapshot_hash: null,
    verification_entered_at: null,
    // The v1.3.5 handoff_provenance_required flag is retained on disk for
    // round-trip stability and operator visibility, but the runtime no longer
    // branches on it: v1.3.6 removed the legacy_unverified handoff path so
    // signed handoffs are unconditionally required. New sessions still
    // serialize the field as true; legacy sessions roundtrip as-is.
    handoff_provenance_required: true,
  };
  if (physicalScope != null) {
    state.physical_scope = normalizePhysicalScopeNucleusAxis(physicalScope);
  }
  return state;
}

// state.prereq_registry_snapshots stores per-wave registry HANDLE SETS so
// the loop detector can reason about whether the specific material that
// would unblock a surface (e.g., the "attacker" auth profile) was added
// since the surface got stuck — not just whether ANY profile was added.
// Counts collapsed unrelated additions into "growth" and gave irrelevant
// blockers permanent amnesty. Snapshot captured at wave start (before
// evaluators dispatch), not merge time, so the comparison reflects "what
// the evaluator could have used".
function normalizePrereqRegistrySnapshots(value, fieldName = "prereq_registry_snapshots") {
  if (value == null) return [];
  if (!Array.isArray(value)) {
    throw new Error(`${fieldName} must be an array`);
  }
  return value.map((entry, index) => {
    if (entry == null || typeof entry !== "object" || Array.isArray(entry)) {
      throw new Error(`${fieldName}[${index}] must be an object`);
    }
    return {
      wave: assertInteger(entry.wave, `${fieldName}[${index}].wave`, { min: 1 }),
      auth_handles: normalizeStringArray(entry.auth_handles, `${fieldName}[${index}].auth_handles`),
      egress_handles: normalizeStringArray(entry.egress_handles, `${fieldName}[${index}].egress_handles`),
    };
  });
}

// state.terminal_block_clear_history records every operator-driven clear:
// when, why, and what was cleared. Stored in state.json (atomic write)
// rather than relying on the best-effort pipeline event for audit
// durability. The loop detector uses these clear epochs to filter
// blocked_prereq_history so a re-block starts a fresh recurrence count
// without erasing prior debugging data.
function normalizeTerminalBlockClearHistory(value, fieldName = "terminal_block_clear_history") {
  if (value == null) return [];
  if (!Array.isArray(value)) {
    throw new Error(`${fieldName} must be an array`);
  }
  return value.map((entry, index) => {
    if (entry == null || typeof entry !== "object" || Array.isArray(entry)) {
      throw new Error(`${fieldName}[${index}] must be an object`);
    }
    const result = {
      surface_id: assertNonEmptyString(entry.surface_id, `${fieldName}[${index}].surface_id`),
      cleared_at_wave: assertInteger(entry.cleared_at_wave, `${fieldName}[${index}].cleared_at_wave`, { min: 0 }),
      cleared_at_ts: assertNonEmptyString(entry.cleared_at_ts, `${fieldName}[${index}].cleared_at_ts`),
      reason: assertNonEmptyString(entry.reason, `${fieldName}[${index}].reason`),
    };
    if (entry.previously_blocked_at_wave != null) {
      result.previously_blocked_at_wave = assertInteger(
        entry.previously_blocked_at_wave,
        `${fieldName}[${index}].previously_blocked_at_wave`,
        { min: 1 },
      );
    }
    if (Array.isArray(entry.previous_blockers)) {
      result.previous_blockers = entry.previous_blockers.map((blocker, blockerIndex) => {
        if (blocker == null || typeof blocker !== "object" || Array.isArray(blocker)) {
          throw new Error(`${fieldName}[${index}].previous_blockers[${blockerIndex}] must be an object`);
        }
        const blockerResult = {
          kind: assertNonEmptyString(blocker.kind, `${fieldName}[${index}].previous_blockers[${blockerIndex}].kind`),
        };
        if (blocker.identifier_hint != null) {
          blockerResult.identifier_hint = assertNonEmptyString(
            blocker.identifier_hint,
            `${fieldName}[${index}].previous_blockers[${blockerIndex}].identifier_hint`,
          );
        }
        if (blocker.reason != null) {
          blockerResult.reason = assertNonEmptyString(
            blocker.reason,
            `${fieldName}[${index}].previous_blockers[${blockerIndex}].reason`,
          );
        }
        return blockerResult;
      });
    }
    return result;
  });
}

// state.blocked_prereq_history is the merge-validated record of blocker
// tuples per wave per surface. Replaces raw handoff JSON reads in the
// promotion path: handoffs go through schema/runtime validation at write
// time, but reading them again at merge time bypasses that validation.
// Cleared entries are kept; the loop detector uses
// state.terminal_block_clear_history to skip them.
function normalizeBlockedPrereqHistory(value, fieldName = "blocked_prereq_history") {
  if (value == null) return [];
  if (!Array.isArray(value)) {
    throw new Error(`${fieldName} must be an array`);
  }
  return value.map((entry, index) => {
    if (entry == null || typeof entry !== "object" || Array.isArray(entry)) {
      throw new Error(`${fieldName}[${index}] must be an object`);
    }
    const result = {
      wave: assertInteger(entry.wave, `${fieldName}[${index}].wave`, { min: 1 }),
      surface_id: assertNonEmptyString(entry.surface_id, `${fieldName}[${index}].surface_id`),
      kind: assertNonEmptyString(entry.kind, `${fieldName}[${index}].kind`),
    };
    if (entry.identifier_hint != null) {
      result.identifier_hint = assertNonEmptyString(entry.identifier_hint, `${fieldName}[${index}].identifier_hint`);
    }
    if (entry.reason != null) {
      result.reason = assertNonEmptyString(entry.reason, `${fieldName}[${index}].reason`);
    }
    return result;
  });
}

function publicSessionState(state) {
  // Cycle O.1: target_repo and repo_hash are only meaningful for repo
  // sessions; for URL sessions they are null. Omit them from the public
  // projection so the historical URL-session shape stays byte-stable for
  // downstream consumers that deep-equal it. composeSessionStateDocument
  // still merges the raw document, so repo sessions write target_repo
  // through buildInitialSessionState -> writeSessionStateDocument.
  return SESSION_PUBLIC_STATE_FIELDS.reduce((result, field) => {
    const value = state[field];
    if ((field === "target_repo" || field === "repo_hash") && value == null) {
      return result;
    }
    // The smart-contract axis fields are only meaningful for contracts
    // sessions; omit them for url/repo sessions (empty target_contracts, null
    // chain_authority_hash) so the historical public-state shape stays
    // byte-stable for downstream deep-equal consumers.
    if (field === "target_contracts" && Array.isArray(value) && value.length === 0) {
      return result;
    }
    if (field === "chain_authority_hash" && value == null) {
      return result;
    }
    if (field === "physical_scope" && value == null) {
      return result;
    }
    result[field] = value;
    return result;
  }, {});
}

function compactSessionState(state) {
  // explored_count, terminally_blocked_count, and lead_surface_ids derive
  // from the frontier-events.jsonl projection (Cycle F.3 / D.3). Loaded
  // lazily to avoid a cycle with frontier-projections at module-import time.
  let exploredCount = 0;
  let terminallyBlockedCount = 0;
  let leadSurfaceIds = [];
  if (state.target) {
    try {
      const projections = require("../frontier/frontier-projections.js");
      exploredCount = projections.currentClosures(state.target).length;
      terminallyBlockedCount = projections.currentBlockers(state.target).length;
      leadSurfaceIds = projections.currentLeadSurfaceIds(state.target);
    } catch {
      // Projection unavailable (fresh session, malformed events); fall back
      // to zero/empty rather than failing the compact serialization.
    }
  }
  const compact = {
    target: state.target,
    deep_mode: state.deep_mode === true,
    checkpoint_mode: state.checkpoint_mode,
    block_internal_hosts: state.block_internal_hosts === true,
    block_internal_hosts_source: state.block_internal_hosts_source,
    phase: state.phase,
    lifecycle_state: state.lifecycle_state,
    evaluation_wave: state.evaluation_wave,
    pending_wave: state.pending_wave,
    total_findings: state.total_findings,
    explored_count: exploredCount,
    terminally_blocked_count: terminallyBlockedCount,
    dead_ends_count: (state.dead_ends || []).length,
    waf_blocked_count: (state.waf_blocked_endpoints || []).length,
    lead_surface_ids: leadSurfaceIds,
    hold_count: state.hold_count,
    auth_status: state.auth_status,
    egress_profile: state.egress_profile,
    egress_region: state.egress_region,
    proxy_configured: state.proxy_configured,
    egress_profile_identity_hash: state.egress_profile_identity_hash,
    egress_profile_identity_version: state.egress_profile_identity_version,
    egress_profile_identity_source: state.egress_profile_identity_source,
    egress_profile_identity_bound_at: state.egress_profile_identity_bound_at,
    egress_profile_identity_bind_source: state.egress_profile_identity_bind_source,
    egress_profile_legacy_migration: state.egress_profile_legacy_migration,
    operator_note: state.operator_note,
    verification_schema_version: state.verification_schema_version,
    verification_attempt_id: state.verification_attempt_id,
    verification_snapshot_hash: state.verification_snapshot_hash,
    verification_entered_at: state.verification_entered_at,
    handoff_provenance_required: state.handoff_provenance_required === true,
  };
  if (state.physical_scope != null) {
    compact.physical_scope = normalizePhysicalScopeNucleusAxis(state.physical_scope);
  }
  return compact;
}

function normalizeSessionStateDocument(document, requestedDomain) {
  if (document == null || typeof document !== "object" || Array.isArray(document)) {
    throw new Error("expected object");
  }

  if (document.target != null) {
    assertNonEmptyString(document.target, "target");
  }

  // Cycle D.1 dual-write window: a session may carry lifecycle_state, the
  // legacy phase, or both on disk. The canonical authority is the lifecycle
  // state; the legacy phase is a derived back-compat read for callers that
  // have not yet migrated. Accept either, then synthesize whichever side is
  // missing so consumers always see both fields.
  let resolvedLifecycleState = null;
  if (document.lifecycle_state != null) {
    resolvedLifecycleState = assertEnumValue(
      document.lifecycle_state,
      SESSION_STATE_LIFECYCLE_VALUES,
      "lifecycle_state",
    );
  } else if (typeof document.phase === "string") {
    resolvedLifecycleState = deriveLifecycleStateFromLegacyPhase(document.phase);
    if (!resolvedLifecycleState) {
      throw new Error(`phase must be one of ${Object.keys(LEGACY_PHASE_TO_LIFECYCLE_STATE).join(", ")} (legacy fallback); got ${JSON.stringify(document.phase)}`);
    }
  } else {
    throw new Error("lifecycle_state (or legacy phase) is required");
  }
  const resolvedLegacyPhase = typeof document.phase === "string"
    ? document.phase
    : deriveLegacyPhaseFromLifecycleState(resolvedLifecycleState);

  // Cycle O.1: repo sessions persist target_repo instead of target_url.
  // We intentionally validate target_repo SHAPE only here — realpath /
  // directory checks happen at session bootstrap (initRepoSession) and
  // would force this module to depend on fs / governance-contracts,
  // breaking the no-cycle, no-fs contract documented for session-state-
  // contracts.
  //
  // Multi-axis (O-P6 MIXED program) axis rule:
  //   * at least one axis must be present (axisCount >= 1);
  //   * target_url and target_repo are the MUTUALLY EXCLUSIVE primary axes —
  //     carrying both is the only multi-axis error (url+repo and
  //     url+repo+contracts both throw);
  //   * target_contracts MAY companion url OR repo, or stand alone (pure-SC).
  // So url-alone, repo-alone, contracts-alone, url+contracts (mixed web+SC), and
  // repo+contracts (mixed repo+SC) are all valid. An EMPTY target_contracts ([])
  // is NOT the contracts axis — web and repo sessions persist [] (and the public
  // projection omits it), so only a non-empty array counts as a contracts
  // binding here. target_url / target_repo normalization below is byte-identical
  // to the non-mixed cases (the companion contracts ride orthogonally).
  const hasUrlField = document.target_url != null;
  const hasRepoField = document.target_repo != null;
  const hasContractsField = Array.isArray(document.target_contracts)
    && document.target_contracts.length > 0;
  const hasPhysicalField = document.physical_scope != null;
  const axisCount = (hasUrlField ? 1 : 0)
    + (hasRepoField ? 1 : 0)
    + (hasContractsField ? 1 : 0)
    + (hasPhysicalField ? 1 : 0);
  if (axisCount === 0) {
    throw new Error("session state requires at least one of target_url, target_repo, target_contracts, or physical_scope");
  }
  if (hasUrlField && hasRepoField) {
    throw new Error("session state must not carry both target_url and target_repo (mutually exclusive primary axes)");
  }
  let normalizedTargetUrl = null;
  let normalizedTargetRepo = null;
  let normalizedRepoHash = null;
  if (hasUrlField) {
    normalizedTargetUrl = assertNonEmptyString(document.target_url, "target_url");
  } else if (hasRepoField) {
    normalizedTargetRepo = normalizeTargetRepoShape(document.target_repo);
    if (typeof document.repo_hash !== "string" || !/^[0-9a-f]{8,64}$/i.test(document.repo_hash)) {
      throw new Error("repo_hash is required (8-64 hex characters) for repo sessions");
    }
    normalizedRepoHash = document.repo_hash.toLowerCase();
  }
  // The contracts axis carries no url/repo binding; its address list is
  // normalized into the document below via normalizeStringArray.

  const normalized = {
    target: requestedDomain,
    target_url: normalizedTargetUrl,
    target_repo: normalizedTargetRepo,
    repo_hash: normalizedRepoHash,
    // Round-trip the smart-contract axis fields. normalizeStringArray defaults
    // to [] and normalizeOptionalText to null, so web/repo sessions (which never
    // wrote these) reload with the byte-stable empty defaults.
    target_contracts: normalizeStringArray(document.target_contracts, "target_contracts"),
    chain_authority_hash: normalizeOptionalText(document.chain_authority_hash, "chain_authority_hash"),
    deep_mode: document.deep_mode == null
      ? false
      : assertBoolean(document.deep_mode, "deep_mode"),
    ...normalizeBlockInternalHostsStateFields(document),
    lifecycle_state: resolvedLifecycleState,
    phase: resolvedLegacyPhase,
    evaluation_wave: document.evaluation_wave == null
      ? 0
      : assertInteger(document.evaluation_wave, "evaluation_wave", { min: 0 }),
    pending_wave: document.pending_wave == null
      ? null
      : assertInteger(document.pending_wave, "pending_wave", { min: 1 }),
    total_findings: document.total_findings == null
      ? 0
      : assertInteger(document.total_findings, "total_findings", { min: 0 }),
    // Cycle D.3 deleted state.explored / state.terminally_blocked /
    // state.lead_surface_ids from the contract. Legacy sessions on disk may
    // still carry these arrays; readers silently drop them and let the
    // frontier-events.jsonl projection (frontier-projections) be the sole
    // surface-state source. The fields are intentionally absent from the
    // normalized result so consumers cannot accidentally route through
    // stale state.json arrays.
    prereq_registry_snapshots: normalizePrereqRegistrySnapshots(document.prereq_registry_snapshots, "prereq_registry_snapshots"),
    blocked_prereq_history: normalizeBlockedPrereqHistory(document.blocked_prereq_history, "blocked_prereq_history"),
    terminal_block_clear_history: normalizeTerminalBlockClearHistory(document.terminal_block_clear_history, "terminal_block_clear_history"),
    dead_ends: normalizeStringArray(document.dead_ends, "dead_ends"),
    waf_blocked_endpoints: normalizeStringArray(document.waf_blocked_endpoints, "waf_blocked_endpoints"),
    scope_exclusions: normalizeStringArray(document.scope_exclusions, "scope_exclusions"),
    hold_count: document.hold_count == null
      ? 0
      : assertInteger(document.hold_count, "hold_count", { min: 0 }),
    auth_status: document.auth_status == null
      ? "pending"
      : assertEnumValue(document.auth_status, AUTH_STATUS_VALUES, "auth_status"),
    egress_profile: document.egress_profile == null
      ? "default"
      : assertNonEmptyString(document.egress_profile, "egress_profile"),
    egress_region: normalizeOptionalText(document.egress_region, "egress_region"),
    proxy_configured: document.proxy_configured == null
      ? false
      : assertBoolean(document.proxy_configured, "proxy_configured"),
    egress_profile_identity_hash: normalizeOptionalText(
      document.egress_profile_identity_hash,
      "egress_profile_identity_hash",
    ),
    egress_profile_identity_version: document.egress_profile_identity_version == null
      ? null
      : assertInteger(document.egress_profile_identity_version, "egress_profile_identity_version", { min: 1 }),
    egress_profile_identity_source: normalizeEgressIdentitySource(
      document.egress_profile_identity_source,
      "egress_profile_identity_source",
    ),
    egress_profile_identity_bound_at: normalizeOptionalText(
      document.egress_profile_identity_bound_at,
      "egress_profile_identity_bound_at",
    ),
    egress_profile_identity_bind_source: normalizeOptionalText(
      document.egress_profile_identity_bind_source,
      "egress_profile_identity_bind_source",
    ),
    egress_profile_legacy_migration: normalizeEgressLegacyMigration(
      document.egress_profile_legacy_migration,
      "egress_profile_legacy_migration",
    ),
    operator_note: normalizeOperatorNote(document.operator_note, "operator_note"),
    verification_schema_version: document.verification_schema_version == null
      ? null
      : assertInteger(document.verification_schema_version, "verification_schema_version", { min: 1, max: 2 }),
    verification_attempt_id: normalizeOptionalText(document.verification_attempt_id, "verification_attempt_id"),
    verification_snapshot_hash: normalizeOptionalText(document.verification_snapshot_hash, "verification_snapshot_hash"),
    verification_entered_at: normalizeOptionalText(document.verification_entered_at, "verification_entered_at"),
    // Provenance enforcement opt-in (v1.3.5+). Missing field = legacy session,
    // defaulted to false to preserve compat with pre-v1.3.5 fixtures and any
    // in-flight sessions. New sessions set this to true in buildInitialSessionState.
    handoff_provenance_required: document.handoff_provenance_required == null
      ? false
      : assertBoolean(document.handoff_provenance_required, "handoff_provenance_required"),
  };
  if (hasPhysicalField) {
    normalized.physical_scope = normalizePhysicalScopeNucleusAxis(document.physical_scope);
  }

  // Cycle D.3 removed state.explored and state.terminally_blocked from the
  // contract; the disjointness invariant was lifted because the frontier
  // ledger projection (foldLatestBySurface across closure / blocker events)
  // is self-disjoint by construction — the latest surface-state event wins.

  return normalized;
}

function composeSessionStateDocument(rawDocument, state) {
  return {
    ...rawDocument,
    ...publicSessionState(state),
  };
}

module.exports = {
  assertOperatorNote,
  blockInternalHostsPolicyFields,
  buildInitialSessionState,
  compactSessionState,
  composeSessionStateDocument,
  deriveBlockInternalHostsPolicy,
  deriveLegacyPhaseFromLifecycleState,
  deriveLifecycleStateFromLegacyPhase,
  egressProfileStateFields,
  LIFECYCLE_STATE_TO_LEGACY_PHASE,
  normalizeSessionStateDocument,
  normalizeTargetRepoShape,
  publicSessionState,
  terminallyBlockedSurfaceIds,
};
