"use strict";

const fs = require("fs");
const {
  assertBoolean,
  assertNonEmptyString,
} = require("../io/validation.js");
const {
  AUTH_STATUS_VALUES,
} = require("./session-state-vocabulary.js");
const {
  sessionDir,
  statePath,
  surfaceIndexPath,
  taskQueuePath,
} = require("../io/paths.js");
const {
  isSessionDirEffectivelyEmpty,
  readJsonFile,
  withSessionLock,
} = require("../io/storage.js");
const {
  ERROR_CODES,
  ToolError,
} = require("../io/envelope.js");
const {
  resolveEgressProfile,
} = require("../egress-profiles.js");
const {
  hasUsableAuthProfile,
} = require("../auth/index.js");
const {
  buildSessionNucleus,
  LIFECYCLE_STATE_VALUES,
  normalizeLifecycleState,
  normalizeOperatorConstraint,
  readVerifiedSessionNucleus,
  sessionNucleusFromState,
} = require("../governance/index.js");
const {
  commitSessionAuthority,
} = require("./session-authority-unit-of-work.js");
const {
  appendClosureRecordedEvent,
  appendFrontierEvent,
} = require("../frontier/frontier-events.js");
const {
  scheduleMaterialization,
} = require("../frontier/frontier-materialize-debounce.js");
const {
  evaluateLifecycleTransition,
} = require("./lifecycle-gates.js");
const {
  hashCanonicalJson,
} = require("../verification/verification-contracts.js");
const {
  safeAppendPipelineEventDirect,
} = require("../telemetry/pipeline-events.js");
const { ensureHandoffSigningKey, ensureHandoffKeypair } = require("../ledger-integrity/index.js");
const {
  recordSandboxIsolationAttestation,
} = require("../ledger-integrity/index.js");
const {
  buildGovernanceContext,
  buildGovernanceContextFromNucleus,
} = require("../governance/index.js");
const {
  assertHttpScopeDomain,
  validateHttpScanScope,
} = require("../scope.js");
const {
  parseLabAuthorization,
  labBootstrapPolicyViolation,
  recordLabAuthorization,
} = require("../lab-target-attest.js");
const {
  assertOperatorNote,
  blockInternalHostsPolicyFields,
  buildInitialSessionState,
  compactSessionState,
  deriveBlockInternalHostsPolicy,
  deriveLegacyPhaseFromLifecycleState,
  egressProfileStateFields,
  publicSessionState,
} = require("./session-state-contracts.js");
const {
  readSessionStateStrict,
  sessionStateMissing,
  writeSessionStateDocument,
} = require("./session-state-store.js");

function assertBlockInternalHostsCompatibleWithEgress(policy, profile) {
  if (!policy || policy.block_internal_hosts !== true || !profile || profile.proxy_configured !== true) {
    return;
  }
  const identityFields = egressProfileStateFields(profile);
  throw new ToolError(
    ERROR_CODES.SCOPE_BLOCKED,
    `block_internal_hosts cannot be enforced with proxy-backed egress_profile "${profile.name}" because target DNS and routing may be resolved outside Bob. Use egress_profile "default" or allow_internal_hosts for authorized internal/lab programs.`,
    {
      ...identityFields,
      ...blockInternalHostsPolicyFields(policy),
    },
  );
}

function assertSessionEgressIdentity(domain, profile, { source = "egress_request", authorityContext = null } = {}) {
  const identityFields = egressProfileStateFields(profile);

  // Fast, lock-free, zero-read path: a frozen per-call session-authority context (see
  // session-authority-context.js) already carries a verified, already-bound
  // egress_identity for this exact domain. When it exact-matches the requested
  // profile, this is the identical "already bound" branch the locked path below
  // returns after its own nucleus read -- consume the frozen value instead of
  // performing a second, independently-timed verified read within the same call.
  // Any mismatch (unbound, drifted, or a different domain) falls through unchanged to
  // the locked path, which re-verifies fresh and is the sole authority for a WRITE.
  if (
    authorityContext
    && authorityContext.target_domain === domain
    && authorityContext.egress_identity
    && authorityContext.egress_identity.egress_profile_identity_hash
    && authorityContext.egress_identity.egress_profile_identity_hash === identityFields.egress_profile_identity_hash
    && authorityContext.egress_identity.egress_profile_identity_version === identityFields.egress_profile_identity_version
  ) {
    return {
      ...identityFields,
      session_state_present: true,
      session_identity_bound: false,
    };
  }

  return withSessionLock(domain, () => {
    // Egress binding is grant-adjacent, so the prior nucleus must be
    // verified first -- never a silent direct write against an unverifiable
    // or missing session-nucleus.json. A legacy state-only session (no
    // verifiable nucleus) is denied here rather than migrated inline;
    // migration remains A7/A6L's exclusive path (bob_advance_session).
    let priorNucleus;
    try {
      priorNucleus = readVerifiedSessionNucleus(domain);
    } catch (error) {
      throw new ToolError(
        ERROR_CODES.STATE_CONFLICT,
        `session nucleus missing or unverifiable for ${domain}; call bob_init_session first (${error.message || String(error)})`,
        {
          target_domain: domain,
          requested: {
            egress_profile: identityFields.egress_profile,
            egress_region: identityFields.egress_region,
            proxy_configured: identityFields.proxy_configured,
            egress_profile_identity_hash: identityFields.egress_profile_identity_hash,
            egress_profile_identity_version: identityFields.egress_profile_identity_version,
          },
        },
      );
    }

    const priorEgress = (priorNucleus.egress_identity && typeof priorNucleus.egress_identity === "object")
      ? priorNucleus.egress_identity
      : {};

    if (priorEgress.egress_profile_identity_hash) {
      if (
        priorEgress.egress_profile_identity_hash !== identityFields.egress_profile_identity_hash ||
        priorEgress.egress_profile_identity_version !== identityFields.egress_profile_identity_version
      ) {
        throw new ToolError(
          ERROR_CODES.STATE_CONFLICT,
          `egress profile drift for ${domain}: session is bound to ${priorEgress.egress_profile} (${priorEgress.egress_profile_identity_hash}); requested ${identityFields.egress_profile} (${identityFields.egress_profile_identity_hash})`,
          {
            target_domain: domain,
            expected: {
              egress_profile: priorEgress.egress_profile,
              egress_region: priorEgress.egress_region,
              proxy_configured: priorEgress.proxy_configured,
              egress_profile_identity_hash: priorEgress.egress_profile_identity_hash,
              egress_profile_identity_version: priorEgress.egress_profile_identity_version,
            },
            requested: identityFields,
          },
        );
      }
      // Matching, already-bound identity: verified read-only, zero writes.
      // priorNucleus alone does not tell us whether state.json exists (a
      // nucleus-only session never acquires one), so presence is checked
      // directly rather than assumed, consistent with the first-bind branch
      // below deriving it from an actual state read.
      return {
        ...identityFields,
        session_state_present: fs.existsSync(statePath(domain)),
        session_identity_bound: false,
      };
    }

    // First bind / legacy migration. Optional state read: a nucleus-only
    // session (no state.json) is never forced to acquire one as a side
    // effect of binding -- stateProjection stays null in that case.
    let raw = {};
    let state = null;
    try {
      ({ raw, state } = readSessionStateStrict(domain));
    } catch (error) {
      if (!sessionStateMissing(error)) throw error;
    }

    const migratedAt = new Date().toISOString();
    let nextNucleus;
    let stateProjection;
    if (state === null) {
      // Nucleus-only session: no state.json to reconcile against, so the
      // next nucleus is derived from the verified prior nucleus directly.
      nextNucleus = buildSessionNucleus({
        target_domain: priorNucleus.target_domain,
        target_url: priorNucleus.scope_policy && priorNucleus.scope_policy.target_url,
        scope_policy: priorNucleus.scope_policy,
        egress_identity: {
          egress_profile: identityFields.egress_profile,
          egress_region: identityFields.egress_region,
          proxy_configured: identityFields.proxy_configured,
          egress_profile_identity_hash: identityFields.egress_profile_identity_hash,
          egress_profile_identity_version: identityFields.egress_profile_identity_version,
          egress_profile_identity_source: identityFields.egress_profile_identity_source,
        },
        auth_context: priorNucleus.auth_context,
        operator_constraint: priorNucleus.operator_constraint,
        lifecycle_state: priorNucleus.lifecycle_state,
        physical_scope: priorNucleus.physical_scope,
        repo_hash: priorNucleus.repo_hash,
      });
      stateProjection = null;
    } else {
      const nextState = {
        ...state,
        ...identityFields,
        egress_profile_identity_bound_at: migratedAt,
        egress_profile_identity_bind_source: "legacy_migration",
        egress_profile_legacy_migration: {
          migrated_at: migratedAt,
          source,
          previous_unbound: true,
          previous: {
            egress_profile: state.egress_profile,
            egress_region: state.egress_region,
            proxy_configured: state.proxy_configured,
            egress_profile_identity_hash: state.egress_profile_identity_hash,
            egress_profile_identity_version: state.egress_profile_identity_version,
          },
        },
      };
      // A state-backed migration derives the canonical nucleus FROM the
      // reconciled state (the same convention initSession and
      // migrateLegacySessionAuthority use), so nucleus/state parity is
      // proven by construction rather than by independently rebuilding the
      // nucleus from priorNucleus fields that may have drifted from a
      // legacy state.json's own defaults (e.g. handoff_provenance_required).
      nextNucleus = sessionNucleusFromState(nextState, {
        physical_scope: priorNucleus.physical_scope,
        repo_hash: priorNucleus.repo_hash,
      });
      stateProjection = { rawDocument: raw, nextState };
    }

    commitSessionAuthority({
      targetDomain: domain,
      nextNucleus,
      stateProjection,
      event: {
        target_domain: domain,
        kind: "governance.egress_identity.bound",
        nucleus_hash: nextNucleus.nucleus_hash,
        payload: {
          prior_nucleus_hash: priorNucleus.nucleus_hash,
          nucleus_hash: nextNucleus.nucleus_hash,
          egress_profile_identity_hash: identityFields.egress_profile_identity_hash,
          egress_profile_identity_version: identityFields.egress_profile_identity_version,
          source,
          legacy_migration: true,
          ...identityFields,
        },
      },
      expectedNucleusHash: priorNucleus.nucleus_hash,
    });

    // Postcommit best-effort telemetry mirror, built from the committed
    // nucleus (never proxy secrets) -- cannot alter or gate the outcome of
    // the durable CAS commit above.
    try {
      safeAppendPipelineEventDirect(domain, "egress_identity_bound", {
        lifecycle_state: nextNucleus.lifecycle_state,
        status: "bound",
        source,
        legacy_migration: true,
        ...identityFields,
      }, buildGovernanceContextFromNucleus(nextNucleus));
    } catch {
      // Telemetry is best-effort only; the bind already committed durably.
    }

    return {
      ...identityFields,
      session_state_present: state !== null,
      session_identity_bound: true,
    };
  });
}

function resolveAndAssertSessionEgressIdentity(domain, requestedProfile = "default", options = {}) {
  const profile = resolveEgressProfile(requestedProfile, options);
  const identity = assertSessionEgressIdentity(domain, profile, {
    source: options.source || "egress_request",
    authorityContext: options.authorityContext || null,
  });
  return { profile, identity };
}

function initSession(args, { contractCompanion = null } = {}) {
  // Operator-attested lab/private-target authorization (OFF by default,
  // fail-closed). When present, a loopback/RFC1918 target_domain that the
  // public-DNS gate would reject is permitted for this session only.
  const labAuthorization = parseLabAuthorization(args.lab_authorization);
  // Both lab POLICY constraints (no block_internal_hosts, default egress only) are enforced through
  // the shared validator so this handler and the pre-handler authority gate (session-authority.js)
  // stay in lockstep — a gate "allowed" must never become a handler reject.
  const labPolicyViolation = labBootstrapPolicyViolation(args, labAuthorization);
  if (labPolicyViolation) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, labPolicyViolation.message);
  }
  let domain;
  try {
    domain = assertHttpScopeDomain(args.target_domain, { labAuthorization });
  } catch (error) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, error.message || String(error));
  }
  const targetUrl = assertNonEmptyString(args.target_url, "target_url");
  try {
    validateHttpScanScope(targetUrl, domain, { labAuthorization });
  } catch (error) {
    throw new ToolError(ERROR_CODES.SCOPE_BLOCKED, error.message || String(error), error.details);
  }
  const deepMode = args.deep_mode == null ? false : assertBoolean(args.deep_mode, "deep_mode");
  let internalHostPolicy;
  try {
    internalHostPolicy = deriveBlockInternalHostsPolicy({
      checkpointMode: args.checkpoint_mode,
      blockInternalHosts: args.block_internal_hosts,
      // A lab attestation implies internal-host egress is allowed for the
      // attested private target; layer-2 (isBlockedInternalHost) must not
      // re-block what the operator explicitly authorized.
      allowInternalHosts: labAuthorization ? true : args.allow_internal_hosts,
      legacyDefault: false,
    });
  } catch (error) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, error.message || String(error));
  }
  const requestedEgressProfile = args.egress_profile == null
    ? "default"
    : assertNonEmptyString(args.egress_profile, "egress_profile");
  // (The lab_authorization + non-default-egress rejection — why a proxy-backed egress would scan the
  // attested private target from the proxy's network rather than the operator's lab — is enforced at
  // the top via labBootstrapPolicyViolation, the same validator the authority gate uses.)

  return withSessionLock(domain, () => {
    const dir = sessionDir(domain);
    const filePath = statePath(domain);

    if (fs.existsSync(filePath)) {
      // Public web-only re-initialization retains its historical conflict.
      // The private companion path alone may resume, and only when both durable
      // authority projections already carry this exact web+chain binding.
      if (!contractCompanion) {
        throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Session already initialized: ${filePath}`);
      }
      let state;
      let verified;
      try {
        state = readSessionStateStrict(domain).state;
        verified = readVerifiedSessionNucleus(domain);
      } catch (error) {
        throw new ToolError(
          ERROR_CODES.STATE_CONFLICT,
          `Session resume failed: ${error.message || String(error)}`,
        );
      }
      const projected = sessionNucleusFromState(state);
      if (state.target_url !== targetUrl
          || state.chain_authority_hash !== contractCompanion.chain_authority_hash
          || verified.scope_policy.chain_authority_hash !== contractCompanion.chain_authority_hash
          || projected.nucleus_hash !== verified.nucleus_hash) {
        throw new ToolError(
          ERROR_CODES.STATE_CONFLICT,
          `Session already initialized for a different web or contracts authority: ${filePath}`,
        );
      }
      return JSON.stringify({
        version: 1,
        created: false,
        session_dir: dir,
        state: publicSessionState(state),
      });
    }
    if (!isSessionDirEffectivelyEmpty(dir)) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Session directory is not empty: ${dir}`);
    }

    const egressProfile = resolveEgressProfile(requestedEgressProfile);
    assertBlockInternalHostsCompatibleWithEgress(internalHostPolicy, egressProfile);
    const egressFields = egressProfileStateFields(egressProfile);
    // Construct the compatibility state first, then derive the canonical
    // SessionNucleus from that exact projection. A mixed companion is therefore
    // part of the original create-CAS authority, never a later state-only bind.
    const state = buildInitialSessionState(domain, targetUrl, {
      deepMode,
      egressProfile,
      blockInternalHostsPolicy: internalHostPolicy,
      targetContracts: contractCompanion ? contractCompanion.target_contracts : [],
      chainAuthorityHash: contractCompanion ? contractCompanion.chain_authority_hash : null,
    });
    const sessionNucleus = sessionNucleusFromState(state);
    commitSessionAuthority({
      targetDomain: domain,
      nextNucleus: sessionNucleus,
      stateProjection: {
        rawDocument: {},
        nextState: state,
      },
      event: {
        target_domain: domain,
        kind: "governance.session.initialized",
        nucleus_hash: sessionNucleus.nucleus_hash,
        payload: {
          nucleus_hash: sessionNucleus.nucleus_hash,
          scope_policy_hash: hashCanonicalJson(sessionNucleus.scope_policy),
          egress_identity_hash: hashCanonicalJson(sessionNucleus.egress_identity),
          auth_context_hash: hashCanonicalJson(sessionNucleus.auth_context),
          operator_constraint_hash: hashCanonicalJson(sessionNucleus.operator_constraint),
          ...(contractCompanion
            ? { chain_authority_hash: contractCompanion.chain_authority_hash }
            : {}),
        },
      },
      expectedNucleusHash: null,
    });
    // Persist the operator attestation as an audit-graded session artifact, so
    // the scope kernel can read it on later scoped calls and an agent cannot
    // forge it via the Write tool. No-op when no attestation was supplied.
    if (labAuthorization) {
      recordLabAuthorization(domain, labAuthorization);
    }
    // Provision the handoff signing key at session creation so every later path
    // (wave assignment, handoff validation, the SubagentStop attestation hook)
    // finds it. Idempotent: creates it exclusively-atomically if absent, reads
    // it otherwise. Wave assignment still ensures it lazily as a safety net.
    ensureHandoffSigningKey(domain);
    // Provision the ed25519 keypair alongside the symmetric key (same lock). New
    // offensive rows sign with the private key; verifiers hold only the public key.
    // The private key is still 0600 at the agent uid (no custody close) — the split
    // is the structural prerequisite, not the close.
    ensureHandoffKeypair(domain);
    // Record, audit-graded, whether the agent uid is OS-excluded from the
    // signer's key (Mechanism A). Runs AFTER ensureHandoffSigningKey because the
    // probe lstats the key file itself (the inverse ordering from
    // recordLabAuthorization, which records before the key exists). INERT:
    // nothing reads this to gate a verdict; on the same-uid box it honestly
    // records attested:false.
    const sandboxIsolation = recordSandboxIsolationAttestation(domain);
    safeAppendPipelineEventDirect(domain, "session_started", {
      lifecycle_state: state.lifecycle_state,
      source: "bob_init_session",
      deep_mode: state.deep_mode,
      checkpoint_mode: state.checkpoint_mode,
      block_internal_hosts: state.block_internal_hosts,
      block_internal_hosts_source: state.block_internal_hosts_source,
      // Audit trail: record whether this session was operator-authorized to
      // scope a private (loopback/RFC1918) target past the public-DNS gate.
      lab_authorized: labAuthorization ? true : false,
      // Audit trail: record whether the server's signing key is isolated from
      // the agent uid. Forensic only — no path gates on it (false on the
      // same-uid dev box).
      sandbox_isolation_attested: sandboxIsolation.attested,
      ...egressFields,
    }, buildGovernanceContextFromNucleus(sessionNucleus));

    // Frontier ledger: capture the same seeds that flow into attack_surface.json
    // (target_domain, target_url, scope-policy notes) as a session.seeded event
    // so the frontier projection can replay the bootstrap.
    try {
      appendFrontierEvent({
        target_domain: domain,
        kind: "session.seeded",
        payload: {
          seed_surface_map: {
            target_domain: domain,
            target_url: targetUrl,
            in_scope: [{ target_domain: domain, target_url: targetUrl }],
            out_of_scope: [],
            notes: {
              deep_mode: state.deep_mode,
              checkpoint_mode: state.checkpoint_mode,
              block_internal_hosts: state.block_internal_hosts,
              block_internal_hosts_source: state.block_internal_hosts_source,
            },
          },
          nucleus_hash: sessionNucleus.nucleus_hash,
        },
        source: { artifact: "session-nucleus.json", tool: "bob_init_session" },
      });
      scheduleMaterialization(domain);
    } catch {
      // Frontier ledger is dual-write best-effort during the deprecation window.
    }

    return JSON.stringify({
      version: 1,
      created: true,
      session_dir: dir,
      state: publicSessionState(state),
    });
  });
}

function readFrontierViewHashes(domain) {
  // Read materialized view hashes from disk. Returns null when either view is
  // missing (typical for sessions whose first producer hasn't yet flushed) so
  // callers can surface the absence without conflating it with a hash mismatch.
  const surfacePath = surfaceIndexPath(domain);
  const queuePath = taskQueuePath(domain);
  if (!fs.existsSync(surfacePath) || !fs.existsSync(queuePath)) {
    return null;
  }
  try {
    const surfaceIndex = readJsonFile(surfacePath, { label: "surface-index.json" });
    const taskQueue = readJsonFile(queuePath, { label: "task-queue.json" });
    return {
      surface_index_hash: surfaceIndex && typeof surfaceIndex.surface_index_hash === "string"
        ? surfaceIndex.surface_index_hash
        : null,
      task_queue_hash: taskQueue && typeof taskQueue.task_queue_hash === "string"
        ? taskQueue.task_queue_hash
        : null,
    };
  } catch {
    // Best-effort: a malformed view should not break the session-state read.
    return null;
  }
}

// Descriptor-pins state once through the canonical state parser
// (readSessionStateStrict) and separately probes nucleus verification through
// the verified-only accessor; it never reopens state.json a second time to
// derive a fallback nucleus (that legacy projection belongs solely to
// bob_read_session_nucleus / readSessionNucleusProjection).
function sessionNucleusIsVerified(domain) {
  try {
    readVerifiedSessionNucleus(domain);
    return true;
  } catch {
    return false;
  }
}

function readSessionState(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const { state } = readSessionStateStrict(domain);
  return JSON.stringify({
    version: 1,
    state: publicSessionState(state),
    frontier_view_hashes: readFrontierViewHashes(domain),
    verified: sessionNucleusIsVerified(domain),
  });
}

function readStateSummary(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const { state } = readSessionStateStrict(domain);
  return JSON.stringify({
    version: 1,
    state: compactSessionState(state),
    frontier_view_hashes: readFrontierViewHashes(domain),
    verified: sessionNucleusIsVerified(domain),
  });
}

function applyOperatorConstraintUpdate(domain, transform) {
  return withSessionLock(domain, () => {
    // Operator-constraint updates are grant-adjacent (they rewrite governance
    // authority), so the prior nucleus must be verified — never a silent
    // fallback to an unverifiable or missing session-nucleus.json. A legacy
    // state-only session (no verifiable nucleus) is denied here rather than
    // migrated inline; migration remains A7/A6L's exclusive path.
    let priorNucleus;
    try {
      priorNucleus = readVerifiedSessionNucleus(domain);
    } catch (error) {
      throw new ToolError(
        ERROR_CODES.STATE_CONFLICT,
        `session nucleus missing or unverifiable for ${domain}; call bob_init_session first (${error.message || String(error)})`,
      );
    }
    const priorConstraint = (priorNucleus.operator_constraint && typeof priorNucleus.operator_constraint === "object")
      ? priorNucleus.operator_constraint
      : {};
    const nextConstraintInput = transform({ ...priorConstraint });
    const operatorConstraint = normalizeOperatorConstraint(nextConstraintInput);

    // Optional state read: a nucleus-only session (no state.json) is never
    // forced to acquire one as a side effect of an operator-note set/clear.
    let raw = {};
    let state = null;
    try {
      ({ raw, state } = readSessionStateStrict(domain));
    } catch (error) {
      if (!sessionStateMissing(error)) throw error;
    }

    let nextNucleus;
    let stateProjection;
    if (state === null) {
      nextNucleus = buildSessionNucleus({
        target_domain: priorNucleus.target_domain,
        target_url: priorNucleus.scope_policy && priorNucleus.scope_policy.target_url,
        scope_policy: priorNucleus.scope_policy,
        egress_identity: priorNucleus.egress_identity,
        auth_context: priorNucleus.auth_context,
        operator_constraint: operatorConstraint,
        lifecycle_state: priorNucleus.lifecycle_state,
        physical_scope: priorNucleus.physical_scope,
        // Preserve the repo session's pinned repo_hash across nucleus rewrites; it is
        // the O-D6 docker image-tag binding and dropping it makes bob_repo_docker_run
        // crash (readRepoSession -> null repo_hash -> buildImageTag null.slice).
        repo_hash: priorNucleus.repo_hash,
      });
      stateProjection = null;
    } else {
      // A state-backed update derives the canonical nucleus FROM the
      // reconciled state (the same convention assertSessionEgressIdentity,
      // initSession and migrateLegacySessionAuthority all use), so
      // nucleus/state parity is proven by construction instead of
      // independently rebuilding the nucleus from priorNucleus fields that
      // may have drifted from a legacy state.json's own field defaults.
      const nextState = {
        ...state,
        operator_note: operatorConstraint.operator_note == null ? null : operatorConstraint.operator_note,
        handoff_provenance_required: operatorConstraint.handoff_provenance_required,
      };
      nextNucleus = sessionNucleusFromState(nextState, {
        physical_scope: priorNucleus.physical_scope,
        repo_hash: priorNucleus.repo_hash,
      });
      stateProjection = { rawDocument: raw, nextState };
    }

    const commitResult = commitSessionAuthority({
      targetDomain: domain,
      nextNucleus,
      stateProjection,
      event: {
        target_domain: domain,
        kind: "governance.operator_constraint.updated",
        nucleus_hash: nextNucleus.nucleus_hash,
        payload: {
          prior_nucleus_hash: priorNucleus.nucleus_hash,
          nucleus_hash: nextNucleus.nucleus_hash,
          operator_constraint_hash: hashCanonicalJson(nextNucleus.operator_constraint),
        },
      },
      expectedNucleusHash: priorNucleus.nucleus_hash,
    });

    return {
      priorNucleus,
      nextNucleus,
      operatorConstraint,
      eventId: commitResult.event_id,
      nextState: stateProjection ? stateProjection.nextState : null,
    };
  });
}

function setOperatorNote(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const operatorNote = assertOperatorNote(args.operator_note, "operator_note");

  return withSessionLock(domain, () => {
    const { nextNucleus, operatorConstraint, eventId, nextState } = applyOperatorConstraintUpdate(
      domain,
      (prior) => ({ ...prior, operator_note: operatorNote }),
    );
    return JSON.stringify({
      version: 1,
      updated: true,
      operator_note: operatorNote,
      nucleus_hash: nextNucleus.nucleus_hash,
      operator_constraint: operatorConstraint,
      event_id: eventId,
      state: nextState === null ? null : compactSessionState(nextState),
    });
  });
}

function clearOperatorNote(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");

  return withSessionLock(domain, () => {
    const { nextNucleus, operatorConstraint, eventId, nextState } = applyOperatorConstraintUpdate(
      domain,
      (prior) => {
        const next = { ...prior };
        delete next.operator_note;
        return next;
      },
    );
    return JSON.stringify({
      version: 1,
      cleared: true,
      operator_note: null,
      nucleus_hash: nextNucleus.nucleus_hash,
      operator_constraint: operatorConstraint,
      event_id: eventId,
      state: nextState === null ? null : compactSessionState(nextState),
    });
  });
}

// The VERIFY snapshot bootstrap (prepareVerificationEntry -> buildClaimFreeze ->
// readCandidateClaims) re-runs the sensitive-material validator over every
// persisted claim. When a claim carries legitimately secret-shaped evidence
// (a CORS Authorization:/cookie reflection that IS the finding) WITHOUT a
// persisted secret_evidence_bypass, that re-scan throws a plain Error. Left
// unclassified it falls through envelope.classifyException to INTERNAL_ERROR,
// which operator_force cannot bypass and which lands mid-transition. These two
// messages are the only ones validateNoSensitiveMaterial raises.
function isSensitiveMaterialError(error) {
  const message = error && typeof error.message === "string" ? error.message : "";
  return /appears to contain secrets, auth headers, cookies, or tokens/.test(message)
    || /is too large; do not persist raw large response bodies/.test(message);
}

// Option C (auth_status): derive auth_status on every lifecycle advance so it reflects
// reality instead of staying "pending" forever (the field has no other setter).
//
// SEMANTICS — auth_status is a session-lifetime MILESTONE (the highest/operator-asserted auth
// state reached), NOT a real-time per-request credential probe: it is recomputed only at advance
// time from profile PRESENCE, and once "authenticated"/"unauthenticated" it is sticky absent an
// explicit caller change. Credential deletion BETWEEN advances is therefore not auto-detected; a
// consumer needing a live "are credentials present right now" answer must call
// hasUsableAuthProfile directly rather than trust this field.
//
// Precedence (in order):
//  (1) operator_force is operator AUTHORITY: an explicit, non-blank value carried with
//      operator_force is always honored — including lifting a prior "unauthenticated" or asserting
//      "authenticated" with no profile (an operator vouching for an out-of-band context).
//      DELIBERATE DUAL-USE (Claude PR#138 review): operator_force is THE operator-authority signal,
//      so it intentionally grants BOTH lifecycle-gate-bypass AND auth-context-assertion authority
//      under one flag. This is defensible for an advisory milestone that grants no capability and
//      whose every operator_force advance already carries an audited override_reason; a separate
//      auth-authority flag would add API surface for no security gain. An UNPRIVILEGED caller (no
//      operator_force) still cannot assert "authenticated" without a backing profile — see (3).
//  (2) A prior "unauthenticated" is STICKY: once a run is `--no-auth`, only operator authority (1)
//      can lift it. It survives BOTH an omitted auth_status AND an UNPRIVILEGED explicit
//      "authenticated" (even with a profile in the store — e.g. a victim credential captured for
//      IDOR testing must not silently re-authenticate a `--no-auth` session). This is broader than
//      "carried forward on omission": an unprivileged backed claim cannot reverse the operator's
//      intent.
//  (3) An UNPRIVILEGED explicit value (no operator_force, prior not sticky-unauthenticated):
//      a negative "unauthenticated" assertion needs no evidence and is honored; a neutral "pending"
//      is honored ONLY when it does not REGRESS an established milestone — an explicit "pending"
//      (the "unknown/initial" state) can never silently downgrade a prior "authenticated" back to
//      "unknown" (it falls through to (4)/(5), which preserve the milestone); a positive
//      "authenticated" is honored ONLY when a usable profile is actually present. This forge guard
//      blocks a BARE unprivileged assertion of "authenticated" with no backing — but it does NOT
//      make the milestone unforgeable: an evaluator able to call the pre-approved bob_auth_store can
//      stash a credential-shaped header and reach (4)'s profile-backed "authenticated". That is
//      acceptable because auth_status grants no capability (a forged/bogus token 401s on use — see
//      SEMANTICS) and because every auth_status CHANGE folds from_auth_status/to_auth_status/
//      auth_status_changed into the single governance.lifecycle.advanced event committed in
//      advanceSession (there is no separate governance.auth_context.replaced event), so a
//      fabricated milestone is always reconstructable. A
//      blank/whitespace value is treated as OMITTED (else it would normalize to "pending" in the
//      nucleus while the raw "" leaked to the state.json mirror).
//  (4) No explicit value: a usable stored profile means "authenticated".
//  (5) Otherwise carry the prior status forward (default "pending"); never silently auto-downgrade.
// buildSessionNucleus -> normalizeAuthContext validates the resulting enum; the caller mirrors the
// NORMALIZED nucleus value into state.json so the two stores can never disagree.
function deriveAdvanceAuthContext(priorAuthContext, explicitAuthStatus, hasProfile, operatorForced = false) {
  const prior = (priorAuthContext && typeof priorAuthContext === "object") ? priorAuthContext : {};
  // SELF-GUARD: this function is exported (module.exports) and callable in-process WITHOUT
  // advanceSession's call-boundary validation, so it validates its own input — fail-closed and
  // consistent with that boundary. A non-string (non-null) value is rejected outright (else it would
  // be silently treated as omitted); a blank/whitespace string is allowed (treated as omitted below);
  // only a non-blank string outside AUTH_STATUS_VALUES throws — rather than any of these propagating
  // into a deep normalizeAuthContext throw at nucleus-build time.
  if (explicitAuthStatus != null && typeof explicitAuthStatus !== "string") {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      `auth_status must be a string; got ${typeof explicitAuthStatus}`,
    );
  }
  if (typeof explicitAuthStatus === "string") {
    const trimmedExplicit = explicitAuthStatus.trim();
    if (trimmedExplicit !== "" && !AUTH_STATUS_VALUES.includes(trimmedExplicit)) {
      throw new ToolError(
        ERROR_CODES.INVALID_ARGUMENTS,
        `auth_status must be one of ${AUTH_STATUS_VALUES.join(", ")}; got ${JSON.stringify(explicitAuthStatus)}`,
      );
    }
  }
  // A blank/whitespace explicit value is NOT an assertion — treat it as omitted. A non-blank value
  // is TRIMMED so a padded " authenticated " is honored as "authenticated" (and reaches the
  // nucleus's normalizeAuthContext enum check trimmed) instead of being passed through raw, which
  // would pass the trim-based call-boundary check yet throw deep on the padded enum value.
  const explicit = (typeof explicitAuthStatus === "string" && explicitAuthStatus.trim() !== "")
    ? explicitAuthStatus.trim()
    : null;
  let nextStatus;
  if (explicit != null && operatorForced === true) {
    nextStatus = explicit;                                 // (1) operator authority
  } else if (prior.auth_status === "unauthenticated") {
    nextStatus = "unauthenticated";                        // (2) sticky --no-auth (only (1) lifts it)
  } else if (
    explicit != null
    && (explicit !== "authenticated" || hasProfile)        // forge guard: a positive needs a profile
    && !(explicit === "pending" && prior.auth_status && prior.auth_status !== "pending")  // no regress to "unknown"
  ) {
    nextStatus = explicit;                                 // (3) unprivileged explicit (forge- + downgrade-guarded)
  } else if (hasProfile) {
    nextStatus = "authenticated";                          // (4) usable stored credentials
  } else {
    nextStatus = prior.auth_status || "pending";           // (5) carry forward / default
  }
  return { ...prior, auth_status: nextStatus };
}

function advanceSession(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  let toState;
  try {
    toState = normalizeLifecycleState(args.to_state, "to_state");
  } catch (error) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, error.message || String(error));
  }
  const override = args.override == null ? null : args.override;
  if (override !== null && override !== "operator_force") {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      `override must be null or "operator_force"; got ${JSON.stringify(override)}`,
    );
  }
  if (
    override === "operator_force"
    && (typeof args.override_reason !== "string" || !args.override_reason.trim())
  ) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "override_reason must be a non-empty string when override is operator_force",
    );
  }
  const overrideReason = args.override_reason == null
    ? null
    : assertNonEmptyString(args.override_reason, "override_reason");
  // Validate auth_status at the call boundary (not deep in buildSessionNucleus -> normalizeAuthContext)
  // so a direct in-process caller gets a clear error. A blank/whitespace value is allowed here and
  // treated as OMITTED downstream by deriveAdvanceAuthContext; only a non-blank invalid value throws.
  if (args.auth_status != null) {
    if (typeof args.auth_status !== "string") {
      throw new ToolError(
        ERROR_CODES.INVALID_ARGUMENTS,
        `auth_status must be a string; got ${typeof args.auth_status}`,
      );
    }
    const trimmedAuth = args.auth_status.trim();
    if (trimmedAuth !== "" && !AUTH_STATUS_VALUES.includes(trimmedAuth)) {
      throw new ToolError(
        ERROR_CODES.INVALID_ARGUMENTS,
        `auth_status must be one of ${AUTH_STATUS_VALUES.join(", ")}; got ${JSON.stringify(args.auth_status)}`,
      );
    }
  }

  return withSessionLock(domain, () => {
    // A lifecycle advance derives its next nucleus from the prior one, so the
    // prior read must be verified — never a silent fallback that could carry
    // a tampered or stale lifecycle_state into the next transition.
    let priorNucleus;
    try {
      priorNucleus = readVerifiedSessionNucleus(domain);
    } catch (error) {
      throw new ToolError(
        ERROR_CODES.STATE_CONFLICT,
        `session nucleus missing or unverifiable for ${domain}; call bob_init_session first (${error.message || String(error)})`,
      );
    }
    const fromState = normalizeLifecycleState(priorNucleus.lifecycle_state, "lifecycle_state");
    const evaluation = evaluateLifecycleTransition({
      target_domain: domain,
      from_state: fromState,
      to_state: toState,
      nucleus: priorNucleus,
    });

    // External approval and the signed physical inventory checkpoint are
    // NON-bypassable by operator_force. For AgentCore, external_approval_pending
    // (gradeToReportApprovalBlocker in lifecycle-gates.js) is also the rail-b
    // human gate in the headless
    // --dangerously-skip-permissions deploy the MODEL is the sole caller of this tool, so
    // letting operator_force wave through the GRADE->REPORT human-approval gate would let the
    // model self-approve. This carve-out is scoped to ONLY the operator_force branch (a caller
    // with no override is already blocked below unconditionally) and keys off each blocker's
    // own blocked_by code. The physical inventory sentinel remains fail-closed until a future
    // signed, current inventory checkpoint is implemented and verified.
    const bypassAttempted = override === "operator_force";
    const nonBypassable = bypassAttempted
      ? evaluation.blockers.find((b) => [
        "external_approval_pending",
        "physical_inventory_required",
      ].includes(b.blocked_by))
      : null;
    if (evaluation.blockers.length > 0 && (!bypassAttempted || nonBypassable)) {
      const first = nonBypassable || evaluation.blockers[0];
      // Y.10 (Y-D12 / Y-P12) — propagate the blocker's structured
      // remediation string through the ToolError so MCP callers see it
      // verbatim in the response envelope (mcp/core/io/envelope.js).
      const remediation = typeof first.remediation === "string" ? first.remediation : null;
      throw new ToolError(
        ERROR_CODES.STATE_CONFLICT,
        `lifecycle transition blocked: ${first.message || first.code || first.blocked_by}`,
        {
          blocked_by: first.blocked_by || first.code || "transition_blocked",
          code: first.code || first.blocked_by || "transition_blocked",
          from: fromState,
          to: toState,
          allowed: first.allowed || (first.blocked_by === "no_transition"
            ? require("./lifecycle-gates.js").allowedTargetsFor(fromState)
            : undefined),
          surfaces: Array.isArray(first.surfaces) ? first.surfaces.slice() : undefined,
          blockers: evaluation.blockers,
        },
        remediation ? { remediation } : null,
      );
    }

    // Derive the next auth context FIRST — deriveAdvanceAuthContext performs the only fallible work
    // left (the hasUsableAuthProfile auth.json read). Computing it before any durable write
    // upholds "all fallible work BEFORE durable writes".
    const hadUsableProfile = hasUsableAuthProfile(domain);
    const nextAuthContext = deriveAdvanceAuthContext(
      priorNucleus.auth_context,
      args.auth_status,
      hadUsableProfile,
      override === "operator_force",
    );

    const nextNucleus = buildSessionNucleus({
      target_domain: priorNucleus.target_domain,
      target_url: priorNucleus.scope_policy && priorNucleus.scope_policy.target_url,
      scope_policy: priorNucleus.scope_policy,
      egress_identity: priorNucleus.egress_identity,
      auth_context: nextAuthContext,
      operator_constraint: priorNucleus.operator_constraint,
      lifecycle_state: toState,
      physical_scope: priorNucleus.physical_scope,
      // Preserve the repo session's pinned repo_hash across the lifecycle advance;
      // without it the nucleus loses repo_hash on the first transition and every
      // bob_repo_docker_run then crashes (null repo_hash -> buildImageTag null.slice).
      repo_hash: priorNucleus.repo_hash,
    });

    // Compute the auth_status transition from the NORMALIZED nuclei (buildSessionNucleus already ran
    // normalizeAuthContext) so the canonical lifecycle.advanced event can carry the transition
    // ATOMICALLY with the lifecycle move (its single append is the durable record of this advance —
    // the transition is always reconstructable from this event alone).
    const priorAuthStatus = priorNucleus.auth_context && typeof priorNucleus.auth_context === "object"
      ? priorNucleus.auth_context.auth_status
      : undefined;
    const nextAuthStatus = nextNucleus.auth_context && typeof nextNucleus.auth_context === "object"
      ? nextNucleus.auth_context.auth_status
      : undefined;
    const authStatusChanged = nextAuthStatus !== priorAuthStatus;

    // Single-authority CAS write (A7). The two durable lifecycle stores
    // (session-nucleus.json and state.json) and the session-events.jsonl append
    // are committed by ONE commitSessionAuthority call — there is no manual
    // multi-file write with a hand-rolled restore any more. commitSessionAuthority
    // itself snapshots state.json/session-nucleus.json/session-events.jsonl, CAS-
    // publishes all three, and rolls all three back to their exact prior bytes on
    // ANY publish failure (session-authority-unit-of-work.js).
    //
    //   1. Run ALL fallible work (buildVerificationEntry, nextState, the event
    //      payload) BEFORE any durable write. buildVerificationEntry is pure (no
    //      I/O) and throws (the sensitive-material re-scan) before anything is
    //      committed, so a throw there leaves both lifecycle stores byte-unchanged.
    //   2. commitVerificationEntry performs the ONE non-CAS durable side effect
    //      this advance can make (the verification archive dir + snapshot write)
    //      and returns an undo() receipt.
    //   3. Everything from just after that write through the commitSessionAuthority
    //      call is one undo-protected window: ANY throw in that span — including a
    //      CAS mismatch inside commitSessionAuthority itself — invokes undo() before
    //      rethrowing, so the archive + snapshot never survive a failed advance.
    //   4. Manifest refresh and the pipeline-events mirror are strictly postcommit
    //      and best-effort: they run only after commitSessionAuthority has already
    //      succeeded, and can never fail the call or alter its result.
    let raw = {};
    let state = null;
    let stateMissing = false;
    try {
      ({ raw, state } = readSessionStateStrict(domain));
    } catch (error) {
      if (!sessionStateMissing(error)) throw error;
      stateMissing = true;
    }

    // (1) Fallible work FIRST — pure, no I/O beyond the sensitive-material scan
    // (which throws before any write).
    let verificationBuild = null;
    if (!stateMissing && toState === "VERIFY") {
      try {
        verificationBuild = require("../verification/verification.js").buildVerificationEntry(domain, state);
      } catch (verificationError) {
        if (!isSensitiveMaterialError(verificationError)) throw verificationError;
        // A persisted claim's evidence trips the sensitive-material scan and
        // has no operator-approved secret_evidence_bypass. The claim was
        // validated at write, so this is a recoverable fail-closed block, not
        // an unbypassable INTERNAL_ERROR. operator_force proceeds past it by
        // skipping the VERIFY snapshot bootstrap; otherwise surface a clean
        // STATE_CONFLICT naming the offending field so the operator can
        // re-record the finding with a secret_detection_bypass. Because this
        // throws BEFORE any durable write, neither lifecycle store is mutated
        // and the two stores still agree (no drift).
        if (override === "operator_force") {
          verificationBuild = null;
        } else {
          const message = verificationError && typeof verificationError.message === "string"
            ? verificationError.message
            : String(verificationError);
          const offendingPath = (message.match(/^(\S+)\s+(?:appears to contain|is too large)/) || [])[1] || null;
          throw new ToolError(
            ERROR_CODES.STATE_CONFLICT,
            `lifecycle transition blocked: a recorded claim's evidence contains secret-shaped material without an operator-approved secret_detection_bypass${offendingPath ? ` (${offendingPath})` : ""}`,
            {
              blocked_by: "claim_evidence_secret_blocked",
              code: "claim_evidence_secret_blocked",
              block_code: "claim_evidence_secret_blocked",
              from: fromState,
              to: toState,
              offending_path: offendingPath,
            },
            {
              remediation: `Re-record the offending finding with a secret_detection_bypass for the flagged field${offendingPath ? ` (${offendingPath})` : ""}, or rerun with override="operator_force" to advance without the VERIFY snapshot bootstrap.`,
            },
          );
        }
      }
    }

    // phase is a migration-only projection: it is always the canonical
    // pre-image of the state we are writing (deriveLegacyPhaseFromLifecycleState),
    // never a history-dependent override. Gates and the evidence-completion
    // check source their admission decision from the lifecycle event ledger
    // (governance.lifecycle.advanced), not from this field.
    const derivedLegacyPhase = stateMissing ? null : deriveLegacyPhaseFromLifecycleState(toState);

    // (2)+(3) Commit the verification entry (if planned), then the CAS. From
    // just after commitVerificationEntry through commitSessionAuthority is one
    // undo-protected window.
    let verificationCommit = null;
    let commitResult;
    try {
      if (verificationBuild) {
        verificationCommit = require("../verification/verification.js").commitVerificationEntry(domain, verificationBuild);
      }

      const nextState = stateMissing ? null : {
        ...state,
        ...(verificationCommit ? verificationCommit.state_fields : {}),
        lifecycle_state: toState,
        // Mirror the NORMALIZED nucleus auth_status into state.json so the two lifecycle stores
        // can never disagree — buildSessionNucleus -> normalizeAuthContext is the single source of
        // truth for the value (e.g. it coerces a blank/legacy value to "pending"); mirroring the
        // pre-normalization derive output here would split-brain on any value the nucleus rewrites.
        auth_status: nextNucleus.auth_context.auth_status,
        ...(derivedLegacyPhase ? { phase: derivedLegacyPhase } : {}),
      };

      // The single canonical event: binds states/hashes, the auth delta,
      // override/reason, the EXACT blockers array that was bypassed (empty when
      // nothing was bypassed), and the VERIFY identity when a snapshot was
      // bootstrapped. This is the durable, atomic record of the advance —
      // governance.lifecycle.override and governance.auth_context.replaced are
      // folded in rather than written as separate events.
      const eventPayload = {
        from_state: fromState,
        to_state: toState,
        nucleus_hash: nextNucleus.nucleus_hash,
        prior_nucleus_hash: priorNucleus.nucleus_hash,
        from_auth_status: priorAuthStatus == null ? null : priorAuthStatus,
        to_auth_status: nextAuthStatus == null ? null : nextAuthStatus,
        auth_status_changed: authStatusChanged,
        had_usable_profile: hadUsableProfile,
        explicit_auth_status_supplied: typeof args.auth_status === "string" && args.auth_status.trim() !== "",
        override: override === "operator_force" ? "operator_force" : null,
        override_reason: overrideReason,
        blockers: override === "operator_force" ? evaluation.blockers : [],
      };
      if (verificationCommit) {
        eventPayload.verification_attempt_id = verificationCommit.state_fields.verification_attempt_id;
        eventPayload.verification_snapshot_hash = verificationCommit.state_fields.verification_snapshot_hash;
      }

      commitResult = commitSessionAuthority({
        targetDomain: domain,
        nextNucleus,
        stateProjection: nextState === null ? null : { rawDocument: raw, nextState },
        event: {
          target_domain: domain,
          kind: "governance.lifecycle.advanced",
          nucleus_hash: nextNucleus.nucleus_hash,
          payload: eventPayload,
        },
        expectedNucleusHash: priorNucleus.nucleus_hash,
      });
    } catch (error) {
      if (verificationCommit) verificationCommit.undo();
      throw error;
    }

    // (4) Postcommit best-effort mirrors — the advance already committed
    // durably above; nothing below may alter success or gate on failure (no
    // prune/manifest/pipeline precommit).
    if (verificationCommit && verificationCommit.schema_version === 2) {
      try {
        require("../verification/verification.js").refreshVerificationManifest(domain);
      } catch (_manifestError) {
        // Best-effort mirror only — the advance already committed durably above.
      }
    }

    // Mirror the advance into pipeline-events.jsonl for analytics consumers.
    // Lifecycle vocabulary is canonical; the legacy phase fields are no
    // longer accepted by the pipeline-events whitelist (D.3).
    try {
      const { state: nextStateForEvent } = readSessionStateStrict(domain);
      const eventFields = {
        from_state: fromState,
        to_state: toState,
        lifecycle_state: toState,
        status: "advanced",
        source: "bob_advance_session",
        egress_profile: nextStateForEvent.egress_profile,
        egress_region: nextStateForEvent.egress_region,
        proxy_configured: nextStateForEvent.proxy_configured,
        egress_profile_identity_hash: nextStateForEvent.egress_profile_identity_hash,
        egress_profile_identity_version: nextStateForEvent.egress_profile_identity_version,
      };
      if (override === "operator_force") {
        eventFields.override = true;
        if (overrideReason != null) eventFields.override_reason = overrideReason;
      }
      if (verificationCommit && verificationCommit.schema_version === 2) {
        eventFields.verification_attempt_id = verificationCommit.state_fields.verification_attempt_id;
        eventFields.verification_snapshot_hash = verificationCommit.state_fields.verification_snapshot_hash;
      }
      safeAppendPipelineEventDirect(domain, "lifecycle_advanced", eventFields, buildGovernanceContextFromNucleus(nextNucleus));
    } catch (error) {
      if (!sessionStateMissing(error)) {
        // Pipeline event is observational; failures to append are tolerated
        // unless the state is fully missing.
      }
    }

    return JSON.stringify({
      version: 1,
      advanced: true,
      from_state: fromState,
      to_state: toState,
      nucleus_hash: nextNucleus.nucleus_hash,
      prior_nucleus_hash: priorNucleus.nucleus_hash,
      override: override === "operator_force" ? "operator_force" : null,
      event_id: commitResult.event_id,
      verification: verificationCommit
        ? {
          schema_version: verificationCommit.schema_version,
          attempt_id: verificationCommit.state_fields.verification_attempt_id,
          snapshot_hash: verificationCommit.state_fields.verification_snapshot_hash,
          archived: verificationCommit.archived != null,
        }
        : undefined,
    });
  });
}

function clearTerminalBlock(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const surfaceId = assertNonEmptyString(args.surface_id, "surface_id");
  if (typeof args.reason !== "string" || args.reason.trim().length < 20) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "reason is required and must be at least 20 characters; the operator note is the audit trail",
    );
  }
  const reason = args.reason.trim();
  if (reason.length > 280) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      "reason must be at most 280 characters",
    );
  }
  // The clear reason lands in state.terminal_block_clear_history (durable
  // public state). Screen for credentials so an operator pasting "added
  // attacker auth profile with cookie SESS=eyJabc..." cannot leak the
  // cookie into bob_read_session_state output.
  try {
    require("../redaction/index.js").validateNoSensitiveMaterial(reason, "reason");
  } catch (error) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, error.message);
  }

  return withSessionLock(domain, () => {
    const { raw, state } = readSessionStateStrict(domain);
    if (state.pending_wave != null) {
      throw new ToolError(
        ERROR_CODES.STATE_CONFLICT,
        `Cannot clear a terminal block while wave ${state.pending_wave} is pending; merge the current wave first`,
      );
    }
    // The blocker ledger is authoritative after D.3: read the current set
    // through frontier-projections rather than state.terminally_blocked.
    // Reconstruct the previous blocker tuple from the frontier event's
    // payload so the audit trail in terminal_block_clear_history keeps the
    // (kind, identifier_hint, reason) shape callers expect.
    const { currentBlockers } = require("../frontier/frontier-projections.js");
    const blockers = currentBlockers(domain);
    const blockerEntry = blockers.find((entry) => entry.surface_id === surfaceId);
    if (!blockerEntry) {
      throw new ToolError(
        ERROR_CODES.STATE_CONFLICT,
        `Surface ${surfaceId} is not terminally blocked in the frontier ledger; nothing to clear`,
      );
    }
    let previousBlockers = [];
    let previouslyBlockedAtWave = null;
    try {
      const { readFrontierEvents } = require("../frontier/frontier-events.js");
      const events = readFrontierEvents(domain);
      const sourceEvent = events.find((event) => event.event_id === blockerEntry.source_event_id) || null;
      if (sourceEvent && sourceEvent.payload && typeof sourceEvent.payload === "object" && !Array.isArray(sourceEvent.payload)) {
        const payload = sourceEvent.payload;
        if (typeof payload.kind === "string") {
          const blocker = { kind: payload.kind };
          if (typeof payload.identifier_hint === "string" && payload.identifier_hint) {
            blocker.identifier_hint = payload.identifier_hint;
          }
          if (typeof payload.reason === "string" && payload.reason) {
            blocker.reason = payload.reason;
          }
          previousBlockers = [blocker];
        }
        if (Number.isInteger(payload.wave) && payload.wave > 0) {
          previouslyBlockedAtWave = payload.wave;
        }
      }
    } catch {
      // Source-event details are best-effort enrichment; the clear-history
      // entry stays valid even if the ledger read fails.
    }
    const clearedAtTs = new Date().toISOString();
    const priorClearHistory = Array.isArray(state.terminal_block_clear_history) ? state.terminal_block_clear_history : [];
    const clearEntry = {
      surface_id: surfaceId,
      cleared_at_wave: state.evaluation_wave,
      cleared_at_ts: clearedAtTs,
      reason,
    };
    if (previouslyBlockedAtWave != null) {
      clearEntry.previously_blocked_at_wave = previouslyBlockedAtWave;
    }
    if (previousBlockers.length > 0) {
      clearEntry.previous_blockers = previousBlockers;
    }
    const nextClearHistory = [...priorClearHistory, clearEntry];

    const nextState = {
      ...state,
      terminal_block_clear_history: nextClearHistory,
    };
    writeSessionStateDocument(domain, raw, nextState);

    // Emit a closure.recorded frontier event with surface_unblocked semantics
    // so the projection's foldLatestBySurface returns the cleared state as
    // the latest surface-state event. The event is sourced from the
    // wave-merge tool sentinel so it satisfies the surface-state predicate
    // without depending on the legacy payload markers.
    try {
      appendClosureRecordedEvent({
        target_domain: domain,
        kind: "closure.recorded",
        surface_id: surfaceId,
        payload: {
          surface_fully_explored: false,
          surface_unblocked: true,
          reason: "operator_cleared_terminal_block",
          operator_reason: reason,
        },
        source: { artifact: "wave-merge", tool: "bob_apply_wave_merge" },
      });
    } catch {
      // Frontier ledger append is best-effort.
    }

    safeAppendPipelineEventDirect(domain, "terminal_block_cleared", {
      lifecycle_state: state.lifecycle_state,
      status: "cleared",
      source: "bob_clear_terminal_block",
      surface_id: surfaceId,
      counts: {
        terminally_blocked_total: Math.max(0, blockers.length - 1),
        clear_history_size: nextClearHistory.length,
      },
    }, buildGovernanceContext(nextState));

    return JSON.stringify({
      version: 1,
      cleared: true,
      surface_id: surfaceId,
      cleared_at_wave: state.evaluation_wave,
      cleared_at_ts: clearedAtTs,
      previous_blockers: clearEntry.previous_blockers || [],
      previously_blocked_at_wave: clearEntry.previously_blocked_at_wave || null,
      state: compactSessionState(nextState),
    });
  });
}

module.exports = {
  advanceSession,
  assertBlockInternalHostsCompatibleWithEgress,
  clearOperatorNote,
  clearTerminalBlock,
  deriveAdvanceAuthContext,
  initSession,
  resolveAndAssertSessionEgressIdentity,
  setOperatorNote,
  readSessionState,
  readStateSummary,
};
