"use strict";

const fs = require("fs");
const {
  assertBoolean,
  assertNonEmptyString,
} = require("./validation.js");
const {
  AUTH_STATUS_VALUES,
} = require("./constants.js");
const {
  sessionDir,
  sessionNucleusPath,
  statePath,
  surfaceIndexPath,
  taskQueuePath,
} = require("./paths.js");
const {
  isSessionDirEffectivelyEmpty,
  readJsonFile,
  withSessionLock,
  writeFileAtomic,
} = require("./storage.js");
const {
  ERROR_CODES,
  ToolError,
} = require("./envelope.js");
const {
  resolveEgressProfile,
} = require("./egress-profiles.js");
const {
  hasUsableAuthProfile,
} = require("./auth.js");
const {
  buildSessionNucleus,
  LIFECYCLE_STATE_VALUES,
  normalizeLifecycleState,
  normalizeOperatorConstraint,
} = require("./governance-contracts.js");
const {
  appendSessionEvent,
} = require("./session-events.js");
const {
  appendFrontierEvent,
} = require("./frontier-events.js");
const {
  scheduleMaterialization,
} = require("./frontier-materialize-debounce.js");
const {
  evaluateLifecycleTransition,
} = require("./lifecycle-gates.js");
const {
  readSessionNucleus,
} = require("./governance-store.js");
const {
  hashCanonicalJson,
} = require("./verification-contracts.js");
const {
  writeJsonDocument,
} = require("./fabric-common.js");
const {
  safeAppendPipelineEventDirect,
} = require("./pipeline-events.js");
const { ensureHandoffSigningKey, ensureHandoffKeypair } = require("./handoff-signing-key.js");
const {
  recordSandboxIsolationAttestation,
} = require("./sandbox-isolation-attest.js");
const {
  buildGovernanceContext,
  buildGovernanceContextFromNucleus,
} = require("./governance-context.js");
const {
  assertHttpScopeDomain,
  validateHttpScanScope,
} = require("./scope.js");
const {
  parseLabAuthorization,
  labBootstrapPolicyViolation,
  recordLabAuthorization,
} = require("./lab-target-attest.js");
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

function assertSessionEgressIdentity(domain, profile, { source = "egress_request" } = {}) {
  const identityFields = egressProfileStateFields(profile);
  let bound = false;

  try {
    withSessionLock(domain, () => {
      const { raw, state } = readSessionStateStrict(domain);
      if (!state.egress_profile_identity_hash) {
        const migratedAt = new Date().toISOString();
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
        writeSessionStateDocument(domain, raw, nextState);
        safeAppendPipelineEventDirect(domain, "egress_identity_bound", {
          lifecycle_state: state.lifecycle_state,
          status: "bound",
          source,
          legacy_migration: true,
          ...identityFields,
        }, buildGovernanceContext(nextState));
        bound = true;
        return;
      }

      if (
        state.egress_profile_identity_hash !== identityFields.egress_profile_identity_hash ||
        state.egress_profile_identity_version !== identityFields.egress_profile_identity_version
      ) {
        throw new ToolError(
          ERROR_CODES.STATE_CONFLICT,
          `egress profile drift for ${domain}: session is bound to ${state.egress_profile} (${state.egress_profile_identity_hash}); requested ${identityFields.egress_profile} (${identityFields.egress_profile_identity_hash})`,
          {
            target_domain: domain,
            expected: {
              egress_profile: state.egress_profile,
              egress_region: state.egress_region,
              proxy_configured: state.proxy_configured,
              egress_profile_identity_hash: state.egress_profile_identity_hash,
              egress_profile_identity_version: state.egress_profile_identity_version,
            },
            requested: identityFields,
          },
        );
      }
    });
  } catch (error) {
    if (!sessionStateMissing(error)) throw error;
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `egress profile identity requires an initialized session for ${domain}; call bob_init_session before egress-bound requests`,
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

  return {
    ...identityFields,
    session_state_present: true,
    session_identity_bound: bound,
  };
}

function resolveAndAssertSessionEgressIdentity(domain, requestedProfile = "default", options = {}) {
  const profile = resolveEgressProfile(requestedProfile, options);
  const identity = assertSessionEgressIdentity(domain, profile, {
    source: options.source || "egress_request",
  });
  return { profile, identity };
}

function initSession(args) {
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
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Session already initialized: ${filePath}`);
    }
    if (!isSessionDirEffectivelyEmpty(dir)) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Session directory is not empty: ${dir}`);
    }

    const egressProfile = resolveEgressProfile(requestedEgressProfile);
    assertBlockInternalHostsCompatibleWithEgress(internalHostPolicy, egressProfile);
    const egressFields = egressProfileStateFields(egressProfile);
    const sessionNucleus = buildSessionNucleus({
      target_domain: domain,
      target_url: targetUrl,
      scope_policy: {
        target_domain: domain,
        target_url: targetUrl,
        ...internalHostPolicy,
      },
      egress_identity: egressFields,
      auth_context: {
        auth_status: "pending",
      },
      operator_constraint: {
        handoff_provenance_required: true,
      },
    });
    writeJsonDocument(sessionNucleusPath(domain), sessionNucleus);
    appendSessionEvent({
      target_domain: domain,
      kind: "governance.session.initialized",
      nucleus_hash: sessionNucleus.nucleus_hash,
      payload: {
        nucleus_hash: sessionNucleus.nucleus_hash,
        scope_policy_hash: hashCanonicalJson(sessionNucleus.scope_policy),
        egress_identity_hash: hashCanonicalJson(sessionNucleus.egress_identity),
        auth_context_hash: hashCanonicalJson(sessionNucleus.auth_context),
        operator_constraint_hash: hashCanonicalJson(sessionNucleus.operator_constraint),
      },
    });
    // bob_init_session is the URL primary axis. It leaves the smart-contract
    // axis fields at their builder defaults (target_contracts: [],
    // chain_authority_hash: null); an empty target_contracts is not the
    // contracts axis, so this stays a single-axis (url) session under the
    // exactly-one-primary-axis normalization in normalizeSessionStateDocument.
    const state = buildInitialSessionState(sessionNucleus.target_domain, sessionNucleus.scope_policy.target_url, {
      deepMode,
      egressProfile,
      blockInternalHostsPolicy: sessionNucleus.scope_policy,
    });
    writeSessionStateDocument(domain, {}, state);
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

function readSessionState(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const { state } = readSessionStateStrict(domain);
  return JSON.stringify({
    version: 1,
    state: publicSessionState(state),
    frontier_view_hashes: readFrontierViewHashes(domain),
  });
}

function readStateSummary(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const { state } = readSessionStateStrict(domain);
  return JSON.stringify({
    version: 1,
    state: compactSessionState(state),
    frontier_view_hashes: readFrontierViewHashes(domain),
  });
}

function applyOperatorConstraintUpdate(domain, transform) {
  const priorNucleus = readSessionNucleus(domain);
  if (!priorNucleus || typeof priorNucleus !== "object") {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `session nucleus missing for ${domain}; call bob_init_session first`,
    );
  }
  const priorConstraint = (priorNucleus.operator_constraint && typeof priorNucleus.operator_constraint === "object")
    ? priorNucleus.operator_constraint
    : {};
  const nextConstraintInput = transform({ ...priorConstraint });
  const operatorConstraint = normalizeOperatorConstraint(nextConstraintInput);
  const nextNucleus = buildSessionNucleus({
    target_domain: priorNucleus.target_domain,
    target_url: priorNucleus.scope_policy && priorNucleus.scope_policy.target_url,
    scope_policy: priorNucleus.scope_policy,
    egress_identity: priorNucleus.egress_identity,
    auth_context: priorNucleus.auth_context,
    operator_constraint: operatorConstraint,
    lifecycle_state: priorNucleus.lifecycle_state,
    // Preserve the repo session's pinned repo_hash across nucleus rewrites; it is
    // the O-D6 docker image-tag binding and dropping it makes bob_repo_docker_run
    // crash (readRepoSession -> null repo_hash -> buildImageTag null.slice).
    repo_hash: priorNucleus.repo_hash,
  });
  writeJsonDocument(sessionNucleusPath(domain), nextNucleus);
  const updatedEvent = appendSessionEvent({
    target_domain: domain,
    kind: "governance.operator_constraint.updated",
    nucleus_hash: nextNucleus.nucleus_hash,
    payload: {
      prior_nucleus_hash: priorNucleus.nucleus_hash,
      nucleus_hash: nextNucleus.nucleus_hash,
      operator_constraint_hash: hashCanonicalJson(nextNucleus.operator_constraint),
    },
  });
  return {
    priorNucleus,
    nextNucleus,
    operatorConstraint,
    eventId: updatedEvent.event_id,
  };
}

function setOperatorNote(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const operatorNote = assertOperatorNote(args.operator_note, "operator_note");

  return withSessionLock(domain, () => {
    const { raw, state } = readSessionStateStrict(domain);
    const { nextNucleus, operatorConstraint, eventId } = applyOperatorConstraintUpdate(
      domain,
      (prior) => ({ ...prior, operator_note: operatorNote }),
    );
    const nextState = {
      ...state,
      operator_note: operatorNote,
    };
    writeSessionStateDocument(domain, raw, nextState);
    return JSON.stringify({
      version: 1,
      updated: true,
      operator_note: operatorNote,
      nucleus_hash: nextNucleus.nucleus_hash,
      operator_constraint: operatorConstraint,
      event_id: eventId,
      state: compactSessionState(nextState),
    });
  });
}

function clearOperatorNote(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");

  return withSessionLock(domain, () => {
    const { raw, state } = readSessionStateStrict(domain);
    const { nextNucleus, operatorConstraint, eventId } = applyOperatorConstraintUpdate(
      domain,
      (prior) => {
        const next = { ...prior };
        delete next.operator_note;
        return next;
      },
    );
    const nextState = {
      ...state,
      operator_note: null,
    };
    writeSessionStateDocument(domain, raw, nextState);
    return JSON.stringify({
      version: 1,
      cleared: true,
      operator_note: null,
      nucleus_hash: nextNucleus.nucleus_hash,
      operator_constraint: operatorConstraint,
      event_id: eventId,
      state: compactSessionState(nextState),
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
//      SEMANTICS) and because every auth_status CHANGE emits a governance.auth_context.replaced
//      audit event (in advanceSession), so a fabricated milestone is always reconstructable. A
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
    const priorNucleus = readSessionNucleus(domain);
    if (!priorNucleus || typeof priorNucleus !== "object") {
      throw new ToolError(
        ERROR_CODES.STATE_CONFLICT,
        `session nucleus missing for ${domain}; call bob_init_session first`,
      );
    }
    const fromState = normalizeLifecycleState(priorNucleus.lifecycle_state, "lifecycle_state");
    const evaluation = evaluateLifecycleTransition({
      target_domain: domain,
      from_state: fromState,
      to_state: toState,
      nucleus: priorNucleus,
    });

    // AgentCore rail-b: external_approval_pending (gradeToReportApprovalBlocker in
    // lifecycle-gates.js) is NON-bypassable by operator_force -- in the headless
    // --dangerously-skip-permissions deploy the MODEL is the sole caller of this tool, so
    // letting operator_force wave through the GRADE->REPORT human-approval gate would let the
    // model self-approve. This carve-out is scoped to ONLY the operator_force branch (a caller
    // with no override is already blocked below unconditionally) and is keyed off the blocker's
    // own blocked_by code rather than re-reading BOB_AGENTCORE here: gradeToReportApprovalBlocker
    // is the sole producer of that code and is itself already inert unless BOB_AGENTCORE==="1",
    // so off that branch nonBypassable is always null and this reduces byte-for-byte to the
    // original `override !== "operator_force"` condition.
    const bypassAttempted = override === "operator_force";
    const nonBypassable = bypassAttempted
      ? evaluation.blockers.find((b) => b.blocked_by === "external_approval_pending")
      : null;
    if (evaluation.blockers.length > 0 && (!bypassAttempted || nonBypassable)) {
      const first = nonBypassable || evaluation.blockers[0];
      // Y.10 (Y-D12 / Y-P12) — propagate the blocker's structured
      // remediation string through the ToolError so MCP callers see it
      // verbatim in the response envelope (mcp/lib/envelope.js).
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
    // left (the hasUsableAuthProfile auth.json read). Computing it before the override audit append
    // upholds "all fallible work BEFORE durable writes": a throw here can never orphan an
    // already-recorded governance.lifecycle.override event with no corresponding state transition.
    const hadUsableProfile = hasUsableAuthProfile(domain);
    const nextAuthContext = deriveAdvanceAuthContext(
      priorNucleus.auth_context,
      args.auth_status,
      hadUsableProfile,
      override === "operator_force",
    );

    if (override === "operator_force") {
      appendSessionEvent({
        target_domain: domain,
        kind: "governance.lifecycle.override",
        nucleus_hash: priorNucleus.nucleus_hash,
        payload: {
          from_state: fromState,
          to_state: toState,
          override: "operator_force",
          override_reason: overrideReason,
          blockers: evaluation.blockers,
          prior_nucleus_hash: priorNucleus.nucleus_hash,
        },
      });
    }

    const nextNucleus = buildSessionNucleus({
      target_domain: priorNucleus.target_domain,
      target_url: priorNucleus.scope_policy && priorNucleus.scope_policy.target_url,
      scope_policy: priorNucleus.scope_policy,
      egress_identity: priorNucleus.egress_identity,
      auth_context: nextAuthContext,
      operator_constraint: priorNucleus.operator_constraint,
      lifecycle_state: toState,
      // Preserve the repo session's pinned repo_hash across the lifecycle advance;
      // without it the nucleus loses repo_hash on the first transition and every
      // bob_repo_docker_run then crashes (null repo_hash -> buildImageTag null.slice).
      repo_hash: priorNucleus.repo_hash,
    });

    // Single-source-of-truth lifecycle write (Step 4). The two durable
    // lifecycle stores (session-nucleus.json and state.json) must never
    // disagree, even on a partial write. The historical ordering wrote the
    // nucleus FIRST and unconditionally, then ran the fallible verification
    // bootstrap; a throw there left the nucleus advanced while state.json
    // stayed at the prior state — a permanent split-brain. The fix:
    //
    //   1. Run ALL fallible work (prepareVerificationEntry, nextState) BEFORE
    //      any durable lifecycle-store write. prepareVerificationEntry throws
    //      at verification.js:342 (the sensitive-material re-scan) BEFORE the
    //      snapshot write at :343, so on a throw neither lifecycle store has
    //      been mutated. (The snapshot/archive are idempotently recomputable
    //      and are not lifecycle stores, so this still yields no-drift.)
    //   2. Write state.json, then the nucleus LAST.
    //   3. On ANY throw after the first durable write (state.json,
    //      nucleus, or the post-nucleus refreshVerificationManifest), restore
    //      BOTH files to their captured prior bytes — a symmetric rollback.
    //
    // The legacy `phase` field is refreshed via the back-compat projection so
    // unmigrated readers see the lifecycle move. The VERIFY transition also
    // triggers verification snapshot bootstrap so downstream evidence/grade
    // gates have the v2 attempt context the legacy phase machine used to bind.
    let verificationEntry = null;
    const nucleusPath = sessionNucleusPath(domain);
    const priorNucleusRaw = fs.existsSync(nucleusPath)
      ? fs.readFileSync(nucleusPath, "utf8")
      : null;
    try {
      const { raw, state } = readSessionStateStrict(domain);

      // (1) Fallible work FIRST — before any durable lifecycle-store write.
      if (toState === "VERIFY") {
        try {
          verificationEntry = require("./verification.js").prepareVerificationEntry(domain, state);
        } catch (verificationError) {
          if (!isSensitiveMaterialError(verificationError)) throw verificationError;
          // A persisted claim's evidence trips the sensitive-material scan and
          // has no operator-approved secret_evidence_bypass. The claim was
          // validated at write, so this is a recoverable fail-closed block, not
          // an unbypassable INTERNAL_ERROR. operator_force proceeds past it by
          // skipping the VERIFY snapshot bootstrap; otherwise surface a clean
          // STATE_CONFLICT naming the offending field so the operator can
          // re-record the finding with a secret_detection_bypass. Because this
          // throws BEFORE the durable writes below, neither lifecycle store is
          // mutated and the two stores still agree (no drift).
          if (override === "operator_force") {
            verificationEntry = null;
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
      // OPEN_FRONTIER is the one lifecycle state whose canonical legacy phase
      // (EVALUATE) is ambiguous: it is both the active evaluate window AND the
      // post-report evidence/re-mine window the operator re-enters from a
      // post-evaluation state. The evidence completion gate
      // (agent-run-completion.js) distinguishes them by the legacy phase —
      // OPEN_FRONTIER + EXPLORE is the evidence window, OPEN_FRONTIER + EVALUATE
      // is active evaluation. When we re-enter OPEN_FRONTIER from REPORT or
      // GRADE (a backwards move only the post-report re-mine takes), stamp the
      // legacy phase EXPLORE so that gate accepts the evidence run instead of
      // rejecting it as active evaluation (evidence_phase_mismatch).
      let derivedLegacyPhase = deriveLegacyPhaseFromLifecycleState(toState);
      if (toState === "OPEN_FRONTIER" && (fromState === "REPORT" || fromState === "GRADE")) {
        derivedLegacyPhase = "EXPLORE";
      }
      const nextState = {
        ...state,
        ...(verificationEntry ? verificationEntry.state_fields : {}),
        lifecycle_state: toState,
        // Mirror the NORMALIZED nucleus auth_status into state.json so the two lifecycle stores
        // can never disagree — buildSessionNucleus -> normalizeAuthContext is the single source of
        // truth for the value (e.g. it coerces a blank/legacy value to "pending"); mirroring the
        // pre-normalization derive output here would split-brain on any value the nucleus rewrites.
        auth_status: nextNucleus.auth_context.auth_status,
        ...(derivedLegacyPhase ? { phase: derivedLegacyPhase } : {}),
      };

      // (2)+(3) Durable writes with symmetric rollback. Capture prior bytes of
      // BOTH lifecycle stores, then write state.json, then the nucleus LAST. On
      // any throw after the first durable write, restore both files. The
      // restore is inlined here (not a nested closure) so it runs synchronously
      // inside the session lock — see test/session-state-store.test.js lock
      // containment guard.
      let firstDurableWriteDone = false;
      try {
        writeSessionStateDocument(domain, raw, nextState);
        firstDurableWriteDone = true;
        writeJsonDocument(nucleusPath, nextNucleus);
        if (verificationEntry && verificationEntry.schema_version === 2) {
          require("./verification.js").refreshVerificationManifest(domain, { throw_on_error: true });
        }
      } catch (writeError) {
        if (firstDurableWriteDone) {
          try {
            writeSessionStateDocument(domain, raw, state);
          } catch (_restoreStateError) {
            // best-effort symmetric rollback
          }
          if (priorNucleusRaw !== null) {
            try {
              writeFileAtomic(nucleusPath, priorNucleusRaw);
            } catch (_restoreNucleusError) {
              // best-effort symmetric rollback
            }
          }
        }
        throw writeError;
      }
    } catch (error) {
      if (!sessionStateMissing(error)) {
        throw error;
      }
      // Session predates init-session-with-state-store; there is no state.json
      // to keep in sync, so the nucleus is the sole lifecycle store. Advance it
      // directly (no symmetric rollback is needed — there is nothing to drift
      // against). Downstream readers fall back to the nucleus.
      writeJsonDocument(nucleusPath, nextNucleus);
    }

    // Compute the auth_status transition from the NORMALIZED nuclei (buildSessionNucleus already ran
    // normalizeAuthContext) BEFORE the advance event, so the canonical lifecycle.advanced event can
    // carry the transition ATOMICALLY with the lifecycle move (its single append is the durable
    // record of this advance — the transition is always reconstructable from this event alone).
    const priorAuthStatus = priorNucleus.auth_context && typeof priorNucleus.auth_context === "object"
      ? priorNucleus.auth_context.auth_status
      : undefined;
    const nextAuthStatus = nextNucleus.auth_context && typeof nextNucleus.auth_context === "object"
      ? nextNucleus.auth_context.auth_status
      : undefined;
    const authStatusChanged = nextAuthStatus !== priorAuthStatus;

    const advancedEvent = appendSessionEvent({
      target_domain: domain,
      kind: "governance.lifecycle.advanced",
      nucleus_hash: nextNucleus.nucleus_hash,
      payload: {
        from_state: fromState,
        to_state: toState,
        nucleus_hash: nextNucleus.nucleus_hash,
        prior_nucleus_hash: priorNucleus.nucleus_hash,
        // Auth-status provenance rides on the CANONICAL advance event so it is captured atomically
        // with the lifecycle move — the dedicated companion below is a best-effort index, not the
        // source of truth. from/to are the NORMALIZED nucleus values (null when absent).
        from_auth_status: priorAuthStatus == null ? null : priorAuthStatus,
        to_auth_status: nextAuthStatus == null ? null : nextAuthStatus,
        auth_status_changed: authStatusChanged,
      },
    });

    // Emit a dedicated, INDEXABLE governance.auth_context.replaced event whenever auth_status changed,
    // so the milestone's moves can be queried directly (operator authority vs profile-derived) without
    // scanning every advance. BEST-EFFORT: the advance is already durably committed and its provenance
    // is on the advanced event above, so a write failure HERE must not fail the tool and report an
    // error for a state change that did happen (mirrors the observational pipeline-events mirror
    // below). change-only keeps the log to real moves.
    if (authStatusChanged) {
      try {
        appendSessionEvent({
          target_domain: domain,
          kind: "governance.auth_context.replaced",
          nucleus_hash: nextNucleus.nucleus_hash,
          payload: {
            from_auth_status: priorAuthStatus == null ? null : priorAuthStatus,
            to_auth_status: nextAuthStatus == null ? null : nextAuthStatus,
            operator_forced: override === "operator_force",
            had_usable_profile: hadUsableProfile,
            explicit_auth_status_supplied:
              typeof args.auth_status === "string" && args.auth_status.trim() !== "",
          },
        });
      } catch (authEventError) {
        // Observability companion only — the advance and its provenance (on the advanced event) are
        // already durable, so a failure to append this index must not surface as a tool error.
        void authEventError;
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
      if (verificationEntry && verificationEntry.schema_version === 2) {
        eventFields.verification_attempt_id = verificationEntry.state_fields.verification_attempt_id;
        eventFields.verification_snapshot_hash = verificationEntry.state_fields.verification_snapshot_hash;
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
      event_id: advancedEvent.event_id,
      verification: verificationEntry
        ? {
          schema_version: verificationEntry.schema_version,
          attempt_id: verificationEntry.state_fields.verification_attempt_id,
          snapshot_hash: verificationEntry.state_fields.verification_snapshot_hash,
          archived: verificationEntry.archived != null,
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
    require("./sensitive-material.js").validateNoSensitiveMaterial(reason, "reason");
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
    const { currentBlockers } = require("./frontier-projections.js");
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
      const { readFrontierEvents } = require("./frontier-events.js");
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
      appendFrontierEvent({
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
