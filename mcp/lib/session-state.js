"use strict";

const fs = require("fs");
const {
  assertBoolean,
  assertNonEmptyString,
} = require("./validation.js");
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
const {
  buildGovernanceContext,
  buildGovernanceContextFromNucleus,
} = require("./governance-context.js");
const {
  assertHttpScopeDomain,
  validateHttpScanScope,
} = require("./scope.js");
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
  let domain;
  try {
    domain = assertHttpScopeDomain(args.target_domain);
  } catch (error) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, error.message || String(error));
  }
  const targetUrl = assertNonEmptyString(args.target_url, "target_url");
  try {
    validateHttpScanScope(targetUrl, domain);
  } catch (error) {
    throw new ToolError(ERROR_CODES.SCOPE_BLOCKED, error.message || String(error), error.details);
  }
  const deepMode = args.deep_mode == null ? false : assertBoolean(args.deep_mode, "deep_mode");
  let internalHostPolicy;
  try {
    internalHostPolicy = deriveBlockInternalHostsPolicy({
      checkpointMode: args.checkpoint_mode,
      blockInternalHosts: args.block_internal_hosts,
      allowInternalHosts: args.allow_internal_hosts,
      legacyDefault: false,
    });
  } catch (error) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, error.message || String(error));
  }
  const requestedEgressProfile = args.egress_profile == null
    ? "default"
    : assertNonEmptyString(args.egress_profile, "egress_profile");

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
    const state = buildInitialSessionState(sessionNucleus.target_domain, sessionNucleus.scope_policy.target_url, {
      deepMode,
      egressProfile,
      blockInternalHostsPolicy: sessionNucleus.scope_policy,
    });
    writeSessionStateDocument(domain, {}, state);
    safeAppendPipelineEventDirect(domain, "session_started", {
      lifecycle_state: state.lifecycle_state,
      source: "bob_init_session",
      deep_mode: state.deep_mode,
      checkpoint_mode: state.checkpoint_mode,
      block_internal_hosts: state.block_internal_hosts,
      block_internal_hosts_source: state.block_internal_hosts_source,
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
// reality instead of staying "pending" forever (the field has no other setter). Precedence:
//  (1) an explicit caller-supplied auth_status wins — honors `--no-auth` advancing with
//      "unauthenticated" and any explicit operator value;
//  (2) otherwise, if a usable auth profile is stored, the session is "authenticated";
//  (3) otherwise carry the prior status forward — only the explicit path (1) ever sets
//      "unauthenticated"; we never silently auto-downgrade.
// buildSessionNucleus -> normalizeAuthContext validates the resulting enum.
function deriveAdvanceAuthContext(priorAuthContext, explicitAuthStatus, hasProfile) {
  const prior = (priorAuthContext && typeof priorAuthContext === "object") ? priorAuthContext : {};
  let nextStatus;
  if (explicitAuthStatus != null) {
    nextStatus = explicitAuthStatus;
  } else if (hasProfile) {
    nextStatus = "authenticated";
  } else {
    nextStatus = prior.auth_status || "pending";
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

    if (evaluation.blockers.length > 0 && override !== "operator_force") {
      const first = evaluation.blockers[0];
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

    const nextAuthContext = deriveAdvanceAuthContext(
      priorNucleus.auth_context,
      args.auth_status,
      hasUsableAuthProfile(domain),
    );
    const nextNucleus = buildSessionNucleus({
      target_domain: priorNucleus.target_domain,
      target_url: priorNucleus.scope_policy && priorNucleus.scope_policy.target_url,
      scope_policy: priorNucleus.scope_policy,
      egress_identity: priorNucleus.egress_identity,
      auth_context: nextAuthContext,
      operator_constraint: priorNucleus.operator_constraint,
      lifecycle_state: toState,
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
        // Mirror the derived auth_status into state.json so it never disagrees with the
        // nucleus auth_context (the two lifecycle stores must stay in lockstep).
        auth_status: nextAuthContext.auth_status,
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

    const advancedEvent = appendSessionEvent({
      target_domain: domain,
      kind: "governance.lifecycle.advanced",
      nucleus_hash: nextNucleus.nucleus_hash,
      payload: {
        from_state: fromState,
        to_state: toState,
        nucleus_hash: nextNucleus.nucleus_hash,
        prior_nucleus_hash: priorNucleus.nucleus_hash,
      },
    });

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

function reportWritten(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const reportPath = require("./paths.js").reportMarkdownPath(domain);
  if (!fs.existsSync(reportPath)) {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `report.md is not present at ${reportPath}; call bounty_report_written only after writing the report`,
    );
  }
  const stats = fs.statSync(reportPath);
  const { state } = readSessionStateStrict(domain);
  safeAppendPipelineEventDirect(domain, "report_written", {
    status: "written",
    source: "bounty_report_written",
    counts: {
      report_size_bytes: stats.size,
    },
  }, buildGovernanceContext(state));
  return JSON.stringify({
    version: 1,
    report_written: true,
    path: reportPath,
    size_bytes: stats.size,
    mtime: stats.mtime.toISOString(),
  });
}

module.exports = {
  advanceSession,
  assertBlockInternalHostsCompatibleWithEgress,
  clearOperatorNote,
  clearTerminalBlock,
  initSession,
  reportWritten,
  resolveAndAssertSessionEgressIdentity,
  setOperatorNote,
  readSessionState,
  readStateSummary,
};
