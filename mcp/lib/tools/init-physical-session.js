"use strict";

const fs = require("fs");
const {
  ERROR_CODES,
  ToolError,
} = require("../envelope.js");
const {
  buildSessionNucleus,
  sessionNucleusFromState,
} = require("../governance-contracts.js");
const {
  readVerifiedSessionNucleus,
} = require("../governance-store.js");
const {
  buildGovernanceContextFromNucleus,
} = require("../governance-context.js");
const {
  hashCanonicalJson,
} = require("../verification-contracts.js");
const {
  sessionDir,
  sessionNucleusPath,
  physicalSessionBootstrapPath,
} = require("../paths.js");
const {
  isSessionDirEffectivelyEmpty,
  withSessionLock,
} = require("../storage.js");
const {
  writeJsonDocument,
} = require("../fabric-common.js");
const {
  buildInitialSessionState,
  publicSessionState,
} = require("../session-state-contracts.js");
const {
  readSessionStateStrict,
  writeSessionStateDocument,
} = require("../session-state-store.js");
const {
  appendSessionEvent,
} = require("../session-events.js");
const {
  safeAppendPipelineEventDirect,
} = require("../pipeline-events.js");
const {
  ensureHandoffSigningKey,
  ensureHandoffKeypair,
} = require("../handoff-signing-key.js");
const {
  buildPhysicalOnlySessionBootstrapPayload,
  projectPhysicalScopeNucleusAxis,
  projectVerifiedPhysicalScopeImport,
} = require("../physical-scope.js");
const {
  normalizeOpaqueRef,
} = require("../physical-quantities.js");
const {
  derivePhysicalSessionIdentity,
} = require("../physical-session-identity.js");
const {
  resolvePhysicalSessionBootstrapImport,
} = require("../physical-session-runtime.js");
const {
  buildPendingPhysicalSessionBootstrapJournal,
  completePhysicalSessionBootstrapJournal,
  readVerifiedPhysicalSessionBootstrapJournal,
  writePhysicalSessionBootstrapJournal,
} = require("../physical-session-journal.js");

const PHYSICAL_SESSION_BOOTSTRAP_VERSION = 1;

function physicalEgressProfile() {
  return Object.freeze({
    name: "default",
    region: null,
    proxy_configured: false,
    egress_profile_identity_hash: null,
    egress_profile_identity_version: null,
    egress_profile_identity_source: Object.freeze({
      proxy_url_source: "none",
      proxy_env_var: null,
      proxy_url_redacted: null,
      resolved_proxy: null,
    }),
  });
}

const SAFE_RUNTIME_ERRORS = new Map([
  [
    "physical_bootstrap_runtime_unconfigured",
    "physical session bootstrap resolver is not configured",
  ],
  [
    "physical_bootstrap_runtime_contract_invalid",
    "physical session bootstrap resolver contract is invalid",
  ],
  [
    "physical_bootstrap_runtime_reentrant",
    "physical session bootstrap resolver invocation is already in progress",
  ],
  [
    "physical_bootstrap_runtime_unavailable",
    "physical session bootstrap resolver is unavailable",
  ],
]);

function asToolError(error, { privateBoundary = false } = {}) {
  if (error instanceof ToolError) return error;
  const runtimeMessage = SAFE_RUNTIME_ERRORS.get(error && error.code);
  if (runtimeMessage) {
    // Do not trust an exception message merely because it carries a known
    // code: a private resolver/verifier callback can spoof both properties.
    return new ToolError(ERROR_CODES.STATE_CONFLICT, runtimeMessage, {
      physical_bootstrap_error_code: error.code,
    });
  }
  if (privateBoundary) {
    // The opaque ref is the only caller-authored input. Everything behind its
    // resolution (envelope, registry, authority/trust callbacks, provider
    // objects) is private integration state and may contain paths, signatures,
    // policy material, or provider diagnostics. Never reflect its exception.
    return new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      "physical session bootstrap import verification failed",
      { physical_bootstrap_error_code: "physical_bootstrap_import_verification_failed" },
    );
  }
  return new ToolError(ERROR_CODES.INVALID_ARGUMENTS, error && error.message ? error.message : String(error), {
    physical_bootstrap_error_code: error && error.code ? error.code : "physical_bootstrap_invalid",
  });
}

function safePhysicalScopeView(axis) {
  return {
    axis_digest: axis.axis_digest,
    policy_digest: axis.policy_digest,
    projection_digest: axis.projection_digest,
    provenance_digest: axis.provenance_digest,
    authority_epoch: axis.authority_epoch,
    revocation_generation: axis.revocation_generation,
  };
}

function bootstrapResponse(journal, { created, nucleusHash = journal.nucleus_hash }) {
  return JSON.stringify({
    version: PHYSICAL_SESSION_BOOTSTRAP_VERSION,
    created: created === true,
    target_domain: journal.target_domain,
    session_id: journal.session_id,
    scope_axes: ["physical"],
    nucleus_hash: nucleusHash,
    physical_scope: safePhysicalScopeView(journal.physical_scope),
  });
}

function assertExistingBootstrap(identity) {
  const journal = readVerifiedPhysicalSessionBootstrapJournal(identity.target_domain);
  if (journal.physical_scope_import_ref_digest !== identity.physical_scope_import_ref_digest) {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `Physical session identity collision for ${identity.target_domain}`,
      { physical_bootstrap_error_code: "physical_bootstrap_identity_conflict" },
    );
  }
  if (journal.status !== "complete") {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `Physical session bootstrap requires operator recovery for ${identity.target_domain}`,
      {
        physical_bootstrap_error_code: "physical_bootstrap_recovery_required",
        bootstrap_journal_status: journal.status,
      },
    );
  }
  let nucleus;
  let state;
  try {
    nucleus = readVerifiedSessionNucleus(identity.target_domain);
    ({ state } = readSessionStateStrict(identity.target_domain));
  } catch (error) {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `Completed physical session bootstrap is not rehydratable for ${identity.target_domain}`,
      {
        physical_bootstrap_error_code: "physical_bootstrap_rehydration_failed",
        reason: error.message || String(error),
      },
    );
  }
  const rehydrated = sessionNucleusFromState(state);
  const physicalOnly = state.target_url == null
    && state.target_repo == null
    && (!Array.isArray(state.target_contracts) || state.target_contracts.length === 0)
    && state.physical_scope != null;
  const driftChecks = {
    physical_only: physicalOnly,
    target_domain_match: nucleus.target_domain === identity.target_domain,
    state_nucleus_match: rehydrated.nucleus_hash === nucleus.nucleus_hash,
    nucleus_axis_match: nucleus.physical_scope != null
      && nucleus.physical_scope.axis_digest === journal.physical_scope.axis_digest,
    state_axis_match: state.physical_scope != null
      && state.physical_scope.axis_digest === journal.physical_scope.axis_digest,
  };
  if (Object.values(driftChecks).some((matches) => matches !== true)) {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `Completed physical session bootstrap has canonical state drift for ${identity.target_domain}`,
      {
        physical_bootstrap_error_code: "physical_bootstrap_state_drift",
        drift_checks: driftChecks,
      },
    );
  }
  return bootstrapResponse(journal, { created: false, nucleusHash: nucleus.nucleus_hash });
}

function createPhysicalBootstrap(identity) {
  return withSessionLock(identity.target_domain, () => {
  let resolved;
  let projection;
  let bootstrapPayload;
  let physicalScope;
  try {
    resolved = resolvePhysicalSessionBootstrapImport(identity.physical_scope_import_ref);
    const sessionNamespace = normalizeOpaqueRef(
      resolved.session_namespace,
      "physical_only_bootstrap.session_namespace",
      { prefix: "session-namespace" },
    );
    // This is the sole replay-consuming operation. Everything before it is
    // argument/runtime validation; everything durable after it is guarded by a
    // pending journal. A process death inside this call remains deliberately
    // fail-closed because the replay store cannot yet rehydrate a projection.
    projection = projectVerifiedPhysicalScopeImport(
      resolved.envelope,
      resolved.effect_template_registry,
      resolved.verifier,
    );
    bootstrapPayload = buildPhysicalOnlySessionBootstrapPayload(
      projection,
      resolved.verifier,
      {
        version: PHYSICAL_SESSION_BOOTSTRAP_VERSION,
        session_id: identity.session_id,
        session_namespace: sessionNamespace,
      },
    );
    physicalScope = projectPhysicalScopeNucleusAxis(projection, resolved.verifier);
  } catch (error) {
    throw asToolError(error, { privateBoundary: true });
  }

  const scopePolicy = {
    target_domain: identity.target_domain,
    checkpoint_mode: "normal",
    block_internal_hosts: false,
    block_internal_hosts_source: "mode_default",
  };
  const nucleus = buildSessionNucleus({
    target_domain: identity.target_domain,
    scope_policy: scopePolicy,
    physical_scope: physicalScope,
    egress_identity: {
      egress_profile: "default",
      egress_region: null,
      proxy_configured: false,
      egress_profile_identity_hash: null,
      egress_profile_identity_version: null,
      egress_profile_identity_source: physicalEgressProfile().egress_profile_identity_source,
    },
    auth_context: { auth_status: "pending" },
    operator_constraint: { handoff_provenance_required: true },
    lifecycle_state: "SETUP",
  });
  const state = buildInitialSessionState(identity.target_domain, null, {
    egressProfile: physicalEgressProfile(),
    blockInternalHostsPolicy: nucleus.scope_policy,
    physicalScope,
  });
  const rehydrated = sessionNucleusFromState(state);
  if (rehydrated.nucleus_hash !== nucleus.nucleus_hash) {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      "Physical session state does not rehydrate to its canonical nucleus",
      { physical_bootstrap_error_code: "physical_bootstrap_nucleus_drift" },
    );
  }
  const sessionNamespaceDigest = hashCanonicalJson({
    domain: "hacker-bob/physical-session-namespace/v1",
    session_namespace: bootstrapPayload.session_namespace,
  });
  const bootstrapBindingDigest = hashCanonicalJson({
    domain: "hacker-bob/physical-session-bootstrap-binding/v1",
    version: PHYSICAL_SESSION_BOOTSTRAP_VERSION,
    target_domain: identity.target_domain,
    session_id: identity.session_id,
    physical_scope_import_ref_digest: identity.physical_scope_import_ref_digest,
    session_namespace_digest: sessionNamespaceDigest,
  });
  const pending = buildPendingPhysicalSessionBootstrapJournal({
    target_domain: identity.target_domain,
    session_id: identity.session_id,
    physical_scope_import_ref_digest: identity.physical_scope_import_ref_digest,
    session_namespace_digest: sessionNamespaceDigest,
    bootstrap_binding_digest: bootstrapBindingDigest,
    bootstrap_payload_digest: bootstrapPayload.bootstrap_payload_digest,
    signed_import_digest: projection.provenance.signed_import_digest,
    replay_reservation_ref: projection.provenance.replay_reservation_ref,
    replay_reservation_receipt_digest: projection.provenance.replay_reservation_receipt_digest,
    nucleus_hash: nucleus.nucleus_hash,
    scope_policy_hash: hashCanonicalJson(nucleus.scope_policy),
    state_hash: hashCanonicalJson(publicSessionState(state)),
    physical_scope: physicalScope,
  });

  // Pending is the first local durable write after replay consumption. Any
  // later failure leaves authority fail-closed until an operator recovery path
  // can reconcile the exact replay reservation.
  writePhysicalSessionBootstrapJournal(identity.target_domain, pending);
  writeJsonDocument(sessionNucleusPath(identity.target_domain), nucleus);
  writeSessionStateDocument(identity.target_domain, {}, state);
  ensureHandoffSigningKey(identity.target_domain);
  ensureHandoffKeypair(identity.target_domain);
  appendSessionEvent({
    target_domain: identity.target_domain,
    kind: "governance.session.initialized",
    nucleus_hash: nucleus.nucleus_hash,
    payload: {
      bootstrap_kind: "physical_only",
      nucleus_hash: nucleus.nucleus_hash,
      scope_policy_hash: pending.scope_policy_hash,
      egress_identity_hash: hashCanonicalJson(nucleus.egress_identity),
      auth_context_hash: hashCanonicalJson(nucleus.auth_context),
      operator_constraint_hash: hashCanonicalJson(nucleus.operator_constraint),
      physical_scope_axis_digest: physicalScope.axis_digest,
    },
    source: { artifact: "physical-session-bootstrap.json", tool: "bob_init_physical_session" },
  });
  safeAppendPipelineEventDirect(identity.target_domain, "session_started", {
    lifecycle_state: "SETUP",
    source: "bob_init_physical_session",
    bootstrap_kind: "physical_only",
    checkpoint_mode: state.checkpoint_mode,
    block_internal_hosts: state.block_internal_hosts,
    block_internal_hosts_source: state.block_internal_hosts_source,
  }, buildGovernanceContextFromNucleus(nucleus));
  const complete = completePhysicalSessionBootstrapJournal(pending);
  writePhysicalSessionBootstrapJournal(identity.target_domain, complete);
  return bootstrapResponse(complete, { created: true });
  });
}

function handler(args = {}) {
  let identity;
  try {
    identity = derivePhysicalSessionIdentity(args.physical_scope_import_ref);
  } catch (error) {
    throw asToolError(error);
  }
  return withSessionLock(identity.target_domain, () => {
    const dir = sessionDir(identity.target_domain);
    if (fs.existsSync(physicalSessionBootstrapPath(identity.target_domain))) {
      return assertExistingBootstrap(identity);
    }
    if (!isSessionDirEffectivelyEmpty(dir)) {
      throw new ToolError(
        ERROR_CODES.STATE_CONFLICT,
        `Physical session directory is not empty: ${dir}`,
        { physical_bootstrap_error_code: "physical_bootstrap_directory_conflict" },
      );
    }
    return createPhysicalBootstrap(identity);
  });
}

module.exports = Object.freeze({
  name: "bob_init_physical_session",
  description:
    "Initialize an effect-free physical-only session from an opaque authenticated scope-import reference. "
    + "Derives the session id, writes only Bob governance state, and never dispatches hardware, RF, network, browser, broker, or provider effects.",
  inputSchema: {
    type: "object",
    properties: {
      physical_scope_import_ref: {
        type: "string",
        pattern: "^physical-scope-import:[A-Za-z0-9][A-Za-z0-9._:-]{0,190}$",
        description:
          "Opaque reference resolved by the operator-configured private runtime. Raw policy, authority, signatures, asset metadata, effects, paths, target ids, and namespaces are not accepted.",
      },
    },
    required: ["physical_scope_import_ref"],
    additionalProperties: false,
  },
  handler,
  role_bundles: ["orchestrator"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [
    "physical-session-bootstrap.json",
    "session-nucleus.json",
    "state.json",
    "session-events.jsonl",
    "pipeline-events.jsonl",
    ".handoff-signing-key.json",
    ".handoff-signing-key-ed25519.json",
    "handoff-signing-pubkey.json",
  ],
  effect_surface: [],
});
