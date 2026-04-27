"use strict";

const fs = require("fs");
const {
  AUTH_STATUS_VALUES,
  PHASE_VALUES,
  SESSION_PUBLIC_STATE_FIELDS,
} = require("./constants.js");
const {
  assertEnumValue,
  assertInteger,
  assertNonEmptyString,
  normalizeStringArray,
} = require("./validation.js");
const {
  sessionDir,
  statePath,
} = require("./paths.js");
const {
  isSessionDirEffectivelyEmpty,
  withSessionLock,
  writeFileAtomic,
} = require("./storage.js");
const {
  ERROR_CODES,
  ToolError,
} = require("./envelope.js");
const {
  safeAppendPipelineEventDirect,
} = require("./pipeline-analytics.js");
const {
  computeHuntToChainGate,
  formatTransitionBlockers,
} = require("./phase-gates.js");

function buildInitialSessionState(domain, targetUrl) {
  return {
    target: domain,
    target_url: targetUrl,
    phase: "RECON",
    hunt_wave: 0,
    pending_wave: null,
    total_findings: 0,
    explored: [],
    dead_ends: [],
    waf_blocked_endpoints: [],
    lead_surface_ids: [],
    scope_exclusions: [],
    hold_count: 0,
    auth_status: "pending",
  };
}

function publicSessionState(state) {
  return SESSION_PUBLIC_STATE_FIELDS.reduce((result, field) => {
    result[field] = state[field];
    return result;
  }, {});
}

function compactSessionState(state) {
  return {
    target: state.target,
    phase: state.phase,
    hunt_wave: state.hunt_wave,
    pending_wave: state.pending_wave,
    total_findings: state.total_findings,
    explored_count: (state.explored || []).length,
    dead_ends_count: (state.dead_ends || []).length,
    waf_blocked_count: (state.waf_blocked_endpoints || []).length,
    lead_surface_ids: state.lead_surface_ids || [],
    hold_count: state.hold_count,
    auth_status: state.auth_status,
  };
}

function normalizeSessionStateDocument(document, requestedDomain) {
  if (document == null || typeof document !== "object" || Array.isArray(document)) {
    throw new Error("expected object");
  }

  if (document.target != null) {
    assertNonEmptyString(document.target, "target");
  }

  return {
    target: requestedDomain,
    target_url: assertNonEmptyString(document.target_url, "target_url"),
    phase: assertEnumValue(document.phase, PHASE_VALUES, "phase"),
    hunt_wave: document.hunt_wave == null
      ? 0
      : assertInteger(document.hunt_wave, "hunt_wave", { min: 0 }),
    pending_wave: document.pending_wave == null
      ? null
      : assertInteger(document.pending_wave, "pending_wave", { min: 1 }),
    total_findings: document.total_findings == null
      ? 0
      : assertInteger(document.total_findings, "total_findings", { min: 0 }),
    explored: normalizeStringArray(document.explored, "explored"),
    dead_ends: normalizeStringArray(document.dead_ends, "dead_ends"),
    waf_blocked_endpoints: normalizeStringArray(document.waf_blocked_endpoints, "waf_blocked_endpoints"),
    lead_surface_ids: normalizeStringArray(document.lead_surface_ids, "lead_surface_ids"),
    scope_exclusions: normalizeStringArray(document.scope_exclusions, "scope_exclusions"),
    hold_count: document.hold_count == null
      ? 0
      : assertInteger(document.hold_count, "hold_count", { min: 0 }),
    auth_status: document.auth_status == null
      ? "pending"
      : assertEnumValue(document.auth_status, AUTH_STATUS_VALUES, "auth_status"),
  };
}

function readSessionStateStrict(domain) {
  const normalizedDomain = assertNonEmptyString(domain, "target_domain");
  const filePath = statePath(normalizedDomain);

  if (!fs.existsSync(filePath)) {
    throw new Error(`Missing session state: ${filePath}`);
  }

  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch (error) {
    throw new Error(`Malformed session state: ${filePath} (${error.message || String(error)})`);
  }

  try {
    return {
      dir: sessionDir(normalizedDomain),
      path: filePath,
      raw: parsed,
      state: normalizeSessionStateDocument(parsed, normalizedDomain),
    };
  } catch (error) {
    throw new Error(`Malformed session state: ${filePath} (${error.message || String(error)})`);
  }
}

function composeSessionStateDocument(rawDocument, state) {
  return {
    ...rawDocument,
    ...publicSessionState(state),
  };
}

function writeSessionStateDocument(domain, rawDocument, state) {
  const filePath = statePath(domain);
  const nextDocument = composeSessionStateDocument(rawDocument, state);
  writeFileAtomic(filePath, `${JSON.stringify(nextDocument, null, 2)}\n`);
  return nextDocument;
}

function initSession(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const targetUrl = assertNonEmptyString(args.target_url, "target_url");

  return withSessionLock(domain, () => {
    const dir = sessionDir(domain);
    const filePath = statePath(domain);

    if (fs.existsSync(filePath)) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Session already initialized: ${filePath}`);
    }
    if (!isSessionDirEffectivelyEmpty(dir)) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Session directory is not empty: ${dir}`);
    }

    const state = buildInitialSessionState(domain, targetUrl);
    writeFileAtomic(filePath, `${JSON.stringify(state, null, 2)}\n`);
    safeAppendPipelineEventDirect(domain, "session_started", {
      phase: state.phase,
      source: "bounty_init_session",
    });

    return JSON.stringify({
      version: 1,
      created: true,
      session_dir: dir,
      state: publicSessionState(state),
    });
  });
}

function readSessionState(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const { state } = readSessionStateStrict(domain);
  return JSON.stringify({
    version: 1,
    state: publicSessionState(state),
  });
}

function readStateSummary(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const { state } = readSessionStateStrict(domain);
  return JSON.stringify({
    version: 1,
    state: compactSessionState(state),
  });
}

function transitionPhase(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const toPhase = assertEnumValue(args.to_phase, PHASE_VALUES, "to_phase");

  return withSessionLock(domain, () => {
    const { raw, state } = readSessionStateStrict(domain);
    const fromPhase = state.phase;
    const allowedTransitions = {
      RECON: ["AUTH"],
      AUTH: ["HUNT"],
      HUNT: ["CHAIN"],
      CHAIN: ["VERIFY"],
      VERIFY: ["GRADE"],
      GRADE: ["REPORT", "HUNT"],
      REPORT: ["EXPLORE"],
      EXPLORE: ["CHAIN"],
    };

    if (!(allowedTransitions[fromPhase] || []).includes(toPhase)) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Invalid phase transition: ${fromPhase} -> ${toPhase}`);
    }

    let overrideReason = null;
    if (args.override_reason != null) {
      if (fromPhase !== "HUNT" || toPhase !== "CHAIN") {
        throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "override_reason is only allowed for HUNT -> CHAIN");
      }
      if (typeof args.override_reason !== "string" || !args.override_reason.trim()) {
        throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "override_reason must be a non-empty string");
      }
      overrideReason = args.override_reason.trim();
      if (overrideReason.length < 20) {
        throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "override_reason must be at least 20 characters");
      }
    }

    let nextAuthStatus = state.auth_status;
    if (fromPhase === "AUTH" && toPhase === "HUNT") {
      if (args.auth_status == null) {
        throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "auth_status is required for AUTH -> HUNT");
      }
      nextAuthStatus = assertEnumValue(
        args.auth_status,
        AUTH_STATUS_VALUES.filter((value) => value !== "pending"),
        "auth_status",
      );
    } else if (args.auth_status != null) {
      throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "auth_status is only allowed for AUTH -> HUNT");
    }

    const transitionGate = fromPhase === "HUNT" && toPhase === "CHAIN"
      ? computeHuntToChainGate(domain, state)
      : null;
    if (transitionGate && transitionGate.transition_blockers.length > 0 && overrideReason == null) {
      throw new ToolError(
        ERROR_CODES.STATE_CONFLICT,
        `HUNT -> CHAIN blocked: ${formatTransitionBlockers(transitionGate.transition_blockers)}`,
      );
    }

    const nextState = {
      ...state,
      phase: toPhase,
      auth_status: nextAuthStatus,
      hold_count: fromPhase === "GRADE" && toPhase === "HUNT"
        ? state.hold_count + 1
        : state.hold_count,
    };

    writeSessionStateDocument(domain, raw, nextState);
    const eventFields = {
      from_phase: fromPhase,
      to_phase: toPhase,
      phase: toPhase,
      status: "transitioned",
      source: "bounty_transition_phase",
      counts: {
        hold_count: nextState.hold_count,
      },
    };
    if (overrideReason != null) {
      eventFields.override = true;
      eventFields.override_reason = overrideReason;
      eventFields.counts.transition_blockers = transitionGate
        ? transitionGate.transition_blockers.length
        : 0;
    }
    safeAppendPipelineEventDirect(domain, "phase_transitioned", eventFields);
    return JSON.stringify({
      version: 1,
      transitioned: true,
      from_phase: fromPhase,
      to_phase: toPhase,
      state: compactSessionState(nextState),
    });
  });
}

module.exports = {
  buildInitialSessionState,
  compactSessionState,
  composeSessionStateDocument,
  initSession,
  normalizeSessionStateDocument,
  publicSessionState,
  readSessionState,
  readSessionStateStrict,
  readStateSummary,
  transitionPhase,
  writeSessionStateDocument,
};
