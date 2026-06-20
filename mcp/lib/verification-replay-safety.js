"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const {
  VERIFICATION_REPLAY_PURPOSE_VALUES,
  VERIFICATION_ROUND_VALUES,
} = require("./constants.js");
const {
  assertEnumValue,
  assertNonEmptyString,
  parseFindingId,
} = require("./validation.js");
const {
  verificationReplayLeaseDir,
} = require("./paths.js");
const {
  readJsonFile,
  writeFileAtomic,
  writeFileExclusiveAtomic,
} = require("./storage.js");
const {
  ERROR_CODES,
  ToolError,
} = require("./envelope.js");
const {
  CAPABILITY_PACKS,
  DEFAULT_REPLAY_SAFETY,
} = require("./capability-packs.js");
const {
  isPlainObject,
} = require("./verification-contracts.js");
const {
  requireFreshVerificationState,
} = require("./verification-snapshot-contracts.js");
const {
  safeAppendPipelineEventDirect,
} = require("./pipeline-events.js");
const {
  safeGovernanceContextForDomain,
} = require("./governance-context.js");

const VERIFICATION_REPLAY_LEASE_TTL_MS = 15 * 60 * 1000;
const VERIFICATION_REPLAY_LEASE_HEARTBEAT_MS = Math.max(1_000, Math.floor(VERIFICATION_REPLAY_LEASE_TTL_MS / 3));

function safeAppendPipelineEvent(domain, type, fields, governanceContext) {
  try {
    safeAppendPipelineEventDirect(domain, type, fields, governanceContext);
  } catch {}
}

function governanceContextForDomain(domain) {
  return safeGovernanceContextForDomain(domain);
}

function replaySafetyForTool(toolName) {
  if (toolName === "bob_repo_docker_run") {
    return {
      capability_pack: "oss_native_code",
      replay_safety: DEFAULT_REPLAY_SAFETY,
    };
  }
  // bob_http_confirm is a web live-request tool exposed to verifier/evidence
  // bundles; govern its VERIFY probes under the SAME replay policy as the web
  // replay tool (bob_http_scan) so concurrent rounds can't add ungoverned live
  // requests. Resolve it via the pack whose replay_tool is bob_http_scan.
  const lookupName = toolName === "bob_http_confirm" ? "bob_http_scan" : toolName;
  for (const pack of Object.values(CAPABILITY_PACKS)) {
    if (!pack || !pack.verifier) continue;
    if (pack.verifier.replay_tool === lookupName || (pack.evidence && pack.evidence.runner === lookupName)) {
      return {
        capability_pack: pack.id,
        replay_safety: pack.verifier.replay_safety || DEFAULT_REPLAY_SAFETY,
      };
    }
  }
  return null;
}

function normalizeReplayContext(ctx) {
  if (!isPlainObject(ctx)) return null;
  const purpose = typeof ctx.purpose === "string" ? ctx.purpose.trim() : "";
  if (!VERIFICATION_REPLAY_PURPOSE_VALUES.includes(purpose)) {
    return { purpose, active: false };
  }
  try {
    return {
      active: true,
      purpose,
      verification_attempt_id: assertNonEmptyString(ctx.verification_attempt_id, "replay_context.verification_attempt_id"),
      verification_snapshot_hash: assertNonEmptyString(ctx.verification_snapshot_hash, "replay_context.verification_snapshot_hash"),
      round: ctx.round == null ? null : assertEnumValue(ctx.round, VERIFICATION_ROUND_VALUES, "replay_context.round"),
      finding_id: ctx.finding_id == null ? null : parseFindingId(ctx.finding_id, "replay_context.finding_id"),
    };
  } catch (error) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, error.message || String(error));
  }
}

function replayLeaseKey({ targetDomain, capabilityPack, context, leaseScope }) {
  if (leaseScope === "none") return null;
  if (leaseScope === "attempt_pack") {
    return `${targetDomain}:${context.verification_attempt_id}:${capabilityPack}`;
  }
  if (leaseScope === "finding") {
    if (!context.finding_id) {
      throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "replay_context.finding_id is required for finding-scoped replay leases");
    }
    return `${targetDomain}:${context.verification_attempt_id}:${context.finding_id}`;
  }
  throw new ToolError(ERROR_CODES.INTERNAL_ERROR, `Unsupported replay lease_scope: ${leaseScope}`);
}

function replayLeaseFileName(key) {
  return `${crypto.createHash("sha256").update(key).digest("hex")}.json`;
}

function replayLeasePath(targetDomain, key) {
  return path.join(verificationReplayLeaseDir(targetDomain), replayLeaseFileName(key));
}

function parseLeaseTime(value) {
  const ms = Date.parse(value);
  return Number.isFinite(ms) ? ms : 0;
}

function isProcessAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return Boolean(error && error.code === "EPERM");
  }
}

function isReplayLeaseExpired(lease, nowMs = Date.now()) {
  if (!lease || !isPlainObject(lease)) return true;
  const expiresAtMs = parseLeaseTime(lease.expires_at);
  if (!expiresAtMs) return true;
  return expiresAtMs <= nowMs;
}

function isReplayLeaseStale(lease, nowMs = Date.now()) {
  if (!lease || !isPlainObject(lease)) return true;
  if (!isReplayLeaseExpired(lease, nowMs)) return false;
  return !isProcessAlive(lease.pid);
}

function readReplayLeaseFile(filePath) {
  try {
    return readJsonFile(filePath, { label: path.basename(filePath) });
  } catch {
    return null;
  }
}

function cleanupStaleReplayLease(filePath, nowMs = Date.now()) {
  const lease = readReplayLeaseFile(filePath);
  if (!isReplayLeaseStale(lease, nowMs)) return false;
  try {
    fs.rmSync(filePath, { force: true });
    return true;
  } catch {
    return false;
  }
}

function sameReplayLeaseOwner(left, right) {
  return Boolean(
    left &&
    right &&
    left.lease_id === right.lease_id &&
    left.acquired_at === right.acquired_at &&
    left.pid === right.pid
  );
}

function refreshReplayLease(lease) {
  if (!lease || !lease.filePath || !lease.metadata) return false;
  const current = readReplayLeaseFile(lease.filePath);
  if (!sameReplayLeaseOwner(current, lease.metadata)) return false;
  const refreshed = {
    ...current,
    expires_at: new Date(Date.now() + VERIFICATION_REPLAY_LEASE_TTL_MS).toISOString(),
  };
  try {
    writeFileAtomic(lease.filePath, `${JSON.stringify(refreshed, null, 2)}\n`);
    lease.metadata = refreshed;
    return true;
  } catch {
    return false;
  }
}

function startReplayLeaseHeartbeat(lease) {
  if (!lease || !lease.filePath || !lease.metadata) return null;
  const timer = setInterval(() => {
    refreshReplayLease(lease);
  }, VERIFICATION_REPLAY_LEASE_HEARTBEAT_MS);
  if (typeof timer.unref === "function") timer.unref();
  return timer;
}

function releaseReplayLease(lease) {
  if (!lease || !lease.filePath || !lease.metadata) return;
  const current = readReplayLeaseFile(lease.filePath);
  if (!sameReplayLeaseOwner(current, lease.metadata)) return;
  try { fs.rmSync(lease.filePath, { force: true }); } catch {}
}

function buildReplayLeaseMetadata({
  targetDomain,
  key,
  toolName,
  policy,
  leaseScope,
  context,
  nowMs = Date.now(),
}) {
  const acquiredAt = new Date(nowMs).toISOString();
  return {
    version: 1,
    lease_id: crypto.createHash("sha256").update(key).digest("hex"),
    target_domain: targetDomain,
    tool: toolName,
    capability_pack: policy.capability_pack,
    lease_scope: leaseScope,
    replay_purpose: context.purpose,
    verification_attempt_id: context.verification_attempt_id,
    verification_snapshot_hash: context.verification_snapshot_hash,
    round: context.round,
    finding_id: context.finding_id,
    acquired_at: acquiredAt,
    expires_at: new Date(nowMs + VERIFICATION_REPLAY_LEASE_TTL_MS).toISOString(),
    pid: process.pid,
  };
}

function acquireReplayLease({
  targetDomain,
  key,
  toolName,
  policy,
  leaseScope,
  context,
}) {
  const dir = verificationReplayLeaseDir(targetDomain);
  fs.mkdirSync(dir, { recursive: true });
  const filePath = replayLeasePath(targetDomain, key);
  const keyHash = crypto.createHash("sha256").update(key).digest("hex");
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const metadata = buildReplayLeaseMetadata({
      targetDomain,
      key,
      toolName,
      policy,
      leaseScope,
      context,
    });
    const payload = `${JSON.stringify(metadata, null, 2)}\n`;
    if (writeFileExclusiveAtomic(filePath, payload)) {
      return { filePath, metadata };
    }
    const existing = readReplayLeaseFile(filePath);
    if (cleanupStaleReplayLease(filePath)) continue;
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Replay lease busy for ${leaseScope}: ${keyHash}`, {
      active_lease: existing && isPlainObject(existing)
        ? {
          lease_id: existing.lease_id || keyHash,
          tool: existing.tool || null,
          capability_pack: existing.capability_pack || policy.capability_pack,
          replay_purpose: existing.replay_purpose || null,
          verification_attempt_id: existing.verification_attempt_id || null,
          round: existing.round || null,
          finding_id: existing.finding_id || null,
          acquired_at: existing.acquired_at || null,
          expires_at: existing.expires_at || null,
        }
        : null,
    });
  }
  throw new ToolError(ERROR_CODES.STATE_CONFLICT, `Replay lease busy for ${leaseScope}: ${keyHash}`);
}

function listActiveReplayLeases(targetDomain) {
  const dir = verificationReplayLeaseDir(targetDomain);
  if (!fs.existsSync(dir)) return [];
  const active = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (!entry.isFile() || !entry.name.endsWith(".json")) continue;
    const filePath = path.join(dir, entry.name);
    const lease = readReplayLeaseFile(filePath);
    if (isReplayLeaseStale(lease)) {
      cleanupStaleReplayLease(filePath);
      continue;
    }
    active.push({
      lease_id: lease.lease_id || entry.name.replace(/\.json$/, ""),
      tool: lease.tool || null,
      capability_pack: lease.capability_pack || null,
      lease_scope: lease.lease_scope || null,
      purpose: lease.replay_purpose || null,
      replay_purpose: lease.replay_purpose || null,
      verification_attempt_id: lease.verification_attempt_id || null,
      round: lease.round || null,
      finding_id: lease.finding_id || null,
      acquired_at: lease.acquired_at || null,
      expires_at: lease.expires_at || null,
    });
  }
  return active.sort((a, b) => a.lease_id.localeCompare(b.lease_id));
}

function assertReplayContextCurrent(targetDomain, context) {
  const { state } = requireFreshVerificationState(targetDomain);
  if (context.verification_attempt_id !== state.verification_attempt_id) {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, "replay_context verification_attempt_id does not match current VERIFY attempt");
  }
  if (context.verification_snapshot_hash !== state.verification_snapshot_hash) {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, "replay_context verification_snapshot_hash does not match current VERIFY snapshot");
  }
}

async function runWithReplaySafety(tool, args, handler) {
  const context = normalizeReplayContext(args && args.replay_context);
  if (!context || !context.active) {
    return handler();
  }
  const targetDomain = assertNonEmptyString(args.target_domain, "target_domain");
  assertReplayContextCurrent(targetDomain, context);
  const policy = replaySafetyForTool(tool.name);
  if (!policy) return handler();
  const mode = policy.replay_safety.mode || DEFAULT_REPLAY_SAFETY.mode;
  const leaseScope = policy.replay_safety.lease_scope || DEFAULT_REPLAY_SAFETY.lease_scope;
  if (leaseScope === "none" && mode !== "parallel_safe") {
    throw new ToolError(ERROR_CODES.INTERNAL_ERROR, "replay lease_scope none is allowed only with mode parallel_safe");
  }
  const key = replayLeaseKey({
    targetDomain,
    capabilityPack: policy.capability_pack,
    context,
    leaseScope,
  });
  let lease = null;
  if (key) {
    try {
      lease = acquireReplayLease({
        targetDomain,
        key,
        toolName: tool.name,
        policy,
        leaseScope,
        context,
      });
    } catch (error) {
      if (error instanceof ToolError && error.code === ERROR_CODES.STATE_CONFLICT) {
        safeAppendPipelineEvent(targetDomain, "verification_replay_policy_applied", {
          phase: "VERIFY",
          status: "lease_rejected",
          source: tool.name,
          verification_attempt_id: context.verification_attempt_id,
          verification_snapshot_hash: context.verification_snapshot_hash,
          capability_pack: policy.capability_pack,
          lease_scope: leaseScope,
          replay_purpose: context.purpose,
          counts: { active_leases: listActiveReplayLeases(targetDomain).length },
        }, governanceContextForDomain(targetDomain));
      }
      throw error;
    }
  }
  if (key && !lease) {
    throw new ToolError(ERROR_CODES.STATE_CONFLICT, "Replay lease acquisition failed");
  }
  const heartbeat = startReplayLeaseHeartbeat(lease);
  safeAppendPipelineEvent(targetDomain, "verification_replay_policy_applied", {
    phase: "VERIFY",
    status: key ? "lease_acquired" : "parallel_safe",
    source: tool.name,
    verification_attempt_id: context.verification_attempt_id,
    verification_snapshot_hash: context.verification_snapshot_hash,
    capability_pack: policy.capability_pack,
    lease_scope: leaseScope,
    replay_purpose: context.purpose,
    counts: { active_leases: listActiveReplayLeases(targetDomain).length },
  }, governanceContextForDomain(targetDomain));
  try {
    return await handler();
  } finally {
    if (heartbeat) clearInterval(heartbeat);
    releaseReplayLease(lease);
  }
}

function replayExecutionPolicy(targetDomain) {
  const activeLeases = targetDomain ? listActiveReplayLeases(targetDomain) : [];
  return Object.values(CAPABILITY_PACKS).map((pack) => {
    const safety = pack.verifier.replay_safety || DEFAULT_REPLAY_SAFETY;
    const active = activeLeases
      .filter((lease) => lease.capability_pack === pack.id)
      .map((lease) => ({
        lease_id: lease.lease_id,
        tool: lease.tool,
        purpose: lease.purpose,
        verification_attempt_id: lease.verification_attempt_id,
        round: lease.round,
        finding_id: lease.finding_id,
        acquired_at: lease.acquired_at,
        expires_at: lease.expires_at,
      }));
    return {
      capability_pack: pack.id,
      mode: safety.mode,
      lease_scope: safety.lease_scope,
      can_run_rounds_concurrently: safety.mode === "parallel_safe" || safety.lease_scope === "finding",
      active_leases: active,
      next_available_after_ms: active.length > 0 && safety.mode === "serialized" ? 1 : 0,
    };
  }).sort((a, b) => a.capability_pack.localeCompare(b.capability_pack));
}

module.exports = {
  DEFAULT_REPLAY_SAFETY,
  VERIFICATION_REPLAY_LEASE_TTL_MS,
  listActiveReplayLeases,
  replayExecutionPolicy,
  runWithReplaySafety,
};
