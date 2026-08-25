"use strict";

const fs = require("fs");
const crypto = require("crypto");
const path = require("path");

const {
  assertSafeDomain,
  attackSurfacePath,
  findingDifferentialVerifiedJsonlPath,
  frontierEventsJsonlPath,
  handoffSigningKeyPath,
  handoffSigningPrivateKeyPath,
  handoffSigningPublicKeyPath,
  offensiveRunsDir,
  offensiveRunsJsonlPath,
  sessionNucleusPath,
  surfaceIndexPath,
} = require("../io/paths.js");
const {
  readFrontierEvents,
} = require("./frontier-events.js");
const {
  readJsonFile,
} = require("../io/storage.js");

// frontier-projections fold frontier-events.jsonl into per-surface views that
// downstream readers (frontier-readiness, wave planner, coverage gating)
// consume in place of state.json arrays.
//
// Cycle F.3 established the ledger as the read source. Cycle D.3 deleted the
// legacy state arrays (state.explored, state.terminally_blocked,
// state.lead_surface_ids) along with the transitional state-fallback paths;
// the ledger is now the sole source of surface-level closure / blocker /
// lead truth.
//
// Surface-level blockers remain event-authoritative. Surface-level closures keep
// the existing honest-exhaustion path unless the event claims a proof. A
// proof_record claim only projects when it exactly matches an independently
// re-derived executed-differential proof record; soft verdict payloads,
// generated hypotheses, and unknown proof classes hold open instead of falling
// back to generic web completion.
//
// Surface-level state events are candidates when they:
//   - carry the explicit payload marker (`surface_fully_explored: true` for
//     closures, `terminally_blocked: true` for blockers), or
//   - originate from the wave-merge tool (`source.tool === bob_apply_wave_merge`).
// Coarse-grained signals (per-endpoint coverage rows from log_coverage,
// dead-end batches from log_dead_ends) are excluded from the surface-state
// projection so they do not mask the merge-promotion's surface-level truth.

const SURFACE_STATE_MERGE_SOURCE = "bob_apply_wave_merge";

const LEAD_SURFACE_LABEL = "promoted_surface_lead";
const OBSERVED_INVARIANT_CANARY_PROOF_MODE = "observed_invariant_canary_v1";
const OBSERVED_INVARIANT_CANARY_DESIGN = Object.freeze({
  version: 1,
  proof_mode: OBSERVED_INVARIANT_CANARY_PROOF_MODE,
  extractor: "secondorder_reread_json_exact_leaf_v1",
  source_ledger: "offensive_runs",
  source_tool_id: "bob_secondorder_reread",
  source_oracle_kind: "second_order_reread",
  positive_outcome: "exploited_safely",
  control_outcome: "blocked_by_defense",
  closure_predicate: "positive exact parsed leaf contains Bob-minted canary and decoy is silent; separate reachable control proves its unreturned decoy is silent",
  llm_verdict_allowed: false,
});
const OBSERVED_INVARIANT_CANARY_DESIGN_HASH = hashCanonicalJson(OBSERVED_INVARIANT_CANARY_DESIGN);
const PROOF_GATED_CLOSURE_CLASSES = Object.freeze(new Set([
  OBSERVED_INVARIANT_CANARY_PROOF_MODE,
]));
const OFFENSIVE_ROW_MAC_CONTEXT = "hacker-bob:offensive-run:row-hmac:v1";
const SECOND_ORDER_REREAD_TOOL_ID = "bob_secondorder_reread";
const SECOND_ORDER_REREAD_ORACLE_KIND = "second_order_reread";
const OOB_ORACLE_KIND = "out_of_band_interaction";
const RUN_ID_SEGMENT_RE = /^[A-Za-z0-9][A-Za-z0-9-]*$/;

function frontierEventsExist(domain) {
  return fs.existsSync(frontierEventsJsonlPath(domain));
}

function loadFrontierEventsSafely(domain) {
  if (!frontierEventsExist(domain)) return [];
  try {
    return readFrontierEvents(domain);
  } catch {
    return [];
  }
}

function pickReasonFromPayload(payload) {
  if (payload == null || typeof payload !== "object" || Array.isArray(payload)) return null;
  if (typeof payload.reason === "string" && payload.reason.trim()) return payload.reason.trim();
  if (typeof payload.code === "string" && payload.code.trim()) return payload.code.trim();
  if (typeof payload.outcome === "string" && payload.outcome.trim()) return payload.outcome.trim();
  return null;
}

function isMergeSourcedEvent(event) {
  const source = event.source;
  if (source == null || typeof source !== "object" || Array.isArray(source)) return false;
  return source.tool === SURFACE_STATE_MERGE_SOURCE;
}

function payloadObject(event) {
  const payload = event && event.payload;
  return payload && typeof payload === "object" && !Array.isArray(payload) ? payload : null;
}

function canonicalJson(value) {
  if (value == null || typeof value === "boolean" || typeof value === "number" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((entry) => {
      const serialized = canonicalJson(entry);
      return serialized === undefined ? "null" : serialized;
    }).join(",")}]`;
  }
  if (typeof value === "object") {
    const keys = Object.keys(value).sort();
    const parts = [];
    for (const key of keys) {
      const serialized = canonicalJson(value[key]);
      if (serialized !== undefined) parts.push(`${JSON.stringify(key)}:${serialized}`);
    }
    return `{${parts.join(",")}}`;
  }
  return undefined;
}

function hashCanonicalJson(value) {
  return crypto.createHash("sha256").update(canonicalJson(value), "utf8").digest("hex");
}

function sha256Buffer(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function sha256Text(text) {
  return crypto.createHash("sha256").update(String(text), "utf8").digest("hex");
}

function readJsonlRecords(filePath) {
  try {
    return fs.readFileSync(filePath, "utf8")
      .split("\n")
      .filter((line) => line.trim())
      .map((line) => { try { return JSON.parse(line); } catch { return null; } })
      .filter((record) => record && typeof record === "object" && !Array.isArray(record));
  } catch {
    return [];
  }
}

function readJsonFileSafely(filePath) {
  try {
    return JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch {
    return null;
  }
}

function offensiveRowHash(row) {
  return hashCanonicalJson({
    target_domain: row.target_domain,
    tool_id: row.tool_id,
    target: row.target,
    offensive_outcome: row.offensive_outcome,
    command_hash: row.command_hash,
    exit_code: row.exit_code,
    stdout_hash: row.stdout_hash,
    stderr_hash: row.stderr_hash,
    demonstrated_severity: row.demonstrated_severity,
    surface_id: row.surface_id,
  });
}

function rowMacPayload(row, macField = "row_mac") {
  const copy = { ...row };
  delete copy[macField];
  return canonicalJson(copy);
}

function rowMacPreimage(context, row, macField = "row_mac") {
  return `${context}\n${rowMacPayload(row, macField)}`;
}

function readHmacKey(domain) {
  const document = readJsonFileSafely(handoffSigningKeyPath(domain));
  if (!document || document.version !== 1 || typeof document.key !== "string") return null;
  try {
    const key = Buffer.from(document.key, "base64url");
    return key.length === 32 ? key : null;
  } catch {
    return null;
  }
}

function decodeEd25519PublicKeyDocument(document) {
  if (!document || document.version !== 1 || document.scheme !== "ed25519" || typeof document.key !== "string") {
    return null;
  }
  try {
    return crypto.createPublicKey({
      key: Buffer.from(document.key, "base64url"),
      format: "der",
      type: "spki",
    });
  } catch {
    return null;
  }
}

function readEd25519PublicKey(domain) {
  const publicKey = decodeEd25519PublicKeyDocument(readJsonFileSafely(handoffSigningPublicKeyPath(domain)));
  if (publicKey) return publicKey;
  const privateDocument = readJsonFileSafely(handoffSigningPrivateKeyPath(domain));
  if (!privateDocument || privateDocument.version !== 1 || privateDocument.scheme !== "ed25519"
      || typeof privateDocument.key !== "string") {
    return null;
  }
  try {
    const privateKey = crypto.createPrivateKey({
      key: Buffer.from(privateDocument.key, "base64url"),
      format: "der",
      type: "pkcs8",
    });
    return crypto.createPublicKey(privateKey);
  } catch {
    return null;
  }
}

function verifyOffensiveRunMac(domain, row) {
  if (!row || typeof row !== "object" || Array.isArray(row)) return false;
  const env = row.row_mac;
  if (!env || typeof env !== "object" || Array.isArray(env)) return false;
  if (env.version === 1 && env.algorithm === "hmac-sha256") {
    if (typeof env.digest !== "string" || !/^[0-9a-f]{64}$/.test(env.digest)) return false;
    const hmacKey = readHmacKey(domain);
    if (!Buffer.isBuffer(hmacKey) || hmacKey.length === 0) return false;
    const expected = crypto.createHmac("sha256", hmacKey)
      .update(OFFENSIVE_ROW_MAC_CONTEXT)
      .update("\n")
      .update(rowMacPayload(row))
      .digest("hex");
    const actual = Buffer.from(env.digest, "hex");
    const expectedBytes = Buffer.from(expected, "hex");
    return actual.length === expectedBytes.length && crypto.timingSafeEqual(actual, expectedBytes);
  }
  if (env.version === 2 && env.scheme === "ed25519") {
    if (typeof env.signature !== "string" || !/^[A-Za-z0-9_-]+$/.test(env.signature)) return false;
    const publicKey = readEd25519PublicKey(domain);
    if (!publicKey) return false;
    let signature;
    try {
      signature = Buffer.from(env.signature, "base64url");
    } catch {
      return false;
    }
    try {
      return crypto.verify(null, Buffer.from(rowMacPreimage(OFFENSIVE_ROW_MAC_CONTEXT, row)), publicKey, signature);
    } catch {
      return false;
    }
  }
  return false;
}

function readOffensiveRowsByRunId(domain) {
  const rowsById = new Map();
  const duplicateRunIds = new Set();
  for (const row of readJsonlRecords(offensiveRunsJsonlPath(domain))) {
    const runId = typeof row.run_id === "string" ? row.run_id : "";
    if (!runId) continue;
    if (rowsById.has(runId)) {
      duplicateRunIds.add(runId);
      rowsById.delete(runId);
      continue;
    }
    if (!duplicateRunIds.has(runId)) rowsById.set(runId, row);
  }
  return rowsById;
}

function resolveExecutedOffensiveRow(domain, rowsById, runId) {
  if (typeof runId !== "string" || !runId) return null;
  const row = rowsById.get(runId);
  if (!row) return null;
  if (row.target_domain !== domain) return null;
  if (row.run_id !== runId) return null;
  if (row.dry_run !== false || row.timed_out !== false) return null;
  if (!verifyOffensiveRunMac(domain, row)) return null;
  return row;
}

function readCaptureJson(domain, row, streamName) {
  if (!RUN_ID_SEGMENT_RE.test(row.run_id || "")) {
    throw new Error(`${streamName} capture has unsafe run_id`);
  }
  const field = `${streamName}_hash`;
  if (typeof row[field] !== "string" || !/^[0-9a-f]{64}$/i.test(row[field])) {
    throw new Error(`${streamName} capture hash is absent from signed row`);
  }
  const captureDir = offensiveRunsDir(domain);
  const capturePath = path.join(captureDir, `${row.run_id}.${streamName}`);
  let fd = null;
  let bytes;
  try {
    const realDir = fs.realpathSync(captureDir);
    const realPath = fs.realpathSync(capturePath);
    if (path.dirname(realPath) !== realDir) throw new Error(`${streamName} capture escapes offensive-runs directory`);
    fd = fs.openSync(capturePath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
    const stats = fs.fstatSync(fd);
    if (!stats.isFile() || stats.nlink !== 1) throw new Error(`${streamName} capture must be a single-link regular file`);
    bytes = fs.readFileSync(fd);
  } finally {
    if (fd != null) {
      try { fs.closeSync(fd); } catch {}
    }
  }
  if (sha256Buffer(bytes) !== row[field].toLowerCase()) throw new Error(`${streamName} capture hash does not match signed row`);
  const parsed = JSON.parse(bytes.toString("utf8"));
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error(`${streamName} capture is not a JSON object`);
  return parsed;
}

function readSessionNucleusRecord(domain) {
  const document = readJsonFileSafely(sessionNucleusPath(domain));
  return document && typeof document === "object" && !Array.isArray(document)
    ? {
      target_domain: document.target_domain || domain,
      nucleus_hash: document.nucleus_hash || null,
      lifecycle_state: document.lifecycle_state || null,
    }
    : { target_domain: domain, nucleus_hash: null, lifecycle_state: null };
}

function requireSecondOrderCanaryProof({ domain, findingId, surfaceId, positiveRow, controlRow }) {
  if (positiveRow.tool_id !== SECOND_ORDER_REREAD_TOOL_ID || controlRow.tool_id !== SECOND_ORDER_REREAD_TOOL_ID) {
    throw new Error("observed_invariant_canary_v1 requires bob_secondorder_reread rows");
  }
  if (positiveRow.oracle_kind !== SECOND_ORDER_REREAD_ORACLE_KIND || controlRow.oracle_kind !== SECOND_ORDER_REREAD_ORACLE_KIND) {
    throw new Error("observed_invariant_canary_v1 requires second_order_reread oracle rows");
  }
  for (const row of [positiveRow, controlRow]) {
    if (row.target_domain !== domain || row.surface_id !== surfaceId) throw new Error("second-order row binding mismatch");
    if (row.canary_minted_server_side !== true || row.decoy_minted_server_side !== true) throw new Error("second-order row lacks minted canary/decoy proof");
    if (row.observation_endpoint_distinct_from_injection !== true) throw new Error("second-order row lacks endpoint distinctness proof");
    if (row.reread_read_only !== true || row.reread_channel_bob_controlled !== true) throw new Error("second-order row lacks read-only Bob-channel proof");
  }
  if (positiveRow.canary_present_exact_leaf !== true || positiveRow.decoy_absent !== true) throw new Error("positive row lacks exact canary/decoy proof");
  if (controlRow.decoy_absent_against_reachable_endpoint !== true || controlRow.decoy_silent !== true) throw new Error("control row lacks decoy silence proof");

  const positiveStdout = readCaptureJson(domain, positiveRow, "stdout");
  const positiveStderr = readCaptureJson(domain, positiveRow, "stderr");
  const controlStdout = readCaptureJson(domain, controlRow, "stdout");
  const controlStderr = readCaptureJson(domain, controlRow, "stderr");
  const canary = typeof positiveStdout.canary === "string" && positiveStdout.canary ? positiveStdout.canary : null;
  const positiveDecoy = typeof positiveStdout.decoy === "string" && positiveStdout.decoy ? positiveStdout.decoy : null;
  const controlDecoy = typeof controlStdout.decoy === "string" && controlStdout.decoy ? controlStdout.decoy : null;
  if (!canary || !positiveDecoy || !controlDecoy || canary === positiveDecoy || canary === controlDecoy) throw new Error("invalid canary/decoy captures");
  if (positiveStdout.bound_surface_id !== surfaceId || controlStdout.bound_surface_id !== surfaceId) throw new Error("capture surface mismatch");
  if (positiveStdout.bound_observation_endpoint !== positiveRow.target || controlStdout.bound_observation_endpoint !== controlRow.target) throw new Error("capture target mismatch");
  if (positiveStdout.bound_injection_endpoint !== controlStdout.bound_injection_endpoint
      || positiveStdout.bound_observation_endpoint !== controlStdout.bound_observation_endpoint) {
    throw new Error("positive/control canary endpoints mismatch");
  }
  if (positiveStderr.canary_match !== "exact_leaf" || positiveStderr.decoy_silent !== true
      || positiveStderr.reread_channel_bob_controlled !== true) {
    throw new Error("positive extractor transcript invalid");
  }
  if (controlStderr.decoy_match !== "none" || controlStderr.reread_channel_bob_controlled !== true) {
    throw new Error("control extractor transcript invalid");
  }
  const leafDepth = Number.isInteger(positiveStdout.canary_leaf_depth)
    ? positiveStdout.canary_leaf_depth
    : positiveStderr.canary_leaf_depth;
  if (!Number.isInteger(leafDepth) || leafDepth < 0) throw new Error("positive capture lacks canary leaf depth");
  const sessionNucleus = readSessionNucleusRecord(domain);
  if (sessionNucleus.target_domain !== domain || typeof sessionNucleus.nucleus_hash !== "string" || !sessionNucleus.nucleus_hash) {
    throw new Error("observed_invariant_canary_v1 requires a verified session nucleus hash");
  }
  const proof = {
    version: 1,
    proof_mode: OBSERVED_INVARIANT_CANARY_PROOF_MODE,
    design_hash: OBSERVED_INVARIANT_CANARY_DESIGN_HASH,
    finding_id: findingId,
    surface: {
      surface_id: surfaceId,
      observation_target: positiveRow.target,
    },
    session_nucleus: sessionNucleus,
    parsed_leaf: {
      extractor: "secondorder_reread_json_exact_leaf_v1",
      match: "exact_leaf",
      canary_sha256: sha256Text(canary),
      leaf_depth: leafDepth,
      positive_stdout_hash: positiveRow.stdout_hash,
      positive_stderr_hash: positiveRow.stderr_hash,
    },
    control_refs: [
      {
        role: "positive_canary_reread",
        ledger: "offensive_runs",
        row_id: positiveRow.run_id,
        row_hash: offensiveRowHash(positiveRow),
        stdout_hash: positiveRow.stdout_hash,
        stderr_hash: positiveRow.stderr_hash,
      },
      {
        role: "decoy_silent_control",
        ledger: "offensive_runs",
        row_id: controlRow.run_id,
        row_hash: offensiveRowHash(controlRow),
        stdout_hash: controlRow.stdout_hash,
        stderr_hash: controlRow.stderr_hash,
        decoy_sha256: sha256Text(controlDecoy),
      },
    ],
  };
  proof.proof_hash = hashCanonicalJson(proof);
  return proof;
}

function canaryProofIsRequired(record, positiveRow, controlRow) {
  const proofRecord = record && record.proof_record;
  return (proofRecord && proofRecord.proof_mode === OBSERVED_INVARIANT_CANARY_PROOF_MODE)
    || positiveRow.tool_id === SECOND_ORDER_REREAD_TOOL_ID
    || controlRow.tool_id === SECOND_ORDER_REREAD_TOOL_ID
    || positiveRow.oracle_kind === SECOND_ORDER_REREAD_ORACLE_KIND
    || controlRow.oracle_kind === SECOND_ORDER_REREAD_ORACLE_KIND;
}

function rederiveFindingDifferentialClosureProof(domain, record, rowsById) {
  if (!record || record.result !== "verified_pass") return null;
  const positiveRow = resolveExecutedOffensiveRow(domain, rowsById, record.positive_run_id);
  const controlRow = resolveExecutedOffensiveRow(domain, rowsById, record.control_run_id);
  if (!positiveRow || !controlRow || positiveRow.run_id === controlRow.run_id) return null;
  const surfaceId = typeof positiveRow.surface_id === "string" ? positiveRow.surface_id.trim() : "";
  if (!surfaceId || controlRow.surface_id !== surfaceId) return null;
  if (positiveRow.offensive_outcome !== "exploited_safely" || controlRow.offensive_outcome !== "blocked_by_defense") return null;
  if (positiveRow.dry_run !== false || controlRow.dry_run !== false || positiveRow.timed_out !== false || controlRow.timed_out !== false) return null;
  if (positiveRow.target_domain !== domain || controlRow.target_domain !== domain) return null;
  if (positiveRow.oracle_kind === OOB_ORACLE_KIND && positiveRow.source_attribution_established !== true) return null;
  if (offensiveRowHash(positiveRow) === offensiveRowHash(controlRow)) return null;
  let proofRecord = null;
  if (canaryProofIsRequired(record, positiveRow, controlRow)) {
    if (!record.proof_record || record.proof_record.proof_mode !== OBSERVED_INVARIANT_CANARY_PROOF_MODE) return null;
    try {
      proofRecord = requireSecondOrderCanaryProof({
        domain,
        findingId: record.finding_id,
        surfaceId,
        positiveRow,
        controlRow,
      });
    } catch {
      return null;
    }
    if (hashCanonicalJson(record.proof_record) !== hashCanonicalJson(proofRecord)) return null;
  }
  return { surfaceId, proofRecord };
}

function rederiveFindingDifferentialSurfaceId(domain, record, rowsById) {
  const proof = rederiveFindingDifferentialClosureProof(domain, record, rowsById);
  return proof ? proof.surfaceId : null;
}

function emptyClosureProofIndex() {
  return {
    surfaceIds: new Set(),
    proofHashesBySurface: new Map(),
  };
}

function addClosureProofToIndex(index, surfaceId, proofRecord) {
  if (typeof surfaceId !== "string" || !surfaceId) return;
  index.surfaceIds.add(surfaceId);
  if (proofRecord == null || typeof proofRecord !== "object" || Array.isArray(proofRecord)) return;
  let hashes = index.proofHashesBySurface.get(surfaceId);
  if (!hashes) {
    hashes = new Set();
    index.proofHashesBySurface.set(surfaceId, hashes);
  }
  hashes.add(hashCanonicalJson(proofRecord));
}

function currentClosureProofIndex(targetDomain) {
  const domain = assertSafeDomain(targetDomain);
  const index = emptyClosureProofIndex();
  const rowsById = readOffensiveRowsByRunId(domain);
  for (const record of readJsonlRecords(findingDifferentialVerifiedJsonlPath(domain))) {
    const proof = rederiveFindingDifferentialClosureProof(domain, record, rowsById);
    if (proof) addClosureProofToIndex(index, proof.surfaceId, proof.proofRecord);
  }
  return index;
}

function currentClosureProofSurfaceIds(targetDomain) {
  return currentClosureProofIndex(targetDomain).surfaceIds;
}

function hasSurfaceClosureSignal(event) {
  const payload = payloadObject(event);
  if (payload && payload.surface_unblocked === true) return false;
  if (payload && payload.surface_fully_explored === true) return true;
  return isMergeSourcedEvent(event);
}

function isSurfaceClosureCandidateEvent(event) {
  if (event.kind !== "closure.recorded") return false;
  if (typeof event.surface_id !== "string" || !event.surface_id) return false;
  return hasSurfaceClosureSignal(event);
}

function isSurfaceClosureEvent(event, closureProofSurfaceIds) {
  if (!isSurfaceClosureCandidateEvent(event)) return false;
  const payload = payloadObject(event);
  if (!payload || !Object.prototype.hasOwnProperty.call(payload, "proof_record")) {
    return !payloadRequiresClosureProof(payload);
  }
  const proofRecord = payload.proof_record;
  if (proofRecord == null || typeof proofRecord !== "object" || Array.isArray(proofRecord)) return false;
  const proofIndex = closureProofSurfaceIds && closureProofSurfaceIds.proofHashesBySurface instanceof Map
    ? closureProofSurfaceIds
    : { proofHashesBySurface: new Map() };
  const proofHashes = proofIndex.proofHashesBySurface.get(event.surface_id);
  return proofHashes instanceof Set && proofHashes.has(hashCanonicalJson(proofRecord));
}

function payloadRequiresClosureProof(payload) {
  if (payload == null || typeof payload !== "object" || Array.isArray(payload)) return false;
  if (payload.generated_hypothesis === true || payload.closure_authority === false) return true;
  if (Object.prototype.hasOwnProperty.call(payload, "soft_verdict")
      || Object.prototype.hasOwnProperty.call(payload, "llm_verdict")
      || Object.prototype.hasOwnProperty.call(payload, "posterior")) {
    return true;
  }
  const proofMode = typeof payload.proof_mode === "string" ? payload.proof_mode.trim() : "";
  if (proofMode) return true;
  const bugClass = typeof payload.bug_class === "string" ? payload.bug_class.trim() : "";
  return PROOF_GATED_CLOSURE_CLASSES.has(bugClass);
}

function isSurfaceUnblockEvent(event) {
  if (event.kind !== "closure.recorded") return false;
  if (typeof event.surface_id !== "string" || !event.surface_id) return false;
  const payload = payloadObject(event);
  return payload != null && payload.surface_unblocked === true;
}

function isSurfaceBlockerEvent(event) {
  if (event.kind !== "blocker.asserted") return false;
  if (typeof event.surface_id !== "string" || !event.surface_id) return false;
  const payload = event.payload;
  if (payload && typeof payload === "object" && !Array.isArray(payload)
    && payload.terminally_blocked === true) {
    return true;
  }
  return isMergeSourcedEvent(event);
}

// A surface-state event is the union of closure / blocker surface-state
// events. Folding "latest of either kind" lets a clear or re-closure
// supersede a prior block, which is the semantic the merge-promotion and
// operator clear paths rely on after D.3.
function isSurfaceStateEvent(event, closureProofSurfaceIds) {
  return isSurfaceClosureCandidateEvent(event)
    || isSurfaceBlockerEvent(event)
    || isSurfaceUnblockEvent(event);
}

function compareEventOrder(a, b) {
  const tsA = Date.parse(a.ts || "");
  const tsB = Date.parse(b.ts || "");
  if (Number.isFinite(tsA) && Number.isFinite(tsB) && tsA !== tsB) {
    return tsA - tsB;
  }
  return 0;
}

function foldLatestBySurface(events, predicate, surfaceStatePredicate) {
  const latestState = new Map();
  for (const event of events) {
    if (!surfaceStatePredicate(event)) continue;
    const existing = latestState.get(event.surface_id);
    if (existing == null || compareEventOrder(existing, event) <= 0) {
      latestState.set(event.surface_id, event);
    }
  }
  return Array.from(latestState.values())
    .filter((event) => predicate(event))
    .map((event) => ({
      surface_id: event.surface_id,
      closed_at: typeof event.ts === "string" ? event.ts : null,
      reason: pickReasonFromPayload(event.payload),
      source_event_id: typeof event.event_id === "string" ? event.event_id : null,
    }))
    .sort((a, b) => a.surface_id.localeCompare(b.surface_id));
}

function currentClosures(targetDomain) {
  const domain = assertSafeDomain(targetDomain);
  const events = loadFrontierEventsSafely(domain);
  const closureProofSurfaceIds = currentClosureProofIndex(domain);
  return foldLatestBySurface(
    events,
    (event) => isSurfaceClosureEvent(event, closureProofSurfaceIds),
    (event) => isSurfaceStateEvent(event, closureProofSurfaceIds),
  );
}

function currentBlockers(targetDomain) {
  const domain = assertSafeDomain(targetDomain);
  const events = loadFrontierEventsSafely(domain);
  const closureProofSurfaceIds = currentClosureProofIndex(domain);
  return foldLatestBySurface(
    events,
    isSurfaceBlockerEvent,
    (event) => isSurfaceStateEvent(event, closureProofSurfaceIds),
  );
}

// A surface is a "lead" if its labels (folded across surface.observed
// events) include the promoted-surface-lead marker. The projection excludes
// surfaces whose latest surface-state event is closure or blocker — the
// wave planner consumes only actionable leads.
function eventCarriesLeadLabel(event) {
  if (event.kind !== "surface.observed") return false;
  if (typeof event.surface_id !== "string" || !event.surface_id) return false;
  const payload = event.payload && typeof event.payload === "object" && !Array.isArray(event.payload)
    ? event.payload
    : null;
  if (!payload) return false;
  if (Array.isArray(payload.labels) && payload.labels.includes(LEAD_SURFACE_LABEL)) {
    return true;
  }
  if (Array.isArray(event.tags) && event.tags.includes(LEAD_SURFACE_LABEL)) {
    return true;
  }
  return false;
}

function currentLeadSurfaceIds(targetDomain) {
  const domain = assertSafeDomain(targetDomain);
  const events = loadFrontierEventsSafely(domain);
  const closureProofSurfaceIds = currentClosureProofIndex(domain);
  const leadSurfaceIds = new Set();
  for (const event of events) {
    if (eventCarriesLeadLabel(event)) {
      leadSurfaceIds.add(event.surface_id);
    }
  }
  if (leadSurfaceIds.size === 0) return [];
  // Drop lead surfaces whose latest surface-state event is a closure or a
  // blocker; the wave planner can only assign actionable lead surfaces.
  const latestState = new Map();
  for (const event of events) {
    if (!isSurfaceStateEvent(event, closureProofSurfaceIds)) continue;
    const existing = latestState.get(event.surface_id);
    if (existing == null || compareEventOrder(existing, event) <= 0) {
      latestState.set(event.surface_id, event);
    }
  }
  // Membership: union of attack_surface.json (legacy projection) and the
  // materialized surface-index.json (or its synthesized projection). Either
  // source is enough to keep a lead surface visible to the planner. The
  // union avoids stale-state false negatives between materializer runs and
  // the attack-surface promotion pipeline.
  const knownSurfaceIds = new Set();
  try {
    if (fs.existsSync(attackSurfacePath(domain))) {
      const legacy = readJsonFile(attackSurfacePath(domain), { label: "attack_surface.json" });
      if (legacy && Array.isArray(legacy.surfaces)) {
        for (const surface of legacy.surfaces) {
          if (surface && typeof surface.id === "string" && surface.id) knownSurfaceIds.add(surface.id);
        }
      }
    }
  } catch {
    // Malformed attack_surface.json — surface-index.json is consulted below.
  }
  try {
    const surfaceProjection = currentSurfaces(domain);
    if (surfaceProjection && surfaceProjection.source !== "missing") {
      for (const surface of surfaceProjection.surfaces || []) {
        if (surface && typeof surface.id === "string" && surface.id) knownSurfaceIds.add(surface.id);
      }
    }
  } catch {
    // Projection unavailable; the legacy projection above may still have entries.
  }
  // Also surface.observed events from lead-promotion's promote-to-frontier
  // path constitute "known" surfaces — the promotion writer emits a rich
  // payload (title, hosts, endpoints, score) that the planner can use even
  // before the materializer flushes. Handoff-only lead events (payload only
  // has labels) do not count: handoff-discovered surface ids without a
  // surface.observed body are still leads pending future promotion.
  for (const event of events) {
    if (event.kind !== "surface.observed") continue;
    if (typeof event.surface_id !== "string" || !event.surface_id) continue;
    const payload = event.payload && typeof event.payload === "object" && !Array.isArray(event.payload)
      ? event.payload
      : null;
    if (!payload) continue;
    // Heuristic: a "rich" surface.observed payload carries at least one of
    // the planner-relevant scalar fields. A label-only event (e.g. emitted
    // by appendHandoffLeadSurfaceFrontierEvents) does not promote the
    // surface to known-surface status here.
    if (typeof payload.title === "string"
      || typeof payload.surface_type === "string"
      || Array.isArray(payload.hosts)
      || Array.isArray(payload.endpoints)
      || Number.isFinite(payload.score)
    ) {
      knownSurfaceIds.add(event.surface_id);
    }
  }
  const useFilter = knownSurfaceIds.size > 0;
  const result = [];
  for (const surfaceId of leadSurfaceIds) {
    if (useFilter && !knownSurfaceIds.has(surfaceId)) continue;
    const state = latestState.get(surfaceId);
    if (state == null) {
      result.push(surfaceId);
      continue;
    }
    if (isSurfaceClosureEvent(state, closureProofSurfaceIds) || isSurfaceBlockerEvent(state)) continue;
    result.push(surfaceId);
  }
  return result.sort((a, b) => a.localeCompare(b));
}

function normalizeObservationEvent(event) {
  const payload = event.payload && typeof event.payload === "object" && !Array.isArray(event.payload)
    ? event.payload
    : {};
  // F.4 normalized shape: `kind` carries the observation-class label (e.g.
  // "http_route", "schema_field", "auth_redirect"). Producers stamp this on
  // `payload.observation_kind`; callers can also stash it under `payload.kind`
  // for backward compatibility. Falls back to the event source artifact name.
  let observationKind = null;
  if (typeof payload.observation_kind === "string" && payload.observation_kind.trim()) {
    observationKind = payload.observation_kind.trim();
  } else if (typeof payload.kind === "string" && payload.kind.trim()) {
    observationKind = payload.kind.trim();
  } else if (event.source && typeof event.source === "object" && !Array.isArray(event.source)
    && typeof event.source.artifact === "string" && event.source.artifact.trim()) {
    observationKind = event.source.artifact.trim();
  }
  const source = event.source && typeof event.source === "object" && !Array.isArray(event.source)
    ? {
      artifact: typeof event.source.artifact === "string" ? event.source.artifact : null,
      ref: typeof event.source.ref === "string"
        ? event.source.ref
        : (typeof event.source.tool === "string" ? event.source.tool : null),
    }
    : { artifact: null, ref: null };
  return {
    event_id: typeof event.event_id === "string" ? event.event_id : null,
    surface_id: typeof event.surface_id === "string" ? event.surface_id : null,
    ts: typeof event.ts === "string" ? event.ts : null,
    kind: observationKind,
    payload,
    source,
  };
}

function compareObservationEvents(a, b) {
  const tsA = Date.parse(a.ts || "");
  const tsB = Date.parse(b.ts || "");
  if (Number.isFinite(tsA) && Number.isFinite(tsB) && tsA !== tsB) {
    return tsA - tsB;
  }
  return String(a.event_id || "").localeCompare(String(b.event_id || ""));
}

function observationsForSurface(targetDomain, surfaceId) {
  const domain = assertSafeDomain(targetDomain);
  if (typeof surfaceId !== "string" || !surfaceId.trim()) {
    throw new Error("surface_id must be a non-empty string");
  }
  const trimmed = surfaceId.trim();
  const events = loadFrontierEventsSafely(domain);
  return events
    .filter((event) => event.kind === "observation.recorded" && event.surface_id === trimmed)
    .sort(compareObservationEvents)
    .map(normalizeObservationEvent);
}

// surface-index.json is the authoritative surface source (Cycle F.5).
// currentSurfaces reads it strictly and projects each materialized surface
// into the legacy attack_surface.json shape (id-keyed, with the rich text
// fields that ranking, phase-gates, surface-router, and pipeline-session-
// artifacts consume). When surface-index.json does not exist for a session
// (legacy or pre-F.1), the projection falls back to attack_surface.json.
// The fallback is transitional and removed in D.3.

const SURFACE_INDEX_SCALAR_FIELDS = [
  "title",
  "uri",
  "method",
  "kind",
  "owner",
  "surface_type",
  // Preserve explicit deny-precedence routing provenance.  In particular,
  // `surface_class: physical` can be the only physical signal when the surface
  // type is an ordinary API/asset label.
  "surface_class",
  "capability_pack",
  "required_capability_pack",
  "disposition",
  "reason",
  "brief_profile",
  "attack_vector",
  "severity_ceiling",
  "chain_family",
  "chain_id",
  "contract_address",
  "file_path",
  "language",
  // OD3 verified-source provenance marker. The materializer preserves it on the
  // surface-index entry; the projection must carry it into the legacy shape so
  // readScExpanderSurfaces recovers real provenance and the OD3 same-chain
  // linked-contract gate fires on the persisted path.
  "provenance",
];

// Integer scalar fields projected as NUMBERS (not the trimmed strings the scalar
// loop would produce). depth is the OD4 linked-contract recursion depth;
// readScExpanderSurfaces uses a Number.isInteger check, so a string depth would
// fall back to the depth-1 default and OD4 depth-capping would never fire.
const SURFACE_INDEX_INTEGER_FIELDS = [
  "depth",
  "capability_pack_version",
  "required_capability_pack_version",
];

const SURFACE_INDEX_BOOLEAN_FIELDS = [
  "network_reachable",
  "native_source",
  "native_build",
];

const SURFACE_INDEX_ARRAY_FIELDS = [
  "hosts",
  "tech_stack",
  "endpoints",
  "interesting_params",
  "nuclei_hits",
  "js_hints",
  "leaked_secrets",
  "bug_class_hints",
  "high_value_flows",
  "evidence",
  "network_reachable_anchors",
  "network_reachable_dirs",
  "local_only_candidate_dirs",
  "residual_hunt_targets",
];

function readSurfaceIndexDocument(domain) {
  const filePath = surfaceIndexPath(domain);
  if (!fs.existsSync(filePath)) return null;
  // Surface-index.json being on disk but malformed is a hard failure: the
  // ledger is authoritative, so silent fallback to attack_surface.json on
  // corruption would hide ledger-truth divergence. The reader throws and the
  // caller decides whether to swallow.
  return readJsonFile(filePath, { label: "surface-index.json" });
}

function readAttackSurfaceDocumentLegacy(domain) {
  const filePath = attackSurfacePath(domain);
  if (!fs.existsSync(filePath)) return null;
  try {
    return readJsonFile(filePath, { label: "attack_surface.json" });
  } catch (error) {
    // Mirror the legacy readAttackSurfaceStrict error shape so consumers that
    // pattern-match on "Malformed attack surface JSON:" keep working through
    // the deprecation window.
    throw new Error(`Malformed attack surface JSON: ${filePath} (${error.message || String(error)})`);
  }
}

function projectMaterializedSurface(materialized) {
  if (materialized == null || typeof materialized !== "object" || Array.isArray(materialized)) {
    return null;
  }
  const surfaceId = typeof materialized.surface_id === "string" ? materialized.surface_id.trim() : "";
  if (!surfaceId) return null;
  const projected = { id: surfaceId };
  for (const field of SURFACE_INDEX_SCALAR_FIELDS) {
    if (typeof materialized[field] === "string" && materialized[field].trim()) {
      projected[field] = materialized[field].trim();
    }
  }
  for (const field of SURFACE_INDEX_INTEGER_FIELDS) {
    if (Number.isInteger(materialized[field])) {
      projected[field] = materialized[field];
    }
  }
  for (const field of SURFACE_INDEX_BOOLEAN_FIELDS) {
    if (typeof materialized[field] === "boolean") {
      projected[field] = materialized[field];
    }
  }
  for (const field of SURFACE_INDEX_ARRAY_FIELDS) {
    if (Array.isArray(materialized[field]) && materialized[field].length > 0) {
      projected[field] = materialized[field].slice();
    }
  }
  if (typeof materialized.priority === "string" && materialized.priority.trim()) {
    projected.priority = materialized.priority.trim().toUpperCase();
  }
  if (Array.isArray(materialized.labels) && materialized.labels.length > 0) {
    projected.labels = materialized.labels.slice();
  }
  if (typeof materialized.state === "string" && materialized.state) {
    projected.surface_state = materialized.state;
  }
  return projected;
}

function currentSurfaces(targetDomain) {
  const domain = assertSafeDomain(targetDomain);
  // Parse surface-index.json strictly: a malformed file fails loud. The
  // projection does not silently fall back to attack_surface.json on
  // corruption in the runtime hot path (F.5 review gate). When the
  // materialized view is present, it is the authoritative source for the
  // surfaces it knows about; legacy attack_surface.json entries that the
  // ledger has not yet observed (e.g., operator-seeded baseline surfaces
  // during the D.3 deprecation window) are unioned in so promotion paths
  // that emit surface.observed events do not silently drop the baseline.
  const surfaceIndex = readSurfaceIndexDocument(domain);
  if (surfaceIndex && Array.isArray(surfaceIndex.surfaces) && surfaceIndex.surfaces.length > 0) {
    let legacy = null;
    let legacyWarning = null;
    try {
      legacy = readAttackSurfaceDocumentLegacy(domain);
    } catch (error) {
      // The materialized surface-index is authoritative in the hot path;
      // a corrupted legacy attack_surface.json must not block current readers.
      legacyWarning = {
        code: "legacy_attack_surface_unreadable",
        path: attackSurfacePath(domain),
        message: error && error.message ? error.message : String(error),
      };
      legacy = null;
    }
    const surfaces = [];
    const seen = new Set();
    for (const entry of surfaceIndex.surfaces) {
      const projected = projectMaterializedSurface(entry);
      if (!projected) continue;
      if (seen.has(projected.id)) continue;
      seen.add(projected.id);
      surfaces.push(projected);
    }
    if (legacy && Array.isArray(legacy.surfaces)) {
      for (const legacySurface of legacy.surfaces) {
        if (legacySurface == null || typeof legacySurface !== "object" || Array.isArray(legacySurface)) continue;
        const legacyId = typeof legacySurface.id === "string" ? legacySurface.id.trim() : "";
        if (!legacyId || seen.has(legacyId)) continue;
        seen.add(legacyId);
        surfaces.push({ ...legacySurface, id: legacyId });
      }
    }
    return {
      source: "surface_index",
      path: surfaceIndexPath(domain),
      document: { surfaces },
      surfaces,
      warnings: legacyWarning ? [legacyWarning] : [],
      surface_index_hash: typeof surfaceIndex.surface_index_hash === "string"
        ? surfaceIndex.surface_index_hash
      : null,
    };
  }
  const legacy = readAttackSurfaceDocumentLegacy(domain);
  if (legacy == null) {
    return {
      source: "missing",
      path: surfaceIndexPath(domain),
      document: { surfaces: [] },
      surfaces: [],
      warnings: [],
      surface_index_hash: null,
    };
  }
  const surfacesArray = Array.isArray(legacy.surfaces) ? legacy.surfaces.slice() : [];
  return {
    source: "attack_surface_legacy",
    path: attackSurfacePath(domain),
    document: legacy,
    surfaces: surfacesArray,
    warnings: [],
    surface_index_hash: null,
  };
}

module.exports = {
  compareObservationEvents,
  currentBlockers,
  currentClosureProofIndex,
  currentClosureProofSurfaceIds,
  currentClosures,
  currentLeadSurfaceIds,
  currentSurfaces,
  isSurfaceClosureCandidateEvent,
  isSurfaceClosureEvent,
  isSurfaceStateEvent,
  isSurfaceUnblockEvent,
  normalizeObservationEvent,
  observationsForSurface,
};
