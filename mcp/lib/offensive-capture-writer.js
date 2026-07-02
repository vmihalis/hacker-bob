"use strict";

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const {
  ERROR_CODES,
  ToolError,
} = require("./envelope.js");
const {
  readOffensiveRunRecords,
  OFFENSIVE_TOOL_DEMONSTRATED_CEILING,
} = require("./claims.js");
const {
  SEVERITY_VALUES,
} = require("./constants.js");
const {
  OFFENSIVE_ROW_MAC_CONTEXT,
} = require("./offensive-row-mac.js");
const {
  signRowViaIsolatedSignerOrLocal,
} = require("./handoff-signing-key.js");
const {
  offensiveRunsDir,
  offensiveRunsJsonlPath,
  sessionsRoot,
  assertSafeDomain,
} = require("./paths.js");
const {
  canonicalJson,
} = require("./verification-contracts.js");
const {
  mintShapeMatchedDecoyBytes,
} = require("./consumable-shape.js");

// The proof-contract fields buildAndSignOffensiveRow controls; relationBooleans
// may never override any of these before the row is signed. consumed_artifact_hash
// is the cross-stack consumable-artifact binding: sha256 of the BYTES the on-chain
// side will consume (a leaked credential/identifier/calldata blob). It is a top-level
// MAC-covered SIBLING outside command_hash/run identity, and nullable — a web-only
// finding that produces no on-chain-consumable artifact signs consumed_artifact_hash:null.
const RESERVED_ROW_KEYS = new Set([
  "version", "target_domain", "run_id", "tool_id", "target", "offensive_outcome",
  "dry_run", "timed_out", "command_hash", "exit_code", "stdout_hash", "stderr_hash",
  "demonstrated_severity", "surface_id", "consumed_artifact_hash", "is_decoy", "oracle_kind", "row_mac",
]);

// The frozen set of offensive_outcome values a producer may sign. A signed row is
// an EXECUTED OBSERVATION: the positive demonstrated the issue (exploited_safely)
// or the server affirmatively DENIED a safe/authorized variant that actually ran
// (blocked_by_defense / blocked_by_infra — the negative control leg of a finding
// differential). A blocked observation is still a completed execution (exit_code 0;
// "blocked" is the server's response, not a process failure), so resolveExecutedRow's
// non-error/non-timed-out/non-dry-run preconditions hold for it identically.
//
// DELIBERATELY ABSENT: blocked_by_design / blocked_operator_pii are PRE-request
// refusals — the producer never fired a request, so there is no executed observation
// to sign. They stay unsigned (row_written:false). exploited_unsafely is likewise
// never a signable outcome here. Anything outside this set is fail-closed rejected.
const OFFENSIVE_ROW_OUTCOMES = Object.freeze(new Set([
  "exploited_safely", "blocked_by_defense", "blocked_by_infra",
]));

// The closed set of oracle kinds a producer may stamp into a row (MAC-covered sibling). An
// out-of-band-interaction row is one whose evidence is an external callback, gated specially
// at read time (the exploit_run skip refuses to treat it as a self-contained binding). Like
// offensiveOutcome, this is a CONTROLLED field validated against a frozen set so an arbitrary
// string can never become a signed oracle_kind.
const OFFENSIVE_ROW_ORACLE_KINDS = Object.freeze(new Set([
  "out_of_band_interaction",
]));

// run_id is a single clean [A-Za-z0-9-] segment so sha256OffensiveCaptureSecure
// (claim-freeze.js) accepts it as a direct child leaf of offensive-runs/.
function newRunId(prefix) {
  return `${prefix}-${crypto.randomUUID()}`;
}

function commandHashOf(method, canonicalTarget, identityTag) {
  return crypto
    .createHash("sha256")
    .update(canonicalJson({ method, canonical_target: canonicalTarget, identity_tag: identityTag }))
    .digest("hex");
}

function sha256OfFileFd(realLeaf) {
  const noFollow = fs.constants.O_NOFOLLOW || 0;
  if (!noFollow) {
    const lst = fs.lstatSync(realLeaf);
    if (lst.isSymbolicLink()) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `offensive capture must not be a symlink: ${realLeaf}`);
    }
  }
  let fd = null;
  try {
    fd = fs.openSync(realLeaf, fs.constants.O_RDONLY | noFollow);
    const stats = fs.fstatSync(fd);
    if (!stats.isFile()) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `offensive capture must be a regular file: ${realLeaf}`);
    }
    if (stats.nlink !== 1) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `offensive capture must not be hard-linked: ${realLeaf}`);
    }
    return crypto.createHash("sha256").update(fs.readFileSync(fd)).digest("hex");
  } finally {
    if (fd != null) {
      try { fs.closeSync(fd); } catch {}
    }
  }
}

// Securely realpath-resolve the capture dir the way readOffensiveRunRecords /
// sha256OffensiveCaptureSecure do (anchored to the real sessions root + safe
// domain), so a symlinked offensive-runs/ or session dir is rejected, not
// followed. Returns the real capture dir; creates it under the nominal dir first.
function resolveCaptureDirSecure(domain) {
  const nominalDir = offensiveRunsDir(domain);
  const nominalParent = path.dirname(nominalDir);
  const realRoot = fs.realpathSync(sessionsRoot());
  const expectedParent = path.join(realRoot, assertSafeDomain(domain));
  // Create + verify the SESSION dir BEFORE creating offensive-runs/ under it: a
  // recursive mkdir would otherwise FOLLOW a symlinked session dir and plant the
  // capture dir at the link target. Checking the parent first means children are
  // never created under a symlinked parent (the post-mkdir realpath check below is
  // kept as a second line for a symlinked offensive-runs/ leaf itself).
  fs.mkdirSync(nominalParent, { recursive: true });
  if (fs.realpathSync(nominalParent) !== expectedParent) {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `offensive-runs session dir must stay inside its session root without symlinks: ${nominalParent}`,
    );
  }
  fs.mkdirSync(nominalDir, { recursive: true });
  const expectedDir = path.join(expectedParent, "offensive-runs");
  const realDir = fs.realpathSync(nominalDir);
  if (realDir !== expectedDir) {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `offensive-runs capture dir must stay inside its session root without symlinks: ${nominalDir}`,
    );
  }
  return realDir;
}

// Write a capture leaf exclusively (O_NOFOLLOW via wx on a fresh path), then
// realpath/O_NOFOLLOW/nlink-recompute its on-disk sha256 — the recomputed hash
// (NOT an in-memory string) is what binds into the row, byte-identical to what
// projectExploitRunObservedRef re-hashes at freeze.
function writeCaptureAndHash(captureDir, runId, suffix, contentBytes) {
  const leaf = path.join(captureDir, `${runId}.${suffix}`);
  // Exclusive create + O_NOFOLLOW defeats a pre-planted symlink at the leaf path
  // (O_EXCL already fails on an existing link; O_NOFOLLOW makes the intent explicit
  // and matches sha256OfFileFd / appendSignedRowHardened).
  const fd = fs.openSync(
    leaf,
    fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW || 0),
    0o600,
  );
  try {
    fs.writeFileSync(fd, contentBytes);
    fs.fsyncSync(fd);
  } finally {
    try { fs.closeSync(fd); } catch {}
  }
  return sha256OfFileFd(leaf);
}

// Append one complete JSON line atomically. Single O_APPEND write of `${line}\n`
// so readOffensiveRunRecords (fail-closed on a partial line) never sees a torn
// record. Realpath/O_NOFOLLOW/nlink discipline on the ledger leaf.
function appendSignedRowHardened(domain, row) {
  const nominalPath = offensiveRunsJsonlPath(domain);
  const nominalDir = path.dirname(nominalPath);
  fs.mkdirSync(nominalDir, { recursive: true });
  const realRoot = fs.realpathSync(sessionsRoot());
  const expectedDir = path.join(realRoot, assertSafeDomain(domain));
  const realDir = fs.realpathSync(nominalDir);
  if (realDir !== expectedDir) {
    throw new ToolError(
      ERROR_CODES.STATE_CONFLICT,
      `offensive-runs.jsonl directory must stay inside its session root without domain-directory symlinks: ${nominalDir}`,
    );
  }
  const realLeaf = path.join(realDir, "offensive-runs.jsonl");
  const noFollow = fs.constants.O_NOFOLLOW || 0;
  if (!noFollow && fs.existsSync(realLeaf)) {
    const lst = fs.lstatSync(realLeaf);
    if (lst.isSymbolicLink()) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `offensive-runs.jsonl must not be a symlink: ${realLeaf}`);
    }
  }
  const line = `${JSON.stringify(row)}\n`;
  let fd = null;
  try {
    fd = fs.openSync(realLeaf, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_APPEND | noFollow, 0o600);
    const stats = fs.fstatSync(fd);
    if (!stats.isFile()) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `offensive-runs.jsonl must be a regular file: ${realLeaf}`);
    }
    if (stats.nlink !== 1) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `offensive-runs.jsonl must not be hard-linked: ${realLeaf}`);
    }
    fs.writeSync(fd, line);
    fs.fsyncSync(fd);
  } finally {
    if (fd != null) {
      try { fs.closeSync(fd); } catch {}
    }
  }
}

// Build + sign + persist the offensive row. Captures FIRST, recompute the on-disk
// content hashes (stdout/stderr, plus the consumable-artifact leaf when supplied),
// build the row, sign LAST, atomic append. Returns the persisted row (signed).
//
// CONCURRENCY CONTRACT: the run_id single-use guard (read-then-append) is only
// race-safe under the per-session lock, so the caller MUST invoke this inside
// withSessionLock(domain) (the IDOR producer does). Moving the lock into this
// primitive is the planned hardening for the next producer (it needs a re-entrancy
// check across both call sites); until then the contract is stated.
function buildAndSignOffensiveRow(domain, {
  runIdPrefix,
  toolId,
  method,
  canonicalTarget,
  surfaceId,
  identityTag,
  stdoutContent,
  stderrContent,
  consumedArtifactContent = null,
  relationBooleans = {},
  demonstratedSeverityOverride,
  offensiveOutcome = "exploited_safely",
  // The DECOY marker (cross-stack artifact-relevance closer). A decoy capture is a
  // real signed offensive row whose consumed bytes are random (NOT the real cause),
  // used as the third adjudication arm: a gate that validates the SPECIFIC credential
  // bytes must HOLD on the decoy. is_decoy is a writer-controlled MAC-covered sibling
  // (in RESERVED_ROW_KEYS so relationBooleans can never set/strip it). A decoy is
  // never a positive cause leg (offensiveOutcome must be blocked_by_defense — it
  // captured nothing real), so OFFENSIVE_LEDGER_ENTRY.demonstrates is false for it.
  isDecoy = false,
  // The ORACLE-KIND marker — a writer-controlled MAC-covered sibling identifying HOW
  // the safe exploit was observed. "out_of_band_interaction" marks a row whose evidence
  // is an external callback: the callback's CAUSATION by this injection is not proven by
  // the row alone (no pre-injection control; intermediary attribution is open), so such a
  // row is NOT a self-contained executed binding and must NOT self-skip the
  // finding-differential flip gate. null for a self-contained direct observation (IDOR,
  // reflected XSS) where the producer row itself is the executed binding.
  oracleKind = null,
  requireExplicitSeverity = false,
}) {
  // The offensive_outcome is a CONTROLLED, registry-bounded field. The positive
  // demonstrates the issue (exploited_safely); a negative control leg signs the
  // server's affirmative denial of a safe variant that actually ran (blocked_by_*).
  // Fail-closed reject of anything outside the frozen set keeps pre-request refusals
  // (blocked_by_design / blocked_operator_pii) — which have no executed observation —
  // permanently unsigned, and an arbitrary string can never become a signed outcome.
  if (!OFFENSIVE_ROW_OUTCOMES.has(offensiveOutcome)) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      `offensiveOutcome must be one of [${[...OFFENSIVE_ROW_OUTCOMES].join(", ")}]: ${offensiveOutcome}`,
    );
  }
  // oracleKind is a CONTROLLED, MAC-covered sibling: null (no oracle marker) or a member of
  // the frozen set. Validate it like offensiveOutcome so an arbitrary string can never be
  // signed into oracle_kind (the read-time gate keys on it).
  if (oracleKind != null && !OFFENSIVE_ROW_ORACLE_KINDS.has(oracleKind)) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      `oracleKind must be null or one of [${[...OFFENSIVE_ROW_ORACLE_KINDS].join(", ")}]: ${oracleKind}`,
    );
  }
  // Defense-in-depth for a tool whose registry ceiling is above the lowest tier and that decides
  // severity PER RUN (e.g. bob_http_massread_confirm: medium for v1, high only on a proven victim arm):
  // with a raised ceiling, an omitted override would default demonstrated_severity to the high ceiling
  // (fail-OPEN). Such a producer passes requireExplicitSeverity:true so a future call path / refactor that
  // forgets the override fails CLOSED here instead of silently signing the ceiling severity.
  if (requireExplicitSeverity && demonstratedSeverityOverride == null) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      `${toolId} requires an explicit demonstratedSeverityOverride (its registry ceiling is per-run; omitting it would fail open to the ceiling)`,
    );
  }
  // runIdPrefix flows into the capture-file path (newRunId -> path.join), so a
  // generic caller must not be able to smuggle a traversal segment into the
  // capture/ledger write. The IDOR producer hardcoded "idor-"; re-impose that
  // single-clean-segment guarantee here for EVERY producer. (suffix is internal —
  // only "stdout"/"stderr" — and the low-level helpers are no longer exported.)
  if (typeof runIdPrefix !== "string" || !/^[a-z][a-z0-9]*$/.test(runIdPrefix)) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      `runIdPrefix must be a lowercase [a-z][a-z0-9]* token: ${runIdPrefix}`,
    );
  }
  // The consumable artifact is the BYTES the on-chain side will consume. It is
  // OPTIONAL: a web-only finding produces none (consumed_artifact_hash:null). When
  // present it must be a string/Buffer so it can be written to a capture leaf and
  // hashed FROM THE ON-DISK BYTES (identical capture-first discipline to stdout).
  if (
    consumedArtifactContent != null
    && typeof consumedArtifactContent !== "string"
    && !Buffer.isBuffer(consumedArtifactContent)
  ) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      `consumedArtifactContent must be a string or Buffer when present, got ${typeof consumedArtifactContent}`,
    );
  }
  // demonstrated_severity is DERIVED from the per-tool registry, NEVER accepted from
  // the caller — a producer cannot drift its signed severity by convention, and an
  // unregistered tool_id cannot mint a row at all (fail-closed; stronger than the
  // record gate's ?? "info" cap, which still applies downstream).
  const registrySeverity = OFFENSIVE_TOOL_DEMONSTRATED_CEILING[toolId];
  if (typeof registrySeverity !== "string" || !registrySeverity) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      `unknown offensive tool_id (absent from the demonstrated-severity registry): ${toolId}`,
    );
  }
  // The registry value MUST be a known severity on EVERY path — not only when an override is
  // supplied. A registry typo (a non-empty string absent from SEVERITY_VALUES) would otherwise pass
  // straight through to the signed row's demonstrated_severity on the NO-override path, unvalidated.
  // A typo is a programming error, so fail closed rather than sign an out-of-enum severity.
  const registryIdx = SEVERITY_VALUES.indexOf(registrySeverity);
  if (registryIdx < 0) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      `registry demonstrated-severity for ${toolId} is not a known severity value: ${registrySeverity}`,
    );
  }
  // An optional per-row override may ONLY LOWER the registry ceiling — e.g. a soft-gated
  // IDOR fire whose cross-tenant attribution was unproven, which must be claim-VISIBLE as a
  // lower severity because the confidence signal itself is not carried into the claim/grade
  // schema. It can never RAISE severity: SEVERITY_VALUES is DESCENDING, so the less-severe
  // value is the higher index and Math.max selects it; an unknown override fails closed.
  let demonstratedSeverity = registrySeverity;
  if (demonstratedSeverityOverride != null) {
    const overrideIdx = SEVERITY_VALUES.indexOf(demonstratedSeverityOverride);
    if (overrideIdx < 0) {
      throw new ToolError(
        ERROR_CODES.INVALID_ARGUMENTS,
        `demonstratedSeverityOverride must be a known severity value: ${demonstratedSeverityOverride}`,
      );
    }
    demonstratedSeverity = SEVERITY_VALUES[Math.max(overrideIdx, registryIdx)];
  }
  // relationBooleans is spread into the row LAST (to document extra legs). It is
  // MAC-covered proof material, not a free-form bag, so it must neither override a
  // reserved proof-contract field NOR carry a non-boolean value — otherwise a caller
  // could clobber demonstrated_severity / *_hash / outcome, or smuggle arbitrary
  // signed data, before the MAC.
  for (const [key, value] of Object.entries(relationBooleans)) {
    if (RESERVED_ROW_KEYS.has(key)) {
      throw new ToolError(
        ERROR_CODES.INVALID_ARGUMENTS,
        `relationBooleans may not override reserved offensive-row field: ${key}`,
      );
    }
    if (typeof value !== "boolean") {
      throw new ToolError(
        ERROR_CODES.INVALID_ARGUMENTS,
        `relationBooleans.${key} must be a boolean (MAC-covered proof material), got ${typeof value}`,
      );
    }
  }

  const runId = newRunId(runIdPrefix);

  // run_id single-use guard (mint condition #25): refuse to re-emit a run_id
  // already present in offensive-runs.jsonl this session.
  const existing = readOffensiveRunRecords(domain);
  for (const r of existing) {
    if (r && r.run_id === runId) {
      throw new ToolError(ERROR_CODES.STATE_CONFLICT, `offensive run_id collision (refusing to re-emit): ${runId}`);
    }
  }

  const captureDir = resolveCaptureDirSecure(domain);
  // STEP 1 — write captures FIRST (audit-graded #115; MCP-owned, agents cannot Write here).
  const stdoutBytes = Buffer.from(stdoutContent, "utf8");
  const stderrBytes = Buffer.from(stderrContent, "utf8");
  // STEP 2 — recompute the THREE hashes FROM THE ON-DISK CAPTURE BYTES.
  const stdoutHash = writeCaptureAndHash(captureDir, runId, "stdout", stdoutBytes);
  const stderrHash = writeCaptureAndHash(captureDir, runId, "stderr", stderrBytes);
  const commandHash = commandHashOf(method, canonicalTarget, identityTag);
  // The CROSS-STACK CONSUMABLE artifact: the exact bytes the on-chain side fetches
  // and consumes. Written to its own MCP-owned capture leaf (offensive-runs/<run_id>.
  // consumed) under the same exclusive-create + O_NOFOLLOW + nlink discipline, then
  // hashed FROM THE ON-DISK BYTES so consumed_artifact_hash recomputes byte-identically
  // at the EVM-side fetch. null when no consumable artifact was captured (web-only).
  let consumedArtifactHash = null;
  if (consumedArtifactContent != null) {
    const consumedBytes = Buffer.isBuffer(consumedArtifactContent)
      ? consumedArtifactContent
      : Buffer.from(consumedArtifactContent, "utf8");
    consumedArtifactHash = writeCaptureAndHash(captureDir, runId, "consumed", consumedBytes);
  }

  // STEP 3 — build the row + optional MAC-covered relation booleans
  // (honest self-documentation, NOT a soundness control). demonstrated_severity
  // is HARDCODED from the producer ceiling, never agent-supplied/content-derived.
  // offensive_outcome is the registry-bounded executed observation (positive or the
  // negative control leg), validated above. exit_code stays 0: a blocked observation
  // is a COMPLETED execution (the server denied the safe variant), not a process
  // failure, so it is as non-forgeable as the positive (same capture-first/sign-last
  // discipline, same MAC coverage).
  const row = {
    version: 1,
    target_domain: domain,
    run_id: runId,
    tool_id: toolId,
    target: canonicalTarget,
    offensive_outcome: offensiveOutcome,
    dry_run: false,
    timed_out: false,
    command_hash: commandHash,
    exit_code: 0,
    stdout_hash: stdoutHash,
    stderr_hash: stderrHash,
    demonstrated_severity: demonstratedSeverity,
    surface_id: surfaceId,
    // The cross-stack consumable-artifact binding. A top-level SIBLING field OUTSIDE
    // command_hash/run identity (so capturing a derived artifact never perturbs run
    // identity) but INSIDE the row_mac (signRowViaIsolatedSignerOrLocal covers the
    // whole row minus row_mac), so an agent cannot swap the bytes for a run_id it did
    // not execute without invalidating the MAC. null for a web-only finding.
    consumed_artifact_hash: consumedArtifactHash,
    // The DECOY marker — a writer-controlled MAC-covered sibling, written ONLY for a
    // decoy row (so a non-decoy producer row keeps its exact existing shape). A decoy
    // carries is_decoy:true and RANDOM consumed bytes (provably NOT the real cause: a
    // distinct run_id, a distinct consumed_artifact_hash, a blocked_by_defense outcome
    // that demonstrates() rejects), used as the third adjudication arm. The cross-stack
    // adjudicator requires the decoy arm to HOLD, structurally forcing the gate to
    // validate the SPECIFIC credential bytes rather than any-non-empty.
    ...(isDecoy === true ? { is_decoy: true } : {}),
    // The oracle-kind sibling — written ONLY when the producer marks the observation
    // method (so a self-contained producer row keeps its exact existing shape). It is
    // MAC-covered and in RESERVED_ROW_KEYS, so relationBooleans can never set/strip it;
    // a read-time gate keys on it to refuse self-skip for non-causal callback evidence.
    ...(typeof oracleKind === "string" && oracleKind ? { oracle_kind: oracleKind } : {}),
    ...relationBooleans,
  };

  // STEP 4 — sign LAST (whole-row MAC auto-binds the relation booleans) through the
  // single signing seam, inside the caller's session lock. New rows are ed25519 (v2):
  // the verifiers verify them with the world-readable public key and never need a
  // secret. The seam isolates the secret when the operator runs the server under a
  // dedicated signer uid (the agent uid then gets EACCES on the key); on the same-uid
  // box it degrades to a local sign and the trust consequence is enforced at the
  // verdict-level attestation gate, not here. The seam backfills the keypair for a
  // session created before this surface existed.
  signRowViaIsolatedSignerOrLocal(domain, OFFENSIVE_ROW_MAC_CONTEXT, row);

  // APPEND — MCP-owned hardened writer.
  appendSignedRowHardened(domain, row);

  return row;
}

// Mint a DECOY capture — a real, MAC-signed offensive-runs row whose consumed bytes
// are cryptographically RANDOM (provably NOT the real cause). It is the third
// adjudication arm for the cross-stack flip: a gate that validates the SPECIFIC
// credential bytes accepts the real cause (positive -> VIOLATE) but REJECTS the random
// decoy (decoy -> HOLD); a tautological / any-non-empty gate accepts the decoy too
// (decoy -> VIOLATE, no flip) -> REFUSED. So a verified_pass structurally requires the
// artifact to be the REAL causal input, not merely "something present".
//
// SEMANTIC FAITHFULNESS (the hard part): the decoy must be indistinguishable-as-a-shape
// from the real cause so the ONLY thing that flips its outcome is the gate validating
// the byte CONTENT. The cross-stack mint path (fromCauseRunId) derives the decoy shape
// FROM THE CAUSE: it reads the named cause's SIGNED .consumed bytes (re-hashed against the
// cause row's MAC-covered consumed_artifact_hash so a forged/unsigned cause is refused
// before any decoy mint) and generates RANDOM content of the SAME byte length AND SAME
// encoding class (raw/hex/base64/json/jwt; for structured shapes the same grammar with
// randomized leaf/secret-bearing fields). A gate can no longer distinguish the decoy from
// the cause by length OR shape — rejecting it REQUIRES validating the byte content. The
// decoy injects through the identical .consumed-leaf + hex-env path the real cause uses and
// differs from the cause EXCLUSIVELY in being random content that is not the captured
// credential. The generic byteLength path stays for non-cross-stack/test use.
//
// It is minted EXACTLY like a real capture (buildAndSignOffensiveRow's capture-first /
// sign-last discipline) but with offensiveOutcome:"blocked_by_defense" (a decoy
// captured nothing real, so it can never stand in as the cause leg) and is_decoy:true
// (a MAC-covered sibling an agent cannot strip/flip). MUST be called inside
// withSessionLock(domain) like buildAndSignOffensiveRow.
function mintDecoyCapture(domain, {
  toolId,
  method,
  canonicalTarget,
  surfaceId,
  identityTag,
  byteLength = 32,
  runIdPrefix = "decoy",
  // CROSS-STACK shape-derivation: when set, the decoy bytes are minted FROM the named
  // cause's stored consumable (same length + encoding class, random content), and byteLength
  // is ignored. Fails closed (throws) if the cause's bytes are missing or no longer hash to
  // the cause row's MAC-covered consumed_artifact_hash — a decoy is never minted off an
  // unverified cause shape.
  fromCauseRunId = null,
}) {
  let decoyBytes;
  if (typeof fromCauseRunId === "string" && fromCauseRunId.trim()) {
    decoyBytes = deriveShapeMatchedDecoyFromCause(domain, fromCauseRunId.trim());
  } else {
    const len = Number.isInteger(byteLength) && byteLength > 0 ? byteLength : 32;
    decoyBytes = crypto.randomBytes(len);
  }
  return buildAndSignOffensiveRow(domain, {
    runIdPrefix,
    toolId,
    method,
    canonicalTarget,
    surfaceId,
    identityTag,
    stdoutContent: "",
    stderrContent: "",
    // RANDOM consumed bytes — provably not the real cause. On the cross-stack path these
    // are SHAPE-MATCHED to the cause (same length + encoding class, random content).
    consumedArtifactContent: decoyBytes,
    // A decoy is a denial, never a positive cause leg (demonstrates() is false).
    offensiveOutcome: "blocked_by_defense",
    isDecoy: true,
  });
}

// Read the named cause's SIGNED .consumed bytes (re-hashed against the cause row's MAC-
// covered consumed_artifact_hash) and mint a SHAPE-MATCHED random decoy: same byte length,
// same encoding class, random content. Fails closed (throws) on a missing/unsigned/forged
// cause or absent capture bytes — a decoy must never be minted off an unverified cause
// shape (a wrong-shape decoy is exactly the HIGH-2 forgery this path closes). A post-gen
// distinctness assertion guarantees the decoy content is not the cause content.
function deriveShapeMatchedDecoyFromCause(domain, causeRunId) {
  // eslint-disable-next-line global-require
  const { readOffensiveRunRecords: readRows } = require("./claims.js");
  // eslint-disable-next-line global-require
  const { assertRowMac } = require("./offensive-row-mac.js");
  // eslint-disable-next-line global-require
  const { resolveRowVerifierSafely } = require("./handoff-signing-key.js");
  // eslint-disable-next-line global-require
  const { readOffensiveCaptureBytesSecure } = require("./claim-freeze.js");
  const rows = readRows(domain);
  const causeRow = rows.find((r) => r && r.run_id === causeRunId) || null;
  if (causeRow == null) {
    throw new Error(`cross-stack decoy mint: cause run ${causeRunId} not found in offensive-runs`);
  }
  // STRICT MAC: the cause shape must come from a genuinely signed row, never an unsigned
  // legacy/forged row a same-uid actor could have appended.
  assertRowMac(OFFENSIVE_ROW_MAC_CONTEXT, causeRow, resolveRowVerifierSafely(domain));
  const causeHash = typeof causeRow.consumed_artifact_hash === "string"
    && /^[0-9a-f]{64}$/.test(causeRow.consumed_artifact_hash)
    ? causeRow.consumed_artifact_hash
    : null;
  if (causeHash == null) {
    throw new Error(`cross-stack decoy mint: cause run ${causeRunId} captured no consumable artifact (consumed_artifact_hash null)`);
  }
  const fetched = readOffensiveCaptureBytesSecure(domain, causeRunId, "consumed");
  if (fetched == null || fetched.sha256 !== causeHash) {
    throw new Error(`cross-stack decoy mint: cause run ${causeRunId} stored bytes do not hash to its MAC-covered consumed_artifact_hash`);
  }
  let decoyBytes = mintShapeMatchedDecoyBytes(fetched.bytes);
  // The decoy MUST differ from the cause (random content). Re-roll on the astronomically-
  // unlikely collision so the verifier's distinctness leg can never trip on a genuine mint.
  let attempts = 0;
  while (Buffer.compare(decoyBytes, fetched.bytes) === 0 && attempts < 4) {
    decoyBytes = mintShapeMatchedDecoyBytes(fetched.bytes);
    attempts += 1;
  }
  if (Buffer.compare(decoyBytes, fetched.bytes) === 0) {
    throw new Error("cross-stack decoy mint: could not generate decoy content distinct from the cause");
  }
  return decoyBytes;
}

// Only the high-level build+sign+append entry points are public. The low-level
// capture/hash/append helpers stay module-internal so a producer mints a signed
// offensive-runs row ONLY through the disciplined build path — and a row is still
// not a finding until a candidate claim cites it through the record-time proof
// gate + per-tool demonstrated-severity ceiling + #111 surface binding.
module.exports = {
  buildAndSignOffensiveRow,
  mintDecoyCapture,
};
