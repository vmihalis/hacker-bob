"use strict";

// PH-S12 durable integration coordinator.
//
// The ordinary frontier-events.jsonl and task-graph.json paths are unchanged.
// Campaigns whose declared expansion crosses the TaskGraph fold ceiling route
// canonical Frontier events into bounded immutable segment ledgers under the
// same session authority.  Each segment is folded by the existing TaskGraph
// materializer in memory; no second graph document/store is created.  The
// signed closure segment binds that graph hash and the exact persisted event
// digests.

const fs = require("node:fs");
const path = require("node:path");
const { types: utilTypes } = require("node:util");

const {
  assertSafeDomain,
  physicalCampaignDir,
  physicalSessionBootstrapPath,
  sessionNucleusPath,
  statePath,
} = require("../../core/io/paths.js");
const {
  withSessionLock,
} = require("../../core/io/storage.js");
const {
  readVerifiedSessionNucleus,
} = require("../../core/governance/index.js");
const {
  sessionNucleusFromState,
} = require("../../core/governance/index.js");
const {
  readSessionStateStrict,
} = require("../../core/session/session-state-store.js");
const {
  normalizeFrontierEvent,
} = require("../../core/frontier/frontier-events.js");
const {
  materializeTaskGraphEvents,
} = require("../../core/waves/task-graph-materializer.js");
const {
  canonicalJson,
  hashCanonicalJson,
} = require("../../core/verification/verification-contracts.js");
const {
  assertPhysicalCampaignClosureSatisfied,
  buildPhysicalCampaignClosurePreflight,
  campaignGenesisDigest,
  createPhysicalCampaignClosureAccumulator,
  exportPhysicalCampaignEd25519VerifierDescriptor,
  importPhysicalCampaignEd25519VerifierDescriptor,
  normalizePhysicalCampaignClosurePreflight,
  sealPhysicalCampaignClosureSegment,
} = require("./physical-campaign-closure.js");
const {
  PHYSICAL_CAMPAIGN_ANCHOR_NAMESPACE,
  PHYSICAL_CAMPAIGN_ANCHOR_PORT_VERSION,
  compareAndSetPhysicalCampaignAnchor,
  isPhysicalCampaignAnchorResolverInstalled,
  physicalCampaignAnchorPortAssurance,
  probePhysicalCampaignAnchorPort,
  readPhysicalCampaignAnchor,
  resolvePhysicalCampaignAnchorPort,
} = require("./physical-campaign-anchor.js");

const PHYSICAL_CAMPAIGN_COORDINATOR_VERSION = 1;
const CAMPAIGN_DOCUMENT_MAX_BYTES = 64 * 1024 * 1024;
const CAMPAIGN_LEDGER_MAX_BYTES = 64 * 1024 * 1024;
const HASH_PATTERN = /^[a-f0-9]{64}$/u;
const PREFLIGHT_FILE = "preflight.json";
const CHECKPOINT_FILE = "checkpoint.json";
const ANCHOR_FILE = "checkpoint-anchor.json";
const MANIFEST_FILE = "aggregate-manifest.json";

function coordinatorError(code, message, details = null) {
  const error = new Error(`${code}: ${message}`);
  error.code = code;
  if (details != null) error.details = Object.freeze({ ...details });
  return error;
}

function assertDigest(value, label) {
  if (typeof value !== "string" || !HASH_PATTERN.test(value)) {
    throw coordinatorError("physical_campaign_contract_invalid", `${label} must be a SHA-256 digest`);
  }
  return value;
}

function assertInteger(value, label, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw coordinatorError(
      "physical_campaign_contract_invalid",
      `${label} must be an integer in ${minimum}..${maximum}`,
    );
  }
  return value;
}

function assertPlainRecord(value, label) {
  if (value != null && typeof value === "object" && utilTypes.isProxy(value)) {
    throw coordinatorError("physical_campaign_contract_invalid", `${label} cannot be a Proxy`);
  }
  if (value == null || typeof value !== "object" || Array.isArray(value)) {
    throw coordinatorError("physical_campaign_contract_invalid", `${label} must be a plain object`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw coordinatorError("physical_campaign_contract_invalid", `${label} must be a plain object`);
  }
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== "string") {
      throw coordinatorError("physical_campaign_contract_invalid", `${label} cannot have symbol fields`);
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, "value")
        || descriptor.enumerable !== true) {
      throw coordinatorError(
        "physical_campaign_contract_invalid",
        `${label}.${key} must be an enumerable data property`,
      );
    }
  }
  return value;
}

function assertDataArray(value, label) {
  if (value != null && typeof value === "object" && utilTypes.isProxy(value)) {
    throw coordinatorError("physical_campaign_contract_invalid", `${label} cannot be a Proxy`);
  }
  if (!Array.isArray(value)) {
    throw coordinatorError("physical_campaign_contract_invalid", `${label} must be an array`);
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, "value")
        || descriptor.enumerable !== true) {
      throw coordinatorError(
        "physical_campaign_contract_invalid",
        `${label}[${index}] must be an enumerable data property`,
      );
    }
  }
  const extras = Reflect.ownKeys(descriptors).filter((key) => (
    key !== "length" && (typeof key !== "string" || !/^(0|[1-9][0-9]*)$/u.test(key)
      || Number(key) >= value.length)
  ));
  if (extras.length > 0) {
    throw coordinatorError("physical_campaign_contract_invalid", `${label} has extra properties`);
  }
  return value;
}

function assertExactFields(value, fields, label) {
  assertPlainRecord(value, label);
  const expected = fields.slice().sort();
  const actual = Object.keys(value).sort();
  if (canonicalJson(expected) !== canonicalJson(actual)) {
    throw coordinatorError("physical_campaign_contract_invalid", `${label} fields are not exact`);
  }
  return value;
}

function copyPlainJsonData(value, label, depth = 0) {
  if (depth > 24) {
    throw coordinatorError("physical_campaign_contract_invalid", `${label} nesting is too deep`);
  }
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (Array.isArray(value)) {
    assertDataArray(value, label);
    return value.map((entry, index) => copyPlainJsonData(entry, `${label}[${index}]`, depth + 1));
  }
  assertPlainRecord(value, label);
  const out = {};
  for (const key of Object.keys(value)) {
    out[key] = copyPlainJsonData(value[key], `${label}.${key}`, depth + 1);
  }
  return out;
}

function pathsFor(domain) {
  const root = physicalCampaignDir(domain);
  return Object.freeze({
    root,
    preflight: path.join(root, PREFLIGHT_FILE),
    checkpoint: path.join(root, CHECKPOINT_FILE),
    anchor: path.join(root, ANCHOR_FILE),
    manifest: path.join(root, MANIFEST_FILE),
    segments: path.join(root, "segments"),
  });
}

function pathEntryPresent(filePath, label) {
  try {
    fs.lstatSync(filePath);
    return true;
  } catch (error) {
    if (error && error.code === "ENOENT") return false;
    throw coordinatorError(
      "physical_campaign_storage_invalid",
      `${label} could not be inspected`,
    );
  }
}

// An absent campaign root is normally vacuous. Do not make pre-nucleus legacy
// web/repo fixtures manufacture physical authority merely because the PH-S12
// gate is registered. At the same time, never use "nucleus missing" as a way
// to erase a declared physical axis: a physical state/bootstrap marker without
// its canonical verified nucleus is corruption and remains fail-closed.
//
// A valid non-physical legacy state can still derive the exact canonical
// nucleus hash needed to probe an enrolled external campaign anchor. This
// preserves rollback detection when an ordinary web/repo session hosted a
// physical campaign and both its campaign root and legacy nucleus mirror were
// deleted while state.json survived.
function campaignProbeNucleusForAbsentRoot(domain) {
  const bootstrapPresent = pathEntryPresent(
    physicalSessionBootstrapPath(domain),
    "physical session bootstrap journal",
  );
  const nucleusPresent = pathEntryPresent(
    sessionNucleusPath(domain),
    "session nucleus",
  );
  const statePresent = pathEntryPresent(statePath(domain), "session state");

  if (nucleusPresent) {
    const nucleus = readVerifiedSessionNucleus(domain);
    if (bootstrapPresent && nucleus.physical_scope == null) {
      throw coordinatorError(
        "physical_campaign_session_authority_drift",
        "physical session bootstrap exists but the verified nucleus has no physical scope",
      );
    }
    if (nucleus.physical_scope != null) {
      if (!statePresent) {
        throw coordinatorError(
          "physical_campaign_session_authority_missing",
          "physical session nucleus exists without canonical session state",
        );
      }
      const stateNucleus = sessionNucleusFromState(readSessionStateStrict(domain).state);
      if (stateNucleus.nucleus_hash !== nucleus.nucleus_hash) {
        throw coordinatorError(
          "physical_campaign_session_authority_drift",
          "physical session state and verified nucleus differ",
        );
      }
    }
    return nucleus;
  }

  if (statePresent) {
    const { state } = readSessionStateStrict(domain);
    if (state.physical_scope != null) {
      throw coordinatorError(
        "physical_campaign_session_authority_missing",
        "physical session state exists without its verified session nucleus",
      );
    }
    if (bootstrapPresent) {
      throw coordinatorError(
        "physical_campaign_session_authority_missing",
        "physical session bootstrap exists without its verified session nucleus",
      );
    }
    return sessionNucleusFromState(state);
  }

  if (bootstrapPresent) {
    throw coordinatorError(
      "physical_campaign_session_authority_missing",
      "physical session bootstrap exists without canonical session state or nucleus",
    );
  }
  return null;
}

function segmentRelativePath(segmentIndex) {
  return `segments/${String(segmentIndex).padStart(6, "0")}/frontier-events.jsonl`;
}

function segmentLedgerPath(campaignPaths, segmentIndex) {
  return path.join(campaignPaths.root, segmentRelativePath(segmentIndex));
}

function realDirectory(directoryPath, label, { create = false } = {}) {
  if (create) fs.mkdirSync(directoryPath, { recursive: true, mode: 0o700 });
  const stats = fs.lstatSync(directoryPath);
  if (!stats.isDirectory() || stats.isSymbolicLink()) {
    throw coordinatorError("physical_campaign_storage_invalid", `${label} must be a real directory`);
  }
  return { dev: stats.dev, ino: stats.ino };
}

function assertDirectoryIdentity(directoryPath, identity, label) {
  const stats = fs.lstatSync(directoryPath);
  if (!stats.isDirectory() || stats.isSymbolicLink()
      || stats.dev !== identity.dev || stats.ino !== identity.ino) {
    throw coordinatorError("physical_campaign_storage_invalid", `${label} changed during storage operation`);
  }
}

function ensureLayout(campaignPaths) {
  const root = realDirectory(campaignPaths.root, "physical campaign directory", { create: true });
  const segments = realDirectory(campaignPaths.segments, "physical campaign segments directory", {
    create: true,
  });
  assertDirectoryIdentity(campaignPaths.root, root, "physical campaign directory");
  return { root, segments };
}

function fsyncDirectory(directoryPath) {
  const descriptor = fs.openSync(directoryPath, fs.constants.O_RDONLY);
  try {
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
}

function tempPathFor(filePath) {
  return path.join(
    path.dirname(filePath),
    `.${path.basename(filePath)}.${process.pid}.${Date.now()}.${Math.random().toString(16).slice(2)}.tmp`,
  );
}

function writeDurableAtomic(filePath, content) {
  const directoryPath = path.dirname(filePath);
  const directoryIdentity = realDirectory(directoryPath, "campaign artifact parent", { create: true });
  const tempPath = tempPathFor(filePath);
  let descriptor;
  try {
    descriptor = fs.openSync(
      tempPath,
      fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY
        | (fs.constants.O_NOFOLLOW || 0),
      0o600,
    );
    fs.writeFileSync(descriptor, content, "utf8");
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor);
    descriptor = null;
    assertDirectoryIdentity(directoryPath, directoryIdentity, "campaign artifact parent");
    fs.renameSync(tempPath, filePath);
    fsyncDirectory(directoryPath);
    const finalStats = fs.lstatSync(filePath);
    if (!finalStats.isFile() || finalStats.isSymbolicLink() || finalStats.nlink !== 1) {
      throw coordinatorError("physical_campaign_storage_invalid", "durable write produced an unsafe file");
    }
  } finally {
    if (descriptor != null) fs.closeSync(descriptor);
    try { fs.unlinkSync(tempPath); } catch {}
  }
}

function readVerifiedText(filePath, label, maximumBytes) {
  const directoryPath = path.dirname(filePath);
  const directoryIdentity = realDirectory(directoryPath, `${label} parent`);
  const pathStats = fs.lstatSync(filePath);
  if (!pathStats.isFile() || pathStats.isSymbolicLink() || pathStats.nlink !== 1
      || pathStats.size > maximumBytes) {
    throw coordinatorError("physical_campaign_storage_invalid", `${label} failed verified-read constraints`);
  }
  let descriptor;
  try {
    descriptor = fs.openSync(filePath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
    const stats = fs.fstatSync(descriptor);
    if (!stats.isFile() || stats.nlink !== 1 || stats.size !== pathStats.size
        || stats.dev !== pathStats.dev || stats.ino !== pathStats.ino) {
      throw coordinatorError("physical_campaign_storage_invalid", `${label} changed before verified read`);
    }
    const content = fs.readFileSync(descriptor, "utf8");
    const finalStats = fs.lstatSync(filePath);
    if (!finalStats.isFile() || finalStats.isSymbolicLink() || finalStats.nlink !== 1
        || finalStats.dev !== stats.dev || finalStats.ino !== stats.ino
        || finalStats.size !== stats.size) {
      throw coordinatorError("physical_campaign_storage_invalid", `${label} changed during verified read`);
    }
    assertDirectoryIdentity(directoryPath, directoryIdentity, `${label} parent`);
    return content;
  } finally {
    if (descriptor != null) fs.closeSync(descriptor);
  }
}

function readVerifiedJson(filePath, label) {
  let parsed;
  try {
    parsed = JSON.parse(readVerifiedText(filePath, label, CAMPAIGN_DOCUMENT_MAX_BYTES));
  } catch (error) {
    if (error && error.code) throw error;
    throw coordinatorError("physical_campaign_storage_invalid", `${label} is not valid JSON`);
  }
  return copyPlainJsonData(parsed, label);
}

function writeDurableJson(filePath, document) {
  writeDurableAtomic(filePath, `${JSON.stringify(document, null, 2)}\n`);
}

function writeImmutableText(filePath, content, label) {
  if (fs.existsSync(filePath)) {
    const existing = readVerifiedText(filePath, label, CAMPAIGN_LEDGER_MAX_BYTES);
    if (existing !== content) {
      throw coordinatorError("physical_campaign_segment_fork", `${label} already contains different bytes`);
    }
    return false;
  }
  const directoryPath = path.dirname(filePath);
  const directoryIdentity = realDirectory(directoryPath, `${label} parent`, { create: true });
  const tempPath = tempPathFor(filePath);
  let descriptor;
  try {
    descriptor = fs.openSync(
      tempPath,
      fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY
        | (fs.constants.O_NOFOLLOW || 0),
      0o600,
    );
    fs.writeFileSync(descriptor, content, "utf8");
    fs.fsyncSync(descriptor);
    fs.closeSync(descriptor);
    descriptor = null;
    assertDirectoryIdentity(directoryPath, directoryIdentity, `${label} parent`);
    try {
      fs.linkSync(tempPath, filePath);
    } catch (error) {
      if (!error || error.code !== "EEXIST") throw error;
      const existing = readVerifiedText(filePath, label, CAMPAIGN_LEDGER_MAX_BYTES);
      if (existing !== content) {
        throw coordinatorError("physical_campaign_segment_fork", `${label} raced different bytes`);
      }
      return false;
    }
    fs.unlinkSync(tempPath);
    fsyncDirectory(directoryPath);
    const finalStats = fs.lstatSync(filePath);
    if (!finalStats.isFile() || finalStats.isSymbolicLink() || finalStats.nlink !== 1) {
      throw coordinatorError("physical_campaign_storage_invalid", `${label} is not immutable-safe`);
    }
    return true;
  } finally {
    if (descriptor != null) fs.closeSync(descriptor);
    try { fs.unlinkSync(tempPath); } catch {}
  }
}

function preflightEnvelope(domain, preflight, verifierDescriptor, anchorSlotDigest) {
  const basis = {
    version: PHYSICAL_CAMPAIGN_COORDINATOR_VERSION,
    target_domain: domain,
    anchor_slot_digest: assertDigest(anchorSlotDigest, "anchor_slot_digest"),
    preflight,
    verifier: verifierDescriptor,
  };
  return Object.freeze({
    ...basis,
    envelope_digest: hashCanonicalJson({
      domain: "hacker-bob/physical-campaign-preflight-envelope/v1",
      ...basis,
    }),
  });
}

function normalizePreflightEnvelope(domain, input, expectedAnchorSlotDigest) {
  assertExactFields(
    input,
    [
      "version",
      "target_domain",
      "anchor_slot_digest",
      "preflight",
      "verifier",
      "envelope_digest",
    ],
    "physical campaign preflight envelope",
  );
  if (input.version !== PHYSICAL_CAMPAIGN_COORDINATOR_VERSION
      || input.target_domain !== domain
      || input.anchor_slot_digest !== expectedAnchorSlotDigest) {
    throw coordinatorError("physical_campaign_authority_drift", "preflight envelope session binding drifted");
  }
  const preflight = normalizePhysicalCampaignClosurePreflight(input.preflight);
  const verifier = importPhysicalCampaignEd25519VerifierDescriptor(input.verifier);
  if (verifier.signer_key_ref !== preflight.closure_signer_key_ref
      || verifier.signer_public_key_digest !== preflight.closure_signer_public_key_digest) {
    throw coordinatorError("physical_campaign_authority_drift", "persisted verifier differs from preflight");
  }
  const normalized = preflightEnvelope(
    domain,
    preflight,
    exportPhysicalCampaignEd25519VerifierDescriptor(verifier),
    assertDigest(input.anchor_slot_digest, "preflight anchor_slot_digest"),
  );
  if (input.envelope_digest !== normalized.envelope_digest
      || canonicalJson(input) !== canonicalJson(normalized)) {
    throw coordinatorError("physical_campaign_preflight_tamper", "preflight envelope content drifted");
  }
  const nucleus = readVerifiedSessionNucleus(domain);
  if (nucleus.nucleus_hash !== preflight.session_nucleus_hash) {
    throw coordinatorError("physical_campaign_authority_drift", "live session nucleus differs from campaign");
  }
  return { envelope: normalized, preflight, verifier };
}

function checkpointEnvelope(domain, preflight, generation, previousAnchorDigest, checkpoint, ledgers) {
  const basis = {
    version: PHYSICAL_CAMPAIGN_COORDINATOR_VERSION,
    target_domain: domain,
    campaign_id: preflight.campaign_id,
    preflight_digest: preflight.preflight_digest,
    session_nucleus_hash: preflight.session_nucleus_hash,
    generation,
    previous_anchor_digest: previousAnchorDigest,
    accumulator_checkpoint: checkpoint,
    segment_ledgers: ledgers,
  };
  return Object.freeze({
    ...basis,
    checkpoint_envelope_digest: hashCanonicalJson({
      domain: "hacker-bob/physical-campaign-checkpoint-envelope/v1",
      ...basis,
    }),
  });
}

function normalizeCheckpointEnvelope(domain, preflight, input) {
  assertExactFields(
    input,
    [
      "version",
      "target_domain",
      "campaign_id",
      "preflight_digest",
      "session_nucleus_hash",
      "generation",
      "previous_anchor_digest",
      "accumulator_checkpoint",
      "segment_ledgers",
      "checkpoint_envelope_digest",
    ],
    "physical campaign checkpoint envelope",
  );
  if (input.version !== PHYSICAL_CAMPAIGN_COORDINATOR_VERSION
      || input.target_domain !== domain
      || input.campaign_id !== preflight.campaign_id
      || input.preflight_digest !== preflight.preflight_digest
      || input.session_nucleus_hash !== preflight.session_nucleus_hash) {
    throw coordinatorError("physical_campaign_authority_drift", "checkpoint envelope authority drifted");
  }
  const generation = assertInteger(input.generation, "checkpoint generation", 0, preflight.segment_count);
  const previousAnchorDigest = input.previous_anchor_digest == null
    ? null
    : assertDigest(input.previous_anchor_digest, "previous_anchor_digest");
  if (generation === 0 && previousAnchorDigest !== null) {
    throw coordinatorError("physical_campaign_checkpoint_tamper", "genesis checkpoint cannot link an anchor");
  }
  assertDataArray(input.segment_ledgers, "checkpoint segment_ledgers");
  if (input.segment_ledgers.length !== generation) {
    throw coordinatorError("physical_campaign_checkpoint_tamper", "checkpoint ledger generation is not exact");
  }
  const ledgers = input.segment_ledgers.map((receipt, index) => {
    assertExactFields(
      receipt,
      [
        "segment_index",
        "relative_path",
        "event_count",
        "ledger_digest",
        "materialized_graph_hash",
      ],
      `segment_ledgers[${index}]`,
    );
    if (receipt.segment_index !== index || receipt.relative_path !== segmentRelativePath(index)) {
      throw coordinatorError("physical_campaign_checkpoint_tamper", "segment ledger path/index drifted");
    }
    return Object.freeze({
      segment_index: index,
      relative_path: segmentRelativePath(index),
      event_count: assertInteger(
        receipt.event_count,
        `segment_ledgers[${index}].event_count`,
        1,
        preflight.segment_event_limit,
      ),
      ledger_digest: assertDigest(receipt.ledger_digest, `segment_ledgers[${index}].ledger_digest`),
      materialized_graph_hash: assertDigest(
        receipt.materialized_graph_hash,
        `segment_ledgers[${index}].materialized_graph_hash`,
      ),
    });
  });
  const claimedDigest = assertDigest(
    input.checkpoint_envelope_digest,
    "checkpoint_envelope_digest",
  );
  const normalized = checkpointEnvelope(
    domain,
    preflight,
    generation,
    previousAnchorDigest,
    copyPlainJsonData(input.accumulator_checkpoint, "accumulator_checkpoint"),
    ledgers,
  );
  if (claimedDigest !== normalized.checkpoint_envelope_digest) {
    throw coordinatorError("physical_campaign_checkpoint_tamper", "checkpoint envelope digest drifted");
  }
  return normalized;
}

function anchorDocument(
  domain,
  preflight,
  anchorSlotDigest,
  generation,
  checkpointDigest,
  previousAnchorDigest,
) {
  const basis = {
    version: PHYSICAL_CAMPAIGN_COORDINATOR_VERSION,
    target_domain: domain,
    campaign_id: preflight.campaign_id,
    preflight_digest: preflight.preflight_digest,
    session_nucleus_hash: preflight.session_nucleus_hash,
    anchor_slot_digest: assertDigest(anchorSlotDigest, "anchor_slot_digest"),
    generation,
    checkpoint_envelope_digest: checkpointDigest,
    previous_anchor_digest: previousAnchorDigest,
  };
  return Object.freeze({
    ...basis,
    anchor_digest: hashCanonicalJson({
      domain: "hacker-bob/physical-campaign-checkpoint-anchor/v1",
      ...basis,
    }),
  });
}

function normalizeAnchor(domain, preflight, input, expectedAnchorSlotDigest) {
  assertExactFields(
    input,
    [
      "version",
      "target_domain",
      "campaign_id",
      "preflight_digest",
      "session_nucleus_hash",
      "anchor_slot_digest",
      "generation",
      "checkpoint_envelope_digest",
      "previous_anchor_digest",
      "anchor_digest",
    ],
    "physical campaign checkpoint anchor",
  );
  if (input.version !== PHYSICAL_CAMPAIGN_COORDINATOR_VERSION
      || input.target_domain !== domain
      || input.campaign_id !== preflight.campaign_id
      || input.preflight_digest !== preflight.preflight_digest
      || input.session_nucleus_hash !== preflight.session_nucleus_hash
      || input.anchor_slot_digest !== expectedAnchorSlotDigest) {
    throw coordinatorError("physical_campaign_authority_drift", "checkpoint anchor authority drifted");
  }
  const generation = assertInteger(input.generation, "anchor generation", 0, preflight.segment_count);
  const previousAnchorDigest = input.previous_anchor_digest == null
    ? null
    : assertDigest(input.previous_anchor_digest, "anchor previous_anchor_digest");
  if (generation === 0 && previousAnchorDigest !== null) {
    throw coordinatorError("physical_campaign_anchor_tamper", "genesis anchor cannot link a prior anchor");
  }
  const normalized = anchorDocument(
    domain,
    preflight,
    assertDigest(input.anchor_slot_digest, "anchor anchor_slot_digest"),
    generation,
    assertDigest(input.checkpoint_envelope_digest, "anchor checkpoint_envelope_digest"),
    previousAnchorDigest,
  );
  if (input.anchor_digest !== normalized.anchor_digest) {
    throw coordinatorError("physical_campaign_anchor_tamper", "checkpoint anchor digest drifted");
  }
  return normalized;
}

function externalAnchorContext(domain) {
  return Object.freeze({
    version: PHYSICAL_CAMPAIGN_ANCHOR_PORT_VERSION,
    anchor_namespace: PHYSICAL_CAMPAIGN_ANCHOR_NAMESPACE,
    target_domain: domain,
  });
}

function sameDocument(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

function readExternalAnchor(anchorPort, domain, preflight) {
  const raw = readPhysicalCampaignAnchor(
    anchorPort,
    externalAnchorContext(domain),
  );
  return raw == null
    ? null
    : normalizeAnchor(
      domain,
      preflight,
      raw,
      physicalCampaignAnchorPortAssurance(anchorPort).anchor_slot_digest,
    );
}

function ambiguousAnchorCommit(cause = null) {
  const error = coordinatorError(
    "physical_campaign_anchor_commit_ambiguous",
    "external campaign anchor commit outcome could not be proven by read-back",
  );
  Object.defineProperty(error, "anchor_commit_outcome", { value: "ambiguous" });
  if (cause != null) Object.defineProperty(error, "cause", { value: cause });
  return error;
}

function pendingAnchorCommit() {
  const error = coordinatorError(
    "physical_campaign_anchor_commit_pending",
    "external campaign anchor retained the expected head; the exact durable local tail remains pending",
  );
  Object.defineProperty(error, "anchor_commit_outcome", { value: "pending" });
  return error;
}

function commitExternalAnchor(anchorPort, domain, preflight, expected, next) {
  let compareResult;
  let compareFailure = null;
  try {
    compareResult = compareAndSetPhysicalCampaignAnchor(
      anchorPort,
      externalAnchorContext(domain),
      expected,
      next,
    );
  } catch (error) {
    compareFailure = error;
  }

  let observed;
  try {
    observed = readExternalAnchor(anchorPort, domain, preflight);
  } catch (readFailure) {
    throw ambiguousAnchorCommit(compareFailure || readFailure);
  }
  if (observed != null && sameDocument(observed, next)) return observed;
  if (!sameDocument(observed, expected)) {
    throw coordinatorError(
      "physical_campaign_checkpoint_fork",
      "external campaign anchor advanced to a different valid head",
    );
  }
  if (compareFailure != null || compareResult === true) {
    throw ambiguousAnchorCommit(compareFailure);
  }
  throw pendingAnchorCommit();
}

function physicalCampaignMetadata(event, label) {
  const metadata = event && event.payload && event.payload.physical_campaign;
  assertExactFields(
    metadata,
    [
      "version",
      "campaign_id",
      "preflight_digest",
      "segment_index",
      "segment_key",
      "cell_id",
      "event_ordinal",
      "terminal_state",
      "terminal_witness_digest",
    ],
    `${label}.payload.physical_campaign`,
  );
  return metadata;
}

function foldPersistedSegment(domain, preflight, segmentIndex, events) {
  const plan = preflight.segments[segmentIndex];
  const closureEvents = [];
  for (let index = 0; index < events.length; index += 1) {
    const event = events[index];
    const metadata = physicalCampaignMetadata(event, `events[${index}]`);
    if (metadata.version !== PHYSICAL_CAMPAIGN_COORDINATOR_VERSION
        || metadata.campaign_id !== preflight.campaign_id
        || metadata.preflight_digest !== preflight.preflight_digest
        || metadata.segment_index !== segmentIndex
        || metadata.segment_key !== plan.segment_key) {
      throw coordinatorError("physical_campaign_segment_tamper", "persisted event campaign binding drifted");
    }
    const closureEvent = {
      cell_id: metadata.cell_id,
      event_ordinal: metadata.event_ordinal,
      event_kind: event.kind,
      source_event_digest: event.event_hash,
    };
    if (metadata.event_ordinal === preflight.events_per_cell) {
      closureEvent.terminal_state = metadata.terminal_state;
      closureEvent.terminal_witness_digest = metadata.terminal_witness_digest;
    } else if (metadata.terminal_state !== null || metadata.terminal_witness_digest !== null) {
      throw coordinatorError("physical_campaign_segment_tamper", "nonterminal event carries terminal fields");
    }
    closureEvents.push(closureEvent);
  }
  const materialized = materializeTaskGraphEvents(domain, events, { now: new Date(0) });
  return {
    closureEvents,
    materializedGraphHash: materialized.document.hashes.graph_hash,
    materializedNodeCount: materialized.document.node_count,
  };
}

function parseSegmentLedger(domain, preflight, segmentIndex, content) {
  const lines = content.split(/\r?\n/u).filter((line) => line.length > 0);
  const plan = preflight.segments[segmentIndex];
  if (lines.length !== plan.expected_event_count) {
    throw coordinatorError("physical_campaign_segment_incomplete", "persisted ledger count is not exact");
  }
  const events = lines.map((line, index) => {
    let raw;
    try {
      raw = JSON.parse(line);
    } catch {
      throw coordinatorError("physical_campaign_segment_tamper", `segment ledger line ${index + 1} is invalid`);
    }
    const safe = copyPlainJsonData(raw, `segment ledger line ${index + 1}`);
    const normalized = normalizeFrontierEvent(safe, { targetDomain: domain, now: null });
    if (safe.event_hash !== normalized.event_hash
        || canonicalJson(safe) !== canonicalJson(normalized)) {
      throw coordinatorError("physical_campaign_segment_tamper", "persisted Frontier event hash/content drifted");
    }
    return normalized;
  });
  const folded = foldPersistedSegment(domain, preflight, segmentIndex, events);
  return {
    events,
    ...folded,
    ledgerDigest: hashCanonicalJson({
      domain: "hacker-bob/physical-campaign-frontier-ledger/v1",
      target_domain: domain,
      segment_index: segmentIndex,
      events,
    }),
  };
}

function verifyPersistedSegment(domain, campaignPaths, preflight, receipt, signedSegment) {
  const content = readVerifiedText(
    path.join(campaignPaths.root, receipt.relative_path),
    `physical campaign segment ${receipt.segment_index}`,
    CAMPAIGN_LEDGER_MAX_BYTES,
  );
  const parsed = parseSegmentLedger(domain, preflight, receipt.segment_index, content);
  if (parsed.ledgerDigest !== receipt.ledger_digest
      || parsed.events.length !== receipt.event_count
      || parsed.materializedGraphHash !== receipt.materialized_graph_hash
      || parsed.materializedGraphHash !== signedSegment.materialized_graph_hash) {
    throw coordinatorError("physical_campaign_segment_tamper", "segment ledger receipt drifted");
  }
  const persistedDigests = parsed.events.map((event) => event.event_hash).sort();
  if (canonicalJson(persistedDigests) !== canonicalJson(signedSegment.source_event_digests)) {
    throw coordinatorError("physical_campaign_segment_tamper", "signed source-event set differs from ledger");
  }
  return parsed;
}

function loadCoordinatorState(domain, { recoverAnchor = false, anchorPort = null } = {}) {
  const campaignPaths = pathsFor(domain);
  ensureLayout(campaignPaths);
  const nucleus = readVerifiedSessionNucleus(domain);
  const resolvedAnchorPort = anchorPort
    || resolvePhysicalCampaignAnchorPort(domain, nucleus.nucleus_hash);
  const anchorSlotAssurance = physicalCampaignAnchorPortAssurance(resolvedAnchorPort);
  const preflightState = normalizePreflightEnvelope(
    domain,
    readVerifiedJson(campaignPaths.preflight, "physical campaign preflight"),
    anchorSlotAssurance.anchor_slot_digest,
  );
  const { preflight, verifier } = preflightState;
  const anchorAssurance = physicalCampaignAnchorPortAssurance(resolvedAnchorPort, {
    target_domain: domain,
    session_nucleus_hash: nucleus.nucleus_hash,
    preflight,
  });
  const checkpoint = normalizeCheckpointEnvelope(
    domain,
    preflight,
    readVerifiedJson(campaignPaths.checkpoint, "physical campaign checkpoint"),
  );
  let anchor = readExternalAnchor(resolvedAnchorPort, domain, preflight);
  if (anchor == null) {
    throw coordinatorError(
      "physical_campaign_external_anchor_missing",
      "active campaign has no externally retained monotonic anchor",
    );
  }
  const committed = checkpoint.generation === anchor.generation
    && checkpoint.checkpoint_envelope_digest === anchor.checkpoint_envelope_digest
    && checkpoint.previous_anchor_digest === anchor.previous_anchor_digest;
  const pendingAnchor = checkpoint.generation === anchor.generation + 1
    && checkpoint.previous_anchor_digest === anchor.anchor_digest;
  if (!committed && !pendingAnchor) {
    const code = checkpoint.generation < anchor.generation
      ? "physical_campaign_checkpoint_rollback"
      : "physical_campaign_checkpoint_fork";
    throw coordinatorError(code, "checkpoint and monotonic anchor do not form one recoverable head");
  }
  const accumulator = createPhysicalCampaignClosureAccumulator(preflight, {
    verifier,
    checkpoint: checkpoint.accumulator_checkpoint,
    expected_checkpoint_digest: checkpoint.accumulator_checkpoint.checkpoint_digest,
  });
  if (checkpoint.generation !== checkpoint.accumulator_checkpoint.next_segment_index
      || checkpoint.generation !== checkpoint.segment_ledgers.length) {
    throw coordinatorError("physical_campaign_checkpoint_tamper", "coordinator generation projection drifted");
  }
  for (let index = 0; index < checkpoint.segment_ledgers.length; index += 1) {
    verifyPersistedSegment(
      domain,
      campaignPaths,
      preflight,
      checkpoint.segment_ledgers[index],
      checkpoint.accumulator_checkpoint.accepted_segments[index],
    );
  }
  if (pendingAnchor) {
    if (!recoverAnchor) {
      throw coordinatorError(
        "physical_campaign_anchor_recovery_required",
        "checkpoint is durable but its monotonic anchor promotion is incomplete",
      );
    }
    const expectedAnchor = anchor;
    const nextAnchor = anchorDocument(
      domain,
      preflight,
      anchorAssurance.anchor_slot_digest,
      checkpoint.generation,
      checkpoint.checkpoint_envelope_digest,
      checkpoint.previous_anchor_digest,
    );
    anchor = commitExternalAnchor(
      resolvedAnchorPort,
      domain,
      preflight,
      expectedAnchor,
      nextAnchor,
    );
  }
  // This co-located file is only a crash/recovery journal. It never authorizes
  // a checkpoint and may be stale after an external CAS won before local fsync.
  let localAnchorJournalSynced = null;
  if (recoverAnchor) {
    try {
      writeDurableJson(campaignPaths.anchor, anchor);
      localAnchorJournalSynced = true;
    } catch {
      localAnchorJournalSynced = false;
    }
  }
  return {
    campaignPaths,
    preflightEnvelope: preflightState.envelope,
    preflight,
    verifier,
    checkpoint,
    anchor,
    anchorPort: resolvedAnchorPort,
    anchorAssurance,
    localAnchorJournalSynced,
    accumulator,
  };
}

function initializePhysicalCampaignCoordinator(input) {
  assertExactFields(
    input,
    ["target_domain", "preflight_input", "signer", "verifier"],
    "physical campaign coordinator initialization",
  );
  const domain = assertSafeDomain(input.target_domain);
  const preflight = buildPhysicalCampaignClosurePreflight(input.preflight_input);
  const signerDescriptor = exportPhysicalCampaignEd25519VerifierDescriptor(input.signer);
  const verifierDescriptor = exportPhysicalCampaignEd25519VerifierDescriptor(input.verifier);
  if (canonicalJson(signerDescriptor) !== canonicalJson(verifierDescriptor)
      || verifierDescriptor.signer_key_ref !== preflight.closure_signer_key_ref
      || verifierDescriptor.signer_public_key_digest !== preflight.closure_signer_public_key_digest) {
    throw coordinatorError("physical_campaign_authority_drift", "signer/verifier pair differs from preflight");
  }
  const nucleus = readVerifiedSessionNucleus(domain);
  if (nucleus.nucleus_hash !== preflight.session_nucleus_hash) {
    throw coordinatorError("physical_campaign_authority_drift", "preflight does not bind the live session nucleus");
  }
  // Resolve the process-local capability before creating any campaign files.
  // An unconfigured runtime must not leave a preflight that can be mistaken
  // for externally anchored state.
  const anchorPort = resolvePhysicalCampaignAnchorPort(domain, nucleus.nucleus_hash);
  const anchorAssurance = physicalCampaignAnchorPortAssurance(anchorPort, {
    target_domain: domain,
    session_nucleus_hash: nucleus.nucleus_hash,
    preflight,
  });
  return withSessionLock(domain, () => {
    const campaignPaths = pathsFor(domain);
    let externalAnchor = readExternalAnchor(anchorPort, domain, preflight);
    if (externalAnchor != null
        && (!fs.existsSync(campaignPaths.preflight)
          || !fs.existsSync(campaignPaths.checkpoint))) {
      throw coordinatorError(
        "physical_campaign_checkpoint_rollback",
        "externally anchored campaign state is missing from the local campaign root",
      );
    }
    ensureLayout(campaignPaths);
    const proposedEnvelope = preflightEnvelope(
      domain,
      preflight,
      verifierDescriptor,
      anchorAssurance.anchor_slot_digest,
    );
    if (fs.existsSync(campaignPaths.preflight)) {
      const persisted = normalizePreflightEnvelope(
        domain,
        readVerifiedJson(campaignPaths.preflight, "physical campaign preflight"),
        anchorAssurance.anchor_slot_digest,
      );
      if (canonicalJson(persisted.envelope) !== canonicalJson(proposedEnvelope)) {
        throw coordinatorError("physical_campaign_preflight_fork", "session already has another campaign preflight");
      }
    } else {
      writeDurableJson(campaignPaths.preflight, proposedEnvelope);
    }
    if (!fs.existsSync(campaignPaths.checkpoint)) {
      if (externalAnchor != null) {
        throw coordinatorError(
          "physical_campaign_checkpoint_rollback",
          "external campaign head exists but its local checkpoint is missing",
        );
      }
      const accumulator = createPhysicalCampaignClosureAccumulator(preflight, {
        verifier: input.verifier,
      });
      const checkpoint = checkpointEnvelope(
        domain,
        preflight,
        0,
        null,
        accumulator.snapshot(),
        [],
      );
      writeDurableJson(campaignPaths.checkpoint, checkpoint);
    }
    if (externalAnchor == null) {
      const checkpoint = normalizeCheckpointEnvelope(
        domain,
        preflight,
        readVerifiedJson(campaignPaths.checkpoint, "physical campaign checkpoint"),
      );
      if (checkpoint.generation !== 0 || checkpoint.previous_anchor_digest !== null) {
        throw coordinatorError(
          "physical_campaign_external_anchor_missing",
          "non-genesis local checkpoint has no external anchor",
        );
      }
      if (fs.existsSync(campaignPaths.anchor)) {
        const localJournal = normalizeAnchor(
          domain,
          preflight,
          readVerifiedJson(campaignPaths.anchor, "physical campaign anchor crash journal"),
          anchorAssurance.anchor_slot_digest,
        );
        if (localJournal.generation !== 0
            || localJournal.checkpoint_envelope_digest
              !== checkpoint.checkpoint_envelope_digest) {
          throw coordinatorError(
            "physical_campaign_external_anchor_missing",
            "local crash journal witnesses a campaign head missing from the external anchor",
          );
        }
      }
      const genesisAnchor = anchorDocument(
        domain,
        preflight,
        anchorAssurance.anchor_slot_digest,
        0,
        checkpoint.checkpoint_envelope_digest,
        null,
      );
      externalAnchor = commitExternalAnchor(
        anchorPort,
        domain,
        preflight,
        null,
        genesisAnchor,
      );
      try { writeDurableJson(campaignPaths.anchor, externalAnchor); } catch {}
    }
    const state = loadCoordinatorState(domain, { recoverAnchor: true, anchorPort });
    return Object.freeze({
      active: true,
      campaign_id: state.preflight.campaign_id,
      preflight_digest: state.preflight.preflight_digest,
      declared_cell_count: state.preflight.declared_cell_count,
      declared_event_count: state.preflight.declared_event_count,
      segment_count: state.preflight.segment_count,
      accepted_segment_count: state.checkpoint.generation,
      anchor_digest: state.anchor.anchor_digest,
      ...state.anchorAssurance,
      local_anchor_journal_synced: state.localAnchorJournalSynced,
    });
  });
}

function normalizeRoutedSegment(domain, preflight, segmentIndex, routedEvents) {
  assertDataArray(routedEvents, "routed_events");
  const plan = preflight.segments[segmentIndex];
  if (routedEvents.length !== plan.expected_event_count) {
    throw coordinatorError("physical_campaign_segment_incomplete", "routed event count differs from preflight");
  }
  const events = routedEvents.map((rawEntry, index) => {
    const entry = copyPlainJsonData(rawEntry, `routed_events[${index}]`);
    const terminal = entry.event_ordinal === preflight.events_per_cell;
    assertExactFields(
      entry,
      terminal
        ? [
          "cell_id",
          "event_ordinal",
          "frontier_event",
          "terminal_state",
          "terminal_witness_digest",
        ]
        : ["cell_id", "event_ordinal", "frontier_event"],
      `routed_events[${index}]`,
    );
    if (!plan.cell_ids.includes(entry.cell_id)) {
      throw coordinatorError("physical_campaign_segment_cell_drift", "routed event cell is outside segment");
    }
    assertInteger(
      entry.event_ordinal,
      `routed_events[${index}].event_ordinal`,
      1,
      preflight.events_per_cell,
    );
    const frontierInput = entry.frontier_event;
    assertPlainRecord(frontierInput, `routed_events[${index}].frontier_event`);
    if (frontierInput.target_domain != null && frontierInput.target_domain !== domain) {
      throw coordinatorError("physical_campaign_authority_drift", "routed Frontier event target drifted");
    }
    const payload = frontierInput.payload == null
      ? {}
      : copyPlainJsonData(frontierInput.payload, `routed_events[${index}].frontier_event.payload`);
    if (Object.prototype.hasOwnProperty.call(payload, "physical_campaign")) {
      throw coordinatorError("physical_campaign_contract_invalid", "caller cannot supply campaign metadata");
    }
    const metadata = {
      version: PHYSICAL_CAMPAIGN_COORDINATOR_VERSION,
      campaign_id: preflight.campaign_id,
      preflight_digest: preflight.preflight_digest,
      segment_index: segmentIndex,
      segment_key: plan.segment_key,
      cell_id: entry.cell_id,
      event_ordinal: entry.event_ordinal,
      terminal_state: terminal ? entry.terminal_state : null,
      terminal_witness_digest: terminal ? entry.terminal_witness_digest : null,
    };
    const event = normalizeFrontierEvent({
      ...frontierInput,
      target_domain: domain,
      payload: { ...payload, physical_campaign: metadata },
    }, { targetDomain: domain, now: null });
    return { event, metadata };
  });
  events.sort((left, right) => (
    left.metadata.cell_id.localeCompare(right.metadata.cell_id)
      || left.metadata.event_ordinal - right.metadata.event_ordinal
  ));
  const eventIds = new Set();
  const eventHashes = new Set();
  for (const { event } of events) {
    if (eventIds.has(event.event_id) || eventHashes.has(event.event_hash)) {
      throw coordinatorError("physical_campaign_duplicate", "routed segment contains a duplicate Frontier event");
    }
    eventIds.add(event.event_id);
    eventHashes.add(event.event_hash);
  }
  const normalizedEvents = events.map((entry) => entry.event);
  const folded = foldPersistedSegment(domain, preflight, segmentIndex, normalizedEvents);
  const ledgerDigest = hashCanonicalJson({
    domain: "hacker-bob/physical-campaign-frontier-ledger/v1",
    target_domain: domain,
    segment_index: segmentIndex,
    events: normalizedEvents,
  });
  return {
    events: normalizedEvents,
    content: `${normalizedEvents.map((event) => JSON.stringify(event)).join("\n")}\n`,
    ledgerDigest,
    ...folded,
  };
}

function routePhysicalCampaignSegment(input) {
  assertExactFields(
    input,
    ["target_domain", "segment_index", "routed_events", "signer"],
    "physical campaign segment route",
  );
  const domain = assertSafeDomain(input.target_domain);
  return withSessionLock(domain, () => {
    const state = loadCoordinatorState(domain, { recoverAnchor: true });
    const index = assertInteger(
      input.segment_index,
      "segment_index",
      0,
      state.preflight.segment_count - 1,
    );
    const signerDescriptor = exportPhysicalCampaignEd25519VerifierDescriptor(input.signer);
    if (signerDescriptor.signer_key_ref !== state.preflight.closure_signer_key_ref
        || signerDescriptor.signer_public_key_digest
          !== state.preflight.closure_signer_public_key_digest) {
      throw coordinatorError("physical_campaign_authority_drift", "route signer differs from campaign");
    }
    if (index > state.checkpoint.generation) {
      throw coordinatorError("physical_campaign_segment_gap", "segment route skipped the checkpoint head");
    }
    const routed = normalizeRoutedSegment(domain, state.preflight, index, input.routed_events);
    const ledgerPath = segmentLedgerPath(state.campaignPaths, index);
    writeImmutableText(ledgerPath, routed.content, `physical campaign segment ${index}`);
    if (index < state.checkpoint.generation) {
      const receipt = state.checkpoint.segment_ledgers[index];
      if (receipt.ledger_digest !== routed.ledgerDigest
          || receipt.materialized_graph_hash !== routed.materializedGraphHash) {
        throw coordinatorError("physical_campaign_segment_fork", "replayed segment differs from checkpoint");
      }
      return Object.freeze({
        accepted: false,
        replayed: true,
        campaign_id: state.preflight.campaign_id,
        segment_index: index,
        accepted_segment_count: state.checkpoint.generation,
        checkpoint_envelope_digest: state.checkpoint.checkpoint_envelope_digest,
        anchor_digest: state.anchor.anchor_digest,
        ...state.anchorAssurance,
        local_anchor_journal_synced: state.localAnchorJournalSynced,
        manifest_synced: null,
      });
    }
    const previousSegmentDigest = index === 0
      ? campaignGenesisDigest(state.preflight)
      : state.checkpoint.accumulator_checkpoint.accepted_segments[index - 1].sealed_segment_digest;
    const signedSegment = sealPhysicalCampaignClosureSegment(
      state.preflight,
      index,
      routed.closureEvents,
      {
        previous_segment_digest: previousSegmentDigest,
        materialized_graph_hash: routed.materializedGraphHash,
        signer: input.signer,
      },
    );
    state.accumulator.appendSegment(signedSegment);
    const accumulatorCheckpoint = state.accumulator.snapshot();
    const receipt = Object.freeze({
      segment_index: index,
      relative_path: segmentRelativePath(index),
      event_count: routed.events.length,
      ledger_digest: routed.ledgerDigest,
      materialized_graph_hash: routed.materializedGraphHash,
    });
    const nextCheckpoint = checkpointEnvelope(
      domain,
      state.preflight,
      index + 1,
      state.anchor.anchor_digest,
      accumulatorCheckpoint,
      [...state.checkpoint.segment_ledgers, receipt],
    );
    // Crash ordering is intentional: a durable checkpoint one generation ahead
    // of the anchor is recoverable after re-verifying every signed ledger.  The
    // inverse (anchor ahead of checkpoint) is never written and is rollback.
    writeDurableJson(state.campaignPaths.checkpoint, nextCheckpoint);
    const proposedAnchor = anchorDocument(
      domain,
      state.preflight,
      state.anchorAssurance.anchor_slot_digest,
      index + 1,
      nextCheckpoint.checkpoint_envelope_digest,
      state.anchor.anchor_digest,
    );
    const nextAnchor = commitExternalAnchor(
      state.anchorPort,
      domain,
      state.preflight,
      state.anchor,
      proposedAnchor,
    );
    // Non-authoritative local crash journal, written only after external CAS
    // was read back as the exact proposed head.
    let localAnchorJournalSynced = true;
    try { writeDurableJson(state.campaignPaths.anchor, nextAnchor); } catch {
      localAnchorJournalSynced = false;
    }
    let manifest = null;
    let manifestSynced = null;
    if (index + 1 === state.preflight.segment_count) {
      manifest = state.accumulator.finalize();
      try {
        writeDurableJson(state.campaignPaths.manifest, manifest);
        manifestSynced = true;
      } catch {
        manifestSynced = false;
      }
    }
    return Object.freeze({
      accepted: true,
      replayed: false,
      campaign_id: state.preflight.campaign_id,
      segment_index: index,
      segment_event_count: routed.events.length,
      materialized_graph_hash: routed.materializedGraphHash,
      materialized_node_count: routed.materializedNodeCount,
      sealed_segment_digest: signedSegment.sealed_segment_digest,
      accepted_segment_count: index + 1,
      checkpoint_envelope_digest: nextCheckpoint.checkpoint_envelope_digest,
      anchor_digest: nextAnchor.anchor_digest,
      ...state.anchorAssurance,
      local_anchor_journal_synced: localAnchorJournalSynced,
      manifest_synced: manifestSynced,
      closure_satisfied: manifest == null ? false : manifest.closure_satisfied,
      aggregate_closure_root: manifest == null ? null : manifest.aggregate_closure_root,
    });
  });
}

function readVerifiedPhysicalCampaignClosureManifest(targetDomain) {
  const domain = assertSafeDomain(targetDomain);
  return withSessionLock(domain, () => {
    const state = loadCoordinatorState(domain, { recoverAnchor: false });
    if (state.checkpoint.generation !== state.preflight.segment_count) {
      throw coordinatorError("physical_campaign_incomplete", "campaign has not accepted every segment");
    }
    const manifest = state.accumulator.finalize();
    if (fs.existsSync(state.campaignPaths.manifest)) {
      const persisted = readVerifiedJson(state.campaignPaths.manifest, "physical campaign manifest");
      if (canonicalJson(persisted) !== canonicalJson(manifest)) {
        throw coordinatorError("physical_campaign_manifest_tamper", "persisted manifest differs from reconstruction");
      }
    }
    return manifest;
  });
}

function campaignAnchorProductionReady(anchorAssurance) {
  return anchorAssurance.production_ready === true
    && anchorAssurance.anchor_externality_attested === true
    && HASH_PATTERN.test(anchorAssurance.anchor_attestation_digest || "")
    && anchorAssurance.campaign_obligation_server_issued === true
    && HASH_PATTERN.test(anchorAssurance.campaign_obligation_digest || "")
    && anchorAssurance.physical_nucleus_authority_attested === true
    && HASH_PATTERN.test(anchorAssurance.physical_nucleus_authority_digest || "")
    && anchorAssurance.closure_signer_production_enrolled === true
    && HASH_PATTERN.test(anchorAssurance.closure_signer_enrollment_digest || "")
    && anchorAssurance.terminal_witnesses_production_attested === true
    && HASH_PATTERN.test(anchorAssurance.terminal_witness_attestation_digest || "")
    && anchorAssurance.no_active_effects_durably_attested === true
    && HASH_PATTERN.test(anchorAssurance.no_active_effects_attestation_digest || "");
}

// Server-owned PH-S12 -> PH-C10 projection.  It is rebuilt from the exact
// externally anchored checkpoint and signed segment chain under the session
// lock; callers cannot provide terminal cells, active-effect counts, or
// assurance booleans.  A non-production anchor remains useful for recovery
// diagnostics but can never become a grading completion projection.
function readVerifiedPhysicalCampaignCompletionState(targetDomain) {
  const domain = assertSafeDomain(targetDomain);
  return withSessionLock(domain, () => {
    const state = loadCoordinatorState(domain, { recoverAnchor: false });
    if (state.checkpoint.generation !== state.preflight.segment_count) {
      throw coordinatorError(
        "physical_campaign_incomplete",
        "campaign has not accepted every segment",
      );
    }
    const manifest = state.accumulator.finalize();
    assertPhysicalCampaignClosureSatisfied(manifest);
    if (fs.existsSync(state.campaignPaths.manifest)) {
      const persisted = readVerifiedJson(
        state.campaignPaths.manifest,
        "physical campaign manifest",
      );
      if (canonicalJson(persisted) !== canonicalJson(manifest)) {
        throw coordinatorError(
          "physical_campaign_manifest_tamper",
          "persisted manifest differs from reconstruction",
        );
      }
    }
    const checkpoint = state.accumulator.snapshot();
    const terminalCells = checkpoint.accepted_segments
      .flatMap((segment) => segment.terminal_cells)
      .map((terminal) => Object.freeze({
        cell_id: terminal.cell_id,
        terminal_state: terminal.terminal_state,
        terminal_witness_digest: terminal.terminal_witness_digest,
      }))
      .sort((left, right) => left.cell_id.localeCompare(right.cell_id));
    if (terminalCells.length !== manifest.terminal_cell_count
        || new Set(terminalCells.map((terminal) => terminal.cell_id)).size
          !== terminalCells.length) {
      throw coordinatorError(
        "physical_campaign_manifest_tamper",
        "terminal cell projection differs from the verified aggregate",
      );
    }
    const liveAnchorAssurance = physicalCampaignAnchorPortAssurance(state.anchorPort, {
      target_domain: domain,
      session_nucleus_hash: state.preflight.session_nucleus_hash,
      preflight: state.preflight,
      manifest,
    });
    const productionReady = state.preflight.campaign_identity_version === 2
      && campaignAnchorProductionReady(liveAnchorAssurance);
    const basis = {
      version: PHYSICAL_CAMPAIGN_COORDINATOR_VERSION,
      ...(state.preflight.campaign_identity_version === 2 ? {
        campaign_identity_version: 2,
      } : {}),
      target_domain: domain,
      session_nucleus_hash: state.preflight.session_nucleus_hash,
      campaign_id: state.preflight.campaign_id,
      authority_binding_digest: state.preflight.authority_binding_digest,
      capability_pack_digest: state.preflight.capability_pack_digest,
      preflight_digest: state.preflight.preflight_digest,
      checkpoint_digest: manifest.checkpoint_digest,
      manifest_digest: manifest.manifest_digest,
      aggregate_closure_root: manifest.aggregate_closure_root,
      terminal_cells_merkle_root: manifest.terminal_cells_merkle_root,
      terminal_cells: Object.freeze(terminalCells),
      terminal_cell_count: manifest.terminal_cell_count,
      coverage_credited_cell_count: manifest.coverage_credited_cell_count,
      residue_cell_count: manifest.residue_cell_count,
      terminal_complete: manifest.terminal_complete,
      active_effect_count: 0,
      production_ready: productionReady,
      ...liveAnchorAssurance,
    };
    return Object.freeze({
      ...basis,
      completion_state_digest: hashCanonicalJson({
        domain: state.preflight.campaign_identity_version === 2
          ? "hacker-bob/verified-physical-campaign-completion-state/v2"
          : "hacker-bob/verified-physical-campaign-completion-state/v1",
        ...basis,
      }),
    });
  });
}

function physicalCampaignClosureReadiness(targetDomain) {
  const domain = assertSafeDomain(targetDomain);
  const campaignPaths = pathsFor(domain);
  if (!pathEntryPresent(campaignPaths.root, "physical campaign root")) {
    const nucleus = campaignProbeNucleusForAbsentRoot(domain);
    if (nucleus == null) {
      return Object.freeze({ active: false, satisfied: true });
    }
    if (!isPhysicalCampaignAnchorResolverInstalled()) {
      // Physical-session authority means an absent local campaign root cannot
      // be declared inactive without checking the externally enrolled slot.
      if (nucleus.physical_scope != null) {
        resolvePhysicalCampaignAnchorPort(domain, nucleus.nucleus_hash);
      }
      return Object.freeze({ active: false, satisfied: true });
    }
    const anchorPort = probePhysicalCampaignAnchorPort(domain, nucleus.nucleus_hash);
    if (anchorPort == null) {
      return Object.freeze({ active: false, satisfied: true });
    }
    const retained = readPhysicalCampaignAnchor(anchorPort, externalAnchorContext(domain));
    if (retained != null) {
      throw coordinatorError(
        "physical_campaign_checkpoint_rollback",
        "external campaign anchor exists but the entire local campaign root is missing",
      );
    }
    return Object.freeze({ active: false, satisfied: true });
  }
  return withSessionLock(domain, () => {
    const state = loadCoordinatorState(domain, { recoverAnchor: false });
    if (state.checkpoint.generation !== state.preflight.segment_count) {
      return Object.freeze({
        active: true,
        satisfied: false,
        integrity_satisfied: false,
        production_ready: false,
        reason: "campaign_incomplete",
        campaign_id: state.preflight.campaign_id,
        accepted_segment_count: state.checkpoint.generation,
        segment_count: state.preflight.segment_count,
        accepted_event_count: state.checkpoint.accumulator_checkpoint.accepted_event_count,
        declared_event_count: state.preflight.declared_event_count,
        ...state.anchorAssurance,
      });
    }
    const manifest = state.accumulator.finalize();
    try {
      assertPhysicalCampaignClosureSatisfied(manifest);
    } catch (error) {
      return Object.freeze({
        active: true,
        satisfied: false,
        integrity_satisfied: false,
        production_ready: false,
        reason: "terminal_residue",
        campaign_id: state.preflight.campaign_id,
        accepted_segment_count: state.checkpoint.generation,
        segment_count: state.preflight.segment_count,
        accepted_event_count: manifest.event_count,
        declared_event_count: manifest.declared_event_count,
        terminal_complete: manifest.terminal_complete,
        coverage_credited_cell_count: manifest.coverage_credited_cell_count,
        residue_cell_count: manifest.residue_cell_count,
        aggregate_closure_root: manifest.aggregate_closure_root,
        ...state.anchorAssurance,
      });
    }
    // The current anchor port deliberately proves only callback-level CAS
    // integrity. It is not independently attested external durability and
    // therefore cannot clear lifecycle authority even when the aggregate is
    // internally complete. Keep the integrity result visible for test and
    // recovery diagnostics while failing the production readiness predicate.
    const liveAnchorAssurance = physicalCampaignAnchorPortAssurance(state.anchorPort, {
      target_domain: domain,
      session_nucleus_hash: state.preflight.session_nucleus_hash,
      preflight: state.preflight,
      manifest,
    });
    const productionReady = state.preflight.campaign_identity_version === 2
      && campaignAnchorProductionReady(liveAnchorAssurance);
    return Object.freeze({
      active: true,
      satisfied: productionReady,
      integrity_satisfied: true,
      production_ready: productionReady,
      reason: productionReady ? "closed" : "campaign_anchor_not_production_attested",
      campaign_id: state.preflight.campaign_id,
      accepted_segment_count: state.checkpoint.generation,
      segment_count: state.preflight.segment_count,
      accepted_event_count: manifest.event_count,
      declared_event_count: manifest.declared_event_count,
      terminal_complete: true,
      coverage_credited_cell_count: manifest.coverage_credited_cell_count,
      residue_cell_count: 0,
      aggregate_closure_root: manifest.aggregate_closure_root,
      ...(state.preflight.campaign_identity_version === 2 ? {
        campaign_identity_version: 2,
      } : {}),
      ...liveAnchorAssurance,
    });
  });
}

module.exports = {
  PHYSICAL_CAMPAIGN_COORDINATOR_VERSION,
  initializePhysicalCampaignCoordinator,
  physicalCampaignClosureReadiness,
  readVerifiedPhysicalCampaignCompletionState,
  readVerifiedPhysicalCampaignClosureManifest,
  routePhysicalCampaignSegment,
};
