"use strict";

// PH-S12 — proof-preserving physical campaign partitioning.
//
// A physical campaign can legitimately produce more events than one TaskGraph
// ledger may fold.  This module does not widen that ledger ceiling.  Instead it
// derives a bounded, deterministic cell plan, packs whole cells into bounded
// segments, and turns each completed segment into a signed checkpoint.  Raw
// event bodies may then be retained elsewhere or trimmed; the signed checkpoint
// (including exact source-event digests and terminal witnesses) is the authority
// consumed by the aggregate closure accumulator.
//
// The implementation is deliberately provider-neutral.  Private signing keys
// are retained only inside branded Ed25519 signer-port closures; accumulator
// code receives a separately branded public-key verifier port.

const crypto = require("node:crypto");
const { types: utilTypes } = require("node:util");

const {
  canonicalJson,
  hashCanonicalJson,
} = require("./verification-contracts.js");
const {
  LEDGER_PRESSURE_REFUSE_THRESHOLD,
} = require("./task-graph-materializer.js");

const PHYSICAL_CAMPAIGN_CLOSURE_VERSION = 1;
const PHYSICAL_CAMPAIGN_IDENTITY_VERSION = 2;
const DEFAULT_SEGMENT_EVENT_LIMIT = 4_096;
const MAX_CAMPAIGN_DIMENSIONS = 16;
const MAX_CAMPAIGN_CELLS = 65_536;
const MAX_CAMPAIGN_EVENTS = 262_144;
const MAX_EVENTS_PER_CELL = 256;
// `events_per_cell` includes every TaskGraph/frontier event a cell can emit,
// not merely provider attempts.  Keep explicit headroom for campaign/session
// bookkeeping that may share a bounded ledger with the cell events.
const SEGMENT_LEDGER_HEADROOM = 256;
const MAX_SEGMENT_EVENT_LIMIT = LEDGER_PRESSURE_REFUSE_THRESHOLD - SEGMENT_LEDGER_HEADROOM;
const HASH_PATTERN = /^[a-f0-9]{64}$/u;
const SIGNATURE_PATTERN = /^[A-Za-z0-9_-]{86}$/u;
const OPAQUE_TOKEN_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,189}$/u;
const TERMINAL_STATE_VALUES = Object.freeze([
  "verified",
  "denied",
  "inconclusive",
  "blocked",
  "not_applicable",
]);
const COVERAGE_CREDIT_STATE_VALUES = Object.freeze(["verified", "denied", "not_applicable"]);
const RESIDUE_STATE_VALUES = Object.freeze(
  TERMINAL_STATE_VALUES.filter((state) => !COVERAGE_CREDIT_STATE_VALUES.includes(state)),
);
const SIGNER_PORT_STATE = new WeakMap();
const VERIFIER_PORT_STATE = new WeakMap();
const FINALIZED_CAMPAIGN_MANIFESTS = new WeakSet();

function campaignError(code, message, details = null) {
  const error = new Error(`${code}: ${message}`);
  error.code = code;
  if (details != null) error.details = deepFreeze(cloneJson(details));
  return error;
}

function cloneJson(value) {
  return JSON.parse(JSON.stringify(value));
}

function deepFreeze(value) {
  if (value == null || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function assertPlainDataObject(value, label) {
  if (value != null && typeof value === "object" && utilTypes.isProxy(value)) {
    throw campaignError("campaign_contract_invalid", `${label} cannot be a Proxy`);
  }
  if (value == null || typeof value !== "object" || Array.isArray(value)) {
    throw campaignError("campaign_contract_invalid", `${label} must be a plain object`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw campaignError("campaign_contract_invalid", `${label} must be a plain object`);
  }
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== "string")) {
    throw campaignError("campaign_contract_invalid", `${label} cannot contain symbol fields`);
  }
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, "value")
        || descriptor.enumerable !== true) {
      throw campaignError(
        "campaign_contract_invalid",
        `${label}.${key} must be an enumerable data property`,
      );
    }
  }
  return value;
}

function assertDataArray(value, label) {
  if (value != null && typeof value === "object" && utilTypes.isProxy(value)) {
    throw campaignError("campaign_contract_invalid", `${label} cannot be a Proxy`);
  }
  if (!Array.isArray(value)) {
    throw campaignError("campaign_contract_invalid", `${label} must be an array`);
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const expectedIndexes = new Set(Array.from({ length: value.length }, (_, index) => String(index)));
  for (const key of Reflect.ownKeys(descriptors)) {
    if (typeof key !== "string") {
      throw campaignError("campaign_contract_invalid", `${label} cannot contain symbol fields`);
    }
    if (key === "length") continue;
    if (!expectedIndexes.has(key)) {
      throw campaignError("campaign_contract_invalid", `${label} cannot contain extra properties`);
    }
    const descriptor = descriptors[key];
    if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, "value")
        || descriptor.enumerable !== true) {
      throw campaignError(
        "campaign_contract_invalid",
        `${label}[${key}] must be an enumerable data property`,
      );
    }
  }
  if (Object.keys(descriptors).filter((key) => key !== "length").length !== value.length) {
    throw campaignError("campaign_contract_invalid", `${label} must be dense`);
  }
  return value;
}

function assertExactFields(value, required, label) {
  assertPlainDataObject(value, label);
  const actual = Object.keys(value).sort();
  const expected = required.slice().sort();
  const missing = expected.filter((field) => !actual.includes(field));
  const unknown = actual.filter((field) => !expected.includes(field));
  if (missing.length > 0 || unknown.length > 0) {
    throw campaignError(
      "campaign_contract_invalid",
      `${label} fields are not exact`,
      { missing, unknown },
    );
  }
  return value;
}

function assertDigest(value, label) {
  if (typeof value !== "string" || !HASH_PATTERN.test(value)) {
    throw campaignError(
      "campaign_contract_invalid",
      `${label} must be a lowercase SHA-256 digest`,
    );
  }
  return value;
}

function assertText(value, label, { maximum = 190 } = {}) {
  if (typeof value !== "string" || value.length < 1 || value.length > maximum
      || value !== value.trim() || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw campaignError(
      "campaign_contract_invalid",
      `${label} must be trimmed control-free text of 1..${maximum} characters`,
    );
  }
  return value;
}

function assertOpaqueToken(value, label) {
  const token = assertText(value, label);
  if (!OPAQUE_TOKEN_PATTERN.test(token) || token.includes("..")) {
    throw campaignError(
      "campaign_contract_invalid",
      `${label} must be an opaque token, not a path or free-form value`,
    );
  }
  return token;
}

function assertInteger(value, label, { minimum = 0, maximum = Number.MAX_SAFE_INTEGER } = {}) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw campaignError(
      "campaign_contract_invalid",
      `${label} must be an integer in ${minimum}..${maximum}`,
    );
  }
  return value;
}

function assertCanonicalSignature(value, label = "signature") {
  if (typeof value !== "string" || !SIGNATURE_PATTERN.test(value)) {
    throw campaignError(
      "campaign_signature_invalid",
      `${label} must be a canonical 64-byte Ed25519 base64url signature`,
    );
  }
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length !== 64 || bytes.toString("base64url") !== value) {
    throw campaignError(
      "campaign_signature_invalid",
      `${label} must use canonical Ed25519 base64url encoding`,
    );
  }
  return value;
}

function compareText(a, b) {
  return a < b ? -1 : a > b ? 1 : 0;
}

function assertSortedUnique(values, label) {
  for (let index = 1; index < values.length; index += 1) {
    const comparison = compareText(values[index - 1], values[index]);
    if (comparison === 0) {
      throw campaignError("campaign_duplicate", `${label} contains a duplicate`);
    }
    if (comparison > 0) {
      throw campaignError("campaign_contract_invalid", `${label} must be canonically sorted`);
    }
  }
}

function assertEd25519Key(key, kind, label) {
  if (!(key instanceof crypto.KeyObject) || key.type !== kind || key.asymmetricKeyType !== "ed25519") {
    throw campaignError(
      "campaign_contract_invalid",
      `${label} must be an Ed25519 ${kind} KeyObject`,
    );
  }
  return key;
}

function publicKeyDigest(publicKey) {
  return crypto.createHash("sha256")
    .update(publicKey.export({ type: "spki", format: "der" }))
    .digest("hex");
}

function createPhysicalCampaignEd25519SignerPort(input) {
  assertExactFields(input, ["signer_key_ref", "private_key"], "campaign signer port input");
  const keyRef = assertOpaqueToken(input.signer_key_ref, "signer_key_ref");
  const key = assertEd25519Key(input.private_key, "private", "private_key");
  const publicKey = crypto.createPublicKey(key);
  const keyDigest = publicKeyDigest(publicKey);
  const port = Object.freeze({
    signer_key_ref: keyRef,
    signer_public_key_digest: keyDigest,
  });
  SIGNER_PORT_STATE.set(port, Object.freeze({ privateKey: key }));
  return port;
}

function createPhysicalCampaignEd25519VerifierPort(input) {
  assertExactFields(input, ["signer_key_ref", "public_key"], "campaign verifier port input");
  const keyRef = assertOpaqueToken(input.signer_key_ref, "signer_key_ref");
  const key = assertEd25519Key(input.public_key, "public", "public_key");
  const keyDigest = publicKeyDigest(key);
  const port = Object.freeze({
    signer_key_ref: keyRef,
    signer_public_key_digest: keyDigest,
  });
  VERIFIER_PORT_STATE.set(port, Object.freeze({ publicKey: key }));
  return port;
}

function exportPhysicalCampaignEd25519VerifierDescriptor(port) {
  const isVerifier = port != null && typeof port === "object" && VERIFIER_PORT_STATE.has(port);
  const isSigner = port != null && typeof port === "object" && SIGNER_PORT_STATE.has(port);
  if (!isVerifier && !isSigner) {
    throw campaignError(
      "campaign_verifier_port_untrusted",
      "only a branded physical campaign verifier port can be exported",
    );
  }
  const publicKey = isVerifier
    ? VERIFIER_PORT_STATE.get(port).publicKey
    : crypto.createPublicKey(SIGNER_PORT_STATE.get(port).privateKey);
  return deepFreeze({
    version: PHYSICAL_CAMPAIGN_CLOSURE_VERSION,
    scheme: "ed25519",
    signer_key_ref: port.signer_key_ref,
    signer_public_key_digest: port.signer_public_key_digest,
    public_key_spki_base64url: publicKey
      .export({ type: "spki", format: "der" })
      .toString("base64url"),
  });
}

function importPhysicalCampaignEd25519VerifierDescriptor(input) {
  assertExactFields(
    input,
    [
      "version",
      "scheme",
      "signer_key_ref",
      "signer_public_key_digest",
      "public_key_spki_base64url",
    ],
    "campaign verifier descriptor",
  );
  if (input.version !== PHYSICAL_CAMPAIGN_CLOSURE_VERSION || input.scheme !== "ed25519") {
    throw campaignError("campaign_contract_invalid", "campaign verifier descriptor version or scheme drifted");
  }
  const keyRef = assertOpaqueToken(input.signer_key_ref, "signer_key_ref");
  const expectedDigest = assertDigest(
    input.signer_public_key_digest,
    "signer_public_key_digest",
  );
  if (typeof input.public_key_spki_base64url !== "string"
      || input.public_key_spki_base64url.length < 1
      || input.public_key_spki_base64url.length > 256) {
    throw campaignError("campaign_contract_invalid", "campaign verifier descriptor public key is invalid");
  }
  let publicKey;
  try {
    const bytes = Buffer.from(input.public_key_spki_base64url, "base64url");
    if (bytes.toString("base64url") !== input.public_key_spki_base64url) throw new Error("noncanonical");
    publicKey = crypto.createPublicKey({ key: bytes, type: "spki", format: "der" });
  } catch {
    throw campaignError("campaign_contract_invalid", "campaign verifier descriptor public key is invalid");
  }
  const port = createPhysicalCampaignEd25519VerifierPort({
    signer_key_ref: keyRef,
    public_key: publicKey,
  });
  if (port.signer_public_key_digest !== expectedDigest) {
    throw campaignError("campaign_authority_drift", "campaign verifier descriptor digest does not match key bytes");
  }
  return port;
}

function merkleRoot(digests, domain) {
  if (!Array.isArray(digests)) {
    throw campaignError("campaign_contract_invalid", "Merkle leaves must be an array");
  }
  if (digests.length === 0) {
    return hashCanonicalJson({ domain: `${domain}/empty` });
  }
  let level = digests.map((digest, index) => hashCanonicalJson({
    domain: `${domain}/leaf`,
    index,
    digest: assertDigest(digest, `Merkle leaf ${index}`),
  }));
  let depth = 0;
  while (level.length > 1) {
    const next = [];
    for (let index = 0; index < level.length; index += 2) {
      const left = level[index];
      const right = level[index + 1] || left;
      next.push(hashCanonicalJson({
        domain: `${domain}/node`,
        depth,
        left,
        right,
      }));
    }
    level = next;
    depth += 1;
  }
  return level[0];
}

function normalizeDeclaredDimensions(input) {
  assertDataArray(input, "declared_dimensions");
  if (input.length < 1 || input.length > MAX_CAMPAIGN_DIMENSIONS) {
    throw campaignError(
      "campaign_cardinality_refusal",
      `declared_dimensions must contain 1..${MAX_CAMPAIGN_DIMENSIONS} dimensions`,
    );
  }
  const dimensions = input.map((dimension, dimensionIndex) => {
    assertExactFields(
      dimension,
      ["dimension_id", "values"],
      `declared_dimensions[${dimensionIndex}]`,
    );
    const dimensionId = assertOpaqueToken(
      dimension.dimension_id,
      `declared_dimensions[${dimensionIndex}].dimension_id`,
    );
    assertDataArray(dimension.values, `declared_dimensions[${dimensionIndex}].values`);
    if (dimension.values.length < 1
        || dimension.values.length > MAX_CAMPAIGN_CELLS) {
      throw campaignError(
        "campaign_cardinality_refusal",
        `declared_dimensions[${dimensionIndex}].values must contain 1..${MAX_CAMPAIGN_CELLS} values`,
      );
    }
    const values = dimension.values.map((value, valueIndex) => assertOpaqueToken(
      value,
      `declared_dimensions[${dimensionIndex}].values[${valueIndex}]`,
    )).sort(compareText);
    assertSortedUnique(values, `declared_dimensions[${dimensionIndex}].values`);
    return { dimension_id: dimensionId, values };
  }).sort((left, right) => compareText(left.dimension_id, right.dimension_id));
  assertSortedUnique(
    dimensions.map((dimension) => dimension.dimension_id),
    "declared dimension ids",
  );
  return dimensions;
}

function declaredCellCardinality(dimensions) {
  let cardinality = 1;
  for (const dimension of dimensions) {
    if (cardinality > Math.floor(MAX_CAMPAIGN_CELLS / dimension.values.length)) {
      throw campaignError(
        "campaign_cardinality_refusal",
        `declared cell cardinality exceeds ${MAX_CAMPAIGN_CELLS}`,
      );
    }
    cardinality *= dimension.values.length;
  }
  return cardinality;
}

function expandCellIds(dimensions, campaignNucleusDigest) {
  const cellIds = [];
  const selection = [];
  const visit = (dimensionIndex) => {
    if (dimensionIndex === dimensions.length) {
      cellIds.push(`physical-cell:${hashCanonicalJson({
        domain: "hacker-bob/physical-campaign-cell/v1",
        campaign_nucleus_digest: campaignNucleusDigest,
        dimension_values: selection,
      })}`);
      return;
    }
    const dimension = dimensions[dimensionIndex];
    for (const value of dimension.values) {
      selection.push({ dimension_id: dimension.dimension_id, value });
      visit(dimensionIndex + 1);
      selection.pop();
    }
  };
  visit(0);
  cellIds.sort(compareText);
  assertSortedUnique(cellIds, "derived campaign cell ids");
  return cellIds;
}

const PREFLIGHT_INPUT_FIELDS = Object.freeze([
  "authority_binding_digest",
  "capability_pack_digest",
  "closure_signer_key_ref",
  "closure_signer_public_key_digest",
  "declared_dimensions",
  "events_per_cell",
  "segment_event_limit",
  "session_nucleus_hash",
]);

// Identity v1 derived campaign_id from a nucleus that also included the full
// assignment authority digest.  Because that assignment digest itself binds
// campaign_ref, a production assignment would require a SHA-256 fixed point.
// V2 accepts only a Bob-issued opaque campaign id, binds it into the nucleus,
// and leaves the full assignment digest free to bind that already-issued id.
// The legacy shape remains byte-compatible for recovery/conformance, but a
// production closure owner rejects it.
const PREFLIGHT_V2_INPUT_FIELDS = Object.freeze([
  ...PREFLIGHT_INPUT_FIELDS,
  "campaign_id",
  "campaign_identity_version",
]);

const PREFLIGHT_FIELDS = Object.freeze([
  "version",
  "campaign_id",
  "campaign_nucleus_digest",
  "session_nucleus_hash",
  "authority_binding_digest",
  "capability_pack_digest",
  "closure_signer_key_ref",
  "closure_signer_public_key_digest",
  "declared_dimensions",
  "declared_dimensions_digest",
  "events_per_cell",
  "declared_cell_count",
  "declared_event_count",
  "segment_event_limit",
  "segment_count",
  "cells_root",
  "segments",
  "preflight_digest",
]);

const PREFLIGHT_V2_FIELDS = Object.freeze([
  ...PREFLIGHT_FIELDS,
  "campaign_identity_version",
]);

function assertCampaignId(value, label = "campaign_id") {
  const campaignId = assertOpaqueToken(value, label);
  if (!campaignId.startsWith("physical-campaign:")) {
    throw campaignError(
      "campaign_contract_invalid",
      `${label} must use the physical-campaign: namespace`,
    );
  }
  return campaignId;
}

function buildPhysicalCampaignClosurePreflight(input) {
  assertPlainDataObject(input, "physical campaign preflight input");
  const identityV2 = Object.prototype.hasOwnProperty.call(
    input,
    "campaign_identity_version",
  );
  assertExactFields(
    input,
    identityV2 ? PREFLIGHT_V2_INPUT_FIELDS : PREFLIGHT_INPUT_FIELDS,
    "physical campaign preflight input",
  );
  if (identityV2 && input.campaign_identity_version !== PHYSICAL_CAMPAIGN_IDENTITY_VERSION) {
    throw campaignError(
      "campaign_contract_invalid",
      `campaign_identity_version must be ${PHYSICAL_CAMPAIGN_IDENTITY_VERSION}`,
    );
  }
  const issuedCampaignId = identityV2
    ? assertCampaignId(input.campaign_id)
    : null;
  const sessionNucleusHash = assertDigest(input.session_nucleus_hash, "session_nucleus_hash");
  const authorityBindingDigest = assertDigest(
    input.authority_binding_digest,
    "authority_binding_digest",
  );
  const capabilityPackDigest = assertDigest(input.capability_pack_digest, "capability_pack_digest");
  const closureSignerKeyRef = assertOpaqueToken(
    input.closure_signer_key_ref,
    "closure_signer_key_ref",
  );
  const closureSignerPublicKeyDigest = assertDigest(
    input.closure_signer_public_key_digest,
    "closure_signer_public_key_digest",
  );
  const dimensions = normalizeDeclaredDimensions(input.declared_dimensions);
  const eventsPerCell = assertInteger(input.events_per_cell, "events_per_cell", {
    minimum: 1,
    maximum: MAX_EVENTS_PER_CELL,
  });
  const segmentEventLimit = assertInteger(input.segment_event_limit, "segment_event_limit", {
    minimum: 1,
    maximum: MAX_SEGMENT_EVENT_LIMIT,
  });
  if (eventsPerCell > segmentEventLimit) {
    throw campaignError(
      "campaign_cardinality_refusal",
      "one cell's declared event budget exceeds the segment event limit",
      { events_per_cell: eventsPerCell, segment_event_limit: segmentEventLimit },
    );
  }
  const declaredCellCount = declaredCellCardinality(dimensions);
  if (declaredCellCount > Math.floor(MAX_CAMPAIGN_EVENTS / eventsPerCell)) {
    throw campaignError(
      "campaign_cardinality_refusal",
      `declared event cardinality exceeds ${MAX_CAMPAIGN_EVENTS}`,
    );
  }
  const declaredEventCount = declaredCellCount * eventsPerCell;
  const declaredDimensionsDigest = hashCanonicalJson({
    domain: "hacker-bob/physical-campaign-dimensions/v1",
    declared_dimensions: dimensions,
  });
  const campaignNucleusDigest = hashCanonicalJson({
    domain: identityV2
      ? "hacker-bob/physical-campaign-nucleus/v2"
      : "hacker-bob/physical-campaign-nucleus/v1",
    ...(identityV2 ? {
      campaign_identity_version: PHYSICAL_CAMPAIGN_IDENTITY_VERSION,
      campaign_id: issuedCampaignId,
    } : {}),
    session_nucleus_hash: sessionNucleusHash,
    authority_binding_digest: authorityBindingDigest,
    capability_pack_digest: capabilityPackDigest,
    closure_signer_key_ref: closureSignerKeyRef,
    closure_signer_public_key_digest: closureSignerPublicKeyDigest,
    declared_dimensions_digest: declaredDimensionsDigest,
    events_per_cell: eventsPerCell,
    declared_cell_count: declaredCellCount,
    declared_event_count: declaredEventCount,
  });
  const campaignId = identityV2
    ? issuedCampaignId
    : `physical-campaign:${hashCanonicalJson({
      domain: "hacker-bob/physical-campaign-id/v1",
      campaign_nucleus_digest: campaignNucleusDigest,
      segment_event_limit: segmentEventLimit,
    })}`;
  const cellIds = expandCellIds(dimensions, campaignNucleusDigest);
  if (cellIds.length !== declaredCellCount) {
    throw campaignError("campaign_cardinality_refusal", "cell expansion cardinality drifted");
  }
  const cellsRoot = merkleRoot(
    cellIds.map((cellId) => hashCanonicalJson({
      domain: "hacker-bob/physical-campaign-cell-leaf/v1",
      cell_id: cellId,
    })),
    "hacker-bob/physical-campaign-cells-merkle/v1",
  );
  const cellsPerSegment = Math.floor(segmentEventLimit / eventsPerCell);
  const segments = [];
  for (let offset = 0; offset < cellIds.length; offset += cellsPerSegment) {
    const segmentCellIds = cellIds.slice(offset, offset + cellsPerSegment);
    const segmentIndex = segments.length;
    const cellAssignmentRoot = merkleRoot(
      segmentCellIds.map((cellId) => hashCanonicalJson({
        domain: "hacker-bob/physical-campaign-segment-cell/v1",
        cell_id: cellId,
      })),
      "hacker-bob/physical-campaign-segment-cells-merkle/v1",
    );
    segments.push({
      segment_index: segmentIndex,
      segment_key: hashCanonicalJson({
        domain: "hacker-bob/physical-campaign-segment-key/v1",
        campaign_nucleus_digest: campaignNucleusDigest,
        segment_index: segmentIndex,
        cell_assignment_root: cellAssignmentRoot,
      }),
      cell_ids: segmentCellIds,
      cell_count: segmentCellIds.length,
      expected_event_count: segmentCellIds.length * eventsPerCell,
      cell_assignment_root: cellAssignmentRoot,
    });
  }
  const basis = {
    version: PHYSICAL_CAMPAIGN_CLOSURE_VERSION,
    ...(identityV2 ? {
      campaign_identity_version: PHYSICAL_CAMPAIGN_IDENTITY_VERSION,
    } : {}),
    campaign_id: campaignId,
    campaign_nucleus_digest: campaignNucleusDigest,
    session_nucleus_hash: sessionNucleusHash,
    authority_binding_digest: authorityBindingDigest,
    capability_pack_digest: capabilityPackDigest,
    closure_signer_key_ref: closureSignerKeyRef,
    closure_signer_public_key_digest: closureSignerPublicKeyDigest,
    declared_dimensions: dimensions,
    declared_dimensions_digest: declaredDimensionsDigest,
    events_per_cell: eventsPerCell,
    declared_cell_count: declaredCellCount,
    declared_event_count: declaredEventCount,
    segment_event_limit: segmentEventLimit,
    segment_count: segments.length,
    cells_root: cellsRoot,
    segments,
  };
  return deepFreeze({
    ...basis,
    preflight_digest: hashCanonicalJson({
      domain: identityV2
        ? "hacker-bob/physical-campaign-preflight/v2"
        : "hacker-bob/physical-campaign-preflight/v1",
      ...basis,
    }),
  });
}

function normalizePhysicalCampaignClosurePreflight(input) {
  assertPlainDataObject(input, "physical campaign preflight");
  const identityV2 = Object.prototype.hasOwnProperty.call(
    input,
    "campaign_identity_version",
  );
  assertExactFields(
    input,
    identityV2 ? PREFLIGHT_V2_FIELDS : PREFLIGHT_FIELDS,
    "physical campaign preflight",
  );
  if (input.version !== PHYSICAL_CAMPAIGN_CLOSURE_VERSION) {
    throw campaignError(
      "campaign_contract_invalid",
      `physical campaign preflight version must be ${PHYSICAL_CAMPAIGN_CLOSURE_VERSION}`,
    );
  }
  const rebuilt = buildPhysicalCampaignClosurePreflight({
    ...(identityV2 ? {
      campaign_identity_version: input.campaign_identity_version,
      campaign_id: input.campaign_id,
    } : {}),
    session_nucleus_hash: input.session_nucleus_hash,
    authority_binding_digest: input.authority_binding_digest,
    capability_pack_digest: input.capability_pack_digest,
    closure_signer_key_ref: input.closure_signer_key_ref,
    closure_signer_public_key_digest: input.closure_signer_public_key_digest,
    declared_dimensions: input.declared_dimensions,
    events_per_cell: input.events_per_cell,
    segment_event_limit: input.segment_event_limit,
  });
  assertDataArray(input.segments, "physical campaign preflight segments");
  for (let index = 0; index < input.segments.length; index += 1) {
    const segment = input.segments[index];
    assertExactFields(
      segment,
      [
        "segment_index",
        "segment_key",
        "cell_ids",
        "cell_count",
        "expected_event_count",
        "cell_assignment_root",
      ],
      `physical campaign preflight segments[${index}]`,
    );
    assertDataArray(segment.cell_ids, `physical campaign preflight segments[${index}].cell_ids`);
  }
  if (canonicalJson(input) !== canonicalJson(rebuilt)) {
    throw campaignError(
      "campaign_preflight_tamper",
      "physical campaign preflight does not match its deterministic expansion",
    );
  }
  return rebuilt;
}

function campaignGenesisDigest(preflightInput) {
  const preflight = normalizePhysicalCampaignClosurePreflight(preflightInput);
  return hashCanonicalJson({
    domain: "hacker-bob/physical-campaign-segment-genesis/v1",
    campaign_id: preflight.campaign_id,
    campaign_nucleus_digest: preflight.campaign_nucleus_digest,
    preflight_digest: preflight.preflight_digest,
  });
}

function eventRef(preflight, cellId, eventOrdinal) {
  return `physical-campaign-event:${hashCanonicalJson({
    domain: "hacker-bob/physical-campaign-event-ref/v1",
    campaign_id: preflight.campaign_id,
    cell_id: cellId,
    event_ordinal: eventOrdinal,
  })}`;
}

function normalizeSegmentEvents(preflight, plan, events) {
  assertDataArray(events, "segment events");
  if (events.length !== plan.expected_event_count) {
    throw campaignError(
      "campaign_segment_incomplete",
      "segment event count does not equal its preflight budget",
      { expected: plan.expected_event_count, actual: events.length },
    );
  }
  const expectedCells = new Set(plan.cell_ids);
  const eventKeys = new Set();
  const sourceEventDigests = new Set();
  const perCellCounts = new Map();
  const projections = events.map((event, index) => {
    assertPlainDataObject(event, `events[${index}]`);
    const cellId = assertText(event.cell_id, `events[${index}].cell_id`, { maximum: 80 });
    if (!expectedCells.has(cellId)) {
      throw campaignError(
        "campaign_segment_cell_drift",
        "event cell is not assigned to this segment",
        { cell_id: cellId, segment_index: plan.segment_index },
      );
    }
    const ordinal = assertInteger(event.event_ordinal, `events[${index}].event_ordinal`, {
      minimum: 1,
      maximum: preflight.events_per_cell,
    });
    const terminal = ordinal === preflight.events_per_cell;
    const required = terminal
      ? ["cell_id", "event_ordinal", "event_kind", "source_event_digest", "terminal_state", "terminal_witness_digest"]
      : ["cell_id", "event_ordinal", "event_kind", "source_event_digest"];
    assertExactFields(event, required, `events[${index}]`);
    const key = `${cellId}\u0000${ordinal}`;
    if (eventKeys.has(key)) {
      throw campaignError("campaign_duplicate", "segment contains a duplicate cell event slot", {
        cell_id: cellId,
        event_ordinal: ordinal,
      });
    }
    eventKeys.add(key);
    const sourceEventDigest = assertDigest(
      event.source_event_digest,
      `events[${index}].source_event_digest`,
    );
    if (sourceEventDigests.has(sourceEventDigest)) {
      throw campaignError("campaign_duplicate", "segment reuses a source event digest", {
        source_event_digest: sourceEventDigest,
      });
    }
    sourceEventDigests.add(sourceEventDigest);
    const projection = {
      campaign_event_ref: eventRef(preflight, cellId, ordinal),
      cell_id: cellId,
      event_ordinal: ordinal,
      event_kind: assertOpaqueToken(event.event_kind, `events[${index}].event_kind`),
      source_event_digest: sourceEventDigest,
    };
    if (terminal) {
      if (!TERMINAL_STATE_VALUES.includes(event.terminal_state)) {
        throw campaignError(
          "campaign_contract_invalid",
          `events[${index}].terminal_state must be one of ${TERMINAL_STATE_VALUES.join(", ")}`,
        );
      }
      projection.terminal_state = event.terminal_state;
      projection.terminal_witness_digest = assertDigest(
        event.terminal_witness_digest,
        `events[${index}].terminal_witness_digest`,
      );
    }
    perCellCounts.set(cellId, (perCellCounts.get(cellId) || 0) + 1);
    return projection;
  });
  for (const cellId of plan.cell_ids) {
    if (perCellCounts.get(cellId) !== preflight.events_per_cell) {
      throw campaignError(
        "campaign_segment_incomplete",
        "segment does not contain every declared event ordinal for a cell",
        { cell_id: cellId, actual: perCellCounts.get(cellId) || 0 },
      );
    }
  }
  projections.sort((left, right) => (
    compareText(left.cell_id, right.cell_id) || left.event_ordinal - right.event_ordinal
  ));
  return projections;
}

function normalizeSignerPort(port, preflight) {
  if (port == null || typeof port !== "object" || !SIGNER_PORT_STATE.has(port)) {
    throw campaignError(
      "campaign_signer_port_untrusted",
      "segment signing requires a branded physical campaign Ed25519 signer port",
    );
  }
  if (port.signer_key_ref !== preflight.closure_signer_key_ref
      || port.signer_public_key_digest !== preflight.closure_signer_public_key_digest) {
    throw campaignError(
      "campaign_authority_drift",
      "segment signer identity does not match campaign preflight",
    );
  }
  return port;
}

function normalizeVerifierPort(port, preflight) {
  if (port == null || typeof port !== "object" || !VERIFIER_PORT_STATE.has(port)) {
    throw campaignError(
      "campaign_verifier_port_untrusted",
      "segment verification requires a branded physical campaign Ed25519 verifier port",
    );
  }
  if (port.signer_key_ref !== preflight.closure_signer_key_ref
      || port.signer_public_key_digest !== preflight.closure_signer_public_key_digest) {
    throw campaignError(
      "campaign_authority_drift",
      "segment verifier identity does not match campaign preflight",
    );
  }
  return port;
}

const SEGMENT_BASIS_FIELDS = Object.freeze([
  "version",
  "campaign_id",
  "campaign_nucleus_digest",
  "preflight_digest",
  "authority_binding_digest",
  "segment_index",
  "segment_key",
  "previous_segment_digest",
  "cell_assignment_root",
  "expected_cell_count",
  "expected_event_count",
  "event_count",
  "materialized_graph_hash",
  "event_root",
  "source_event_digests",
  "source_event_digests_root",
  "terminal_cell_count",
  "terminal_cells",
  "terminal_cells_root",
  "coverage_credited_cell_count",
  "residue_cell_count",
  "terminal_state_counts",
  "signer_key_ref",
  "signer_public_key_digest",
]);

const SEGMENT_FIELDS = Object.freeze([
  ...SEGMENT_BASIS_FIELDS,
  "segment_root",
  "signature_scheme",
  "signature_input_digest",
  "signature",
  "sealed_segment_digest",
]);

function terminalCellProjection(preflight, event) {
  return {
    cell_id: event.cell_id,
    terminal_state: event.terminal_state,
    terminal_witness_digest: event.terminal_witness_digest,
    terminal_event_ref: event.campaign_event_ref,
    terminal_source_event_digest: event.source_event_digest,
  };
}

function sealPhysicalCampaignClosureSegment(preflightInput, segmentIndex, events, options) {
  const preflight = normalizePhysicalCampaignClosurePreflight(preflightInput);
  const index = assertInteger(segmentIndex, "segment_index", {
    minimum: 0,
    maximum: preflight.segment_count - 1,
  });
  assertExactFields(
    options,
    ["materialized_graph_hash", "previous_segment_digest", "signer"],
    "segment seal options",
  );
  const previousSegmentDigest = assertDigest(
    options.previous_segment_digest,
    "previous_segment_digest",
  );
  if (index === 0 && previousSegmentDigest !== campaignGenesisDigest(preflight)) {
    throw campaignError(
      "campaign_segment_gap",
      "segment zero must link the campaign genesis digest",
    );
  }
  const signer = normalizeSignerPort(options.signer, preflight);
  const materializedGraphHash = assertDigest(
    options.materialized_graph_hash,
    "materialized_graph_hash",
  );
  const plan = preflight.segments[index];
  const normalizedEvents = normalizeSegmentEvents(preflight, plan, events);
  const eventLeafDigests = normalizedEvents.map((event) => hashCanonicalJson({
    domain: "hacker-bob/physical-campaign-event-leaf/v1",
    event,
  }));
  const sourceEventDigests = normalizedEvents
    .map((event) => event.source_event_digest)
    .sort(compareText);
  const terminalCells = normalizedEvents
    .filter((event) => event.event_ordinal === preflight.events_per_cell)
    .map((event) => terminalCellProjection(preflight, event))
    .sort((left, right) => compareText(left.cell_id, right.cell_id));
  const stateCounts = Object.fromEntries(TERMINAL_STATE_VALUES.map((state) => [state, 0]));
  for (const terminal of terminalCells) stateCounts[terminal.terminal_state] += 1;
  const coverageCreditedCellCount = COVERAGE_CREDIT_STATE_VALUES.reduce(
    (total, state) => total + stateCounts[state],
    0,
  );
  const residueCellCount = terminalCells.length - coverageCreditedCellCount;
  const basis = {
    version: PHYSICAL_CAMPAIGN_CLOSURE_VERSION,
    campaign_id: preflight.campaign_id,
    campaign_nucleus_digest: preflight.campaign_nucleus_digest,
    preflight_digest: preflight.preflight_digest,
    authority_binding_digest: preflight.authority_binding_digest,
    segment_index: index,
    segment_key: plan.segment_key,
    previous_segment_digest: previousSegmentDigest,
    cell_assignment_root: plan.cell_assignment_root,
    expected_cell_count: plan.cell_count,
    expected_event_count: plan.expected_event_count,
    event_count: normalizedEvents.length,
    materialized_graph_hash: materializedGraphHash,
    event_root: merkleRoot(
      eventLeafDigests,
      "hacker-bob/physical-campaign-events-merkle/v1",
    ),
    source_event_digests: sourceEventDigests,
    source_event_digests_root: merkleRoot(
      sourceEventDigests,
      "hacker-bob/physical-campaign-source-events-merkle/v1",
    ),
    terminal_cell_count: terminalCells.length,
    terminal_cells: terminalCells,
    terminal_cells_root: merkleRoot(
      terminalCells.map((terminal) => hashCanonicalJson({
        domain: "hacker-bob/physical-campaign-terminal-cell/v1",
        terminal,
      })),
      "hacker-bob/physical-campaign-terminal-cells-merkle/v1",
    ),
    coverage_credited_cell_count: coverageCreditedCellCount,
    residue_cell_count: residueCellCount,
    terminal_state_counts: stateCounts,
    signer_key_ref: preflight.closure_signer_key_ref,
    signer_public_key_digest: preflight.closure_signer_public_key_digest,
  };
  const segmentRoot = hashCanonicalJson({
    domain: "hacker-bob/physical-campaign-segment-root/v1",
    ...basis,
  });
  const signatureInputDigest = hashCanonicalJson({
    domain: "hacker-bob/physical-campaign-segment-signature/v1",
    campaign_id: preflight.campaign_id,
    segment_index: index,
    segment_root: segmentRoot,
  });
  const request = deepFreeze({
    scheme: "ed25519",
    signer_key_ref: preflight.closure_signer_key_ref,
    signer_public_key_digest: preflight.closure_signer_public_key_digest,
    campaign_id: preflight.campaign_id,
    segment_index: index,
    segment_root: segmentRoot,
    signature_input_digest: signatureInputDigest,
  });
  const signerState = SIGNER_PORT_STATE.get(signer);
  const signature = crypto.sign(
    null,
    Buffer.from(request.signature_input_digest, "hex"),
    signerState.privateKey,
  ).toString("base64url");
  const canonicalSignature = assertCanonicalSignature(signature);
  const sealedSegmentDigest = hashCanonicalJson({
    domain: "hacker-bob/physical-campaign-sealed-segment/v1",
    segment_root: segmentRoot,
    signature_scheme: "ed25519",
    signature_input_digest: signatureInputDigest,
    signature: canonicalSignature,
  });
  return deepFreeze({
    ...basis,
    segment_root: segmentRoot,
    signature_scheme: "ed25519",
    signature_input_digest: signatureInputDigest,
    signature: canonicalSignature,
    sealed_segment_digest: sealedSegmentDigest,
  });
}

function normalizeTerminalCell(input, index, preflight, plan, sourceDigestSet) {
  assertExactFields(
    input,
    [
      "cell_id",
      "terminal_state",
      "terminal_witness_digest",
      "terminal_event_ref",
      "terminal_source_event_digest",
    ],
    `terminal_cells[${index}]`,
  );
  const cellId = assertText(input.cell_id, `terminal_cells[${index}].cell_id`, { maximum: 80 });
  if (!plan.cell_ids.includes(cellId)) {
    throw campaignError("campaign_segment_cell_drift", "terminal cell is outside segment plan", {
      cell_id: cellId,
    });
  }
  if (!TERMINAL_STATE_VALUES.includes(input.terminal_state)) {
    throw campaignError("campaign_contract_invalid", "terminal cell state is not closed");
  }
  const sourceDigest = assertDigest(
    input.terminal_source_event_digest,
    `terminal_cells[${index}].terminal_source_event_digest`,
  );
  if (!sourceDigestSet.has(sourceDigest)) {
    throw campaignError(
      "campaign_segment_tamper",
      "terminal source event is absent from the signed segment digest set",
    );
  }
  const expectedEventRef = eventRef(preflight, cellId, preflight.events_per_cell);
  if (input.terminal_event_ref !== expectedEventRef) {
    throw campaignError("campaign_segment_tamper", "terminal event reference drifted");
  }
  return {
    cell_id: cellId,
    terminal_state: input.terminal_state,
    terminal_witness_digest: assertDigest(
      input.terminal_witness_digest,
      `terminal_cells[${index}].terminal_witness_digest`,
    ),
    terminal_event_ref: expectedEventRef,
    terminal_source_event_digest: sourceDigest,
  };
}

function verifyPhysicalCampaignClosureSegment(
  segmentInput,
  preflightInput,
  { verifier: verifierInput, expected_previous_segment_digest: expectedPrevious = null } = {},
) {
  const preflight = normalizePhysicalCampaignClosurePreflight(preflightInput);
  const verifier = normalizeVerifierPort(verifierInput, preflight);
  assertExactFields(segmentInput, SEGMENT_FIELDS, "physical campaign closure segment");
  const index = assertInteger(segmentInput.segment_index, "segment_index", {
    minimum: 0,
    maximum: preflight.segment_count - 1,
  });
  const plan = preflight.segments[index];
  for (const [field, expected] of [
    ["version", PHYSICAL_CAMPAIGN_CLOSURE_VERSION],
    ["campaign_id", preflight.campaign_id],
    ["campaign_nucleus_digest", preflight.campaign_nucleus_digest],
    ["preflight_digest", preflight.preflight_digest],
    ["authority_binding_digest", preflight.authority_binding_digest],
    ["segment_key", plan.segment_key],
    ["cell_assignment_root", plan.cell_assignment_root],
    ["expected_cell_count", plan.cell_count],
    ["expected_event_count", plan.expected_event_count],
    ["event_count", plan.expected_event_count],
    ["terminal_cell_count", plan.cell_count],
    ["signer_key_ref", preflight.closure_signer_key_ref],
    ["signer_public_key_digest", preflight.closure_signer_public_key_digest],
  ]) {
    if (segmentInput[field] !== expected) {
      throw campaignError(
        field.includes("signer") || field === "authority_binding_digest"
          ? "campaign_authority_drift"
          : "campaign_segment_tamper",
        `segment ${field} does not match campaign preflight`,
      );
    }
  }
  const previousSegmentDigest = assertDigest(
    segmentInput.previous_segment_digest,
    "previous_segment_digest",
  );
  if (expectedPrevious != null
      && previousSegmentDigest !== assertDigest(expectedPrevious, "expected_previous_segment_digest")) {
    throw campaignError("campaign_segment_gap", "segment previous digest does not link chain head");
  }
  assertDataArray(segmentInput.source_event_digests, "source_event_digests");
  if (segmentInput.source_event_digests.length !== plan.expected_event_count) {
    throw campaignError("campaign_segment_tamper", "source event digest count drifted");
  }
  const sourceEventDigests = segmentInput.source_event_digests.map((digest, digestIndex) => (
    assertDigest(digest, `source_event_digests[${digestIndex}]`)
  ));
  assertSortedUnique(sourceEventDigests, "source_event_digests");
  const sourceDigestSet = new Set(sourceEventDigests);
  const sourceRoot = merkleRoot(
    sourceEventDigests,
    "hacker-bob/physical-campaign-source-events-merkle/v1",
  );
  if (segmentInput.source_event_digests_root !== sourceRoot) {
    throw campaignError("campaign_segment_tamper", "source event digest root drifted");
  }
  assertDigest(segmentInput.event_root, "event_root");
  assertDigest(segmentInput.materialized_graph_hash, "materialized_graph_hash");
  assertDataArray(segmentInput.terminal_cells, "terminal_cells");
  if (segmentInput.terminal_cells.length !== plan.cell_count) {
    throw campaignError("campaign_segment_tamper", "terminal cell count drifted");
  }
  const terminalCells = segmentInput.terminal_cells.map((terminal, terminalIndex) => (
    normalizeTerminalCell(terminal, terminalIndex, preflight, plan, sourceDigestSet)
  ));
  const terminalIds = terminalCells.map((terminal) => terminal.cell_id);
  assertSortedUnique(terminalIds, "terminal cell ids");
  if (canonicalJson(terminalIds) !== canonicalJson(plan.cell_ids)) {
    throw campaignError("campaign_segment_cell_drift", "terminal cell set differs from segment plan");
  }
  const terminalCellsRoot = merkleRoot(
    terminalCells.map((terminal) => hashCanonicalJson({
      domain: "hacker-bob/physical-campaign-terminal-cell/v1",
      terminal,
    })),
    "hacker-bob/physical-campaign-terminal-cells-merkle/v1",
  );
  if (segmentInput.terminal_cells_root !== terminalCellsRoot) {
    throw campaignError("campaign_segment_tamper", "terminal cell root drifted");
  }
  assertExactFields(
    segmentInput.terminal_state_counts,
    TERMINAL_STATE_VALUES,
    "terminal_state_counts",
  );
  const stateCounts = Object.fromEntries(TERMINAL_STATE_VALUES.map((state) => [state, 0]));
  for (const terminal of terminalCells) stateCounts[terminal.terminal_state] += 1;
  for (const state of TERMINAL_STATE_VALUES) {
    assertInteger(segmentInput.terminal_state_counts[state], `terminal_state_counts.${state}`, {
      minimum: 0,
      maximum: plan.cell_count,
    });
    if (segmentInput.terminal_state_counts[state] !== stateCounts[state]) {
      throw campaignError("campaign_segment_tamper", "terminal state totals drifted");
    }
  }
  const coverageCreditedCellCount = COVERAGE_CREDIT_STATE_VALUES.reduce(
    (total, state) => total + stateCounts[state],
    0,
  );
  if (segmentInput.coverage_credited_cell_count !== coverageCreditedCellCount
      || segmentInput.residue_cell_count !== plan.cell_count - coverageCreditedCellCount) {
    throw campaignError("campaign_segment_tamper", "segment coverage totals drifted");
  }
  const basis = Object.fromEntries(SEGMENT_BASIS_FIELDS.map((field) => [field, (
    field === "source_event_digests" ? sourceEventDigests
      : field === "terminal_cells" ? terminalCells
        : field === "terminal_state_counts" ? stateCounts
          : segmentInput[field]
  )]));
  const segmentRoot = hashCanonicalJson({
    domain: "hacker-bob/physical-campaign-segment-root/v1",
    ...basis,
  });
  if (segmentInput.segment_root !== segmentRoot) {
    throw campaignError("campaign_segment_tamper", "segment root does not match canonical content");
  }
  if (segmentInput.signature_scheme !== "ed25519") {
    throw campaignError("campaign_signature_invalid", "segment signature scheme must be ed25519");
  }
  const signatureInputDigest = hashCanonicalJson({
    domain: "hacker-bob/physical-campaign-segment-signature/v1",
    campaign_id: preflight.campaign_id,
    segment_index: index,
    segment_root: segmentRoot,
  });
  if (segmentInput.signature_input_digest !== signatureInputDigest) {
    throw campaignError("campaign_signature_invalid", "signature input digest drifted");
  }
  const signature = assertCanonicalSignature(segmentInput.signature);
  const sealedSegmentDigest = hashCanonicalJson({
    domain: "hacker-bob/physical-campaign-sealed-segment/v1",
    segment_root: segmentRoot,
    signature_scheme: "ed25519",
    signature_input_digest: signatureInputDigest,
    signature,
  });
  if (segmentInput.sealed_segment_digest !== sealedSegmentDigest) {
    throw campaignError("campaign_segment_tamper", "sealed segment content address drifted");
  }
  const normalized = deepFreeze({
    ...basis,
    segment_root: segmentRoot,
    signature_scheme: "ed25519",
    signature_input_digest: signatureInputDigest,
    signature,
    sealed_segment_digest: sealedSegmentDigest,
  });
  const verifierState = VERIFIER_PORT_STATE.get(verifier);
  let verified = false;
  try {
    verified = crypto.verify(
      null,
      Buffer.from(normalized.signature_input_digest, "hex"),
      verifierState.publicKey,
      Buffer.from(normalized.signature, "base64url"),
    );
  } catch {
    verified = false;
  }
  if (!verified) {
    throw campaignError("campaign_signature_invalid", "segment Ed25519 signature verification failed");
  }
  return normalized;
}

const CHECKPOINT_FIELDS = Object.freeze([
  "version",
  "campaign_id",
  "preflight_digest",
  "accepted_segments",
  "next_segment_index",
  "chain_head",
  "accepted_event_count",
  "accepted_cell_count",
  "coverage_credited_cell_count",
  "residue_cell_count",
  "checkpoint_digest",
]);

function checkpointDocument(preflight, state) {
  const basis = {
    version: PHYSICAL_CAMPAIGN_CLOSURE_VERSION,
    campaign_id: preflight.campaign_id,
    preflight_digest: preflight.preflight_digest,
    accepted_segments: state.segments.slice(),
    next_segment_index: state.segments.length,
    chain_head: state.chainHead,
    accepted_event_count: state.eventCount,
    accepted_cell_count: state.terminalCells.size,
    coverage_credited_cell_count: state.coverageCreditedCount,
    residue_cell_count: state.residueCount,
  };
  return deepFreeze({
    ...basis,
    checkpoint_digest: hashCanonicalJson({
      domain: "hacker-bob/physical-campaign-checkpoint/v1",
      ...basis,
    }),
  });
}

function normalizeCheckpoint(input, preflight, expectedCheckpointDigest, verifier) {
  assertExactFields(input, CHECKPOINT_FIELDS, "physical campaign checkpoint");
  if (expectedCheckpointDigest == null) {
    throw campaignError(
      "campaign_checkpoint_anchor_required",
      "restart requires an externally retained expected checkpoint digest",
    );
  }
  const expectedDigest = assertDigest(expectedCheckpointDigest, "expected_checkpoint_digest");
  if (input.version !== PHYSICAL_CAMPAIGN_CLOSURE_VERSION
      || input.campaign_id !== preflight.campaign_id
      || input.preflight_digest !== preflight.preflight_digest) {
    throw campaignError("campaign_authority_drift", "checkpoint belongs to another campaign authority");
  }
  const claimedCheckpointDigest = assertDigest(input.checkpoint_digest, "checkpoint_digest");
  assertDataArray(input.accepted_segments, "checkpoint accepted_segments");
  if (input.accepted_segments.length > preflight.segment_count) {
    throw campaignError("campaign_checkpoint_tamper", "checkpoint segment list is invalid");
  }
  const acceptedSegments = [];
  let previousSegmentDigest = campaignGenesisDigest(preflight);
  for (const segmentInput of input.accepted_segments) {
    const segment = verifyPhysicalCampaignClosureSegment(segmentInput, preflight, {
      verifier,
      expected_previous_segment_digest: previousSegmentDigest,
    });
    if (segment.segment_index !== acceptedSegments.length) {
      throw campaignError("campaign_checkpoint_tamper", "checkpoint segment chain is not contiguous");
    }
    acceptedSegments.push(segment);
    previousSegmentDigest = segment.sealed_segment_digest;
  }
  const basis = {
    version: PHYSICAL_CAMPAIGN_CLOSURE_VERSION,
    campaign_id: preflight.campaign_id,
    preflight_digest: preflight.preflight_digest,
    accepted_segments: acceptedSegments,
    next_segment_index: assertInteger(input.next_segment_index, "checkpoint next_segment_index", {
      minimum: 0,
      maximum: preflight.segment_count,
    }),
    chain_head: assertDigest(input.chain_head, "checkpoint chain_head"),
    accepted_event_count: assertInteger(
      input.accepted_event_count,
      "checkpoint accepted_event_count",
      { minimum: 0, maximum: preflight.declared_event_count },
    ),
    accepted_cell_count: assertInteger(
      input.accepted_cell_count,
      "checkpoint accepted_cell_count",
      { minimum: 0, maximum: preflight.declared_cell_count },
    ),
    coverage_credited_cell_count: assertInteger(
      input.coverage_credited_cell_count,
      "checkpoint coverage_credited_cell_count",
      { minimum: 0, maximum: preflight.declared_cell_count },
    ),
    residue_cell_count: assertInteger(
      input.residue_cell_count,
      "checkpoint residue_cell_count",
      { minimum: 0, maximum: preflight.declared_cell_count },
    ),
  };
  const digest = hashCanonicalJson({
    domain: "hacker-bob/physical-campaign-checkpoint/v1",
    ...basis,
  });
  if (claimedCheckpointDigest !== digest || digest !== expectedDigest) {
    throw campaignError(
      "campaign_checkpoint_tamper",
      "checkpoint does not match its externally retained digest",
    );
  }
  return deepFreeze({ ...basis, checkpoint_digest: digest });
}

function createPhysicalCampaignClosureAccumulator(preflightInput, options = {}) {
  const preflight = normalizePhysicalCampaignClosurePreflight(preflightInput);
  assertPlainDataObject(options, "physical campaign accumulator options");
  const allowedOptions = new Set(["verifier", "checkpoint", "expected_checkpoint_digest"]);
  const unknownOptions = Object.keys(options).filter((field) => !allowedOptions.has(field));
  if (unknownOptions.length > 0) {
    throw campaignError("campaign_contract_invalid", "accumulator options contain unknown fields", {
      unknown: unknownOptions.sort(),
    });
  }
  const verifier = normalizeVerifierPort(options.verifier, preflight);
  const state = {
    segments: [],
    chainHead: campaignGenesisDigest(preflight),
    sourceEventDigests: new Set(),
    terminalCells: new Map(),
    eventCount: 0,
    coverageCreditedCount: 0,
    residueCount: 0,
    busy: false,
  };

  function appendSegment(segmentInput) {
    if (state.busy) {
      throw campaignError("campaign_reentrant_call", "campaign accumulator is already reconciling");
    }
    state.busy = true;
    try {
      assertPlainDataObject(segmentInput, "physical campaign closure segment");
      const index = assertInteger(segmentInput.segment_index, "segment_index", {
        minimum: 0,
        maximum: preflight.segment_count - 1,
      });
      const nextIndex = state.segments.length;
      if (index > nextIndex) {
        throw campaignError("campaign_segment_gap", "segment handoff skipped an index", {
          expected_segment_index: nextIndex,
          received_segment_index: index,
        });
      }
      const expectedPrevious = index === 0
        ? campaignGenesisDigest(preflight)
        : state.segments[index - 1].sealed_segment_digest;
      const segment = verifyPhysicalCampaignClosureSegment(segmentInput, preflight, {
        verifier,
        expected_previous_segment_digest: expectedPrevious,
      });
      if (index < nextIndex) {
        const existing = state.segments[index];
        if (existing.sealed_segment_digest !== segment.sealed_segment_digest) {
          throw campaignError("campaign_segment_fork", "accepted segment index has a second valid root", {
            segment_index: index,
            accepted_digest: existing.sealed_segment_digest,
            received_digest: segment.sealed_segment_digest,
          });
        }
        return deepFreeze({
          accepted: false,
          replayed: true,
          segment_index: index,
          sealed_segment_digest: segment.sealed_segment_digest,
          accepted_event_count: state.eventCount,
          accepted_cell_count: state.terminalCells.size,
        });
      }
      for (const digest of segment.source_event_digests) {
        if (state.sourceEventDigests.has(digest)) {
          throw campaignError("campaign_duplicate", "source event digest crosses segment boundary", {
            source_event_digest: digest,
            segment_index: index,
          });
        }
      }
      for (const terminal of segment.terminal_cells) {
        if (state.terminalCells.has(terminal.cell_id)) {
          throw campaignError("campaign_duplicate", "terminal cell crosses segment boundary", {
            cell_id: terminal.cell_id,
            segment_index: index,
          });
        }
      }
      const nextEventCount = state.eventCount + segment.event_count;
      const nextCellCount = state.terminalCells.size + segment.terminal_cell_count;
      if (nextEventCount > preflight.declared_event_count
          || nextCellCount > preflight.declared_cell_count) {
        throw campaignError("campaign_cardinality_refusal", "segment exceeds preflight cardinality");
      }
      state.segments.push(segment);
      state.chainHead = segment.sealed_segment_digest;
      for (const digest of segment.source_event_digests) state.sourceEventDigests.add(digest);
      for (const terminal of segment.terminal_cells) {
        state.terminalCells.set(terminal.cell_id, terminal);
      }
      state.eventCount = nextEventCount;
      state.coverageCreditedCount += segment.coverage_credited_cell_count;
      state.residueCount += segment.residue_cell_count;
      return deepFreeze({
        accepted: true,
        replayed: false,
        segment_index: index,
        sealed_segment_digest: segment.sealed_segment_digest,
        accepted_event_count: state.eventCount,
        accepted_cell_count: state.terminalCells.size,
      });
    } finally {
      state.busy = false;
    }
  }

  function snapshot() {
    if (state.busy) {
      throw campaignError("campaign_reentrant_call", "cannot checkpoint during reconciliation");
    }
    return checkpointDocument(preflight, state);
  }

  function finalize() {
    if (state.busy) {
      throw campaignError("campaign_reentrant_call", "cannot finalize during reconciliation");
    }
    if (state.segments.length !== preflight.segment_count
        || state.eventCount !== preflight.declared_event_count
        || state.terminalCells.size !== preflight.declared_cell_count) {
      throw campaignError("campaign_incomplete", "campaign has missing segments, events, or cells", {
        expected_segment_count: preflight.segment_count,
        accepted_segment_count: state.segments.length,
        expected_event_count: preflight.declared_event_count,
        accepted_event_count: state.eventCount,
        expected_cell_count: preflight.declared_cell_count,
        accepted_cell_count: state.terminalCells.size,
      });
    }
    const terminalCells = Array.from(state.terminalCells.values())
      .sort((left, right) => compareText(left.cell_id, right.cell_id));
    const expectedCellIds = preflight.segments.flatMap((segment) => segment.cell_ids);
    expectedCellIds.sort(compareText);
    if (canonicalJson(terminalCells.map((terminal) => terminal.cell_id))
        !== canonicalJson(expectedCellIds)) {
      throw campaignError("campaign_incomplete", "aggregate terminal cell set differs from preflight");
    }
    const sourceEventDigests = Array.from(state.sourceEventDigests).sort(compareText);
    if (sourceEventDigests.length !== preflight.declared_event_count) {
      throw campaignError("campaign_duplicate", "aggregate source event set is not exact");
    }
    const stateCounts = Object.fromEntries(TERMINAL_STATE_VALUES.map((terminalState) => [
      terminalState,
      0,
    ]));
    for (const terminal of terminalCells) stateCounts[terminal.terminal_state] += 1;
    const residueCells = terminalCells
      .filter((terminal) => RESIDUE_STATE_VALUES.includes(terminal.terminal_state))
      .map((terminal) => ({
        cell_id: terminal.cell_id,
        terminal_state: terminal.terminal_state,
        terminal_witness_digest: terminal.terminal_witness_digest,
      }));
    const coverageCreditedCellCount = COVERAGE_CREDIT_STATE_VALUES.reduce(
      (total, terminalState) => total + stateCounts[terminalState],
      0,
    );
    const terminalComplete = terminalCells.length === preflight.declared_cell_count;
    const closureSatisfied = terminalComplete
      && residueCells.length === 0
      && coverageCreditedCellCount === preflight.declared_cell_count;
    const checkpoint = checkpointDocument(preflight, state);
    const segmentReceipts = state.segments.map((segment) => ({
      segment_index: segment.segment_index,
      segment_key: segment.segment_key,
      previous_segment_digest: segment.previous_segment_digest,
      segment_root: segment.segment_root,
      sealed_segment_digest: segment.sealed_segment_digest,
      event_count: segment.event_count,
      materialized_graph_hash: segment.materialized_graph_hash,
      terminal_cell_count: segment.terminal_cell_count,
      coverage_credited_cell_count: segment.coverage_credited_cell_count,
      residue_cell_count: segment.residue_cell_count,
      signature_scheme: segment.signature_scheme,
      signer_key_ref: segment.signer_key_ref,
      signer_public_key_digest: segment.signer_public_key_digest,
      signature_input_digest: segment.signature_input_digest,
      signature: segment.signature,
    }));
    const segmentChainMerkleRoot = merkleRoot(
      state.segments.map((segment) => segment.sealed_segment_digest),
      "hacker-bob/physical-campaign-segment-chain-merkle/v1",
    );
    const terminalCellsMerkleRoot = merkleRoot(
      terminalCells.map((terminal) => hashCanonicalJson({
        domain: "hacker-bob/physical-campaign-terminal-cell/v1",
        terminal,
      })),
      "hacker-bob/physical-campaign-aggregate-terminal-cells-merkle/v1",
    );
    const sourceEventsMerkleRoot = merkleRoot(
      sourceEventDigests,
      "hacker-bob/physical-campaign-aggregate-source-events-merkle/v1",
    );
    const residueCellsMerkleRoot = merkleRoot(
      residueCells.map((residue) => hashCanonicalJson({
        domain: "hacker-bob/physical-campaign-residue-cell/v1",
        residue,
      })),
      "hacker-bob/physical-campaign-residue-cells-merkle/v1",
    );
    const closureBasis = {
      domain: preflight.campaign_identity_version === PHYSICAL_CAMPAIGN_IDENTITY_VERSION
        ? "hacker-bob/physical-campaign-aggregate-closure/v2"
        : "hacker-bob/physical-campaign-aggregate-closure/v1",
      ...(preflight.campaign_identity_version === PHYSICAL_CAMPAIGN_IDENTITY_VERSION ? {
        campaign_identity_version: PHYSICAL_CAMPAIGN_IDENTITY_VERSION,
      } : {}),
      campaign_id: preflight.campaign_id,
      campaign_nucleus_digest: preflight.campaign_nucleus_digest,
      preflight_digest: preflight.preflight_digest,
      checkpoint_digest: checkpoint.checkpoint_digest,
      segment_count: state.segments.length,
      segment_chain_head: state.chainHead,
      segment_chain_merkle_root: segmentChainMerkleRoot,
      event_count: state.eventCount,
      source_events_merkle_root: sourceEventsMerkleRoot,
      terminal_cell_count: terminalCells.length,
      terminal_cells_merkle_root: terminalCellsMerkleRoot,
      terminal_complete: terminalComplete,
      coverage_credited_cell_count: state.coverageCreditedCount,
      residue_cell_count: state.residueCount,
      residue_cells_merkle_root: residueCellsMerkleRoot,
      terminal_state_counts: stateCounts,
      closure_status: closureSatisfied ? "closed" : "terminal_residue",
      closure_satisfied: closureSatisfied,
    };
    const aggregateClosureRoot = hashCanonicalJson(closureBasis);
    const manifestBasis = {
      version: PHYSICAL_CAMPAIGN_CLOSURE_VERSION,
      ...(preflight.campaign_identity_version === PHYSICAL_CAMPAIGN_IDENTITY_VERSION ? {
        campaign_identity_version: PHYSICAL_CAMPAIGN_IDENTITY_VERSION,
      } : {}),
      campaign_id: preflight.campaign_id,
      campaign_nucleus_digest: preflight.campaign_nucleus_digest,
      preflight_digest: preflight.preflight_digest,
      checkpoint_digest: checkpoint.checkpoint_digest,
      declared_cell_count: preflight.declared_cell_count,
      declared_event_count: preflight.declared_event_count,
      segment_count: state.segments.length,
      segment_chain_head: state.chainHead,
      segment_chain_merkle_root: segmentChainMerkleRoot,
      segment_receipts: segmentReceipts,
      event_count: state.eventCount,
      source_events_merkle_root: sourceEventsMerkleRoot,
      terminal_cell_count: terminalCells.length,
      terminal_cells_merkle_root: terminalCellsMerkleRoot,
      terminal_complete: terminalComplete,
      coverage_credited_cell_count: state.coverageCreditedCount,
      residue_cell_count: state.residueCount,
      residue_cells: residueCells,
      residue_cells_merkle_root: residueCellsMerkleRoot,
      terminal_state_counts: stateCounts,
      closure_status: closureSatisfied ? "closed" : "terminal_residue",
      closure_satisfied: closureSatisfied,
      aggregate_closure_root: aggregateClosureRoot,
    };
    const manifest = deepFreeze({
      ...manifestBasis,
      manifest_digest: hashCanonicalJson({
        domain: preflight.campaign_identity_version === PHYSICAL_CAMPAIGN_IDENTITY_VERSION
          ? "hacker-bob/physical-campaign-manifest/v2"
          : "hacker-bob/physical-campaign-manifest/v1",
        ...manifestBasis,
      }),
    });
    FINALIZED_CAMPAIGN_MANIFESTS.add(manifest);
    return manifest;
  }

  const accumulator = Object.freeze({ appendSegment, finalize, snapshot });
  if (options.checkpoint != null) {
    const checkpoint = normalizeCheckpoint(
      options.checkpoint,
      preflight,
      options.expected_checkpoint_digest,
      verifier,
    );
    for (const segment of checkpoint.accepted_segments) appendSegment(segment);
    const reconstructed = snapshot();
    if (canonicalJson(reconstructed) !== canonicalJson(checkpoint)) {
      throw campaignError(
        "campaign_checkpoint_tamper",
        "checkpoint projections do not match signed segment reconstruction",
      );
    }
  } else if (options.expected_checkpoint_digest != null) {
    throw campaignError(
      "campaign_contract_invalid",
      "expected_checkpoint_digest cannot be supplied without a checkpoint",
    );
  }
  return accumulator;
}

function assertPhysicalCampaignClosureSatisfied(manifest) {
  if (manifest == null || typeof manifest !== "object"
      || !FINALIZED_CAMPAIGN_MANIFESTS.has(manifest)) {
    throw campaignError(
      "campaign_manifest_untrusted",
      "closure assertion requires a manifest finalized by a live verified accumulator",
    );
  }
  if (manifest.closure_satisfied !== true || manifest.closure_status !== "closed"
      || manifest.terminal_complete !== true
      || manifest.residue_cell_count !== 0) {
    throw campaignError(
      "campaign_terminal_residue",
      "physical campaign retains terminal residue and cannot satisfy closure",
      {
        closure_status: manifest.closure_status,
        residue_cell_count: manifest.residue_cell_count,
      },
    );
  }
  return manifest;
}

module.exports = {
  COVERAGE_CREDIT_STATE_VALUES,
  DEFAULT_SEGMENT_EVENT_LIMIT,
  MAX_CAMPAIGN_CELLS,
  MAX_CAMPAIGN_DIMENSIONS,
  MAX_CAMPAIGN_EVENTS,
  MAX_EVENTS_PER_CELL,
  MAX_SEGMENT_EVENT_LIMIT,
  PHYSICAL_CAMPAIGN_CLOSURE_VERSION,
  PHYSICAL_CAMPAIGN_IDENTITY_VERSION,
  RESIDUE_STATE_VALUES,
  SEGMENT_LEDGER_HEADROOM,
  TERMINAL_STATE_VALUES,
  assertPhysicalCampaignClosureSatisfied,
  buildPhysicalCampaignClosurePreflight,
  campaignGenesisDigest,
  createPhysicalCampaignClosureAccumulator,
  createPhysicalCampaignEd25519SignerPort,
  createPhysicalCampaignEd25519VerifierPort,
  exportPhysicalCampaignEd25519VerifierDescriptor,
  importPhysicalCampaignEd25519VerifierDescriptor,
  merkleRoot,
  normalizePhysicalCampaignClosurePreflight,
  sealPhysicalCampaignClosureSegment,
  verifyPhysicalCampaignClosureSegment,
};
