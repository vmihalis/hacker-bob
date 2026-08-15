"use strict";

// Reviewed, package-safe Plane-PH release contract projections. Runtime gate
// evidence and the repository checker both use these functions so an evidence
// issuer cannot bind one interpretation of a node while release validation
// checks another.

const crypto = require("node:crypto");
const { types: utilTypes } = require("node:util");

const GRAPH_ID = "plane-physical-security";
const RELEASE_NODE_ID = "PH-X8";
const REVIEWED_NODE_CONTRACT_REGISTRY_SHA256 =
  "aba04a5376b5c3ba75b864166baf3d563e2cb69fdf406a113e530d41b070a99d";
const REVIEWED_HYPEREDGE_REGISTRY_SHA256 =
  "bc71611c7512463d2462434f5633a966fd4f42257117f41d732853371aadc755";
const PRODUCTION_NONWAIVABLE_HIL_NODE_IDS = Object.freeze([
  "PH-C1", "PH-C10", "PH-C2", "PH-C3", "PH-C4", "PH-C5", "PH-C6", "PH-C7",
  "PH-C8", "PH-C9", "PH-P5", "PH-P6", "PH-P7", "PH-P9", "PH-S3", "PH-S5",
  "PH-S7", "PH-X4", "PH-X5", "PH-X6", "PH-X7", "PH-X8",
]);

const NODE_CONTRACT_FIELDS = Object.freeze([
  "id",
  "kind",
  "title",
  "action",
  "phase",
  "intent",
  "anchors",
  "deliverables",
  "predecessors",
  "effect_surface",
  "engineering_gate",
  "hil_gate",
  "findings",
]);

const isProxy = utilTypes.isProxy.bind(utilTypes);
const objectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const objectGetOwnPropertyNames = Object.getOwnPropertyNames;
const objectGetOwnPropertySymbols = Object.getOwnPropertySymbols;
const objectGetPrototypeOf = Object.getPrototypeOf;
const objectHasOwn = Function.call.bind(Object.prototype.hasOwnProperty);
const objectPrototype = Object.prototype;

function assertDataObject(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value) || isProxy(value)) {
    throw new Error(`${label} must be a non-Proxy object`);
  }
  const prototype = objectGetPrototypeOf(value);
  if (prototype !== objectPrototype && prototype !== null) {
    throw new Error(`${label} must be a plain data object`);
  }
  if (objectGetOwnPropertySymbols(value).length !== 0) {
    throw new Error(`${label} cannot contain symbol fields`);
  }
  for (const field of objectGetOwnPropertyNames(value)) {
    const descriptor = objectGetOwnPropertyDescriptor(value, field);
    if (!descriptor || descriptor.get || descriptor.set || !descriptor.enumerable
        || !objectHasOwn(descriptor, "value")) {
      throw new Error(`${label}.${field} must be an enumerable data property`);
    }
  }
  return value;
}

function assertDenseArray(value, label) {
  if (!Array.isArray(value) || isProxy(value)) throw new Error(`${label} must be an array`);
  if (objectGetOwnPropertySymbols(value).length !== 0) {
    throw new Error(`${label} cannot contain symbol fields`);
  }
  const names = objectGetOwnPropertyNames(value);
  if (names.length !== value.length + 1 || names[names.length - 1] !== "length") {
    throw new Error(`${label} must be a dense data-only array`);
  }
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = objectGetOwnPropertyDescriptor(value, `${index}`);
    if (!descriptor || descriptor.get || descriptor.set || !descriptor.enumerable
        || !objectHasOwn(descriptor, "value")) {
      throw new Error(`${label}[${index}] must be an enumerable data property`);
    }
  }
  return value;
}

function compareStrings(left, right) {
  return left.localeCompare(right);
}

function canonicalStrings(value, label) {
  assertDenseArray(value, label);
  const result = [];
  for (let index = 0; index < value.length; index += 1) {
    if (typeof value[index] !== "string") throw new Error(`${label}[${index}] must be a string`);
    result.push(value[index]);
  }
  return result.sort(compareStrings);
}

function readRequired(object, field, label) {
  if (!objectHasOwn(object, field)) throw new Error(`${label} is missing ${field}`);
  return object[field];
}

function canonicalPlanePhysicalNodeContract(node, label = "plane_physical_node_contract") {
  assertDataObject(node, label);
  for (const field of NODE_CONTRACT_FIELDS) readRequired(node, field, label);
  for (const field of ["id", "kind", "title", "action", "phase", "intent", "engineering_gate"]) {
    if (typeof node[field] !== "string" || node[field].length === 0) {
      throw new Error(`${label}.${field} must be a non-empty string`);
    }
  }
  if (node.hil_gate !== null
      && (typeof node.hil_gate !== "string" || node.hil_gate.length === 0)) {
    throw new Error(`${label}.hil_gate must be null or a non-empty string`);
  }
  return Object.freeze({
    id: node.id,
    kind: node.kind,
    title: node.title,
    action: node.action,
    phase: node.phase,
    intent: node.intent,
    anchors: Object.freeze(canonicalStrings(node.anchors, `${label}.anchors`)),
    deliverables: Object.freeze(canonicalStrings(node.deliverables, `${label}.deliverables`)),
    predecessors: Object.freeze(canonicalStrings(node.predecessors, `${label}.predecessors`)),
    effect_surface: Object.freeze(canonicalStrings(node.effect_surface, `${label}.effect_surface`)),
    engineering_gate: node.engineering_gate,
    hil_gate: node.hil_gate,
    findings: Object.freeze(canonicalStrings(node.findings, `${label}.findings`)),
  });
}

function canonicalPlanePhysicalNodeContractRegistry(document) {
  assertDataObject(document, "plane_physical_nodes_document");
  const nodes = assertDenseArray(
    readRequired(document, "nodes", "plane_physical_nodes_document"),
    "plane_physical_nodes_document.nodes",
  );
  const canonicalNodes = nodes.map((node, index) => canonicalPlanePhysicalNodeContract(
    node,
    `plane_physical_nodes_document.nodes[${index}]`,
  )).sort((left, right) => compareStrings(left.id, right.id));
  return Object.freeze({
    version: readRequired(document, "version", "plane_physical_nodes_document"),
    production_nonwaivable_hil_node_ids: Object.freeze(canonicalStrings(
      readRequired(
        document,
        "production_nonwaivable_hil_node_ids",
        "plane_physical_nodes_document",
      ),
      "plane_physical_nodes_document.production_nonwaivable_hil_node_ids",
    )),
    nodes: Object.freeze(canonicalNodes),
  });
}

function canonicalPlanePhysicalHyperedgeRegistry(document) {
  assertDataObject(document, "plane_physical_hyperedges_document");
  const edges = assertDenseArray(
    readRequired(document, "hyperedges", "plane_physical_hyperedges_document"),
    "plane_physical_hyperedges_document.hyperedges",
  );
  const canonicalEdges = edges.map((edge, index) => {
    const label = `plane_physical_hyperedges_document.hyperedges[${index}]`;
    assertDataObject(edge, label);
    for (const field of ["id", "predecessors", "unlocks", "kind"]) {
      readRequired(edge, field, label);
    }
    if (typeof edge.id !== "string" || typeof edge.kind !== "string") {
      throw new Error(`${label}.id and kind must be strings`);
    }
    if (objectHasOwn(edge, "note") && typeof edge.note !== "string") {
      throw new Error(`${label}.note must be a string when present`);
    }
    return Object.freeze({
      id: edge.id,
      predecessors: Object.freeze(canonicalStrings(edge.predecessors, `${label}.predecessors`)),
      unlocks: Object.freeze(canonicalStrings(edge.unlocks, `${label}.unlocks`)),
      kind: edge.kind,
      note: edge.note,
    });
  }).sort((left, right) => compareStrings(left.id, right.id));
  return Object.freeze({
    version: readRequired(document, "version", "plane_physical_hyperedges_document"),
    note: readRequired(document, "note", "plane_physical_hyperedges_document"),
    hyperedges: Object.freeze(canonicalEdges),
  });
}

function digestJson(value) {
  return crypto.createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

function planePhysicalNodeContractDigest(node) {
  return digestJson(canonicalPlanePhysicalNodeContract(node));
}

function planePhysicalNodeContractRegistryDigest(document) {
  return digestJson(canonicalPlanePhysicalNodeContractRegistry(document));
}

function planePhysicalHyperedgeRegistryDigest(document) {
  return digestJson(canonicalPlanePhysicalHyperedgeRegistry(document));
}

module.exports = {
  PLANE_PHYSICAL_GRAPH_ID: GRAPH_ID,
  PLANE_PHYSICAL_PRODUCTION_NONWAIVABLE_HIL_NODE_IDS: PRODUCTION_NONWAIVABLE_HIL_NODE_IDS,
  PLANE_PHYSICAL_RELEASE_NODE_ID: RELEASE_NODE_ID,
  PLANE_PHYSICAL_REVIEWED_HYPEREDGE_REGISTRY_SHA256: REVIEWED_HYPEREDGE_REGISTRY_SHA256,
  PLANE_PHYSICAL_REVIEWED_NODE_CONTRACT_REGISTRY_SHA256:
    REVIEWED_NODE_CONTRACT_REGISTRY_SHA256,
  canonicalPlanePhysicalHyperedgeRegistry,
  canonicalPlanePhysicalNodeContract,
  canonicalPlanePhysicalNodeContractRegistry,
  planePhysicalHyperedgeRegistryDigest,
  planePhysicalNodeContractDigest,
  planePhysicalNodeContractRegistryDigest,
};
