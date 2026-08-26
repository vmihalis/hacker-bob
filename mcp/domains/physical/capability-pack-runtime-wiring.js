"use strict";

const {
  assertPhysicalFinding,
} = require("./physical-finding-contract.js");
const {
  PHYSICAL_CAPABILITY_CONSUMERS,
} = require("./physical-capability-manifest.js");
const {
  PHYSICAL_SURFACE_NODE_TYPES,
} = require("./physical-surface-transition.js");
const {
  assertProductionPhysicalExperimentLedger,
  assertVerifiedPhysicalClaimProjection,
  describeProductionPhysicalExperimentLedger,
} = require("./physical-experiment-contract.js");
const {
  buildPhysicalCapabilityPackEvidencePack,
  buildPhysicalCapabilityPackGradeBinding,
  resolvePhysicalCapabilityPackArtifacts,
} = require("./capability-pack-physical-artifacts.js");
const {
  configureCapabilityPackCompositionPorts,
} = require("../../core/capability/capability-pack-composition-adapters.js");
const {
  configurePhysicalCapabilityPackRuntimePorts,
} = require("./capability-pack-runtime-ports.js");

configureCapabilityPackCompositionPorts({
  assertPhysicalFinding,
  physicalCapabilityConsumers: PHYSICAL_CAPABILITY_CONSUMERS,
  physicalSurfaceNodeTypes: PHYSICAL_SURFACE_NODE_TYPES,
  assertProductionPhysicalExperimentLedger,
  assertVerifiedPhysicalClaimProjection,
  describeProductionPhysicalExperimentLedger,
});

configurePhysicalCapabilityPackRuntimePorts({
  artifacts: resolvePhysicalCapabilityPackArtifacts,
  grade: buildPhysicalCapabilityPackGradeBinding,
  evidence: buildPhysicalCapabilityPackEvidencePack,
});

module.exports = Object.freeze({ configured: true });
