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
  normalizePhysicalFindingRecord,
} = require("./physical-finding-record-adapter.js");
const {
  physicalCampaignClosureReadiness,
} = require("./physical-campaign-coordinator.js");
const {
  configureCapabilityPackCompositionPorts,
} = require("../../core/capability/capability-pack-composition-adapters.js");
const {
  configurePhysicalDomainRuntimePorts,
} = require("../../core/physical-domain-runtime-ports.js");
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

configurePhysicalDomainRuntimePorts({
  assertVerifiedPhysicalClaimProjection,
  normalizePhysicalFindingRecord,
  physicalCampaignClosureReadiness,
});

configurePhysicalCapabilityPackRuntimePorts({
  artifacts: resolvePhysicalCapabilityPackArtifacts,
  grade: buildPhysicalCapabilityPackGradeBinding,
  evidence: buildPhysicalCapabilityPackEvidencePack,
});

module.exports = Object.freeze({ configured: true });
