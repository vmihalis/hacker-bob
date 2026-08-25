"use strict";

const {
  discoveryBeforePhysicalClaimTools,
  discoveryAfterPhysicalClaimTools,
} = require("./manifests/discovery.js");
const {
  sessionInitializerTools,
  sessionAfterSpecializedSessionTools,
} = require("./manifests/session-waves.js");
const {
  reportingBeforeBlockchainInvariantTools,
  surfaceAnalysisTools,
} = require("./manifests/reporting-capabilities.js");
const {
  taskReproVerificationTools,
  findingVerificationTools,
  taskGraphExecutionTools,
  browserSessionExecutionTools,
  packTelemetryTools,
} = require("./manifests/task-graph.js");

const physicalClaimTools = Object.freeze([
  require("./physical/record-physical-candidate-claim.js"),
]);

const specializedSessionTools = Object.freeze([
  require("./blockchain/init-contract-session.js"),
  require("./physical/init-physical-session.js"),
  require("./physical/query-instrument-capabilities.js"),
]);

const blockchainInvariantReportingTools = Object.freeze([
  require("./blockchain/suggest-invariants.js"),
  require("./blockchain/run-invariant-for-finding.js"),
  require("./blockchain/read-invariant-runs.js"),
]);

const blockchainRuntimeTools = Object.freeze([
  require("./blockchain/evm-call.js"),
  require("./blockchain/evm-storage-read.js"),
  require("./blockchain/evm-fetch-source.js"),
  require("./blockchain/evm-role-table.js"),
  require("./blockchain/foundry-run.js"),
  require("./blockchain/halmos-run.js"),
  require("./blockchain/svm-fetch-account.js"),
  require("./blockchain/svm-fetch-program.js"),
  require("./blockchain/anchor-run.js"),
  require("./blockchain/aptos-fetch-resource.js"),
  require("./blockchain/aptos-fetch-module.js"),
  require("./blockchain/aptos-run.js"),
  require("./blockchain/sui-fetch-object.js"),
  require("./blockchain/sui-fetch-package.js"),
  require("./blockchain/sui-run.js"),
  require("./blockchain/substrate-run.js"),
  require("./blockchain/substrate-fetch-storage.js"),
  require("./blockchain/substrate-fetch-runtime.js"),
  require("./blockchain/cosmwasm-run.js"),
  require("./blockchain/cosmwasm-fetch-contract.js"),
  require("./blockchain/cosmwasm-smart-query.js"),
]);

const blockchainVerificationTools = Object.freeze([
  require("./blockchain/verify-invariant-differential.js"),
]);

const physicalVerificationInstrumentTools = Object.freeze([
  require("./physical/verify-physical-verdict.js"),
  require("./physical/verify-physical-candidate-claim.js"),
  require("./physical/physical-observe.js"),
  require("./physical/credential-acquire.js"),
  require("./physical/credential-recover.js"),
  require("./physical/credential-emulate.js"),
  require("./physical/credential-write.js"),
  require("./physical/protocol-transceive.js"),
  require("./physical/rf-trace.js"),
]);

const TOOL_MODULES = Object.freeze([
  ...discoveryBeforePhysicalClaimTools,
  ...physicalClaimTools,
  ...discoveryAfterPhysicalClaimTools,
  ...require("./manifests/chain.js"),
  ...require("./manifests/verification.js"),
  ...sessionInitializerTools,
  ...specializedSessionTools,
  ...sessionAfterSpecializedSessionTools,
  ...reportingBeforeBlockchainInvariantTools,
  ...blockchainInvariantReportingTools,
  ...surfaceAnalysisTools,
  ...blockchainRuntimeTools,
  ...require("./manifests/frontier-belief.js"),
  ...taskReproVerificationTools,
  ...blockchainVerificationTools,
  ...findingVerificationTools,
  ...physicalVerificationInstrumentTools,
  ...taskGraphExecutionTools,
  ...browserSessionExecutionTools,
  ...packTelemetryTools,
  ...require("./manifests/friction.js"),
]);

module.exports = {
  TOOL_MODULES,
};
