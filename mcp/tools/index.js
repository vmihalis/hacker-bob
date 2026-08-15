"use strict";

const discoveryTools = require("./manifests/discovery.js");
const sessionWaveTools = require("./manifests/session-waves.js");
const reportingCapabilityTools = require("./manifests/reporting-capabilities.js");
const taskGraphTools = require("./manifests/task-graph.js");

const TOOL_MODULES = Object.freeze([
  ...discoveryTools.slice(0, 30),
  require("./physical/record-physical-candidate-claim.js"),
  ...discoveryTools.slice(30),
  ...require("./manifests/chain.js"),
  ...require("./manifests/verification.js"),
  ...sessionWaveTools.slice(0, 2),
  require("./blockchain/init-contract-session.js"),
  require("./physical/init-physical-session.js"),
  require("./physical/query-instrument-capabilities.js"),
  ...sessionWaveTools.slice(2),
  ...reportingCapabilityTools.slice(0, 17),
  require("./blockchain/suggest-invariants.js"),
  require("./blockchain/run-invariant-for-finding.js"),
  require("./blockchain/read-invariant-runs.js"),
  ...reportingCapabilityTools.slice(17),
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
  ...require("./manifests/frontier-belief.js"),
  ...taskGraphTools.slice(0, 10),
  require("./blockchain/verify-invariant-differential.js"),
  ...taskGraphTools.slice(10, 11),
  require("./physical/verify-physical-verdict.js"),
  require("./physical/verify-physical-candidate-claim.js"),
  require("./physical/physical-observe.js"),
  require("./physical/credential-acquire.js"),
  require("./physical/credential-recover.js"),
  require("./physical/credential-emulate.js"),
  require("./physical/credential-write.js"),
  require("./physical/protocol-transceive.js"),
  require("./physical/rf-trace.js"),
  ...taskGraphTools.slice(11),
  ...require("./manifests/friction.js"),
]);

module.exports = {
  TOOL_MODULES,
};
