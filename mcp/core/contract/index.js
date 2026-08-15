"use strict";

function defineLazyExports(load, names) {
  for (const name of names) {
    Object.defineProperty(module.exports, name, {
      enumerable: true,
      get() {
        return load()[name];
      },
    });
  }
}

const loadContracts = () => require("./contracts.js");
const loadContractVerifier = () => require("./contract-verifier.js");
const loadCellContract = () => require("./cell-contract.js");
const loadProducerContract = () => require("./producer-contract.js");

defineLazyExports(loadContracts, [
  "APPEND_CONTRACT_LEGAL_FROM_STATES",
  "ARTIFACT_REF_PREFIX_VALUES",
  "ARTIFACT_REF_RE",
  "INVARIANT_STATEMENT_MAX_CHARS",
  "JSONPATH_SELECTOR_RE",
  "PRODUCTION_PATH_DESCRIPTION_MAX_CHARS",
  "RELATIONAL_MATCH_OP_VALUES",
  "SEVERITY_FLOOR_VALUES",
  "WITNESS_KIND_VALUES",
  "appendContract",
  "artifactRefPrefix",
  "assertArtifactRef",
  "assertContractSatisfiable",
  "assertJsonPathSelector",
  "collectContractArtifactRefs",
  "normalizeContract",
]);

defineLazyExports(loadContractVerifier, [
  "EVALUATORS",
  "extractByJsonPath",
  "mechanicalVerify",
  "resolveArtifactBodyInternal",
]);

defineLazyExports(loadCellContract, [
  "CELL_COVERAGE_EVIDENCE_KIND",
  "CELL_PROBE_TOOL",
  "CELL_ATTEMPT_KIND_VALUES",
  "CELL_COVERING_ATTEMPT_KINDS",
  "isCellCoveringAttempt",
  "buildCellCoverageContract",
]);

defineLazyExports(loadProducerContract, [
  "PRODUCER_OUTPUT_WITNESS_KIND",
  "PRODUCER_OUTPUT_FRONTIER_KIND",
  "SATISFIED_BY",
  "buildProducerOutputContract",
  "buildWitness",
  "inputConsumedSatisfied",
  "producerRunOutputSatisfied",
  "resolveProducer",
  "surfaceObservedSatisfied",
]);
