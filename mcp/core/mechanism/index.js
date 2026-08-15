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

const loadCandidateStore = () => require("./mechanism-candidate-store.js");
const loadTemplateIngest = () => require("./mechanism-template-ingest.js");
const loadInvariantTemplateCorpus = () => require("./invariant-template-corpus.js");

defineLazyExports(loadCandidateStore, [
  "CANDIDATE_TIER",
  "buildRegistryRecord",
  "registerMechanismCandidates",
  "readMechanismCandidates",
]);

defineLazyExports(loadTemplateIngest, [
  "CANDIDATE_SOURCE_TIERS",
  "normalizeCweEntry",
  "normalizeAuditFinding",
  "normalizeSchemaContract",
  "normalizeKnowledgeRecord",
  "normalizeKnowledgeBatch",
  "candidateDedupKey",
  "buildAdvisoryEvidence",
]);

defineLazyExports(loadInvariantTemplateCorpus, [
  "MECHANISM_TEMPLATES",
  "OBJECT_AUTHORIZATION_MECHANISM_TEMPLATE",
  "TEMPLATES",
  "SUPPORTED_CLASSES",
  "CORPUS_TEMPLATE_TIER",
  "CROSS_STACK_CONSUME_TEMPLATE_ID",
  "SLOT_VALUE_GRAMMAR",
  "validateSlotValues",
  "getTemplatesForClass",
  "getMechanismTemplate",
  "getMechanismTemplatesForDomain",
  "loadMechanismTemplates",
  "normalizeMechanismTemplate",
  "suggestInvariantsForFinding",
  "suggestInvariantsForReport",
]);
