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

const loadSensitiveMaterial = () => require("./sensitive-material.js");
const loadReportCredentialFence = () => require("./report-credential-fence.js");

defineLazyExports(loadSensitiveMaterial, [
  "DEFAULT_MAX_TEXT_CHARS",
  "LABELED_PHYSICAL_VALUE_PATTERNS",
  "PHYSICAL_SENSITIVE_FIELD_RE",
  "SENSITIVE_KEY_RE",
  "SENSITIVE_VALUE_RE",
  "assertPackageSafePhysicalDesignDocument",
  "budgetPhysicalPublicOutput",
  "redactPhysicalSensitiveValues",
  "redactPhysicalStructuredOutput",
  "redactTextSensitiveValues",
  "validateNoPhysicalSensitiveMaterial",
  "validateNoSensitiveMaterial",
]);

defineLazyExports(loadReportCredentialFence, [
  "COMMON_REPORT_WORDS",
  "MIN_FENCED_CREDENTIAL_LENGTH",
  "MIN_FENCED_DISTINCT_CHARS",
  "buildReportCredentialFence",
  "findCredentialExportLeaks",
  "isFenceableCredentialValue",
]);

Object.defineProperties(module.exports, {
  scan: {
    enumerable: true,
    get() {
      return loadSensitiveMaterial().validateNoSensitiveMaterial;
    },
  },
  redact: {
    enumerable: true,
    get() {
      return loadSensitiveMaterial().redactTextSensitiveValues;
    },
  },
});

module.exports.fenceReportExport = function fenceReportExport(targetDomain, regions, materialProvider) {
  const fence = loadReportCredentialFence().buildReportCredentialFence(targetDomain, materialProvider);
  return loadReportCredentialFence().findCredentialExportLeaks(fence, regions);
};
