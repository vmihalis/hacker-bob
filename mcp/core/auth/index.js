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

const loadAuth = () => require("./auth.js");
const loadPlaceholders = () => require("./auth-placeholders.js");

defineLazyExports(loadAuth, [
  "applyAuthProfileHeaders",
  "authStore",
  "buildHeaderProfile",
  "candidateAuthDomains",
  "credentialFieldNames",
  "CREDENTIAL_MATERIAL_SOURCES",
  "hasUsableAuthProfile",
  "listAuthProfiles",
  "migrateAuthJson",
  "PROFILE_METADATA_KEYS",
  "readAuthJson",
  "resolveAuthJsonPath",
  "resolveAuthProfile",
  "resolveProfileCredentialValue",
  "sessionCredentialMaterial",
  "writeAuthFile",
]);

defineLazyExports(loadPlaceholders, [
  "CREDENTIAL_PLACEHOLDER_SOURCE",
  "CredentialPlaceholderError",
  "DECISION_REJECTED",
  "DECISION_UNRESOLVED",
  "IDENTITY_REDACTOR",
  "containsAnyPlaceholder",
  "containsLoosePlaceholder",
  "containsStrictPlaceholder",
  "isCredentialPlaceholderError",
  "makeCredentialRedactor",
  "placeholderLabel",
  "prepareRequestBody",
  "redactionMarker",
]);

Object.defineProperties(module.exports, {
  resolvePlaceholder: {
    enumerable: true,
    get() {
      return loadAuth().resolveProfileCredentialValue;
    },
  },
  profileFor: {
    enumerable: true,
    get() {
      return loadAuth().resolveAuthProfile;
    },
  },
});
