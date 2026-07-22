"use strict";

const {
  ARTIFACT_DATA_CLASSES,
  ARTIFACT_VAULT_SCHEMA_VERSION,
  PUBLIC_ARTIFACT_HANDLE_RE,
  PUBLIC_RESERVATION_HANDLE_RE,
  normalizeArtifactMetadata,
  normalizeReservationRequest,
} = require("./lib/contracts.js");
const { createArtifactVault } = require("./lib/vault.js");

module.exports = {
  ARTIFACT_DATA_CLASSES,
  ARTIFACT_VAULT_SCHEMA_VERSION,
  PUBLIC_ARTIFACT_HANDLE_RE,
  PUBLIC_RESERVATION_HANDLE_RE,
  createArtifactVault,
  normalizeArtifactMetadata,
  normalizeReservationRequest,
};
