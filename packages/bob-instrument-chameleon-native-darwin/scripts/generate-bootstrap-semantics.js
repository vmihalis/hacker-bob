#!/usr/bin/env node
"use strict";

// Generate the native PH-P7 admission table from the transport-neutral
// Chameleon bootstrap registry. This script is the only authoring surface for
// the generated JavaScript projection and C++ header; neither generated file
// is a second command registry.

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "..");
const CHAMELEON_ROOT = path.resolve(ROOT, "..", "bob-instrument-chameleon");
const BOOTSTRAP_SOURCE = path.join(CHAMELEON_ROOT, "lib", "bootstrap-operations.js");
const OPERATIONS_SOURCE = path.join(CHAMELEON_ROOT, "lib", "operations.js");
const JS_OUTPUT = path.join(ROOT, "lib", "generated-bootstrap-semantics.js");
const HEADER_OUTPUT = path.join(ROOT, "native", "generated_bootstrap_semantics.h");
const CHECK_ONLY = process.argv.includes("--check");

const {
  BOOTSTRAP_INVARIANTS_DIGEST,
  CHAMELEON_BOOTSTRAP_MANIFEST,
  CHAMELEON_BOOTSTRAP_OPERATION_REGISTRY,
} = require(BOOTSTRAP_SOURCE);
const {
  CHAMELEON_SEMANTIC_MANIFEST,
  CHAMELEON_V220_SOURCE_PROFILE,
} = require(OPERATIONS_SOURCE);
const {
  hashCanonicalJson,
} = require(path.resolve(ROOT, "..", "bob-instrument-contracts", "lib",
  "verification-contracts.js"));

// These are review pins for the canonical source artifacts, not a duplicate
// operation or command table. The generated rows below are read exclusively
// from CHAMELEON_BOOTSTRAP_MANIFEST after the complete artifact identities are
// proven.
const REVIEWED_BOOTSTRAP_MANIFEST_DIGEST =
  "0ad9202fb20734fdec58d16ee5eea10cb0549f35b0fedca57d8285aafa967623";
const REVIEWED_SEMANTIC_MANIFEST_DIGEST =
  "3a270fa758a365e9cb4d5fa1db9c5c2f051e4b2df9aa6dd75856826050f09c29";
const REVIEWED_BOOTSTRAP_OPERATION_REGISTRY_DIGEST =
  "7ebe8f68f1529fee5b925b393aadeb0f05b4301d5773c9e0c0e6ccac98c9b0b6";

function sha256File(filename) {
  return crypto.createHash("sha256").update(fs.readFileSync(filename)).digest("hex");
}

function sameArray(left, right) {
  return left.length === right.length
    && left.every((value, index) => value === right[index]);
}

function assertSourceRegistry() {
  const operationIds = CHAMELEON_BOOTSTRAP_OPERATION_REGISTRY.ids();
  const manifestOperationIds = CHAMELEON_BOOTSTRAP_MANIFEST.operations
    .map((operation) => operation.operation_id).sort();
  if (!sameArray(operationIds, manifestOperationIds)
      || operationIds.length !== 3
      || CHAMELEON_BOOTSTRAP_MANIFEST.provider_id !== "chameleon_ultra"
      || CHAMELEON_BOOTSTRAP_MANIFEST.version !== 1
      || CHAMELEON_BOOTSTRAP_MANIFEST.manifest_digest
        !== REVIEWED_BOOTSTRAP_MANIFEST_DIGEST
      || CHAMELEON_BOOTSTRAP_MANIFEST.operation_registry_digest
        !== CHAMELEON_BOOTSTRAP_OPERATION_REGISTRY.registry_digest
      || CHAMELEON_BOOTSTRAP_OPERATION_REGISTRY.registry_digest
        !== REVIEWED_BOOTSTRAP_OPERATION_REGISTRY_DIGEST
      || CHAMELEON_SEMANTIC_MANIFEST.provider_id !== "chameleon_ultra"
      || CHAMELEON_SEMANTIC_MANIFEST.manifest_digest
        !== REVIEWED_SEMANTIC_MANIFEST_DIGEST) {
    throw new Error("Chameleon native bootstrap generator source registry drifted");
  }
  for (const operationId of operationIds) {
    const manifestOperation = CHAMELEON_BOOTSTRAP_MANIFEST.operations.find(
      (entry) => entry.operation_id === operationId,
    );
    const registryOperation = CHAMELEON_BOOTSTRAP_OPERATION_REGISTRY.get(operationId);
    if (!manifestOperation || !registryOperation
        || manifestOperation.operation_digest !== registryOperation.operation_digest
        || !Array.isArray(manifestOperation.command_ids)
        || manifestOperation.command_ids.length < 1
        || manifestOperation.command_ids.length > 3
        || manifestOperation.invariants.request_payload_bytes !== 0
        || manifestOperation.invariants.rf_state !== "off"
        || manifestOperation.invariants.mode_change !== "forbidden"
        || manifestOperation.invariants.slot_access !== "forbidden"
        || manifestOperation.invariants.workspace_write !== "forbidden"
        || manifestOperation.effect.subject_kind !== "instrument"
        || manifestOperation.effect.action !== "observe"
        || manifestOperation.effect.channel !== "usb"
        || manifestOperation.effect.persistence !== "none") {
      throw new Error(`Chameleon native bootstrap generator operation drift: ${operationId}`);
    }
  }
}

function buildTable() {
  assertSourceRegistry();
  const operations = CHAMELEON_BOOTSTRAP_OPERATION_REGISTRY.ids().map((operationId) => {
    const operation = CHAMELEON_BOOTSTRAP_MANIFEST.operations.find(
      (entry) => entry.operation_id === operationId,
    );
    return Object.freeze({
      operation_id: operation.operation_id,
      operation_digest: operation.operation_digest,
      command_set_digest: operation.command_set_digest,
      commands: Object.freeze(operation.command_ids.map((commandId, index) => Object.freeze({
        command_sequence: index + 1,
        command_id: commandId,
        request_payload_byte_length: 0,
        request_frame_byte_length: 10,
      }))),
    });
  });
  const basis = Object.freeze({
    version: 1,
    table_kind: "chameleon_native_bootstrap_semantics",
    provider_id: "chameleon_ultra",
    semantic_manifest_digest: CHAMELEON_SEMANTIC_MANIFEST.manifest_digest,
    bootstrap_manifest_digest: CHAMELEON_BOOTSTRAP_MANIFEST.manifest_digest,
    bootstrap_operation_registry_digest:
      CHAMELEON_BOOTSTRAP_OPERATION_REGISTRY.registry_digest,
    bootstrap_invariants_digest: BOOTSTRAP_INVARIANTS_DIGEST,
    source_profile_digest: CHAMELEON_V220_SOURCE_PROFILE.source_profile_digest,
    upstream_declaration_source_sha256:
      CHAMELEON_V220_SOURCE_PROFILE.declaration_source_sha256,
    upstream_registry_source_sha256:
      CHAMELEON_V220_SOURCE_PROFILE.registry_source_sha256,
    local_bootstrap_source_sha256: sha256File(BOOTSTRAP_SOURCE),
    local_operations_source_sha256: sha256File(OPERATIONS_SOURCE),
    operations: Object.freeze(operations),
  });
  return Object.freeze({
    ...basis,
    table_digest: hashCanonicalJson(basis),
  });
}

function jsSource(table) {
  return `"use strict";\n\n`
    + `// GENERATED by scripts/generate-bootstrap-semantics.js. DO NOT EDIT.\n`
    + `// This is a source-pinned projection, not an independent command registry.\n\n`
    + `function deepFreeze(value) {\n`
    + `  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;\n`
    + `  for (const child of Object.values(value)) deepFreeze(child);\n`
    + `  return Object.freeze(value);\n`
    + `}\n\n`
    + `const CHAMELEON_NATIVE_BOOTSTRAP_SEMANTICS = deepFreeze(${JSON.stringify(table, null, 2)});\n\n`
    + `module.exports = Object.freeze({ CHAMELEON_NATIVE_BOOTSTRAP_SEMANTICS });\n`;
}

function byteInitializer(digest) {
  const values = [];
  for (let offset = 0; offset < digest.length; offset += 2) {
    values.push(`0x${digest.slice(offset, offset + 2)}`);
  }
  return `{${values.join(", ")}}`;
}

function cString(value) {
  return JSON.stringify(value);
}

function headerSource(table) {
  const operationRows = table.operations.map((operation) => {
    const commandIds = operation.commands.map((command) => command.command_id);
    const sequences = operation.commands.map((command) => command.command_sequence);
    while (commandIds.length < 3) commandIds.push(0);
    while (sequences.length < 3) sequences.push(0);
    return `    {${cString(operation.operation_id)}, ${operation.operation_id.length}U,\n`
      + `     ${byteInitializer(operation.operation_digest)},\n`
      + `     ${byteInitializer(operation.command_set_digest)},\n`
      + `     {${commandIds.map((value) => `${value}U`).join(", ")}},\n`
      + `     {${sequences.map((value) => `${value}ULL`).join(", ")}},\n`
      + `     ${operation.commands.length}U}`;
  }).join(",\n");
  return `// GENERATED by scripts/generate-bootstrap-semantics.js. DO NOT EDIT.\n`
    + `// Source-pinned PH-P7 semantics; this is not an independent command registry.\n`
    + `#ifndef HACKER_BOB_CHAMELEON_GENERATED_BOOTSTRAP_SEMANTICS_H_\n`
    + `#define HACKER_BOB_CHAMELEON_GENERATED_BOOTSTRAP_SEMANTICS_H_\n\n`
    + `#include <array>\n`
    + `#include <cstddef>\n`
    + `#include <cstdint>\n\n`
    + `namespace hacker_bob_chameleon_bootstrap {\n\n`
    + `struct OperationSemantic {\n`
    + `  const char* operation_id;\n`
    + `  size_t operation_id_length;\n`
    + `  std::array<unsigned char, 32> operation_digest;\n`
    + `  std::array<unsigned char, 32> command_set_digest;\n`
    + `  std::array<uint16_t, 3> command_ids;\n`
    + `  std::array<uint64_t, 3> command_sequences;\n`
    + `  size_t command_count;\n`
    + `};\n\n`
    + `inline constexpr char kProviderId[] = ${cString(table.provider_id)};\n`
    + `inline constexpr std::array<unsigned char, 32> kSemanticManifestDigest =\n`
    + `    ${byteInitializer(table.semantic_manifest_digest)};\n`
    + `inline constexpr std::array<unsigned char, 32> kBootstrapManifestDigest =\n`
    + `    ${byteInitializer(table.bootstrap_manifest_digest)};\n`
    + `inline constexpr std::array<unsigned char, 32> kBootstrapOperationRegistryDigest =\n`
    + `    ${byteInitializer(table.bootstrap_operation_registry_digest)};\n`
    + `inline constexpr std::array<unsigned char, 32> kBootstrapInvariantsDigest =\n`
    + `    ${byteInitializer(table.bootstrap_invariants_digest)};\n`
    + `inline constexpr std::array<unsigned char, 32> kNativeSemanticTableDigest =\n`
    + `    ${byteInitializer(table.table_digest)};\n`
    + `inline constexpr char kLocalBootstrapSourceSha256[] =\n`
    + `    ${cString(table.local_bootstrap_source_sha256)};\n`
    + `inline constexpr char kLocalOperationsSourceSha256[] =\n`
    + `    ${cString(table.local_operations_source_sha256)};\n`
    + `inline constexpr std::array<OperationSemantic, ${table.operations.length}> kOperations = {{\n`
    + `${operationRows}\n`
    + `}};\n\n`
    + `}  // namespace hacker_bob_chameleon_bootstrap\n\n`
    + `#endif  // HACKER_BOB_CHAMELEON_GENERATED_BOOTSTRAP_SEMANTICS_H_\n`;
}

function publish(filename, content) {
  if (CHECK_ONLY) {
    let existing;
    try {
      existing = fs.readFileSync(filename, "utf8");
    } catch {
      throw new Error(`generated Chameleon native semantics missing: ${path.relative(ROOT, filename)}`);
    }
    if (existing !== content) {
      throw new Error(`generated Chameleon native semantics drift: ${path.relative(ROOT, filename)}`);
    }
    return;
  }
  fs.writeFileSync(filename, content, { encoding: "utf8", mode: 0o644 });
}

const table = buildTable();
publish(JS_OUTPUT, jsSource(table));
publish(HEADER_OUTPUT, headerSource(table));
