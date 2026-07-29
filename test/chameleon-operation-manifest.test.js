"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");

require("../packages/bob-instrument-chameleon/test/operations.test.js");

const coverage = require("../docs/plane-physical/coverage.json");
const {
  HF14A_PROBE_COMPILER_MANIFEST,
} = require("../packages/bob-instrument-chameleon/lib/hf14a-probe-compiler.js");
const {
  canonicalCommandSourceEntryBasis,
  canonicalCommandSourceRegistry,
  validateChameleonRuntimeManifest,
  validateCommandSourceRegistry,
  validateHf14aClosedProbeContract,
  validateUpstreamCommandRegistry,
} = require("../scripts/check-plane-physical.js");

function hashJson(value) {
  return crypto.createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

function commandOwners(document) {
  const owners = new Map();
  for (const row of document.coverage) {
    for (const commandId of row.upstream_command_ids) {
      if (!owners.has(commandId)) owners.set(commandId, []);
      owners.get(commandId).push({
        capabilityId: row.provider_capability_id,
        disposition: row.disposition,
      });
    }
  }
  return owners;
}

function sourceErrors(document) {
  const errors = [];
  const upstream = validateUpstreamCommandRegistry(document, errors);
  validateCommandSourceRegistry(document, upstream, commandOwners(document), errors);
  return errors;
}

function makeSelfConsistentSourceMutation(mutate) {
  const document = JSON.parse(JSON.stringify(coverage));
  mutate(document.command_source_registry);
  for (const entry of document.command_source_registry) {
    entry.entry_digest = hashJson(canonicalCommandSourceEntryBasis(entry));
  }
  document.command_source_registry_sha256 = hashJson(
    canonicalCommandSourceRegistry(document.command_source_registry),
  );
  return document;
}

function hf14aErrors(document, manifest = HF14A_PROBE_COMPILER_MANIFEST) {
  const errors = [];
  validateHf14aClosedProbeContract(document, manifest, errors);
  return errors;
}

test("Plane-PH checker links the runtime manifest to reviewed documentation", () => {
  const currentErrors = [];
  validateChameleonRuntimeManifest(coverage, currentErrors);
  assert.deepEqual(currentErrors, []);

  const drifted = JSON.parse(JSON.stringify(coverage));
  drifted.coverage[0].effect_profile_refs = [];
  const driftErrors = [];
  validateChameleonRuntimeManifest(drifted, driftErrors);
  assert.equal(
    driftErrors.some((error) => /coverage semantics drifted/u.test(error)),
    true,
  );
});

test("source metadata mutations fail on symbols, hooks, owners, and nullability", () => {
  const commitDrift = JSON.parse(JSON.stringify(coverage));
  commitDrift.upstream_command_registry.source_commit = "0".repeat(40);
  assert.equal(sourceErrors(commitDrift).some(
    (error) => /source_commit: pinned value drifted from the reviewed v2\.2\.0 source/u.test(error),
  ), true);

  const declarationDrift = makeSelfConsistentSourceMutation((registry) => {
    registry.find((entry) => entry.command_id === 1000).declaration_symbol =
      "DATA_CMD_FORGED_VERSION";
  });
  assert.equal(sourceErrors(declarationDrift).some(
    (error) => /metadata drifted from reviewed v2\.2\.0 sources/u.test(error),
  ), true);

  const hookDrift = makeSelfConsistentSourceMutation((registry) => {
    registry.find((entry) => entry.command_id === 2000).hook_symbols = [
      "after_hf_reader_run",
      "before_forged_reader_run",
      "before_hf_reader_run",
    ];
  });
  assert.equal(sourceErrors(hookDrift).some(
    (error) => /metadata drifted from reviewed v2\.2\.0 sources/u.test(error),
  ), true);

  const ownerDrift = makeSelfConsistentSourceMutation((registry) => {
    registry.find((entry) => entry.command_id === 1000).provider_capability_id =
      "CU-CORE-FRAME-CODEC";
  });
  assert.equal(sourceErrors(ownerDrift).some(
    (error) => /provider_capability_id: drifted from the unique command owner/u.test(error),
  ), true);

  const privateNullabilityDrift = makeSelfConsistentSourceMutation((registry) => {
    registry.find((entry) => entry.command_id === 6010).declaration_symbol =
      "DATA_CMD_FORGED_PRIVATE";
  });
  assert.equal(sourceErrors(privateNullabilityDrift).some(
    (error) => /registry-private command must be null/u.test(error),
  ), true);

  const unregisteredNullabilityDrift = makeSelfConsistentSourceMutation((registry) => {
    registry.find((entry) => entry.command_id === 3007).runtime_handler_symbol =
      "cmd_processor_forged_unregistered";
  });
  assert.equal(sourceErrors(unregisteredNullabilityDrift).some(
    (error) => /declared-unregistered command must be null/u.test(error),
  ), true);
});

test("HF14A guard rejects assurance leakage, proof substitution, and schema drift", () => {
  assert.deepEqual(hf14aErrors(coverage), []);

  const assuranceLeak = JSON.parse(JSON.stringify(coverage));
  assuranceLeak.normalized_operation_registry["protocol.compiled_exchange"]
    .minimum_assurance_profile_id = "enrolled_conformance_tested";
  assert.equal(hf14aErrors(assuranceLeak).some(
    (error) => /must bind only protocol\.discovery_probe|must not widen/u.test(error),
  ), true);

  const proofSubstitution = JSON.parse(JSON.stringify(coverage));
  proofSubstitution.capability_dependency_registry["CU-HF-14A-COMPILED-PROBE"]
    .all_of[2] = "conformance:chameleon_frame_codec_v1";
  assert.equal(hf14aErrors(proofSubstitution).some(
    (error) => /exact raw, compiler, and distinct HIL-conformance dependencies/u.test(error),
  ), true);

  const proofLeak = JSON.parse(JSON.stringify(coverage));
  proofLeak.capability_dependency_registry["CU-CORE-FRAME-CODEC"].all_of.push(
    "conformance:chameleon_hf14a_closed_probe_v1",
  );
  assert.equal(hf14aErrors(proofLeak).some(
    (error) => /HIL proof must not satisfy or gate any other capability/u.test(error),
  ), true);

  const widenedEffect = JSON.parse(JSON.stringify(coverage));
  widenedEffect.capability_dependency_registry["CU-HF-14A-COMPILED-PROBE"]
    .variants.wupa_atqa_v1.effect_profile_refs.push("EP-TARGET-MUTATE-RF-STATEFUL");
  assert.equal(hf14aErrors(widenedEffect).some(
    (error) => /wupa_atqa_v1 must map bijectively/u.test(error),
  ), true);

  const thirdVariant = JSON.parse(JSON.stringify(coverage));
  thirdVariant.capability_dependency_registry["CU-HF-14A-COMPILED-PROBE"]
    .variants.rats_v1 = JSON.parse(JSON.stringify(
      thirdVariant.capability_dependency_registry["CU-HF-14A-COMPILED-PROBE"]
        .variants.requa_atqa_v1,
    ));
  thirdVariant.capability_dependency_registry["CU-HF-14A-COMPILED-PROBE"]
    .variants.rats_v1.parameter_selector_id = "rats_v1";
  assert.equal(hf14aErrors(thirdVariant).some(
    (error) => /exactly the REQA and WUPA variants/u.test(error),
  ), true);

  const codecWidening = JSON.parse(JSON.stringify(coverage));
  codecWidening.codec_profile = { command_ids: [2010] };
  assert.equal(hf14aErrors(codecWidening).some(
    (error) => /command 2010 must remain absent/u.test(error),
  ), true);

  const manifestDrift = JSON.parse(JSON.stringify(HF14A_PROBE_COMPILER_MANIFEST));
  manifestDrift.schema_variant_bindings[0].variant_id = "default";
  assert.equal(hf14aErrors(coverage, manifestDrift).some(
    (error) => /compiler schemas and availability variants.*exact.*bijection/u.test(error),
  ), true);
});
