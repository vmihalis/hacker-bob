"use strict";

const {
  normalizeLifecycleCustodianMutation,
} = require("./lifecycle-custodian-contract.js");

const EXEC_IMAGE_BINDING_BLOCKER = "openat_to_exec_or_mapped_image_binding_missing";

function lifecycleCustodianStatus() {
  return Object.freeze({
    version: 1,
    kind: "descriptor_relative_lifecycle_custodian",
    available: false,
    qualified: false,
    production_ready: false,
    mutation_authorized: false,
    helper_resolution_policy: "fixed_enrolled_signed_prebuild_only",
    target_authority: "single_retained_root_fd",
    source_authority: "single_retained_prepared_source_fd",
    native_dispatch: "fixed_inherited_descriptors_only",
    blocker: EXEC_IMAGE_BINDING_BLOCKER,
  });
}

function unavailableError() {
  const error = new Error("Qualified lifecycle custodian is unavailable");
  error.code = "lifecycle_custodian_unavailable";
  error.reason_code = EXEC_IMAGE_BINDING_BLOCKER;
  error.status = lifecycleCustodianStatus();
  return error;
}

function assertLifecycleCustodianAvailable() {
  // Production admission remains deliberately closed until a signed platform
  // loader binds the retained, hash-qualified helper to the image actually
  // exec'd or mapped. A pathname pre/post check cannot establish that fact.
  throw unavailableError();
}

function withLifecycleCustodianTarget(targetAbs, callback) {
  if (typeof targetAbs !== "string" || targetAbs.length === 0 || typeof callback !== "function") {
    const error = new TypeError("Lifecycle custodian target authority input is invalid");
    error.code = "lifecycle_custodian_target_invalid";
    throw error;
  }
  // Helper qualification precedes every target probe. Production admission is
  // intentionally closed, so this never opens the pathname or invokes the
  // callback until the signed loader can retain and bind the real root fd.
  return assertLifecycleCustodianAvailable();
}

function lifecycleCustodianTargetSnapshot(_authority) {
  return assertLifecycleCustodianAvailable();
}

function executeLifecycleMutation(_authority, input) {
  // Validate the closed registry surface without creating, pruning, opening,
  // or journaling anything under the target. There is intentionally no Node
  // mutation fallback.
  normalizeLifecycleCustodianMutation(input);
  return assertLifecycleCustodianAvailable();
}

module.exports = {
  EXEC_IMAGE_BINDING_BLOCKER,
  assertLifecycleCustodianAvailable,
  executeLifecycleMutation,
  lifecycleCustodianTargetSnapshot,
  lifecycleCustodianStatus,
  withLifecycleCustodianTarget,
};
