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

defineLazyExports(() => require("./governance-contracts.js"), [
  "GOVERNANCE_VERSION",
  "LIFECYCLE_STATE_VALUES",
  "PHYSICAL_SCOPE_NUCLEUS_AXIS_VERSION",
  "assertRepoRootPath",
  "buildSessionNucleus",
  "normalizeAuthContext",
  "normalizeEgressIdentity",
  "normalizeLifecycleState",
  "normalizeOperatorConstraint",
  "normalizePhysicalScopeNucleusAxis",
  "normalizeScopePolicy",
  "normalizeTargetRepo",
  "sessionNucleusFromState",
  "sessionNucleusHash",
]);

defineLazyExports(() => require("./governance-context.js"), [
  "buildGovernanceContext",
  "buildGovernanceContextFromNucleus",
  "safeGovernanceContextForDomain",
]);

defineLazyExports(() => require("./governance-store.js"), [
  "readSessionNucleus",
  "readVerifiedSessionNucleus",
]);
