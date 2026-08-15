"use strict";

const path = require("path");

// The enforced plane axes. Directory position remains the layer definition;
// these names also bind each structural plane to its exported tool authority.
const PLANE_AXIS = "physical";
const BLOCKCHAIN_PLANE_AXIS = "blockchain";
const PLANE_AXES = Object.freeze([PLANE_AXIS, BLOCKCHAIN_PLANE_AXIS]);
const PLANE_SESSION_AXES = Object.freeze({
  [PLANE_AXIS]: PLANE_AXIS,
  [BLOCKCHAIN_PLANE_AXIS]: "contracts",
});
// The adjudication vocabulary. Closed and frozen: a class outside it fails, so a
// future entry cannot be excused by inventing a softer word for it.
const BOUNDARY_ADJUDICATION_CLASSES = Object.freeze([
  "composition_root",
  "control_flow_core",
  "plane_value_import",
  "consolidatable_not_taken",
]);
// The plane axis structurally owning a module, or null. Physical and blockchain
// both keep their library modules under `domains/<axis>/*` and their composition
// modules under `tools/<axis>/*`.
function planeAxisOf(walkRoot, absolutePath) {
  const relative = path.relative(walkRoot, absolutePath);
  if (relative === "" || relative.startsWith("..") || path.isAbsolute(relative)) return null;
  const segments = relative.split(path.sep);
  if (segments[0] === "domains" && segments[1] === PLANE_AXIS && segments.length > 2) {
    return PLANE_AXIS;
  }
  if (segments[0] === TOOLS_DIR && segments[1] === PLANE_AXIS && segments.length > 2) return PLANE_AXIS;
  if (segments[0] === "domains" && segments[1] === BLOCKCHAIN_PLANE_AXIS && segments.length > 2) {
    return BLOCKCHAIN_PLANE_AXIS;
  }
  if (segments[0] === TOOLS_DIR && segments[1] === BLOCKCHAIN_PLANE_AXIS && segments.length > 2) {
    return BLOCKCHAIN_PLANE_AXIS;
  }
  return null;
}

// The walk-root-relative path of a module inside any enforced plane, or null.
function planeMemberOf(walkRoot, absolutePath) {
  return planeAxisOf(walkRoot, absolutePath) === null ? null : path.relative(walkRoot, absolutePath);
}

// Axis-specific membership is what keeps each seam's binary census independent:
// blockchain remains core in the physical audit, and physical remains core in
// the blockchain audit, exactly as each plane's severance question requires.
function planeMemberOfAxis(walkRoot, absolutePath, axis) {
  return planeAxisOf(walkRoot, absolutePath) === axis ? path.relative(walkRoot, absolutePath) : null;
}

module.exports.BOUNDARY_ADJUDICATION_CLASSES = BOUNDARY_ADJUDICATION_CLASSES;
module.exports.planeMemberOf = planeMemberOf;
module.exports.planeMemberOfAxis = planeMemberOfAxis;

const {
  TOOLS_DIR,
  frozenMap,
  frozenSet,
} = require("./shared.js");

// The composition root: the single module where the tool registry names concrete
// implementations. Checked against the walk, never assumed from a key.
const COMPOSITION_ROOT_MODULE = path.join(TOOLS_DIR, "index.js");
// The core -> plane edges that exist today, seeded by EXECUTING this checker
// against the tree it audits, each mapped to the one class that adjudicates it.
// Widening this list to dodge a new violation is prohibited: it is a record of
// debt, not a policy. A stale entry FAILS, so the list can only shrink.
const ALLOWLIST_BOUNDARY_VIOLATIONS = frozenMap("ALLOWLIST_BOUNDARY_VIOLATIONS", [
  ["core/capability/capability-packs.js -> domains/physical/physical-capability-manifest.js", "plane_value_import"],
  ["core/capability/capability-packs.js -> domains/physical/physical-surface-transition.js", "plane_value_import"],
  ["core/executed-evidence-registry.js -> domains/physical/physical-experiment-contract.js", "plane_value_import"],
  ["core/executed-evidence-registry.js -> domains/physical/physical-surface-transition.js", "plane_value_import"],
  ["core/finding-contracts.js -> domains/physical/physical-finding-record-adapter.js", "control_flow_core"],
  ["core/frontier/frontier-readiness.js -> domains/physical/physical-campaign-coordinator.js", "control_flow_core"],
  ["core/frontier/surface-graph.js -> domains/physical/physical-surface-transition.js", "control_flow_core"],
  ["core/session/lifecycle-gates.js -> domains/physical/physical-campaign-coordinator.js", "control_flow_core"],
  ["core/session/session-authority.js -> domains/physical/physical-session-journal.js", "control_flow_core"],
  ["tools/index.js -> tools/physical/credential-acquire.js", "composition_root"],
  ["tools/index.js -> tools/physical/credential-emulate.js", "composition_root"],
  ["tools/index.js -> tools/physical/credential-recover.js", "composition_root"],
  ["tools/index.js -> tools/physical/credential-write.js", "composition_root"],
  ["tools/index.js -> tools/physical/init-physical-session.js", "composition_root"],
  ["tools/index.js -> tools/physical/physical-observe.js", "composition_root"],
  ["tools/index.js -> tools/physical/protocol-transceive.js", "composition_root"],
  ["tools/index.js -> tools/physical/query-instrument-capabilities.js", "composition_root"],
  ["tools/index.js -> tools/physical/record-physical-candidate-claim.js", "composition_root"],
  ["tools/index.js -> tools/physical/rf-trace.js", "composition_root"],
  ["tools/index.js -> tools/physical/verify-physical-candidate-claim.js", "composition_root"],
  ["tools/index.js -> tools/physical/verify-physical-verdict.js", "composition_root"],
]);

// The separately adjudicated core -> blockchain seam. This list was seeded from
// the same live AST walk as the physical list. It is independent so either plane
// can shrink without changing the other's census or waivers.
const BLOCKCHAIN_ALLOWLIST_BOUNDARY_VIOLATIONS = frozenMap("BLOCKCHAIN_ALLOWLIST_BOUNDARY_VIOLATIONS", [
  ["core/invariant-runner.js -> domains/blockchain/smart-contracts/evm-client.js", "control_flow_core"],
  ["core/invariant-runner.js -> domains/blockchain/smart-contracts/evm-rpc-pool.js", "control_flow_core"],
  ["core/session/assignment-brief.js -> domains/blockchain/smart-contracts/evm-rpc-pool.js", "control_flow_core"],
  ["core/session/session-authority.js -> domains/blockchain/chain-tool-identity.js", "control_flow_core"],
  ["core/session/session-authority.js -> tools/blockchain/init-contract-session.js", "control_flow_core"],
  ["tools/finalize-node.js -> domains/blockchain/contract-target.js", "control_flow_core"],
  ["tools/index.js -> tools/blockchain/anchor-run.js", "composition_root"],
  ["tools/index.js -> tools/blockchain/aptos-fetch-module.js", "composition_root"],
  ["tools/index.js -> tools/blockchain/aptos-fetch-resource.js", "composition_root"],
  ["tools/index.js -> tools/blockchain/aptos-run.js", "composition_root"],
  ["tools/index.js -> tools/blockchain/cosmwasm-fetch-contract.js", "composition_root"],
  ["tools/index.js -> tools/blockchain/cosmwasm-run.js", "composition_root"],
  ["tools/index.js -> tools/blockchain/cosmwasm-smart-query.js", "composition_root"],
  ["tools/index.js -> tools/blockchain/evm-call.js", "composition_root"],
  ["tools/index.js -> tools/blockchain/evm-fetch-source.js", "composition_root"],
  ["tools/index.js -> tools/blockchain/evm-role-table.js", "composition_root"],
  ["tools/index.js -> tools/blockchain/evm-storage-read.js", "composition_root"],
  ["tools/index.js -> tools/blockchain/foundry-run.js", "composition_root"],
  ["tools/index.js -> tools/blockchain/halmos-run.js", "composition_root"],
  ["tools/index.js -> tools/blockchain/init-contract-session.js", "composition_root"],
  ["tools/index.js -> tools/blockchain/read-invariant-runs.js", "composition_root"],
  ["tools/index.js -> tools/blockchain/run-invariant-for-finding.js", "composition_root"],
  ["tools/index.js -> tools/blockchain/substrate-fetch-runtime.js", "composition_root"],
  ["tools/index.js -> tools/blockchain/substrate-fetch-storage.js", "composition_root"],
  ["tools/index.js -> tools/blockchain/substrate-run.js", "composition_root"],
  ["tools/index.js -> tools/blockchain/suggest-invariants.js", "composition_root"],
  ["tools/index.js -> tools/blockchain/sui-fetch-object.js", "composition_root"],
  ["tools/index.js -> tools/blockchain/sui-fetch-package.js", "composition_root"],
  ["tools/index.js -> tools/blockchain/sui-run.js", "composition_root"],
  ["tools/index.js -> tools/blockchain/svm-fetch-account.js", "composition_root"],
  ["tools/index.js -> tools/blockchain/svm-fetch-program.js", "composition_root"],
  ["tools/index.js -> tools/blockchain/verify-invariant-differential.js", "composition_root"],
  ["tools/init-session.js -> domains/blockchain/contract-target.js", "control_flow_core"],
  ["tools/repo/init-repo-session.js -> domains/blockchain/contract-target.js", "control_flow_core"],
]);
// THE PLANE INVENTORY. Layer membership is derived from directory position,
// never from this list. The two-way reconciliation is what makes a move bite:
// a recorded name moved out of `domains/physical/` fails as missing, and a new file
// moved in fails as unrecorded. Seeded from the live walk, frozen with hardened
// Set mutators, and only allowed to shrink.
// `role_bundles` is NOT the discriminator, though it reads like one. Measured
// on the live tree, 16 tool modules declare `evaluator-physical`, and 7 of them
// — read-session-nucleus, read-assignment-brief, get-context-budget,
// select-technique-packs, read-technique-pack, log-technique-attempt,
// read-task-graph — are shared core tools that the seam audit lists as
// necessarily core-visible. Meanwhile init-physical-session.js declares
// `["orchestrator"]` and the two physical verifiers declare
// `["verifier", "evidence"]`. Classifying by bundle would seed seven allowlist
// entries that can never legitimately shrink and still miss three real plane
// modules.
const PLANE_MEMBERS = frozenSet("PLANE_MEMBERS", [
  "capability-pack-physical-artifacts.js",
  "capability-pack-runtime-ports.js",
  "capability-pack-runtime-wiring.js",
  "credential-acquire.js",
  "credential-emulate.js",
  "credential-recover.js",
  "credential-write.js",
  "init-physical-session.js",
  "instrument-bootstrap-contract.js",
  "instrument-bootstrap-store.js",
  "instrument-capabilities-chameleon.js",
  "instrument-capabilities.js",
  "instrument-lease-contract.js",
  "instrument-lease-store.js",
  "instrument-provider-contract.js",
  "instrument-safety-supervisor.js",
  "physical-authority.js",
  "physical-campaign-anchor.js",
  "physical-campaign-closure-owner.js",
  "physical-campaign-closure.js",
  "physical-campaign-coordinator.js",
  "physical-capability-consumers.js",
  "physical-capability-manifest.js",
  "physical-claim-lifecycle-adapter.js",
  "physical-dispatch-authority.js",
  "physical-experiment-contract.js",
  "physical-experiment-store.js",
  "physical-experiment-trust-store.js",
  "physical-finding-contract.js",
  "physical-finding-record-adapter.js",
  "physical-inventory-checkpoint.js",
  "physical-lifecycle-capstone.js",
  "physical-monotonic-owner.js",
  "physical-observe.js",
  "physical-provider-authoring.js",
  "physical-quantities.js",
  "physical-resource-arbiter.js",
  "physical-resource-graph-coordinator.js",
  "physical-resource-scheduler.js",
  "physical-scope.js",
  "physical-session-journal.js",
  "physical-session-runtime.js",
  "physical-surface-transition.js",
  "physical-technique-composition-root.js",
  "physical-technique-runtime.js",
  "physical-technique-tool.js",
  "physical-trusted-clock-store.js",
  "physical-trusted-clock.js",
  "physical-verdict-runtime.js",
  "plane-physical-gate-evidence.js",
  "plane-physical-release-contracts.js",
  "plane-physical-release-readiness.js",
  "plane-physical-release-snapshot.js",
  "protocol-transceive.js",
  "query-instrument-capabilities.js",
  "record-physical-candidate-claim.js",
  "rf-trace.js",
  "verify-physical-candidate-claim.js",
  "verify-physical-verdict.js",
]);

const BLOCKCHAIN_PLANE_MEMBERS = frozenSet("BLOCKCHAIN_PLANE_MEMBERS", [
  "anchor-run.js",
  "anchor-runner.js",
  "aptos-client.js",
  "aptos-fetch-module.js",
  "aptos-fetch-resource.js",
  "aptos-rpc-pool.js",
  "aptos-run.js",
  "aptos-runner.js",
  "cargo-test-output.js",
  "chain-rpc-pool.js",
  "chain-tool-identity.js",
  "contract-address-shapes.js",
  "contract-target.js",
  "cosmwasm-client.js",
  "cosmwasm-fetch-contract.js",
  "cosmwasm-rpc-pool.js",
  "cosmwasm-run.js",
  "cosmwasm-runner.js",
  "cosmwasm-smart-query.js",
  "evm-call.js",
  "evm-client.js",
  "evm-fetch-source.js",
  "evm-role-table.js",
  "evm-rpc-pool.js",
  "evm-source.js",
  "evm-storage-read.js",
  "foundry-run.js",
  "foundry-runner.js",
  "halmos-run.js",
  "halmos-runner.js",
  "init-contract-session.js",
  "json-rpc-transport.js",
  "move-test-output.js",
  "read-invariant-runs.js",
  "run-invariant-for-finding.js",
  "sc-container-exec.js",
  "sc-egress-policy.js",
  "sc-http-client.js",
  "substrate-client.js",
  "substrate-fetch-runtime.js",
  "substrate-fetch-storage.js",
  "substrate-rpc-pool.js",
  "substrate-run.js",
  "substrate-runner.js",
  "suggest-invariants.js",
  "sui-client.js",
  "sui-fetch-object.js",
  "sui-fetch-package.js",
  "sui-rpc-pool.js",
  "sui-run.js",
  "sui-runner.js",
  "svm-client.js",
  "svm-fetch-account.js",
  "svm-fetch-program.js",
  "svm-rpc-pool.js",
  "verify-invariant-differential.js",
]);
// The only out-of-walk-root subset the coverage note calls plane-shaped. This
// is deliberately explicit rather than borrowing the in-root classifier: the
// package targets were never part of that partition, and the five live edges
// all enter packages whose names begin `bob-instrument-`.
function isPlanePackageTarget(root, absolutePath) {
  const relative = path.relative(root, absolutePath);
  if (relative === "" || relative.startsWith("..") || path.isAbsolute(relative)) return false;
  return relative.split(path.sep).join("/").startsWith("packages/bob-instrument-");
}

// Reconcile structural membership against the frozen inventory in both
// directions. The list never classifies a file; it makes moves into and out of
// the structural directories fail rather than changing the definition in
// silence.
function reconcilePlaneMembers({ walkRoot, files, members, violations, axis = PLANE_AXIS }) {
  const onDisk = new Set();
  for (const file of files) {
    const relative = planeMemberOfAxis(walkRoot, file, axis);
    if (relative !== null) onDisk.add(path.basename(relative));
  }
  for (const name of onDisk) {
    if (members.has(name)) continue;
    violations.push({
      kind: "plane_member_unrecorded",
      id: name,
      detail: axis === PLANE_AXIS
        ? `${name} sits below a domains/physical/ directory but PLANE_MEMBERS does not record it; moving core `
          + `into the plane is a boundary change and must not alter classification in silence`
        : `${name} sits below a ${axis} plane directory but the ${axis} PLANE_MEMBERS inventory does not record it; `
          + `moving core into the plane is a boundary change and must not alter classification in silence`,
    });
  }
  for (const name of members) {
    if (onDisk.has(name)) continue;
    violations.push({
      kind: "plane_member_missing",
      id: name,
      detail: axis === PLANE_AXIS
        ? `PLANE_MEMBERS records ${name} as a physical-plane member, but no such file is below a `
          + `domains/physical/ directory; the inventory only shrinks, so restore the member or deliberately drop it`
        : `the ${axis} PLANE_MEMBERS inventory records ${name}, but no such file is below a ${axis} `
          + `plane directory; the inventory only shrinks, so restore the member or deliberately drop it`,
    });
  }
}

Object.assign(module.exports, {
  ALLOWLIST_BOUNDARY_VIOLATIONS,
  BLOCKCHAIN_ALLOWLIST_BOUNDARY_VIOLATIONS,
  BLOCKCHAIN_PLANE_AXIS,
  BLOCKCHAIN_PLANE_MEMBERS,
  BOUNDARY_ADJUDICATION_CLASSES,
  COMPOSITION_ROOT_MODULE,
  PLANE_AXIS,
  PLANE_AXES,
  PLANE_MEMBERS,
  PLANE_SESSION_AXES,
  isPlanePackageTarget,
  planeMemberOf,
  planeMemberOfAxis,
  planeAxisOf,
  reconcilePlaneMembers,
});
