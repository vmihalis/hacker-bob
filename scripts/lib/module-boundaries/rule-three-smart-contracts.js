"use strict";

const path = require("path");
const {
  TOOLS_DIR,
  frozenMap,
  frozenSet,
  isInside,
} = require("./shared.js");

// ---------------------------------------------------------------------------
// RULE THREE's vocabulary. One definition site each, exported, and every list
// frozen and only-shrinking under the same hardening as the two above.

const SMART_CONTRACTS_DIR = path.join("domains", "blockchain", "smart-contracts");

// The directory's membership, seeded by EXECUTING this checker against the tree
// it audits. Membership for the WALK is derived from the directory — every `.js`
// under it — so this list is not what admits a module. It exists so the module
// cannot be silently emptied into a vacuous pass: a name here with no file on
// disk fails, which is the failure a directory-derived membership cannot see.
const SMART_CONTRACTS_MEMBERS = frozenSet("SMART_CONTRACTS_MEMBERS", [
  "anchor-runner.js",
  "aptos-client.js",
  "aptos-rpc-pool.js",
  "aptos-runner.js",
  "cargo-test-output.js",
  "cosmwasm-client.js",
  "cosmwasm-rpc-pool.js",
  "cosmwasm-runner.js",
  "evm-client.js",
  "evm-rpc-pool.js",
  "evm-source.js",
  "foundry-runner.js",
  "halmos-runner.js",
  "move-test-output.js",
  "sc-container-exec.js",
  "sc-egress-policy.js",
  "sc-http-client.js",
  "substrate-client.js",
  "substrate-rpc-pool.js",
  "substrate-runner.js",
  "sui-client.js",
  "sui-rpc-pool.js",
  "sui-runner.js",
  "svm-client.js",
  "svm-rpc-pool.js",
]);

// THE INTERNALS: members with no importer outside the directory, measured. This
// is the fact the directory makes checkable and the flat listing could not, so
// there is NO exception list beside it — an edge from outside into any of these
// fails outright. Today's tree has zero such edges, and the whole value of the
// rule is that the number stays zero.
const SMART_CONTRACTS_INTERNALS = frozenSet("SMART_CONTRACTS_INTERNALS", [
  "aptos-rpc-pool.js",
  "cargo-test-output.js",
  "cosmwasm-rpc-pool.js",
  "move-test-output.js",
  "sc-container-exec.js",
  "sc-egress-policy.js",
  "sc-http-client.js",
  "substrate-rpc-pool.js",
  "sui-rpc-pool.js",
  "svm-rpc-pool.js",
]);

// The adjudication vocabulary for what a member may depend on. Closed and
// frozen, same rule as BOUNDARY_ADJUDICATION_CLASSES: a class outside it fails.
//
//   shared_vocabulary      a module the whole tree reads for names and shapes;
//                          depending on it says nothing about this directory.
//   cross_module_seam      genuinely shared with modules outside this one, which
//                          the walk can see: it has non-member importers too.
//   exclusively_used_here  every in-root importer is a member. DERIVED — the
//                          walk re-checks it, so the label cannot be pasted onto
//                          a module the rest of the tree also uses.
const SMART_CONTRACTS_DEPENDENCY_CLASSES = Object.freeze([
  "shared_vocabulary",
  "cross_module_seam",
  "exclusively_used_here",
]);

// What a member may depend on OUTSIDE the directory, keyed walk-root-relative —
// or repo-relative for a target outside the walk root, the same keying the
// cross-package edge census already uses. Seeded by executing this checker.
//
// This arm DOES police the two targets outside the walk root, and that is
// consistent with this gate's refusal to assert a LAYER out there: the rule
// asserts an allowed-dependency fact about an edge whose IMPORTER the walk
// classified, not a layer it never derived for the target.
const SMART_CONTRACTS_ALLOWED_DEPENDENCIES = frozenMap("SMART_CONTRACTS_ALLOWED_DEPENDENCIES", [
  ["core/io/paths.js", "shared_vocabulary"],
  ["core/io/storage.js", "shared_vocabulary"],
  ["core/ledger-integrity/index.js", "cross_module_seam"],
  ["core/url-surface.js", "cross_module_seam"],
  ["redaction.js", "shared_vocabulary"],
]);

// Edges from OUTSIDE the directory into its public surface that do not come
// from the composition root's tool modules. Keyed `importer -> target` as
// walk-root-relative paths, exactly as ALLOWLIST_BOUNDARY_VIOLATIONS is keyed,
// and carrying the argument for why the entry point is where it is. Frozen and
// only-shrinking: an entry with no matching edge fails as stale.
const SMART_CONTRACTS_ENTRYPOINT_EXCEPTIONS = frozenMap("SMART_CONTRACTS_ENTRYPOINT_EXCEPTIONS", [
  ["core/invariant-runner.js -> domains/blockchain/smart-contracts/evm-client.js", "the invariant runner reaches the concrete EVM client from the pre-DIP composition-runtime cycle; this baseline records that current entry point until the later inversion node removes it"],
  ["core/invariant-runner.js -> domains/blockchain/smart-contracts/evm-rpc-pool.js", "the invariant runner reads the concrete fork endpoint pool from the pre-DIP composition-runtime cycle; this baseline records that current entry point until the later inversion node removes it"],
  ["core/session/assignment-brief.js -> domains/blockchain/smart-contracts/evm-rpc-pool.js", "the assignment brief summarizes the configured RPC pool through its concrete summarizer; this baseline records the current pre-DIP entry point"],
]);
// The walk-root-relative path of a module INSIDE the smart-contracts directory,
// or null. Membership is DERIVED from where the file sits — the frozen member
// list never admits anything. The directory base is nested, so containment is
// checked against the complete base rather than only the first path segment.
function smartContractsMemberOf(walkRoot, absolutePath) {
  const relative = path.relative(walkRoot, absolutePath);
  if (relative === "" || relative.startsWith("..") || path.isAbsolute(relative)) return null;
  return isInside(path.join(walkRoot, SMART_CONTRACTS_DIR), absolutePath) ? relative : null;
}

// RULE THREE, per edge, over the same resolutions the plane rule is decided on.
// Called BEFORE the in-root/out-of-root split, because a member's dependency on
// a module outside the walk root is exactly as much a dependency as one inside.
function policeSmartContractsEdge({
  root, walkRoot, importer, importerRelative, target, line,
  internals, allowedDependencies, entrypointExceptions, violations, measured,
}) {
  const importerIsMember = smartContractsMemberOf(walkRoot, importer) !== null;
  const targetMember = smartContractsMemberOf(walkRoot, target);

  // GATE B — a member acquiring a dependency the boundary does not allow.
  if (importerIsMember) {
    if (targetMember !== null) return;
    const inRoot = isInside(walkRoot, target);
    const targetKey = inRoot ? path.relative(walkRoot, target) : path.relative(root, target);
    const key = `${importerRelative} -> ${targetKey}`;
    measured.smartContractsDependencyEdges.add(key);
    measured.smartContractsDependencyTargets.add(targetKey);
    if (!inRoot) measured.smartContractsOutOfRootTargets.add(targetKey);
    if (!allowedDependencies.has(targetKey)) {
      violations.push({
        kind: "smart_contracts_dependency_not_allowed",
        id: key,
        detail: `${importerRelative}:${line} requires ${targetKey}, which is not one of the modules `
          + `${SMART_CONTRACTS_DIR}/ is allowed to depend on; either the dependency belongs inside the `
          + `directory, or record it with the class that adjudicates it`,
      });
    }
    return;
  }

  // GATE A — a module outside the directory reaching into it.
  if (targetMember === null) return;
  const key = `${importerRelative} -> ${targetMember}`;
  measured.smartContractsInboundEdges.add(key);
  if (internals.has(path.basename(targetMember))) {
    violations.push({
      kind: "smart_contracts_internal_reached_from_outside",
      id: key,
      detail: `${importerRelative}:${line} requires ${targetMember}, which is INTERNAL to ${SMART_CONTRACTS_DIR}/ `
        + `— nothing outside the directory imports it today, and that is the fact the directory exists to keep `
        + `checkable. Reach it through a module on the public surface, or move the caller inside`,
    });
    return;
  }
  // The composition-root arm, DERIVED the same way `classifyModule` derives it:
  // a tool module is where concrete implementations may be named.
  if (importerRelative.split(path.sep)[0] === TOOLS_DIR) {
    measured.smartContractsToolsEdges.add(key);
    return;
  }
  if (!entrypointExceptions.has(key)) {
    violations.push({
      kind: "smart_contracts_entrypoint_edge_unrecorded",
      id: key,
      detail: `${importerRelative}:${line} requires ${targetMember} from outside ${SMART_CONTRACTS_DIR}/ and `
        + `outside ${TOOLS_DIR}/, so it is a new entry point into the module; record it with the argument for `
        + `why the entry point is there, or route it through a tool module`,
    });
  }
}

// Reconcile RULE THREE's frozen lists against the walk, in both directions. A
// member name with no file fails, a list entry with no matching edge fails, and
// the one DERIVED dependency class is re-checked rather than trusted.
function reconcileSmartContracts({
  walkRoot, files, moduleEdges, members, internals, allowedDependencies, entrypointExceptions,
  violations, measured,
}) {
  const onDisk = new Set();
  for (const file of files) {
    const relative = smartContractsMemberOf(walkRoot, file);
    if (relative !== null) onDisk.add(path.basename(relative));
  }
  measured.smartContractsOnDisk = onDisk;
  for (const name of onDisk) {
    if (internals.has(name)) measured.smartContractsInternalsOnDisk.add(name);
    else measured.smartContractsPublicOnDisk.add(name);
  }

  for (const name of members) {
    if (onDisk.has(name)) continue;
    violations.push({
      kind: "smart_contracts_member_missing",
      id: name,
      detail: `SMART_CONTRACTS_MEMBERS records ${name} as a member of ${SMART_CONTRACTS_DIR}/, but no such file `
        + `is there; a module that can pass by being empty is not a boundary, so re-derive the membership or `
        + `drop the name`,
    });
  }

  const stale = (list, entry, why) => {
    violations.push({
      kind: "stale_smart_contracts_entry",
      id: `${list} ${entry}`,
      detail: `${list} records ${entry}, but ${why}; the list only shrinks, so drop the entry`,
    });
  };
  for (const name of internals) {
    if (!onDisk.has(name)) stale("SMART_CONTRACTS_INTERNALS", name, `${SMART_CONTRACTS_DIR}/ holds no such file`);
  }
  for (const targetKey of allowedDependencies.keys()) {
    if (!measured.smartContractsDependencyTargets.has(targetKey)) {
      stale("SMART_CONTRACTS_ALLOWED_DEPENDENCIES", targetKey, "no member depends on it");
    }
  }
  for (const key of entrypointExceptions.keys()) {
    if (!measured.smartContractsInboundEdges.has(key)) {
      stale("SMART_CONTRACTS_ENTRYPOINT_EXCEPTIONS", key, "the walk found no such edge");
    }
  }

  // ADJUDICATION, and the one class that is a claim about the walk rather than a
  // label carried in from a document.
  for (const [targetKey, adjudication] of allowedDependencies) {
    if (!SMART_CONTRACTS_DEPENDENCY_CLASSES.includes(adjudication)) {
      violations.push({
        kind: "misclassified_smart_contracts_dependency",
        id: targetKey,
        detail: `${targetKey} is classed ${JSON.stringify(adjudication)}, which is outside the frozen `
          + `vocabulary ${SMART_CONTRACTS_DEPENDENCY_CLASSES.join(", ")}`,
      });
      continue;
    }
    measured.smartContractsDependencyClasses.set(
      adjudication, measured.smartContractsDependencyClasses.get(adjudication) + 1,
    );
    if (adjudication !== "exclusively_used_here") continue;
    // DERIVED: every in-root importer of the target must be a member. A target
    // the walk cannot see the importers of cannot carry this class at all, or it
    // would pass vacuously on a module nothing in the walk root reaches.
    if (measured.smartContractsOutOfRootTargets.has(targetKey)) {
      violations.push({
        kind: "misclassified_smart_contracts_dependency",
        id: targetKey,
        detail: `${targetKey} is classed exclusively_used_here, but it sits outside ${measured.walkRoot} where `
          + `this walk reads no importers, so the class cannot be derived and would pass vacuously`,
      });
      continue;
    }
    const outsiders = [];
    for (const [from, targets] of moduleEdges) {
      if (!targets.has(targetKey)) continue;
      if (from.startsWith(`${SMART_CONTRACTS_DIR}${path.sep}`)) continue;
      outsiders.push(from);
    }
    if (outsiders.length > 0) {
      violations.push({
        kind: "misclassified_smart_contracts_dependency",
        id: targetKey,
        detail: `${targetKey} is classed exclusively_used_here, but the walk found ${outsiders.length} importer(s) `
          + `outside ${SMART_CONTRACTS_DIR}/: ${outsiders.sort().join(", ")}. The class says every in-root `
          + `importer is a member, and this one is not`,
      });
    }
  }
}

module.exports = {
  SMART_CONTRACTS_ALLOWED_DEPENDENCIES,
  SMART_CONTRACTS_DEPENDENCY_CLASSES,
  SMART_CONTRACTS_DIR,
  SMART_CONTRACTS_ENTRYPOINT_EXCEPTIONS,
  SMART_CONTRACTS_INTERNALS,
  SMART_CONTRACTS_MEMBERS,
  policeSmartContractsEdge,
  reconcileSmartContracts,
  smartContractsMemberOf,
};
