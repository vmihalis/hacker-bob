#!/usr/bin/env node
"use strict";

// `check:module-boundaries` — read-only gate over the module graph of
// `mcp`, in the family of scripts/check-invariant-registry.js and
// scripts/check-closed-set-emitters.js. Never writes, never touches the clock,
// randomness, or the network.
//
// RULE ONE: core may not require a plane implementation.
//
// RULE TWO: the module graph may not grow a cycle nobody argued for. A module
// cannot be extracted across a cycle, so the set of files sitting inside one is
// the hard ceiling on any directory layout this tree could adopt — and, like the
// boundary count, it was a number in a document that nobody re-derived. It is
// re-derived here, as strongly connected components over the SAME edge set the
// plane rule is enforced on, and reconciled against a frozen, only-shrinking
// inventory in which every surviving cycle carries a written irreducibility
// argument. A new cycle fails; a stale entry fails; a recorded cycle that
// changed size fails, because "36 files are stuck" stops being true the moment a
// 37th joins and an argument written about 36 no longer covers it.
//
// A DEFERRED require does NOT break a cycle, and this gate refuses to let one
// look as though it did. `collectStaticRequires` stamps every site with whether
// it sits inside a function body, an edge with only in-function sites is still
// an edge in the graph, and the count of such edges is printed next to the cycle
// census — because moving a require into a function removes it from a reader's
// view of the top of the file and from nothing else. Measured on the live tree,
// most of the cycle's edges are already written that way, which is the evidence
// that deferral has been tried here and bought no acyclicity.
//
// RULE THREE: an extracted directory must state a dependency fact the flat
// listing could not. `mcp/domains/blockchain/smart-contracts/` holds the per-blockchain
// contract evaluators, and the reason it is a directory rather than a filing
// preference is that being one makes two facts CHECKABLE that a flat listing
// could only assert:
//
//   (a) ten of its twenty-five modules have no importer outside it — every RPC
//       pool but evm-rpc-pool, the shared pinned HTTP client, the container-exec
//       seam, the smart-contract egress policy, and both test-output parsers.
//       That set is the module's INTERNALS,
//       and the exception list for reaching into it is EMPTY and must stay
//       empty. This also hardens the existing SC dispatch seam without
//       duplicating it: nothing outside may reach sc-container-exec.js, so every
//       SC run still arrives through a runner and ROUTED_SC_RUNNERS
//       (domains/blockchain/smart-contracts/sc-container-exec.js) stays the one dispatch registry.
//
//   (b) a member may depend on exactly five modules outside the directory, each
//       carrying an adjudication class, and one of those classes is RE-DERIVED
//       from the walk rather than asserted — see the vocabulary below.
//
// THE ADMISSION TEST this rule was built against: the move is admissible only
// while those lists stay small. If the exception lists ever grow toward the edge
// count they police, the boundary has become the old graph rewritten and the
// directory is filing. The counts are printed in the coverage note on every run
// so that is visible rather than inferred.
//
// A plane is a self-contained capability domain whose modules core is supposed
// to reach only through a contract. Physical and blockchain are independently
// enforced planes, and each boundary is violated deeply enough that its current
// violations are frozen rather than fixed. That is the point of this gate: a
// boundary is unenforceable until it is COUNTABLE, and a count nobody re-derives
// is a number in a document. This gate re-derives both on every run.
//
// LAYER DERIVATION is structural and axis-specific. Physical owns `domains/physical/`
// and `tools/physical/`; blockchain owns `domains/blockchain/` and
// `tools/blockchain/`. For each independent boundary view, every other walked
// module is core. Renaming a file therefore cannot launder it out of the rule,
// and moving one in either direction is reconciled against that axis's frozen
// member inventory.
//
// Each plane's runtime session axis survives as an independent, fail-closed
// consistency signal. A tool whose LIVE `required_session_axes` export includes
// the corresponding session axis (`physical`, or `contracts` for blockchain)
// must live below that plane's tool directory. This catches axis-visible drift
// from a runtime fact; protocol-transceive.js is the load-bearing physical case
// because its basename carries no physical vocabulary at all.
//
// Every violation is keyed PER EDGE (both endpoints as walk-root-relative
// paths), not per file: a file-level key would let a module quietly add a fifth
// plane import under an existing entry. The TARGET half is a path and not a
// basename for the same reason at one level down — two distinct edges from one
// importer to same-named plane modules in different directories collapse into a
// single entry, and one entry then silences both. The target path is the identity
// that keeps such a collision distinct rather than discovering it after one
// allowlist entry has hidden multiple imports.
//
// ADJUDICATION. Counting the debt is necessary and not sufficient. A bare edge
// list reads as a backlog somebody is about to burn down, while these seams need
// explicit architectural judgments. So every entry carries exactly one class
// from a frozen four-value vocabulary, and an entry with no class — or with a
// class outside it — fails:
//
//   composition_root          the flat TOOL_MODULES array in tools/index.js, the
//                             one place dependency injection permits concretions.
//   control_flow_core         core computes an allow/deny or a canonical digest
//                             FROM the plane symbol. Absorbing it needs a named
//                             shim; these are the audit's driving edges.
//   plane_value_import        a value/registration import a plane contract could
//                             absorb — except no plane contract exists, and
//                             building one is a graph of its own.
//   consolidatable_not_taken  removable today by collapsing duplicate importers
//                             of one plane symbol, and deliberately left: a 5%
//                             shrink shipped as progress is the false progress
//                             this gate exists to prevent.
//
// Only `composition_root` is DERIVED — the gate re-checks against the walk that
// the importer really is the composition root module, so the label cannot be
// pasted onto an ordinary edge. `consolidatable_not_taken` carries a necessary
// condition the walk checks (the plane target really does have other allowlisted
// core importers), which is not the same as deriving it. The remaining two are
// human adjudications carried from the seam audit, and the coverage note says so
// rather than letting a label read as a proof.
//
// SEAM INVENTORY BINDING. docs/architecture/physical-severance-seam.md holds the
// per-edge inventory the verdict was argued from, one row per edge with a cited
// `file:line`. A prose inventory beside a machine list is two censuses that drift
// — and drift is what it did: a row cited a line the require had already moved
// off. So the doc is bound to the tree here rather than trusted: every row's
// cited site is re-read through the same parser, and the rows are reconciled
// against the measured edge set as an identity
//
//   <inventoried rows> = <policed core -> plane> + <cross-package> + <plane -> plane>
//
// A row with no edge fails, an edge with no row fails, and a row whose cited line
// no longer holds its require fails.
//
// SEAM CITATION BINDING. The inventory rows were bound and the rest of the doc
// was not, and the rest of the doc is where the rot went: six citations in the
// Tool Split table pointed at lines their symbol had moved off, while the rows
// beside them were correct because something re-read them. So EVERY `file:line`
// citation in the doc is now classified, and a citation in no bound class fails:
//
//   inventory row          the row reader above already re-reads its require.
//   tool-split registration  `mcp/tools/index.js:<line>` in the Registration
//                          column: the cited line must hold a static require
//                          whose module LOADS and whose descriptor `.name` is the
//                          tool the row names.
//   symbol-anchored        `` `<name>` at `<path>:<line>` ``, the declared grammar
//                          for citing a symbol: the cited line must DECLARE that
//                          name, read from a parse.
//   echo                   the same `importer:line` an inventory row already cites,
//                          so the row's re-read covers it.
//
// Anything else is `unbound_seam_citation`, unless it is in the frozen
// UNBINDABLE_SEAM_CITATIONS with a written reason — a list that only shrinks and
// whose entries fail as stale once the doc stops citing them. Naming an unbound
// class is the honest half; implying the whole doc is checked is not.
//
// Fail-closed like the sibling gates. A source the parser cannot read is a
// named error, not a skip. A `require()` whose specifier is computed is named
// and counted rather than dropped, because an edge the gate cannot resolve is
// an edge it cannot police. The same rule covers the edge FORMS a require-scan
// used to walk past — `import(x)`, `x.require(y)`, an aliased `const r = require`
// — and the in-root targets the file listing never reached, because `./x.json`
// resolves to a real file that the `.js` walk never gave a layer. A form the
// reader will not resolve fails as `unpoliceable_require_form`; a target with no
// derived layer is counted and named. Silence was the defect, not the gap.
//
// Flags:
//   --root <dir>       repo root override (default: parent of scripts/)
//   --walk <relpath>   walk root override (default: mcp)
//   --no-allowlist     audit with EVERY frozen list empty — the two boundary
//                      lists, the cycle inventory, and the four smart-contracts
//                      lists (negative-control harness; on the real tree it
//                      reports the full debt)
//   --inventory <rel>  seam inventory override (default: the path above)
//   --no-inventory     skip the inventory binding (fixture harnesses, which
//                      have a module tree but no seam audit to bind it to)
//
// Exit codes: 0 pass, 1 violations (one line each), 2 unexpected throw.

const fs = require("fs");
const path = require("path");
const {
  JS_PARSE_ERROR_CODE,
  REQUIRE_CALLEE_FORMS,
  collectStaticRequires,
  parseJsSource,
  staticPropertyName,
  walk,
} = require("./lib/js-source-facts.js");
const {
  SEAM_CENSUS_PATTERNS,
  SEAM_CITATION_RE,
  SEAM_INVENTORY_RELPATH,
  SEAM_SYMBOL_CITATION_RE,
  TOOLS_DIR,
  UNBINDABLE_SEAM_CITATIONS,
  classifyModule,
  declaredSessionAxes,
  isInside,
  listJsFiles,
  parseSeamInventoryRows,
  readSites,
  reconcileSeamInventory,
  resolveRelative,
  targetLayerInsideWalkRoot,
} = require("./lib/module-boundaries/shared.js");
const {
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
  reconcilePlaneMembers,
} = require("./lib/module-boundaries/rule-one-core-plane.js");
const {
  ALLOWLIST_DYNAMIC_REQUIRES,
  ALLOWLIST_MODULE_CYCLES,
  reconcileModuleCycles,
  stronglyConnectedComponents,
} = require("./lib/module-boundaries/rule-two-cycles.js");
const {
  SMART_CONTRACTS_ALLOWED_DEPENDENCIES,
  SMART_CONTRACTS_DEPENDENCY_CLASSES,
  SMART_CONTRACTS_DIR,
  SMART_CONTRACTS_ENTRYPOINT_EXCEPTIONS,
  SMART_CONTRACTS_INTERNALS,
  SMART_CONTRACTS_MEMBERS,
  policeSmartContractsEdge,
  reconcileSmartContracts,
  smartContractsMemberOf,
} = require("./lib/module-boundaries/rule-three-smart-contracts.js");

// The site forms that ARE a module edge, and so count toward the walked-edge
// census. `require.resolve(x)` asks where a module would be and this tree uses
// it only to probe for an installed package; an alias binding is not a call at
// all. Both are counted on their own lines in the coverage note instead, so
// neither inflates a number the seam audit cites.
const EDGE_CALLEE_FORMS = Object.freeze(new Set([
  REQUIRE_CALLEE_FORMS.REQUIRE,
  REQUIRE_CALLEE_FORMS.DYNAMIC_IMPORT,
  REQUIRE_CALLEE_FORMS.MEMBER_REQUIRE,
]));

const DEFAULT_ROOT = path.join(__dirname, "..");
const DEFAULT_WALK = "mcp";
const BLOCKCHAIN_SEAM_INVENTORY_RELPATH = path.join("docs", "architecture", "blockchain-severance-seam.md");

function parseArgs(argv) {
  const args = { root: DEFAULT_ROOT, walk: DEFAULT_WALK };
  for (let i = 2; i < argv.length; i += 1) {
    if (argv[i] === "--root" && argv[i + 1]) { args.root = path.resolve(argv[i + 1]); i += 1; }
    else if (argv[i] === "--walk" && argv[i + 1]) { args.walk = argv[i + 1]; i += 1; }
    else if (argv[i] === "--no-allowlist") {
      args.allowlist = new Map();
      args.blockchainAllowlist = new Map();
      args.dynamicAllowlist = new Set();
      args.cycleAllowlist = new Map();
      args.smartContractsMembers = new Set();
      args.smartContractsInternals = new Set();
      args.smartContractsAllowedDependencies = new Map();
      args.smartContractsEntrypointExceptions = new Map();
    }
    else if (argv[i] === "--inventory" && argv[i + 1]) { args.inventory = argv[i + 1]; i += 1; }
    else if (argv[i] === "--no-inventory") { args.inventory = null; args.blockchainInventory = null; }
  }
  return args;
}

function createPlaneMeasurement(axis, inventory) {
  const measured = {
    axis,
    planeModules: 0,
    coreModules: 0,
    boundaryEdges: new Set(),
    boundaryEdgeFacts: new Map(),
    get boundaryImporters() {
      return new Set([...this.boundaryEdgeFacts.values()].map((facts) => facts.importer)).size;
    },
    get boundaryEdgeCount() { return this.boundaryEdges.size; },
    planeTargetImporters: new Map(),
    adjudication: new Map(BOUNDARY_ADJUDICATION_CLASSES.map((name) => [name, 0])),
    inventoryPath: inventory === null ? null : inventory,
    inventoryRows: 0,
    inventoryPoliced: 0,
    inventoryCrossPackage: 0,
    inventoryPlaneToPlane: 0,
    seamCitations: 0,
    inventoryRowCites: 0,
    symbolAnchoredCites: 0,
    echoedCites: 0,
    unbindableCites: 0,
    unbindableCitationSites: new Set(),
    toolSplitTools: 0,
    toolSplitRegistrations: 0,
    toolSplitPlaneTools: 0,
    toolSplitCoreTools: 0,
    reverseDirectionRows: 0,
  };
  for (const name of BOUNDARY_ADJUDICATION_CLASSES) {
    Object.defineProperty(measured, `adjudication_${name}`, {
      get() { return this.adjudication.get(name); },
    });
  }
  return measured;
}

function runChecks({
  root = DEFAULT_ROOT,
  walk = DEFAULT_WALK,
  allowlist = ALLOWLIST_BOUNDARY_VIOLATIONS,
  blockchainAllowlist = BLOCKCHAIN_ALLOWLIST_BOUNDARY_VIOLATIONS,
  dynamicAllowlist = ALLOWLIST_DYNAMIC_REQUIRES,
  cycleAllowlist = ALLOWLIST_MODULE_CYCLES,
  planeMembers = PLANE_MEMBERS,
  blockchainPlaneMembers = BLOCKCHAIN_PLANE_MEMBERS,
  smartContractsMembers = SMART_CONTRACTS_MEMBERS,
  smartContractsInternals = SMART_CONTRACTS_INTERNALS,
  smartContractsAllowedDependencies = SMART_CONTRACTS_ALLOWED_DEPENDENCIES,
  smartContractsEntrypointExceptions = SMART_CONTRACTS_ENTRYPOINT_EXCEPTIONS,
  inventory = SEAM_INVENTORY_RELPATH,
  blockchainInventory = BLOCKCHAIN_SEAM_INVENTORY_RELPATH,
  // The unbindable list is a property of the ONE doc it was measured against, so
  // a fixture inventory carries none unless its caller supplies them. Same
  // discipline the fixtures already use for the two allowlists, without making
  // every seam fixture restate it.
  unbindableCitations = inventory === SEAM_INVENTORY_RELPATH ? UNBINDABLE_SEAM_CITATIONS : new Map(),
  blockchainUnbindableCitations = new Map(),
} = {}) {
  const violations = [];
  const walkRoot = path.isAbsolute(walk) ? walk : path.join(root, walk);
  const measured = {
    walkRoot: path.relative(root, walkRoot) || walk,
    filesWalked: 0,
    edgesWalked: 0,
    planeModules: 0,
    coreModules: 0,
    boundaryEdges: new Set(),
    boundaryEdgeFacts: new Map(),
    // Distinct core importers among the boundary edges — see coverageNote.
    get boundaryImporters() {
      return new Set([...this.boundaryEdgeFacts.values()].map((f) => f.importer)).size;
    },
    // Scalar views of the three Set/array-valued measurements the doc quotes.
    // The census table reconciles NUMBERS, and a number the doc credits to this
    // gate has to come out of it — so the accessor lives here, next to the
    // thing it counts, rather than as a second count somewhere else.
    get boundaryEdgeCount() { return this.boundaryEdges.size; },
    get corePlanePackageEdgeCount() { return this.corePlanePackageEdges.size; },
    get computedSpecifierSites() { return this.dynamicSites.length; },
    planeTargetImporters: new Map(),
    adjudication: new Map(BOUNDARY_ADJUDICATION_CLASSES.map((name) => [name, 0])),
    dynamicSites: [],
    // Sites whose SHAPE the reader will not resolve, keyed per site and broken
    // out per form in the coverage note. No allowlist: there are no live
    // instances, so fail-closed costs nothing and an empty frozen list would be
    // one more thing to keep honest.
    unpoliceableSites: [],
    // `require.resolve(...)`: named and counted, never walked.
    requireResolveSites: 0,
    // Require targets that exist INSIDE the walk root but that the walk never
    // classified, because the file listing is `.js` and resolution is not.
    inRootUnwalkedTargets: new Set(),
    crossWalkRootEdges: 0,
    corePlanePackageEdges: new Set(),
    externalEdges: 0,
    // THE CYCLE CENSUS, over the same in-root edges the plane rule is enforced
    // on. `cycleDeferredEdges` counts the in-cycle edges whose every site sits
    // inside a function body — printed beside the others precisely so a deferral
    // cannot read as a break.
    moduleCycles: [],
    filesInCycles: new Set(),
    cycleInternalEdges: 0,
    cycleDeferredEdges: 0,
    largestCycle: 0,
    inRootEdgePairs: 0,
    get cycleCount() { return this.moduleCycles.length; },
    get filesInCyclesCount() { return this.filesInCycles.size; },
    // RULE THREE's census. Every figure the coverage note prints for the
    // smart-contracts module is one of these, derived from the walk — the
    // frozen lists are what the walk is reconciled AGAINST, never what it
    // reports.
    smartContractsOnDisk: new Set(),
    smartContractsPublicOnDisk: new Set(),
    smartContractsInternalsOnDisk: new Set(),
    smartContractsInboundEdges: new Set(),
    smartContractsToolsEdges: new Set(),
    smartContractsDependencyEdges: new Set(),
    smartContractsDependencyTargets: new Set(),
    smartContractsOutOfRootTargets: new Set(),
    smartContractsDependencyClasses: new Map(SMART_CONTRACTS_DEPENDENCY_CLASSES.map((name) => [name, 0])),
    get smartContractsMemberCount() { return this.smartContractsOnDisk.size; },
    get smartContractsPublicCount() { return this.smartContractsPublicOnDisk.size; },
    get smartContractsInternalCount() { return this.smartContractsInternalsOnDisk.size; },
    get smartContractsDependencyCount() { return this.smartContractsDependencyTargets.size; },
    get smartContractsToolsEdgeCount() { return this.smartContractsToolsEdges.size; },
    get smartContractsEntrypointCount() {
      return this.smartContractsInboundEdges.size - this.smartContractsToolsEdges.size;
    },
    inventoryPath: inventory === null ? null : inventory,
    inventoryRows: 0,
    inventoryPoliced: 0,
    inventoryCrossPackage: 0,
    inventoryPlaneToPlane: 0,
    // THE CITATION CENSUS. Every `file:line` the doc writes, and which bound
    // class carries it. The five class counters sum to `seamCitations` on a
    // clean run, which is what makes the census a claim rather than a list.
    seamCitations: 0,
    inventoryRowCites: 0,
    symbolAnchoredCites: 0,
    echoedCites: 0,
    unbindableCites: 0,
    unbindableCitationSites: new Set(),
    // The Tool Split tables. `toolSplitTools` counts rows, `toolSplitRegistrations`
    // counts the ones whose Registration column could be read at all, so a row
    // that lost its citation is a difference rather than a silence.
    toolSplitTools: 0,
    toolSplitRegistrations: 0,
    toolSplitPlaneTools: 0,
    toolSplitCoreTools: 0,
    reverseDirectionRows: 0,
  };
  // One scalar accessor per adjudication class, derived from the frozen
  // vocabulary rather than transcribed, so a fifth class arrives in the census
  // table by itself instead of being forgotten there.
  for (const name of BOUNDARY_ADJUDICATION_CLASSES) {
    Object.defineProperty(measured, `adjudication_${name}`, {
      get() { return this.adjudication.get(name); },
    });
  }
  const blockchainMeasured = createPlaneMeasurement(BLOCKCHAIN_PLANE_AXIS, blockchainInventory);
  blockchainMeasured.walkRoot = measured.walkRoot;
  measured.blockchain = blockchainMeasured;
  if (!fs.existsSync(walkRoot)) {
    violations.push({ kind: "missing_walk_root", id: measured.walkRoot, detail: `${measured.walkRoot} does not exist` });
    return { violations, measured };
  }

  const files = listJsFiles(walkRoot);
  measured.filesWalked = files.length;

  const layerOfByAxis = new Map(PLANE_AXES.map((axis) => [axis, new Map()]));
  const layerOf = layerOfByAxis.get(PLANE_AXIS);
  const planeMeasurements = new Map([
    [PLANE_AXIS, measured],
    [BLOCKCHAIN_PLANE_AXIS, blockchainMeasured],
  ]);
  for (const file of files) {
    const relative = path.relative(walkRoot, file);
    const axes = relative.split(path.sep)[0] === TOOLS_DIR ? declaredSessionAxes(file) : new Set();
    for (const axis of PLANE_AXES) {
      const layer = classifyModule(file, walkRoot, axis);
      layerOfByAxis.get(axis).set(file, layer);
      const axisMeasured = planeMeasurements.get(axis);
      if (layer === "plane") axisMeasured.planeModules += 1;
      else axisMeasured.coreModules += 1;
      const sessionAxis = PLANE_SESSION_AXES[axis];
      if (relative.split(path.sep)[0] === TOOLS_DIR
          && planeMemberOfAxis(walkRoot, file, axis) === null
          && axes.has(sessionAxis)) {
        if (axis === BLOCKCHAIN_PLANE_AXIS) {
          violations.push({
            kind: "blockchain_axis_tool_outside_blockchain_directory",
            id: relative,
            detail: `${relative} declares required_session_axes containing ${JSON.stringify(sessionAxis)} but `
              + `does not live below ${TOOLS_DIR}/${axis}/; axis authority and structural membership must agree`,
          });
        } else {
          violations.push({
            kind: "physical_axis_tool_outside_physical_directory",
            id: relative,
            detail: `${relative} declares required_session_axes containing ${JSON.stringify(sessionAxis)} but `
              + `does not live below ${TOOLS_DIR}/${axis}/; axis authority and structural membership must agree`,
          });
        }
      }
    }
  }
  if (planeMembers !== null) {
    reconcilePlaneMembers({ walkRoot, files, members: planeMembers, violations, axis: PLANE_AXIS });
  }
  if (blockchainPlaneMembers !== null) {
    reconcilePlaneMembers({
      walkRoot, files, members: blockchainPlaneMembers, violations, axis: BLOCKCHAIN_PLANE_AXIS,
    });
  }

  // THE IN-ROOT EDGE SET, as walk-root-relative paths, built from the same
  // resolutions the plane rule below is decided on rather than from a second
  // pass. A module with no outgoing in-root edge is still a node, so the graph
  // is seeded from the file listing: a component derived over a graph that only
  // holds importers would silently exclude every leaf.
  const moduleEdges = new Map(files.map((file) => [path.relative(walkRoot, file), new Map()]));
  const recordModuleEdge = (from, to, site) => {
    if (!moduleEdges.has(from)) moduleEdges.set(from, new Map());
    const targets = moduleEdges.get(from);
    if (!targets.has(to)) { targets.set(to, []); measured.inRootEdgePairs += 1; }
    targets.get(to).push({ line: site.line, deferred: site.deferred === true });
  };
  const planePolicies = [
    {
      axis: PLANE_AXIS,
      allowlist,
      layerOf,
      measured,
    },
    {
      axis: BLOCKCHAIN_PLANE_AXIS,
      allowlist: blockchainAllowlist,
      layerOf: layerOfByAxis.get(BLOCKCHAIN_PLANE_AXIS),
      measured: blockchainMeasured,
    },
  ].filter((policy) => policy.allowlist !== null);

  const siteCache = new Map();
  for (const file of files) {
    const relative = path.relative(walkRoot, file);
    let sites;
    try {
      sites = readSites(file, relative, siteCache);
    } catch (err) {
      if (!err || err.code !== JS_PARSE_ERROR_CODE) throw err;
      violations.push({
        kind: "unparseable_module",
        id: relative,
        detail: `${relative} cannot be parsed, so its module edges cannot be read: ${err.parse_message}`,
      });
      continue;
    }
    for (const site of sites) {
      if (site.callee_form === REQUIRE_CALLEE_FORMS.REQUIRE_RESOLVE) {
        measured.requireResolveSites += 1;
        continue;
      }
      if (EDGE_CALLEE_FORMS.has(site.callee_form)) measured.edgesWalked += 1;
      if (site.callee_form !== REQUIRE_CALLEE_FORMS.REQUIRE && site.specifier === null) {
        // The reader saw the site but will not answer for its target: an
        // `import()` of an expression, an `x.require()` whose receiver decides
        // the resolution base, or the alias binding that ends this file's
        // completeness guarantee. Keyed by LINE and form so it can never
        // collide with the `${relative} (${argument_type})` key the frozen
        // dynamic allowlist is written in.
        const key = `${relative}:${site.line} (${site.callee_form})`;
        measured.unpoliceableSites.push({ key, callee_form: site.callee_form });
        violations.push({
          kind: "unpoliceable_require_form",
          id: key,
          detail: `${relative}:${site.line} writes a module edge as ${site.callee_form} with a `
            + `${site.argument_type} argument; this gate can see the site but not the target it resolves `
            + `against, so the edge cannot be policed — write it as a bare require of a string literal`,
        });
        continue;
      }
      if (site.specifier === null) {
        const key = `${relative} (${site.argument_type})`;
        measured.dynamicSites.push({ key, line: site.line });
        if (!dynamicAllowlist.has(key)) {
          violations.push({
            kind: "non_static_require_specifier",
            id: key,
            detail: `${relative}:${site.line} requires a ${site.argument_type} specifier, so this edge `
              + `cannot be resolved or policed; make it a string literal or record it as known-unresolvable`,
          });
        }
        continue;
      }
      if (!site.specifier.startsWith(".")) { measured.externalEdges += 1; continue; }
      const target = resolveRelative(file, site.specifier);
      if (target === null) {
        violations.push({
          kind: "unresolvable_require",
          id: `${relative}:${site.line}`,
          detail: `${relative}:${site.line} requires ${JSON.stringify(site.specifier)}, which resolves to no file`,
        });
        continue;
      }
      // RULE THREE, before the in-root split: a member's dependency on a module
      // outside the walk root is as much a dependency as one inside, and this
      // rule asserts an allowed-dependency fact rather than a layer.
      policeSmartContractsEdge({
        root,
        walkRoot,
        importer: file,
        importerRelative: relative,
        target,
        line: site.line,
        internals: smartContractsInternals,
        allowedDependencies: smartContractsAllowedDependencies,
        entrypointExceptions: smartContractsEntrypointExceptions,
        violations,
        measured,
      });
      if (!isInside(walkRoot, target)) {
        // Outside the walk root, so outside the partition: the layer of a
        // module this gate never classified is not a fact it may assert. The
        // subset that leaves core for a bob-instrument-* package is counted
        // anyway, because it is the interesting one and silence about it would
        // read as coverage.
        measured.crossWalkRootEdges += 1;
        if (layerOf.get(file) === "core" && isPlanePackageTarget(root, target)) {
          measured.corePlanePackageEdges.add(`${relative} -> ${path.relative(root, target)}`);
        }
        continue;
      }
      // A target INSIDE the walk root that the walk never classified falls
      // through the core/plane test on an `undefined` layer, which dropped
      // those edges in silence — including ones below domains/physical/. The shared
      // layer decision answers structurally for those; anything it does not
      // name is COUNTED, because the alternative is asserting a layer never
      // derived.
      // RECORDED BEFORE the layer test, and before the core/plane filter below,
      // because the cycle rule is a property of the graph and not of the
      // partition: an edge dropped here for having no derived layer, or for
      // running plane -> plane, is still an edge a component can close through.
      // A target the file listing never reached is a sink — it has no outgoing
      // edges to read — so recording it can only ever add a node no cycle
      // contains, never hide one.
      recordModuleEdge(relative, path.relative(walkRoot, target), site);
      const physicalTargetLayer = targetLayerInsideWalkRoot(target, layerOf, walkRoot, PLANE_AXIS);
      if (physicalTargetLayer === undefined
          && targetLayerInsideWalkRoot(
            target, layerOfByAxis.get(BLOCKCHAIN_PLANE_AXIS), walkRoot, BLOCKCHAIN_PLANE_AXIS,
          ) === undefined) {
        measured.inRootUnwalkedTargets.add(`${relative} -> ${path.relative(walkRoot, target)}`);
        continue;
      }
      const targetRelative = path.relative(walkRoot, target);
      for (const policy of planePolicies) {
        const importerLayer = policy.layerOf.get(file);
        const targetLayer = targetLayerInsideWalkRoot(target, policy.layerOf, walkRoot, policy.axis);
        if (importerLayer !== "core" || targetLayer !== "plane") continue;
        const key = `${relative} -> ${targetRelative}`;
        policy.measured.boundaryEdges.add(key);
        policy.measured.boundaryEdgeFacts.set(key, { importer: relative, target: targetRelative });
        if (!policy.measured.planeTargetImporters.has(targetRelative)) {
          policy.measured.planeTargetImporters.set(targetRelative, new Set());
        }
        policy.measured.planeTargetImporters.get(targetRelative).add(relative);
        if (!policy.allowlist.has(key)) {
          violations.push({
            kind: "core_requires_plane",
            id: key,
            detail: `${relative}:${site.line} requires the ${policy.axis} plane module ${targetRelative}; `
              + `core may not require a plane implementation — route it through a contract, or move the caller`,
          });
        }
      }
    }
  }

  // RULE THREE's reconciliation, over the same edge set the loop above resolved.
  reconcileSmartContracts({
    walkRoot,
    files,
    moduleEdges,
    members: smartContractsMembers,
    internals: smartContractsInternals,
    allowedDependencies: smartContractsAllowedDependencies,
    entrypointExceptions: smartContractsEntrypointExceptions,
    violations,
    measured,
  });

  // RULE TWO, over the edge set the loop above resolved.
  const adjacency = new Map([...moduleEdges].map(([from, targets]) => [from, new Set(targets.keys())]));
  reconcileModuleCycles({
    components: stronglyConnectedComponents(adjacency),
    edgeFacts: moduleEdges,
    cycleAllowlist,
    violations,
    measured,
  });

  const reconcileBoundaryAllowlist = (policy) => {
    const policyAllowlist = policy.allowlist;
    const policyMeasured = policy.measured;
    for (const entry of policyAllowlist.keys()) {
      if (!policyMeasured.boundaryEdges.has(entry)) {
        violations.push({
          kind: "stale_allowlist_entry",
          id: entry,
          detail: policy.axis === PLANE_AXIS
            ? `stale allowlist entry (core -> plane edge no longer in tree): ${entry}`
            : `stale blockchain allowlist entry (core -> plane edge no longer in tree): ${entry}`,
        });
      }
    }
    for (const [entry, adjudication] of policyAllowlist) {
      if (typeof adjudication !== "string" || adjudication === "") {
        violations.push({
          kind: "unclassified_allowlist_entry",
          id: entry,
          detail: `${policy.axis} allowlist entry carries no adjudication class: ${entry}; every entry must be one of `
            + `${BOUNDARY_ADJUDICATION_CLASSES.join(", ")}`,
        });
        continue;
      }
      if (!BOUNDARY_ADJUDICATION_CLASSES.includes(adjudication)) {
        violations.push({
          kind: "unknown_adjudication_class",
          id: entry,
          detail: `${policy.axis} allowlist entry ${entry} is classed ${JSON.stringify(adjudication)}, which is `
            + `outside the frozen vocabulary ${BOUNDARY_ADJUDICATION_CLASSES.join(", ")}`,
        });
        continue;
      }
      policyMeasured.adjudication.set(adjudication, policyMeasured.adjudication.get(adjudication) + 1);
    }
    for (const [key, { importer, target }] of policyMeasured.boundaryEdgeFacts) {
      const adjudication = policyAllowlist.get(key);
      if (adjudication === "composition_root" && importer !== COMPOSITION_ROOT_MODULE) {
        violations.push({
          kind: "misclassified_composition_root",
          id: key,
          detail: `${key} is classed composition_root, but the walk read its importer as ${importer}, not `
            + `${COMPOSITION_ROOT_MODULE}; only the composition root may name concrete plane modules`,
        });
      }
      if (adjudication === "consolidatable_not_taken") {
        const siblings = [...(policyMeasured.planeTargetImporters.get(target) || [])]
          .filter((other) => other !== importer && policyAllowlist.has(`${other} -> ${target}`));
        if (siblings.length < 2) {
          violations.push({
            kind: "misclassified_consolidatable",
            id: key,
            detail: `${key} is classed consolidatable_not_taken, but the walk found ${siblings.length} other `
              + `allowlisted core importer(s) of ${target}; collapsing duplicates needs at least two, so this `
              + `edge duplicates nothing and the class is wrong`,
          });
        }
      }
    }
  };
  for (const policy of planePolicies) reconcileBoundaryAllowlist(policy);

  Object.assign(blockchainMeasured, {
    filesWalked: measured.filesWalked,
    edgesWalked: measured.edgesWalked,
    crossWalkRootEdges: measured.crossWalkRootEdges,
    corePlanePackageEdges: new Set(),
    dynamicSites: measured.dynamicSites,
  });
  Object.defineProperties(blockchainMeasured, {
    computedSpecifierSites: { get() { return this.dynamicSites.length; } },
    corePlanePackageEdgeCount: { get() { return this.corePlanePackageEdges.size; } },
  });

  if (inventory !== null) {
    reconcileSeamInventory({
      root, walkRoot, inventory, layerOf, planeAxis: PLANE_AXIS, siteCache,
      unbindableCitations, violations, measured,
    });
  }
  if (blockchainInventory !== null) {
    reconcileSeamInventory({
      root,
      walkRoot,
      inventory: blockchainInventory,
      layerOf: layerOfByAxis.get(BLOCKCHAIN_PLANE_AXIS),
      planeAxis: BLOCKCHAIN_PLANE_AXIS,
      siteCache,
      unbindableCitations: blockchainUnbindableCitations,
      violations,
      measured: blockchainMeasured,
    });
  }
  for (const entry of dynamicAllowlist) {
    if (!measured.dynamicSites.some((site) => site.key === entry)) {
      violations.push({
        kind: "stale_dynamic_allowlist_entry",
        id: entry,
        detail: `stale allowlist entry (computed require no longer in tree): ${entry}`,
      });
    }
  }

  return { violations, measured };
}

// The unresolvable site FORMS, per form, so the exclusion is a breakdown rather
// than one opaque total. Empty renders as "none" instead of an empty bracket.
function unpoliceableHistogram(measured) {
  const counts = new Map();
  for (const site of measured.unpoliceableSites) {
    counts.set(site.callee_form, (counts.get(site.callee_form) || 0) + 1);
  }
  if (counts.size === 0) return "none";
  return [...counts].sort((a, b) => (a[0] < b[0] ? -1 : 1)).map(([form, n]) => `${n} ${form}`).join(", ");
}

// The dependency-class split, derived from the frozen vocabulary rather than
// listed, so a fourth class arrives in the note by itself.
function smartContractsDependencyHistogram(measured) {
  return SMART_CONTRACTS_DEPENDENCY_CLASSES
    .map((name) => `${measured.smartContractsDependencyClasses.get(name)} ${name}`)
    .join(", ");
}

// What this gate covers and what it deliberately does not. Printed on BOTH the
// OK line and the failure header so the exclusions are visible rather than
// silent — an exclusion nobody can see reads as coverage.
function coverageNote(measured) {
  const blockchain = measured.blockchain;
  const histogram = BOUNDARY_ADJUDICATION_CLASSES
    .map((name) => `${measured.adjudication.get(name)} ${name}`)
    .join(", ");
  const total = BOUNDARY_ADJUDICATION_CLASSES
    .reduce((sum, name) => sum + measured.adjudication.get(name), 0);
  return [
    `walked ${measured.walkRoot} (${measured.filesWalked} .js file(s): `
      + `${measured.coreModules} core, ${measured.planeModules} plane; `
      + `${measured.edgesWalked} require site(s))`,
    // Emitted because the seam doc cites it. A number a document attributes to
    // this checker has to come OUT of this checker: the doc previously carried
    // "from 20 distinct core files" under that attribution while nothing here
    // produced it, which is the asserted-as-derived defect the doc exists to
    // prevent. Derived from the same edge keys the adjudication counts.
    `${total} edge(s) from ${measured.boundaryImporters} distinct core file(s)`,
    // THE CYCLE CENSUS. The deferred count is printed HERE, next to the cycle it
    // fails to break, rather than in the exclusions below: a reader who sees
    // that most of the component's edges are already written inside function
    // bodies can tell that deferral was tried and bought nothing.
    `module cycles: ${measured.cycleCount} over ${measured.filesInCyclesCount} of ${measured.filesWalked} `
      + `walked module(s) (${measured.inRootEdgePairs} in-root edge pair(s); largest cycle `
      + `${measured.largestCycle}; ${measured.cycleInternalEdges} in-cycle edge(s), of which `
      + `${measured.cycleDeferredEdges} are written ONLY inside a function body — deferred, and therefore `
      + `still edges) [${measured.moduleCycles.map((c) => `${c.representative} +${c.size - 1}`).join("; ") || "none"}]`,
    `adjudication of ${total} allowlisted edge(s): ${histogram}`,
    `blockchain plane: ${blockchain.coreModules} core, ${blockchain.planeModules} plane; `
      + `${blockchain.boundaryEdges.size} edge(s) from ${blockchain.boundaryImporters} distinct core file(s); `
      + `adjudication: ${BOUNDARY_ADJUDICATION_CLASSES.map((name) => (
        `${blockchain.adjudication.get(name)} ${name}`
      )).join(", ")}`,
    // RULE THREE, derived on every run rather than written in a comment. The
    // two exception counts are printed beside the edge counts they police so a
    // reader can see the admission test the directory was moved under: an
    // exception list drifting toward its edge count is the boundary becoming
    // the old graph rewritten.
    `${SMART_CONTRACTS_DIR}/: ${measured.smartContractsMemberCount} member(s) `
      + `(${measured.smartContractsPublicCount} public, ${measured.smartContractsInternalCount} internal with `
      + `NO exception list); ${measured.smartContractsDependencyCount} allowed dependenc(ies) over `
      + `${measured.smartContractsDependencyEdges.size} outbound edge(s) `
      + `[${smartContractsDependencyHistogram(measured)}]; ${measured.smartContractsInboundEdges.size} inbound `
      + `edge(s) = ${measured.smartContractsToolsEdgeCount} derived from ${TOOLS_DIR}/ + `
      + `${measured.smartContractsEntrypointCount} recorded entry point(s)`,
    measured.inventoryPath === null
      ? "seam inventory: not bound (--no-inventory)"
      : `seam inventory ${measured.inventoryPath}: ${measured.inventoryRows} row(s) = `
        + `${measured.inventoryPoliced} policed + ${measured.inventoryCrossPackage} cross-package + `
        + `${measured.inventoryPlaneToPlane} plane -> plane`,
    blockchain.inventoryPath === null
      ? "blockchain seam inventory: not bound (--no-inventory)"
      : `blockchain seam inventory ${blockchain.inventoryPath}: ${blockchain.inventoryRows} row(s) = `
        + `${blockchain.inventoryPoliced} policed + ${blockchain.inventoryCrossPackage} cross-package + `
        + `${blockchain.inventoryPlaneToPlane} plane -> plane`,
    // THE CITATION CENSUS, printed for the same reason the edge count is: the
    // doc's own claim about how much of it is checked is a claim about the code,
    // and this line is where it is answered with a number instead of a promise.
    measured.inventoryPath === null
      ? "seam citations: not bound (--no-inventory)"
      : `seam citations: ${measured.seamCitations} cite(s) = ${measured.inventoryRowCites} inventory row + `
        + `${measured.toolSplitRegistrations} tool-split registration (of ${measured.toolSplitTools} row(s): `
        + `${measured.toolSplitPlaneTools} plane, ${measured.toolSplitCoreTools} core) + `
        + `${measured.symbolAnchoredCites} symbol-anchored + ${measured.echoedCites} echo of an inventoried `
        + `site + ${measured.unbindableCites} occurrence(s) of ${measured.unbindableCitationSites.size} `
        + `unbindable site(s) [${[...measured.unbindableCitationSites].sort().join("; ") || "none"}]`,
    `NOT enforced: (1) string-keyed coupling — the "${PLANE_AXIS}" pack id, the `
      + `"${PLANE_AXIS}" session axis, the "evaluator-${PLANE_AXIS}" role bundle, and plane `
      + `tool-name literals in generated manifests and authority maps are behavior a `
      + `require-scan cannot see; (2) ${measured.crossWalkRootEdges} edge(s) leaving the walk `
      + `root, of which ${measured.corePlanePackageEdges.size} run from core into a plane-named `
      + `package — OUT of scope by decision, because the layer partition is defined over modules `
      + `INSIDE the walk root and this gate may not assert a layer it never derived `
      + `[${[...measured.corePlanePackageEdges].sort().join("; ")}]; `
      + `(3) ${measured.dynamicSites.length} computed require specifier(s), named rather than `
      + `resolved, plus ${measured.unpoliceableSites.length} site(s) whose FORM the reader will not `
      + `resolve [${unpoliceableHistogram(measured)}] and ${measured.requireResolveSites} `
      + `require.resolve(...) probe(s) — excluded because require.resolve asks where a module WOULD `
      + `be and this tree uses it only to test for an installed package, so it is not a module edge `
      + `and is not counted as one; (4) importers outside ${measured.walkRoot} — scripts/ and test/ also require `
      + `plane modules and are not walked, and the same silence covers RULE THREE: a suite that requires a `
      + `${SMART_CONTRACTS_DIR}/ internal is outside this walk, so INTERNAL here means internal to the runtime `
      + `graph, not unreachable from a test; (5) three of the four adjudication classes are HUMAN `
      + `judgements carried from the seam audit, not derived facts — only composition_root is `
      + `re-derived from the walk, and the necessary condition checked for consolidatable_not_taken `
      + `is not a derivation of it, so control_flow_core, plane_value_import, and `
      + `consolidatable_not_taken are labels to be argued with, not proofs; `
      + `(6) ${measured.inRootUnwalkedTargets.size} require target(s) INSIDE ${measured.walkRoot} that the `
      + `walk never classified — the file listing is .js and CommonJS resolution is not, so a resolvable `
      + `.json/.cjs/.mjs target has no walked layer. A target below domains/physical/ is policed by the path arm `
      + `for any extension; the rest are counted here rather than assigned a layer this gate never derived `
      + `[${[...measured.inRootUnwalkedTargets].sort().join("; ")}]; `
      + `(7) the Tool Split DISCRIMINATOR — a tool is SHARED only if a non-physical plane's behavior changes `
      + `when it is absent — is a human judgement no walk derives. Each row's registration, its cited symbols, `
      + `and the plane/core layer of what it registers are checked; which side of that judgement a tool `
      + `belongs on is not; (8) the Reverse Direction section's numbers — the physical footprint's file and `
      + `line totals and its 47/49/42 support-target counts — are credited to no tool and come from a reverse `
      + `walk this gate does not perform. Only that section's ${measured.reverseDirectionRows}-row table is `
      + `bound, and only to its own row count`,
  ].join("\n  ");
}

function main() {
  const args = parseArgs(process.argv);
  const { violations, measured } = runChecks(args);
  if (violations.length === 0) {
    console.log(
      `module-boundaries OK (${measured.boundaryEdges.size} allowlisted core -> plane edge(s), `
      + `${measured.blockchain.boundaryEdges.size} allowlisted core -> blockchain edge(s), 0 new)\n  `
      + `${coverageNote(measured)}`,
    );
    process.exit(0);
  }
  console.error(
    `module-boundaries FAIL (${violations.length} violation${violations.length === 1 ? "" : "s"}):`
    + `\n  ${coverageNote(measured)}`,
  );
  for (const v of violations) console.error(`  - [${v.kind}] ${v.id}: ${v.detail}`);
  process.exit(1);
}

if (require.main === module) {
  try {
    main();
  } catch (err) {
    console.error(err && err.stack ? err.stack : String(err));
    process.exit(2);
  }
}

module.exports = {
  ALLOWLIST_BOUNDARY_VIOLATIONS,
  BLOCKCHAIN_ALLOWLIST_BOUNDARY_VIOLATIONS,
  BLOCKCHAIN_PLANE_AXIS,
  BLOCKCHAIN_PLANE_MEMBERS,
  BLOCKCHAIN_SEAM_INVENTORY_RELPATH,
  ALLOWLIST_DYNAMIC_REQUIRES,
  ALLOWLIST_MODULE_CYCLES,
  BOUNDARY_ADJUDICATION_CLASSES,
  COMPOSITION_ROOT_MODULE,
  PLANE_AXIS,
  PLANE_AXES,
  PLANE_MEMBERS,
  SEAM_CENSUS_PATTERNS,
  SEAM_CITATION_RE,
  SEAM_INVENTORY_RELPATH,
  SEAM_SYMBOL_CITATION_RE,
  SMART_CONTRACTS_ALLOWED_DEPENDENCIES,
  SMART_CONTRACTS_DEPENDENCY_CLASSES,
  SMART_CONTRACTS_DIR,
  SMART_CONTRACTS_ENTRYPOINT_EXCEPTIONS,
  SMART_CONTRACTS_INTERNALS,
  SMART_CONTRACTS_MEMBERS,
  UNBINDABLE_SEAM_CITATIONS,
  classifyModule,
  coverageNote,
  planeMemberOf,
  parseSeamInventoryRows,
  runChecks,
  smartContractsMemberOf,
  stronglyConnectedComponents,
};
