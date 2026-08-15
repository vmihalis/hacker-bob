"use strict";

const {
  frozenMap,
  frozenSet,
} = require("./shared.js");

// `require()` call sites in mcp whose specifier is computed. The gate cannot
// follow these, so it names them instead of pretending the file has no such
// edge. Frozen and only-shrinking for the same reason as the boundary list: the
// unpoliceable set must not silently grow.
//
// EMPTY, and that is the end state rather than a starting one. Its single entry
// was trace-reading-composer.js requiring a module-scope `const` folded from
// `path.resolve(__dirname, ...)`; the reader now folds that shape, so the edge
// resolves and the entry went stale by this file's own stale-entry check. An
// only-shrinking list is allowed to reach zero.
const ALLOWLIST_DYNAMIC_REQUIRES = frozenSet("ALLOWLIST_DYNAMIC_REQUIRES", []);

// THE CYCLE INVENTORY. Every strongly connected component of the module graph
// that survives today, keyed by its REPRESENTATIVE — the lexicographically first
// member path — and carrying the size the argument was written about plus the
// argument itself.
//
// Keyed by representative rather than by the full member list because the key
// has to be readable and stable, and the size is checked separately: a cycle
// that gained or lost a file fails as `module_cycle_size_drift` even though its
// representative is unchanged. So the pair (representative, size) is as strict
// as listing every member would be, and a reader can still see what the entry
// names. An entry whose argument is empty fails: an inventory of cycles with no
// arguments is the backlog this file already refuses to keep for the plane rule.
//
// Frozen and only-shrinking, same rule as the two lists above.
const ALLOWLIST_MODULE_CYCLES = frozenMap("ALLOWLIST_MODULE_CYCLES", [
  [
    "core/auth-differential-runner.js",
    {
      size: 243,
      argument:
        "PRE-DIP COMPOSITION-RUNTIME CYCLE, re-derived after the N5 runtime-port inversion and registry-manifest fold as 243 members. The component spans "
        + "belief, capability, claims, contract, differential, dispatch, frontier, ledger-integrity, session, "
        + "telemetry, verification, and wave core modules; blockchain, physical, repo, and web domain runtimes; "
        + "and their composition tools. N5 removed nine core-to-physical edges by routing generic capability adapters "
        + "through configured runtime ports. The physical runtime wiring and artifact implementation remain in the "
        + "same live composition component through the tool registry. The eight concept manifests also remain in that "
        + "component, without restoring any of the severed core-to-plane edges: concrete physical and blockchain tools "
        + "are still named only by the established tools/index.js composition root. Deferred requires are still graph "
        + "edges, so the public seam indexes and "
        + "runtime wiring do not themselves split this pre-existing SCC. This records that residual debt honestly.",
    },
  ],
  [
    "core/mechanism/invariant-template-corpus.js",
    {
      size: 2,
      argument:
        "INTRA-MODULE, and therefore blocking no extraction. Both files are members of the same candidate "
        + "module — the mechanism-template group — so the cycle lives entirely inside a boundary anyone would "
        + "draw around them and a directory holding both is acyclic from the outside. "
        + "mechanism-candidate-store.js:32 requires normalizeMechanismTemplate at LOAD time — a candidate is "
        + "only meaningful against the template shape it is scored on. invariant-template-corpus.js:349 "
        + "reaches back for readMechanismCandidates, deferred inside loadRegisteredCandidates so the corpus's "
        + "frozen base stays load-time pure; that deferral does NOT break the cycle and this gate counts the "
        + "edge, which is the honest reading of the comment already written above it. Both directions are "
        + "real: splitting them yields two files neither of which is usable without the other, which states "
        + "the dependency graph worse than the cycle does.",
    },
  ],
]);
// Strongly connected components of size > 1, as sorted member lists, sorted by
// descending size. Tarjan's algorithm, written with an explicit work stack: the
// recursive form is depth-bounded by the longest path in the graph, and the
// component this walks is 120 files deep enough that a gate should not be
// betting on the interpreter's stack.
//
// A singleton is not returned even when it is a self-loop: `require("./self")`
// resolves to the importing file, which is a fact about one module and not a
// boundary anything can be extracted across.
function stronglyConnectedComponents(graph) {
  let counter = 0;
  const index = new Map();
  const lowlink = new Map();
  const onStack = new Set();
  const stack = [];
  const components = [];
  const successorsOf = (node) => [...(graph.get(node) || new Set())].sort();

  for (const root of [...graph.keys()].sort()) {
    if (index.has(root)) continue;
    const work = [[root, 0]];
    index.set(root, counter);
    lowlink.set(root, counter);
    counter += 1;
    stack.push(root);
    onStack.add(root);
    while (work.length > 0) {
      const frame = work[work.length - 1];
      const [node] = frame;
      const successors = successorsOf(node);
      if (frame[1] < successors.length) {
        const next = successors[frame[1]];
        frame[1] += 1;
        if (!index.has(next)) {
          index.set(next, counter);
          lowlink.set(next, counter);
          counter += 1;
          stack.push(next);
          onStack.add(next);
          work.push([next, 0]);
        } else if (onStack.has(next)) {
          lowlink.set(node, Math.min(lowlink.get(node), index.get(next)));
        }
        continue;
      }
      work.pop();
      if (work.length > 0) {
        const parent = work[work.length - 1][0];
        lowlink.set(parent, Math.min(lowlink.get(parent), lowlink.get(node)));
      }
      if (lowlink.get(node) === index.get(node)) {
        const component = [];
        for (;;) {
          const member = stack.pop();
          onStack.delete(member);
          component.push(member);
          if (member === node) break;
        }
        if (component.length > 1) components.push(component.sort());
      }
    }
  }
  return components.sort((a, b) => (b.length - a.length) || (a[0] < b[0] ? -1 : 1));
}

// Reconcile the derived cycles against the frozen inventory, in both directions.
// A cycle with no entry, an entry with no cycle, an entry whose size no longer
// matches, and an entry with no argument each fail on their own line.
function reconcileModuleCycles({ components, edgeFacts, cycleAllowlist, violations, measured }) {
  const seen = new Set();
  for (const members of components) {
    const representative = members[0];
    measured.moduleCycles.push({ representative, size: members.length, members });
    for (const member of members) measured.filesInCycles.add(member);
    let internalEdges = 0;
    let deferredInternalEdges = 0;
    for (const member of members) {
      for (const target of edgeFacts.get(member) || new Map()) {
        const [to, sites] = target;
        if (!members.includes(to)) continue;
        internalEdges += 1;
        if (sites.every((site) => site.deferred)) deferredInternalEdges += 1;
      }
    }
    measured.cycleInternalEdges += internalEdges;
    measured.cycleDeferredEdges += deferredInternalEdges;
    if (members.length > measured.largestCycle) measured.largestCycle = members.length;

    const entry = cycleAllowlist.get(representative);
    if (entry === undefined) {
      violations.push({
        kind: "unrecorded_module_cycle",
        id: representative,
        detail: `${members.length} module(s) in ${measured.walkRoot} form a dependency cycle that the frozen `
          + `inventory does not record: ${members.join(", ")}. A module cannot be extracted across a cycle, so `
          + `either break it or record it under its first member with the argument for why it is irreducible`,
      });
      continue;
    }
    seen.add(representative);
    if (typeof entry.argument !== "string" || entry.argument.trim() === "") {
      violations.push({
        kind: "unargued_module_cycle",
        id: representative,
        detail: `the cycle inventory records ${representative} but carries no irreducibility argument for it; `
          + `a list of cycles with no arguments is a backlog, and this list is a record of decisions`,
      });
    }
    if (entry.size !== members.length) {
      violations.push({
        kind: "module_cycle_size_drift",
        id: representative,
        detail: `the cycle inventory records ${representative} as a ${entry.size}-module cycle and the walk `
          + `measured ${members.length}: ${members.join(", ")}. The argument was written about the smaller set, `
          + `so re-derive it and rewrite the argument rather than moving the number`,
      });
    }
  }
  for (const representative of cycleAllowlist.keys()) {
    if (seen.has(representative)) continue;
    violations.push({
      kind: "stale_cycle_entry",
      id: representative,
      detail: `stale cycle inventory entry (no cycle in ${measured.walkRoot} is now represented by `
        + `${representative}); the list only shrinks, so drop the entry`,
    });
  }
}

module.exports = {
  ALLOWLIST_DYNAMIC_REQUIRES,
  ALLOWLIST_MODULE_CYCLES,
  reconcileModuleCycles,
  stronglyConnectedComponents,
};
