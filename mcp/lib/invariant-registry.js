"use strict";

// CR-4 — Canonical invariant registry.
//
// Single source-of-truth mapping every correctness-vocabulary TAG used in the
// tree (S*, I*, C*, X.*, Y-P*, Y-D*, Y-R*) to a definition and an enforcing
// site. scripts/check-invariant-registry.js orphan-checks both directions:
//   (a) tag->registry: every found tag resolves to an entry here (or to
//       ALLOWLIST_UNDOCUMENTED — the backlog of tags not yet written up).
//   (b) registry->site: every entry.enforced_by[*] {file, symbol} resolves to
//       a real file containing that literal symbol.
//
// NAMESPACE COLLISION: the bare S/C/I tokens (I6, S3, C2, …) are reused across
// unrelated planes (lifecycle vs capability-hypergraph vs causal-belief). To
// avoid mis-binding a docs-prose homonym to an enforcing entry, the S/C/I
// families are matched ONLY in anchored comment form (`// I6`, `/* S14`,
// `* C10`, `# I9`). Unique-shape families (Y-P*, Y-D*, Y-R*, X-P*, C.n, X.n)
// are matched prose-wide because their shape does not collide. See TAG_GRAMMAR.
//
// kind: "invariant"  -> must have >=1 live enforced_by {file, symbol}.
// kind: "label"      -> cycle/plane provenance only; tag->registry only.
//
// ADDING A TAG: add the entry here AND anchor the tag string at the enforcing
// site. For an S/C/I tag the anchor MUST be a comment (`// <tag>`), or the scan
// will not see it. Do NOT widen ALLOWLIST_UNDOCUMENTED to dodge this — the
// allowlist only shrinks.

const TAG_GRAMMAR = Object.freeze({
  // Unique-shape families: matched anywhere (prose or code). Their token shape
  // does not collide with English words or generic identifiers.
  uniquePatterns: Object.freeze([
    /\bY-[PDR]\d+[a-z]?\b/g, // Y-P13a, Y-D15b, Y-R22
    /\b[CX]\.\d+[a-z]?\b/g, //  C.7, X.10  (dotted cycle labels)
    /(?<![A-Za-z0-9_])X-P\d+\b/g, // X-P8 (plane-X invariant)
  ]),
  // S/C/I families: collision-prone bare tokens. Matched ONLY as a leading
  // comment token so docs-prose homonyms (I6 the capability node, C2 the C&C
  // mention) never resolve to a lifecycle/path invariant. One capture group:
  // the tag. Allows an optional single CR-4-style prefix word ("// CR-4 I6").
  sciCommentPattern:
    /(?:^|\s)(?:\/\/|\/\*|\*|#)\s*(?:[A-Za-z0-9-]+\s+)?((?:S|C|I)\d{1,2}[a-z]?)(?![A-Za-z0-9_])/gm,
});

const REGISTRY = Object.freeze({
  // ── Lifecycle (I6 — the reopenability back-edges) ───────────────────────
  "I6": Object.freeze({
    kind: "invariant",
    class: "lifecycle",
    title:
      "Lifecycle reopenability: CLAIM_FREEZE/VERIFY/GRADE/REPORT may back-edge "
      + "to OPEN_FRONTIER (operator re-entry). Removing a back-edge is a "
      + "breaking state-machine change, not a cleanup.",
    enforced_by: Object.freeze([
      Object.freeze({ file: "mcp/lib/lifecycle-gates.js", symbol: "ALLOWED_TRANSITIONS" }),
      Object.freeze({ file: "mcp/lib/lifecycle-gates.js", symbol: "I6" }), // tag anchor
    ]),
  }),

  // ── Audit-graded path enforcement (Y-P13 family) ────────────────────────
  "Y-P13": Object.freeze({
    kind: "invariant",
    class: "audit_graded_paths",
    title: "Audit-graded session paths are MCP-rendered; agents never Write them.",
    enforced_by: Object.freeze([
      Object.freeze({ file: "mcp/lib/paths.js", symbol: "AUDIT_GRADED_PATHS" }),
      Object.freeze({ file: "mcp/lib/paths.js", symbol: "isAuditGradedPath" }),
    ]),
  }),
  "Y-P13a": Object.freeze({
    kind: "invariant",
    class: "audit_graded_paths",
    title: "Operator-amendment path for audit-graded report prose.",
    enforced_by: Object.freeze([
      Object.freeze({ file: "mcp/lib/paths.js", symbol: "report-amendments.jsonl" }),
    ]),
  }),

  // ── Differential-control invariant (S14) ────────────────────────────────
  // enforced_by points at a symbol that is UNIQUE to S14 enforcement, not the
  // generic `checkout` arg. `assertContainerCheckoutDest` is the run-scoped
  // /src-vs-/work boundary guard for the S14 differential checkout, anchored
  // by the `// S14 control replay …` comment in repo-env.js. The anchored-
  // comment scan resolves S14 -> repo-env.js via that comment.
  "S14": Object.freeze({
    kind: "invariant",
    class: "oss_differential",
    title:
      "Differential control: refuse shallow/absent refs, /src read-only, "
      + "run-scoped control checkout under /work, bind exploit replay hash.",
    enforced_by: Object.freeze([
      Object.freeze({ file: "mcp/lib/repo-env.js", symbol: "assertContainerCheckoutDest" }),
      Object.freeze({ file: "mcp/lib/repo-env.js", symbol: "S14" }), // tag anchor (repo-env.js comment)
    ]),
  }),

  // ── Frontier producer-boundary integrity (Y-D21) ────────────────────────
  // The append funnel is the cheapest fail-closed boundary every surface.observed
  // emitter flows through. Enforcing the smart_contract => chain_family pairing
  // here turns a far-downstream, provenance-free capability-routing throw into a
  // located append-time rejection that can never poison the surface set.
  "Y-D21": Object.freeze({
    kind: "invariant",
    class: "frontier_integrity",
    title:
      "Producer-boundary surface integrity: a surface.observed event whose "
      + "surface_type is smart_contract MUST carry a known chain_family (one of "
      + "CHAIN_FAMILY_VALUES), enforced fail-closed at append time so a dropped "
      + "field cannot poison surface-index.json or detonate as a provenance-free "
      + "routing INTERNAL_ERROR.",
    enforced_by: Object.freeze([
      Object.freeze({ file: "mcp/lib/frontier-events.js", symbol: "assertSmartContractChainFamily" }),
    ]),
  }),
});

// Backlog: tags that EXIST in the tree but do not yet have a written registry
// entry. The orphan-check accepts these (tag->registry passes) but the list is
// frozen and only shrinks — adding to it requires a maintainer to consciously
// defer documentation. Seeded once via
// `node scripts/check-invariant-registry.js --seed-allowlist` and checked in
// verbatim.
// Object.freeze on a Set does NOT block Set.prototype.add/delete (freezing only
// affects own properties, not internal [[SetData]]). Harden mutators to throw so
// the allowlist is genuinely immutable — it only shrinks via source edits.
function frozenSet(values) {
  const s = new Set(values);
  const block = () => { throw new TypeError("ALLOWLIST_UNDOCUMENTED is immutable"); };
  s.add = block;
  s.delete = block;
  s.clear = block;
  return Object.freeze(s);
}

const ALLOWLIST_UNDOCUMENTED = frozenSet([
  "C.1", "C.2", "C.3", "C.4", "C.5", "C.6", "C.7", "C10",
  "C11", "C12", "C13", "C14", "C15", "C16", "C17", "C2",
  "C9", "I10", "I11", "I12", "I13", "I9", "S11", "S12",
  "S13", "S15", "S2", "S3", "S4", "S4b", "S5", "S6",
  "X-P1", "X-P2", "X-P3", "X-P4", "X-P5", "X-P6", "X-P7", "X-P8",
  "X-P9", "X.1", "X.10", "X.11", "X.12", "X.2", "X.3", "X.4",
  "X.5", "X.6", "X.7", "X.8", "X.9", "Y-D11", "Y-D12", "Y-D13",
  "Y-D14", "Y-D15", "Y-D15a", "Y-D15b", "Y-D15c", "Y-D16", "Y-D17", "Y-D18",
  "Y-D19", "Y-D2", "Y-D20", "Y-D5", "Y-D6", "Y-D7", "Y-D7c", "Y-D9",
  "Y-P1", "Y-P10", "Y-P11", "Y-P12", "Y-P13b", "Y-P13c", "Y-P13d", "Y-P14",
  "Y-P14a", "Y-P14b", "Y-P14c", "Y-P14d", "Y-P14e", "Y-P2", "Y-P3", "Y-P4",
  "Y-P5", "Y-P6", "Y-P7", "Y-P8", "Y-P9", "Y-R17", "Y-R20", "Y-R21",
  "Y-R22", "Y-R24", "Y-R27",
]);

function knownTags() {
  return new Set(Object.keys(REGISTRY));
}

function enforcingSites() {
  const out = [];
  for (const [tag, entry] of Object.entries(REGISTRY)) {
    if (entry.kind !== "invariant") continue;
    for (const site of entry.enforced_by) out.push({ tag, ...site });
  }
  return out;
}

// Self-closure support: the files that legitimately embed every REGISTRY key as
// a string literal (and therefore MUST be excluded from the tag scan, or they
// would trivially "resolve" every tag and mask real orphans). The driver
// asserts that scanning ANY file NOT in this set never produces a key-as-string
// false hit for the registry's own keys — i.e. SELF_FILES is complete. See
// scripts/check-invariant-registry.js::assertSelfFilesComplete.
const SELF_FILES = Object.freeze([
  "mcp/lib/invariant-registry.js",
  "scripts/check-invariant-registry.js",
  "test/invariant-registry-orphan.test.js",
]);

module.exports = Object.freeze({
  REGISTRY,
  TAG_GRAMMAR,
  ALLOWLIST_UNDOCUMENTED,
  SELF_FILES,
  knownTags,
  enforcingSites,
});
