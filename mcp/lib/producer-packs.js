"use strict";

// A pure constants require keeps the "PURE: no I/O at import" header below
// accurate — constants.js has zero requires, so there is no circular dependency.
const { CHAIN_FAMILY_VALUES } = require("./constants.js");

// Pure SSOT producer-pack manifest — a structural sibling of
// capability-packs.js. It describes the recon producer DAG: a single ROOT
// producer triggered by the target_class fans out into DERIVED producers, each
// consuming upstream artifact kinds, terminating in the web_assembly producer
// that synthesizes the web_surface.
//
// The chain plane mirrors that shape on the smart-contract side: the
// chain-front-door root producer emits the chain_address_set seed, which the
// sc_address_expander consumes to synthesize sc_surface. The expander also
// consumes sc_surface and produces sc_surface — the single identity-keyed
// sc_surface self-edge — so each minted contract recursively expands into the
// proxy/diamond/role/linked surfaces it implies.
//
//   producer_id        — stable key, used as the producer's identity
//   producer_version   — manifest version for the producer's contract
//   producer_agent     — recon subagent that runs this producer
//   recon_profile      — { angle, steps } mirroring recon-angle-plan.js
//                        RECON_ANGLES (host_family[2,3,4], urls[5], nuclei[6],
//                        js_jwt[7]); the assembly worker runs once after the
//                        angle workers drain so it carries no numbered step
//   trigger            — { kind: 'root'|'derived', target_class, consumes:[],
//                        input_mode? } root producers fire on a target_class;
//                        derived producers fire when their consumed artifact
//                        kinds exist. input_mode governs the JOIN over consumes:
//                        'all' (the default — every consumed kind must exist, so
//                        a multi-input synthesizer never fires partially) or
//                        'any' (a disjunction for a producer whose inputs are
//                        alternative triggers, e.g. the sc_address_expander)
//   produces           — artifact kinds (from ARTIFACT_KIND_VALUES) emitted
//   emits_surface_types — broad surface-class tags this producer synthesizes
//   scratch_namespace  — per-producer scratch root, single-sourced through
//                        producerScratchNamespace(producer_id)
//   advisory           — false: these packs describe the durable producer DAG
//
// PURE: no clock, random, env, or I/O, and no side effects at import. The same
// inputs yield deep-equal outputs across calls. Deep-frozen exactly like the
// sibling capability-packs.js (per-object and per-array Object.freeze applied
// manually, no shared recursive deepFreeze helper).
//
// NOT wired into any tool and NOT part of the stigmergy-coherence registry —
// this is a sibling of capability-packs.js, not of stigmergic-producers.js.

// Closed vocabulary of artifact kinds the recon producer DAG moves. This frozen
// ordered list is the single source of truth for artifact kinds; producer
// produces/consumes values stay within it.
const ARTIFACT_KIND_VALUES = Object.freeze([
  "target",
  "subdomains",
  "live_hosts",
  "family_live",
  "all_urls",
  "nuclei_results",
  "js_endpoints",
  "js_secrets",
  "jwt_candidates",
  "repo_inventory",
  "chain_address_set",
  "sc_surface",
  "web_surface",
]);

// Membership set for artifact-kind checks (mirrors the WEB_SURFACE_TYPE_SET
// pattern in capability-packs.js). Internal only — not exported.
const ARTIFACT_KIND_SET = new Set(ARTIFACT_KIND_VALUES);

// Fail-loud namespace minter. Hoisted (function declaration) so each pack's
// scratch_namespace can be initialized by calling it at module load, making this
// the only namespace-minting path — runtime per-node namespaces match the static
// pack defaults. Matches the capability-packs assertPackString fail-loud idiom.
function producerScratchNamespace(nodeId) {
  if (typeof nodeId !== "string" || !nodeId) {
    throw new Error("producerScratchNamespace requires a non-empty nodeId");
  }
  return "scratch/" + nodeId + "/";
}

const PRODUCER_AGENT = "surface-discovery-agent";

// Root producer: fires on a web target_class, runs the host_family angle
// (steps 2,3,4), and produces the live-host / family / subdomain artifacts the
// derived producers consume. No upstream artifacts consumed; emits no surface
// type itself (the terminal web_assembly producer synthesizes web_surface).
const WEB_HOST_FAMILY_PRODUCER_PACK = Object.freeze({
  producer_id: "web_host_family",
  producer_version: 1,
  producer_agent: PRODUCER_AGENT,
  recon_profile: Object.freeze({
    angle: "host_family",
    steps: Object.freeze([2, 3, 4]),
  }),
  trigger: Object.freeze({
    kind: "root",
    target_class: "web",
    consumes: Object.freeze([]),
  }),
  produces: Object.freeze(["live_hosts", "family_live", "subdomains"]),
  emits_surface_types: Object.freeze([]),
  scratch_namespace: producerScratchNamespace("web_host_family"),
  advisory: false,
});

// Derived: urls angle (step 5). Consumes the live host sets, produces all_urls.
const WEB_URLS_PRODUCER_PACK = Object.freeze({
  producer_id: "web_urls",
  producer_version: 1,
  producer_agent: PRODUCER_AGENT,
  recon_profile: Object.freeze({
    angle: "urls",
    steps: Object.freeze([5]),
  }),
  trigger: Object.freeze({
    kind: "derived",
    target_class: "web",
    consumes: Object.freeze(["live_hosts", "family_live"]),
  }),
  produces: Object.freeze(["all_urls"]),
  emits_surface_types: Object.freeze([]),
  scratch_namespace: producerScratchNamespace("web_urls"),
  advisory: false,
});

// Derived: nuclei angle (step 6). Consumes the live host sets, produces
// nuclei_results.
const WEB_NUCLEI_PRODUCER_PACK = Object.freeze({
  producer_id: "web_nuclei",
  producer_version: 1,
  producer_agent: PRODUCER_AGENT,
  recon_profile: Object.freeze({
    angle: "nuclei",
    steps: Object.freeze([6]),
  }),
  trigger: Object.freeze({
    kind: "derived",
    target_class: "web",
    consumes: Object.freeze(["live_hosts", "family_live"]),
  }),
  produces: Object.freeze(["nuclei_results"]),
  emits_surface_types: Object.freeze([]),
  scratch_namespace: producerScratchNamespace("web_nuclei"),
  advisory: false,
});

// Derived: js_jwt angle (step 7). Consumes all_urls, produces the JS endpoint /
// secret-shape / JWT-candidate artifacts.
const WEB_JS_JWT_PRODUCER_PACK = Object.freeze({
  producer_id: "web_js_jwt",
  producer_version: 1,
  producer_agent: PRODUCER_AGENT,
  recon_profile: Object.freeze({
    angle: "js_jwt",
    steps: Object.freeze([7]),
  }),
  trigger: Object.freeze({
    kind: "derived",
    target_class: "web",
    consumes: Object.freeze(["all_urls"]),
  }),
  produces: Object.freeze(["js_endpoints", "js_secrets", "jwt_candidates"]),
  emits_surface_types: Object.freeze([]),
  scratch_namespace: producerScratchNamespace("web_js_jwt"),
  advisory: false,
});

// Terminal derived producer: the union/synthesis worker that runs once after the
// angle workers drain (per recon-angle-plan.js), so it carries no numbered
// discovery step. Consumes the eight upstream artifact kinds and produces the
// web_surface, emitting the broad "web" surface-class tag it synthesizes
// (matching the web|smart_contract|oss vocabulary).
const WEB_ASSEMBLY_PRODUCER_PACK = Object.freeze({
  producer_id: "web_assembly",
  producer_version: 1,
  producer_agent: PRODUCER_AGENT,
  recon_profile: Object.freeze({
    angle: "assembly",
    steps: Object.freeze([]),
  }),
  trigger: Object.freeze({
    kind: "derived",
    target_class: "web",
    consumes: Object.freeze([
      "live_hosts",
      "family_live",
      "subdomains",
      "all_urls",
      "nuclei_results",
      "js_endpoints",
      "js_secrets",
      "jwt_candidates",
    ]),
  }),
  produces: Object.freeze(["web_surface"]),
  emits_surface_types: Object.freeze(["web"]),
  scratch_namespace: producerScratchNamespace("web_assembly"),
  advisory: false,
});

// Chain front-door root producer: fires on a non-web (chain) target_class and
// emits the chain_address_set seed the expander consumes. Mirrors the
// web_host_family root shape — consumes nothing, emits no surface type itself —
// so producing chain_address_set keeps the expander's consumption non-orphan
// without minting a forbidden self-edge.
const SC_CHAIN_ROOT_PRODUCER_PACK = Object.freeze({
  producer_id: "sc_chain_root",
  producer_version: 1,
  producer_agent: "sc-recon-expander",
  recon_profile: Object.freeze({
    angle: "chain_root",
    steps: Object.freeze([]),
  }),
  trigger: Object.freeze({
    kind: "root",
    target_class: "smart_contract",
    consumes: Object.freeze([]),
  }),
  produces: Object.freeze(["chain_address_set"]),
  emits_surface_types: Object.freeze([]),
  scratch_namespace: producerScratchNamespace("sc_chain_root"),
  advisory: false,
});

// Derived chain producer: consumes the chain_address_set seed AND sc_surface,
// recursively resolving proxies/diamonds/roles/linked addresses into more
// sc_surface. The sc_surface consume+produce is the single identity-keyed
// self-edge whitelisted by the acyclicity gate. Stamps chain identity onto every
// minted smart_contract surface (Y-D21).
const SC_ADDRESS_EXPANDER_PRODUCER_PACK = Object.freeze({
  producer_id: "sc_address_expander",
  producer_version: 1,
  producer_agent: "sc-recon-expander",
  recon_profile: Object.freeze({
    angle: "sc_expand",
    steps: Object.freeze([]),
  }),
  trigger: Object.freeze({
    kind: "derived",
    target_class: "smart_contract",
    consumes: Object.freeze(["chain_address_set", "sc_surface"]),
    // ANY-of over the EXTERNAL inputs: the chain_address_set seed bootstraps the
    // depth-1 root expansion. The self-produced sc_surface is deliberately NOT a
    // readiness trigger — isProducerReady excludes self-edge kinds — because once a
    // single sc_surface is ever minted it is PERMANENTLY available, so counting it
    // would make the bare expander "ready forever" (a non-structural termination
    // leaning on downstream dedup/caps). The identity-keyed sc_surface recursion
    // instead runs through the per-instance expanders (planScExpanderRecursion),
    // whose readiness IS structural: an instance is proposed iff its on-chain
    // identity is not yet expanded (a non-terminal run-ledger key), so once every
    // source is expanded that readiness goes FALSE — a true fixpoint. 'any' still
    // never JOIN-waits for the sc_surface the expander is itself responsible for.
    input_mode: "any",
  }),
  produces: Object.freeze(["sc_surface"]),
  emits_surface_types: Object.freeze(["smart_contract"]),
  scratch_namespace: producerScratchNamespace("sc_address_expander"),
  advisory: false,
  stamps: Object.freeze(["chain_family", "chain_id"]),
});

// Producer registry keyed by producer_id, mirroring the CAPABILITY_PACKS object.
const PRODUCER_PACKS = Object.freeze({
  web_host_family: WEB_HOST_FAMILY_PRODUCER_PACK,
  web_urls: WEB_URLS_PRODUCER_PACK,
  web_nuclei: WEB_NUCLEI_PRODUCER_PACK,
  web_js_jwt: WEB_JS_JWT_PRODUCER_PACK,
  web_assembly: WEB_ASSEMBLY_PRODUCER_PACK,
  sc_chain_root: SC_CHAIN_ROOT_PRODUCER_PACK,
  sc_address_expander: SC_ADDRESS_EXPANDER_PRODUCER_PACK,
});

// Closed vocabulary of derived-producer input modes. 'all' is the default JOIN
// (every consumed kind must be available); 'any' is the disjunction (one
// available consumed kind suffices). An unknown/absent mode resolves to the
// strict 'all' default so a producer never over-fires on a partial input set.
const PRODUCER_INPUT_MODE_VALUES = Object.freeze(["all", "any"]);

// Pure readiness predicate for a derived producer: given its declared consumed
// artifact kinds, the set of currently-available kinds, and (for a self-edge
// producer) the kinds it itself produces, decide whether its input clause holds.
// THE SINGLE readiness source — both the producer-floor planner (planProducerFloor)
// and, transitively through it, the seed_producers_drained scheduler precondition
// resolve readiness here so the two can never drift. 'all' (the default) is a JOIN:
// every consumed kind must be available, so a multi-input synthesizer (e.g.
// web_assembly's eight inputs) never fires on a partial input set. 'any' is a
// disjunction for a producer whose inputs are alternative triggers (e.g.
// sc_address_expander).
//
// STRUCTURAL SELF-EDGE EXCLUSION: a kind a producer ALSO produces is a self-edge
// input (sc_address_expander consumes AND produces sc_surface). Once a single
// instance of that kind is ever minted it is PERMANENTLY available, so counting it
// toward readiness would make the producer "ready forever" — a non-structural
// termination that leans on downstream dedup/caps to eventually emit nothing rather
// than on readiness itself going false. Readiness therefore rests on the EXTERNAL
// (non-self-produced) inputs ONLY: the sc-expander bootstraps off the external
// chain_address_set seed, and its self-recursion's "ready iff an un-expanded source
// remains" termination is carried STRUCTURALLY by the per-instance run-ledger dedup
// in planScExpanderRecursion, never by this kind-availability predicate. Excluding
// self-produced kinds also strengthens the deadlock fix: the producer never waits on
// — nor is perpetually re-triggered by — the output it is itself responsible for.
//
// An empty consumes set, or one with no external (non-self) input, is never ready
// under either mode (a producer with no external trigger cannot bootstrap itself).
// Closed over no I/O — deterministic.
function isProducerReady(consumes, available, mode = "all", produces = []) {
  const kinds = Array.isArray(consumes) ? consumes : [];
  if (kinds.length === 0) return false;
  const have = available instanceof Set
    ? available
    : new Set(Array.isArray(available) ? available : []);
  const selfProduced = new Set(Array.isArray(produces) ? produces : []);
  const external = kinds.filter((kind) => !selfProduced.has(kind));
  if (external.length === 0) return false;
  if (mode === "any") return external.some((kind) => have.has(kind));
  return external.every((kind) => have.has(kind));
}

// Pure: the single root producer whose trigger fires on this target_class, or
// null. Graceful (never throws) on unknown/missing target_class — this is a
// classification read, not a fail-loud contract check.
function classifyRootProducer({ target_class } = {}) {
  const targetClass = typeof target_class === "string" ? target_class : null;
  if (!targetClass) return null;
  for (const pack of Object.values(PRODUCER_PACKS)) {
    if (pack.trigger.kind === "root" && pack.trigger.target_class === targetClass) {
      return pack;
    }
  }
  return null;
}

// Pure: the derived producers (declaration order) that consume this artifact
// kind. An EMPTY array means a LEAF artifact — no downstream consumer — which is
// NOT a gap/error; the caller decides what an empty result means. An unknown or
// unmapped artifact_kind also returns [] (it simply matches no consumer).
function classifyDerivedProducers(artifact_kind) {
  // An artifact kind outside the closed vocabulary matches no consumer; short
  // out so the [] result is the same "no downstream consumer" leaf signal a
  // known-but-terminal kind (e.g. web_surface) yields.
  if (!ARTIFACT_KIND_SET.has(artifact_kind)) return [];
  return Object.values(PRODUCER_PACKS).filter(
    (pack) => pack.trigger.kind === "derived" && pack.trigger.consumes.includes(artifact_kind),
  );
}

// Closed set of supported chain families (single-sourced from constants.js).
const CHAIN_FAMILY_SET = new Set(CHAIN_FAMILY_VALUES);

// Pure: route a smart_contract surface/lead to its chain producer by chain_family.
// A chain_family in CHAIN_FAMILY_VALUES maps to the sc_address_expander producer;
// a missing or unsupported chain_family is a NAMED, fail-closed producer gap
// (kind: sc_chain_family_unsupported) — NEVER a web fallback. Mirrors the
// classifySurfaceCapability fail-closed stance: a smart_contract surface must
// never be routed to a web evaluator that has no on-chain tools. Graceful: never
// throws (a classification read, not a fail-loud contract check).
function classifyScProducer({ chain_family } = {}) {
  const normalized =
    typeof chain_family === "string" ? chain_family.trim().toLowerCase() : null;
  if (normalized && CHAIN_FAMILY_SET.has(normalized)) {
    return SC_ADDRESS_EXPANDER_PRODUCER_PACK;
  }
  const reason = normalized
    ? `chain_family:${normalized}:unsupported`
    : "chain_family:missing";
  return Object.freeze({
    producer_gap: Object.freeze({
      kind: "sc_chain_family_unsupported",
      reasons: Object.freeze([reason]),
    }),
  });
}

module.exports = {
  ARTIFACT_KIND_VALUES,
  PRODUCER_INPUT_MODE_VALUES,
  PRODUCER_PACKS,
  classifyDerivedProducers,
  classifyRootProducer,
  classifyScProducer,
  isProducerReady,
  producerScratchNamespace,
};
