"use strict";

const fs = require("fs");
const path = require("path");
const {
  TECHNIQUE_ATTEMPT_LOG_MAX_RECORDS,
  TECHNIQUE_ATTEMPT_STATUS_VALUES,
  TECHNIQUE_PACK_READ_LOG_MAX_RECORDS,
} = require("./constants.js");
const {
  assertEnumValue,
  assertInteger,
  assertNonEmptyString,
  assertRequiredText,
  normalizeOptionalInteger,
  normalizeOptionalText,
  parseAgentId,
  parseWaveId,
} = require("./validation.js");
const {
  currentSurfaces,
} = require("./frontier-projections.js");
const {
  validateAssignedWaveAgentSurface,
} = require("./assignments.js");
const {
  techniqueAttemptsJsonlPath,
  techniquePackReadsJsonlPath,
  surfaceRoutesPath,
} = require("./paths.js");
const {
  classifySurfaceCapability,
  getCapabilityPack,
  normalizeContextBudget,
} = require("./capability-packs.js");
const {
  readSurfaceRoutesStrict,
} = require("./surface-router.js");
const {
  appendJsonlLine,
  readFileUtf8,
  withSessionLock,
} = require("./storage.js");
const {
  safeAppendPipelineEventDirect,
} = require("./pipeline-events.js");
const {
  safeGovernanceContextForDomain,
} = require("./governance-context.js");
const {
  resourceCandidatePaths,
} = require("./runtime-resources.js");
const {
  ERROR_CODES,
  ToolError,
} = require("./envelope.js");

const EVALUATOR_KNOWLEDGE_FILE = Object.freeze(["knowledge", "evaluator-techniques.json"]);
const EVALUATOR_KNOWLEDGE_DEFAULT_ID = "generic-rest-api";
const EVALUATOR_KNOWLEDGE_MAX_ENTRIES = 4;
const EVALUATOR_KNOWLEDGE_MAX_CHARS = 4500;
const TECHNIQUE_PACK_ID_RE = /^[A-Za-z][A-Za-z0-9_-]{0,127}$/;

// ── Plane O Cycle O.6 — OSS technique-pack content ──────────────────────────
// Seven OSS technique packs with hunting vocabulary carried in `summary`
// content (per Reviewer D's carry-back: heuristics live in pack content, not
// role-prompt prose). Each pack declares `lens_affinity` so future brief
// renderers can foreground packs for the matching OSS task lens.
//
// These packs do NOT flow through `getCapabilityPack(capability_pack)` — the
// "oss" capability_pack is not registered yet (cycle O.9 wires the orchestrator
// branch and any registry entries it needs). Instead they live as JS-defined
// records exposed via the OSS_TECHNIQUE_PACKS export so the brief renderer
// (under the `profile: "oss"` slice registry) and tests can read them
// directly.
//
// Spec wording was deliberate: native-code pack carries the FULL MVP bug-class
// vocabulary in its `summary` so tests can grep for "bounds checks" /
// "double-free" / "use-after-free" against pack content without needing the
// vocabulary to be hard-coded in evaluator-techniques.json.
const OSS_TECHNIQUE_PACKS = Object.freeze([
  Object.freeze({
    id: "oss_dependency",
    title: "OSS dependency triage",
    lens_affinity: Object.freeze(["taint_trace"]),
    summary: "Lockfile drift, vendored fork without security backports, manifest-declared vs resolved version, transitive dependency with known CVE reaching app code via call graph.",
  }),
  Object.freeze({
    id: "oss_native_code",
    title: "OSS native-code vulnerabilities",
    lens_affinity: Object.freeze(["taint_trace", "fuzz_run"]),
    summary: "bounds checks, integer truncation, signed/unsigned conversion, allocation-size math, NUL/path handling, state-machine confusion, lifetime/ownership mistakes, double-free/use-after-free, attacker-controlled network/file input reaching parser sites. For NFS/XDR/protocol projects: map data path from packet/file/API input to exact parser or state transition before recording; name file, function/symbol, controlling fields, impact if malformed.",
  }),
  Object.freeze({
    id: "oss_api_schema",
    title: "OSS API schema enforcement",
    lens_affinity: Object.freeze(["code_surface_scout", "taint_trace"]),
    summary: "OpenAPI/GraphQL schema in repo, server-side enforcement gaps vs declared schema, type-confusion via inheritance or polymorphism in handlers.",
  }),
  Object.freeze({
    id: "oss_authz",
    title: "OSS authorization gaps",
    lens_affinity: Object.freeze(["taint_trace"]),
    summary: "Decorator/middleware auth that's bypassable, role-check happens only in one of two callers, server-trusted client claims, IDOR in handlers.",
  }),
  Object.freeze({
    id: "oss_ci_cd",
    title: "OSS CI/CD pipeline review",
    lens_affinity: Object.freeze(["code_surface_scout"]),
    summary: "Workflow secrets via pull_request_target, malicious test runners on PR, GITHUB_TOKEN over-permissioning, third-party action without SHA pin.",
  }),
  Object.freeze({
    id: "oss_secrets_config",
    title: "OSS committed secrets and config misuse",
    lens_affinity: Object.freeze(["code_surface_scout"]),
    summary: "Committed credentials, weak crypto defaults, debug flags committed, .env in tree, history-purged secrets still recoverable.",
  }),
  Object.freeze({
    id: "oss_docs_behavior",
    title: "OSS docs-vs-behavior divergence",
    lens_affinity: Object.freeze(["code_surface_scout"]),
    summary: "Docs claim X but code does Y — rate-limit docs vs enforced limit, auth docs vs hard-coded admin email check.",
  }),
]);

// ── Plane X Cycle X.5 — cross-stack identity-handoff technique pack ────────
// Carries the hunting vocabulary that exercises the X.5 / X.11 cross-stack
// thesis (the "Nike fix"): off-chain identity asserted by an auth artifact
// (JWT / signed envelope) must propagate to on-chain identity in a way the
// on-chain code can rely on without trust. Most cross-stack bugs live in the
// silent assumption that "the wallet I see in tx is the same principal that
// minted the JWT". `lens_affinity` covers the X.3 transition surface kinds
// directly so the X.8 brief renderer can foreground this pack whenever the
// dispatched node is a Transition (X.5 derivePackForNode UNION-includes it
// for every Transition; the lens_affinity surfaces it for Surface and
// Hypothesis briefs that touch identity_propagation / trust_handoff
// adjacency too).
//
// Per X-P9 the `summary` is the brief-inlinable form; `full` keeps the
// production-grade prompt the brief renderer pulls when the operator opts
// into full-pack reads. Both stay short — under the 280-char invariant /
// 512-char trust_assumption prose discipline applied across Plane X — so a
// transition brief with this pack stays under the X-P9 brief budget by
// construction.
const WEB3_IDENTITY_HANDOFF_TECHNIQUE_PACK = Object.freeze({
  id: "web3_identity_handoff",
  title: "Cross-stack identity / trust handoff",
  lens_affinity: Object.freeze([
    "identity_propagation",
    "value_movement",
    "trust_handoff",
    "state_dependency",
    "oracle_dependency",
    "message_passing",
  ]),
  summary:
    "token-to-wallet correlation, off-chain auth assumption used as on-chain trust, signature recovery accepting forged eth_sign, meta-transaction replay, gas relayer permission escalation, message-bridge validator threshold under-set.",
  full:
    "Cross-stack identity / trust handoff hunting checklist:\n"
    + "- token-to-wallet correlation: does the JWT.sub (or session principal) match the on-chain msg.sender / recovered signer? Mismatch = identity-propagation bug.\n"
    + "- off-chain auth assumption used as on-chain trust: contract accepts an action because some off-chain service signed for it (oracle, relayer, custodian) — does the contract verify a signature bound to the OFF-CHAIN identity?\n"
    + "- signature recovery accepting forged eth_sign: ecrecover over user-controlled prefix bytes; \\x19Ethereum Signed Message:\\n vs EIP-712 vs raw — wrong prefix → cross-domain replay.\n"
    + "- meta-transaction replay: nonce per (signer, relayer) vs per signer; chainId binding; deadline; same signature replayable on fork chain.\n"
    + "- gas relayer permission escalation: relayer wraps user-signed payload but adds its own privileged calldata after the boundary check.\n"
    + "- message-bridge validator threshold under-set: validator set / DVN threshold defined off-chain or by a role that can be re-keyed without a freeze period.\n"
    + "Witness this with relational_value_match: left = off-chain artifact (http_record, JWT.sub or signed envelope.signer), right = on-chain artifact (evm_call, recover_signer result or msg.sender). op: eq.",
});

// ── Plane X Cycle X.11 — per-transition-kind hunting vocabulary ────────────
// The X-D3 closed enum of six transition_kind values each has its own
// focused hunting vocabulary derived from WEB3_IDENTITY_HANDOFF_TECHNIQUE_PACK.
// X.11 brief composition foregrounds the per-kind vocab when rendering a
// Transition node brief so the agent doesn't have to mentally pattern-match
// the combined summary against the specific transition_kind they were
// dispatched against. Each entry stays under the 512-char prose discipline
// (X-P9) so a Transition brief with all six hunting bullets would still fit
// inside the X-P9 brief budget.
const TRANSITION_KIND_HUNTING_VOCAB = Object.freeze({
  identity_propagation:
    "token-to-wallet correlation: does the JWT.sub (or session principal) match the on-chain msg.sender / recovered signer? Mismatch = identity-propagation bug. Off-chain identity asserted in an auth artifact (JWT, signed envelope) must bind to the on-chain identity the contract enforces — a privileged caller hand-off without binding is the canonical bug.",
  value_movement:
    "off-chain auth used as on-chain trust for money movement: a contract that accepts a transfer or mint because some off-chain service signed for it (custodian, relayer, oracle) — does the contract verify a signature bound to the OFF-CHAIN identity that authorized the off-chain leg? Cross-stack value movement bugs hide in the silent assumption that the off-chain auth principal equals the on-chain caller.",
  trust_handoff:
    "trust handoff between off-chain auth and on-chain authority: an off-chain role (admin / operator / oracle owner) maps to an on-chain role without a binding. Check whether the on-chain role can be re-keyed without notice, whether the off-chain role's signing key rotates separately from the on-chain assignment, and whether revoking off-chain access removes the on-chain authority.",
  state_dependency:
    "state read across the off-chain/on-chain boundary: contract reads a state derived off-chain (e.g., committed reward index from an indexer, off-chain order book digest) — does the contract enforce that the off-chain producer's signature is fresh, bound to the contract's expected sequence, and unforgeable? A stale or replayed off-chain state digest accepted on-chain is the canonical bug.",
  oracle_dependency:
    "oracle dependency from a privileged off-chain producer: contract trusts a price / event / signature from a named oracle — does the contract enforce the oracle's signature scheme, freshness, and the off-chain producer's identity binding (NOT just \"this address signed\")? Oracle-stale, oracle-replay, oracle-impersonation each map to a different witness predicate.",
  message_passing:
    "cross-chain / cross-stack message passing: a message routed through a bridge / DVN / relayer carries an off-chain-signed envelope that the destination contract accepts. Check whether the validator threshold is set on-chain (not by an off-chain role), whether the envelope's source-chain identity binds to the destination action, and whether replay across forks / chains is prevented (chainId + nonce + deadline).",
});

// ── Plane X Cycle X.11 — per-transition-kind worked Contract templates ─────
// The X.11 brief composition surfaces a complete relational_value_match
// predicate skeleton per transition_kind so the agent doesn't have to invent
// the shape. Each template names a left artifact_ref + extract_path AND a
// right artifact_ref + extract_path; the agent fills in the real refs from
// their dispatched observations. Templates use placeholder ref ids
// (e.g. `<auth_token_response>`, `<verify_signature>`) so the agent reads
// them as "fill these in" not "use these literal ids".
//
// Per X-P9 each template stays under the X-D4 invariant cap (280 chars per
// invariant statement) so a Transition brief carrying all six templates
// remains under the brief budget.
const TRANSITION_KIND_CONTRACT_TEMPLATES = Object.freeze({
  identity_propagation: Object.freeze({
    invariant:
      "An attacker MUST NOT cause the on-chain msg.sender / recovered signer to differ from the off-chain principal that signed the auth artifact.",
    witness: Object.freeze({
      kind: "relational_value_match",
      predicate: Object.freeze({
        left: Object.freeze({
          artifact_ref: "http_record:<auth_token_response>",
          extract_path: "$.response.body.access_token.payload.sub",
        }),
        op: "eq",
        right: Object.freeze({
          artifact_ref: "evm_call:<verify_signature>",
          extract_path: "$.recovered_signer",
        }),
      }),
    }),
  }),
  value_movement: Object.freeze({
    invariant:
      "An attacker MUST NOT cause an on-chain value-moving call to authorize a recipient that differs from the off-chain authorization's payee.",
    witness: Object.freeze({
      kind: "relational_value_match",
      predicate: Object.freeze({
        left: Object.freeze({
          artifact_ref: "http_record:<authorize_transfer_response>",
          extract_path: "$.response.body.authorized.payee",
        }),
        op: "eq",
        right: Object.freeze({
          artifact_ref: "evm_call:<execute_transfer>",
          extract_path: "$.calldata.recipient",
        }),
      }),
    }),
  }),
  trust_handoff: Object.freeze({
    invariant:
      "An attacker MUST NOT cause the on-chain authority to act under a role whose off-chain holder no longer holds the corresponding off-chain credential.",
    witness: Object.freeze({
      kind: "relational_value_match",
      predicate: Object.freeze({
        left: Object.freeze({
          artifact_ref: "http_record:<current_role_holder>",
          extract_path: "$.response.body.role.holder_address",
        }),
        op: "eq",
        right: Object.freeze({
          artifact_ref: "evm_call:<role_authority_check>",
          extract_path: "$.recovered_signer",
        }),
      }),
    }),
  }),
  state_dependency: Object.freeze({
    invariant:
      "An attacker MUST NOT cause the on-chain contract to accept an off-chain-produced state digest whose freshness, sequence, or signer binding is unverified.",
    witness: Object.freeze({
      kind: "relational_value_match",
      predicate: Object.freeze({
        left: Object.freeze({
          artifact_ref: "http_record:<offchain_state_digest>",
          extract_path: "$.response.body.commitment.digest",
        }),
        op: "eq",
        right: Object.freeze({
          artifact_ref: "evm_call:<onchain_state_read>",
          extract_path: "$.return_value.committed_digest",
        }),
      }),
    }),
  }),
  oracle_dependency: Object.freeze({
    invariant:
      "An attacker MUST NOT cause the on-chain contract to accept an oracle value whose signer identity does not bind to the named oracle's off-chain identity.",
    witness: Object.freeze({
      kind: "relational_value_match",
      predicate: Object.freeze({
        left: Object.freeze({
          artifact_ref: "http_record:<oracle_report_envelope>",
          extract_path: "$.response.body.signer_address",
        }),
        op: "eq",
        right: Object.freeze({
          artifact_ref: "evm_call:<oracle_verification>",
          extract_path: "$.recovered_signer",
        }),
      }),
    }),
  }),
  message_passing: Object.freeze({
    invariant:
      "An attacker MUST NOT cause a destination-chain action to be authorized by a source-chain envelope whose source-chain identity does not bind to the destination action.",
    witness: Object.freeze({
      kind: "relational_value_match",
      predicate: Object.freeze({
        left: Object.freeze({
          artifact_ref: "http_record:<source_chain_envelope>",
          extract_path: "$.response.body.source_chain.sender_address",
        }),
        op: "eq",
        right: Object.freeze({
          artifact_ref: "evm_call:<destination_chain_dispatch>",
          extract_path: "$.calldata.authorized_sender",
        }),
      }),
    }),
  }),
});

// X.11 helper: surface the per-kind hunting vocab + Contract template for a
// given transition_kind. Returns null for an unknown kind so callers can
// gracefully fall back to the combined `web3_identity_handoff` summary.
function transitionKindBriefContent(transitionKind) {
  if (typeof transitionKind !== "string") return null;
  const trimmed = transitionKind.trim();
  if (!trimmed) return null;
  const vocab = TRANSITION_KIND_HUNTING_VOCAB[trimmed];
  const template = TRANSITION_KIND_CONTRACT_TEMPLATES[trimmed];
  if (!vocab && !template) return null;
  return Object.freeze({
    transition_kind: trimmed,
    hunting_vocab: vocab || null,
    contract_template: template || null,
  });
}

const TECHNIQUE_PACKS_BY_ID = Object.freeze({
  ...Object.fromEntries(OSS_TECHNIQUE_PACKS.map((pack) => [pack.id, pack])),
  [WEB3_IDENTITY_HANDOFF_TECHNIQUE_PACK.id]: WEB3_IDENTITY_HANDOFF_TECHNIQUE_PACK,
});

function getTechniquePackById(packId) {
  if (typeof packId !== "string" || !packId.trim()) return null;
  return TECHNIQUE_PACKS_BY_ID[packId.trim()] || null;
}

// Technique-pack id alias map. MVP wisdom about id-typo recovery: the MVP
// branch shipped packs under longer descriptive ids (e.g.
// `oss-native-code-c-parser-review`) and operators / docs reference them by
// those legacy ids. The alias map resolves a legacy id to the canonical id.
// Aliases also cover dash-vs-underscore variants and the human-friendly
// hyphenated form some docs use.
const OSS_TECHNIQUE_PACK_ID_ALIASES = Object.freeze({
  "oss-native-code-c-parser-review": "oss_native_code",
  "oss-native-code-protocol-memory": "oss_native_code",
  "oss-native-code": "oss_native_code",
  "oss-dependency": "oss_dependency",
  "oss-api-schema": "oss_api_schema",
  "oss-authz": "oss_authz",
  "oss-ci-cd": "oss_ci_cd",
  "oss-secrets-config": "oss_secrets_config",
  "oss-docs-behavior": "oss_docs_behavior",
});

function resolveOssTechniquePackId(packId) {
  if (typeof packId !== "string") return null;
  const trimmed = packId.trim();
  if (!trimmed) return null;
  // Direct hit first (canonical id).
  if (OSS_TECHNIQUE_PACKS.some((pack) => pack.id === trimmed)) {
    return trimmed;
  }
  // Alias hit.
  const aliased = OSS_TECHNIQUE_PACK_ID_ALIASES[trimmed];
  if (aliased && OSS_TECHNIQUE_PACKS.some((pack) => pack.id === aliased)) {
    return aliased;
  }
  return null;
}

function findOssTechniquePack(packId) {
  const resolvedId = resolveOssTechniquePackId(packId);
  if (resolvedId == null) return null;
  return OSS_TECHNIQUE_PACKS.find((pack) => pack.id === resolvedId) || null;
}
const DEFAULT_SUMMARY_ESTIMATED_TOKENS = 500;
const DEFAULT_FULL_ESTIMATED_TOKENS = 1500;
const TECHNIQUE_SUMMARY_ITEMS_PER_KIND = 4;
const TECHNIQUE_SUMMARY_ITEM_MAX_CHARS = 240;
const TECHNIQUE_FULL_ITEMS_PER_KIND = 12;
const TECHNIQUE_FULL_ITEM_MAX_CHARS = 900;
const TECHNIQUE_SELECTION_MAX_CHARS = 6000;

function registryWarning(source, { entryIndex = null, entryId = null, reason }) {
  const warning = {
    source: source ? path.basename(source) : EVALUATOR_KNOWLEDGE_FILE[EVALUATOR_KNOWLEDGE_FILE.length - 1],
    reason: String(reason || "invalid technique registry entry"),
  };
  if (entryIndex != null) warning.entry_index = entryIndex;
  if (entryId != null && String(entryId).trim()) {
    warning.entry_id = String(entryId).trim().slice(0, 128);
  }
  return warning;
}

function readableEntryId(entry) {
  if (entry && typeof entry === "object" && !Array.isArray(entry) && entry.id != null) {
    return String(entry.id);
  }
  return null;
}

function evaluatorKnowledgeCandidatePaths() {
  return resourceCandidatePaths(...EVALUATOR_KNOWLEDGE_FILE);
}

function loadEvaluatorKnowledge() {
  for (const candidate of evaluatorKnowledgeCandidatePaths()) {
    if (!candidate || !fs.existsSync(candidate)) continue;
    let parsed;
    try {
      parsed = JSON.parse(fs.readFileSync(candidate, "utf8"));
    } catch (error) {
      return {
        path: candidate,
        version: 1,
        entries: [],
        warnings: [registryWarning(candidate, {
          reason: `Malformed evaluator-techniques.json: ${error.message || String(error)}`,
        })],
      };
    }
    const version = parsed && Number.isInteger(parsed.version) ? parsed.version : 1;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed) || !Array.isArray(parsed.entries)) {
      return {
        path: candidate,
        version,
        entries: [],
        warnings: [registryWarning(candidate, {
          reason: "evaluator-techniques.json must be an object with entries[]",
        })],
      };
    }
    return {
      path: candidate,
      version,
      entries: parsed.entries,
      warnings: [],
    };
  }
  return { path: null, version: 1, entries: [], warnings: [] };
}

function lowerStringArray(value) {
  if (value == null) return [];
  const values = Array.isArray(value) ? value : [value];
  return values
    .filter((item) => item != null)
    .map((item) => String(item).toLowerCase());
}

function stringArray(value) {
  if (value == null) return [];
  const values = Array.isArray(value) ? value : [value];
  return values
    .filter((item) => item != null)
    .map((item) => String(item));
}

function capTechniqueString(value, maxChars) {
  const text = String(value);
  if (text.length <= maxChars) {
    return { value: text, truncated: false, total_chars: text.length };
  }
  return {
    value: text.slice(0, maxChars),
    truncated: true,
    total_chars: text.length,
  };
}

function boundedTechniqueStrings(value, { itemLimit, itemMaxChars }) {
  const rawValues = stringArray(value)
    .map((item) => item.trim())
    .filter(Boolean);
  let truncatedValues = 0;
  const values = rawValues.slice(0, itemLimit).map((item) => {
    const capped = capTechniqueString(item, itemMaxChars);
    if (capped.truncated) truncatedValues += 1;
    return capped.value;
  });
  return {
    values,
    limits: {
      item_limit: itemLimit,
      item_max_chars: itemMaxChars,
      shown: values.length,
      total: rawValues.length,
      omitted: Math.max(0, rawValues.length - values.length),
      truncated_values: truncatedValues,
    },
  };
}

function surfaceFieldText(surface, fields) {
  const values = [];
  for (const field of fields) {
    values.push(...lowerStringArray(surface[field]));
  }
  return values.join("\n");
}

function countMatches(patterns, haystack, weight, label) {
  const matches = [];
  let score = 0;
  for (const pattern of lowerStringArray(patterns)) {
    if (!pattern || !haystack.includes(pattern)) continue;
    score += weight;
    matches.push(`${label}:${pattern}`);
  }
  return { score, matches };
}

function countExactMatches(patterns, values, weight, label) {
  const valueSet = new Set(lowerStringArray(values));
  const matches = [];
  let score = 0;
  for (const pattern of lowerStringArray(patterns)) {
    if (!pattern || !valueSet.has(pattern)) continue;
    score += weight;
    matches.push(`${label}:${pattern}`);
  }
  return { score, matches };
}

function scoreTechniqueEntry(entry, surface) {
  const match = entry.match && typeof entry.match === "object" ? entry.match : {};
  const techText = surfaceFieldText(surface, [
    "tech_stack",
    "surface_type",
  ]);
  const endpointText = surfaceFieldText(surface, [
    "endpoints",
    "discovered_endpoints",
    "js_endpoints",
    "hosts",
    "high_value_flows",
    "evidence",
  ]);
  const paramValues = [
    ...lowerStringArray(surface.interesting_params),
    ...lowerStringArray(surface.params),
    ...lowerStringArray(surface.parameters),
  ];
  const hintText = surfaceFieldText(surface, [
    "nuclei_hits",
    "js_hints",
    "security_issues",
    "leaked_secrets",
    "auth_info",
    "surface_type",
    "bug_class_hints",
    "high_value_flows",
    "evidence",
  ]);

  const scored = [
    countMatches(match.tech, techText, 8, "tech"),
    countMatches(match.endpoints, endpointText, 5, "endpoint"),
    countExactMatches(match.params, paramValues, 3, "param"),
    countMatches(match.hints, hintText, 4, "hint"),
  ];

  return scored.reduce(
    (result, item) => ({
      score: result.score + item.score,
      matches: result.matches.concat(item.matches),
    }),
    { score: 0, matches: [] },
  );
}

function normalizeTechniquePackId(value, fieldName = "pack_id") {
  const packId = assertNonEmptyString(value, fieldName);
  if (!TECHNIQUE_PACK_ID_RE.test(packId)) {
    throw new Error(`${fieldName} has invalid format`);
  }
  return packId;
}

function normalizeCapabilityPacks(entry) {
  const packs = stringArray(entry.capability_packs)
    .map((item) => item.trim())
    .filter(Boolean);
  return packs.length > 0 ? Array.from(new Set(packs)) : ["web"];
}

function packEstimatedTokens(entry) {
  const explicit = entry.estimated_tokens && typeof entry.estimated_tokens === "object"
    ? entry.estimated_tokens
    : {};
  return {
    summary: Number.isInteger(explicit.summary) && explicit.summary > 0
      ? explicit.summary
      : DEFAULT_SUMMARY_ESTIMATED_TOKENS,
    full: Number.isInteger(explicit.full) && explicit.full > 0
      ? explicit.full
      : DEFAULT_FULL_ESTIMATED_TOKENS,
  };
}

function normalizeLensAffinity(entry, packId) {
  if (entry.lens_affinity == null) return null;
  if (!Array.isArray(entry.lens_affinity)) {
    throw new Error(`technique pack ${packId}: lens_affinity must be a string[] when set`);
  }
  const cleaned = entry.lens_affinity
    .filter((item) => typeof item === "string" && item.trim())
    .map((item) => item.trim());
  if (cleaned.length !== entry.lens_affinity.length) {
    throw new Error(`technique pack ${packId}: lens_affinity entries must be non-empty strings`);
  }
  return cleaned.length > 0 ? Object.freeze(cleaned) : null;
}

function normalizeRegistryEntry(entry, registryVersion) {
  if (entry == null || typeof entry !== "object" || Array.isArray(entry)) {
    throw new Error("technique pack entry must be an object");
  }
  const id = normalizeTechniquePackId(entry.id || "knowledge-entry", "technique_pack.id");
  const title = assertNonEmptyString(entry.title || entry.id || "Evaluator guidance", "technique_pack.title");
  const capabilityPacks = normalizeCapabilityPacks(entry);
  for (const capabilityPack of capabilityPacks) {
    if (!getCapabilityPack(capabilityPack)) {
      throw new Error(`Unknown capability_pack in technique pack ${id}: ${capabilityPack}`);
    }
  }
  // Plane T cycle T.4 — optional `lens_affinity` field. When set, the brief
  // renderer foregrounds the pack for matching task lenses (e.g.
  // `browser_behavior_probe`) and demotes packs without affinity to "Other
  // applicable techniques". When absent, the pack stays in the default flow.
  const lensAffinity = normalizeLensAffinity(entry, id);
  return {
    id,
    version: Number.isInteger(entry.version) ? entry.version : registryVersion,
    title,
    capability_packs: capabilityPacks,
    ...(lensAffinity ? { lens_affinity: lensAffinity } : {}),
    match: entry.match && typeof entry.match === "object" && !Array.isArray(entry.match) ? entry.match : {},
    techniques: stringArray(entry.techniques)
      .map((item) => item.trim())
      .filter(Boolean),
    payload_hints: stringArray(entry.payload_hints)
      .map((item) => item.trim())
      .filter(Boolean),
    estimated_tokens: packEstimatedTokens(entry),
    raw_entry: {
      id,
      title,
      ...(lensAffinity ? { lens_affinity: lensAffinity } : {}),
      match: entry.match && typeof entry.match === "object" && !Array.isArray(entry.match) ? entry.match : {},
      techniques: stringArray(entry.techniques)
        .map((item) => item.trim())
        .filter(Boolean),
      payload_hints: stringArray(entry.payload_hints)
        .map((item) => item.trim())
        .filter(Boolean),
    },
  };
}

function loadTechniqueRegistry() {
  const knowledge = loadEvaluatorKnowledge();
  const warnings = Array.isArray(knowledge.warnings) ? knowledge.warnings.slice() : [];
  const packs = [];
  const seenIds = new Set();
  for (let index = 0; index < knowledge.entries.length; index += 1) {
    const entry = knowledge.entries[index];
    let normalized;
    try {
      normalized = normalizeRegistryEntry(entry, knowledge.version);
    } catch (error) {
      warnings.push(registryWarning(knowledge.path, {
        entryIndex: index,
        entryId: readableEntryId(entry),
        reason: error.message || String(error),
      }));
      continue;
    }
    if (seenIds.has(normalized.id)) {
      warnings.push(registryWarning(knowledge.path, {
        entryIndex: index,
        entryId: normalized.id,
        reason: `Duplicate technique pack id: ${normalized.id}`,
      }));
      continue;
    }
    seenIds.add(normalized.id);
    packs.push(normalized);
  }
  return {
    source: knowledge.path,
    version: knowledge.version,
    packs,
    warnings,
  };
}

function techniquePackSummary(pack, { matches = [], score = 0, attempt = null } = {}) {
  const guidance = boundedTechniqueStrings(pack.techniques, {
    itemLimit: TECHNIQUE_SUMMARY_ITEMS_PER_KIND,
    itemMaxChars: TECHNIQUE_SUMMARY_ITEM_MAX_CHARS,
  });
  const payloadHints = boundedTechniqueStrings(pack.payload_hints, {
    itemLimit: TECHNIQUE_SUMMARY_ITEMS_PER_KIND,
    itemMaxChars: TECHNIQUE_SUMMARY_ITEM_MAX_CHARS,
  });
  const summary = {
    id: pack.id,
    version: pack.version,
    title: pack.title,
    capability_packs: pack.capability_packs.slice(),
    // Plane T cycle T.4 — expose `lens_affinity` so the brief renderer can
    // foreground/demote summaries without re-reading the registry.
    ...(Array.isArray(pack.lens_affinity) ? { lens_affinity: pack.lens_affinity.slice() } : {}),
    matched: matches.slice(0, 8),
    score,
    summary: {
      guidance: guidance.values,
      payload_hints: payloadHints.values,
    },
    summary_limits: {
      guidance: guidance.limits,
      payload_hints: payloadHints.limits,
    },
    estimated_tokens: { ...pack.estimated_tokens },
  };
  if (attempt) {
    summary.attempt = summarizeTechniqueAttempt(attempt);
  }
  return summary;
}

function latestAttemptByPack(attempts) {
  const latest = new Map();
  for (const attempt of attempts || []) {
    latest.set(attempt.pack_id, attempt);
  }
  return latest;
}

function shouldSkipAttemptedPack(attempt, includeAttempted) {
  if (includeAttempted) return false;
  return !!attempt;
}

function fitTechniquePackSummaries(summaries, maxChars = TECHNIQUE_SELECTION_MAX_CHARS, {
  candidateLimit = null,
} = {}) {
  const selected = [];
  for (const summary of summaries) {
    const candidate = selected.concat(summary);
    if (JSON.stringify(candidate).length > maxChars) break;
    selected.push(summary);
  }
  const selectionLimits = {
    max_chars: maxChars,
    selected_chars: JSON.stringify(selected).length,
    selected_count: selected.length,
    candidate_count: summaries.length,
    omitted_due_to_char_limit: Math.max(0, summaries.length - selected.length),
    summary_items_per_kind: TECHNIQUE_SUMMARY_ITEMS_PER_KIND,
    summary_item_max_chars: TECHNIQUE_SUMMARY_ITEM_MAX_CHARS,
  };
  if (candidateLimit != null) {
    selectionLimits.candidate_pack_limit = candidateLimit;
  }
  return {
    selected,
    selection_limits: selectionLimits,
  };
}

function selectTechniquePacksForSurface(surface, {
  capabilityPack = "web",
  maxPacks = EVALUATOR_KNOWLEDGE_MAX_ENTRIES,
  includeAttempted = true,
  attempts = [],
} = {}) {
  const limit = normalizeOptionalInteger(maxPacks, "max_packs", { min: 1, max: 50 }) || EVALUATOR_KNOWLEDGE_MAX_ENTRIES;
  const registry = loadTechniqueRegistry();
  if (registry.packs.length === 0) {
    return {
      source: registry.source,
      selected: [],
      omitted_attempted: [],
      registry_version: registry.version,
      registry_warnings: registry.warnings.slice(),
      selection_limits: fitTechniquePackSummaries([], TECHNIQUE_SELECTION_MAX_CHARS, {
        candidateLimit: limit,
      }).selection_limits,
    };
  }

  const attemptsByPack = latestAttemptByPack(attempts);
  const scoredPacks = [];
  for (const pack of registry.packs) {
    if (!pack.capability_packs.includes(capabilityPack)) continue;
    const scored = scoreTechniqueEntry(pack, surface || {});
    if (scored.score > 0) {
      scoredPacks.push({ pack, score: scored.score, matches: scored.matches });
    }
  }

  if (scoredPacks.length === 0) {
    const fallback = registry.packs.find(
      (pack) => pack.id === EVALUATOR_KNOWLEDGE_DEFAULT_ID && pack.capability_packs.includes(capabilityPack),
    );
    if (fallback) {
      scoredPacks.push({ pack: fallback, score: 0, matches: ["fallback:generic-rest-api"] });
    }
  }

  scoredPacks.sort((a, b) => {
    if (b.score !== a.score) return b.score - a.score;
    return a.pack.id.localeCompare(b.pack.id);
  });

  const selectedCandidates = [];
  const omittedAttempted = [];
  for (const scored of scoredPacks) {
    const attempt = attemptsByPack.get(scored.pack.id) || null;
    if (shouldSkipAttemptedPack(attempt, includeAttempted)) {
      omittedAttempted.push(summarizeTechniqueAttempt(attempt));
      continue;
    }
    selectedCandidates.push(techniquePackSummary(scored.pack, {
      matches: scored.matches,
      score: scored.score,
      attempt,
    }));
    if (selectedCandidates.length >= limit) break;
  }
  const fitted = fitTechniquePackSummaries(selectedCandidates, TECHNIQUE_SELECTION_MAX_CHARS, {
    candidateLimit: limit,
  });

  return {
    source: registry.source,
    selected: fitted.selected,
    omitted_attempted: omittedAttempted,
    registry_version: registry.version,
    registry_warnings: registry.warnings.slice(),
    selection_limits: fitted.selection_limits,
  };
}

function readTechniquePack(packId, { mode = "summary" } = {}) {
  const normalizedPackId = normalizeTechniquePackId(packId);
  const normalizedMode = mode == null ? "summary" : assertEnumValue(mode, ["summary", "full"], "mode");
  const registry = loadTechniqueRegistry();
  const pack = registry.packs.find((entry) => entry.id === normalizedPackId);
  if (!pack) {
    throw new Error(`Unknown technique pack id: ${normalizedPackId}`);
  }
  const summary = techniquePackSummary(pack);
  if (normalizedMode === "summary") {
    return {
      version: 1,
      mode: normalizedMode,
      source: registry.source ? path.basename(registry.source) : null,
      registry_version: registry.version,
      technique_pack: summary,
      summary_limits: summary.summary_limits,
      registry_warnings: registry.warnings.slice(),
    };
  }
  const fullTechniques = boundedTechniqueStrings(pack.techniques, {
    itemLimit: TECHNIQUE_FULL_ITEMS_PER_KIND,
    itemMaxChars: TECHNIQUE_FULL_ITEM_MAX_CHARS,
  });
  const fullPayloadHints = boundedTechniqueStrings(pack.payload_hints, {
    itemLimit: TECHNIQUE_FULL_ITEMS_PER_KIND,
    itemMaxChars: TECHNIQUE_FULL_ITEM_MAX_CHARS,
  });
  const fullLimits = {
    techniques: fullTechniques.limits,
    payload_hints: fullPayloadHints.limits,
  };
  return {
    version: 1,
    mode: normalizedMode,
    source: registry.source ? path.basename(registry.source) : null,
    registry_version: registry.version,
    technique_pack: {
      ...summary,
      full: {
        id: pack.id,
        version: pack.version,
        title: pack.title,
        capability_packs: pack.capability_packs.slice(),
        match: pack.match,
        techniques: fullTechniques.values,
        payload_hints: fullPayloadHints.values,
      },
      full_limits: fullLimits,
    },
    summary_limits: summary.summary_limits,
    full_limits: fullLimits,
    registry_warnings: registry.warnings.slice(),
  };
}

function normalizeOptionalVersionInteger(value, fieldName) {
  if (value == null) return null;
  return assertInteger(value, fieldName, { min: 1, max: 100000 });
}

function addOptionalTechniqueVersionMetadata(normalized, record) {
  const packVersion = normalizeOptionalVersionInteger(record.pack_version, "pack_version");
  const registryVersion = normalizeOptionalVersionInteger(record.registry_version, "registry_version");
  const capabilityPack = normalizeOptionalText(record.capability_pack, "capability_pack");
  const capabilityPackVersion = normalizeOptionalVersionInteger(record.capability_pack_version, "capability_pack_version");

  if (packVersion != null) normalized.pack_version = packVersion;
  if (registryVersion != null) normalized.registry_version = registryVersion;
  if (capabilityPack) {
    if (!getCapabilityPack(capabilityPack)) {
      throw new Error(`Unknown capability_pack: ${capabilityPack}`);
    }
    normalized.capability_pack = capabilityPack;
  }
  if (capabilityPackVersion != null) normalized.capability_pack_version = capabilityPackVersion;
}

function techniqueVersionMetadata(packResult, routeOrAssignment) {
  const packVersion = packResult && packResult.technique_pack
    ? packResult.technique_pack.version
    : null;
  const metadata = {};
  if (Number.isInteger(packVersion) && packVersion > 0) metadata.pack_version = packVersion;
  if (Number.isInteger(packResult && packResult.registry_version) && packResult.registry_version > 0) {
    metadata.registry_version = packResult.registry_version;
  }
  if (routeOrAssignment && routeOrAssignment.capability_pack) {
    metadata.capability_pack = routeOrAssignment.capability_pack;
  }
  if (routeOrAssignment && Number.isInteger(routeOrAssignment.capability_pack_version)) {
    metadata.capability_pack_version = routeOrAssignment.capability_pack_version;
  }
  return metadata;
}

function normalizeTechniquePackReadRecord(record, { expectedDomain = null, lineNumber = null } = {}) {
  if (record == null || typeof record !== "object" || Array.isArray(record)) {
    throw new Error(lineNumber == null
      ? "technique pack read record must be an object"
      : `Malformed technique-pack-reads.jsonl at line ${lineNumber}: expected object`);
  }

  try {
    const read = {
      version: record.version == null
        ? 1
        : assertInteger(record.version, "version", { min: 1, max: 1 }),
      ts: assertNonEmptyString(record.ts, "ts"),
      target_domain: assertNonEmptyString(record.target_domain, "target_domain"),
      wave: parseWaveId(record.wave),
      agent: parseAgentId(record.agent),
      surface_id: assertNonEmptyString(record.surface_id, "surface_id"),
      pack_id: normalizeTechniquePackId(record.pack_id),
      mode: assertEnumValue(record.mode, ["full"], "mode"),
    };
    addOptionalTechniqueVersionMetadata(read, record);
    if (expectedDomain != null && read.target_domain !== expectedDomain) {
      throw new Error("target_domain mismatch");
    }
    return read;
  } catch (error) {
    if (lineNumber == null) {
      throw error;
    }
    throw new Error(`Malformed technique-pack-reads.jsonl at line ${lineNumber}: ${error.message || String(error)}`);
  }
}

function readTechniquePackReadRecordsFromJsonl(domain) {
  const filePath = techniquePackReadsJsonlPath(domain);
  if (!fs.existsSync(filePath)) {
    return [];
  }
  const content = readFileUtf8(filePath, { label: "technique-pack-reads.jsonl" });
  if (!content.trim()) {
    return [];
  }

  const records = [];
  const lines = content.split("\n");
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (!line.trim()) continue;
    let parsed;
    try {
      parsed = JSON.parse(line);
    } catch (error) {
      throw new Error(`Malformed technique-pack-reads.jsonl at line ${index + 1}: ${error.message || String(error)}`);
    }
    records.push(normalizeTechniquePackReadRecord(parsed, {
      expectedDomain: domain,
      lineNumber: index + 1,
    }));
  }
  return records;
}

function assertFullReadContext(args) {
  const domain = normalizeOptionalText(args.target_domain, "target_domain");
  const wave = normalizeOptionalText(args.wave, "wave");
  const agent = normalizeOptionalText(args.agent, "agent");
  const surfaceId = normalizeOptionalText(args.surface_id, "surface_id");
  const missing = [];
  if (!domain) missing.push("target_domain");
  if (!wave) missing.push("wave");
  if (!agent) missing.push("agent");
  if (!surfaceId) missing.push("surface_id");
  if (missing.length > 0) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      `mode=full requires ${missing.join(", ")} so full_pack_read_limit can be enforced`,
    );
  }
  return {
    domain,
    wave: parseWaveId(wave),
    agent: parseAgentId(agent),
    surface_id: surfaceId,
  };
}

function assertTechniquePackMatchesCapability(techniquePack, capabilityPack) {
  const capabilityPacks = techniquePack && Array.isArray(techniquePack.capability_packs)
    ? techniquePack.capability_packs
    : [];
  if (!capabilityPacks.includes(capabilityPack)) {
    throw new ToolError(
      ERROR_CODES.INVALID_ARGUMENTS,
      `technique pack ${techniquePack && techniquePack.id ? techniquePack.id : "(unknown)"} is not compatible with capability_pack ${capabilityPack}`,
    );
  }
}

function assertPackMatchesAssignment(packResult, assignment) {
  assertTechniquePackMatchesCapability(packResult && packResult.technique_pack, assignment.capability_pack);
}

function readTechniquePackForTool(args) {
  const mode = args.mode || "summary";
  if (mode !== "full") {
    return JSON.stringify(readTechniquePack(args.pack_id, { mode }));
  }

  const context = assertFullReadContext(args);
  const packId = normalizeTechniquePackId(args.pack_id);
  const assignment = validateAssignedWaveAgentSurface(
    context.domain,
    context.wave,
    context.agent,
    context.surface_id,
  );
  const full = readTechniquePack(packId, { mode: "full" });
  assertPackMatchesAssignment(full, assignment);

  return withSessionLock(context.domain, () => {
    const existingRecords = readTechniquePackReadRecordsFromJsonl(context.domain);
    const matchingRecords = existingRecords.filter((record) =>
      record.wave === context.wave
      && record.agent === context.agent
      && record.surface_id === context.surface_id
      && record.mode === "full",
    );
    const readPackIds = new Set(matchingRecords.map((record) => record.pack_id));
    const alreadyRead = readPackIds.has(packId);
    const limit = assignment.context_budget.full_pack_read_limit;
    if (!alreadyRead && readPackIds.size >= limit) {
      throw new ToolError(
        ERROR_CODES.INVALID_ARGUMENTS,
        `full_pack_read_limit reached for ${context.wave}/${context.agent}/${context.surface_id}: ${readPackIds.size}/${limit}`,
      );
    }

    if (!alreadyRead) {
      appendJsonlLine(techniquePackReadsJsonlPath(context.domain), normalizeTechniquePackReadRecord({
        version: 1,
        ts: new Date().toISOString(),
        target_domain: context.domain,
        wave: context.wave,
        agent: context.agent,
        surface_id: context.surface_id,
        pack_id: packId,
        ...techniqueVersionMetadata(full, assignment),
        mode: "full",
      }, { expectedDomain: context.domain }), { maxRecords: TECHNIQUE_PACK_READ_LOG_MAX_RECORDS });
      readPackIds.add(packId);
    }

    return JSON.stringify({
      ...full,
      full_read_budget: {
        target_domain: context.domain,
        wave: context.wave,
        agent: context.agent,
        surface_id: context.surface_id,
        full_pack_read_limit: limit,
        full_packs_read: readPackIds.size,
        remaining_full_pack_reads: Math.max(0, limit - readPackIds.size),
        already_read: alreadyRead,
        log_path: techniquePackReadsJsonlPath(context.domain),
      },
    });
  });
}

function resolveSurfaceTechniqueRoute(domain, surface, requestedCapabilityPack = null) {
  const routesPath = surfaceRoutesPath(domain);
  let route = null;
  if (fs.existsSync(routesPath)) {
    try {
      const routesInfo = readSurfaceRoutesStrict(domain);
      route = routesInfo.document.routes.find((entry) => entry.surface_id === surface.id) || null;
    } catch {}
  }
  if (!route) {
    route = classifySurfaceCapability(surface);
  }

  const capabilityPack = requestedCapabilityPack || route.capability_pack;
  const pack = getCapabilityPack(capabilityPack);
  if (!pack) {
    throw new Error(`Unknown capability_pack: ${capabilityPack}`);
  }
  if (requestedCapabilityPack && route.capability_pack && requestedCapabilityPack !== route.capability_pack) {
    throw new Error(`surface_id ${surface.id} is routed to capability_pack ${route.capability_pack}`);
  }

  return {
    capability_pack: capabilityPack,
    capability_pack_version: route.capability_pack_version || pack.capability_pack_version,
    brief_profile: route.brief_profile || pack.brief_profile,
    evaluator_agent: route.evaluator_agent || pack.evaluator_agent,
    context_budget: normalizeContextBudget(route.context_budget, pack),
  };
}

function selectTechniquePacks(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const surfaceId = assertNonEmptyString(args.surface_id, "surface_id");
  const requestedCapabilityPack = normalizeOptionalText(args.capability_pack, "capability_pack");
  const includeAttempted = args.include_attempted == null ? false : args.include_attempted;
  if (typeof includeAttempted !== "boolean") {
    throw new Error("include_attempted must be a boolean");
  }

  const attackSurface = currentSurfaces(domain);
  const surface = attackSurface.document.surfaces.find((entry) => entry && entry.id === surfaceId);
  if (!surface) {
    throw new Error(`Unknown surface_id: ${surfaceId}`);
  }

  const route = resolveSurfaceTechniqueRoute(domain, surface, requestedCapabilityPack);
  const requestedLimit = normalizeOptionalInteger(args.max_packs, "max_packs", { min: 1, max: 50 });
  const maxPacks = Math.min(
    requestedLimit || route.context_budget.candidate_pack_limit,
    route.context_budget.candidate_pack_limit,
  );
  const attempts = readTechniqueAttemptRecordsFromJsonl(domain)
    .filter((record) => record.surface_id === surfaceId);
  const selected = selectTechniquePacksForSurface(surface, {
    capabilityPack: route.capability_pack,
    maxPacks,
    includeAttempted,
    attempts,
  });

  return JSON.stringify({
    version: 1,
    target_domain: domain,
    surface_id: surfaceId,
    capability_pack: route.capability_pack,
    capability_pack_version: route.capability_pack_version,
    brief_profile: route.brief_profile,
    context_budget: route.context_budget,
    max_packs: maxPacks,
    include_attempted: includeAttempted,
    technique_packs: selected.selected,
    selection_limits: selected.selection_limits,
    registry_warnings: selected.registry_warnings,
    attempts_summary: {
      total_for_surface: attempts.length,
      omitted_attempted: selected.omitted_attempted,
    },
  });
}

function fitKnowledgeEntries(entries, maxChars) {
  const selected = [];
  for (const entry of entries) {
    const candidate = selected.concat(entry);
    if (JSON.stringify(candidate).length > maxChars) break;
    selected.push(entry);
  }
  return selected;
}

function resolveEvaluatorKnowledge(surface, {
  capabilityPack = "web",
  maxEntries = EVALUATOR_KNOWLEDGE_MAX_ENTRIES,
} = {}) {
  const selectedResult = selectTechniquePacksForSurface(surface, {
    capabilityPack,
    maxPacks: maxEntries,
    includeAttempted: true,
  });

  const slimEntries = selectedResult.selected
    .slice(0, maxEntries)
    .map((pack) => ({
      id: pack.id,
      title: pack.title,
      matched: pack.matched.slice(0, 6),
      techniques: pack.summary.guidance.slice(0, 4),
      payload_hints: pack.summary.payload_hints.slice(0, 4),
    }));
  const fittedEntries = fitKnowledgeEntries(slimEntries, EVALUATOR_KNOWLEDGE_MAX_CHARS);
  let techniques = [];
  let payloadHints = [];
  let charCount = 0;
  while (fittedEntries.length > 0) {
    techniques = fittedEntries.map((entry) => ({
      id: entry.id,
      title: entry.title,
      matched: entry.matched,
      guidance: entry.techniques,
    }));
    payloadHints = fittedEntries
      .filter((entry) => entry.payload_hints.length > 0)
      .map((entry) => ({
        id: entry.id,
        title: entry.title,
        hints: entry.payload_hints,
      }));
    charCount = JSON.stringify({ techniques, payload_hints: payloadHints }).length;
    if (charCount <= EVALUATOR_KNOWLEDGE_MAX_CHARS) break;
    fittedEntries.pop();
  }
  if (fittedEntries.length === 0) {
    techniques = [];
    payloadHints = [];
    charCount = 0;
  }

  return {
    techniques,
    payload_hints: payloadHints,
    knowledge_summary: {
      source: selectedResult.source ? path.basename(selectedResult.source) : null,
      entries_returned: fittedEntries.length,
      capped: slimEntries.length > fittedEntries.length,
      char_count: charCount,
      max_chars: EVALUATOR_KNOWLEDGE_MAX_CHARS,
      registry_warnings: selectedResult.registry_warnings,
    },
  };
}

function normalizeTechniqueAttemptRecord(record, { expectedDomain = null, lineNumber = null } = {}) {
  if (record == null || typeof record !== "object" || Array.isArray(record)) {
    throw new Error(lineNumber == null
      ? "technique attempt record must be an object"
      : `Malformed technique-attempts.jsonl at line ${lineNumber}: expected object`);
  }

  try {
    const attempt = {
      version: record.version == null
        ? 1
        : assertInteger(record.version, "version", { min: 1, max: 1 }),
      ts: assertNonEmptyString(record.ts, "ts"),
      target_domain: assertNonEmptyString(record.target_domain, "target_domain"),
      surface_id: assertNonEmptyString(record.surface_id, "surface_id"),
      pack_id: normalizeTechniquePackId(record.pack_id),
      status: assertEnumValue(record.status, TECHNIQUE_ATTEMPT_STATUS_VALUES, "status"),
      evidence: assertRequiredText(record.evidence, "evidence"),
    };
    addOptionalTechniqueVersionMetadata(attempt, record);

    const wave = normalizeOptionalText(record.wave, "wave");
    const agent = normalizeOptionalText(record.agent, "agent");
    const outcome = normalizeOptionalText(record.outcome, "outcome");
    if (wave) attempt.wave = parseWaveId(wave);
    if (agent) attempt.agent = parseAgentId(agent);
    if (outcome) attempt.outcome = outcome;
    if (expectedDomain != null && attempt.target_domain !== expectedDomain) {
      throw new Error("target_domain mismatch");
    }
    return attempt;
  } catch (error) {
    if (lineNumber == null) {
      throw error;
    }
    throw new Error(`Malformed technique-attempts.jsonl at line ${lineNumber}: ${error.message || String(error)}`);
  }
}

function readTechniqueAttemptRecordsFromJsonl(domain) {
  const filePath = techniqueAttemptsJsonlPath(domain);
  if (!fs.existsSync(filePath)) {
    return [];
  }
  const content = readFileUtf8(filePath, { label: "technique-attempts.jsonl" });
  if (!content.trim()) {
    return [];
  }

  const records = [];
  const lines = content.split("\n");
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (!line.trim()) continue;
    let parsed;
    try {
      parsed = JSON.parse(line);
    } catch (error) {
      throw new Error(`Malformed technique-attempts.jsonl at line ${index + 1}: ${error.message || String(error)}`);
    }
    records.push(normalizeTechniqueAttemptRecord(parsed, {
      expectedDomain: domain,
      lineNumber: index + 1,
    }));
  }
  return records;
}

function summarizeTechniqueAttempt(record) {
  if (!record) return null;
  const summary = {
    pack_id: record.pack_id,
    status: record.status,
    ts: record.ts,
    evidence: record.evidence,
  };
  if (record.outcome) summary.outcome = record.outcome;
  if (record.wave) summary.wave = record.wave;
  if (record.agent) summary.agent = record.agent;
  if (record.surface_id) summary.surface_id = record.surface_id;
  if (record.pack_version != null) summary.pack_version = record.pack_version;
  if (record.registry_version != null) summary.registry_version = record.registry_version;
  if (record.capability_pack) summary.capability_pack = record.capability_pack;
  if (record.capability_pack_version != null) summary.capability_pack_version = record.capability_pack_version;
  return summary;
}

function logTechniqueAttempt(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const surfaceId = assertNonEmptyString(args.surface_id, "surface_id");
  const packId = normalizeTechniquePackId(args.pack_id);
  const status = assertEnumValue(args.status, TECHNIQUE_ATTEMPT_STATUS_VALUES, "status");
  const evidence = assertRequiredText(args.evidence, "evidence");
  if (evidence.length > 2000) {
    throw new Error("evidence must be at most 2000 characters");
  }
  const outcome = normalizeOptionalText(args.outcome, "outcome");
  if (outcome && outcome.length > 200) {
    throw new Error("outcome must be at most 200 characters");
  }

  const wave = normalizeOptionalText(args.wave, "wave");
  const agent = normalizeOptionalText(args.agent, "agent");
  if ((wave && !agent) || (agent && !wave)) {
    throw new Error("wave and agent must be provided together");
  }
  const parsedWave = wave ? parseWaveId(wave) : null;
  const parsedAgent = agent ? parseAgentId(agent) : null;

  const packResult = readTechniquePack(packId, { mode: "summary" });
  const attackSurface = currentSurfaces(domain);
  const surface = attackSurface.document.surfaces.find((entry) => entry && entry.id === surfaceId);
  if (!surface) {
    throw new Error(`Unknown surface_id: ${surfaceId}`);
  }
  let routeMetadata;
  if (parsedWave && parsedAgent) {
    const assignment = validateAssignedWaveAgentSurface(domain, parsedWave, parsedAgent, surfaceId);
    assertPackMatchesAssignment(packResult, assignment);
    routeMetadata = assignment;
  } else {
    const route = resolveSurfaceTechniqueRoute(domain, surface);
    assertTechniquePackMatchesCapability(packResult.technique_pack, route.capability_pack);
    routeMetadata = route;
  }

  const record = normalizeTechniqueAttemptRecord({
    version: 1,
    ts: new Date().toISOString(),
    target_domain: domain,
    wave: parsedWave,
    agent: parsedAgent,
    surface_id: surfaceId,
    pack_id: packId,
    ...techniqueVersionMetadata(packResult, routeMetadata),
    status,
    outcome,
    evidence,
  }, { expectedDomain: domain });

  return withSessionLock(domain, () => {
    const logPath = techniqueAttemptsJsonlPath(domain);
    appendJsonlLine(logPath, record, { maxRecords: TECHNIQUE_ATTEMPT_LOG_MAX_RECORDS });
    safeAppendPipelineEventDirect(domain, "technique_attempt_logged", {
      wave: parsedWave,
      agent: parsedAgent,
      surface_id: surfaceId,
      status,
      source: "bob_log_technique_attempt",
      counts: {
        records: 1,
      },
    }, safeGovernanceContextForDomain(domain));
    return JSON.stringify({
      appended: 1,
      log_path: logPath,
      record: summarizeTechniqueAttempt(record),
      registry_warnings: packResult.registry_warnings,
    });
  });
}

module.exports = {
  EVALUATOR_KNOWLEDGE_FILE,
  EVALUATOR_KNOWLEDGE_MAX_CHARS,
  EVALUATOR_KNOWLEDGE_MAX_ENTRIES,
  TECHNIQUE_FULL_ITEM_MAX_CHARS,
  TECHNIQUE_FULL_ITEMS_PER_KIND,
  TECHNIQUE_SELECTION_MAX_CHARS,
  TECHNIQUE_SUMMARY_ITEM_MAX_CHARS,
  TECHNIQUE_SUMMARY_ITEMS_PER_KIND,
  evaluatorKnowledgeCandidatePaths,
  loadEvaluatorKnowledge,
  loadTechniqueRegistry,
  logTechniqueAttempt,
  normalizeTechniqueAttemptRecord,
  readTechniqueAttemptRecordsFromJsonl,
  readTechniquePack,
  readTechniquePackForTool,
  readTechniquePackReadRecordsFromJsonl,
  resolveEvaluatorKnowledge,
  scoreTechniqueEntry,
  selectTechniquePacks,
  selectTechniquePacksForSurface,
  assertTechniquePackMatchesCapability,
  summarizeTechniqueAttempt,
  techniquePackSummary,
  // Cycle O.6 — OSS technique-pack content + id alias map.
  OSS_TECHNIQUE_PACKS,
  OSS_TECHNIQUE_PACK_ID_ALIASES,
  findOssTechniquePack,
  resolveOssTechniquePackId,
  // Cycle X.5 — cross-stack identity-handoff technique pack + lookup helper.
  WEB3_IDENTITY_HANDOFF_TECHNIQUE_PACK,
  TECHNIQUE_PACKS_BY_ID,
  getTechniquePackById,
  // Cycle X.11 — per-transition-kind hunting vocab + worked Contract
  // templates surfaced in the cross-stack Transition brief composition.
  TRANSITION_KIND_HUNTING_VOCAB,
  TRANSITION_KIND_CONTRACT_TEMPLATES,
  transitionKindBriefContent,
};
