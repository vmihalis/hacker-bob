"use strict";
const {
  assertNonEmptyString,
  normalizeOptionalText,
  parseAgentId,
  parseWaveId,
} = require("./validation.js");
const {
  loadWaveAssignments,
} = require("./assignments.js");
const {
  blockInternalHostsPolicyFields,
} = require("./session-state-contracts.js");
const {
  blockInternalHostsRequestPolicy,
  readSessionStateStrict,
} = require("./session-state-store.js");
const {
  resolveAndAssertSessionEgressIdentity,
} = require("./session-state.js");
const {
  readAttackSurfaceStrict,
} = require("./attack-surface.js");
const {
  currentSurfaces,
} = require("./frontier-projections.js");
const {
  rankAttackSurfaces,
} = require("./ranking.js");
const {
  buildCoverageSummaryForSurface,
  readCoverageRecordsFromJsonl,
} = require("./coverage.js");
const {
  buildCircuitBreakerSummary,
  readHttpAuditRecordsFromJsonl,
  readTrafficRecordsFromJsonl,
  summarizeHttpAuditRecords,
  summarizeTrafficRecords,
} = require("./http-records.js");
const {
  summarizePublicIntelForSurface,
} = require("./public-intel.js");
const {
  summarizeStaticScanHints,
} = require("./static-artifacts.js");
const {
  readSurfaceLeadsDocument,
} = require("./lead-intake.js");
const {
  summarizeSchemaSliceForSurface,
} = require("./schema-contracts-store.js");
const {
  summarizeSurfaceGraphForSurface,
} = require("./surface-graph.js");
const {
  loadBobSpec,
  summarizeBobSpecForBrief,
} = require("./bob-spec.js");
const {
  summarizeRpcPoolForBrief,
} = require("./evm-rpc-pool.js");
const {
  filterExclusionsByHosts,
} = require("./scope.js");
const {
  readResourceText,
} = require("./runtime-resources.js");
const {
  normalizeAssignmentRouteMetadata,
} = require("./capability-packs.js");
const {
  readFrontierEvents,
} = require("./frontier-events.js");
// Plane Y Cycle Y.5 — wave-side derivation helper (friction history + target
// class threading per Y-P5 / Y-P6 / rev-4 O5) and the trace-reading
// expectations composer (Y-P14d / W1).
const {
  buildWaveBriefDerivation,
} = require("./wave-brief-derivation.js");
const {
  composeTraceReadingExpectationsForRole,
} = require("./trace-reading-composer.js");
const {
  EVALUATOR_KNOWLEDGE_MAX_CHARS,
  OSS_TECHNIQUE_PACKS,
  TECHNIQUE_SUMMARY_ITEM_MAX_CHARS,
  evaluatorKnowledgeCandidatePaths,
  resolveEvaluatorKnowledge,
  selectTechniquePacksForSurface,
} = require("./technique-packs.js");
const {
  suggestFamiliesForSurface,
} = require("./oss-rootcause-family-corpus.js");
const {
  CLI_TOOL_PACKS,
  fillInvocationPlaceholders,
  observationList,
  selectCliToolPacks,
} = require("./cli-tool-packs.js");
const {
  DEMOTION_SCORE_PENALTY,
  loadPackTelemetry,
} = require("./pack-telemetry.js");
const {
  safeGovernanceContextForDomain,
} = require("./governance-context.js");
const {
  checkCliToolInstallation,
  presenceCachePath,
} = require("./cli-tool-presence.js");
const {
  repoEnvPath,
} = require("./paths.js");
const {
  wrapUntrusted,
  UNTRUSTED_DATA_SYSTEM_NOTE,
  OPEN_SENTINEL,
  CLOSE_SENTINEL,
  UNTRUSTED_FENCE_OVERHEAD_CHARS,
  fenceOverheadForLabel,
} = require("./untrusted-envelope.js");
const fs = require("fs");

// Bypass table tech-to-file map used by evaluator brief generation.
const BYPASS_TABLE_MAP = {
  wordpress: "wordpress.txt",
  graphql: "graphql.txt",
  ssrf: "ssrf.txt",
  jwt: "jwt.txt",
  firebase: "firebase.txt",
  "next.js": "nextjs.txt",
  nextjs: "nextjs.txt",
  oauth: "oauth-oidc.txt",
  oidc: "oauth-oidc.txt",
};
const BYPASS_TABLE_DEFAULT = "rest-api.txt";
const ASSIGNMENT_BRIEF_SURFACE_ARRAY_LIMITS = Object.freeze({
  hosts: 20,
  tech_stack: 20,
  endpoints: 80,
  interesting_params: 40,
  nuclei_hits: 30,
  bug_class_hints: 20,
  high_value_flows: 20,
  evidence: 25,
  fork_rpc_pool: 6,
  // Recently-patched security fixes whose sibling/adjacent code paths the
  // patch may not have covered — the incomplete-fix residual hunting seed.
  // Stamped onto OSS native-code surfaces by repo-target.js; the evaluator
  // brief must surface it or the residual-hunt signal is silently dropped.
  residual_hunt_targets: 20,
});
const ASSIGNMENT_BRIEF_SURFACE_SCALAR_LIMITS = Object.freeze({
  id: 120,
  priority: 40,
  original_priority: 40,
  surface_type: 80,
  // Reachability/ceiling triage — tells the evaluator whether this surface
  // is AV:N (CRITICAL-capable) or AV:L (MEDIUM-realistic) so it pursues the
  // write/UAF/RCE primitive on network-reachable surfaces. All three are named
  // in the evaluator/orchestrator prompts as fields the surface carries, so all
  // three must survive the slim whitelist (booleans coerce to "true"/"false").
  attack_vector: 40,
  severity_ceiling: 40,
  network_reachable: 8,
  chain_family: 40,
  chain_id: 20,
  file_path: 240,
  language: 40,
  native_source: 8,
  native_build: 8,
  // Per-chain harness paths. Each smart-contract evaluator prompt expects a
  // chain-specific scalar — whitelisting them all keeps slim surfaces lossy
  // only on cap, not on field name. Adding a new chain pack is one entry.
  foundry_harness_path: 240,    // EVM
  anchor_harness_path: 240,     // SVM
  move_harness_path: 240,       // Aptos + Sui (Move pack)
  ink_harness_path: 240,        // Substrate ink!
  cargo_harness_path: 240,      // Generic Cargo (Substrate / CosmWasm fallback)
  cosmwasm_harness_path: 240,   // CosmWasm explicit
  name: 160,
  title: 160,
  description: 500,
});
// slimSurfaceForBrief copies every surface scalar/short-array BY DEFAULT, so a
// new triage field added in makeSurface / repo-target stamping reaches the
// evaluator automatically — the failure mode that silently dropped
// network_reachable until it was whitelisted. The *_LIMITS maps above are
// per-field cap OVERRIDES; unlisted fields get these defaults. The denylist
// below is the only thing that blocks a field — keep it to secrets and bulky
// raw bodies that must never travel in a brief.
const ASSIGNMENT_BRIEF_SURFACE_DEFAULT_SCALAR_CAP = 200;
const ASSIGNMENT_BRIEF_SURFACE_DEFAULT_ARRAY_LIMIT = 12;
const ASSIGNMENT_BRIEF_SURFACE_FIELD_DROP_EXACT = Object.freeze(new Set([
  "ranking",          // slimmed separately via slimRankingForBrief
  "raw", "raw_body", "request_body", "response_body", "body",
  "headers", "cookies", "set_cookie",
  "auth", "credentials", "secret", "secrets", "token", "tokens",
  "api_key", "apikey", "private_key", "password",
  "surface_discovery_blob",   // raw discovery pipeline output — bulky, not for brief
]));
const ASSIGNMENT_BRIEF_SURFACE_SENSITIVE_FIELD_SEGMENTS = Object.freeze(new Set([
  "auth",
  "authorization",
  "cookie",
  "cookies",
  "credential",
  "credentials",
  "password",
  "passwords",
  "secret",
  "secrets",
  "session",
  "sessions",
  "token",
  "tokens",
  "apikey",
]));
const ASSIGNMENT_BRIEF_ARRAY_ITEM_MAX_CHARS = 500;
const ASSIGNMENT_BRIEF_RANKING_REASON_LIMIT = 10;
const ASSIGNMENT_BRIEF_RANKING_REASON_MAX_CHARS = 160;

// Default brief message returned when bob-spec.json is absent. The loader is
// real (mcp/lib/bob-spec.js); this message is the empty-state fallback.
const BOB_SPEC_ABSENT_MESSAGE = "bob-spec.json not present in the session directory; the smart_contract anti-stop rule still applies (record at least one bypass_attempts[] entry citing the trust assumption you actually attempted to break, or record a finding).";
const UNTRUSTED_CONTENT_POLICY =
  `${UNTRUSTED_DATA_SYSTEM_NOTE} Markers: ${OPEN_SENTINEL} / ${CLOSE_SENTINEL}.`;

function briefSliceEntry(key, budget_chars, read, untrusted = false) {
  return Object.freeze({
    key,
    budget_chars,
    read,
    untrusted: untrusted === true,
  });
}

// Plane T cycle T.4 — when the assignment's lens is `browser_behavior_probe`,
// the brief leads with a browser-shaped workflow stanza naming the Patchright
// session driver tools. The HTTP-shaped technique-pack narrative and CLI tools
// stay AVAILABLE (under "Other applicable techniques" / shorter snippets) but
// the brief de-emphasizes them — per T-P1 "brief mentions are the rendering
// target". Sentinel value is the literal lens name; helpers below branch on it.
const BROWSER_BEHAVIOR_PROBE_LENS = "browser_behavior_probe";

// Static intro stanza for the browser_behavior_probe lens. Pinned content so
// the renderer is deterministic across calls. Names the Patchright session
// driver tools the evaluator must use, plus the browser-shaped surface
// vocabulary (DOM source/sink, postMessage, WebAuthn ceremonies, OAuth
// callbacks, ServiceWorker, IndexedDB, multi-step in-session flows).
const BROWSER_BEHAVIOR_PROBE_WORKFLOW_TEXT = [
  "## Browser-shaped surfaces",
  "This wave is assigned `task_lens: browser_behavior_probe`. Lead with the",
  "Patchright session workflow rather than curl-shaped HTTP probes. The browser",
  "session driver is the canonical substrate for DOM source/sink analysis,",
  "postMessage handlers, WebAuthn ceremonies, OAuth callbacks with client-side",
  "token storage, ServiceWorker / IndexedDB inspection, and multi-step",
  "in-session flows.",
  "",
  "Patchright session workflow:",
  "1. `bob_browser_session_start({ target_url })` — opens a stealth Chrome",
  "   session, returns `session_id`. Sessions are scope-checked.",
  "2. `bob_browser_navigate({ session_id, url })` — drive in-scope navigation.",
  "3. `bob_browser_snapshot({ session_id })` — capture the accessibility tree.",
  "4. Exercise the surface with `bob_browser_click`, `bob_browser_type`,",
  "   `bob_browser_fill_form`, `bob_browser_press_key`, `bob_browser_evaluate`",
  "   (scope-guarded — no off-target fetch / XMLHttpRequest).",
  "5. Diff observations via `bob_browser_network_requests`,",
  "   `bob_browser_console_messages`, repeated snapshots.",
  "6. `bob_browser_session_close({ session_id })` when finished — sessions are",
  "   session-scoped and idle-timeout at 5 min.",
  "",
  "The curl-shaped HTTP playbook (`bob_http_scan`, ffuf-style content discovery,",
  "param fuzzing) remains available for follow-up confirmation but is",
  "de-emphasized in this lens to reduce context competition. See",
  "`technique_packs.other_applicable` and `cli_tools` for shorter snippets.",
].join("\n");

const WEB_BRIEF_SLICE_REGISTRY = Object.freeze([
  // Plane T cycle T.4 — `browser_workflow` is the first slice under the
  // `browser_behavior_probe` lens. Other lenses see "" and the slice key is
  // dropped by the registry assembly pass (no empty header inflation).
  briefSliceEntry("browser_workflow", 2048, (context) => (
    context.taskLens === BROWSER_BEHAVIOR_PROBE_LENS
      ? BROWSER_BEHAVIOR_PROBE_WORKFLOW_TEXT
      : ""
  )),
  briefSliceEntry("bypass_table", 4096, (context) => context.bypassTable),
  briefSliceEntry("techniques", 4096, (context) => context.knowledge.techniques),
  briefSliceEntry("payload_hints", 2048, (context) => context.knowledge.payload_hints),
  briefSliceEntry("knowledge_summary", 1024, (context) => context.knowledge.knowledge_summary),
  briefSliceEntry("technique_packs", 8192, (context) => buildTechniquePacksSlice(context)),
  // Plane T cycle T.3 — `cli_tools` lands immediately after `technique_packs`
  // so the operator reads the conditional toolkit alongside the narrative pack
  // selection. Slice returns "" when no packs apply; the registry pass deletes
  // the key so the brief stays absent (not "empty header only").
  briefSliceEntry("cli_tools", 2048, (context) => renderAvailableCliToolsSectionSync({
    surface_fingerprint: context.cliToolSurfaceFingerprint,
    task_lens: context.cliToolTaskLens,
    observations: context.cliToolObservations,
    target_domain: context.cliToolTargetDomain,
  })),
  briefSliceEntry("traffic_summary", 4096 + UNTRUSTED_FENCE_OVERHEAD_CHARS, (context) => context.trafficSummary, true),
  briefSliceEntry("audit_summary", 4096 + UNTRUSTED_FENCE_OVERHEAD_CHARS, (context) => context.auditSummary, true),
  briefSliceEntry("circuit_breaker_summary", 1024, (context) => context.circuitBreakerSummary),
  briefSliceEntry("intel_hints", 4096 + UNTRUSTED_FENCE_OVERHEAD_CHARS, (context) => context.intelHints, true),
  briefSliceEntry("static_scan_hints", 4096 + UNTRUSTED_FENCE_OVERHEAD_CHARS, (context) => context.staticScanHints, true),
  briefSliceEntry("schema_slice", 8192 + UNTRUSTED_FENCE_OVERHEAD_CHARS, (context) => context.schemaSlice, true),
  briefSliceEntry("surface_graph_slice", 8192 + UNTRUSTED_FENCE_OVERHEAD_CHARS, (context) => context.surfaceGraphSlice, true),
  briefSliceEntry("auth_profiles_hint", 512, () => "Call `bob_list_auth_profiles`; pass the chosen profile name as `auth_profile` to `bob_http_scan`."),
]);

// Plane T cycle T.4 — partition the selected technique packs by lens affinity
// when the active lens is `browser_behavior_probe`:
//   - Packs declaring `lens_affinity: ["browser_behavior_probe"]` are
//     FOREGROUNDED (full summary, listed under `selected`).
//   - Packs declaring `lens_affinity: ["behavior_probe"]` (HTTP-only) or no
//     affinity at all are demoted to `other_applicable` with a shorter snippet
//     (id, title, score, matched only — guidance/payload_hints stripped).
// Other lenses keep the existing flat `selected` layout — the partition only
// activates under `browser_behavior_probe`. This is parameter wiring: no
// browser-affined packs ship in T.4; the plumbing is what's load-bearing.
function partitionTechniquePacksByLensAffinity(packs, lens) {
  if (lens !== BROWSER_BEHAVIOR_PROBE_LENS) {
    return { selected: packs.slice(), other_applicable: [] };
  }
  const foregrounded = [];
  const demoted = [];
  for (const pack of packs) {
    const affinity = Array.isArray(pack.lens_affinity) ? pack.lens_affinity : null;
    if (affinity && affinity.includes(BROWSER_BEHAVIOR_PROBE_LENS)) {
      foregrounded.push(pack);
    } else {
      demoted.push({
        id: pack.id,
        title: pack.title,
        matched: Array.isArray(pack.matched) ? pack.matched.slice(0, 4) : [],
        score: pack.score,
        ...(Array.isArray(pack.lens_affinity) ? { lens_affinity: pack.lens_affinity.slice() } : {}),
      });
    }
  }
  return { selected: foregrounded, other_applicable: demoted };
}

function buildTechniquePacksSlice(context) {
  const partitioned = partitionTechniquePacksByLensAffinity(
    context.selectedTechniquePacks,
    context.taskLens,
  );
  const base = {
    selected: partitioned.selected,
    selection_limits: context.selectedTechniquePackLimits,
    registry_warnings: context.selectedTechniquePackResult.registry_warnings,
    selection_budget: {
      candidate_pack_limit: context.candidatePackLimit,
      full_pack_read_limit: context.routeMetadata.context_budget.full_pack_read_limit,
      attempt_log_required: context.routeMetadata.context_budget.attempt_log_required,
    },
  };
  // Only attach `other_applicable` under the browser lens. Under other lenses
  // an empty array would leak the partition plumbing into briefs that never
  // wanted it.
  if (context.taskLens === BROWSER_BEHAVIOR_PROBE_LENS) {
    base.other_applicable = partitioned.other_applicable;
    base.lens_partitioned = true;
  }
  return base;
}

function ossTechniquePackForBrief(pack, { summary = true } = {}) {
  const brief = {
    id: pack.id,
    title: pack.title,
    ...(Array.isArray(pack.lens_affinity) ? { lens_affinity: pack.lens_affinity.slice() } : {}),
  };
  if (summary && typeof pack.summary === "string") {
    brief.summary = pack.summary;
  }
  return brief;
}

const OSS_ROOTCAUSE_FAMILY_BRIEF_LIMIT = 10;

function emptyRootCauseFamilyResult(lens, { unmatchedLens = false } = {}) {
  return {
    lens: typeof lens === "string" && lens.length > 0 ? lens : "unknown",
    family_count: 0,
    suggestions: [],
    unmatched_lens: unmatchedLens,
    summary_limits: {
      item_max_chars: TECHNIQUE_SUMMARY_ITEM_MAX_CHARS,
      limit: 0,
      returned: 0,
    },
  };
}

function normalizedBriefSignal(value) {
  return typeof value === "string" ? value.trim().toLowerCase() : "";
}

function isTrueSignal(value) {
  return value === true || normalizedBriefSignal(value) === "true";
}

function isNativeCodeFamilySurface(surface, routeMetadata) {
  const surfaceObj = surface && typeof surface === "object" && !Array.isArray(surface) ? surface : {};
  const routePack = normalizedBriefSignal(routeMetadata && routeMetadata.capability_pack);
  const surfacePack = normalizedBriefSignal(surfaceObj.capability_pack);
  const surfaceType = normalizedBriefSignal(surfaceObj.surface_type);
  return routePack === "oss_native_code"
    || surfacePack === "oss_native_code"
    || surfaceType === "oss_native_code"
    || isTrueSignal(surfaceObj.native_source)
    || isTrueSignal(surfaceObj.nativeSource);
}

function partitionOssTechniquePacksByLens(packs, taskLens) {
  const packList = Array.isArray(packs) ? packs : [];
  if (!isOssLens(taskLens)) {
    return {
      selected: packList.map((pack) => ossTechniquePackForBrief(pack)),
      other_applicable: [],
    };
  }
  const selected = [];
  const otherApplicable = [];
  for (const pack of packList) {
    const affinity = Array.isArray(pack.lens_affinity) ? pack.lens_affinity : [];
    if (affinity.includes(taskLens)) {
      selected.push(ossTechniquePackForBrief(pack));
    } else {
      otherApplicable.push(ossTechniquePackForBrief(pack, { summary: false }));
    }
  }
  return {
    selected,
    other_applicable: otherApplicable,
  };
}

function buildOssTechniquePacksSlice(taskLens, surface, routeMetadata) {
  const partitioned = partitionOssTechniquePacksByLens(OSS_TECHNIQUE_PACKS, taskLens);
  const routeCapabilityPack = routeMetadata && typeof routeMetadata.capability_pack === "string"
    ? routeMetadata.capability_pack
    : null;
  const familySurface = surface && typeof surface === "object" && !Array.isArray(surface)
    ? { ...surface, ...(routeCapabilityPack ? { capability_pack: routeCapabilityPack } : {}), task_lens: taskLens }
    : { ...(routeCapabilityPack ? { capability_pack: routeCapabilityPack } : {}), task_lens: taskLens };
  const rootCauseFamilies = isNativeCodeFamilySurface(surface, routeMetadata)
    ? suggestFamiliesForSurface(familySurface, {
      lens: taskLens,
      limit: OSS_ROOTCAUSE_FAMILY_BRIEF_LIMIT,
    })
    : emptyRootCauseFamilyResult(taskLens, { unmatchedLens: !isOssLens(taskLens) });
  const renderedFamilies = rootCauseFamilies.suggestions;
  return {
    selected: partitioned.selected,
    other_applicable: partitioned.other_applicable,
    root_cause_families: renderedFamilies,
    root_cause_family_limits: {
      lens: rootCauseFamilies.lens,
      family_count: rootCauseFamilies.family_count,
      unmatched_lens: rootCauseFamilies.unmatched_lens,
      item_max_chars: rootCauseFamilies.summary_limits?.item_max_chars,
      limit: rootCauseFamilies.summary_limits?.limit,
      returned: rootCauseFamilies.summary_limits?.returned,
    },
    selection_limits: {
      selected_chars: JSON.stringify(partitioned.selected).length,
      selected_count: partitioned.selected.length,
      root_cause_family_chars: JSON.stringify(renderedFamilies).length,
      root_cause_family_count: renderedFamilies.length,
    },
    lens_partitioned: isOssLens(taskLens),
  };
}

const SMART_CONTRACT_BRIEF_SLICE_REGISTRY = Object.freeze([
  briefSliceEntry("bob_spec_status", 4096, (context) => context.bobSpecStatus),
  briefSliceEntry("rpc_pool", 4096, (context) => context.rpcPool),
  briefSliceEntry("surface_graph_slice", 8192 + UNTRUSTED_FENCE_OVERHEAD_CHARS, (context) => context.surfaceGraphSlice, true),
]);

// ── Plane O Cycle O.6 — OSS brief slice registry ─────────────────────────────
// `profile: "oss"` is a distinct slice registry per O-D8 (cleaner than folding
// into `web`; matches the precedent that each surface family owns its slice
// registry). Slices included:
//   governance, goal_orientation, repo_workflow, code_surface_pack,
//   technique_packs, cli_tools, recap_and_handoff
//
// `repo_workflow` leads the brief under ANY of the three OSS lenses
// (code_surface_scout, taint_trace, fuzz_run) and SUPPRESSES the curl-shaped
// HTTP playbook (mirroring T.4's `browser_workflow` pattern: an explicit
// stanza names the tools to use and de-emphasizes the alternate playbook).
//
// Cycle O.9 will wire the orchestrator OSS branch + brief dispatch; this
// cycle defines the registry and the slice content so the lens-aware brief
// dispatch is ready when O.9 lands.
const OSS_LENSES = Object.freeze(["code_surface_scout", "taint_trace", "fuzz_run"]);

function isOssLens(value) {
  return typeof value === "string" && OSS_LENSES.includes(value);
}

const REPO_WORKFLOW_TEXT = [
  "## Repo-bound surfaces",
  "This wave is assigned an OSS task lens. Lead with the repo-bound workflow",
  "rather than curl-shaped HTTP probes. The repo target is a locally-checked-",
  "out codebase; all probes stay inside the bound repo or its sandboxed",
  "/work area inside docker.",
  "",
  "OSS workflow tools:",
  "1. `bob_repo_inventory({ target_domain })` — enumerate code modules,",
  "   manifests, dependency declarations, CI configs, entry points, native",
  "   build files. Emits surface.observed events the materializer consumes.",
  "2. `bob_repo_check({ target_domain, file_path, pattern?, regex? })` —",
  "   read-only file probe with secret redaction at the write boundary. Use",
  "   for unsafe-sink hunting, config-misuse hunting, docs-vs-behavior diffs.",
  "3. `bob_repo_docker_run({ target_domain, command, allow_network?: false })`",
  "   — sandboxed execution (cap-drop ALL, no-new-privileges, --user 1000:1000,",
  "   --network none default). Use for fuzz / sanitizer / build runs.",
  "4. Static analyzers via cli_tools: semgrep, trivy, CodeQL, Coccinelle,",
  "   cargo-audit, npm-audit, pip-audit. Each pack lists the install_check",
  "   + invocation template.",
  "",
  "Structure-aware fuzzing: under `fuzz_run`, prefer the bounded",
  "`repo-env.json` `role:\"fuzz\"` command when present. Shape seeds to the",
  "target parser's framing (length-prefixed records, magic bytes, checksums,",
  "chunk order) and start from discovered testdata/seed corpora rather than",
  "blind empty inputs.",
  "",
  "Plateau read: compare only the `fuzz_stats` scalars on recent",
  "`repo-command-runs.jsonl` rows. Flat `cov`/`ft` means switch seed or",
  "harness strategy; it never completes or blocks a surface by itself.",
  "",
  "The curl-shaped HTTP playbook (`bob_http_scan`, ffuf-style content",
  "discovery, param fuzzing) is de-emphasized under OSS lenses — repo-bound",
  "sessions do not own the deployed instance unless an operator explicitly",
  "opts a `target_url` companion (O-P2 / O-P6).",
].join("\n");

const OSS_BRIEF_SLICE_REGISTRY = Object.freeze([
  // `repo_workflow` leads when the active task lens is one of the OSS lenses.
  // Returns "" for other lenses; the registry assembly pass drops empty-string
  // slices so the brief stays absent rather than carrying an empty header.
  briefSliceEntry("repo_workflow", 2048, (context) => (
    isOssLens(context.taskLens) ? REPO_WORKFLOW_TEXT : ""
  )),
  briefSliceEntry("governance", 1024, (context) => context.governance),
  briefSliceEntry("goal_orientation", 1024, (context) => context.goalOrientation),
  briefSliceEntry("code_surface_pack", 4096, (context) => context.codeSurfacePack),
  briefSliceEntry(
    "static_analysis_leads",
    4096 + UNTRUSTED_FENCE_OVERHEAD_CHARS,
    (context) => context.staticAnalysisLeads,
    true,
  ),
  briefSliceEntry("repo_env_recommendations", 4096, (context) => context.repoEnvRecommendations),
  briefSliceEntry("technique_packs", 8192, (context) => context.ossTechniquePacks),
  briefSliceEntry("cli_tools", 2048, (context) => renderAvailableCliToolsSectionSync({
    surface_fingerprint: context.cliToolSurfaceFingerprint,
    task_lens: context.cliToolTaskLens,
    observations: context.cliToolObservations,
    target_domain: context.cliToolTargetDomain,
  })),
  briefSliceEntry("recap_and_handoff", 2048, (context) => context.recapAndHandoff),
]);

// Plane X Cycle X.8 — `node` profile slice registry. The X.8 bob_prepare_node
// tool renders the per-node brief via this registry (separate from the
// wave-scheduler readAssignmentBrief path because TaskGraph dispatch carries
// its own context: a Contract, a derived capability pack, ≤1-hop adjacency,
// and structured recall slices for prior_attempt + adjacent_hypotheses +
// recommended_reads). Slices are listed in the spec's Do step 1 order:
//
//   1. governance                 — common operator-facing context
//   2. node_context               — node_id, kind, surface_refs, severity_floor,
//                                   graph_context_hash
//   3. contract                   — the FULL Contract inlined (already distilled
//                                   per X-D4 + X-P9)
//   4. cross_stack_composition    — Plane X Cycle X.11. For Transition nodes:
//                                   transition_kind + per-kind hunting vocab +
//                                   worked Contract template + both endpoints'
//                                   summary-grade observations + tools from
//                                   BOTH endpoint families. For Surface nodes
//                                   with ≥1 adjacent Transition: one-line
//                                   summary of each adjacent transition. The
//                                   Nike-fix "cross-stack visibility" slice
//                                   per X.11 spec Do step 1 + 2.
//   5. allowed_tools_for_node     — the per-node tool-allow-list constraint
//   6. recommended_reads          — distilled summary of each artifact_ref the
//                                   agent should ground reasoning in
//   7. adjacent_observations      — recent observation.recorded events at
//                                   ≤1-hop; each already summary-grade per X-P9
//   8. prior_attempt              — conditional: when a prior node.transitioned
//                                   → failed exists for the node, surface its
//                                   structured failure_reason + witness ids
//   9. adjacent_hypotheses        — conditional for Surface + Transition: open
//                                   Hypothesis nodes overlapping the dispatched
//                                   node's surfaces
//  10. recap_and_handoff          — handoff stanza
//
// Conditional slices return an empty string when the condition does not hold;
// the registry assembly drops empty-string slices so the brief stays absent
// rather than carrying an empty header (T-R1 inflation guard).
const NODE_BRIEF_SLICE_REGISTRY = Object.freeze([
  briefSliceEntry("governance", 1024, (context) => context.governance),
  briefSliceEntry("node_context", 1024, (context) => context.nodeContext),
  briefSliceEntry("contract", 4096, (context) => context.contract),
  briefSliceEntry("cross_stack_composition", 8192 + UNTRUSTED_FENCE_OVERHEAD_CHARS, (context) => context.crossStackComposition || "", true),
  briefSliceEntry("allowed_tools_for_node", 2048, (context) => context.allowedToolsForNode),
  briefSliceEntry("recommended_reads", 4096 + UNTRUSTED_FENCE_OVERHEAD_CHARS, (context) => context.recommendedReads, true),
  briefSliceEntry("adjacent_observations", 4096 + UNTRUSTED_FENCE_OVERHEAD_CHARS, (context) => context.adjacentObservations, true),
  briefSliceEntry("prior_attempt", 4096 + UNTRUSTED_FENCE_OVERHEAD_CHARS, (context) => context.priorAttempt || "", true),
  briefSliceEntry("adjacent_hypotheses", 2048 + UNTRUSTED_FENCE_OVERHEAD_CHARS, (context) => context.adjacentHypotheses || "", true),
  briefSliceEntry("recap_and_handoff", 2048, (context) => context.recapAndHandoff),
]);

const ASSIGNMENT_BRIEF_SLICE_REGISTRY = Object.freeze({
  web: WEB_BRIEF_SLICE_REGISTRY,
  smart_contract: SMART_CONTRACT_BRIEF_SLICE_REGISTRY,
  oss: OSS_BRIEF_SLICE_REGISTRY,
  // Plane X Cycle X.8 — TaskGraph node dispatch profile. Read via
  // bob_prepare_node, NOT via readAssignmentBrief.
  node: NODE_BRIEF_SLICE_REGISTRY,
});

function briefSliceRegistryForProfile(profile) {
  if (profile === "web") {
    return WEB_BRIEF_SLICE_REGISTRY;
  }
  if (typeof profile === "string" && profile.startsWith("smart_contract_")) {
    return SMART_CONTRACT_BRIEF_SLICE_REGISTRY;
  }
  if (profile === "oss") {
    return OSS_BRIEF_SLICE_REGISTRY;
  }
  if (profile === "node") {
    return NODE_BRIEF_SLICE_REGISTRY;
  }
  return null;
}

// Render the `node` profile brief from a precomputed context bag. Used by
// bob_prepare_node (X.8). Drops conditional slices that return an empty
// string so an absent prior_attempt or adjacent_hypotheses section does not
// carry an empty header into the brief.
//
// Plane X Cycle X.11 — the `cross_stack_composition` slice is conditional
// too: emitted for Transition nodes ALWAYS and for Surface nodes ONLY when
// there is ≥1 adjacent Transition (per X.11 spec Do step 2). The prepare-node
// context sets it to "" when neither applies; we drop the empty key so the
// brief stays absent rather than carrying an empty header (T-R1 guard).
function renderNodeBriefExtras(context) {
  const extras = {
    untrusted_content_policy: UNTRUSTED_CONTENT_POLICY,
    ...buildBriefExtrasFromRegistry(NODE_BRIEF_SLICE_REGISTRY, context),
  };
  if (extras.prior_attempt === "" || extras.prior_attempt == null) {
    delete extras.prior_attempt;
  }
  if (extras.adjacent_hypotheses === "" || extras.adjacent_hypotheses == null) {
    delete extras.adjacent_hypotheses;
  }
  if (extras.cross_stack_composition === "" || extras.cross_stack_composition == null) {
    delete extras.cross_stack_composition;
  }
  return extras;
}

function buildBriefExtrasFromRegistry(registry, context) {
  const extras = {};
  for (const slice of registry) {
    const value = slice.read(context);
    if (slice.untrusted === true) {
      const rendered = renderUntrustedBriefSlice(slice.key, value);
      if (rendered === "") continue;
      extras[slice.key] = rendered;
      continue;
    }
    extras[slice.key] = value;
  }
  return extras;
}

function renderUntrustedBriefSlice(label, value) {
  if (value === "" || value == null) return "";
  let body;
  if (Buffer.isBuffer(value) || typeof value === "string") {
    body = value;
  } else {
    try {
      body = JSON.stringify(value, null, 2);
    } catch {
      body = String(value);
    }
  }
  if (body == null || body === "") return "";
  const overhead = fenceOverheadForLabel(label);
  if (overhead > UNTRUSTED_FENCE_OVERHEAD_CHARS) {
    throw new Error(`untrusted brief slice ${label} fence overhead ${overhead} exceeds addend ${UNTRUSTED_FENCE_OVERHEAD_CHARS}`);
  }
  return wrapUntrusted(body, { label }).fenced;
}

function resolveBypassTable(techStack) {
  if (!Array.isArray(techStack)) return BYPASS_TABLE_DEFAULT;
  for (const tech of techStack) {
    const key = String(tech).toLowerCase();
    for (const [pattern, file] of Object.entries(BYPASS_TABLE_MAP)) {
      if (key.includes(pattern)) return file;
    }
  }
  return BYPASS_TABLE_DEFAULT;
}

function isBriefScalar(value) {
  return value == null || ["string", "number", "boolean"].includes(typeof value);
}

// Split a surface field name into lowercased token segments so the denylist
// can reason about it segment-wise — `authorization_header`, `csrfToken`,
// `session-cookie`, and `api-key` all normalize through here. snake_case +
// camelCase + dashed-case all collapse to the same segment list.
function surfaceFieldNameSegments(field) {
  return String(field)
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1_$2")
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
}

function hasAdjacentSegments(segments, first, second) {
  for (let i = 0; i < segments.length - 1; i += 1) {
    if (segments[i] === first && segments[i + 1] === second) {
      return true;
    }
  }
  return false;
}

// Sensitive-field guard for copy-by-default. Returns true for exact-name
// matches (cookies, raw bodies, auth), for fields containing a sensitive
// segment (session_cookie, leaked_secrets, authorization_header), and for
// adjacent api/key + private/key splits (apiKey, private-key).
function shouldDropSurfaceFieldForBrief(field) {
  const normalizedField = String(field).toLowerCase();
  if (ASSIGNMENT_BRIEF_SURFACE_FIELD_DROP_EXACT.has(normalizedField)) return true;

  const segments = surfaceFieldNameSegments(field);
  if (segments.some((segment) => ASSIGNMENT_BRIEF_SURFACE_SENSITIVE_FIELD_SEGMENTS.has(segment))) {
    return true;
  }
  return hasAdjacentSegments(segments, "api", "key")
    || hasAdjacentSegments(segments, "private", "key");
}

function capStringValue(value, maxChars) {
  if (typeof value !== "string" || value.length <= maxChars) {
    return { value, truncated: false, total_chars: typeof value === "string" ? value.length : null };
  }
  return {
    value: value.slice(0, maxChars),
    truncated: true,
    total_chars: value.length,
  };
}

const REPO_ENV_RECOMMENDED_COMMAND_LIMIT = 8;
const REPO_ENV_COMMAND_ARG_LIMIT = 12;
// Match bob_repo_docker_run's per-token limit so briefed command arrays stay
// executable instead of silently clipping long `sh -lc` recipes.
const REPO_ENV_COMMAND_ARG_MAX_CHARS = 2048;
const REPO_ENV_STRING_MAX_CHARS = 240;
const REPO_ENV_SEED_CORPUS_LIMIT = 8;
const REPO_ENV_SEED_SAMPLE_LIMIT = 8;

function cappedBriefString(value, maxChars = REPO_ENV_STRING_MAX_CHARS) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  if (!trimmed) return null;
  return capStringValue(trimmed, maxChars).value;
}

function slimRepoEnvCommand(command) {
  if (command == null || typeof command !== "object" || Array.isArray(command)) return null;
  const slim = {};
  for (const field of ["id", "role", "description", "seed_path"]) {
    const value = cappedBriefString(command[field]);
    if (value) slim[field] = value;
  }
  if (Array.isArray(command.command)) {
    const argv = command.command
      .slice(0, REPO_ENV_COMMAND_ARG_LIMIT)
      .map((arg) => cappedBriefString(String(arg), REPO_ENV_COMMAND_ARG_MAX_CHARS))
      .filter(Boolean);
    if (argv.length > 0) slim.command = argv;
  }
  return Object.keys(slim).length > 0 ? slim : null;
}

function slimSeedCorpusEntry(entry) {
  if (entry == null || typeof entry !== "object" || Array.isArray(entry)) return null;
  const relPath = cappedBriefString(entry.rel_path);
  if (!relPath) return null;
  const slim = { rel_path: relPath };
  for (const field of ["file_count", "total_bytes"]) {
    if (Number.isInteger(entry[field]) && entry[field] >= 0) slim[field] = entry[field];
  }
  if (typeof entry.has_zip === "boolean") slim.has_zip = entry.has_zip;
  if (typeof entry.truncated === "boolean") slim.truncated = entry.truncated;
  if (Array.isArray(entry.sample_rels)) {
    const samples = entry.sample_rels
      .slice(0, REPO_ENV_SEED_SAMPLE_LIMIT)
      .map((sample) => cappedBriefString(String(sample), REPO_ENV_STRING_MAX_CHARS))
      .filter(Boolean);
    if (samples.length > 0) slim.sample_rels = samples;
  }
  const hash = cappedBriefString(entry.manifest_hash, 80);
  if (hash) slim.manifest_hash = hash;
  return slim;
}

function buildRepoEnvRecommendationsForBrief(domain) {
  const filePath = repoEnvPath(domain);
  if (!fs.existsSync(filePath)) return null;
  let document;
  try {
    document = JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch {
    return null;
  }
  if (document == null || typeof document !== "object" || Array.isArray(document)) return null;

  const recommendedCommands = Array.isArray(document.recommended_commands)
    ? document.recommended_commands
      .slice(0, REPO_ENV_RECOMMENDED_COMMAND_LIMIT)
      .map(slimRepoEnvCommand)
      .filter(Boolean)
    : [];
  const seedCorpus = Array.isArray(document.seed_corpus)
    ? document.seed_corpus
      .slice(0, REPO_ENV_SEED_CORPUS_LIMIT)
      .map(slimSeedCorpusEntry)
      .filter(Boolean)
    : [];

  const detection = document.detection && typeof document.detection === "object" && !Array.isArray(document.detection)
    ? document.detection
    : {};
  const seedCorpusCount = Number.isInteger(detection.seed_corpus_count) && detection.seed_corpus_count >= 0
    ? detection.seed_corpus_count
    : seedCorpus.length;

  if (recommendedCommands.length === 0 && seedCorpus.length === 0) return null;
  const result = {
    source: "repo-env.json",
    language: cappedBriefString(detection.language, 80),
    dry_run: typeof document.dry_run === "boolean" ? document.dry_run : null,
    build_image: typeof document.build_image === "boolean" ? document.build_image : null,
    seed_corpus_count: seedCorpusCount,
    recommended_commands: recommendedCommands,
    seed_corpus: seedCorpus,
    usage: "Readable bounded subset for OSS evaluators; run command arrays through bob_repo_docker_run, not shell reads of repo-env.json.",
  };
  for (const key of Object.keys(result)) {
    if (result[key] == null) delete result[key];
  }
  return result;
}

function cappedSurfaceArray(value, limit) {
  const values = Array.isArray(value)
    ? value
    : value == null
      ? []
      : [value];
  let truncatedValues = 0;
  const shownValues = values.filter((item) => item != null).slice(0, limit).map((item) => {
    const capped = capStringValue(String(item), ASSIGNMENT_BRIEF_ARRAY_ITEM_MAX_CHARS);
    if (capped.truncated) truncatedValues += 1;
    return capped.value;
  });
  const limits = {
    shown: shownValues.length,
    total: values.length,
    omitted: Math.max(0, values.length - shownValues.length),
  };
  if (truncatedValues > 0) {
    limits.truncated_values = truncatedValues;
    limits.max_value_chars = ASSIGNMENT_BRIEF_ARRAY_ITEM_MAX_CHARS;
  }
  return {
    values: shownValues,
    limits,
  };
}

function slimRankingForBrief(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const ranking = {};
  if (Number.isFinite(value.version)) ranking.version = value.version;
  if (Number.isFinite(value.score)) ranking.score = value.score;
  if (isBriefScalar(value.priority)) {
    ranking.priority = capStringValue(String(value.priority), ASSIGNMENT_BRIEF_SURFACE_SCALAR_LIMITS.priority).value;
  }
  const cappedReasons = cappedSurfaceArray(value.reasons, ASSIGNMENT_BRIEF_RANKING_REASON_LIMIT);
  ranking.reasons = cappedReasons.values.map((reason) => {
    const capped = capStringValue(reason, ASSIGNMENT_BRIEF_RANKING_REASON_MAX_CHARS);
    return capped.value;
  });
  return ranking;
}

function slimSurfaceForBrief(surface) {
  const source = surface && typeof surface === "object" && !Array.isArray(surface) ? surface : {};
  const slimSurface = {};
  const surfaceLimits = {};
  const handled = new Set(["ranking"]);

  const copyScalar = (field, value, maxChars) => {
    const normalizedValue = typeof value === "string" ? value : String(value);
    const capped = capStringValue(normalizedValue, maxChars);
    slimSurface[field] = capped.value;
    if (capped.truncated) {
      surfaceLimits[field] = {
        shown_chars: capped.value.length,
        total_chars: capped.total_chars,
        omitted_chars: capped.total_chars - capped.value.length,
      };
    }
  };

  for (const [field, maxChars] of Object.entries(ASSIGNMENT_BRIEF_SURFACE_SCALAR_LIMITS)) {
    handled.add(field);
    if (shouldDropSurfaceFieldForBrief(field)) continue;
    const value = source[field];
    if (!isBriefScalar(value) || value == null) continue;
    copyScalar(field, value, maxChars);
  }

  const ranking = slimRankingForBrief(source.ranking);
  if (ranking) {
    slimSurface.ranking = ranking;
  }

  for (const [field, limit] of Object.entries(ASSIGNMENT_BRIEF_SURFACE_ARRAY_LIMITS)) {
    handled.add(field);
    if (shouldDropSurfaceFieldForBrief(field)) continue;
    const capped = cappedSurfaceArray(source[field], limit);
    slimSurface[field] = capped.values;
    surfaceLimits[field] = capped.limits;
  }

  return {
    surface: slimSurface,
    surface_limits: surfaceLimits,
  };
}

function readSurfaceInfoForBrief(domain, routeMetadata) {
  if (routeMetadata.brief_profile === "oss") {
    const projected = currentSurfaces(domain);
    if (projected.source === "missing") {
      throw new Error(`Missing surface projection: ${projected.path}`);
    }
    return projected;
  }
  try {
    return readAttackSurfaceStrict(domain);
  } catch (error) {
    if (error && /^Missing attack surface JSON:/.test(error.message || "")) {
      const projected = currentSurfaces(domain);
      if (projected.source !== "missing") return projected;
    }
    throw error;
  }
}

function readAssignmentBrief(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const wave = parseWaveId(args.wave);
  const agent = parseAgentId(args.agent);
  const egressProfile = normalizeOptionalText(args.egress_profile, "egress_profile") || "default";
  const internalHostPolicy = blockInternalHostsRequestPolicy(domain, args);
  const internalHostContext = blockInternalHostsPolicyFields(internalHostPolicy);
  const { identity: egressIdentity } = resolveAndAssertSessionEgressIdentity(domain, egressProfile, {
    source: "bob_read_assignment_brief",
  });
  const waveNumber = Number(wave.slice(1));

  // 1. Load and validate assignment
  const { assignmentByAgent } = loadWaveAssignments(domain, waveNumber);
  const assignment = assignmentByAgent.get(agent);
  if (!assignment) {
    throw new Error(`Agent ${agent} is not assigned in wave ${wave}`);
  }
  // normalizeAssignmentRouteMetadata already validates brief_profile against
  // the capability-packs registry; any registered profile (web today, plus
  // smart_contract_* once SC packs are added) is accepted by assignment-brief.
  const routeMetadata = normalizeAssignmentRouteMetadata(assignment);

  // 2. Load surfaces and find assigned surface. OSS repo sessions usually
  // only have the materialized surface-index.json. Web/SC briefs prefer the
  // legacy attack_surface.json when present because it carries rich cross-
  // cutting fields (for example valid_surface_ids) that the projection trims.
  const attackSurface = readSurfaceInfoForBrief(domain, routeMetadata);
  let surfacesForBrief = attackSurface.document.surfaces;
  // Ranking summarizes traffic + public intel per surface, neither of which
  // non-web evaluators consume. Skip it for non-web profiles to avoid
  // paying that I/O cost for a result we'd just drop.
  const isWebBrief = routeMetadata.brief_profile === "web";
  if (isWebBrief) {
    try {
      const ranked = rankAttackSurfaces(domain);
      if (ranked && Array.isArray(ranked.surfaces)) {
        surfacesForBrief = ranked.surfaces;
      }
    } catch {}
  }
  const surfaceObj = surfacesForBrief.find(
    (s) => s.id === assignment.surface_id,
  );
  if (!surfaceObj) {
    throw new Error(`Surface ${assignment.surface_id} not found in current surface projection`);
  }

  // 3. Read session state for exclusions
  const { state } = readSessionStateStrict(domain);

  const deadEndResult = filterExclusionsByHosts(state.dead_ends, surfaceObj.hosts);
  const wafResult = filterExclusionsByHosts(state.waf_blocked_endpoints, surfaceObj.hosts);
  const slimSurface = slimSurfaceForBrief(surfaceObj);
  // coverage_summary stays in both profiles: SC evaluators call bob_log_coverage
  // for chain-flavored bug-class taxonomies, and resumed waves want to know
  // what was already tested regardless of profile.
  const coverageSummary = buildCoverageSummaryForSurface(
    readCoverageRecordsFromJsonl(domain),
    assignment.surface_id,
  );

  // Dispatch explicitly on brief_profile. The capability-pack registry is
  // the source of truth for what profiles exist; an unknown profile is a
  // route-metadata bug, not a fall-through to SC.
  const profileExtras = buildBriefExtrasForProfile(routeMetadata.brief_profile, {
    domain,
    surface: surfaceObj,
    assignment,
    routeMetadata,
  });

  // Plane Y Cycle Y.5 — wave-scheduler derivation slice (Y-P5 / Y-P6 / O5).
  // The synthetic Surface node + friction history + target_class flow purely
  // through `derivePackForNode`; we attach the bounded summary at the brief
  // top level so wave-dispatched evaluators see the per-spawn narrowing
  // surface alongside the existing profile extras. Frontier-event /
  // queue-policy reads happen here (caller side, Y-P4) and fail soft — a
  // missing frontier-events log or queue-policy.json yields zero frictions
  // and a null target_class rather than aborting brief composition.
  let waveBriefDerivation = null;
  try {
    const frontierEvents = (() => {
      try { return readFrontierEvents(domain); } catch { return []; }
    })();
    waveBriefDerivation = buildWaveBriefDerivation({
      surfaceObj,
      surfaceId: assignment.surface_id,
      waveNumber,
      frontierEvents,
      // queuePolicy intentionally omitted — the derivation helper reads
      // the raw policy JSON via `domain` so the rev-4 `target_class_default`
      // field surfaces even before Y.6 lands the normalizer support.
      queuePolicy: null,
      domain,
      explicitTargetClass: null,
      // Y-P11 quarantine: voluntary tool_inadequate frictions are excluded
      // by default; operator opts in via include_inadequacy on the
      // selector. The wave brief honors the default (false) — operator
      // override lands on the promotion-tool path (Y.6).
      includeInadequacy: false,
    });
  } catch {
    waveBriefDerivation = null;
  }

  // Plane Y Cycle Y.5 (W1 — Y-P14d) — role-specific trace-reading
  // expectations slice. The composer joins Y.2's
  // FRICTION_PROMPT_FRAGMENTS to Y.6's ROLE_TRACE_EXPECTATIONS. When the
  // Y.6 module is absent the composer returns null and we omit the slice
  // entirely (drop-empty-keys discipline mirrors WEB_BRIEF_SLICE_REGISTRY).
  const traceReadingExpectations = composeTraceReadingExpectationsForRole(
    routeMetadata.evaluator_agent,
  );

  return JSON.stringify({
    untrusted_content_policy: UNTRUSTED_CONTENT_POLICY,
    run_context: {
      target_domain: domain,
      lifecycle_state: state.lifecycle_state,
      phase: state.phase,
      auth_status: state.auth_status,
      egress_profile: egressIdentity.egress_profile,
      egress_region: egressIdentity.egress_region,
      proxy_configured: egressIdentity.proxy_configured,
      egress_profile_identity_hash: egressIdentity.egress_profile_identity_hash,
      egress_profile_identity_version: egressIdentity.egress_profile_identity_version,
      ...internalHostContext,
      capability_pack: routeMetadata.capability_pack,
      capability_pack_version: routeMetadata.capability_pack_version,
      evaluator_agent: routeMetadata.evaluator_agent,
      brief_profile: routeMetadata.brief_profile,
      context_budget: routeMetadata.context_budget,
    },
    target_url: state.target_url,
    wave,
    agent,
    surface: slimSurface.surface,
    surface_limits: slimSurface.surface_limits,
    valid_surface_ids: attackSurface.surface_ids || attackSurface.document.surfaces.map((s) => s.id),
    dead_ends: deadEndResult.filtered,
    waf_blocked_endpoints: wafResult.filtered,
    exclusions_summary: {
      dead_ends_total: deadEndResult.total,
      dead_ends_shown: deadEndResult.filtered.length,
      dead_ends_omitted: deadEndResult.omitted,
      waf_blocked_total: wafResult.total,
      waf_blocked_shown: wafResult.filtered.length,
      waf_blocked_omitted: wafResult.omitted,
    },
    coverage_summary: coverageSummary,
    ranking_summary: surfaceObj.ranking || null,
    // Plane Y Cycle Y.5 — top-level slice carrying the wave-side
    // derivation summary (friction-widened allowed tools, target_class
    // auxiliaries, technique pack ids). Distinct from `technique_packs`
    // inside profile extras because it reflects the Y.4 PURE
    // derivation, not the technique-pack scorer narrative.
    wave_brief_derivation: waveBriefDerivation,
    // Plane Y Cycle Y.5 (W1) — role-trace expectations composed per
    // Y-P14d. Null until Y.6 lands role-trace-expectations.js OR when
    // the assignment's evaluator_agent has no mapped entry.
    ...(traceReadingExpectations ? { trace_reading_expectations: traceReadingExpectations } : {}),
    ...profileExtras,
  }, null, 2);
}

// Profile dispatch table. Adding a non-web, non-smart-contract pack means
// adding both a pack record (capability-packs.js) and an entry here — fail
// loudly on any profile we did not explicitly opt in.
function buildBriefExtrasForProfile(profile, { domain, surface, assignment, routeMetadata }) {
  const registry = briefSliceRegistryForProfile(profile);
  if (registry === WEB_BRIEF_SLICE_REGISTRY) {
    return buildWebBriefExtras(domain, surface, routeMetadata, assignment);
  }
  if (registry === OSS_BRIEF_SLICE_REGISTRY) {
    return buildOssBriefExtras(domain, surface, routeMetadata, assignment);
  }
  if (registry === SMART_CONTRACT_BRIEF_SLICE_REGISTRY) {
    return buildSmartContractBriefExtras(domain, surface, assignment);
  }
  throw new Error(`Unsupported brief profile: ${profile}`);
}

// Plane T cycle T.3 — derive the cli-tool surface fingerprint from the
// assigned surface object. The fingerprint is the input to
// `selectCliToolPacks`'s `applicable_when` predicates. We hand the predicate
// the minimum it needs to fire (kind, host, hosts[], session_dir,
// target_domain) so the cli-tool-pack predicates stay pure functions of
// observed surface properties (T-R8).
//
// Hosts are capped at CLI_TOOL_HOST_PLACEHOLDER_MAX_CHARS before they can
// land in an invocation_template `<host>` placeholder. Mirrors the endpoint
// cap below — a 5000-char host string must not echo verbatim into the brief.
const CLI_TOOL_HOST_PLACEHOLDER_MAX_CHARS = 240;

function capHostForPlaceholder(value) {
  const text = String(value);
  return text.length > CLI_TOOL_HOST_PLACEHOLDER_MAX_CHARS
    ? text.slice(0, CLI_TOOL_HOST_PLACEHOLDER_MAX_CHARS)
    : text;
}

function buildCliToolSurfaceFingerprint(surfaceObj, brief_profile, domain) {
  const fingerprint = {};
  if (typeof brief_profile === "string") {
    if (brief_profile === "web") {
      fingerprint.kind = "web";
    } else if (brief_profile === "oss") {
      fingerprint.kind = "repo";
    } else if (brief_profile.startsWith("smart_contract")) {
      fingerprint.kind = "smart_contract";
    }
  }
  if (surfaceObj && typeof surfaceObj === "object") {
    if (Array.isArray(surfaceObj.hosts) && surfaceObj.hosts.length > 0) {
      fingerprint.hosts = surfaceObj.hosts.map(capHostForPlaceholder);
      fingerprint.host = capHostForPlaceholder(surfaceObj.hosts[0]);
    }
    if (Array.isArray(surfaceObj.tech_stack) && surfaceObj.tech_stack.length > 0) {
      fingerprint.tech_stack = surfaceObj.tech_stack.slice();
    }
  }
  if (typeof domain === "string" && domain) {
    fingerprint.target_domain = capHostForPlaceholder(domain);
    if (!fingerprint.host) fingerprint.host = capHostForPlaceholder(domain);
  }
  return fingerprint;
}

// Project the surface object into the observation summary shape the cli-tool
// pack predicates expect. T.3 fills `routes_count` / `observed_endpoints`
// from the surface signal; T.5+ will add `items[]` from the frontier
// observation feed (jwt_observed, etc.). Per T-R8, this projection is a pure
// function of the surface — no clock, no I/O.
//
// Each endpoint is capped at CLI_TOOL_ENDPOINT_PLACEHOLDER_MAX_CHARS before
// it can land in an invocation_template `<endpoint>` placeholder. Without
// this cap, a pathological surface (e.g., a 5000-char endpoint string) would
// echo verbatim into the brief — re-introducing the same unbounded-scalar
// bloat that `slimSurfaceForBrief` already guards against (T-R1).
const CLI_TOOL_ENDPOINT_PLACEHOLDER_MAX_CHARS = 240;

function buildCliToolObservationsSummary(surfaceObj) {
  const summary = {};
  if (surfaceObj && typeof surfaceObj === "object") {
    const endpoints = Array.isArray(surfaceObj.endpoints) ? surfaceObj.endpoints.filter((e) => e != null) : [];
    summary.routes_count = endpoints.length;
    if (endpoints.length > 0) {
      summary.observed_endpoints = endpoints.map((endpoint) => {
        const text = String(endpoint);
        return text.length > CLI_TOOL_ENDPOINT_PLACEHOLDER_MAX_CHARS
          ? text.slice(0, CLI_TOOL_ENDPOINT_PLACEHOLDER_MAX_CHARS)
          : text;
      });
    }
  } else {
    summary.routes_count = 0;
  }
  return summary;
}

// Web profile carries HTTP-flavored intel: bypass tables for the surface's
// tech stack, web technique/payload knowledge, traffic + audit + circuit
// breaker summaries from real HTTP probes, public bounty intel, static scan
// hints, and an auth-profile hint pointing the evaluator at bob_list_auth_profiles.
const LEGACY_TECHNIQUE_SUMMARY_LIMIT = 2;

function basenameForSummary(filePath) {
  if (!filePath) return null;
  return String(filePath).split(/[\\/]/).pop() || null;
}

function legacyKnowledgeFromTechniquePacks(selectedResult, selectedTechniquePacks) {
  const legacyEntries = selectedTechniquePacks.slice(0, LEGACY_TECHNIQUE_SUMMARY_LIMIT);
  const techniques = legacyEntries
    .filter((pack) => pack.summary && Array.isArray(pack.summary.guidance) && pack.summary.guidance.length > 0)
    .map((pack) => ({
      id: pack.id,
      title: pack.title,
      matched: Array.isArray(pack.matched) ? pack.matched.slice(0, 6) : [],
      guidance: pack.summary.guidance.slice(0, 4),
    }));
  const payloadHints = legacyEntries
    .filter((pack) => pack.summary && Array.isArray(pack.summary.payload_hints) && pack.summary.payload_hints.length > 0)
    .map((pack) => ({
      id: pack.id,
      title: pack.title,
      hints: pack.summary.payload_hints.slice(0, 4),
    }));
  const charCount = JSON.stringify({ techniques, payload_hints: payloadHints }).length;
  return {
    techniques,
    payload_hints: payloadHints,
    knowledge_summary: {
      source: basenameForSummary(selectedResult.source),
      entries_returned: legacyEntries.length,
      capped: selectedTechniquePacks.length > legacyEntries.length,
      char_count: charCount,
      max_chars: EVALUATOR_KNOWLEDGE_MAX_CHARS,
      max_entries: LEGACY_TECHNIQUE_SUMMARY_LIMIT,
      legacy_compatibility: true,
      registry_warnings: selectedResult.registry_warnings || [],
    },
  };
}

function buildWebBriefExtras(domain, surfaceObj, routeMetadata, assignment) {
  const bypassFile = resolveBypassTable(surfaceObj.tech_stack);
  let bypassTable = "";
  try {
    const content = readResourceText("bypass-tables", bypassFile);
    if (content != null) bypassTable = content.trim();
  } catch {}
  const candidatePackLimit = routeMetadata.context_budget.candidate_pack_limit;
  const selectedTechniquePackResult = selectTechniquePacksForSurface(surfaceObj, {
    capabilityPack: routeMetadata.capability_pack,
    maxPacks: candidatePackLimit,
    includeAttempted: true,
  });
  const selectedTechniquePacks = selectedTechniquePackResult.selected.map((pack) => ({
    id: pack.id,
    version: pack.version,
    title: pack.title,
    matched: pack.matched,
    score: pack.score,
    summary: pack.summary,
    summary_limits: pack.summary_limits,
    estimated_tokens: pack.estimated_tokens,
    // Plane T cycle T.4 — `lens_affinity` flows through to the brief so the
    // operator (and downstream renderers) can see which packs target the
    // active lens. Absent on packs that did not declare an affinity.
    ...(Array.isArray(pack.lens_affinity) ? { lens_affinity: pack.lens_affinity.slice() } : {}),
  }));
  const selectedTechniquePackLimits = {
    ...selectedTechniquePackResult.selection_limits,
    selected_chars: JSON.stringify(selectedTechniquePacks).length,
    selected_count: selectedTechniquePacks.length,
  };
  const knowledge = legacyKnowledgeFromTechniquePacks(selectedTechniquePackResult, selectedTechniquePacks);
  const trafficSummary = summarizeTrafficRecords(
    readTrafficRecordsFromJsonl(domain),
    { surface: surfaceObj },
  );
  const auditRecords = readHttpAuditRecordsFromJsonl(domain);
  const auditSummary = summarizeHttpAuditRecords(auditRecords, { surface: surfaceObj, targetDomain: domain });
  const circuitBreakerSummary = buildCircuitBreakerSummary(auditRecords, { surface: surfaceObj });
  const intelHints = summarizePublicIntelForSurface(domain, surfaceObj);
  const staticScanHints = summarizeStaticScanHints(domain, { surface: surfaceObj });
  const schemaSlice = summarizeSchemaSliceForSurface(domain, surfaceObj);
  const surfaceGraphSlice = summarizeSurfaceGraphForSurface(domain, surfaceObj);
  // Plane T cycle T.3 — cli-tool render context. Surface fingerprint + task
  // lens + observations summary feed the conditional pack selection that
  // lands in the brief immediately after the technique-pack narrative.
  const cliToolSurfaceFingerprint = buildCliToolSurfaceFingerprint(surfaceObj, routeMetadata.brief_profile, domain);
  const cliToolTaskLens = assignment && typeof assignment.task_lens === "string" ? assignment.task_lens : null;
  const cliToolObservations = buildCliToolObservationsSummary(surfaceObj);
  const webBriefContext = {
    // Plane T cycle T.4 — `taskLens` drives lens-aware slice rendering
    // (browser_workflow stanza, technique-pack partitioning). Distinct from
    // `cliToolTaskLens` only because the latter is the explicit knob the cli
    // tool predicates already consume; both currently mirror the same value.
    taskLens: cliToolTaskLens,
    bypassTable: bypassTable || null,
    knowledge,
    selectedTechniquePacks,
    selectedTechniquePackLimits,
    selectedTechniquePackResult,
    candidatePackLimit,
    routeMetadata,
    trafficSummary,
    auditSummary,
    circuitBreakerSummary,
    intelHints,
    staticScanHints,
    schemaSlice,
    surfaceGraphSlice,
    cliToolSurfaceFingerprint,
    cliToolTaskLens,
    cliToolObservations,
    cliToolTargetDomain: domain,
  };
  const extras = buildBriefExtrasFromRegistry(WEB_BRIEF_SLICE_REGISTRY, webBriefContext);
  // Per T-R1 "brief inflation": drop `cli_tools` entirely when no packs
  // apply. An empty header would still cost tokens and confuse the operator
  // who would scan for invocations under the section.
  if (!extras.cli_tools) {
    delete extras.cli_tools;
  }
  // Same rule for the T.4 `browser_workflow` slice — empty under any lens
  // other than `browser_behavior_probe`.
  if (!extras.browser_workflow) {
    delete extras.browser_workflow;
  }
  return extras;
}

const STATIC_ANALYSIS_LEAD_MAX_ITEMS = 10;
const STATIC_ANALYSIS_LEAD_SLICE_MAX_CHARS = 4096;
const STATIC_ANALYSIS_LEAD_LINE_MAX_CHARS = 300;

function staticLeadField(lead, fieldName) {
  const meta = lead && typeof lead.reachability_meta === "object" && !Array.isArray(lead.reachability_meta)
    ? lead.reachability_meta
    : null;
  if (meta && Object.prototype.hasOwnProperty.call(meta, fieldName)) {
    return String(meta[fieldName]) || null;
  }
  const prefix = `${fieldName}=`;
  for (const flow of (Array.isArray(lead.high_value_flows) ? lead.high_value_flows : [])) {
    if (typeof flow === "string" && flow.startsWith(prefix)) return flow.slice(prefix.length) || null;
  }
  return null;
}

function staticLeadEndpoint(lead) {
  const endpoints = Array.isArray(lead.endpoints) ? lead.endpoints : [];
  return endpoints.find((endpoint) => typeof endpoint === "string" && endpoint.includes(":"))
    || endpoints.find((endpoint) => typeof endpoint === "string")
    || "unknown:0";
}

function staticLeadEndpointFile(endpoint) {
  const match = String(endpoint).match(/^(.+):[1-9][0-9]*$/);
  return match ? match[1] : String(endpoint);
}

function surfaceReferenceValues(surfaceObj) {
  if (!surfaceObj || typeof surfaceObj !== "object" || Array.isArray(surfaceObj)) return [];
  return [
    surfaceObj.file_path,
    surfaceObj.file,
    surfaceObj.path,
    ...(Array.isArray(surfaceObj.endpoints) ? surfaceObj.endpoints : []),
  ].filter((value) => typeof value === "string" && value.length > 0);
}

function endpointMatchesSurface(endpoint, surfaceObj) {
  const file = staticLeadEndpointFile(endpoint);
  return surfaceReferenceValues(surfaceObj).some((value) => (
    value === endpoint
    || value === file
    || file.startsWith(`${value}/`)
  ));
}

function staticLeadAppliesToSurface(lead, surfaceObj) {
  if (!lead || lead.source !== "bob_static_scan" || lead.surface_type !== "oss_static_sink") return false;
  if (lead.source_surface_id && surfaceObj && lead.source_surface_id === surfaceObj.id) return true;
  if (lead.promoted_surface_id && surfaceObj && lead.promoted_surface_id === surfaceObj.id) return true;
  if (lead.source_surface_id && surfaceObj && lead.source_surface_id !== surfaceObj.id) return false;
  const endpoints = Array.isArray(lead.endpoints) ? lead.endpoints : [];
  if (endpoints.some((endpoint) => endpointMatchesSurface(endpoint, surfaceObj))) return true;
  return !lead.source_surface_id && (!surfaceObj || !surfaceObj.id);
}

function staticLeadTimestamp(lead) {
  const value = lead.scanned_at || lead.indexed_at || lead.created_at || "";
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

function sortStaticAnalysisLeads(leads) {
  return [...leads].sort((a, b) => (
    (b.score || 0) - (a.score || 0)
      || staticLeadTimestamp(b) - staticLeadTimestamp(a)
      || String(a.key || a.id || "").localeCompare(String(b.key || b.id || ""))
  ));
}

function capStaticLeadLine(line) {
  if (line.length <= STATIC_ANALYSIS_LEAD_LINE_MAX_CHARS) return line;
  return line.slice(0, STATIC_ANALYSIS_LEAD_LINE_MAX_CHARS);
}

function capStaticAnalysisLeadSlice(lines) {
  const kept = [];
  for (const line of lines) {
    const next = [...kept, line].join("\n");
    if (next.length > STATIC_ANALYSIS_LEAD_SLICE_MAX_CHARS) break;
    kept.push(line);
  }
  return kept.join("\n");
}

function staticLeadBriefValue(value) {
  return String(value == null ? "" : value)
    .replace(/[|\r\n]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function renderStaticAnalysisLead(lead) {
  const endpoint = staticLeadBriefValue(staticLeadEndpoint(lead)) || "unknown:0";
  const family = Array.isArray(lead.bug_class_hints) && lead.bug_class_hints.length > 0
    ? staticLeadBriefValue(lead.bug_class_hints[0]) || "static_analysis"
    : "static_analysis";
  const attackVector = staticLeadBriefValue(staticLeadField(lead, "attack_vector")) || "unknown";
  const networkReachable = staticLeadBriefValue(staticLeadField(lead, "network_reachable")) || "unknown";
  const severityCeiling = staticLeadBriefValue(staticLeadField(lead, "severity_ceiling")) || "unknown";
  const recommendation = attackVector === "network" && networkReachable === "true"
    ? "trace source->sink, prioritize write/UAF/RCE, prove with non-dry-run bob_repo_docker_run"
    : "trace source->sink, keep capped until replay proves impact";
  return capStaticLeadLine(
    `- ${endpoint} | family=${family} | AV=${attackVector} | network_reachable=${networkReachable} | severity_ceiling=${severityCeiling} | score=${lead.score || 0} | ${recommendation}`,
  );
}

function summarizeStaticAnalysisLeadsForBrief(domain, surfaceObj) {
  let document;
  try {
    document = readSurfaceLeadsDocument(domain);
  } catch {
    return "";
  }
  const leads = Array.isArray(document.leads) ? document.leads : [];
  const ranked = sortStaticAnalysisLeads(
    leads.filter((lead) => staticLeadAppliesToSurface(lead, surfaceObj)),
  ).slice(0, STATIC_ANALYSIS_LEAD_MAX_ITEMS);
  if (ranked.length === 0) return "";
  return capStaticAnalysisLeadSlice([
    "### Static analysis leads",
    ...ranked.map(renderStaticAnalysisLead),
  ]);
}

function buildOssBriefExtras(domain, surfaceObj, routeMetadata, assignment) {
  const taskLens = assignment && typeof assignment.task_lens === "string" ? assignment.task_lens : null;
  const slimSurface = slimSurfaceForBrief(surfaceObj);
  const cliToolSurfaceFingerprint = buildCliToolSurfaceFingerprint(surfaceObj, routeMetadata.brief_profile, domain);
  const cliToolObservations = buildCliToolObservationsSummary(surfaceObj);
  const ossBriefContext = {
    taskLens,
    governance: safeGovernanceContextForDomain(domain),
    goalOrientation: {
      target_domain: domain,
      task_lens: taskLens,
      capability_pack: routeMetadata.capability_pack,
      instruction:
        "Repo-bound OSS assignment: pursue the assigned local code surface, keep evidence inside the repo or sandboxed /work area, and do not infer authorization for a hosted sibling.",
    },
    codeSurfacePack: {
      assigned_surface: slimSurface.surface,
      surface_limits: slimSurface.surface_limits,
      route_metadata: {
        capability_pack: routeMetadata.capability_pack,
        capability_pack_version: routeMetadata.capability_pack_version,
        evaluator_agent: routeMetadata.evaluator_agent,
        brief_profile: routeMetadata.brief_profile,
      },
    },
    staticAnalysisLeads: summarizeStaticAnalysisLeadsForBrief(domain, slimSurface.surface),
    repoEnvRecommendations: buildRepoEnvRecommendationsForBrief(domain),
    ossTechniquePacks: buildOssTechniquePacksSlice(taskLens, slimSurface.surface, routeMetadata),
    cliToolSurfaceFingerprint,
    cliToolTaskLens: taskLens,
    cliToolObservations,
    cliToolTargetDomain: domain,
    recapAndHandoff: {
      completion:
        "Before finalizing, log at least one completion-status technique attempt, write exactly one wave handoff for this surface, then call bob_finalize_agent_run.",
      required_tools: [
        "bob_log_technique_attempt",
        "bob_write_wave_handoff",
        "bob_finalize_agent_run",
      ],
    },
  };
  const extras = buildBriefExtrasFromRegistry(OSS_BRIEF_SLICE_REGISTRY, ossBriefContext);
  if (!extras.repo_workflow) {
    delete extras.repo_workflow;
  }
  if (!extras.cli_tools) {
    delete extras.cli_tools;
  }
  if (!extras.static_analysis_leads) {
    delete extras.static_analysis_leads;
  }
  if (!extras.repo_env_recommendations) {
    delete extras.repo_env_recommendations;
  }
  return extras;
}

// Smart-contract profile carries on-chain context: the bob-spec status with
// trust assumptions and bypass conditions filtered to this surface, and the
// public RPC pool for the surface's chain_family/chain_id. Web-flavored
// fields (bypass_table, traffic, audit, intel, payload hints, auth profiles)
// are intentionally omitted; SC evaluators do not have the tools that consume them.
function buildSmartContractBriefExtras(domain, surfaceObj, assignment) {
  const smartContractBriefContext = {
    bobSpecStatus: summarizeBobSpecForBrief(loadBobSpec(domain), assignment.surface_id),
    rpcPool: summarizeRpcPoolForBrief(surfaceObj.chain_family, surfaceObj.chain_id),
    surfaceGraphSlice: summarizeSurfaceGraphForSurface(domain, surfaceObj),
  };
  return buildBriefExtrasFromRegistry(SMART_CONTRACT_BRIEF_SLICE_REGISTRY, smartContractBriefContext);
}

// Plane T Cycle T.3 — surface-conditional CLI tool block, wired into the brief.
//
// Returns a markdown section listing the CLI tool packs that apply to a
// surface + lens + observations triple, ranked by:
//   score = install_present * 1
//         + applicable_when_match * 2
//         + telemetry_promotion * 0.5
// and capped at 5 (T-P2 "conditional, not totaled"). Telemetry promotion is a
// no-op until T.8 populates pack-telemetry signals; we pass 0 here so the
// scoring stays deterministic and the cap remains the binding constraint.
// Packs whose tool is not installed are still scored — they just contribute 0
// to the install term. Empty projection returns null so the brief renderer can
// drop the slice entirely (per T-R1: an empty header would still inflate the
// brief).
const AVAILABLE_CLI_TOOLS_HEADER = "Available CLI tools for this surface";
const AVAILABLE_CLI_TOOLS_MAX = 5;
const TELEMETRY_PROMOTION_WEIGHT = 0.5;
const APPLICABLE_MATCH_WEIGHT = 2;
const INSTALL_PRESENT_WEIGHT = 1;
const CLI_TOOL_TIE_BREAK_PRIORITY = Object.freeze({
  // I10's baseline repo scanners feed the SARIF/secret index path. Keep them
  // visible under the five-pack cap when all repo packs tie on score.
  semgrep: 0,
  trivy: 1,
});
const CLI_TOOL_DEFAULT_TIE_BREAK_PRIORITY = 100;

async function loadCliToolInstallStatus(targetDomain, packs) {
  const status = {};
  if (!targetDomain) return status;
  for (const pack of packs) {
    try {
      const result = await checkCliToolInstallation(
        pack.id,
        pack.install_check,
        targetDomain,
      );
      status[pack.id] = result;
    } catch {
      status[pack.id] = { installed: false, cached: false };
    }
  }
  return status;
}

// Sync presence read for the brief assembly path. readAssignmentBrief is
// synchronous and must not shell out — the install-check subprocess fan-out
// belongs to the async warm-up path (T.2) that populates the cache. Here we
// only consult what is already on disk; missing/stale entries surface as
// `{ installed: false }` so the brief stays graceful (T-P3).
function readCliToolInstallStatusSync(targetDomain) {
  const status = {};
  if (typeof targetDomain !== "string" || !targetDomain.trim()) return status;
  let cache = null;
  try {
    const cachePath = presenceCachePath(targetDomain);
    if (!fs.existsSync(cachePath)) return status;
    cache = JSON.parse(fs.readFileSync(cachePath, "utf8"));
  } catch {
    return status;
  }
  const results = cache && typeof cache === "object" && cache.results && typeof cache.results === "object" && !Array.isArray(cache.results)
    ? cache.results
    : {};
  for (const pack of CLI_TOOL_PACKS) {
    const entry = results[pack.id];
    if (entry && typeof entry === "object") {
      status[pack.id] = {
        installed: Boolean(entry.installed),
        ...(entry.version ? { version: entry.version } : {}),
      };
    } else {
      status[pack.id] = { installed: false };
    }
  }
  return status;
}

// Score + render the cli-tool section against a precomputed install status.
// Shared by the sync brief-assembly path and the async caller that probes
// install_check live (test/cli-tool-packs.test.js). `packTelemetry` is the
// T.8 reader output (a Map keyed by pack id). T.3 carried a zero-promotion
// stub; T.8 wires the real reader here. When `packTelemetry` is absent or
// adaptive_curation is off, every promotion is 0 and the formula reduces to
// its T.3 form (T-R8 determinism preserved).
function scoreAndRenderCliToolPacks({
  surface_fingerprint,
  task_lens,
  observations,
  target_domain,
  installStatus,
  packTelemetry,
}) {
  const telemetryMap = packTelemetry && typeof packTelemetry.get === "function"
    ? packTelemetry
    : null;
  const applicable = selectCliToolPacks({
    surface_fingerprint,
    task_lens,
    observations,
    install_status: installStatus || {},
    pack_telemetry: telemetryMap,
  });
  const applicableIds = new Set(applicable.map((pack) => pack.id));
  const demotedIds = new Set(
    applicable.filter((pack) => pack.demoted === true).map((pack) => pack.id),
  );
  const scored = CLI_TOOL_PACKS
    .map((pack) => {
      const installEntry = (installStatus && installStatus[pack.id]) || { installed: false };
      const installScore = installEntry.installed ? INSTALL_PRESENT_WEIGHT : 0;
      const applicableScore = applicableIds.has(pack.id) ? APPLICABLE_MATCH_WEIGHT : 0;
      const telemetryEntry = telemetryMap ? telemetryMap.get(pack.id) : null;
      let telemetryScore = 0;
      if (telemetryEntry && Number.isFinite(telemetryEntry.telemetry_promotion)) {
        telemetryScore = telemetryEntry.telemetry_promotion * TELEMETRY_PROMOTION_WEIGHT;
      }
      const demoted = demotedIds.has(pack.id);
      const demotionPenalty = demoted ? DEMOTION_SCORE_PENALTY : 0;
      const score = installScore + applicableScore + telemetryScore + demotionPenalty;
      return {
        pack,
        score,
        applicable: applicableIds.has(pack.id),
        installEntry,
        demoted,
      };
    })
    .filter((entry) => entry.applicable)
    .sort((a, b) => {
      if (b.score !== a.score) return b.score - a.score;
      const aPriority = CLI_TOOL_TIE_BREAK_PRIORITY[a.pack.id] ?? CLI_TOOL_DEFAULT_TIE_BREAK_PRIORITY;
      const bPriority = CLI_TOOL_TIE_BREAK_PRIORITY[b.pack.id] ?? CLI_TOOL_DEFAULT_TIE_BREAK_PRIORITY;
      if (aPriority !== bPriority) return aPriority - bPriority;
      return a.pack.id.localeCompare(b.pack.id);
    })
    .slice(0, AVAILABLE_CLI_TOOLS_MAX);
  if (scored.length === 0) return "";
  const renderContext = buildCliToolRenderContext(surface_fingerprint, observations, target_domain);
  const lines = [`### ${AVAILABLE_CLI_TOOLS_HEADER}`];
  for (const entry of scored) {
    const version = entry.installEntry && entry.installEntry.version ? entry.installEntry.version : null;
    const versionLabel = version ? ` (v${version})` : "";
    const demotedLabel = entry.demoted ? " (demoted)" : "";
    const invocation = fillInvocationPlaceholders(entry.pack.invocation_template, renderContext);
    lines.push(`- **${entry.pack.id}**${versionLabel}${demotedLabel} — ${entry.pack.narrative}`);
    lines.push(`  \`${invocation}\``);
  }
  return lines.join("\n");
}

// Sync variant used by readAssignmentBrief / WEB_BRIEF_SLICE_REGISTRY. Reads
// the install-presence cache file directly; never spawns a subprocess.
// T.8 — wire in the adaptive pack-telemetry projection. When the operator
// has not enabled adaptive curation (pack-telemetry-config.json absent or
// `adaptive_curation: false`), `loadPackTelemetry` returns a Map where every
// pack carries `telemetry_promotion: 0` and `demoted: false`, so the scoring
// formula collapses to its T.3 form — preserving determinism for the
// default-off path (T-P5 / T-D5 / T-R8).
function renderAvailableCliToolsSectionSync({
  surface_fingerprint,
  task_lens,
  observations,
  target_domain,
} = {}) {
  const installStatus = readCliToolInstallStatusSync(target_domain);
  const packTelemetry = loadPackTelemetrySafe(target_domain);
  return scoreAndRenderCliToolPacks({
    surface_fingerprint,
    task_lens,
    observations,
    target_domain,
    installStatus,
    packTelemetry,
  });
}

function loadPackTelemetrySafe(targetDomain) {
  try {
    return loadPackTelemetry(targetDomain);
  } catch {
    // Telemetry must never block brief rendering. A read failure (missing
    // session dir, malformed JSONL) silently degrades to the default-off
    // shape: every pack at promotion=0, demoted=false.
    return null;
  }
}

function buildCliToolRenderContext(surface_fingerprint, observations, target_domain) {
  const ctx = {};
  if (surface_fingerprint && typeof surface_fingerprint === "object") {
    if (surface_fingerprint.host) ctx.host = surface_fingerprint.host;
    if (surface_fingerprint.hosts && Array.isArray(surface_fingerprint.hosts) && surface_fingerprint.hosts.length) {
      ctx.host = ctx.host || surface_fingerprint.hosts[0];
    }
    if (surface_fingerprint.session_dir) ctx.session_dir = surface_fingerprint.session_dir;
    if (surface_fingerprint.target_domain) ctx.target_domain = surface_fingerprint.target_domain;
  }
  if (target_domain && !ctx.target_domain) ctx.target_domain = target_domain;
  if (target_domain && !ctx.host) ctx.host = target_domain;
  const list = observationList(observations);
  for (const observation of list) {
    if (!observation || typeof observation !== "object") continue;
    const payload = observation.payload && typeof observation.payload === "object" ? observation.payload : observation;
    if (!ctx.endpoint && payload.endpoint) ctx.endpoint = payload.endpoint;
    if (!ctx.param && payload.param) ctx.param = payload.param;
    if (!ctx.token && payload.snippet) ctx.token = payload.snippet;
  }
  if (observations && typeof observations === "object" && !Array.isArray(observations)) {
    if (!ctx.endpoint && Array.isArray(observations.observed_endpoints) && observations.observed_endpoints.length) {
      ctx.endpoint = observations.observed_endpoints[0];
    }
  }
  return ctx;
}

async function renderAvailableCliToolsSection({
  surface_fingerprint,
  task_lens,
  observations,
  target_domain,
} = {}) {
  const installStatus = await loadCliToolInstallStatus(target_domain, CLI_TOOL_PACKS);
  const packTelemetry = loadPackTelemetrySafe(target_domain);
  return scoreAndRenderCliToolPacks({
    surface_fingerprint,
    task_lens,
    observations,
    target_domain,
    installStatus,
    packTelemetry,
  });
}

module.exports = {
  AVAILABLE_CLI_TOOLS_HEADER,
  AVAILABLE_CLI_TOOLS_MAX,
  APPLICABLE_MATCH_WEIGHT,
  INSTALL_PRESENT_WEIGHT,
  TELEMETRY_PROMOTION_WEIGHT,
  BOB_SPEC_ABSENT_MESSAGE,
  // Plane T cycle T.4 — surfaced so tests can pin the browser-workflow stanza
  // and partition behavior without re-encoding the strings.
  BROWSER_BEHAVIOR_PROBE_LENS,
  BROWSER_BEHAVIOR_PROBE_WORKFLOW_TEXT,
  partitionTechniquePacksByLensAffinity,
  partitionOssTechniquePacksByLens,
  buildOssBriefExtras,
  buildRepoEnvRecommendationsForBrief,
  buildBriefExtrasFromRegistry,
  buildBriefExtrasForProfile,
  ASSIGNMENT_BRIEF_SLICE_REGISTRY,
  UNTRUSTED_CONTENT_POLICY,
  UNTRUSTED_FENCE_OVERHEAD_CHARS,
  readAssignmentBrief,
  renderAvailableCliToolsSection,
  renderAvailableCliToolsSectionSync,
  evaluatorKnowledgeCandidatePaths,
  resolveBypassTable,
  resolveEvaluatorKnowledge,
  slimSurfaceForBrief,
  // Plane O cycle O.6 — OSS brief slice registry + repo_workflow stanza.
  OSS_BRIEF_SLICE_REGISTRY,
  OSS_LENSES,
  REPO_WORKFLOW_TEXT,
  briefSliceRegistryForProfile,
  isOssLens,
  // Plane X cycle X.8 — TaskGraph node profile slice registry + renderer.
  NODE_BRIEF_SLICE_REGISTRY,
  renderNodeBriefExtras,
  // Plane Y cycle Y.5 — re-export for tests.
  buildWaveBriefDerivation,
  composeTraceReadingExpectationsForRole,
};
