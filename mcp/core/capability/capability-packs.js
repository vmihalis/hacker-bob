"use strict";

const { FANOUT_ROLE_REGISTRY } = require("../session/nested-spawn.js");
const {
  PHYSICAL_SURFACE_NODE_TYPES,
} = require("../../domains/physical/physical-surface-transition.js");
const {
  PHYSICAL_CAPABILITY_CONSUMERS,
  PHYSICAL_CAPABILITY_PACK_DISPATCH_BLOCK_REASON,
} = require("../../domains/physical/physical-capability-manifest.js");
const {
  PHYSICAL_CAPABILITY_PACK_ADAPTERS,
} = require("./capability-pack-runtime-ports.js");
const {
  CONTROL_VALIDITY_CLASS_OBJECT_AUTH,
} = require("../validity/class-ids.js");

// Capability pack manifest. Each pack is the single source of truth for:
//   id              — string used in surface-routes.json and findings.jsonl
//   evaluator_agent    — Claude/Codex subagent name spawned for this pack
//   brief_profile   — selects which buildBriefExtras builder assignment-brief calls
//   context_budget  — bounded context contract exposed to routed evaluators
//   role_bundles    — MCP tool bundles the spawned evaluator sees
//   completion_gate — wave-handoff completion rule the merge layer enforces
//   verifier        — pack-keyed PoC replay for brutalist/balanced/final verifier
//   evidence        — pack-keyed runner for evidence-agent's pre-grade re-runs
//   spawn           — pack-keyed spawn template strings consumed by both the
//                     Claude and Codex orchestrator-skill renderers
//
// Verifier and evidence consumers look up the pack by finding.capability_pack
// and dispatch on the verifier/evidence blocks instead of branching on
// chain_family in their prompts. The orchestrator evaluator spawn template body
// is composed from spawn fields, so adding a chain pack auto-generates its
// catalogue entry without touching any renderer.

const DEFAULT_CONTEXT_BUDGET = Object.freeze({
  candidate_pack_limit: 5,
  full_pack_read_limit: 2,
  attempt_log_required: true,
});

const SMART_CONTRACT_CONTEXT_BUDGET = Object.freeze({
  candidate_pack_limit: 5,
  full_pack_read_limit: 2,
  attempt_log_required: false,
});

const DEFAULT_REPLAY_SAFETY = Object.freeze({
  mode: "serialized",
  lease_scope: "attempt_pack",
});

// Plane-PH routing is intentionally registered before it is dispatchable. The
// physical substrate already has provider-neutral authority, resource,
// campaign, evidence, and SurfaceGraph contracts, but the pack-declared
// assignment brief, closure, finding, verifier, grade, report, and composition
// consumers are not all connected yet. Reusing the web evaluator while those
// consumers are absent would let a web-shaped handoff claim completion for a
// physical campaign. Keep the pack discoverable so physical surfaces can bind
// the exact capability family they require, but make dispatch availability an
// explicit registry fact that every consumer can fail closed on.
const PHYSICAL_CAPABILITY_PACK_UNAVAILABLE_REASON =
  PHYSICAL_CAPABILITY_PACK_DISPATCH_BLOCK_REASON;

const PHYSICAL_SURFACE_TYPES = Object.freeze(Array.from(new Set([
  "physical",
  ...PHYSICAL_SURFACE_NODE_TYPES,
])).sort());
const PHYSICAL_SURFACE_TYPE_SET = new Set(PHYSICAL_SURFACE_TYPES);

const SC_DIRECT_EGRESS_SUMMARY = "SC RPC/REST egress is direct public HTTPS only: DNS-private endpoints, private/localnet RPC, and egress_profile proxy routing are unsupported by default.";

// The objective + bar the orchestrator states when it dispatches an SC
// evaluator — the same posture the role prompt carries, single-sourced here so
// the spawn-dispatch line opens with WHY (break an invariant; a flipped control
// is the bar) before the causal tool chain that follows describes HOW. The
// trailing chain is the prerequisite ordering (fetch -> trust map -> scaffold
// -> run) plus the recording contract, not a procedure to walk in lockstep.
const SC_OBJECTIVE_LEAD = "Objective: break an invariant or demonstrate attacker-reachable impact on this surface; a surface closes only when an executed differential whose negative control flips is recorded, or with an honest partial/blocked. The tool chain below is the causal prerequisite order, not a checklist:";

const WEB_CAPABILITY_PACK = Object.freeze({
  id: "web",
  capability_pack_version: 1,
  // Technique guidance is keyed by capability family, not by the evaluator
  // routing variant that happens to execute it. Routing variants derive from
  // this pack and inherit the canonical family, so every technique-pack
  // consumer can resolve compatibility through CAPABILITY_PACKS instead of
  // maintaining local aliases (for example, web_fanout -> web).
  technique_compatibility_pack: "web",
  evaluator_agent: "evaluator-agent",
  brief_profile: "web",
  role_bundles: Object.freeze(["evaluator-shared", "evaluator-web"]),
  completion_gate: "web_wave_handoff",
  context_budget: DEFAULT_CONTEXT_BUDGET,
  verifier: Object.freeze({
    // Web verifier replay is a fresh HTTP call against the same endpoint
    // with the captured auth profile. Verifier extracts the request from
    // the finding's PoC and re-issues via bob_http_scan.
    replay_tool: "bob_http_scan",
    sample_type: "http_replay",
    fresh_state_omit_field: null,        // HTTP has no fork concept
    disambiguation: null,                // single endpoint, no chain confusion
    replay_safety: DEFAULT_REPLAY_SAFETY,
  }),
  evidence: Object.freeze({
    runner: "bob_http_scan",
    sample_type: "http_replay",
  }),
  // Web pack uses a structurally distinct spawn body (web context fields,
  // auth profiles, geofence rule). The renderer recognises profile="web"
  // and emits the legacy SPAWN_EVALUATOR_AGENT body unchanged.
  spawn: Object.freeze({
    profile: "web",
  }),
});

// The spawn-capable web variant: byte-identical to WEB_CAPABILITY_PACK except the
// evaluator_agent is the spawn-capable evaluator-fanout role. SPREAD-derived (never a
// hand-cloned sibling) so verifier/evidence/completion_gate/context_budget/brief_profile
// cannot drift from web. Selected (in place of web) for high-value surfaces when nesting is
// actually possible (see selectWebEvaluatorPack); this is what ARMS the child fan-out plan a
// flat evaluator-agent has no Task tool to actuate — the ns.com "0 of 33 spawned" gap.
const WEB_FANOUT_CAPABILITY_PACK = Object.freeze({
  ...WEB_CAPABILITY_PACK,
  id: "web_fanout",
  evaluator_agent: FANOUT_ROLE_REGISTRY.root.subagent_type,
});

// Select the web evaluator pack for a classified WEB surface: the spawn-capable web_fanout
// variant for a HIGH-VALUE surface when nesting can actually fire, else the flat web pack.
// idBearing is passed IN (from the MCP-owned route.id_bearing frozen in buildSurfaceRoutesDocument)
// and NEVER re-derived here, so the routing choice and route.id_bearing cannot desync.
//   - Default ON (route_high_value_to_fanout !== false): high-value web surfaces fan out.
//   - Trigger = idBearing (the clean high-value signal). multi-auth is NOT a trigger — it is
//     session-global (identical for every surface) and is the satisfiability PRECONDITION for a
//     flip, not a depth signal. HIGH priority is an opt-in only (web_fanout_on_high_priority):
//     priority is a RANK, agent-writable, and defaults medium.
//   - Gated on spawnDepth>1: at max_spawn_depth<=1 nesting can never fire, so rerouting to the
//     fanout role would only incur its transition-blindness for nothing — keep flat.
function selectWebEvaluatorPack(classification, { idBearing = false, highPriority = false, spawnDepth = 1, hasBugClassHints = true, queuePolicy = null } = {}) {
  if (!classification || classification.capability_pack !== "web") return null;
  const policy = queuePolicy && typeof queuePolicy === "object" ? queuePolicy : {};
  if (policy.route_high_value_to_fanout === false) return WEB_CAPABILITY_PACK;
  if (!(Number.isInteger(spawnDepth) && spawnDepth > 1)) return WEB_CAPABILITY_PACK;
  // Only reroute if the fan-out will actually produce CELLS: deriveChildFanoutPlan is a leaf
  // (null plan) when bug_class_hints is empty, so rerouting such a surface to the
  // transition-blind evaluator-fanout would incur its blindness for zero fan-out benefit —
  // keep it on the transition-capable flat evaluator-agent.
  if (!hasBugClassHints) return WEB_CAPABILITY_PACK;
  const highValue = idBearing || (highPriority && policy.web_fanout_on_high_priority === true);
  return highValue ? WEB_FANOUT_CAPABILITY_PACK : WEB_CAPABILITY_PACK;
}

function ossCapabilityPack(id, sampleType) {
  return Object.freeze({
    id,
    capability_pack_version: 1,
    evaluator_agent: "evaluator-agent",
    brief_profile: "oss",
    role_bundles: Object.freeze(["evaluator-shared", "evaluator-web"]),
    completion_gate: "web_wave_handoff",
    context_budget: DEFAULT_CONTEXT_BUDGET,
    verifier: Object.freeze({
      replay_tool: "bob_repo_check",
      sample_type: sampleType,
      fresh_state_omit_field: null,
      disambiguation: null,
      replay_safety: DEFAULT_REPLAY_SAFETY,
    }),
    evidence: Object.freeze({
      runner: "bob_repo_check",
      sample_type: sampleType,
    }),
    spawn: Object.freeze({
      profile: "web",
    }),
  });
}

const OSS_DEPENDENCY_CAPABILITY_PACK = ossCapabilityPack("oss_dependency", "repo_dependency_check");
const OSS_NATIVE_CODE_CAPABILITY_PACK = ossCapabilityPack("oss_native_code", "repo_native_code_check");
const OSS_API_SCHEMA_CAPABILITY_PACK = ossCapabilityPack("oss_api_schema", "repo_api_schema_check");
const OSS_AUTHZ_CAPABILITY_PACK = ossCapabilityPack("oss_authz", "repo_authz_check");
const OSS_CI_CD_CAPABILITY_PACK = ossCapabilityPack("oss_ci_cd", "repo_ci_cd_check");
const OSS_SECRETS_CONFIG_CAPABILITY_PACK = ossCapabilityPack("oss_secrets_config", "repo_config_check");
const OSS_DOCS_BEHAVIOR_CAPABILITY_PACK = ossCapabilityPack("oss_docs_behavior", "repo_docs_behavior_check");

const SMART_CONTRACT_EVM_CAPABILITY_PACK = Object.freeze({
  id: "smart_contract_evm",
  capability_pack_version: 1,
  evaluator_agent: "evaluator-evm-agent",
  brief_profile: "smart_contract_evm",
  role_bundles: Object.freeze(["evaluator-shared", "evaluator-evm"]),
  completion_gate: "smart_contract_wave_handoff",
  context_budget: SMART_CONTRACT_CONTEXT_BUDGET,
  verifier: Object.freeze({
    replay_tool: "bob_foundry_run",
    sample_type: "evm_foundry_run",
    fresh_state_omit_field: "fork_block",
    // The runner response field carrying the resolved block reference
    // (block / slot / version / checkpoint depending on chain). Final
    // verifier captures this for the report's "verified at block N" line.
    block_reference_field: "fork_block_used",
    block_reference_label: "block",
    // EVM 0x... addresses are unambiguous across EVM chains; chain_id alone
    // fixes the fork RPC. No read-side disambiguation required.
    disambiguation: null,
    replay_safety: DEFAULT_REPLAY_SAFETY,
  }),
  evidence: Object.freeze({
    runner: "bob_foundry_run",
    sample_type: "evm_foundry_run",
  }),
  spawn: Object.freeze({
    profile: "smart_contract",
    chain_family: "evm",
    role_id: "evaluator-evm",
    evaluator_name_prefix: "evaluator-evm",
    chain_id_description: "the EVM chain id (e.g., 1, 137, 10, 42161)",
    workflow_summary: `${SC_OBJECTIVE_LEAD} bob_evm_fetch_source -> read sources via Read -> bob_evm_role_table to map the trust boundary -> scaffold a Foundry test under harness_path/test/ via Write -> bob_foundry_run with chain_id and pinned fork_block -> bob_halmos_run to symbolically explore the invariant a single concrete fork run cannot exhaust -> record bypass_attempts[] entries citing the actual harness path + test name in attempt_summary. ${SC_DIRECT_EGRESS_SUMMARY}`,
    cli_dependency: "forge",
    blocked_harness_kind_options: "foundry_fork or rpc_endpoint",
  }),
});

const SMART_CONTRACT_SVM_CAPABILITY_PACK = Object.freeze({
  id: "smart_contract_svm",
  capability_pack_version: 1,
  evaluator_agent: "evaluator-svm-agent",
  brief_profile: "smart_contract_svm",
  role_bundles: Object.freeze(["evaluator-shared", "evaluator-svm"]),
  completion_gate: "smart_contract_wave_handoff",
  context_budget: SMART_CONTRACT_CONTEXT_BUDGET,
  verifier: Object.freeze({
    replay_tool: "bob_anchor_run",
    sample_type: "svm_anchor_run",
    // The runner-input parameter that pins replay to a specific chain
    // ordering point. sc_evidence persists a single `fork_block` field
    // (findings.js), and the verifier translates it into this runner
    // parameter when calling the runner. Omitting this parameter forces
    // a fresh-state replay against current cluster state.
    fresh_state_omit_field: "fork_slot",
    block_reference_field: "fork_slot_used",
    block_reference_label: "slot",
    disambiguation: null,
    replay_safety: DEFAULT_REPLAY_SAFETY,
  }),
  evidence: Object.freeze({
    runner: "bob_anchor_run",
    sample_type: "svm_anchor_run",
  }),
  spawn: Object.freeze({
    profile: "smart_contract",
    chain_family: "svm",
    role_id: "evaluator-svm",
    evaluator_name_prefix: "evaluator-svm",
    chain_id_description: "the Solana cluster",
    workflow_summary: `${SC_OBJECTIVE_LEAD} bob_svm_fetch_program (confirm upgrade authority) -> bob_svm_fetch_account (read multisig + state accounts) -> scaffold an Anchor test under harness_path/tests/ via Write -> bob_anchor_run with cluster and optional pinned fork_slot -> record bypass_attempts[] entries citing the actual harness path + test description in attempt_summary. ${SC_DIRECT_EGRESS_SUMMARY}`,
    cli_dependency: "anchor",
    blocked_harness_kind_options: "anchor_fork or rpc_endpoint",
  }),
});

// Aptos and Sui are separate packs so verifier dispatch is one runner per
// pack (bob_aptos_run vs bob_sui_run). Both packs still route to
// evaluator-move-agent — the agent's own tool list covers both bob_aptos_*
// and bob_sui_*.
const SMART_CONTRACT_APTOS_CAPABILITY_PACK = Object.freeze({
  id: "smart_contract_aptos",
  capability_pack_version: 1,
  evaluator_agent: "evaluator-move-agent",
  brief_profile: "smart_contract_aptos",
  role_bundles: Object.freeze(["evaluator-shared", "evaluator-move"]),
  completion_gate: "smart_contract_wave_handoff",
  context_budget: SMART_CONTRACT_CONTEXT_BUDGET,
  verifier: Object.freeze({
    replay_tool: "bob_aptos_run",
    sample_type: "aptos_move_test",
    fresh_state_omit_field: "fork_version",
    block_reference_field: "fork_version_used",
    block_reference_label: "ledger_version",
    // Aptos and Sui share the same 0x + 64-hex address space; the runner
    // alone cannot detect a wrong-network record. Verifier must call
    // bob_aptos_fetch_module to confirm the module exists on the
    // claimed network before passing through.
    disambiguation: Object.freeze({
      tool: "bob_aptos_fetch_module",
      fail_reason: "address does not resolve on the claimed Aptos network; chain_family/chain_id mismatch suspected",
    }),
    replay_safety: DEFAULT_REPLAY_SAFETY,
  }),
  evidence: Object.freeze({
    runner: "bob_aptos_run",
    sample_type: "aptos_move_test",
  }),
  spawn: Object.freeze({
    profile: "smart_contract",
    chain_family: "aptos",
    role_id: "evaluator-move",
    evaluator_name_prefix: "evaluator-aptos",
    chain_id_description: "the network name (mainnet/testnet/devnet)",
    workflow_summary: `${SC_OBJECTIVE_LEAD} bob_aptos_fetch_module (enumerate exposed_functions, structs, friends) -> bob_aptos_fetch_resource (read capability tokens, ownership records, treasury balances) -> scaffold an \`aptos move test\` harness under harness_path/sources/ via Write -> bob_aptos_run with network and optional pinned fork_version -> record bypass_attempts[] citing the actual harness path + test name in attempt_summary. ${SC_DIRECT_EGRESS_SUMMARY}`,
    cli_dependency: "aptos",
    blocked_harness_kind_options: "aptos_fork or rpc_endpoint",
  }),
});

const SMART_CONTRACT_SUI_CAPABILITY_PACK = Object.freeze({
  id: "smart_contract_sui",
  capability_pack_version: 1,
  evaluator_agent: "evaluator-move-agent",
  brief_profile: "smart_contract_sui",
  role_bundles: Object.freeze(["evaluator-shared", "evaluator-move"]),
  completion_gate: "smart_contract_wave_handoff",
  context_budget: SMART_CONTRACT_CONTEXT_BUDGET,
  verifier: Object.freeze({
    replay_tool: "bob_sui_run",
    sample_type: "sui_move_test",
    fresh_state_omit_field: "fork_checkpoint",
    block_reference_field: "fork_checkpoint_used",
    block_reference_label: "checkpoint",
    disambiguation: Object.freeze({
      tool: "bob_sui_fetch_package",
      fail_reason: "package does not resolve on the claimed Sui network; chain_family/chain_id mismatch suspected",
    }),
    replay_safety: DEFAULT_REPLAY_SAFETY,
  }),
  evidence: Object.freeze({
    runner: "bob_sui_run",
    sample_type: "sui_move_test",
  }),
  spawn: Object.freeze({
    profile: "smart_contract",
    chain_family: "sui",
    role_id: "evaluator-move",
    evaluator_name_prefix: "evaluator-sui",
    chain_id_description: "the network name (mainnet/testnet/devnet/localnet)",
    workflow_summary: `${SC_OBJECTIVE_LEAD} bob_sui_fetch_package (enumerate entry functions and friend relationships) -> bob_sui_fetch_object (inspect Owner=Immutable/Shared/AddressOwner/ObjectOwner, Move type, capability fields) -> scaffold a \`sui move test\` harness under harness_path/sources/ via Write -> bob_sui_run with network and optional pinned fork_checkpoint -> record bypass_attempts[] citing the actual harness path + test name in attempt_summary. ${SC_DIRECT_EGRESS_SUMMARY}`,
    cli_dependency: "sui",
    blocked_harness_kind_options: "sui_fork or rpc_endpoint",
  }),
});

const SMART_CONTRACT_SUBSTRATE_CAPABILITY_PACK = Object.freeze({
  id: "smart_contract_substrate",
  capability_pack_version: 1,
  evaluator_agent: "evaluator-substrate-agent",
  brief_profile: "smart_contract_substrate",
  role_bundles: Object.freeze(["evaluator-shared", "evaluator-substrate"]),
  completion_gate: "smart_contract_wave_handoff",
  context_budget: SMART_CONTRACT_CONTEXT_BUDGET,
  verifier: Object.freeze({
    replay_tool: "bob_substrate_run",
    sample_type: "substrate_ink_test",
    fresh_state_omit_field: "fork_block",
    block_reference_field: "fork_block_used",
    block_reference_label: "block",
    // SS58 addresses share base58 alphabet with chain-specific prefix
    // bytes the validator does not BLAKE2b-check (cost). A Kusama address
    // could be recorded against polkadot. Verifier must read storage on
    // the claimed network before passing through.
    disambiguation: Object.freeze({
      tool: "bob_substrate_fetch_storage",
      fail_reason: "address does not resolve on the claimed Substrate network; chain_family/chain_id mismatch suspected",
    }),
    replay_safety: DEFAULT_REPLAY_SAFETY,
  }),
  evidence: Object.freeze({
    runner: "bob_substrate_run",
    sample_type: "substrate_ink_test",
  }),
  spawn: Object.freeze({
    profile: "smart_contract",
    chain_family: "substrate",
    role_id: "evaluator-substrate",
    evaluator_name_prefix: "evaluator-substrate",
    chain_id_description: "the network name (polkadot/kusama/astar/shiden/rococo/westend/localnet)",
    workflow_summary: `${SC_OBJECTIVE_LEAD} bob_substrate_fetch_runtime (confirm chain identity + spec_version) -> bob_substrate_fetch_storage (read pallet_contracts.ContractInfoOf for code_hash and admin) -> scaffold an ink! \`cargo test\` harness under harness_path/ via Write (uses #[ink::test] for unit or #[ink_e2e::test] for E2E) -> bob_substrate_run with network and optional pinned fork_block -> record bypass_attempts[] citing the actual harness path + test name in attempt_summary. ${SC_DIRECT_EGRESS_SUMMARY}`,
    cli_dependency: "cargo or substrate-contracts-node",
    blocked_harness_kind_options: "substrate_fork or rpc_endpoint",
  }),
});

const SMART_CONTRACT_COSMWASM_CAPABILITY_PACK = Object.freeze({
  id: "smart_contract_cosmwasm",
  capability_pack_version: 1,
  evaluator_agent: "evaluator-cosmwasm-agent",
  brief_profile: "smart_contract_cosmwasm",
  role_bundles: Object.freeze(["evaluator-shared", "evaluator-cosmwasm"]),
  completion_gate: "smart_contract_wave_handoff",
  context_budget: SMART_CONTRACT_CONTEXT_BUDGET,
  verifier: Object.freeze({
    replay_tool: "bob_cosmwasm_run",
    sample_type: "cosmwasm_cw_multi_test",
    fresh_state_omit_field: "fork_block",
    block_reference_field: "fork_block_used",
    block_reference_label: "block",
    // bech32 addresses with different HRPs share the bech32 character
    // space — an osmo1... could be recorded against juno. Verifier must
    // call bob_cosmwasm_fetch_contract on the claimed network.
    disambiguation: Object.freeze({
      tool: "bob_cosmwasm_fetch_contract",
      fail_reason: "address does not resolve on the claimed CosmWasm network; chain_family/chain_id mismatch suspected",
    }),
    replay_safety: DEFAULT_REPLAY_SAFETY,
  }),
  evidence: Object.freeze({
    runner: "bob_cosmwasm_run",
    sample_type: "cosmwasm_cw_multi_test",
  }),
  spawn: Object.freeze({
    profile: "smart_contract",
    chain_family: "cosmwasm",
    role_id: "evaluator-cosmwasm",
    evaluator_name_prefix: "evaluator-cosmwasm",
    chain_id_description: "the network name (osmosis/juno/neutron/archway/sei/stargaze/terra/kava/localnet)",
    workflow_summary: `${SC_OBJECTIVE_LEAD} bob_cosmwasm_fetch_contract (confirm contract exists, capture code_id + admin) -> bob_cosmwasm_smart_query (inspect public Config / Owner / Balance entrypoints) -> scaffold a cw-multi-test integration test under harness_path/tests/ via Write -> bob_cosmwasm_run with network and optional pinned fork_block -> record bypass_attempts[] citing the actual harness path + test name in attempt_summary. ${SC_DIRECT_EGRESS_SUMMARY}`,
    cli_dependency: "cargo",
    blocked_harness_kind_options: "cosmwasm_fork or rpc_endpoint",
  }),
});

// Registered, provider-neutral Plane-PH capability family.  PH-S9/PH-X1 now
// supplies dedicated consumer metadata and a physical-only evaluator role,
// while dispatch stays false until the production verdict resolver and the
// no-active-effects wave-handoff adapter exist.  No consumer borrows web
// endpoint/PoC/base_url semantics and no role receives provider transport.
const physicalCapabilityPack = {
  id: "physical",
  capability_pack_version: 1,
  surface_class: "physical",
  dispatchable: false,
  dispatch_block_reason: PHYSICAL_CAPABILITY_PACK_UNAVAILABLE_REASON,
  technique_compatibility_pack: "physical",
  evaluator_agent: "evaluator-physical-agent",
  brief_profile: "physical",
  role_bundles: Object.freeze(["evaluator-physical"]),
  completion_gate: PHYSICAL_CAPABILITY_CONSUMERS.coverage.adapter,
  context_budget: DEFAULT_CONTEXT_BUDGET,
  verifier: Object.freeze({
    replay_tool: PHYSICAL_CAPABILITY_CONSUMERS.finding.verifier_tool,
    sample_type: "physical_candidate_claim_projection",
    fresh_state_omit_field: null,
    disambiguation: null,
    replay_safety: Object.freeze({
      mode: "server_owned_projection",
      lease_scope: "physical_verdict_ref",
    }),
  }),
  evidence: Object.freeze({
    runner: PHYSICAL_CAPABILITY_CONSUMERS.finding.verifier_tool,
    sample_type: "physical_candidate_claim_projection",
    adapter: PHYSICAL_CAPABILITY_CONSUMERS.evidence.adapter,
  }),
  proof: PHYSICAL_CAPABILITY_CONSUMERS.proof,
  spawn: Object.freeze({
    profile: "physical",
    role_id: "evaluator-physical",
    evaluator_name_prefix: "evaluator-physical",
    authority_summary: "Evidence planning only; every hardware effect requires an independent broker grant and admission decision.",
  }),
  assignment: PHYSICAL_CAPABILITY_CONSUMERS.assignment,
  coverage: PHYSICAL_CAPABILITY_CONSUMERS.coverage,
  finding: PHYSICAL_CAPABILITY_CONSUMERS.finding,
  verdict: PHYSICAL_CAPABILITY_CONSUMERS.verdict,
  grade: PHYSICAL_CAPABILITY_CONSUMERS.grade,
  report: PHYSICAL_CAPABILITY_CONSUMERS.report,
  composition: PHYSICAL_CAPABILITY_CONSUMERS.composition,
};
Object.defineProperty(physicalCapabilityPack, "runtimeAdapters", {
  value: PHYSICAL_CAPABILITY_PACK_ADAPTERS,
  enumerable: false,
});
const PHYSICAL_CAPABILITY_PACK = Object.freeze(physicalCapabilityPack);

const CAPABILITY_PACKS = Object.freeze({
  web: WEB_CAPABILITY_PACK,
  web_fanout: WEB_FANOUT_CAPABILITY_PACK,
  oss_dependency: OSS_DEPENDENCY_CAPABILITY_PACK,
  oss_native_code: OSS_NATIVE_CODE_CAPABILITY_PACK,
  oss_api_schema: OSS_API_SCHEMA_CAPABILITY_PACK,
  oss_authz: OSS_AUTHZ_CAPABILITY_PACK,
  oss_ci_cd: OSS_CI_CD_CAPABILITY_PACK,
  oss_secrets_config: OSS_SECRETS_CONFIG_CAPABILITY_PACK,
  oss_docs_behavior: OSS_DOCS_BEHAVIOR_CAPABILITY_PACK,
  smart_contract_evm: SMART_CONTRACT_EVM_CAPABILITY_PACK,
  smart_contract_svm: SMART_CONTRACT_SVM_CAPABILITY_PACK,
  smart_contract_aptos: SMART_CONTRACT_APTOS_CAPABILITY_PACK,
  smart_contract_sui: SMART_CONTRACT_SUI_CAPABILITY_PACK,
  smart_contract_substrate: SMART_CONTRACT_SUBSTRATE_CAPABILITY_PACK,
  smart_contract_cosmwasm: SMART_CONTRACT_COSMWASM_CAPABILITY_PACK,
  physical: PHYSICAL_CAPABILITY_PACK,
});

// Evaluator-role registry — keyed by role_id, deduped across packs. Multiple
// capability packs that share a role_id (Move-family aptos+sui both route
// to evaluator-move-agent) collapse to a single role spec here. role-model.js,
// claude-role-renderer.js, codex/role-specs.js, and tool-registry.js all
// derive their evaluator role specs from this map. Adding a chain pack means
// adding an entry here and a CAPABILITY_PACKS entry plus a new
// prompts/roles/evaluator-X.md, plus the per-chain validation in findings.js.
//
// Cross-cutting roles (orchestrator, surface-discovery, deep-surface-discovery, surface-router,
// chain, brutalist-verifier, balanced-verifier, final-verifier, evidence,
// grader, reporter, status, debug, evaluator [web]) stay defined inside the
// individual consumer modules — they are not chain-specific and there is
// no value in routing them through this registry.
const EVALUATOR_ROLES = Object.freeze({
  "evaluator-physical": Object.freeze({
    role_id: "evaluator-physical",
    name: "evaluator-physical-agent",
    description: "Provider-neutral physical-security evaluator — plans bounded coverage and records opaque evidence references without direct hardware, transport, or provider authority",
    color: "red",
    role_bundles: Object.freeze(["evaluator-physical"]),
    prompt_body_filename: "evaluator-physical.md",
    local_tools: Object.freeze([]),
  }),
  "evaluator-evm": Object.freeze({
    role_id: "evaluator-evm",
    name: "evaluator-evm-agent",
    description: "EVM smart-contract bug bounty evaluator — spawned per smart_contract surface, scaffolds and runs Foundry tests against the direct public HTTPS RPC ladder",
    color: "magenta",
    role_bundles: Object.freeze(["evaluator-shared", "evaluator-evm"]),
    prompt_body_filename: "evaluator-evm.md",
  }),
  "evaluator-svm": Object.freeze({
    role_id: "evaluator-svm",
    name: "evaluator-svm-agent",
    description: "SVM (Solana) smart-contract bug bounty evaluator — spawned per smart_contract surface with chain_family=svm, scaffolds and runs Anchor tests against the direct public HTTPS Solana RPC ladder",
    color: "cyan",
    role_bundles: Object.freeze(["evaluator-shared", "evaluator-svm"]),
    prompt_body_filename: "evaluator-svm.md",
  }),
  "evaluator-move": Object.freeze({
    role_id: "evaluator-move",
    name: "evaluator-move-agent",
    description: "Move (Aptos + Sui) smart-contract bug bounty evaluator — spawned per smart_contract surface with chain_family in {aptos, sui}, scaffolds and runs aptos move test or sui move test against direct public HTTPS Move RPC/REST ladders",
    color: "blue",
    role_bundles: Object.freeze(["evaluator-shared", "evaluator-move"]),
    prompt_body_filename: "evaluator-move.md",
  }),
  "evaluator-substrate": Object.freeze({
    role_id: "evaluator-substrate",
    name: "evaluator-substrate-agent",
    description: "Substrate / ink! smart-contract bug bounty evaluator — spawned per smart_contract surface with chain_family=substrate, scaffolds and runs cargo test on ink! contracts against the direct public HTTPS Substrate JSON-RPC ladder",
    color: "pink",
    role_bundles: Object.freeze(["evaluator-shared", "evaluator-substrate"]),
    prompt_body_filename: "evaluator-substrate.md",
  }),
  "evaluator-cosmwasm": Object.freeze({
    role_id: "evaluator-cosmwasm",
    name: "evaluator-cosmwasm-agent",
    description: "CosmWasm smart-contract bug bounty evaluator — spawned per smart_contract surface with chain_family=cosmwasm, scaffolds and runs cargo test with cw-multi-test against the direct public HTTPS CosmWasm REST ladder",
    color: "yellow",
    role_bundles: Object.freeze(["evaluator-shared", "evaluator-cosmwasm"]),
    prompt_body_filename: "evaluator-cosmwasm.md",
  }),
});

const WEB_SURFACE_TYPES = Object.freeze([
  "admin",
  "api",
  "auth",
  "billing",
  "ci_cd",
  "cms",
  "graphql",
  "js_endpoint",
  "mobile_api",
  "secrets",
  "static",
  "unknown",
  "upload",
]);

const WEB_SURFACE_TYPE_SET = new Set(WEB_SURFACE_TYPES);
const OSS_SURFACE_TYPE_TO_PACK = Object.freeze({
  oss_dependency: OSS_DEPENDENCY_CAPABILITY_PACK,
  oss_native_code: OSS_NATIVE_CODE_CAPABILITY_PACK,
  oss_static_sink: OSS_NATIVE_CODE_CAPABILITY_PACK,
  oss_api_schema: OSS_API_SCHEMA_CAPABILITY_PACK,
  oss_authz: OSS_AUTHZ_CAPABILITY_PACK,
  oss_ci_cd: OSS_CI_CD_CAPABILITY_PACK,
  oss_secrets_config: OSS_SECRETS_CONFIG_CAPABILITY_PACK,
  oss_docs_behavior: OSS_DOCS_BEHAVIOR_CAPABILITY_PACK,
});

// Smart-contract surfaces are routed by `chain_family`. Aptos and Sui have
// distinct packs (so verifier dispatch is one runner per pack) but both
// route to evaluator-move-agent — the agent's tool list covers both
// bob_aptos_* and bob_sui_*.
const SMART_CONTRACT_CHAIN_FAMILY_TO_PACK = Object.freeze({
  evm: SMART_CONTRACT_EVM_CAPABILITY_PACK,
  svm: SMART_CONTRACT_SVM_CAPABILITY_PACK,
  aptos: SMART_CONTRACT_APTOS_CAPABILITY_PACK,
  sui: SMART_CONTRACT_SUI_CAPABILITY_PACK,
  substrate: SMART_CONTRACT_SUBSTRATE_CAPABILITY_PACK,
  cosmwasm: SMART_CONTRACT_COSMWASM_CAPABILITY_PACK,
});

function normalizeSurfaceType(value) {
  if (value == null) return null;
  const normalized = String(value).trim().toLowerCase().replace(/[\s-]+/g, "_");
  return normalized || null;
}

// A physical surface must carry an explicit, provider-neutral signal. The
// canonical `physical` surface type and the SurfaceGraph ontology are the
// closed known vocabulary; a `physical_*` type or `surface_class:physical`
// preserves future/unknown physical types as physical-but-unroutable instead
// of laundering them into the web fallback. An explicit `capability_pack`
// or `required_capability_pack` marker is also deny-precedence input: stale or
// tampered physical metadata may become unavailable, but it cannot silently
// acquire web tools.
function isPhysicalSurfaceMetadata(surface) {
  if (!surface || typeof surface !== "object" || Array.isArray(surface)) return false;
  const surfaceType = normalizeSurfaceType(surface.surface_type);
  const surfaceClass = normalizeSurfaceType(surface.surface_class);
  const declaredPack = normalizeSurfaceType(surface.capability_pack);
  const requiredPack = normalizeSurfaceType(surface.required_capability_pack);
  return surfaceClass === "physical"
    || declaredPack === "physical"
    || requiredPack === "physical"
    || PHYSICAL_SURFACE_TYPE_SET.has(surfaceType)
    || (typeof surfaceType === "string" && surfaceType.startsWith("physical_"));
}

function getCapabilityPack(packId) {
  return CAPABILITY_PACKS[packId] || null;
}

function isCapabilityPackDispatchable(packOrId) {
  const pack = typeof packOrId === "string" ? getCapabilityPack(packOrId) : packOrId;
  return !!pack && pack.dispatchable !== false;
}

function dispatchableCapabilityPacks() {
  return Object.values(CAPABILITY_PACKS).filter(isCapabilityPackDispatchable);
}

// NS-6 — Resolve the canonical capability-pack id used by the technique registry.
// Most packs are their own technique family. Routing-only variants declare
// `technique_compatibility_pack` on their registry entry (or inherit it via a
// SPREAD-derived entry such as web_fanout), keeping the relation registry-owned
// and automatically shared by selection, full reads, and attempt logging.
function techniqueCompatibilityPackId(packId) {
  const pack = getCapabilityPack(packId);
  if (!isCapabilityPackDispatchable(pack)) return null;
  const compatibilityPackId = pack.technique_compatibility_pack || pack.id;
  const compatibilityPack = getCapabilityPack(compatibilityPackId);
  if (!isCapabilityPackDispatchable(compatibilityPack)) {
    throw new Error(
      `Capability pack ${pack.id} references unavailable technique_compatibility_pack ${compatibilityPackId}`,
    );
  }
  const canonicalTarget = compatibilityPack.technique_compatibility_pack || compatibilityPack.id;
  if (canonicalTarget !== compatibilityPackId) {
    throw new Error(
      `Capability pack ${pack.id} references non-canonical technique_compatibility_pack ${compatibilityPackId}; use ${canonicalTarget}`,
    );
  }
  return compatibilityPackId;
}

function cloneContextBudget(budget) {
  return {
    candidate_pack_limit: budget.candidate_pack_limit,
    full_pack_read_limit: budget.full_pack_read_limit,
    attempt_log_required: budget.attempt_log_required,
  };
}

function getCapabilityPackContextBudget(packId) {
  const pack = getCapabilityPack(packId);
  if (!isCapabilityPackDispatchable(pack)) return null;
  return cloneContextBudget(pack.context_budget || DEFAULT_CONTEXT_BUDGET);
}

function evaluatorAgentNamesForCapabilityPacks() {
  return Array.from(new Set(
    dispatchableCapabilityPacks()
      .map((pack) => pack && pack.evaluator_agent)
      .filter((value) => typeof value === "string" && value.trim()),
  ));
}

// Plane X Cycle X.10 — family tag for evaluator-spawn descriptions.
// Returns the short chain-family identifier for a capability pack id
// (e.g., "web" → "web", "smart_contract_evm" → "evm",
// "smart_contract_aptos" → "aptos"). Used by bob_prepare_node to mint
// the family-tagged spawn label (e.g., evaluator-spawn[web|evm] for a
// web↔EVM transition node). Returns null for unknown pack ids so the
// caller can decide whether to omit the tag.
function familyTagForCapabilityPackId(packId) {
  const pack = getCapabilityPack(packId);
  if (!pack || !pack.spawn) return null;
  // Web pack has spawn.profile = "web" without a chain_family field;
  // SC packs carry spawn.chain_family directly.
  if (pack.spawn.profile === "web") return "web";
  if (pack.spawn.profile === "physical") return "physical";
  if (typeof pack.spawn.chain_family === "string" && pack.spawn.chain_family.length > 0) {
    return pack.spawn.chain_family;
  }
  return null;
}

// Spawn-template iteration helper consumed by Claude/Codex
// orchestrator-skill renderers.
function smartContractCapabilityPacks() {
  return Object.values(CAPABILITY_PACKS).filter(
    (pack) => pack && pack.spawn && pack.spawn.profile === "smart_contract",
  );
}

function evaluatorRoleSpec(roleId) {
  const spec = EVALUATOR_ROLES[roleId];
  if (!spec) throw new Error(`Unknown evaluator role id: ${roleId}`);
  return spec;
}

function evaluatorRoleSpecs() {
  return Object.values(EVALUATOR_ROLES);
}

// Chain-specific role bundles derived from EVALUATOR_ROLES, used by
// tool-registry.js to build VALID_ROLE_BUNDLES at module load. Adding a
// evaluator role automatically adds its role bundle here. role_bundles[0]
// is "evaluator-shared" across every role; role_bundles[1+] are the
// chain-specific bundles.
function chainSpecificEvaluatorBundles() {
  const bundles = new Set();
  for (const role of evaluatorRoleSpecs()) {
    for (const bundle of role.role_bundles) {
      if (bundle === "evaluator-shared") continue;
      bundles.add(bundle);
    }
  }
  return Array.from(bundles).sort();
}

function defaultWebRouteMetadata() {
  return {
    capability_pack: WEB_CAPABILITY_PACK.id,
    capability_pack_version: WEB_CAPABILITY_PACK.capability_pack_version,
    evaluator_agent: WEB_CAPABILITY_PACK.evaluator_agent,
    brief_profile: WEB_CAPABILITY_PACK.brief_profile,
    context_budget: cloneContextBudget(WEB_CAPABILITY_PACK.context_budget),
  };
}

// Ordinal confidence ladder in demotion order (highest first).
// deriveConfidenceAdjustment only ever walks DOWN this ladder, never UP.
const CONFIDENCE_LADDER = Object.freeze(["high", "medium", "low"]);

// N distinct tool_inadequate observations on a surface/pack = one confidence
// step down. Heavier friction crosses more thresholds and demotes further.
const HEAVY_FRICTION_DEMOTION_THRESHOLD = 3;

// PURE, deterministic post-adjustment of a classifier confidence given a
// per-surface / per-pack friction aggregate. No fs, no frontier reads, no
// Date.now(), no randomness — input maps to output only. Demotes one ordinal
// step per HEAVY_FRICTION_DEMOTION_THRESHOLD tool_inadequate observations,
// clamped at "low"; NEVER promotes above baseConfidence, NEVER changes
// routability. An unrecognised/absent base is returned unchanged.
function deriveConfidenceAdjustment(baseConfidence, frictionSignalForSurfaceOrPack) {
  const idx = CONFIDENCE_LADDER.indexOf(baseConfidence);
  // Unrecognised base (or absent): never invent a level — no-op passthrough.
  if (idx === -1) return baseConfidence;

  // Accept the small aggregate shape { tool_inadequate_count: <int> }, or a
  // bare non-negative integer as shorthand for that count. Any other shape,
  // null, or undefined means zero steps (no demotion).
  let count = 0;
  if (
    frictionSignalForSurfaceOrPack &&
    typeof frictionSignalForSurfaceOrPack === "object" &&
    Number.isInteger(frictionSignalForSurfaceOrPack.tool_inadequate_count) &&
    frictionSignalForSurfaceOrPack.tool_inadequate_count >= 0
  ) {
    count = frictionSignalForSurfaceOrPack.tool_inadequate_count;
  } else if (
    Number.isInteger(frictionSignalForSurfaceOrPack) &&
    frictionSignalForSurfaceOrPack >= 0
  ) {
    count = frictionSignalForSurfaceOrPack;
  }

  const steps = Math.floor(count / HEAVY_FRICTION_DEMOTION_THRESHOLD);
  // demotedIdx >= idx structurally guarantees demotion-only (never promotes);
  // steps === 0 returns baseConfidence unchanged.
  const demotedIdx = Math.min(CONFIDENCE_LADDER.length - 1, idx + steps);
  return CONFIDENCE_LADDER[demotedIdx];
}

function classifySurfaceCapability(surface) {
  const rawSurfaceType = surface && typeof surface === "object" ? surface.surface_type : null;
  const normalizedType = normalizeSurfaceType(rawSurfaceType);
  const surfaceType = normalizedType || "unknown";
  const reasons = normalizedType ? [`surface_type:${surfaceType}`] : ["surface_type:missing"];

  if (isPhysicalSurfaceMetadata(surface)) {
    const surfaceClass = normalizeSurfaceType(surface.surface_class);
    const declaredPack = normalizeSurfaceType(surface.capability_pack);
    const requiredPack = normalizeSurfaceType(surface.required_capability_pack);
    if (surfaceClass === "physical") reasons.push("surface_class:physical");
    if (declaredPack === "physical") reasons.push("declared_capability_pack:physical");
    if (requiredPack === "physical") reasons.push("required_capability_pack:physical");
    if (!PHYSICAL_SURFACE_TYPE_SET.has(normalizedType)
        && typeof normalizedType === "string"
        && normalizedType.startsWith("physical_")) {
      reasons.push("physical_surface_type:unregistered");
    }
    reasons.push("capability_pack:physical_registered_unavailable");
    return {
      surface_type: surfaceType,
      surface_class: "physical",
      capability_pack: null,
      capability_pack_version: null,
      required_capability_pack: PHYSICAL_CAPABILITY_PACK.id,
      required_capability_pack_version: PHYSICAL_CAPABILITY_PACK.capability_pack_version,
      evaluator_agent: null,
      brief_profile: null,
      context_budget: null,
      chain_family: null,
      confidence: PHYSICAL_SURFACE_TYPE_SET.has(normalizedType) ? "high" : "low",
      routable: false,
      unroutable_reason: PHYSICAL_CAPABILITY_PACK_UNAVAILABLE_REASON,
      reasons,
    };
  }

  if (normalizedType === "smart_contract") {
    const rawChainFamily = surface && typeof surface === "object" ? surface.chain_family : null;
    const normalizedChainFamily = normalizeSurfaceType(rawChainFamily);
    if (normalizedChainFamily) {
      const pack = SMART_CONTRACT_CHAIN_FAMILY_TO_PACK[normalizedChainFamily];
      if (pack) {
        reasons.push(`chain_family:${normalizedChainFamily}`);
        return {
          surface_type: surfaceType,
          capability_pack: pack.id,
          capability_pack_version: pack.capability_pack_version,
          evaluator_agent: pack.evaluator_agent,
          brief_profile: pack.brief_profile,
          context_budget: cloneContextBudget(pack.context_budget),
          chain_family: normalizedChainFamily,
          confidence: "high",
          routable: true,
          reasons,
        };
      }
      // Smart-contract surface with an unrecognised chain_family. Falling back
      // to the web pack would launder an on-chain surface into a web evaluator
      // with no chain tools, contradicting surface_type. Per Y-D21 the
      // smart_contract classification and its chain_family are preserved and
      // the result is marked unroutable so the caller records a graceful
      // disposition instead of mis-routing.
      reasons.push(`chain_family:${normalizedChainFamily}`);
      return {
        surface_type: surfaceType,
        capability_pack: null,
        capability_pack_version: null,
        evaluator_agent: null,
        brief_profile: null,
        context_budget: null,
        chain_family: normalizedChainFamily,
        confidence: "low",
        routable: false,
        unroutable_reason: `smart_contract surface has unsupported chain_family ${normalizedChainFamily}; register a capability pack or correct the surface`,
        reasons,
      };
    }
    // Smart-contract surface without a chain_family: routing requires it, so
    // preserve the smart_contract classification and mark unroutable rather
    // than falling through to the web pack (Y-D21).
    reasons.push("chain_family:missing");
    return {
      surface_type: surfaceType,
      capability_pack: null,
      capability_pack_version: null,
      evaluator_agent: null,
      brief_profile: null,
      context_budget: null,
      chain_family: normalizedChainFamily,
      confidence: "low",
      routable: false,
      unroutable_reason: "smart_contract surface is missing chain_family; capability routing requires it",
      reasons,
    };
  }

  if (normalizedType && OSS_SURFACE_TYPE_TO_PACK[normalizedType]) {
    const pack = OSS_SURFACE_TYPE_TO_PACK[normalizedType];
    reasons.push(`oss_pack:${pack.id}`);
    return {
      surface_type: surfaceType,
      capability_pack: pack.id,
      capability_pack_version: pack.capability_pack_version,
      evaluator_agent: pack.evaluator_agent,
      brief_profile: pack.brief_profile,
      context_budget: cloneContextBudget(pack.context_budget),
      chain_family: null,
      confidence: "high",
      routable: true,
      reasons,
    };
  }

  const knownWebType = normalizedType == null || WEB_SURFACE_TYPE_SET.has(surfaceType);
  if (!knownWebType) {
    reasons.push("fallback:web");
  }

  return {
    surface_type: surfaceType,
    capability_pack: WEB_CAPABILITY_PACK.id,
    capability_pack_version: WEB_CAPABILITY_PACK.capability_pack_version,
    evaluator_agent: WEB_CAPABILITY_PACK.evaluator_agent,
    brief_profile: WEB_CAPABILITY_PACK.brief_profile,
    context_budget: cloneContextBudget(WEB_CAPABILITY_PACK.context_budget),
    chain_family: null,
    confidence: knownWebType ? "high" : "medium",
    routable: true,
    reasons,
  };
}

function assertPackString(value, fieldName) {
  if (typeof value !== "string" || !value.trim()) {
    throw new Error(`assignment route metadata has invalid ${fieldName}`);
  }
  const normalized = value.trim();
  if (!/^[A-Za-z][A-Za-z0-9_-]{0,63}$/.test(normalized)) {
    throw new Error(`assignment route metadata has invalid ${fieldName}`);
  }
  return normalized;
}

function assertPositiveInteger(value, fieldName) {
  if (!Number.isInteger(value) || value < 1) {
    throw new Error(`assignment route metadata has invalid ${fieldName}`);
  }
  return value;
}

function normalizeBudgetInteger(value, fieldName) {
  if (!Number.isInteger(value) || value < 1 || value > 100_000) {
    throw new Error(`assignment route metadata has invalid context_budget.${fieldName}`);
  }
  return value;
}

function normalizeBudgetBoolean(value, fieldName) {
  if (typeof value !== "boolean") {
    throw new Error(`assignment route metadata has invalid context_budget.${fieldName}`);
  }
  return value;
}

function normalizeContextBudget(value, pack) {
  if (value == null) {
    return cloneContextBudget(pack.context_budget || DEFAULT_CONTEXT_BUDGET);
  }
  if (typeof value !== "object" || Array.isArray(value)) {
    throw new Error("assignment route metadata has invalid context_budget");
  }
  const allowedFields = new Set([
    "candidate_pack_limit",
    "full_pack_read_limit",
    "attempt_log_required",
  ]);
  for (const field of Object.keys(value)) {
    if (!allowedFields.has(field)) {
      throw new Error(`assignment route metadata has unsupported context_budget.${field}`);
    }
  }
  return {
    candidate_pack_limit: normalizeBudgetInteger(value.candidate_pack_limit, "candidate_pack_limit"),
    full_pack_read_limit: normalizeBudgetInteger(value.full_pack_read_limit, "full_pack_read_limit"),
    attempt_log_required: normalizeBudgetBoolean(value.attempt_log_required, "attempt_log_required"),
  };
}

function normalizeAssignmentRouteMetadata(assignment) {
  // The FROZEN (MCP-owned, route-time) id-bearing endpoint set is carried regardless of
  // which route-metadata path applies, so the AD1 completion gate can bind sweep coverage
  // to it — never re-derived from agent-writable attack_surface.json.
  const idBearingEndpoints = Array.isArray(assignment && assignment.id_bearing_endpoints)
    ? assignment.id_bearing_endpoints.filter((e) => typeof e === "string" && e) : [];
  const idBearing = !!(assignment && assignment.id_bearing === true);
  const hasRouteMetadata = !!assignment && (
    assignment.capability_pack != null ||
    assignment.capability_pack_version != null ||
    assignment.evaluator_agent != null ||
    assignment.brief_profile != null ||
    assignment.context_budget != null
  );
  if (!hasRouteMetadata) {
    // Legacy assignment files (pre-router) carry no route metadata. Default
    // to the web pack — but ONLY if the captured surface_type is non-SC. A
    // smart_contract assignment with no route triple would otherwise be
    // silently stamped as a web evaluator; that contradicts surface_type and
    // sends pack-keyed consumers into the wrong pipeline.
    const surfaceType = assignment && typeof assignment === "object"
      ? assignment.surface_type
      : null;
    if (surfaceType === "smart_contract") {
      throw new Error(
        "assignment with surface_type=smart_contract is missing capability_pack/evaluator_agent/brief_profile; route the surface via bob_route_surfaces before starting the wave",
      );
    }
    if (isPhysicalSurfaceMetadata(assignment)) {
      throw new Error(
        "assignment with physical surface metadata is missing a dispatchable capability_pack/evaluator_agent/brief_profile; route the surface via bob_route_surfaces before starting the wave",
      );
    }
    return { ...defaultWebRouteMetadata(), id_bearing: idBearing, id_bearing_endpoints: idBearingEndpoints };
  }

  const capabilityPack = assertPackString(assignment.capability_pack, "capability_pack");
  const pack = getCapabilityPack(capabilityPack);
  if (!pack) {
    throw new Error(`assignment route metadata references unknown capability_pack: ${capabilityPack}`);
  }
  if (!isCapabilityPackDispatchable(pack)) {
    throw new Error(
      `assignment route metadata references non-dispatchable capability_pack ${capabilityPack}: ${pack.dispatch_block_reason}`,
    );
  }
  if (isPhysicalSurfaceMetadata(assignment)) {
    throw new Error(
      `assignment with physical surface metadata cannot bind active capability_pack ${capabilityPack}; ${PHYSICAL_CAPABILITY_PACK_UNAVAILABLE_REASON}`,
    );
  }
  const evaluatorAgent = assertPackString(assignment.evaluator_agent, "evaluator_agent");
  const briefProfile = assertPackString(assignment.brief_profile, "brief_profile");
  if (evaluatorAgent !== pack.evaluator_agent) {
    throw new Error(`assignment route metadata evaluator_agent ${evaluatorAgent} does not match pack ${capabilityPack}`);
  }
  if (briefProfile !== pack.brief_profile) {
    throw new Error(`assignment route metadata brief_profile ${briefProfile} does not match pack ${capabilityPack}`);
  }
  const capabilityPackVersion = assignment.capability_pack_version == null
    ? pack.capability_pack_version
    : assertPositiveInteger(assignment.capability_pack_version, "capability_pack_version");

  return {
    capability_pack: capabilityPack,
    capability_pack_version: capabilityPackVersion,
    evaluator_agent: evaluatorAgent,
    brief_profile: briefProfile,
    context_budget: normalizeContextBudget(assignment.context_budget, pack),
    id_bearing: idBearing,
    id_bearing_endpoints: idBearingEndpoints,
  };
}

// Read-side backfill for legacy findings.jsonl rows written before
// bob_record_candidate_claim persisted the route triple. Legacy rows carry
// surface_type and (for SC findings) sc_evidence.chain_family but no
// capability_pack/evaluator_agent/brief_profile. Rebuilding the triple
// at read time keeps verifier/evidence/grader/reporter consumers from
// each having to implement the same fallback. Returns null when the
// record carries no usable signal.
function capabilityPackForLegacyFinding({ surface_type: surfaceType, sc_evidence: scEvidence } = {}) {
  if (isPhysicalSurfaceMetadata({ surface_type: surfaceType })) {
    // Physical findings require their own opaque-asset/verdict schema and may
    // never be reinterpreted as legacy web findings. That schema is not wired
    // in this slice, so the only honest read-side backfill is no backfill.
    return null;
  }
  if (surfaceType === "smart_contract") {
    const chainFamily = scEvidence && typeof scEvidence === "object" ? scEvidence.chain_family : null;
    const normalized = normalizeSurfaceType(chainFamily);
    if (normalized) {
      const pack = SMART_CONTRACT_CHAIN_FAMILY_TO_PACK[normalized];
      if (pack) {
        return {
          capability_pack: pack.id,
          evaluator_agent: pack.evaluator_agent,
          brief_profile: pack.brief_profile,
        };
      }
    }
    // SC row whose chain_family no longer maps to a registered pack.
    // Caller decides whether to leave nulls or treat as malformed.
    return null;
  }
  // Any non-SC, non-physical legacy row maps to the web pack.
  return defaultWebRouteMetadata();
}

// Coarse (surface-class x bug_class) applicability gate for cell enumeration.
// Maps the clearly type-restricted bug classes to the surface class(es) they
// can occur on. FAILS OPEN: a bug_class with no rule here is relevant on every
// surface, so the gate only prunes the structurally-impossible (e.g. reentrancy
// on a web surface, sqli on a smart contract), never the merely-unmapped. Keep
// it conservative — over-pruning loses coverage, which is the opposite of the
// goal; ambiguous classes (idor, ssrf, dos, ...) stay unmapped on purpose.
const BUG_CLASS_SURFACE_APPLICABILITY = Object.freeze({
  reentrancy: Object.freeze(["smart_contract"]),
  sql_injection: Object.freeze(["web"]),
  sqli: Object.freeze(["web"]),
  xss: Object.freeze(["web"]),
  csrf: Object.freeze(["web"]),
});

function normalizeBugClassKey(bugClass) {
  return typeof bugClass === "string"
    ? bugClass.trim().toLowerCase().replace(/[\s-]+/g, "_")
    : "";
}

const CONTROL_VALIDITY_CLASS_BY_BUG_CLASS = Object.freeze({
  access_control: CONTROL_VALIDITY_CLASS_OBJECT_AUTH,
  auth_bypass: CONTROL_VALIDITY_CLASS_OBJECT_AUTH,
  authorization_bypass: CONTROL_VALIDITY_CLASS_OBJECT_AUTH,
  broken_access_control: CONTROL_VALIDITY_CLASS_OBJECT_AUTH,
  broken_object_level_authorization: CONTROL_VALIDITY_CLASS_OBJECT_AUTH,
  cwe_639: CONTROL_VALIDITY_CLASS_OBJECT_AUTH,
  idor: CONTROL_VALIDITY_CLASS_OBJECT_AUTH,
  missing_authorization: CONTROL_VALIDITY_CLASS_OBJECT_AUTH,
  missing_authz: CONTROL_VALIDITY_CLASS_OBJECT_AUTH,
  object_authorization: CONTROL_VALIDITY_CLASS_OBJECT_AUTH,
  object_level_authorization: CONTROL_VALIDITY_CLASS_OBJECT_AUTH,
  privilege_escalation: CONTROL_VALIDITY_CLASS_OBJECT_AUTH,
  unauth_succeeds_where_auth_blocked: CONTROL_VALIDITY_CLASS_OBJECT_AUTH,
});

// Closure fan-out is fail-closed for genuinely unknown autonomous classes, but
// it still recognizes the legacy, registry-owned classes Bob already routes.
// This is a routing registry, not closure authority: only a deterministic
// proof-mode can certify a finding.
const REGISTERED_CLOSURE_BUG_CLASS_KEYS = Object.freeze(Array.from(new Set([
  ...Object.keys(BUG_CLASS_SURFACE_APPLICABILITY),
  ...Object.keys(CONTROL_VALIDITY_CLASS_BY_BUG_CLASS),
  "asan",
  "ubsan",
  "msan",
  "raw_corpus",
  "value_profile",
  "cmplog",
  "ssrf",
  "ssti",
  "replay",
  "cross_chain",
  "cross_chain_replay",
  "identity_handoff",
  "cross_stack_identity",
  "value_flow",
  "trust_boundary",
  "state_consistency",
  "oracle_manipulation",
  "staleness",
  "message_forgery",
  "validate_vs_consume",
  "cwe_120",
  "memory_safety",
  "length_field",
  "bound_check_site",
  "pull_request_target",
  "github_token",
])));

function controlValidityClassForBugClass(bugClass) {
  const key = normalizeBugClassKey(bugClass);
  return CONTROL_VALIDITY_CLASS_BY_BUG_CLASS[key] || null;
}

function isBugClassRegisteredForClosure(bugClass) {
  return REGISTERED_CLOSURE_BUG_CLASS_KEYS.includes(normalizeBugClassKey(bugClass));
}

// Broad surface class ("web" | "smart_contract" | "oss") for a surface's
// metadata, mirroring packIdForSurfaceMetadata's honor-then-classify order.
// Returns null (-> fail open) on any unknown/throwing classification.
function surfaceClassForMetadata(surfaceMetadata) {
  let packId = null;
  try {
    if (isPhysicalSurfaceMetadata(surfaceMetadata)) return "physical";
    if (surfaceMetadata && typeof surfaceMetadata === "object"
      && typeof surfaceMetadata.capability_pack === "string") {
      const pack = getCapabilityPack(surfaceMetadata.capability_pack);
      if (pack && isCapabilityPackDispatchable(pack)) packId = pack.id;
      if (pack && pack.surface_class === "physical") return "physical";
    }
    if (!packId) {
      const classification = classifySurfaceCapability(surfaceMetadata || {});
      packId = classification.capability_pack;
      // An unavailable physical pack and an ambiguous smart_contract both
      // classify with capability_pack:null. Preserve their declared class;
      // neither is ever a web surface.
      if (packId == null && classification.surface_class === "physical") {
        return "physical";
      }
      if ((packId == null) && classification.surface_type === "smart_contract") {
        return "smart_contract";
      }
    }
  } catch {
    return null;
  }
  if (typeof packId !== "string") return null;
  if (packId.startsWith("smart_contract")) return "smart_contract";
  if (packId.startsWith("oss")) return "oss";
  if (packId === "physical") return "physical";
  return "web";
}

// OSS/native coverage modality axes. An OSS surface IS a harness (a code_module
// fuzz target); its cells cross the build-config axis (sanitizer class) with the
// fuzzing-strategy axis (input class). The specific crash found is an OUTCOME
// recorded at reconcile, NOT a pre-enumerated axis. All values are lowercase so
// they survive coverage-key normalization unchanged.
const OSS_SANITIZER_CLASS_AXIS = Object.freeze(["asan", "ubsan", "msan"]);
const OSS_INPUT_CLASS_AXIS = Object.freeze(["raw_corpus", "value_profile", "cmplog"]);

// Transition-cell bug_class axis (A2). A transition-cell is a (transition_edge x
// bug_class) coverage obligation — a cross-surface invariant a per-surface model
// cannot see because it lives on the EDGE. The axis is keyed by the transition
// KIND (the closed TRANSITION_KIND_VALUES enum), so the bug_class is the class of
// trust hop being crossed, not a per-surface vuln hint. There is NO auth axis:
// the cross-surface invariant holds regardless of which credential probes one
// endpoint. The replay/cross-chain/identity classes are exactly the ones
// BUG_CLASS_WEAPON maps to web3_identity_handoff, so a transition-cell auto-adopts
// the cross-surface weapon a surface-cell never reaches for. All lowercase so the
// values survive coverage-key normalization unchanged; 1-2 entries each keeps the
// floor finite and deterministic.
const TRANSITION_BUG_CLASS_AXIS = Object.freeze({
  identity_propagation: Object.freeze(["identity_handoff", "replay"]),
  value_movement: Object.freeze(["value_flow", "replay"]),
  trust_handoff: Object.freeze(["trust_boundary", "cross_chain_replay"]),
  state_dependency: Object.freeze(["state_consistency", "replay"]),
  oracle_dependency: Object.freeze(["oracle_manipulation", "staleness"]),
  message_passing: Object.freeze(["cross_chain_replay", "message_forgery"]),
});

function isOssSurfaceMetadata(surfaceMetadata) {
  return surfaceClassForMetadata(surfaceMetadata) === "oss";
}

// Is this bug_class structurally possible on this surface? Fail-open: unmapped
// bug_classes and unknown surface classes are always relevant.
function isBugClassRelevantForSurface(surfaceMetadata, bugClass) {
  const allowed = BUG_CLASS_SURFACE_APPLICABILITY[normalizeBugClassKey(bugClass)];
  if (!allowed) return true;
  const surfaceClass = surfaceClassForMetadata(surfaceMetadata);
  if (surfaceClass === null) return true;
  return allowed.includes(surfaceClass);
}

module.exports = {
  CAPABILITY_PACKS,
  DEFAULT_CONTEXT_BUDGET,
  DEFAULT_REPLAY_SAFETY,
  EVALUATOR_ROLES,
  PHYSICAL_CAPABILITY_PACK,
  PHYSICAL_CAPABILITY_PACK_UNAVAILABLE_REASON,
  PHYSICAL_SURFACE_TYPES,
  WEB_SURFACE_TYPES,
  capabilityPackForLegacyFinding,
  chainSpecificEvaluatorBundles,
  classifySurfaceCapability,
  controlValidityClassForBugClass,
  deriveConfidenceAdjustment,
  dispatchableCapabilityPacks,
  isBugClassRelevantForSurface,
  isBugClassRegisteredForClosure,
  isCapabilityPackDispatchable,
  isPhysicalSurfaceMetadata,
  isOssSurfaceMetadata,
  OSS_SANITIZER_CLASS_AXIS,
  OSS_INPUT_CLASS_AXIS,
  TRANSITION_BUG_CLASS_AXIS,
  defaultWebRouteMetadata,
  getCapabilityPack,
  getCapabilityPackContextBudget,
  evaluatorAgentNamesForCapabilityPacks,
  evaluatorRoleSpec,
  evaluatorRoleSpecs,
  familyTagForCapabilityPackId,
  normalizeAssignmentRouteMetadata,
  selectWebEvaluatorPack,
  techniqueCompatibilityPackId,
  normalizeContextBudget,
  normalizeSurfaceType,
  SMART_CONTRACT_CONTEXT_BUDGET,
  smartContractCapabilityPacks,
};
