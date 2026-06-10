"use strict";

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

const SC_DIRECT_EGRESS_SUMMARY = "SC RPC/REST egress is direct public HTTPS only: DNS-private endpoints, private/localnet RPC, and egress_profile proxy routing are unsupported by default.";

const WEB_CAPABILITY_PACK = Object.freeze({
  id: "web",
  capability_pack_version: 1,
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
    workflow_summary: `bob_evm_fetch_source -> read sources via Read -> bob_evm_role_table to map the trust boundary -> scaffold a Foundry test under harness_path/test/ via Write -> bob_foundry_run with chain_id and pinned fork_block -> record bypass_attempts[] entries citing the actual harness path + test name in attempt_summary. ${SC_DIRECT_EGRESS_SUMMARY}`,
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
    workflow_summary: `bob_svm_fetch_program (confirm upgrade authority) -> bob_svm_fetch_account (read multisig + state accounts) -> scaffold an Anchor test under harness_path/tests/ via Write -> bob_anchor_run with cluster and optional pinned fork_slot -> record bypass_attempts[] entries citing the actual harness path + test description in attempt_summary. ${SC_DIRECT_EGRESS_SUMMARY}`,
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
    workflow_summary: `bob_aptos_fetch_module (enumerate exposed_functions, structs, friends) -> bob_aptos_fetch_resource (read capability tokens, ownership records, treasury balances) -> scaffold an \`aptos move test\` harness under harness_path/sources/ via Write -> bob_aptos_run with network and optional pinned fork_version -> record bypass_attempts[] citing the actual harness path + test name in attempt_summary. ${SC_DIRECT_EGRESS_SUMMARY}`,
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
    workflow_summary: `bob_sui_fetch_package (enumerate entry functions and friend relationships) -> bob_sui_fetch_object (inspect Owner=Immutable/Shared/AddressOwner/ObjectOwner, Move type, capability fields) -> scaffold a \`sui move test\` harness under harness_path/sources/ via Write -> bob_sui_run with network and optional pinned fork_checkpoint -> record bypass_attempts[] citing the actual harness path + test name in attempt_summary. ${SC_DIRECT_EGRESS_SUMMARY}`,
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
    workflow_summary: `bob_substrate_fetch_runtime (confirm chain identity + spec_version) -> bob_substrate_fetch_storage (read pallet_contracts.ContractInfoOf for code_hash and admin) -> scaffold an ink! \`cargo test\` harness under harness_path/ via Write (uses #[ink::test] for unit or #[ink_e2e::test] for E2E) -> bob_substrate_run with network and optional pinned fork_block -> record bypass_attempts[] citing the actual harness path + test name in attempt_summary. ${SC_DIRECT_EGRESS_SUMMARY}`,
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
    workflow_summary: `bob_cosmwasm_fetch_contract (confirm contract exists, capture code_id + admin) -> bob_cosmwasm_smart_query (inspect public Config / Owner / Balance entrypoints) -> scaffold a cw-multi-test integration test under harness_path/tests/ via Write -> bob_cosmwasm_run with network and optional pinned fork_block -> record bypass_attempts[] citing the actual harness path + test name in attempt_summary. ${SC_DIRECT_EGRESS_SUMMARY}`,
    cli_dependency: "cargo",
    blocked_harness_kind_options: "cosmwasm_fork or rpc_endpoint",
  }),
});

const CAPABILITY_PACKS = Object.freeze({
  web: WEB_CAPABILITY_PACK,
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

function getCapabilityPack(packId) {
  return CAPABILITY_PACKS[packId] || null;
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
  if (!pack) return null;
  return cloneContextBudget(pack.context_budget || DEFAULT_CONTEXT_BUDGET);
}

function evaluatorAgentNamesForCapabilityPacks() {
  return Array.from(new Set(
    Object.values(CAPABILITY_PACKS)
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

function classifySurfaceCapability(surface) {
  const rawSurfaceType = surface && typeof surface === "object" ? surface.surface_type : null;
  const normalizedType = normalizeSurfaceType(rawSurfaceType);
  const surfaceType = normalizedType || "unknown";
  const reasons = normalizedType ? [`surface_type:${surfaceType}`] : ["surface_type:missing"];

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
          confidence: "high",
          reasons,
        };
      }
      // Smart-contract surface with an unrecognised chain_family. Falling
      // back to the web pack would create a contradiction (surface_type=smart_contract
      // routed to a evaluator that has no on-chain tools); fail loudly so the
      // operator either fixes the surface or registers the missing pack.
      throw new Error(
        `smart_contract surface ${surface && surface.id ? surface.id : "(unknown)"} has unsupported chain_family ${normalizedChainFamily}; register a capability pack or correct the surface`,
      );
    }
    throw new Error(
      `smart_contract surface ${surface && surface.id ? surface.id : "(unknown)"} is missing chain_family; capability routing requires it`,
    );
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
      confidence: "high",
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
    confidence: knownWebType ? "high" : "medium",
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
    return defaultWebRouteMetadata();
  }

  const capabilityPack = assertPackString(assignment.capability_pack, "capability_pack");
  const evaluatorAgent = assertPackString(assignment.evaluator_agent, "evaluator_agent");
  const briefProfile = assertPackString(assignment.brief_profile, "brief_profile");
  const pack = getCapabilityPack(capabilityPack);
  if (!pack) {
    throw new Error(`assignment route metadata references unknown capability_pack: ${capabilityPack}`);
  }
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
  // Any non-SC legacy row maps to the web pack.
  return defaultWebRouteMetadata();
}

module.exports = {
  CAPABILITY_PACKS,
  DEFAULT_CONTEXT_BUDGET,
  DEFAULT_REPLAY_SAFETY,
  EVALUATOR_ROLES,
  WEB_SURFACE_TYPES,
  capabilityPackForLegacyFinding,
  chainSpecificEvaluatorBundles,
  classifySurfaceCapability,
  defaultWebRouteMetadata,
  getCapabilityPack,
  getCapabilityPackContextBudget,
  evaluatorAgentNamesForCapabilityPacks,
  evaluatorRoleSpec,
  evaluatorRoleSpecs,
  familyTagForCapabilityPackId,
  normalizeAssignmentRouteMetadata,
  normalizeContextBudget,
  normalizeSurfaceType,
  SMART_CONTRACT_CONTEXT_BUDGET,
  smartContractCapabilityPacks,
};
