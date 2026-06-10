"use strict";

const fs = require("fs");
const path = require("path");
const {
  mcpToolNamesForRole,
  roleDefinition,
} = require("../../mcp/lib/role-model.js");
const {
  substituteCapabilityPackVerifierTable,
  substituteHandoffFieldLimits,
  EVALUATOR_PACK_CATALOGUE_PLACEHOLDER,
} = require("../../mcp/lib/capability-packs-rendering.js");
const {
  renderCapabilityPlaybookAppendix,
} = require("../../mcp/lib/capability-playbooks.js");
const { evaluatorRoleSpecs } = require("../../mcp/lib/capability-packs.js");

const DEFAULT_ROOT = path.join(__dirname, "..", "..");

// Committed source-of-truth location for the rendered subagents. install()
// copies these into the target's `.opencode/agents/`. Mirrors how the Codex/
// Kimi adapters commit their rendered skills under `adapters/<host>/`.
const AGENTS_SOURCE_DIR = path.join("adapters", "opencode", "agents");

// OpenCode emits the native-tool booleans in this fixed order for stable,
// drift-free frontmatter. MCP `bob_*` tools ARE gated per role below:
// OpenCode registers MCP tools as `<server>_<tool>` keys that the per-agent
// `tools:` map matches with glob patterns (longest matching pattern wins in
// Wildcard.all), so each subagent denies `hacker-bob_*` wholesale and then
// allows exactly its registry-driven role bundle from mcpToolNamesForRole().
// This mirrors the Claude per-agent `mcp__hacker-bob__bob_*` allow-lists.
const OPENCODE_TOOL_ORDER = Object.freeze(["bash", "read", "write", "edit", "task"]);

// Server keys Bob wires into opencode.json (see adapters/opencode/index.js).
const BOB_MCP_SERVER_KEY = "hacker-bob";
const BRUTALIST_MCP_SERVER_KEY = "brutalist";

// Roles allowed to use the optional external @brutalist/mcp roast server.
const BRUTALIST_ALLOWED_ROLE_IDS = Object.freeze(["brutalist-verifier"]);

// Cross-cutting Bob roles -> OpenCode subagent specs. The orchestrator is the
// single `mode: primary` agent; every other role is a `mode: subagent` reached
// via `task(subagent_type: "bob-<name>")` from the orchestrator body.
// Per-chain evaluator specs are spliced in from evaluatorRoleSpecs() so adding
// a chain pack auto-extends this set without editing this file. No `model:` is
// pinned — OpenCode is BYOK and each subagent inherits the operator's
// configured model. Role IDs must match mcp/lib/role-model.js exactly.
const OPENCODE_CROSS_CUTTING_SPECS = Object.freeze({
  orchestrator: Object.freeze({
    name: "bob-orchestrator",
    mode: "primary",
    tools: Object.freeze({ bash: true, read: true, write: false, edit: false, task: true }),
    description: "Hacker Bob orchestrator — drives the six-state bug-bounty lifecycle and dispatches the per-role Bob subagents through the task tool. Invoked by /bob-evaluate.",
  }),
  "surface-discovery": Object.freeze({
    name: "bob-surface-discovery-agent",
    mode: "subagent",
    tools: Object.freeze({ bash: true, read: true, write: true, edit: false }),
    description: "Bob surface-discovery subagent — runs bounded normal surface discovery (subdomain enum, live hosts, archived/crawled URLs, nuclei, JS/JWT extraction) and writes attack_surface.json.",
  }),
  "deep-surface-discovery": Object.freeze({
    name: "bob-deep-surface-discovery-agent",
    mode: "subagent",
    tools: Object.freeze({ bash: true, read: true, write: true, edit: false }),
    description: "Bob deep surface-discovery subagent — runs bounded deep discovery and produces compact attack_surface, deep-summary, and surface-lead artifacts.",
  }),
  "surface-router": Object.freeze({
    name: "bob-surface-router-agent",
    mode: "subagent",
    tools: Object.freeze({ bash: false, read: true, write: false, edit: false }),
    description: "Bob surface-router subagent — calls the MCP surface router after discovery and reports the capability-pack summary.",
  }),
  evaluator: Object.freeze({
    name: "bob-evaluator-agent",
    mode: "subagent",
    tools: Object.freeze({ bash: true, read: true, write: false, edit: false }),
    description: "Bob web evaluator subagent — tests one routed attack surface for vulnerabilities and writes a wave handoff.",
  }),
});

// Plane X Cycle X.10 generic TaskGraph evaluator shell + the remaining
// cross-cutting roles, ordered to group the evaluator family together (mirrors
// the Claude/Kimi ordering).
const OPENCODE_TRAILING_SPECS = Object.freeze({
  "evaluator-spawn": Object.freeze({
    name: "bob-evaluator-spawn",
    mode: "subagent",
    tools: Object.freeze({ bash: true, read: true, write: true, edit: false }),
    description: "Bob generic TaskGraph evaluator shell — executes a dispatched Transition/Hypothesis node under the brief's allowed_tools_for_node[] constraint and writes a wave handoff.",
  }),
  chain: Object.freeze({
    name: "bob-chain-builder",
    mode: "subagent",
    tools: Object.freeze({ bash: false, read: true, write: false, edit: false }),
    description: "Bob chain-builder subagent — analyzes proven findings for credible impact chains that elevate severity, via the MCP graph apparatus.",
  }),
  "brutalist-verifier": Object.freeze({
    name: "bob-brutalist-verifier",
    mode: "subagent",
    tools: Object.freeze({ bash: true, read: true, write: false, edit: false }),
    description: "Bob round-1 verifier subagent — re-runs PoCs with maximum skepticism and filters non-bugs and severity inflation.",
  }),
  "balanced-verifier": Object.freeze({
    name: "bob-balanced-verifier",
    mode: "subagent",
    tools: Object.freeze({ bash: true, read: true, write: false, edit: false }),
    description: "Bob round-2 verifier subagent — reviews decisions for false negatives and severity over-corrections.",
  }),
  "final-verifier": Object.freeze({
    name: "bob-final-verifier",
    mode: "subagent",
    tools: Object.freeze({ bash: true, read: true, write: false, edit: false }),
    description: "Bob round-3 verifier subagent — re-runs only reportable findings with fresh requests as final confirmation.",
  }),
  evidence: Object.freeze({
    name: "bob-evidence-agent",
    mode: "subagent",
    tools: Object.freeze({ bash: false, read: true, write: false, edit: false }),
    description: "Bob evidence subagent — collects bounded pre-grade evidence packs for final reportable findings.",
  }),
  grader: Object.freeze({
    name: "bob-grader",
    mode: "subagent",
    tools: Object.freeze({ bash: false, read: true, write: false, edit: false }),
    description: "Bob grader subagent — scores verified findings on 5 axes and issues a SUBMIT/HOLD/SKIP verdict.",
  }),
  reporter: Object.freeze({
    name: "bob-report-writer",
    mode: "subagent",
    tools: Object.freeze({ bash: false, read: true, write: false, edit: false }),
    description: "Bob report-writer subagent — composes the submission-ready report from verified, graded findings via bob_compose_report.",
  }),
});

function evaluatorPackSpecs() {
  // Per-chain evaluator subagents, one per smart-contract chain family. Names
  // and descriptions come from the registry (evaluatorRoleSpecs) so a new chain
  // pack extends the set automatically without editing this file. All chain
  // evaluators write scratch test scaffolds, so they carry the write boolean.
  return Object.fromEntries(
    evaluatorRoleSpecs().map((role) => [
      role.role_id,
      Object.freeze({
        name: `bob-${role.name}`,
        mode: "subagent",
        tools: Object.freeze({ bash: true, read: true, write: true, edit: false }),
        description: role.description,
      }),
    ]),
  );
}

const OPENCODE_ROLE_SPECS = Object.freeze({
  ...OPENCODE_CROSS_CUTTING_SPECS,
  ...evaluatorPackSpecs(),
  ...OPENCODE_TRAILING_SPECS,
});

function roleSpec(roleId) {
  const spec = OPENCODE_ROLE_SPECS[roleId];
  if (!spec) throw new Error(`Missing OpenCode role spec for ${roleId}`);
  return spec;
}

function opencodeRoleOutputPath(roleId, { root = DEFAULT_ROOT } = {}) {
  return path.join(root, AGENTS_SOURCE_DIR, `${roleSpec(roleId).name}.md`);
}

function renderFrontmatter(spec, roleId) {
  const lines = ["---", `description: ${spec.description}`, `mode: ${spec.mode}`, "tools:"];
  for (const tool of OPENCODE_TOOL_ORDER) {
    if (tool in spec.tools) lines.push(`  ${tool}: ${spec.tools[tool]}`);
  }
  // Registry-driven MCP gating: deny the whole hacker-bob server, then allow
  // exactly this role's bundle. OpenCode's Wildcard.all gives the longest
  // matching pattern precedence, so each specific `hacker-bob_bob_*` allow key
  // overrides the `hacker-bob_*` deny glob. The external @brutalist/mcp server
  // is opened only for the verifier role that owns the roast contract.
  lines.push(`  "${BOB_MCP_SERVER_KEY}_*": false`);
  for (const toolName of mcpToolNamesForRole(roleId)) {
    lines.push(`  ${BOB_MCP_SERVER_KEY}_${toolName}: true`);
  }
  lines.push(`  "${BRUTALIST_MCP_SERVER_KEY}_*": ${BRUTALIST_ALLOWED_ROLE_IDS.includes(roleId)}`);
  lines.push("---");
  return lines.join("\n");
}

function roleBody(roleId, { root = DEFAULT_ROOT } = {}) {
  const role = roleDefinition(roleId);
  return fs.readFileSync(path.join(root, role.prompt_body), "utf8").replace(/^\n+/, "");
}

// Each {{SPAWN_*}} token becomes a `task(subagent_type: "bob-<role>", ...)`
// call block. OpenCode's task tool resolves subagent_type against the
// committed subagent file (whose body is the full role contract), so the task
// prompt only needs the run-specific header plus a wait line. `@bob-<role>`
// mentions are NOT used here: in OpenCode the `@` path is manual operator
// invocation in the TUI only — literal @mention text in an assistant message
// does not dispatch a sub-session.
function opencodeLaunchTemplates() {
  return Object.freeze({
    "{{SPAWN_SEED_DISCOVERY_AGENT}}": [
      "```text",
      "deep_mode false: task(subagent_type: \"bob-surface-discovery-agent\", description: \"Bob surface discovery\", prompt: \"DOMAIN=[domain] SESSION=~/hacker-bob-sessions/[domain]\")",
      "```",
      "Wait for the bob-surface-discovery-agent task call to return before continuing.",
    ].join("\n"),
    "{{SPAWN_DEEP_SEED_DISCOVERY_AGENT}}": [
      "```text",
      "deep_mode true: task(subagent_type: \"bob-deep-surface-discovery-agent\", description: \"Bob deep surface discovery\", prompt: \"DOMAIN=[domain] SESSION=~/hacker-bob-sessions/[domain]\")",
      "```",
      "Wait for the bob-deep-surface-discovery-agent task call to return before continuing.",
    ].join("\n"),
    "{{SPAWN_SURFACE_ROUTER_AGENT}}": [
      "```text",
      "task(subagent_type: \"bob-surface-router-agent\", description: \"Bob surface routing\", prompt: \"Domain: [domain]. Session: ~/hacker-bob-sessions/[domain]. Confirm attack_surface.json exists and has surfaces, then call bob_route_surfaces({ target_domain: '[domain]' }) and use .data. If routing fails or returns zero surfaces, report the error and stop. Otherwise return route count, capability-pack counts, and surface_routes_path.\")",
      "```",
      "Wait for the bob-surface-router-agent task call to return before continuing.",
    ].join("\n"),
    "{{SPAWN_EVALUATOR_AGENT}}": [
      "```text",
      "Evaluator waves run one assigned surface per task call. OpenCode resolves subagent_type \"bob-<evaluator_agent>\" against the committed subagent file, so the task prompt carries only the run header below — the full evaluator contract lives in that subagent file.",
      "",
      "For each assignment in result.data.assignments[], dispatch task(subagent_type: \"bob-[assignment.evaluator_agent]\", description: \"Bob evaluator w[wave]/a[agent]\", prompt: <run header below>) — subagent_type is one of: bob-evaluator-agent, or any per-pack evaluator in the smart-contract pack catalogue. Run header:",
      "Domain: [domain]; Wave: w[wave]; Agent: a[agent]; Surface: [surface_id]; Capability pack: [assignment.capability_pack]; Brief profile: [assignment.brief_profile]; Evaluator agent: [assignment.evaluator_agent]; Context budget: [assignment.context_budget]; Egress profile: [egress_profile]; Block internal hosts: [block_internal_hosts]; Handoff token: [only this agent's handoff_token from wave-start result.data.assignments]; Checkpoint mode: [normal|paranoid|yolo].",
      "First action inside the sub-session: call bob_read_assignment_brief({ target_domain: '[domain]', wave: 'w[wave]', agent: 'a[agent]', egress_profile: '[egress_profile]', block_internal_hosts: [block_internal_hosts] }) and use .data.run_context.context_budget plus .data.technique_packs.selected when present.",
      "",
      "OpenCode task calls block until the subagent returns: dispatch the wave's assignments as a sequence of task calls, one settling before the next is sent. Track the local mapping task call -> w[wave]/a[agent]/surface_id; Bob's aN value is authoritative. Each sub-session calls bob_write_wave_handoff exactly once then bob_finalize_agent_run for its surface; the wave is not merged in the dispatch turn. After every assigned surface for this wave has a finalized handoff, proceed to wave settlement — the MCP wave-merge barrier blocks until all assignments are finalized, so sequential dispatch yields the same merged frontier as parallel fan-out.",
      "```",
    ].join("\n"),
    "{{SPAWN_CHAIN_AGENT}}": [
      "```text",
      "task(subagent_type: \"bob-chain-builder\", description: \"Bob chain analysis\", prompt: \"Domain: [domain]. Egress profile: [egress_profile]. Block internal hosts: [block_internal_hosts]. Session: ~/hacker-bob-sessions/[domain]. Read findings, wave handoffs, auth profiles, HTTP audit, and prior chain attempts through MCP. Call bob_read_chain_attempts BEFORE proposing anything. For NEW chain proposals use the graph apparatus: bob_propose_hypothesis (new hypothesis nodes), bob_propose_transition (cross-stack pivots), bob_attach_contract (binding Contracts), bob_append_chain_node (chain-state-tree growth), bob_query_chain_tree (ancestry / verdict lookups). Test plausible chains with bob_http_scan as needed, passing egress_profile and block_internal_hosts on every scan, and write every outcome through bob_write_chain_attempt with the required steps array. Do NOT hand-write chain-attempts.jsonl or chain-tree.jsonl via Bash redirect or Write — the graph apparatus is authoritative. Do not read findings.md, chains.md, or markdown handoffs.\")",
      "```",
      "Wait for the bob-chain-builder task call to return before continuing.",
    ].join("\n"),
    "{{SPAWN_BRUTALIST_VERIFIER}}": [
      "```text",
      "task(subagent_type: \"bob-brutalist-verifier\", description: \"Bob round-1 verification\", prompt: \"Session: ~/hacker-bob-sessions/[domain]. Egress profile: [egress_profile]. Block internal hosts: [block_internal_hosts]. First call bob_read_verification_context({ target_domain }); for v2 use current_attempt_id and snapshot_hash on writes and verification_replay context, pass egress_profile and block_internal_hosts on replay HTTP tools, cover exactly the snapshot findings, then write only through bob_write_verification_round(round='brutalist').\")",
      "```",
      "Wait for the bob-brutalist-verifier task call to return before continuing; do not read the brutalist round in the same message that dispatched it.",
    ].join("\n"),
    "{{SPAWN_BALANCED_VERIFIER}}": [
      "```text",
      "task(subagent_type: \"bob-balanced-verifier\", description: \"Bob round-2 verification\", prompt: \"Session: ~/hacker-bob-sessions/[domain]. Egress profile: [egress_profile]. Block internal hosts: [block_internal_hosts]. First call bob_read_verification_context({ target_domain }). If v1, read brutalist and preserve the legacy cascade. If v2, do not read brutalist or adjudication; use current_attempt_id and snapshot_hash, pass verification_replay context plus egress_profile and block_internal_hosts on replay HTTP tools, cover exactly snapshot findings, then write only through bob_write_verification_round(round='balanced').\")",
      "```",
      "Wait for the bob-balanced-verifier task call to return before continuing; do not read the balanced round in the same message that dispatched it.",
    ].join("\n"),
    "{{SPAWN_FINAL_VERIFIER}}": [
      "```text",
      "task(subagent_type: \"bob-final-verifier\", description: \"Bob round-3 verification\", prompt: \"Session: ~/hacker-bob-sessions/[domain]. Egress profile: [egress_profile]. Block internal hosts: [block_internal_hosts]. First call bob_read_verification_context({ target_domain }). If v2, consume adjudication_context.adjudication_plan_hash from bob_read_verification_context, do not compute diffs, pass verification_replay context plus egress_profile and block_internal_hosts on replay HTTP tools, and write round='final' with verification_attempt_id, verification_snapshot_hash, and adjudication_plan_hash. If v1, read balanced and use the legacy final cascade.\")",
      "```",
      "Wait for the bob-final-verifier task call to return before continuing.",
    ].join("\n"),
    "{{SPAWN_EVIDENCE_AGENT}}": [
      "```text",
      "task(subagent_type: \"bob-evidence-agent\", description: \"Bob evidence packs\", prompt: \"Domain: [domain]. Egress profile: [egress_profile]. Block internal hosts: [block_internal_hosts]. Session: ~/hacker-bob-sessions/[domain]. Call bob_read_verification_context, bob_read_candidate_claims, bob_read_verification_round({ target_domain: '[domain]', round: 'final' }), bob_read_http_audit, and bob_list_auth_profiles; for v2 pass evidence_replay context plus egress_profile and block_internal_hosts on replay HTTP tools and rely on MCP to bind evidence to final_verification_hash; write only through bob_write_evidence_packs.\")",
      "```",
      "Wait for the bob-evidence-agent task call to return before continuing.",
    ].join("\n"),
    "{{SPAWN_GRADER_AGENT}}": [
      "```text",
      "task(subagent_type: \"bob-grader\", description: \"Bob grading\", prompt: \"Domain: [domain]. Session: ~/hacker-bob-sessions/[domain]. Call bob_read_candidate_claims, bob_read_chain_attempts, bob_read_verification_round({ target_domain: '[domain]', round: 'final' }), and bob_read_evidence_packs, score survivors, then write only through bob_write_grade_verdict.\")",
      "```",
      "Wait for the bob-grader task call to return before continuing.",
    ].join("\n"),
    "{{SPAWN_REPORTER_AGENT}}": [
      "```text",
      "task(subagent_type: \"bob-report-writer\", description: \"Bob report writing\", prompt: \"Domain: [domain]. Session: ~/hacker-bob-sessions/[domain]. Call bob_read_candidate_claims, bob_read_chain_attempts, bob_read_verification_round({ target_domain: '[domain]', round: 'final' }), bob_read_evidence_packs, and bob_read_grade_verdict, then compose and finalize through bob_compose_report and bob_finalize_report; do not Write report.md directly. For SUBMIT, include only confirmed chain evidence. For SKIP/no reportables, write a concise no-findings closeout with verification, chain-attempt, and blocker summary.\")",
      "```",
      "Wait for the bob-report-writer task call to return before continuing.",
    ].join("\n"),
  });
}

function applyOpencodeHostText(document) {
  return document
    .replace(/First, read the passive update cache if the helper is installed:\n```\n/g, "First, read the passive update cache if the helper is installed:\n```bash\n")
    .replace(/After resolving `target_domain`, call:\n```\n/g, "After resolving `target_domain`, call:\n```text\n")
    .replace(/Use host-normal agent permissions by default/g, "Use normal OpenCode agent permissions by default")
    .replace(/Evaluator waves MUST use the host's asynchronous\/background worker mechanism when available\./g, "Evaluator waves run as sequential `task(subagent_type: \"bob-<evaluator_agent>\")` calls; OpenCode task calls block until the subagent returns, so dispatch one assigned surface per task call and rely on the MCP wave-merge barrier for settlement.")
    .replace(/Use each assignment's `evaluator_agent` as the subagent type and its `handoff_token` only in its spawn prompt\./g, "Use `bob-<assignment.evaluator_agent>` as the task `subagent_type` and include only that assignment's `handoff_token` in its task prompt.")
    .replace(/Generic evaluator spawn template \(uses the routed `assignment\.evaluator_agent`; the brief itself carries chain-specific context\):/g, "Generic evaluator spawn template (dispatches `task(subagent_type: \"bob-<assignment.evaluator_agent>\")`; the brief itself carries chain-specific context):")
    .replace(/host stop hooks are only adapter guardrails/g, "OpenCode has no Bob stop hook, so MCP finalization is the only completion authority")
    .replace(/Claude Code enforces `maxTurns` as a turn budget, not a raw tool-call budget\./g, "The host may enforce turn budgets differently from raw tool-call budgets.")
    .replace(/wait for background completion notifications/g, "wait for each evaluator task call to return and its handoff to finalize")
    .replace(/Paste in the current agent session\./g, "Paste in the current OpenCode session.")
    .replace(/for Claude compatibility/g, "for host compatibility")
    .replace(/Claude transcript windows/g, "OpenCode session log windows")
    .replace(/Claude transcripts/g, "OpenCode session logs")
    .replace(/Claude transcript JSONL files/g, "OpenCode session log files")
    .replace(/Claude project JSONL files/g, "OpenCode session log files")
    .replace(/Do not use the `Task` tool by default\./g, "Do not spawn subagents by default.")
    .replace(/Do not use `Task`\./g, "Do not spawn subagents.")
    .replace(/Claude Code/g, "OpenCode")
    // OpenCode keeps native `/bob-*` slash commands, so normalize the `/bob:`
    // source spelling to the hyphenated command but do NOT rewrite to a
    // `/skill:` form (that is the Kimi/Codex behavior — those hosts lack a
    // command/skill split).
    .replace(/\/bob:evaluate/g, "/bob-evaluate")
    .replace(/\/bob:status/g, "/bob-status")
    .replace(/\/bob:debug/g, "/bob-debug")
    .replace(/\/bob:update/g, "/bob-update");
}

function replaceLaunchTemplates(document) {
  let next = document;
  for (const [placeholder, template] of Object.entries(opencodeLaunchTemplates())) {
    next = next.split(placeholder).join(template);
  }
  return next;
}

function opencodeOrchestratorPreamble() {
  return [
    "## OpenCode Agent Mapping",
    "- Bob named roles are committed OpenCode subagents under `.opencode/agents/bob-<role>.md`. Spawn each through the `task` tool — `task(subagent_type: \"bob-<role>\", description: \"<3-5 word label>\", prompt: \"<run-specific header>\")`. OpenCode loads that subagent file's contract as the worker's system prompt, so the task prompt only needs the run-specific header.",
    "- `@bob-<role>` mentions are the operator's manual invocation path in the OpenCode TUI only; literal `@bob-<role>` text in YOUR messages does NOT dispatch a sub-session. `task(subagent_type: ...)` is the only programmatic spawn seam, and each `subagent_type` resolves to the matching committed subagent file.",
    "- OpenCode task calls block until the subagent returns: evaluator waves run as a sequence of task calls, one settling before the next. Correctness is owned by the MCP wave-merge barrier (`bob_apply_wave_merge` blocks until every assignment has a finalized handoff), not host parallelism.",
    "- Bob `wN`, `aN`, `surface_id`, and `handoff_token` values are durable truth; OpenCode sub-session IDs and task descriptions are local execution metadata only.",
    "- If OpenCode does not surface Bob MCP tools yet, use tool discovery for `bob_*` tools before falling back to local artifact reads.",
    "",
  ].join("\n");
}

function renderOpencodeEvaluatorPackCatalogue() {
  const { smartContractCapabilityPacks } = require("../../mcp/lib/capability-packs.js");
  const packs = smartContractCapabilityPacks();
  const lines = packs.map((pack) =>
    `- \`capability_pack: "${pack.id}"\` (chain_family \`${pack.spawn.chain_family}\`) -> evaluator_agent \`${pack.evaluator_agent}\` (task subagent_type \`bob-${pack.evaluator_agent}\`). chain_id: ${pack.spawn.chain_id_description}. Workflow: ${pack.spawn.workflow_summary} CLI dependency: ${pack.spawn.cli_dependency}; blocked_harness_runs[] kind: ${pack.spawn.blocked_harness_kind_options}.`,
  );
  return [
    "Smart-contract spawn dispatch:",
    "- If `assignment.brief_profile === \"web\"` -> use the generic evaluator spawn template above; do not use the SC template below.",
    "- Otherwise -> use the canonical smart-contract template below and look up the matching catalogue line by `assignment.capability_pack`.",
    "",
    "Pack metadata is the source of truth in `mcp/lib/capability-packs.js`; adding a chain pack auto-extends the catalogue at next prompt regeneration.",
    "",
    "```text",
    "Dispatch task(subagent_type: \"bob-[assignment.evaluator_agent]\", description: \"Bob SC evaluator w[wave]/a[agent]\", prompt: <run header below>) — the routed evaluator subagent; its full contract lives in its .opencode/agents/ file. Run header:",
    "Domain: [domain]",
    "Wave: w[wave]",
    "Agent: a[agent]",
    "Handoff token: [only this agent's handoff_token from wave-start result.data.assignments]",
    "Capability pack: [assignment.capability_pack]. Brief profile: [assignment.brief_profile]. Evaluator agent: [assignment.evaluator_agent]. Context budget: [assignment.context_budget].",
    "First action: call bob_read_assignment_brief({ target_domain: '[domain]', wave: 'w[wave]', agent: 'a[agent]', egress_profile: '[egress_profile]', block_internal_hosts: [block_internal_hosts] }) and use .data, including run_context.context_budget.",
    "Confirm surface_type is smart_contract AND surface.chain_family matches the catalogue line's chain_family for [assignment.capability_pack]; surface.chain_id matches the catalogue line's chain_id description.",
    "Use bob_spec_status for trust_assumptions, invariants, known_issues, and severity_system metadata. Use rpc_pool.endpoints for non-MCP reads.",
    "Workflow: <copy verbatim from the catalogue line for [assignment.capability_pack]>.",
    "If <copy CLI dependency from the catalogue line> is not in PATH or all fork_attempts fail, set surface_status: partial and record blocked_harness_runs[] with kind: <copy from the catalogue line>.",
    "Checkpoint mode: [normal|paranoid|yolo].",
    "Final: call bob_write_wave_handoff exactly once with target_domain, wave, agent, surface_id, surface_status, handoff_token, summary, content, optional bypass_attempts, blocked_harness_runs, chain_notes, dead_ends, lead_surface_ids. Then call bob_finalize_agent_run. If finalization fails, fix the handoff and retry. After finalization succeeds, emit `BOB_AGENT_RUN_DONE {\"target_domain\":\"[domain]\",\"wave\":\"w[wave]\",\"agent\":\"a[agent]\",\"surface_id\":\"[surface_id]\"}`.",
    "Dispatch SC evaluators sequentially: send one task(subagent_type: \"bob-<evaluator_agent>\") call at a time and let it finalize its handoff before sending the next; the MCP wave-merge barrier settles the wave once every assignment has a finalized handoff.",
    "```",
    "",
    "Pack catalogue (lookup by `assignment.capability_pack`):",
    ...lines,
  ].join("\n");
}

function renderOpencodePromptBody(roleId, body, options = {}) {
  let document = body;
  if (roleId === "status") {
    document = document.replace(
      "{{STATUS_UPDATE_CACHE_COMMAND}}",
      'node -e "const update=require(\'./mcp/lib/update-check.js\'); console.log(JSON.stringify(update.readUpdateCache(process.cwd()) || null, null, 2));"',
    );
  }
  document = applyOpencodeHostText(document);
  document = replaceLaunchTemplates(document);
  document = substituteCapabilityPackVerifierTable(document);
  document = substituteHandoffFieldLimits(document);
  if (roleId === "orchestrator") {
    document = document.replace("## Hard Rules\n", `${opencodeOrchestratorPreamble()}## Hard Rules\n`);
    document += renderCapabilityPlaybookAppendix(options);
    if (document.includes(EVALUATOR_PACK_CATALOGUE_PLACEHOLDER)) {
      document = document.split(EVALUATOR_PACK_CATALOGUE_PLACEHOLDER).join(renderOpencodeEvaluatorPackCatalogue());
    }
  }
  return document;
}

function renderOpencodeRole(roleId, options = {}) {
  const spec = roleSpec(roleId);
  const body = renderOpencodePromptBody(roleId, roleBody(roleId, options), options);
  return `${renderFrontmatter(spec, roleId)}\n\n${body}`;
}

function updateOpencodeRoleFile(roleId, { check = false, root = DEFAULT_ROOT } = {}) {
  const filePath = opencodeRoleOutputPath(roleId, { root });
  const nextDocument = renderOpencodeRole(roleId, { root });
  const document = fs.existsSync(filePath) ? fs.readFileSync(filePath, "utf8") : null;
  if (document === nextDocument) return false;
  if (check) {
    throw new Error(`${path.relative(root, filePath)} is stale; run node scripts/generate-opencode-roles.js`);
  }
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, nextDocument, "utf8");
  return true;
}

function updateOpencodeRoleFiles({ check = false, root = DEFAULT_ROOT, roleIds = Object.keys(OPENCODE_ROLE_SPECS) } = {}) {
  let changed = false;
  for (const roleId of roleIds) {
    changed = updateOpencodeRoleFile(roleId, { check, root }) || changed;
  }
  return changed;
}

module.exports = {
  AGENTS_SOURCE_DIR,
  OPENCODE_ROLE_SPECS,
  applyOpencodeHostText,
  opencodeRoleOutputPath,
  renderFrontmatter,
  renderOpencodeEvaluatorPackCatalogue,
  renderOpencodePromptBody,
  renderOpencodeRole,
  roleBody,
  updateOpencodeRoleFile,
  updateOpencodeRoleFiles,
};
