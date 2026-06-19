"use strict";

const fs = require("fs");
const path = require("path");
const {
  mcpPermissionForTool,
} = require("../../adapters/claude/config.js");
const {
  mcpToolNamesForRole,
  roleDefinition,
} = require("../../mcp/lib/role-model.js");
const {
  substituteCapabilityPackVerifierTable,
  substituteClaudeEvaluatorPackCatalogue,
  substituteHandoffFieldLimits,
} = require("../../mcp/lib/capability-packs-rendering.js");
const {
  renderCapabilityPlaybookAppendix,
} = require("../../mcp/lib/capability-playbooks.js");
const { evaluatorRoleSpecs } = require("../../mcp/lib/capability-packs.js");
const { TOOL_REGISTRY } = require("../../mcp/lib/tool-registry.js");
const { parseSkillText } = require("./skill-parser.js");

// Y.8 Do step 0b — `@schema_ref` directive auto-injection. The
// generator scans each STATE block of the orchestrator source body
// after all other substitutions, identifies write-tool tokens that
// resolve to a real TOOL_REGISTRY entry, and appends one
// `<!-- @schema_ref: <tool> -->` HTML-comment marker per unique
// write tool at the END of the state block (right before the next
// H2 heading or EOF). This satisfies the Y-D7c structural
// containment heuristic ("a `bob_write_*` token's `@schema_ref` MUST
// appear in the same state-block") mechanically — operators do not
// hand-author the markers, the generator derives them from
// TOOL_REGISTRY. The check script
// `scripts/check-skill-protocol-coherence.js` consumes the resulting
// rendered SKILL.md and asserts the structural-containment predicate.
const REGISTERED_TOOL_NAMES = new Set(
  TOOL_REGISTRY.filter((tool) => !tool.alias_of).map((tool) => tool.name),
);

function injectSchemaRefDirectives(document, { filePath = "<orchestrator-render>" } = {}) {
  const parsed = parseSkillText(document, { filePath });
  const stateBlocks = parsed.blocks.filter((block) => block.kind === "state");
  if (stateBlocks.length === 0) return document;
  const lines = document.split(/\r?\n/);
  const insertions = []; // { lineIndex, lines: string[] }
  for (const block of stateBlocks) {
    const seen = new Set();
    const refs = [];
    for (const token of block.tokens.write_tools) {
      if (token.in_code_block) continue;
      if (!REGISTERED_TOOL_NAMES.has(token.token)) continue;
      if (seen.has(token.token)) continue;
      seen.add(token.token);
      refs.push(token.token);
    }
    if (refs.length === 0) continue;
    // Avoid double-injection on re-render: skip if any of the refs
    // already has an `@schema_ref` directive somewhere in the block.
    const existing = new Set(block.tokens.schema_refs.map((r) => r.token));
    const missing = refs.filter((ref) => !existing.has(ref));
    if (missing.length === 0) continue;
    // Insert at the line just past the block's last content line. The
    // parser stores 1-indexed `content_end_line` as the line index of
    // the NEXT block's header (or lines.length if EOF). We splice
    // BEFORE that index in 0-indexed terms.
    const insertAt = block.content_end_line;
    const markerLines = missing.map((ref) => `<!-- @schema_ref: ${ref} -->`);
    // Add a blank-line separator before the markers when the previous
    // line isn't already blank, so the rendered SKILL.md stays
    // readable.
    insertions.push({ lineIndex: insertAt, lines: markerLines });
  }
  if (insertions.length === 0) return document;
  // Apply insertions from highest index to lowest so earlier indices
  // remain stable.
  insertions.sort((a, b) => b.lineIndex - a.lineIndex);
  for (const insertion of insertions) {
    const idx = insertion.lineIndex;
    const previousLine = idx > 0 ? lines[idx - 1] : "";
    const prefix = previousLine === "" ? [] : [""];
    const suffix = idx < lines.length && lines[idx] !== "" ? [""] : [];
    lines.splice(idx, 0, ...prefix, ...insertion.lines, ...suffix);
  }
  return lines.join("\n");
}

const DEFAULT_ROOT = path.join(__dirname, "..", "..");

const SUPPORTED_CLAUDE_AGENT_COLORS = Object.freeze([
  "blue",
  "green",
  "yellow",
  "magenta",
  "cyan",
  "purple",
  "orange",
  "pink",
  "red",
]);

const CLAUDE_LAUNCH_TEMPLATES = Object.freeze({
  "{{SPAWN_SEED_DISCOVERY_AGENT}}": [
    "```text",
    "deep_mode false: Agent(subagent_type: \"surface-discovery-agent\", name: \"surface-discovery\", prompt: \"DOMAIN=[domain] SESSION=~/hacker-bob-sessions/[domain]\")",
    "```",
  ].join("\n"),
  "{{SPAWN_DEEP_SEED_DISCOVERY_AGENT}}": [
    "```text",
    "deep_mode true: Agent(subagent_type: \"deep-surface-discovery-agent\", name: \"deep-surface-discovery\", prompt: \"DOMAIN=[domain] SESSION=~/hacker-bob-sessions/[domain]\")",
    "```",
  ].join("\n"),
  "{{SPAWN_SURFACE_ROUTER_AGENT}}": [
    "```text",
    "Agent(subagent_type: \"surface-router-agent\", name: \"surface-router\", prompt: \"Domain: [domain]. Session: ~/hacker-bob-sessions/[domain]. Confirm attack_surface.json exists and has surfaces, then call bob_route_surfaces({ target_domain: '[domain]' }) and use .data. If routing fails or returns zero surfaces, report the error and stop. Otherwise return route count, capability-pack counts, and surface_routes_path.\")",
    "```",
  ].join("\n"),
  "{{SPAWN_EVALUATOR_AGENT}}": [
    "```text",
    "Agent(subagent_type: \"[assignment.evaluator_agent]\", name: \"evaluator-w[wave]-a[agent]\", run_in_background: true, prompt: \"",
    "Domain: [domain]",
    "Wave: w[wave]",
    "Agent: a[agent]",
    "Handoff token: [only this agent's handoff_token from wave-start result.data.assignments]",
    "Capability pack: [assignment.capability_pack]. Brief profile: [assignment.brief_profile]. Evaluator agent: [assignment.evaluator_agent]. Context budget: [assignment.context_budget].",
    "First action: call bob_read_assignment_brief({ target_domain: '[domain]', wave: 'w[wave]', agent: 'a[agent]', egress_profile: '[egress_profile]', block_internal_hosts: [block_internal_hosts] }) and use .data, including run_context.context_budget and technique_packs.selected.",
    "Use surface_type, bug_class_hints, high_value_flows, evidence, surface_limits, coverage_summary, traffic_summary, audit_summary, circuit_breaker_summary, ranking_summary, intel_hints, static_scan_hints, and technique_packs.selected as prioritization inputs for this one assigned surface.",
    "Call bob_read_technique_pack(mode=\"full\") only with target_domain/wave/agent/surface_id for relevant selected summaries, and bob_log_technique_attempt for selections, skips, attempts, and outcomes. Before finalizing, ensure one completion-status technique attempt is logged for this surface.",
    "Egress profile: [egress_profile]. Block internal hosts: [block_internal_hosts]. Pass these exact values as egress_profile and block_internal_hosts on every bob_http_scan call. If strict internal-host blocking conflicts with a proxy-backed egress profile, record the blocked prerequisite instead of retrying.",
    "Prefer traffic_summary endpoints, replay through bob_http_scan with target_domain, egress_profile, and block_internal_hosts, log bob_log_coverage after meaningful tests, and log before switching away from promising traffic-derived endpoints.",
    "New token-contract scans must use bob_import_static_artifact then bob_static_scan; never scan arbitrary paths.",
    "Checkpoint mode: [normal|paranoid|yolo].",
    "Auth: call bob_list_auth_profiles, use attacker profile for primary testing, victim profile for IDOR/access-control confirmation, legacy auth as a single profile, or unauthenticated testing if auth is absent.",
    "Geofence rule: after 3+ consecutive INTERNAL_ERROR, timeout, connection reset, or network_unreachable_target results on target-owned hosts, log blocked/unreachable coverage and dead-end context, write or prepare the handoff, and request orchestrator egress rotation instead of retrying.",
    "Final: if no completion-status technique attempt has been logged, call bob_log_technique_attempt first. Then call bob_write_wave_handoff exactly once with target_domain, wave, agent, surface_id, surface_status, handoff_token, summary, optional chain_notes, content, and any dead_ends / waf_blocked_endpoints / lead_surface_ids. Then call bob_finalize_agent_run with target_domain, wave, agent, and surface_id. If finalization fails, fix the structured handoff or missing technique-attempt log and retry finalization. After finalization succeeds, emit `BOB_AGENT_RUN_DONE {\"target_domain\":\"[domain]\",\"wave\":\"w[wave]\",\"agent\":\"a[agent]\",\"surface_id\":\"[surface_id]\"}` for Claude compatibility.",
    "\")",
    "```",
  ].join("\n"),
  // Smart-contract spawn bodies are rendered from the capability pack
  // manifest's `spawn` block — see `mcp/lib/capability-packs-rendering.js`.
  // Adding a new chain pack auto-extends the orchestrator catalogue at next
  // prompt regeneration; no per-pack template lives inline here anymore.
  "{{SPAWN_CHAIN_AGENT}}": [
    "```",
    "Agent(subagent_type: \"chain-builder\", name: \"chain\", prompt: \"Domain: [domain]. Egress profile: [egress_profile]. Block internal hosts: [block_internal_hosts]. Session: ~/hacker-bob-sessions/[domain]. Read findings, wave handoffs, auth profiles, HTTP audit, and prior chain attempts through MCP. Call bob_read_chain_attempts BEFORE proposing anything. For NEW chain proposals use the graph apparatus: bob_propose_hypothesis (new hypothesis nodes), bob_propose_transition (cross-stack pivots), bob_attach_contract (binding Contracts), bob_append_chain_node (chain-state-tree growth), bob_query_chain_tree (ancestry / verdict lookups). Test plausible chains with bob_http_scan as needed, passing egress_profile and block_internal_hosts on every scan, and write every outcome through bob_write_chain_attempt with the required steps array. Do NOT hand-write chain-attempts.jsonl or chain-tree.jsonl via Bash redirect or Write — the graph apparatus is authoritative. Do not read findings.md, chains.md, or markdown handoffs.\")",
    "```",
  ].join("\n"),
  "{{SPAWN_BRUTALIST_VERIFIER}}": [
    "```",
    "Agent(subagent_type: \"brutalist-verifier\", name: \"brutalist\", prompt: \"Session: ~/hacker-bob-sessions/[domain]. Egress profile: [egress_profile]. Block internal hosts: [block_internal_hosts]. First call bob_read_verification_context({ target_domain }); for v2 use current_attempt_id and snapshot_hash on writes and verification_replay context, pass egress_profile and block_internal_hosts on replay HTTP tools, cover exactly the snapshot findings, then write only through bob_write_verification_round(round='brutalist').\")",
    "```",
  ].join("\n"),
  "{{SPAWN_BALANCED_VERIFIER}}": [
    "```",
    "Agent(subagent_type: \"balanced-verifier\", name: \"balanced\", prompt: \"Session: ~/hacker-bob-sessions/[domain]. Egress profile: [egress_profile]. Block internal hosts: [block_internal_hosts]. First call bob_read_verification_context({ target_domain }). If v1, read brutalist and preserve the legacy cascade. If v2, do not read brutalist or adjudication; use current_attempt_id and snapshot_hash, pass verification_replay context plus egress_profile and block_internal_hosts on replay HTTP tools, cover exactly snapshot findings, then write only through bob_write_verification_round(round='balanced').\")",
    "```",
  ].join("\n"),
  "{{SPAWN_FINAL_VERIFIER}}": [
    "```",
    "Agent(subagent_type: \"final-verifier\", name: \"final-verify\", prompt: \"Session: ~/hacker-bob-sessions/[domain]. Egress profile: [egress_profile]. Block internal hosts: [block_internal_hosts]. First call bob_read_verification_context({ target_domain }). If v2, consume adjudication_context.adjudication_plan_hash from bob_read_verification_context, do not compute diffs, pass verification_replay context plus egress_profile and block_internal_hosts on replay HTTP tools, and write round='final' with verification_attempt_id, verification_snapshot_hash, and adjudication_plan_hash. If v1, read balanced and use the legacy final cascade.\")",
    "```",
  ].join("\n"),
  "{{SPAWN_EVIDENCE_AGENT}}": [
    "```",
    "Agent(subagent_type: \"evidence-agent\", name: \"evidence\", prompt: \"Domain: [domain]. Egress profile: [egress_profile]. Block internal hosts: [block_internal_hosts]. Session: ~/hacker-bob-sessions/[domain]. Call bob_read_verification_context, bob_read_candidate_claims, bob_read_verification_round({ target_domain: '[domain]', round: 'final' }), bob_read_http_audit, and bob_list_auth_profiles; for v2 pass evidence_replay context plus egress_profile and block_internal_hosts on replay HTTP tools and rely on MCP to bind evidence to final_verification_hash; write only through bob_write_evidence_packs.\")",
    "```",
  ].join("\n"),
  "{{SPAWN_GRADER_AGENT}}": [
    "```",
    "Agent(subagent_type: \"grader\", name: \"grader\", prompt: \"Domain: [domain]. Session: ~/hacker-bob-sessions/[domain]. Call bob_read_candidate_claims, bob_read_chain_attempts, bob_read_verification_round({ target_domain: '[domain]', round: 'final' }), and bob_read_evidence_packs, score survivors, then write only through bob_write_grade_verdict.\")",
    "```",
  ].join("\n"),
  "{{SPAWN_REPORTER_AGENT}}": [
    "```",
    "Agent(subagent_type: \"report-writer\", name: \"reporter\", prompt: \"Domain: [domain]. Session: ~/hacker-bob-sessions/[domain]. Call bob_read_candidate_claims, bob_read_chain_attempts, bob_read_verification_round({ target_domain: '[domain]', round: 'final' }), bob_read_evidence_packs, and bob_read_grade_verdict, then write the canonical ~/hacker-bob-sessions/[domain]/report.md. For SUBMIT, include only confirmed chain evidence. For SKIP/no reportables, write a concise no-findings closeout with verification, chain-attempt, and blocker summary.\")",
    "```",
  ].join("\n"),
});

const CLAUDE_ROLE_SPECS = Object.freeze({
  orchestrator: Object.freeze({
    role_id: "orchestrator",
    kind: "skill",
    // Skill directory is intentionally distinct from the /bob-evaluate command
    // slash name so Claude Code's picker does not register two entries under
    // the same /bob-evaluate label. The command file owns the operator-facing
    // /bob-evaluate slot; this skill is a callable subroutine the command
    // invokes via the Skill tool.
    output_path: path.join(".claude", "skills", "bob-evaluate-runner", "SKILL.md"),
    name: "bob-evaluate-runner",
    description: "Hacker Bob orchestrator runtime — invoked by /bob-evaluate. Do not call directly.",
    disable_model_invocation: true,
    argument_hint: "[target-url | resume <domain> [force-merge]] [--no-auth] [--normal|--paranoid|--yolo] [--deep] [--egress <profile>] [--block-internal-hosts|--allow-internal-hosts]",
    local_tools: Object.freeze(["Task", "Read"]),
  }),
  status: Object.freeze({
    role_id: "status",
    kind: "skill",
    output_path: path.join(".claude", "skills", "bob-status", "SKILL.md"),
    name: "bob-status",
    description: "Read Hacker Bob session state, wave status, findings, verification, and grade summaries.",
    disable_model_invocation: true,
    argument_hint: "[--last | <target_domain>]",
    local_tools: Object.freeze([
      "Read",
      "Glob",
      "Bash(find *)",
      "Bash(ls *)",
      "Bash(node *)",
      "Bash(stat *)",
      "Bash(test *)",
    ]),
  }),
  debug: Object.freeze({
    role_id: "debug",
    kind: "skill",
    output_path: path.join(".claude", "skills", "bob-debug", "SKILL.md"),
    name: "bob-debug",
    description: "Debug a completed or stuck Hacker Bob session — pipeline quality, drift, failures, improvements.",
    disable_model_invocation: true,
    argument_hint: "[--last | <target_domain>] [--deep]",
    local_tools: Object.freeze([
      "Read",
      "Glob",
      "Grep",
      "Bash(find *)",
      "Bash(ls *)",
      "Bash(stat *)",
      "Bash(test *)",
    ]),
  }),
  "surface-discovery": Object.freeze({
    role_id: "surface-discovery",
    kind: "agent",
    output_path: path.join(".claude", "agents", "surface-discovery-agent.md"),
    name: "surface-discovery-agent",
    description: "Runs bounded normal surface-discovery \u2014 subdomain enum, live hosts, archived/crawled URLs, nuclei, JS/JWT extraction \u2014 and produces attack_surface.json",
    model: "opus",
    color: "cyan",
    local_tools: Object.freeze(["Bash", "Read", "Write", "Glob", "Grep"]),
  }),
  "deep-surface-discovery": Object.freeze({
    role_id: "deep-surface-discovery",
    kind: "agent",
    output_path: path.join(".claude", "agents", "deep-surface-discovery-agent.md"),
    name: "deep-surface-discovery-agent",
    description: "Runs bounded deep surface-discovery and produces compact attack_surface, deep-summary, and surface lead artifacts",
    model: "opus",
    color: "cyan",
    local_tools: Object.freeze(["Bash", "Read", "Write", "Glob", "Grep"]),
  }),
  "surface-router": Object.freeze({
    role_id: "surface-router",
    kind: "agent",
    output_path: path.join(".claude", "agents", "surface-router-agent.md"),
    name: "surface-router-agent",
    description: "Calls the MCP surface router after surface-discovery and reports the capability-pack summary",
    model: "sonnet",
    color: "blue",
    mcp_server: true,
    local_tools: Object.freeze(["Read"]),
  }),
  evaluator: Object.freeze({
    role_id: "evaluator",
    kind: "agent",
    output_path: path.join(".claude", "agents", "evaluator-agent.md"),
    name: "evaluator-agent",
    description: "Tests one attack surface for vulnerabilities \u2014 spawned per-surface with injected context from the orchestrator",
    model: "opus",
    color: "yellow",
    max_turns: 99999,
    background: true,
    mcp_server: true,
    local_tools: Object.freeze(["Bash", "Read", "Grep", "Glob"]),
  }),
  // Per-chain evaluator Claude role specs derived from EVALUATOR_ROLES. Multiple
  // capability packs that share a role_id (e.g. Aptos and Sui both route to
  // the Move evaluator) collapse to a single Claude agent \u2014 matching
  // role-model.js + codex/role-specs.js. Adding a new evaluator role
  // auto-extends this object without editing this file.
  ...Object.fromEntries(
    evaluatorRoleSpecs().map((role) => [
      role.role_id,
      Object.freeze({
        role_id: role.role_id,
        kind: "agent",
        output_path: path.join(".claude", "agents", `${role.name}.md`),
        name: role.name,
        description: role.description,
        model: "opus",
        color: role.color,
        max_turns: 99999,
        background: true,
        mcp_server: true,
        local_tools: Object.freeze(["Bash", "Read", "Write", "Grep", "Glob"]),
      }),
    ]),
  ),
  // Plane X Cycle X.10 — generic TaskGraph evaluator shell. Union of the
  // shared evaluator + web + every chain-specific evaluator bundle plus
  // bob_resolve_body (already in evaluator-shared) and the dispatch tools
  // bob_prepare_node + bob_finalize_node (read-only of own context per
  // X.10 step 1; the actual dispatch authority is the orchestrator). The
  // honest X-P7 framing lives in prompts/roles/evaluator-spawn.md.
  "evaluator-spawn": Object.freeze({
    role_id: "evaluator-spawn",
    kind: "agent",
    output_path: path.join(".claude", "agents", "evaluator-spawn.md"),
    name: "evaluator-spawn",
    description: "Generic TaskGraph evaluator shell — executes Transition and Hypothesis nodes the orchestrator dispatched via bob_prepare_node. Carries the union of evaluator-family tools; the dispatched brief's allowed_tools_for_node[] is the per-spawn constraint enforced by the X.6 mechanical verifier on bob_finalize_node.",
    model: "opus",
    color: "yellow",
    max_turns: 200,
    background: true,
    mcp_server: true,
    local_tools: Object.freeze(["Bash", "Read", "Write", "Grep", "Glob"]),
  }),
  chain: Object.freeze({
    role_id: "chain",
    kind: "agent",
    output_path: path.join(".claude", "agents", "chain-builder.md"),
    name: "chain-builder",
    description: "Analyzes proven findings for credible impact chains that elevate severity",
    model: "opus",
    color: "purple",
    mcp_server: true,
    // Y.3 Stage d (Y-P13 enforcement at source) — Write removed; chains.md
    // is MCP-rendered via bob_write_chain_rollup. The agent returns the
    // structured rollup in its handoff; the orchestrator calls
    // bob_write_chain_rollup on receipt. Y.8 adds a CI guard that fails the
    // build if Write/Edit reappears in this frontmatter.
    local_tools: Object.freeze([]),
  }),
  "brutalist-verifier": Object.freeze({
    role_id: "brutalist-verifier",
    kind: "agent",
    output_path: path.join(".claude", "agents", "brutalist-verifier.md"),
    name: "brutalist-verifier",
    description: "Round 1 verification \u2014 re-runs PoCs with maximum skepticism, checks severity inflation, filters non-bugs",
    model: "sonnet",
    color: "red",
    mcp_server: true,
    local_tools: Object.freeze(["Bash", "Read"]),
    // External @brutalist/mcp tools for the adversarial roast layer.
    // roast_cli_debate is intentionally excluded: the debate orchestrator
    // spawns multiple CLI agents and is too time-expensive for a per-finding
    // loop. Single-shot roast is the correct primitive here.
    extra_mcp_tools: Object.freeze([
      "mcp__brutalist__roast",
      "mcp__brutalist__brutalist_discover",
      "mcp__brutalist__cli_agent_roster",
    ]),
    // Brutalist MCP is optional \u2014 registered for availability but not gated.
    // Graceful fallback when missing is the brutalist-verifier prompt's job.
    extra_mcp_servers: Object.freeze(["brutalist"]),
  }),
  "balanced-verifier": Object.freeze({
    role_id: "balanced-verifier",
    kind: "agent",
    output_path: path.join(".claude", "agents", "balanced-verifier.md"),
    name: "balanced-verifier",
    description: "Round 2 verification \u2014 reviews brutalist decisions for false negatives and severity over-corrections",
    model: "opus",
    color: "blue",
    mcp_server: true,
    local_tools: Object.freeze(["Bash", "Read"]),
  }),
  "final-verifier": Object.freeze({
    role_id: "final-verifier",
    kind: "agent",
    output_path: path.join(".claude", "agents", "final-verifier.md"),
    name: "final-verifier",
    description: "Round 3 verification \u2014 re-runs only REPORTABLE findings with fresh requests as final confirmation",
    model: "sonnet",
    color: "green",
    mcp_server: true,
    local_tools: Object.freeze(["Bash"]),
  }),
  evidence: Object.freeze({
    role_id: "evidence",
    kind: "agent",
    output_path: path.join(".claude", "agents", "evidence-agent.md"),
    name: "evidence-agent",
    description: "Collects bounded pre-grade evidence packs for final reportable findings (HTTP via bob_http_scan; SC via family runners)",
    model: "sonnet",
    color: "cyan",
    mcp_server: true,
    local_tools: Object.freeze([]),
  }),
  grader: Object.freeze({
    role_id: "grader",
    kind: "agent",
    output_path: path.join(".claude", "agents", "grader.md"),
    name: "grader",
    description: "Scores verified findings on 5 axes and issues SUBMIT/HOLD/SKIP verdict",
    model: "sonnet",
    color: "orange",
    mcp_server: true,
    local_tools: Object.freeze([]),
  }),
  reporter: Object.freeze({
    role_id: "reporter",
    kind: "agent",
    output_path: path.join(".claude", "agents", "report-writer.md"),
    name: "report-writer",
    description: "Generates submission-ready bug bounty report from verified and graded findings",
    model: "sonnet",
    color: "green",
    mcp_server: true,
    // Y.3 Stage d (Y-P13 enforcement at source) — Write removed; report.md
    // is MCP-rendered via bob_compose_report (with structured sections +
    // bounded narrative caps + provenance enforcement). Read remains so the
    // agent can ingest MCP-rendered chains.md when composing the report.
    // Y.8 adds a CI guard that fails the build if Write/Edit reappears here.
    local_tools: Object.freeze(["Read"]),
  }),
});

function uniqueStrings(values) {
  return Array.from(new Set(values.filter((value) => typeof value === "string" && value.trim())));
}

function claudeMcpToolsForRole(roleId) {
  return mcpToolNamesForRole(roleId).map(mcpPermissionForTool);
}

function claudeAllowedToolsForRole(roleId) {
  const spec = CLAUDE_ROLE_SPECS[roleId];
  if (!spec) throw new Error(`Missing Claude role spec for ${roleId}`);
  return uniqueStrings([
    ...(spec.local_tools || []),
    ...claudeMcpToolsForRole(roleId),
    ...(spec.extra_mcp_tools || []),
  ]);
}

function renderSkillFrontmatter(spec) {
  if (!spec.description) {
    throw new Error(`Claude skill ${spec.name} is missing a description; Claude Code's slash-command picker falls back to the body lede otherwise.`);
  }
  const allowedTools = claudeAllowedToolsForRole(spec.role_id);
  return [
    "---",
    `name: ${spec.name}`,
    `description: ${spec.description}`,
    `disable-model-invocation: ${spec.disable_model_invocation ? "true" : "false"}`,
    `argument-hint: ${JSON.stringify(spec.argument_hint)}`,
    "allowed-tools:",
    ...allowedTools.map((tool) => `  - ${tool}`),
    "---",
  ].join("\n");
}

function renderAgentFrontmatter(spec) {
  const lines = [
    "---",
    `name: ${spec.name}`,
    `description: ${spec.description}`,
    `tools: ${claudeAllowedToolsForRole(spec.role_id).join(", ")}`,
    `model: ${spec.model}`,
    `color: ${spec.color}`,
  ];
  if (spec.max_turns) lines.push(`maxTurns: ${spec.max_turns}`);
  if (spec.background) lines.push("background: true");
  if (spec.mcp_server) {
    const mcpServers = uniqueStrings(["hacker-bob", ...(spec.extra_mcp_servers || [])]);
    lines.push("mcpServers:");
    for (const server of mcpServers) lines.push(`  - ${server}`);
    // requiredMcpServers stays at hacker-bob only — extra servers are optional
    // (graceful fallback). Bumping a server here makes the agent fail to spawn
    // when the server is missing, which we explicitly do not want for brutalist.
    lines.push("requiredMcpServers:", "  - hacker-bob");
  }
  lines.push("---");
  return lines.join("\n");
}

function roleBody(roleId, { root = DEFAULT_ROOT } = {}) {
  const role = roleDefinition(roleId);
  const body = fs.readFileSync(path.join(root, role.prompt_body), "utf8").replace(/^\n+/, "");
  return renderClaudePromptBody(roleId, body, { root });
}

function renderClaudePromptBody(roleId, body, { root = DEFAULT_ROOT } = {}) {
  let document = body;
  if (roleId === "status") {
    document = document.replace(
      "{{STATUS_UPDATE_CACHE_COMMAND}}",
      'node "${CLAUDE_PROJECT_DIR:-$PWD}/.claude/hooks/bob-update.js" status "${CLAUDE_PROJECT_DIR:-$PWD}" --json',
    );
  }
  document = document
    .replace(/Use host-normal agent permissions by default/g, "Use normal Agent permissions by default")
    .replace(/Evaluator waves MUST use the host's asynchronous\/background worker mechanism when available\./g, "Evaluator waves MUST use `run_in_background: true`.")
    .replace(/host stop hooks are only adapter guardrails/g, "Claude `SubagentStop` is only an adapter guardrail")
    .replace(/Paste in the current agent session\./g, "Paste in Claude Code.");
  for (const [placeholder, template] of Object.entries(CLAUDE_LAUNCH_TEMPLATES)) {
    document = document.split(placeholder).join(template);
  }
  // Lazily-rendered, registry-driven placeholders. Substitution lives in
  // mcp/lib/capability-packs-rendering.js so the Codex renderer consumes
  // the same logic. Adding a pack to capability-packs.js updates every
  // consumer prompt at next regeneration.
  document = substituteCapabilityPackVerifierTable(document);
  document = substituteClaudeEvaluatorPackCatalogue(document);
  document = substituteHandoffFieldLimits(document);
  if (roleId === "orchestrator") {
    document += renderCapabilityPlaybookAppendix({ root });
  }
  document = document
    .replace(/\/bob:evaluate/g, "/bob-evaluate")
    .replace(/\/bob:status/g, "/bob-status")
    .replace(/\/bob:debug/g, "/bob-debug")
    .replace(/\/bob:update/g, "/bob-update");
  // Y.8 Do step 0b — inject auto-derived `@schema_ref` directives
  // into every state block of skills that carry state-block dispatch
  // text (orchestrator). Agent prompts and helper skills (status,
  // debug) don't carry STATE: blocks so the injector is a no-op for
  // them, but we run it unconditionally so any future role that
  // adopts state blocks picks up the same coherence machinery.
  document = injectSchemaRefDirectives(document, { filePath: `<render:${roleId}>` });
  return document;
}

function renderClaudeRole(roleId, options = {}) {
  const spec = CLAUDE_ROLE_SPECS[roleId];
  if (!spec) throw new Error(`Missing Claude role spec for ${roleId}`);
  const frontmatter = spec.kind === "skill"
    ? renderSkillFrontmatter(spec)
    : renderAgentFrontmatter(spec);
  const separator = spec.kind === "agent" ? "\n\n" : "\n";
  return `${frontmatter}${separator}${roleBody(roleId, options)}`;
}

function claudeRoleOutputPath(roleId, { root = DEFAULT_ROOT } = {}) {
  const spec = CLAUDE_ROLE_SPECS[roleId];
  if (!spec) throw new Error(`Missing Claude role spec for ${roleId}`);
  return path.join(root, spec.output_path);
}

function updateClaudeRoleFile(roleId, { check = false, root = DEFAULT_ROOT } = {}) {
  const filePath = claudeRoleOutputPath(roleId, { root });
  const document = fs.existsSync(filePath) ? fs.readFileSync(filePath, "utf8") : null;
  const nextDocument = renderClaudeRole(roleId, { root });
  if (document === nextDocument) return false;
  if (check) {
    throw new Error(`${path.relative(root, filePath)} is stale; run node scripts/generate-claude-roles.js`);
  }
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, nextDocument, "utf8");
  return true;
}

function updateClaudeRoleFiles({ check = false, root = DEFAULT_ROOT, roleIds = Object.keys(CLAUDE_ROLE_SPECS) } = {}) {
  let changed = false;
  for (const roleId of roleIds) {
    changed = updateClaudeRoleFile(roleId, { check, root }) || changed;
  }
  return changed;
}

module.exports = {
  CLAUDE_ROLE_SPECS,
  SUPPORTED_CLAUDE_AGENT_COLORS,
  claudeAllowedToolsForRole,
  claudeMcpToolsForRole,
  claudeRoleOutputPath,
  renderClaudePromptBody,
  renderClaudeRole,
  updateClaudeRoleFile,
  updateClaudeRoleFiles,
};
