"use strict";

const fs = require("fs");
const path = require("path");
const {
  roleDefinition,
} = require("../../mcp/lib/role-model.js");
const {
  KIMI_SKILL_SPECS,
} = require("../../adapters/kimi/config.js");
const {
  substituteCapabilityPackVerifierTable,
  substituteHandoffFieldLimits,
} = require("../../mcp/lib/capability-packs-rendering.js");
const {
  renderCapabilityPlaybookAppendix,
} = require("../../mcp/lib/capability-playbooks.js");
const { evaluatorRoleSpecs } = require("../../mcp/lib/capability-packs.js");

const DEFAULT_ROOT = path.join(__dirname, "..", "..");

// Cross-cutting Kimi worker contracts (surface-discovery/router/chain/verifier/
// evidence/grade/report). Per-chain evaluator contracts are appended from
// evaluatorRoleSpecs() so adding a chain pack auto-extends this list without
// editing this file. Role IDs must match mcp/lib/role-model.js exactly.
const KIMI_CROSS_CUTTING_ROLE_IDS = Object.freeze([
  "surface-discovery",
  "deep-surface-discovery",
  "surface-router",
  "evaluator",
  "chain",
  "brutalist-verifier",
  "balanced-verifier",
  "final-verifier",
  "evidence",
  "grader",
  "reporter",
]);
const KIMI_WORKER_CONTRACT_ROLE_IDS = Object.freeze([
  ...KIMI_CROSS_CUTTING_ROLE_IDS.slice(0, 4),
  ...evaluatorRoleSpecs().map((role) => role.role_id),
  // Plane X Cycle X.10 — generic TaskGraph evaluator shell appended after the
  // per-chain evaluator contracts so the appendix groups all evaluator family
  // contracts together before the cross-cutting roles (mirrors Codex).
  "evaluator-spawn",
  ...KIMI_CROSS_CUTTING_ROLE_IDS.slice(4),
]);

function renderFrontmatter(spec) {
  return [
    "---",
    `name: ${spec.name}`,
    `description: ${spec.description}`,
    `type: ${spec.type || "standard"}`,
    "---",
  ].join("\n");
}

function roleBody(roleId, { root = DEFAULT_ROOT } = {}) {
  const role = roleDefinition(roleId);
  return fs.readFileSync(path.join(root, role.prompt_body), "utf8").replace(/^\n+/, "");
}

function workerLabel(roleId) {
  return `Bob ${roleId}`;
}

function kimiLaunchTemplates() {
  return Object.freeze({
    "{{SPAWN_SEED_DISCOVERY_AGENT}}": [
      "```text",
      `Agent(subagent_type="coder", prompt: "Bob role: surface-discovery-agent. DOMAIN=[domain] SESSION=~/hacker-bob-sessions/[domain]. Run bounded normal surface discovery — subdomain enum, live hosts, archived/crawled URLs, nuclei, JS/JWT extraction — and produce attack_surface.json. Use Bash, Read, Write, Glob, Grep. Emit BOB_AGENT_RUN_DONE when finished.")`,
      "```",
    ].join("\n"),
    "{{SPAWN_DEEP_SEED_DISCOVERY_AGENT}}": [
      "```text",
      `Agent(subagent_type="coder", prompt: "Bob role: deep-surface-discovery-agent. DOMAIN=[domain] SESSION=~/hacker-bob-sessions/[domain]. Run bounded deep surface discovery and produce compact attack_surface, deep-summary, and surface lead artifacts. Use Bash, Read, Write, Glob, Grep. Emit BOB_AGENT_RUN_DONE when finished.")`,
      "```",
    ].join("\n"),
    "{{SPAWN_SURFACE_ROUTER_AGENT}}": [
      "```text",
      `Agent(subagent_type="coder", prompt: "Bob role: surface-router-agent. Domain: [domain]. Session: ~/hacker-bob-sessions/[domain]. Confirm attack_surface.json exists and has surfaces, then call bob_route_surfaces({ target_domain: '[domain]' }) and use .data. If routing fails or returns zero surfaces, report the error and stop. Otherwise return route count, capability-pack counts, and surface_routes_path. Emit BOB_AGENT_RUN_DONE when finished.")`,
      "```",
    ].join("\n"),
    "{{SPAWN_EVALUATOR_AGENT}}": [
      "```text",
      `For each assignment, spawn an Agent(subagent_type="coder") for the evaluator family chosen by the MCP capability router (assignment.evaluator_agent from wave-start result.data.assignments[] — one of evaluator-agent or any of the per-pack evaluators listed in the smart-contract pack catalogue: ${evaluatorRoleSpecs().map((role) => role.name).join(", ")}).`,
      "- prompt: include the compact run header below plus the full contract for assignment.evaluator_agent from Kimi Worker Role Contracts.",
      "- Header fields: Domain: [domain]; Wave: w[wave]; Agent: a[agent]; Surface: [surface_id]; Capability pack: [assignment.capability_pack]; Brief profile: [assignment.brief_profile]; Evaluator agent: [assignment.evaluator_agent]; Context budget: [assignment.context_budget]; Egress profile: [egress_profile]; Block internal hosts: [block_internal_hosts]; Handoff token: [only this agent's handoff_token from wave-start result.data.assignments]; Checkpoint mode: [normal|paranoid|yolo].",
      "- First action inside the worker: call bob_read_assignment_brief({ target_domain: '[domain]', wave: 'w[wave]', agent: 'a[agent]', egress_profile: '[egress_profile]', block_internal_hosts: [block_internal_hosts] }) and use .data.run_context.context_budget plus .data.technique_packs.selected when present.",
      "- For web evaluators, call bob_read_technique_pack(mode=\"full\") only with target_domain/wave/agent/surface_id for relevant selected summaries, and bob_log_technique_attempt for selections, skips, attempts, and outcomes. Before finalizing, ensure one completion-status technique attempt is logged for this surface.",
      "- Track the local mapping host_agent_id -> w[wave]/a[agent]/surface_id; Bob's aN value is authoritative even if Kimi displays a different nickname.",
      "- Respect Kimi capacity. Launch only as many workers as the host accepts, keep the rest queued, and start queued assignments only after completed agents are closed.",
      "- Use run_in_background: true for evaluator agents when the host supports it.",
      "Wait for worker completion notifications. Do not merge in the launch turn.",
      "```",
    ].join("\n"),
    "{{SPAWN_CHAIN_AGENT}}": [
      "```text",
      `Agent(subagent_type="coder", prompt: "Bob role: chain-builder. Domain: [domain]. Egress profile: [egress_profile]. Session: ~/hacker-bob-sessions/[domain]. Read findings, wave handoffs, auth profiles, HTTP audit, and prior chain attempts through MCP. Test plausible chains with bob_http_scan as needed, passing egress_profile on every scan, and write every outcome through bob_write_chain_attempt with the required steps array. Do not read findings.md, chains.md, or markdown handoffs. Emit BOB_CHAIN_DONE when finished.")`,
      "```",
    ].join("\n"),
    "{{SPAWN_BRUTALIST_VERIFIER}}": [
      "```text",
      `Agent(subagent_type="coder", prompt: "Bob role: brutalist-verifier. Session: ~/hacker-bob-sessions/[domain]. Egress profile: [egress_profile]. Target: [domain]. First call bob_read_verification_context({ target_domain }); for v2 include current_attempt_id/snapshot_hash on writes and verification_replay context on replay tools. Emit BOB_VERIFY_DONE when finished.")`,
      "```",
    ].join("\n"),
    "{{SPAWN_BALANCED_VERIFIER}}": [
      "```text",
      `Agent(subagent_type="coder", prompt: "Bob role: balanced-verifier. Session: ~/hacker-bob-sessions/[domain]. Egress profile: [egress_profile]. Target: [domain]. First call bob_read_verification_context({ target_domain }). If v2, do not read brutalist or adjudication; use current_attempt_id/snapshot_hash and write the independent balanced round. Emit BOB_VERIFY_DONE when finished.")`,
      "```",
    ].join("\n"),
    "{{SPAWN_FINAL_VERIFIER}}": [
      "```text",
      `Agent(subagent_type="coder", prompt: "Bob role: final-verifier. Session: ~/hacker-bob-sessions/[domain]. Egress profile: [egress_profile]. Target: [domain]. First call bob_read_verification_context({ target_domain }). If v2, consume adjudication_context.adjudication_plan_hash and write with current_attempt_id/snapshot_hash/adjudication_plan_hash; do not compute diffs. Emit BOB_VERIFY_DONE when finished.")`,
      "```",
    ].join("\n"),
    "{{SPAWN_GRADER_AGENT}}": [
      "```text",
      `Agent(subagent_type="coder", prompt: "Bob role: grader. Domain: [domain]. Session: ~/hacker-bob-sessions/[domain]. Call bob_read_candidate_claims, bob_read_chain_attempts, bob_read_verification_round({ target_domain: '[domain]', round: 'final' }), and bob_read_evidence_packs, score survivors, then write only through bob_write_grade_verdict. Emit BOB_GRADE_DONE when finished.")`,
      "```",
    ].join("\n"),
    "{{SPAWN_REPORTER_AGENT}}": [
      "```text",
      `Agent(subagent_type="coder", prompt: "Bob role: report-writer. Domain: [domain]. Session: ~/hacker-bob-sessions/[domain]. Call bob_read_candidate_claims, bob_read_chain_attempts, bob_read_verification_round({ target_domain: '[domain]', round: 'final' }), bob_read_evidence_packs, and bob_read_grade_verdict, then compose and finalize through bob_compose_report and bob_finalize_report; do not Write report.md directly. For SUBMIT, include only confirmed chain evidence. For SKIP/no reportables, write a concise no-findings closeout with verification, chain-attempt, and blocker summary. Emit BOB_REPORT_DONE when finished.")`,
      "```",
    ].join("\n"),
    "{{SPAWN_EVIDENCE_AGENT}}": [
      "```text",
      `Agent(subagent_type="coder", prompt: "Bob role: evidence-agent. Session: ~/hacker-bob-sessions/[domain]. Egress profile: [egress_profile]. First call bob_read_verification_context({ target_domain }); for v2 pass evidence_replay context and bind evidence to the current final_verification_hash. Emit BOB_EVIDENCE_DONE when finished.")`,
      "```",
    ].join("\n"),
  });
}

function applyKimiHostText(document) {
  return document
    .replace(
      "{{STATUS_UPDATE_CACHE_COMMAND}}",
      'node -e "const update=require(\'./mcp/lib/update-check.js\'); console.log(JSON.stringify(update.readUpdateCache(process.cwd()) || null, null, 2));"',
    )
    .replace(/First, read the passive update cache if the helper is installed:\n```\n/g, "First, read the passive update cache if the helper is installed:\n```bash\n")
    .replace(/After resolving `target_domain`, call:\n```\n/g, "After resolving `target_domain`, call:\n```text\n")
    .replace(/Use host-normal agent permissions by default/g, "Use normal Agent permissions by default")
    .replace(/Evaluator waves MUST use the host's asynchronous\/background worker mechanism when available\./g, "Evaluator waves MUST use Agent with run_in_background: true when the host supports it.")
    .replace(/Use each assignment's `evaluator_agent` as the subagent type and its `handoff_token` only in its spawn prompt\./g, 'Use `Agent(subagent_type="coder")` for every evaluator worker; put each assignment\'s `evaluator_agent` in the prompt contract/header and include only that assignment\'s `handoff_token`.')
    .replace(/Generic evaluator spawn template \(uses the routed `assignment\.evaluator_agent`; the brief itself carries chain-specific context\):/g, 'Generic evaluator spawn template (uses Kimi `coder` workers; the routed `assignment.evaluator_agent` selects the embedded Bob contract):')
    .replace(/host stop hooks are only adapter guardrails/g, "Kimi subagent completion is only an adapter guardrail")
    .replace(/Claude Code enforces `maxTurns` as a turn budget, not a raw tool-call budget\./g, "The host may enforce turn budgets differently from raw tool-call budgets.")
    .replace(/Paste in the current agent session\./g, "Paste in the current Kimi CLI session.")
    .replace(/for Claude compatibility/g, "for host compatibility")
    .replace(/Claude transcript windows/g, "Kimi session log windows")
    .replace(/Claude transcripts/g, "Kimi session logs")
    .replace(/Claude transcript JSONL files/g, "Kimi session log files")
    .replace(/Claude project JSONL files/g, "Kimi session log files")
    .replace(/Do not use the `Task` tool by default\./g, "Do not spawn agents by default.")
    .replace(/Do not use `Task`\./g, "Do not spawn agents.")
    .replace(/Claude Code/g, "Kimi CLI")
    // Bob host slash commands -> Kimi `/skill:` invocations. On Claude the
    // evaluate entry point is the `/bob-evaluate` command wrapping the
    // bob-evaluate-runner skill; Kimi has no command/skill split, so it maps to
    // the `bob-evaluate` skill directly (matching the Codex adapter). The
    // negative lookaheads keep us from (a) rewriting artifact tokens like
    // `/bob-surface-discovery-*` and (b) partial-matching a longer
    // `/bob-evaluate…`-prefixed token.
    .replace(/\/bob-evaluate(?![\w-])/g, "/skill:bob-evaluate")
    .replace(/\/bob-status(?![\w-])/g, "/skill:bob-status")
    .replace(/\/bob-debug(?![\w-])/g, "/skill:bob-debug")
    .replace(/\/bob-update(?![\w-])/g, "/skill:bob-update")
    // Slash-replace set mirrors the gated Codex reference (evaluate/status/debug/
    // update/export). No shared role body references `/bob-egress`, so — like
    // Codex — there is no egress slash-replace here; the egress skill is rendered
    // directly by renderEgressSkill() and never passes through this rewrite.
    .replace(/\/bob-export(?![\w-])/g, "/skill:bob-export");
}

function replaceLaunchTemplates(document) {
  let next = document;
  for (const [placeholder, template] of Object.entries(kimiLaunchTemplates())) {
    next = next.split(placeholder).join(template);
  }
  return next;
}

function kimiOrchestratorPreamble() {
  return [
    "## Kimi Agent Mapping",
    "- Bob named roles are logical roles; Kimi host agents are spawned as `coder` subagents via the `Agent` tool.",
    "- Bob `wN`, `aN`, `surface_id`, and `handoff_token` values are durable truth. Kimi subagent IDs and nicknames are local execution metadata only.",
    "- If Kimi does not expose Bob MCP tools yet, use tool discovery for `bob_*` tools before falling back to local artifact reads.",
    "- This workflow requires background worker agents. Proceed only when the operator's request clearly authorizes Hacker Bob or agent execution; otherwise ask before spawning.",
    "",
  ].join("\n");
}

function kimiRoleContractAppendix({ root = DEFAULT_ROOT } = {}) {
  const sections = [
    "",
    "## Kimi Worker Role Contracts",
    "When spawning a Kimi `Agent(subagent_type=\"coder\")`, include the matching contract below in that agent's prompt along with the run-specific header. These contracts replace host-native named subagents in Kimi.",
  ];
  for (const roleId of KIMI_WORKER_CONTRACT_ROLE_IDS) {
    sections.push(
      "",
      `### ${roleId}`,
      `BEGIN ${roleId} CONTRACT`,
      substituteHandoffFieldLimits(
        substituteCapabilityPackVerifierTable(applyKimiHostText(roleBody(roleId, { root })).trimEnd()),
      ),
      `END ${roleId} CONTRACT`,
    );
  }
  return sections.join("\n");
}

function renderKimiEvaluatorPackCatalogue() {
  const { smartContractCapabilityPacks } = require("../../mcp/lib/capability-packs.js");
  const packs = smartContractCapabilityPacks();
  const lines = packs.map((pack) =>
    `- \`capability_pack: "${pack.id}"\` (chain_family \`${pack.spawn.chain_family}\`) -> evaluator_agent \`${pack.evaluator_agent}\`. chain_id: ${pack.spawn.chain_id_description}. Workflow: ${pack.spawn.workflow_summary} CLI dependency: ${pack.spawn.cli_dependency}; blocked_harness_runs[] kind: ${pack.spawn.blocked_harness_kind_options}.`,
  );
  return [
    "Smart-contract spawn dispatch:",
    "- If `assignment.brief_profile === \"web\"` -> use the generic evaluator spawn template above; do not use the SC template below.",
    "- Otherwise -> use the canonical smart-contract template below and look up the matching catalogue line by `assignment.capability_pack`.",
    "",
    "Pack metadata is the source of truth in `mcp/lib/capability-packs.js`; adding a chain pack auto-extends the catalogue at next prompt regeneration.",
    "",
    "```text",
    "Agent(subagent_type=\"coder\", prompt: \"",
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
    "\")",
    "```",
    "",
    "Pack catalogue (lookup by `assignment.capability_pack`):",
    ...lines,
  ].join("\n");
}

function renderKimiPromptBody(roleId, body, options = {}) {
  let document = applyKimiHostText(body);
  document = replaceLaunchTemplates(document);
  document = substituteCapabilityPackVerifierTable(document);
  document = substituteHandoffFieldLimits(document);
  if (roleId === "orchestrator") {
    document = document.replace("## Hard Rules\n", `${kimiOrchestratorPreamble()}## Hard Rules\n`);
    document += `${renderCapabilityPlaybookAppendix(options)}${kimiRoleContractAppendix(options)}\n`;
    // Also substitute the evaluator pack catalogue placeholder if present
    const { EVALUATOR_PACK_CATALOGUE_PLACEHOLDER } = require("../../mcp/lib/capability-packs-rendering.js");
    if (document.includes(EVALUATOR_PACK_CATALOGUE_PLACEHOLDER)) {
      document = document.split(EVALUATOR_PACK_CATALOGUE_PLACEHOLDER).join(renderKimiEvaluatorPackCatalogue());
    }
  }
  return document;
}

function renderUpdateSkill() {
  return [
    "# Hacker Bob Update",
    "",
    "Use this when the operator asks to check, plan, or apply Hacker Bob updates from Kimi CLI.",
    "",
    "## Read Cache",
    "Read the passive local cache without network access:",
    "```bash",
    'node -e "const update=require(\'./mcp/lib/update-check.js\'); console.log(JSON.stringify(update.readUpdateCache(process.cwd()) || null, null, 2));"',
    "```",
    "",
    "## Check Latest",
    "Run this only when the operator explicitly asks to check for updates:",
    "```bash",
    'node -e "const update=require(\'./mcp/lib/update-check.js\'); update.checkForUpdate(process.cwd(), { includeChangelog: true }).then((result) => console.log(update.renderUpdatePlan(result))).catch((error) => { console.error(error.message || String(error)); process.exit(1); });"',
    "```",
    "",
    "## Apply Update",
    "Ask before updating. When confirmed, run from the project root:",
    "```bash",
    'npx -y hacker-bob@latest install "$PWD"',
    "```",
    "",
    "After installation, tell the operator to restart Kimi CLI in this project before continuing.",
    "",
  ].join("\n");
}

function renderExportSkill() {
  return [
    "# Hacker Bob Export",
    "",
    "Use this when the operator asks to create a post-release improvement bundle from Kimi CLI.",
    "",
    "Run from the project root. The command has no v1 flags:",
    "```bash",
    'node -e "const exporter=require(\'./mcp/lib/bob-export.js\'); const result=exporter.exportBobReleaseBundle({ projectDir: process.cwd() }); process.stdout.write(exporter.renderExportResult(result));"',
    "```",
    "",
    "Report the helper output exactly. This workflow exports telemetry and session summaries for improving Hacker Bob; it does not hunt, resume sessions, or interact with targets.",
    "",
  ].join("\n");
}

function renderEgressSkill() {
  return [
    "# Hacker Bob Egress",
    "",
    "Use this when the operator asks to list, add, test, enable, disable, or remove Hacker Bob egress profiles from Kimi CLI.",
    "",
    "**Input:** `$ARGUMENTS` (`list`, `add <name>`, `test <name>`, `enable <name>`, `disable <name>`, or `remove <name>`)",
    "",
    "Run from the project root:",
    "```bash",
    'node ./mcp/lib/egress-cli.js "$PWD" $ARGUMENTS',
    "```",
    "",
    "Rules:",
    "- If no subcommand is provided, use `list`.",
    "- For `add <name>`, prefer an environment variable reference such as `--proxy-env BOB_EGRESS_GR_RESIDENTIAL_PROXY`; do not ask the operator to paste credentials into chat.",
    "- For `remove <name>`, ask the operator to confirm removal, then rerun with `--yes` only after confirmation.",
    "- Report profile names, enabled status, region, description, and whether a proxy is configured. Never print proxy URLs or credentials.",
    "",
  ].join("\n");
}

function renderKimiSkill(skillId, options = {}) {
  const spec = KIMI_SKILL_SPECS[skillId];
  if (!spec) throw new Error(`Missing Kimi skill spec for ${skillId}`);
  let body;
  if (spec.role_id) {
    body = renderKimiPromptBody(spec.role_id, roleBody(spec.role_id, options), options);
  } else if (skillId === "export") {
    body = renderExportSkill();
  } else if (skillId === "egress") {
    body = renderEgressSkill();
  } else {
    body = renderUpdateSkill();
  }
  return `${renderFrontmatter(spec)}\n\n${body}`;
}

function kimiSkillOutputPath(skillId, { root = DEFAULT_ROOT } = {}) {
  const spec = KIMI_SKILL_SPECS[skillId];
  if (!spec) throw new Error(`Missing Kimi skill spec for ${skillId}`);
  return path.join(root, spec.output_path);
}

function updateKimiSkillFile(skillId, { check = false, root = DEFAULT_ROOT } = {}) {
  const filePath = kimiSkillOutputPath(skillId, { root });
  const nextDocument = renderKimiSkill(skillId, { root });
  const document = fs.existsSync(filePath) ? fs.readFileSync(filePath, "utf8") : null;
  if (document === nextDocument) return false;
  if (check) {
    throw new Error(`${path.relative(root, filePath)} is stale; run node scripts/generate-kimi-roles.js`);
  }
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, nextDocument, "utf8");
  return true;
}

function updateKimiSkillFiles({ check = false, root = DEFAULT_ROOT, skillIds = Object.keys(KIMI_SKILL_SPECS) } = {}) {
  let changed = false;
  for (const skillId of skillIds) {
    changed = updateKimiSkillFile(skillId, { check, root }) || changed;
  }
  return changed;
}

module.exports = {
  KIMI_SKILL_SPECS,
  KIMI_WORKER_CONTRACT_ROLE_IDS,
  kimiSkillOutputPath,
  renderKimiPromptBody,
  renderKimiSkill,
  updateKimiSkillFile,
  updateKimiSkillFiles,
};
