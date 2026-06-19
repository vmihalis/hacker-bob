"use strict";

const fs = require("fs");
const path = require("path");
const {
  roleDefinition,
} = require("../../mcp/lib/role-model.js");
const {
  codexRoleSpec,
} = require("../../adapters/codex/role-specs.js");
const {
  substituteCapabilityPackVerifierTable,
  substituteCodexEvaluatorPackCatalogue,
  substituteHandoffFieldLimits,
} = require("../../mcp/lib/capability-packs-rendering.js");
const {
  renderCapabilityPlaybookAppendix,
} = require("../../mcp/lib/capability-playbooks.js");
const { evaluatorRoleSpecs } = require("../../mcp/lib/capability-packs.js");

const DEFAULT_ROOT = path.join(__dirname, "..", "..");
// Cross-cutting Codex worker contracts (surface-discovery/auth/chain/verifier/evidence/
// grade/report). Per-chain evaluator contracts are appended from EVALUATOR_ROLES
// so adding a chain pack auto-extends this list without editing this file.
const CODEX_CROSS_CUTTING_ROLE_IDS = Object.freeze([
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
const CODEX_WORKER_CONTRACT_ROLE_IDS = Object.freeze([
  ...CODEX_CROSS_CUTTING_ROLE_IDS.slice(0, 4),
  ...evaluatorRoleSpecs().map((role) => role.role_id),
  // Plane X Cycle X.10 — generic TaskGraph evaluator shell appended
  // after the per-chain evaluator contracts so the appendix groups all
  // evaluator family contracts together before the cross-cutting roles.
  "evaluator-spawn",
  ...CODEX_CROSS_CUTTING_ROLE_IDS.slice(4),
]);

const CODEX_SKILL_SPECS = Object.freeze({
  evaluate: Object.freeze({
    role_id: "orchestrator",
    output_path: path.join("adapters", "codex", "skills", "bob-evaluate", "SKILL.md"),
    name: "bob-evaluate",
    description: "Run or resume a Hacker Bob bug bounty evaluate in Codex using the shared MCP runtime.",
  }),
  status: Object.freeze({
    role_id: "status",
    output_path: path.join("adapters", "codex", "skills", "bob-status", "SKILL.md"),
    name: "bob-status",
    description: "Read Hacker Bob session state, wave status, findings, verification, and grade summaries in Codex.",
  }),
  debug: Object.freeze({
    role_id: "debug",
    output_path: path.join("adapters", "codex", "skills", "bob-debug", "SKILL.md"),
    name: "bob-debug",
    description: "Debug Hacker Bob sessions in Codex using MCP telemetry and local session artifacts.",
  }),
  update: Object.freeze({
    output_path: path.join("adapters", "codex", "skills", "bob-update", "SKILL.md"),
    name: "bob-update",
    description: "Check for Hacker Bob package updates and guide project-local update installation from Codex.",
  }),
  export: Object.freeze({
    output_path: path.join("adapters", "codex", "skills", "bob-export", "SKILL.md"),
    name: "bob-export",
    description: "Create a Hacker Bob post-release improvement bundle for the currently installed Bob version.",
  }),
  egress: Object.freeze({
    output_path: path.join("adapters", "codex", "skills", "bob-egress", "SKILL.md"),
    name: "bob-egress",
    description: "List, add, test, enable, disable, or remove Hacker Bob egress profiles from Codex.",
  }),
});

function renderFrontmatter(spec) {
  return [
    "---",
    `name: ${spec.name}`,
    `description: ${spec.description}`,
    "---",
  ].join("\n");
}

function roleBody(roleId, { root = DEFAULT_ROOT } = {}) {
  const role = roleDefinition(roleId);
  return fs.readFileSync(path.join(root, role.prompt_body), "utf8").replace(/^\n+/, "");
}

function workerLabel(roleId) {
  const spec = codexRoleSpec(roleId);
  return `${spec.bob_role} -> Codex ${spec.agent_type}`;
}

function codexLaunchTemplates() {
  return Object.freeze({
    "{{SPAWN_SEED_DISCOVERY_AGENT}}": [
      "```text",
      `Use Codex spawn_agent for ${workerLabel("surface-discovery")}.`,
      "- agent_type: \"worker\"",
      "- message: include `Bob role: surface-discovery-agent`, `DOMAIN=[domain]`, `SESSION=~/hacker-bob-sessions/[domain]`, and the full `surface-discovery` contract from Codex Worker Role Contracts below.",
      "Wait with `wait_agent` before continuing. After reading the result and checking `attack_surface.json`, call `close_agent` for the host agent.",
      "```",
    ].join("\n"),
    "{{SPAWN_DEEP_SEED_DISCOVERY_AGENT}}": [
      "```text",
      `Use Codex spawn_agent for ${workerLabel("deep-surface-discovery")}.`,
      "- agent_type: \"worker\"",
      "- message: include `Bob role: deep-surface-discovery-agent`, `DOMAIN=[domain]`, `SESSION=~/hacker-bob-sessions/[domain]`, and the full `deep-surface-discovery` contract from Codex Worker Role Contracts below.",
      "Wait with `wait_agent` before continuing. After reading the result, call `close_agent` for the host agent.",
      "```",
    ].join("\n"),
    "{{SPAWN_SURFACE_ROUTER_AGENT}}": [
      "```text",
      `Use Codex spawn_agent for ${workerLabel("surface-router")}.`,
      "- agent_type: \"worker\"",
      "- message: include `Bob role: surface-router-agent`, `Domain: [domain]`, `Session: ~/hacker-bob-sessions/[domain]`, and instruct the worker to confirm `attack_surface.json` exists and call `bob_route_surfaces({ target_domain: '[domain]' })`. Include the full `surface-router` contract from Codex Worker Role Contracts below.",
      "Wait with `wait_agent`. If routing fails or returns zero surfaces, report the error and stop. After reading the result, call `close_agent` for the host agent.",
      "```",
    ].join("\n"),
    "{{SPAWN_EVALUATOR_AGENT}}": [
      "```text",
      `For each assignment, use Codex spawn_agent for the evaluator family chosen by the MCP capability router (\`assignment.evaluator_agent\` from wave-start result.data.assignments[] — one of evaluator-agent or any of the per-pack evaluators listed in the smart-contract pack catalogue: ${evaluatorRoleSpecs().map((role) => role.name).join(", ")}).`,
      "- agent_type: \"worker\"",
      "- message: include the compact run header below plus the full contract for `assignment.evaluator_agent` from Codex Worker Role Contracts.",
      "- Header fields: Domain: [domain]; Wave: w[wave]; Agent: a[agent]; Surface: [surface_id]; Capability pack: [assignment.capability_pack]; Brief profile: [assignment.brief_profile]; Evaluator agent: [assignment.evaluator_agent]; Context budget: [assignment.context_budget]; Egress profile: [egress_profile]; Block internal hosts: [block_internal_hosts]; Handoff token: [only this agent's handoff_token from wave-start result.data.assignments]; Checkpoint mode: [normal|paranoid|yolo].",
      "- First action inside the worker: call bob_read_assignment_brief({ target_domain: '[domain]', wave: 'w[wave]', agent: 'a[agent]', egress_profile: '[egress_profile]', block_internal_hosts: [block_internal_hosts] }) and use .data.run_context.context_budget plus .data.technique_packs.selected when present.",
      "- Pass the header egress_profile and block_internal_hosts values on every bob_http_scan call. If strict internal-host blocking conflicts with a proxy-backed egress profile, record the blocked prerequisite instead of retrying.",
      "- For web evaluators, call bob_read_technique_pack(mode=\"full\") only with target_domain/wave/agent/surface_id for relevant selected summaries, and bob_log_technique_attempt for selections, skips, attempts, and outcomes. Before finalizing, ensure one completion-status technique attempt is logged for this surface.",
      "- Track the local mapping `host_agent_id -> w[wave]/a[agent]/surface_id`; Bob's `aN` value is authoritative even if Codex displays a different nickname.",
      "- Respect Codex capacity. Launch only as many workers as the host accepts, keep the rest queued, and start queued assignments only after completed agents are closed.",
      "- Do not set `fork_context: true` when also setting `agent_type`; use a direct worker spawn unless Codex requires a different host default.",
      "Wait for worker completion notifications or `wait_agent` results. Do not merge in the launch turn.",
      "```",
    ].join("\n"),
    "{{SPAWN_CHAIN_AGENT}}": [
      "```text",
      `Use Codex spawn_agent for ${workerLabel("chain")}.`,
      "- agent_type: \"worker\"",
      "- message: `Bob role: chain-builder. Domain: [domain]. Session: ~/hacker-bob-sessions/[domain]. Egress profile: [egress_profile]. Block internal hosts: [block_internal_hosts]. Pass both values on every bob_http_scan call. Every bob_write_chain_attempt call must include the required steps array.` Include the full `chain` contract from Codex Worker Role Contracts.",
      "Wait with `wait_agent`, validate expected output, then `close_agent`.",
      "```",
    ].join("\n"),
    "{{SPAWN_BRUTALIST_VERIFIER}}": [
      "```text",
      `Use Codex spawn_agent for ${workerLabel("brutalist-verifier")}.`,
      "- agent_type: \"worker\"",
      "- message: `Bob role: brutalist-verifier. Session: ~/hacker-bob-sessions/[domain]. Target: [domain]. Egress profile: [egress_profile]. Block internal hosts: [block_internal_hosts]. First call bob_read_verification_context({ target_domain }); for v2 include current_attempt_id/snapshot_hash on writes and verification_replay context on replay tools. Pass egress_profile and block_internal_hosts on replay HTTP tools.` Include the full `brutalist-verifier` contract from Codex Worker Role Contracts.",
      "Wait with `wait_agent`, read the MCP verification artifact, then `close_agent`.",
      "```",
    ].join("\n"),
    "{{SPAWN_BALANCED_VERIFIER}}": [
      "```text",
      `Use Codex spawn_agent for ${workerLabel("balanced-verifier")}.`,
      "- agent_type: \"worker\"",
      "- message: `Bob role: balanced-verifier. Session: ~/hacker-bob-sessions/[domain]. Target: [domain]. Egress profile: [egress_profile]. Block internal hosts: [block_internal_hosts]. First call bob_read_verification_context({ target_domain }). If v2, do not read brutalist or adjudication; use current_attempt_id/snapshot_hash and write the independent balanced round. Pass egress_profile and block_internal_hosts on replay HTTP tools.` Include the full `balanced-verifier` contract from Codex Worker Role Contracts.",
      "Wait with `wait_agent`, read the MCP verification artifact, then `close_agent`.",
      "```",
    ].join("\n"),
    "{{SPAWN_FINAL_VERIFIER}}": [
      "```text",
      `Use Codex spawn_agent for ${workerLabel("final-verifier")}.`,
      "- agent_type: \"worker\"",
      "- message: `Bob role: final-verifier. Session: ~/hacker-bob-sessions/[domain]. Target: [domain]. Egress profile: [egress_profile]. Block internal hosts: [block_internal_hosts]. First call bob_read_verification_context({ target_domain }). If v2, consume adjudication_context.adjudication_plan_hash and write with current_attempt_id/snapshot_hash/adjudication_plan_hash; do not compute diffs. Pass egress_profile and block_internal_hosts on replay HTTP tools.` Include the full `final-verifier` contract from Codex Worker Role Contracts.",
      "Wait with `wait_agent`, read the MCP verification artifact, then `close_agent`.",
      "```",
    ].join("\n"),
    "{{SPAWN_GRADER_AGENT}}": [
      "```text",
      `Use Codex spawn_agent for ${workerLabel("grader")}.`,
      "- agent_type: \"worker\"",
      "- message: `Bob role: grader. Domain: [domain]. Session: ~/hacker-bob-sessions/[domain].` Include the full `grader` contract from Codex Worker Role Contracts.",
      "Wait with `wait_agent`, read `bob_read_grade_verdict.data`, then `close_agent`.",
      "```",
    ].join("\n"),
    "{{SPAWN_REPORTER_AGENT}}": [
      "```text",
      `Use Codex spawn_agent for ${workerLabel("reporter")}.`,
      "- agent_type: \"worker\"",
      "- message: `Bob role: report-writer. Domain: [domain]. Session: ~/hacker-bob-sessions/[domain]. Write the canonical ~/hacker-bob-sessions/[domain]/report.md before calling bounty_report_written.` Include the full `reporter` contract from Codex Worker Role Contracts.",
      "Wait with `wait_agent`, read the report, then `close_agent`.",
      "```",
    ].join("\n"),
    "{{SPAWN_EVIDENCE_AGENT}}": [
      "```text",
      `Use Codex spawn_agent for ${workerLabel("evidence")}.`,
      "- agent_type: \"worker\"",
      "- message: `Bob role: evidence-agent. Session: ~/hacker-bob-sessions/[domain]. Egress profile: [egress_profile]. Block internal hosts: [block_internal_hosts]. First call bob_read_verification_context({ target_domain }); for v2 pass evidence_replay context and bind evidence to the current final_verification_hash. Pass egress_profile and block_internal_hosts on replay HTTP tools.` Include the full `evidence` contract from Codex Worker Role Contracts.",
      "Wait with `wait_agent`, read `bob_read_evidence_packs.data`, then `close_agent`.",
      "```",
    ].join("\n"),
    // Smart-contract spawn templates render from the capability pack manifest.
    // The Codex renderer fills the {{EVALUATOR_PACK_CATALOGUE}} placeholder via
    // substituteCodexEvaluatorPackCatalogue, which iterates
    // smartContractCapabilityPacks() and emits one entry per pack. Adding a
    // new chain pack auto-extends the catalogue here without editing this
    // file. Per-pack worker contracts still live in the role-contract
    // appendix below — that loop is also driven by the registry.
  });
}

function applyCodexHostText(document) {
  return document
    .replace(
      "{{STATUS_UPDATE_CACHE_COMMAND}}",
      "node -e \"const update=require('./mcp/lib/update-check.js'); console.log(JSON.stringify(update.readUpdateCache(process.cwd()) || null, null, 2));\"",
    )
    .replace(/Use host-normal agent permissions by default/g, "Use Codex worker-agent permissions by default")
    .replace(/Evaluator waves MUST use the host's asynchronous\/background worker mechanism when available\./g, "Evaluator waves MUST use Codex `spawn_agent` workers and must respect host capacity.")
    .replace(/host stop hooks are only adapter guardrails/g, "Codex has no Bob stop hook; MCP finalization is the correctness boundary")
    .replace(/Claude Code enforces `maxTurns` as a turn budget, not a raw tool-call budget\./g, "The host may enforce turn budgets differently from raw tool-call budgets.")
    .replace(/Paste in the current agent session\./g, "Paste in the current Codex session.")
    .replace(/for Claude compatibility/g, "for host compatibility")
    .replace(/Claude transcript windows/g, "Codex session log windows")
    .replace(/Claude transcripts/g, "Codex session logs")
    .replace(/Claude transcript JSONL files/g, "Codex session log files")
    .replace(/Claude project JSONL files/g, "Codex session log files")
    .replace(/Claude Code/g, "Codex")
    .replace(/Do not use the `Task` tool by default\./g, "Do not spawn agents by default.")
    .replace(/Do not use `Task`\./g, "Do not spawn agents.")
    .replace(/\/bob-evaluate/g, "$bob-evaluate")
    .replace(/\/bob-status/g, "$bob-status")
    .replace(/\/bob-debug/g, "$bob-debug")
    .replace(/\/bob-update/g, "$bob-update")
    .replace(/\/bob-export/g, "$bob-export")
    .replace(/\/bob:evaluate/g, "$bob-evaluate")
    .replace(/\/bob:status/g, "$bob-status")
    .replace(/\/bob:debug/g, "$bob-debug")
    .replace(/\/bob:update/g, "$bob-update")
    .replace(/\/bob:export/g, "$bob-export");
}

function replaceLaunchTemplates(document) {
  let next = document;
  for (const [placeholder, template] of Object.entries(codexLaunchTemplates())) {
    next = next.split(placeholder).join(template);
  }
  return next;
}

function codexOrchestratorPreamble() {
  return [
    "## Codex Agent Mapping",
    "- Bob named roles are logical roles; Codex host agents are spawned as `worker` agents.",
    "- Bob `wN`, `aN`, `surface_id`, and `handoff_token` values are durable truth. Codex host agent IDs and nicknames are local execution metadata only.",
    "- If Codex does not expose Bob MCP tools yet, use tool discovery for `bob_*` tools before falling back to local artifact reads.",
    "- This workflow requires background worker agents. Proceed only when the operator's request clearly authorizes Hacker Bob or agent execution; otherwise ask before spawning.",
    "",
  ].join("\n");
}

function codexRoleContractAppendix({ root = DEFAULT_ROOT } = {}) {
  const sections = [
    "",
    "## Codex Worker Role Contracts",
    "When spawning a Codex worker, include the matching contract below in that worker's message along with the run-specific header. These contracts replace host-native named subagents in Codex.",
  ];
  for (const roleId of CODEX_WORKER_CONTRACT_ROLE_IDS) {
    sections.push(
      "",
      `### ${roleId}`,
      `BEGIN ${roleId} CONTRACT`,
      // Substitute the capability-pack verifier table and the handoff
      // field-limit table inside Codex worker contracts too — verifier/
      // evidence prompts embed the verifier-table placeholder and evaluator
      // prompts embed the handoff-limits placeholder; Codex workers read
      // both from the appendix in bob-evaluate SKILL.md.
      substituteHandoffFieldLimits(
        substituteCapabilityPackVerifierTable(applyCodexHostText(roleBody(roleId, { root })).trimEnd()),
      ),
      `END ${roleId} CONTRACT`,
    );
  }
  return sections.join("\n");
}

function codexWorkerLabelForPack(pack) {
  // pack.evaluator_agent is the Bob agent name (with the conventional
  // "-agent" suffix). The catalogue line surrounds this with adjacent
  // prose ("-> Codex worker ${label}"), so the label itself is just the
  // bob_role+agent_type pair. Multiple packs that share a role_id (e.g.
  // Move-family aptos+sui) resolve to the same Codex worker contract;
  // the renderer picks the role id by stripping "-agent" from
  // pack.evaluator_agent.
  const roleId = pack.evaluator_agent.replace(/-agent$/, "");
  // CODEX_WORKER_CONTRACT_ROLE_IDS holds the canonical role list. If a pack
  // is added without a matching codex role spec, fail loudly here rather
  // than silently rendering "undefined -> Codex undefined".
  if (!CODEX_WORKER_CONTRACT_ROLE_IDS.includes(roleId)) {
    throw new Error(
      `pack ${pack.id} evaluator_agent ${pack.evaluator_agent} maps to roleId ${roleId} which is not in CODEX_WORKER_CONTRACT_ROLE_IDS; add the role spec before regenerating prompts`,
    );
  }
  return workerLabel(roleId);
}

function renderCodexPromptBody(roleId, body, options = {}) {
  let document = applyCodexHostText(body);
  document = replaceLaunchTemplates(document);
  document = substituteCapabilityPackVerifierTable(document);
  document = substituteCodexEvaluatorPackCatalogue(document, codexWorkerLabelForPack);
  document = substituteHandoffFieldLimits(document);
  if (roleId === "orchestrator") {
    document = document.replace("## Hard Rules\n", `${codexOrchestratorPreamble()}## Hard Rules\n`);
    document += `${renderCapabilityPlaybookAppendix(options)}${codexRoleContractAppendix(options)}\n`;
  }
  return document;
}

function renderUpdateSkill() {
  return [
    "# Hacker Bob Update",
    "",
    "Use this when the operator asks to check, plan, or apply Hacker Bob updates from Codex.",
    "",
    "## Read Cache",
    "Read the passive local cache without network access:",
    "```bash",
    "node -e \"const update=require('./mcp/lib/update-check.js'); console.log(JSON.stringify(update.readUpdateCache(process.cwd()) || null, null, 2));\"",
    "```",
    "",
    "## Check Latest",
    "Run this only when the operator explicitly asks to check for updates:",
    "```bash",
    "node -e \"const update=require('./mcp/lib/update-check.js'); update.checkForUpdate(process.cwd(), { includeChangelog: true }).then((result) => console.log(update.renderUpdatePlan(result))).catch((error) => { console.error(error.message || String(error)); process.exit(1); });\"",
    "```",
    "",
    "## Apply Update",
    "Ask before updating. When confirmed, run from the project root:",
    "```bash",
    "npx -y hacker-bob@latest install \"$PWD\"",
    "```",
    "",
    "After installation, tell the operator to restart Codex in this project before continuing.",
    "",
  ].join("\n");
}

function renderExportSkill() {
  return [
    "# Hacker Bob Export",
    "",
    "Use this when the operator asks to create a post-release improvement bundle from Codex.",
    "",
    "Run from the project root. The command has no v1 flags:",
    "```bash",
    "node -e \"const exporter=require('./mcp/lib/bob-export.js'); const result=exporter.exportBobReleaseBundle({ projectDir: process.cwd() }); process.stdout.write(exporter.renderExportResult(result));\"",
    "```",
    "",
    "Report the helper output exactly. This workflow exports telemetry and session summaries for improving Hacker Bob; it does not evaluate, resume sessions, or interact with targets.",
    "",
  ].join("\n");
}

function renderEgressSkill() {
  return [
    "# Hacker Bob Egress",
    "",
    "Use this when the operator asks to list, add, test, enable, disable, or remove Hacker Bob egress profiles from Codex.",
    "",
    "**Input:** `$ARGUMENTS` (`list`, `add <name>`, `test <name>`, `enable <name>`, `disable <name>`, or `remove <name>`)",
    "",
    "Run from the project root:",
    "```bash",
    "node ./mcp/lib/egress-cli.js \"$PWD\" $ARGUMENTS",
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

function renderCodexSkill(skillId, options = {}) {
  const spec = CODEX_SKILL_SPECS[skillId];
  if (!spec) throw new Error(`Missing Codex skill spec for ${skillId}`);
  let body;
  if (spec.role_id) {
    body = renderCodexPromptBody(spec.role_id, roleBody(spec.role_id, options), options);
  } else if (skillId === "export") {
    body = renderExportSkill();
  } else if (skillId === "egress") {
    body = renderEgressSkill();
  } else {
    body = renderUpdateSkill();
  }
  return `${renderFrontmatter(spec)}\n\n${body}`;
}

function codexSkillOutputPath(skillId, { root = DEFAULT_ROOT } = {}) {
  const spec = CODEX_SKILL_SPECS[skillId];
  if (!spec) throw new Error(`Missing Codex skill spec for ${skillId}`);
  return path.join(root, spec.output_path);
}

function updateCodexSkillFile(skillId, { check = false, root = DEFAULT_ROOT } = {}) {
  const filePath = codexSkillOutputPath(skillId, { root });
  const nextDocument = renderCodexSkill(skillId, { root });
  const document = fs.existsSync(filePath) ? fs.readFileSync(filePath, "utf8") : null;
  if (document === nextDocument) return false;
  if (check) {
    throw new Error(`${path.relative(root, filePath)} is stale; run node scripts/generate-codex-skills.js`);
  }
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, nextDocument, "utf8");
  return true;
}

function updateCodexSkillFiles({ check = false, root = DEFAULT_ROOT, skillIds = Object.keys(CODEX_SKILL_SPECS) } = {}) {
  let changed = false;
  for (const skillId of skillIds) {
    changed = updateCodexSkillFile(skillId, { check, root }) || changed;
  }
  return changed;
}

module.exports = {
  CODEX_SKILL_SPECS,
  CODEX_WORKER_CONTRACT_ROLE_IDS,
  codexSkillOutputPath,
  renderCodexPromptBody,
  renderCodexSkill,
  updateCodexSkillFile,
  updateCodexSkillFiles,
};
