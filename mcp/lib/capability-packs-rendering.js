"use strict";

const {
  CAPABILITY_PACKS,
  smartContractCapabilityPacks,
} = require("./capability-packs.js");
const writeWaveHandoffTool = require("./tools/write-wave-handoff.js");

// Render a markdown reference table of every pack's verifier dispatch.
// Both the Claude and Codex prompt renderers consume this so adding a new
// pack to capability-packs.js updates every adapter at next regeneration.
// Keep the rendering renderer-agnostic — the same string is dropped into
// brutalist/balanced/final/evidence prompts on Claude and into the Codex
// `bob-evaluate` skill's worker contracts.
function renderCapabilityPackVerifierTable() {
  const rows = [];
  const failReasonNotes = [];
  for (const pack of Object.values(CAPABILITY_PACKS)) {
    const v = pack.verifier;
    if (!v) continue;
    const replay = v.replay_tool;
    const sample = v.sample_type;
    const fresh = v.fresh_state_omit_field == null ? "—" : `omit \`${v.fresh_state_omit_field}\``;
    const blockRef = v.block_reference_field
      ? `\`${v.block_reference_field}\` (${v.block_reference_label || "block"})`
      : "—";
    const disambig = v.disambiguation && v.disambiguation.tool
      ? `\`${v.disambiguation.tool}\``
      : "—";
    rows.push(`| \`${pack.id}\` | \`${replay}\` | \`${sample}\` | ${fresh} | ${blockRef} | ${disambig} |`);
    if (v.disambiguation && v.disambiguation.tool && v.disambiguation.fail_reason) {
      failReasonNotes.push(`- \`${pack.id}\` disambiguation deny reason: ${v.disambiguation.fail_reason}`);
    }
  }
  return [
    "## Capability pack verifier table",
    "",
    "Generated from `mcp/lib/capability-packs.js`. Adding a new pack updates this table at next prompt regeneration.",
    "",
    "| capability_pack | replay_tool | sample_type | runner-input param to omit for fresh-state replay | runner response field with resolved block reference | required disambiguation read |",
    "|---|---|---|---|---|---|",
    ...rows,
    "",
    "Disambiguation deny reasons (use as `reasoning` when the disambiguation read does not resolve):",
    ...failReasonNotes,
  ].join("\n");
}

const CAPABILITY_PACK_VERIFIER_TABLE_PLACEHOLDER = "{{CAPABILITY_PACK_VERIFIER_TABLE}}";

// Substitute the verifier-table placeholder in any document. Returns the
// document unchanged if the placeholder is absent.
function substituteCapabilityPackVerifierTable(document) {
  if (!document.includes(CAPABILITY_PACK_VERIFIER_TABLE_PLACEHOLDER)) return document;
  return document.split(CAPABILITY_PACK_VERIFIER_TABLE_PLACEHOLDER).join(renderCapabilityPackVerifierTable());
}

// ----------------------------------------------------------------------
// Evaluator pack catalogue rendering
// ----------------------------------------------------------------------
//
// The orchestrator skill embeds one canonical smart-contract spawn template
// (a parameterised Agent(...) call for Claude or Codex spawn_agent block).
// Per-pack details — chain_family, chain_id description, workflow, CLI
// dependency, blocked_harness_runs[].kind — live in `pack.spawn` and render
// as a one-line catalogue entry per pack. Adding a 7th chain pack adds one
// catalogue line at next regeneration; no extra spawn template body or
// renderer edit is needed. Web pack is excluded — its prompt fields differ
// structurally and stay on the legacy SPAWN_EVALUATOR_AGENT body.
//
// Catalogue lookup contract: the orchestrator receives `assignment.capability_pack`
// from wave-start result.data.assignments[]. Catalogue lines are keyed by
// `capability_pack` (not chain_family) because that is the field every
// downstream consumer — verifier, evidence, reporter — uses for dispatch.
// Brief-profile dispatch: the orchestrator picks between the generic evaluator
// SPAWN_EVALUATOR_AGENT body (when `assignment.brief_profile` is "web" or
// "oss") and the SC canonical template below (otherwise). Never use both for
// one assignment.

function assertSpawnField(pack, fieldName) {
  const value = pack && pack.spawn ? pack.spawn[fieldName] : undefined;
  if (typeof value !== "string" || !value.trim()) {
    throw new Error(`pack ${pack && pack.id} spawn.${fieldName} must be a non-empty string`);
  }
  return value;
}

const EVALUATOR_PACK_CATALOGUE_PLACEHOLDER = "{{EVALUATOR_PACK_CATALOGUE}}";

// JSON-schema enum for blocked_harness_runs[].kind, surfaced here so the
// catalogue can validate that every pack's blocked_harness_kind_options is
// expressible inside the schema. Keep in sync with
// mcp/lib/tools/write-wave-handoff.js.
const BLOCKED_HARNESS_RUN_KINDS = Object.freeze([
  "foundry_fork",
  "anchor_fork",
  "aptos_fork",
  "sui_fork",
  "substrate_fork",
  "cosmwasm_fork",
  "rpc_endpoint",
  "fuzzer",
  "symbolic_solver",
  "mock_dependency",
  "external_api",
  "docker_unavailable",
  "sanitizer_unavailable",
  "static_analyzer_unavailable",
  "cve_feed_stale",
  "other",
]);

// JSON-schema enum for blocked_prereqs[].kind. Same three-way mirror as
// BLOCKED_HARNESS_RUN_KINDS: schema enum, this constant, and waves.js
// runtime normalizer must agree. Bounded set rather than free-form so the
// merge layer can group blockers and operators get a finite menu of
// registry kinds to satisfy.
const BLOCKED_PREREQ_KINDS = Object.freeze([
  "auth_missing",
  "egress_unreachable",
  "funded_wallet_missing",
  "key_material_missing",
  "external_credential_missing",
]);

function assertBlockedHarnessKindOptions(pack) {
  const raw = assertSpawnField(pack, "blocked_harness_kind_options");
  // Accept "foo" or "foo or bar" — split on " or " and validate each piece.
  const tokens = raw.split(/\s+or\s+/).map((t) => t.trim()).filter(Boolean);
  for (const token of tokens) {
    if (!BLOCKED_HARNESS_RUN_KINDS.includes(token)) {
      throw new Error(
        `pack ${pack.id} spawn.blocked_harness_kind_options token "${token}" is not in the write-wave-handoff schema enum`,
      );
    }
  }
}

function eachSmartContractPackValidated() {
  const packs = smartContractCapabilityPacks();
  for (const pack of packs) {
    assertSpawnField(pack, "chain_family");
    assertSpawnField(pack, "chain_id_description");
    assertSpawnField(pack, "workflow_summary");
    assertSpawnField(pack, "cli_dependency");
    assertSpawnField(pack, "evaluator_name_prefix");
    assertBlockedHarnessKindOptions(pack);
  }
  return packs;
}

function renderEvaluatorPackCataloguePreamble() {
  return [
    "Smart-contract spawn dispatch:",
    "- If `assignment.brief_profile === \"web\"` or `assignment.brief_profile === \"oss\"` -> use the generic evaluator spawn template above; do not use the SC template below.",
    "- Otherwise -> use the canonical smart-contract template below and look up the matching catalogue line by `assignment.capability_pack`.",
    "",
    "Pack metadata is the source of truth in `mcp/lib/capability-packs.js`; adding a chain pack auto-extends the catalogue at next prompt regeneration.",
  ].join("\n");
}

function renderClaudeSmartContractCanonicalSpawn() {
  // The orchestrator must look up the catalogue line for
  // assignment.capability_pack and substitute the chain_family, workflow,
  // CLI, and blocked_harness kind into this template before spawning.
  return [
    "```",
    "Agent(subagent_type: \"[assignment.evaluator_agent]\", name: \"[assignment.evaluator_agent]-w[wave]-a[agent]\", run_in_background: true, prompt: \"",
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
    "Final: call bob_write_wave_handoff exactly once with target_domain, wave, agent, surface_id, surface_status, handoff_token, summary, content, optional bypass_attempts, blocked_harness_runs, chain_notes, dead_ends, lead_surface_ids. Then call bob_finalize_agent_run. If finalization fails, fix the handoff and retry. After finalization succeeds, emit `BOB_AGENT_RUN_DONE {\"target_domain\":\"[domain]\",\"wave\":\"w[wave]\",\"agent\":\"a[agent]\",\"surface_id\":\"[surface_id]\"}` for Claude compatibility.",
    "\")",
    "```",
  ].join("\n");
}

function renderClaudeEvaluatorPackCatalogue() {
  const packs = eachSmartContractPackValidated();
  const lines = packs.map((pack) =>
    `- \`capability_pack: "${pack.id}"\` (chain_family \`${pack.spawn.chain_family}\`) -> evaluator_agent \`${pack.evaluator_agent}\`. chain_id: ${pack.spawn.chain_id_description}. Workflow: ${pack.spawn.workflow_summary} CLI dependency: ${pack.spawn.cli_dependency}; blocked_harness_runs[] kind: ${pack.spawn.blocked_harness_kind_options}.`,
  );
  return [
    renderEvaluatorPackCataloguePreamble(),
    renderClaudeSmartContractCanonicalSpawn(),
    "",
    "Pack catalogue (lookup by `assignment.capability_pack`):",
    ...lines,
  ].join("\n");
}

function renderCodexEvaluatorPackCatalogue(codexWorkerLabelFor) {
  const packs = eachSmartContractPackValidated();
  const lines = packs.map((pack) => {
    const label = codexWorkerLabelFor(pack);
    return `- \`capability_pack: "${pack.id}"\` (chain_family \`${pack.spawn.chain_family}\`) -> ${label}. chain_id: ${pack.spawn.chain_id_description}. Workflow: ${pack.spawn.workflow_summary} CLI dependency: ${pack.spawn.cli_dependency}; blocked_harness_runs[] kind: ${pack.spawn.blocked_harness_kind_options}.`;
  });
  return [
    renderEvaluatorPackCataloguePreamble(),
    "```text",
    "For each smart-contract assignment, use Codex spawn_agent with `agent_type: \"worker\"` and a message that: (1) includes the run header (Domain, Wave, Agent, Surface, Capability pack, Brief profile, Evaluator agent, Context budget, Egress profile, Block internal hosts, Handoff token, Checkpoint mode), (2) instructs the first action to call bob_read_assignment_brief({ target_domain: '[domain]', wave: 'w[wave]', agent: 'a[agent]', egress_profile: '[egress_profile]', block_internal_hosts: [block_internal_hosts] }), (3) inlines the workflow summary, CLI dependency, and blocked_harness_runs[] kind copied verbatim from the catalogue line for [assignment.capability_pack], and (4) includes the worker contract for [assignment.evaluator_agent] from Codex Worker Role Contracts.",
    "```",
    "",
    "Pack catalogue (lookup by `assignment.capability_pack`):",
    ...lines,
  ].join("\n");
}

function substituteClaudeEvaluatorPackCatalogue(document) {
  if (!document.includes(EVALUATOR_PACK_CATALOGUE_PLACEHOLDER)) return document;
  return document.split(EVALUATOR_PACK_CATALOGUE_PLACEHOLDER).join(renderClaudeEvaluatorPackCatalogue());
}

function substituteCodexEvaluatorPackCatalogue(document, codexWorkerLabelFor) {
  if (!document.includes(EVALUATOR_PACK_CATALOGUE_PLACEHOLDER)) return document;
  return document.split(EVALUATOR_PACK_CATALOGUE_PLACEHOLDER).join(renderCodexEvaluatorPackCatalogue(codexWorkerLabelFor));
}

// ----------------------------------------------------------------------
// bob_write_wave_handoff field-limit rendering
// ----------------------------------------------------------------------
//
// Evaluator prompts learn handoff field limits before submission, not from
// rejection messages mid-flight. Limits are read from the live schema in
// `mcp/lib/tools/write-wave-handoff.js` so a future schema bump propagates
// to every consumer prompt at next regeneration without hand-edits.

const HANDOFF_FIELD_LIMITS_PLACEHOLDER = "{{HANDOFF_FIELD_LIMITS}}";

function describeStringLimits(propertySchema) {
  const min = propertySchema && Number.isFinite(propertySchema.minLength) ? propertySchema.minLength : null;
  const max = propertySchema && Number.isFinite(propertySchema.maxLength) ? propertySchema.maxLength : null;
  if (min != null && max != null) return `${min}–${max} chars`;
  if (max != null) return `≤ ${max} chars`;
  if (min != null) return `≥ ${min} chars`;
  return "string";
}

function renderHandoffFieldLimits() {
  const props = writeWaveHandoffTool.inputSchema.properties;
  const blockedHarnessProps = props.blocked_harness_runs.items.properties;
  const blockedPrereqProps = props.blocked_prereqs.items.properties;
  const bypassAttemptProps = props.bypass_attempts.items.properties;
  const lines = [
    "Handoff field limits (enforced by `bob_write_wave_handoff`; oversize values are rejected):",
    `- \`summary\`: ${describeStringLimits(props.summary)}`,
    `- \`chain_notes[]\`: each entry ${describeStringLimits(props.chain_notes.items)} (max ${props.chain_notes.maxItems} entries)`,
    `- \`blocked_harness_runs[].harness\`: ${describeStringLimits(blockedHarnessProps.harness)}`,
    `- \`blocked_harness_runs[].reason\`: ${describeStringLimits(blockedHarnessProps.reason)}`,
    `- \`blocked_harness_runs[].needed_for\`: ${describeStringLimits(blockedHarnessProps.needed_for)} (optional)`,
    `- \`blocked_prereqs[].kind\`: one of ${BLOCKED_PREREQ_KINDS.join(", ")}`,
    `- \`blocked_prereqs[].identifier_hint\`: ${describeStringLimits(blockedPrereqProps.identifier_hint)}, lowercase alphanumeric + ._- only (optional, no secrets — registry handle when known)`,
    `- \`blocked_prereqs[].reason\`: ${describeStringLimits(blockedPrereqProps.reason)} (free text screened for credentials at write time)`,
    `- \`blocked_prereqs[].evidence_summary\`: ${describeStringLimits(blockedPrereqProps.evidence_summary)} (optional, screened for credentials)`,
    `- \`blocked_prereqs[].needed_for\`: ${describeStringLimits(blockedPrereqProps.needed_for)} (optional)`,
    `- \`bypass_attempts[].condition\`: ${describeStringLimits(bypassAttemptProps.condition)}`,
    `- \`bypass_attempts[].attempt_summary\`: ${describeStringLimits(bypassAttemptProps.attempt_summary)} (max ${props.bypass_attempts.maxItems} entries)`,
  ];
  return lines.join("\n");
}

function substituteHandoffFieldLimits(document) {
  if (!document.includes(HANDOFF_FIELD_LIMITS_PLACEHOLDER)) return document;
  return document.split(HANDOFF_FIELD_LIMITS_PLACEHOLDER).join(renderHandoffFieldLimits());
}

module.exports = {
  BLOCKED_HARNESS_RUN_KINDS,
  BLOCKED_PREREQ_KINDS,
  CAPABILITY_PACK_VERIFIER_TABLE_PLACEHOLDER,
  HANDOFF_FIELD_LIMITS_PLACEHOLDER,
  EVALUATOR_PACK_CATALOGUE_PLACEHOLDER,
  renderCapabilityPackVerifierTable,
  renderClaudeEvaluatorPackCatalogue,
  renderCodexEvaluatorPackCatalogue,
  renderHandoffFieldLimits,
  substituteCapabilityPackVerifierTable,
  substituteClaudeEvaluatorPackCatalogue,
  substituteCodexEvaluatorPackCatalogue,
  substituteHandoffFieldLimits,
};
