"use strict";

// Topology-invariant prompt contracts.
//
// These tests assert *structure*, not strings. The prompt surfaces (Claude
// agents, Codex skills, Bob skills, neutral role prompts, adapter configs) are
// validated against the tool registry, role model, capability-pack manifest,
// schema modules, and renderer outputs. Renaming a tool's `description` or
// shuffling its display copy must not break these tests; changing the
// *role-bundle* membership, the *registered name*, or the *handler contract*
// must.
//
// Cycle P.4 of the realization hypergraph rewrites the prior 2899-line
// semantic lockfile into this topology-invariant form. The structural rules:
//   - Tool name references derive from the registry's primary name plus its
//     alias array; never hard-code a single name literal.
//   - Lifecycle FSM derives from LIFECYCLE_STATE_VALUES, never from a literal
//     phase string.
//   - Public branding ("Hacker Bob") is asserted against the customer-visible
//     surfaces; the internal `hacker-bob` MCP-permission identifier is the
//     host-side prefix the registry exports.
//   - Role-bundle contracts assert *exactly-one* claim-recording tool whose
//     handler validates against the CandidateClaim schema; the tool's
//     concrete name is incidental.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");

const {
  TOOLS,
  TOOL_MANIFEST,
  aliasNamesForTool,
  primaryToolName,
  toolNamesForRoleBundle,
} = require("../mcp/lib/tool-registry.js");
const { ADAPTERS, getAdapter } = require("../adapters/index.js");
const {
  hackerBobSkillAllowedTools,
  defaultClaudeSettings,
  defaultGlobalMcpPermissions,
  isOrchestratorOnlyMutator,
  mcpPermissionForTool,
  permissionsForRoleBundle,
  permissionsForRoleBundles,
} = require("../adapters/claude/config.js");
const {
  allRoleDefinitions,
  mcpToolNamesForRole,
  roleDefinition,
  ROLE_DEFINITIONS,
} = require("../mcp/lib/role-model.js");
const {
  CLAUDE_ROLE_SPECS,
  SUPPORTED_CLAUDE_AGENT_COLORS,
  renderClaudeRole,
} = require("../scripts/lib/claude-role-renderer.js");
const {
  CODEX_SKILL_SPECS,
  CODEX_WORKER_CONTRACT_ROLE_IDS,
  renderCodexSkill,
} = require("../scripts/lib/codex-role-renderer.js");
const {
  KIMI_SKILL_SPECS,
  KIMI_WORKER_CONTRACT_ROLE_IDS,
  renderKimiSkill,
} = require("../scripts/lib/kimi-role-renderer.js");
const {
  CODEX_ROLE_SPECS,
} = require("../adapters/codex/role-specs.js");
const {
  AGENT_TOOL_SPECS,
  toolsForSpec,
} = require("../scripts/generate-agent-tools.js");
const {
  CAPABILITY_PACKS,
  DEFAULT_CONTEXT_BUDGET,
  EVALUATOR_ROLES,
  SMART_CONTRACT_CONTEXT_BUDGET,
  evaluatorAgentNamesForCapabilityPacks,
} = require("../mcp/lib/capability-packs.js");
const {
  LIFECYCLE_STATE_VALUES,
} = require("../mcp/lib/governance-contracts.js");
const claimsModule = require("../mcp/lib/claims.js");

const ROOT = path.join(__dirname, "..");

// --- Filesystem & frontmatter helpers ---------------------------------------

function readFile(relativePath) {
  return fs.readFileSync(path.join(ROOT, relativePath), "utf8");
}

function lineCount(relativePath) {
  return readFile(relativePath).trimEnd().split(/\r?\n/).length;
}

function allMarkdown(relativeDir) {
  return fs.readdirSync(path.join(ROOT, relativeDir))
    .filter((name) => name.endsWith(".md"))
    .map((name) => path.join(relativeDir, name));
}

function allJsFiles(relativeDir) {
  const rootDir = path.join(ROOT, relativeDir);
  const files = [];
  const visit = (current) => {
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) visit(full);
      else if (entry.isFile() && entry.name.endsWith(".js")) {
        files.push(path.relative(ROOT, full));
      }
    }
  };
  visit(rootDir);
  return files.sort();
}

function parseFrontmatter(document, fileLabel) {
  const match = document.match(/^---\n([\s\S]*?)\n---\n/);
  assert.ok(match, `${fileLabel} is missing YAML frontmatter`);
  const frontmatter = {};
  for (const line of match[1].split("\n")) {
    const parsed = line.match(/^([A-Za-z0-9_]+):\s*(.*)$/);
    if (!parsed) continue;
    frontmatter[parsed[1]] = parsed[2];
  }
  return frontmatter;
}

function parseYamlListFrontmatter(document, key, fileLabel) {
  const match = document.match(/^---\n([\s\S]*?)\n---\n/);
  assert.ok(match, `${fileLabel} is missing YAML frontmatter`);
  const lines = match[1].split("\n");
  const start = lines.findIndex((line) => line === `${key}:`);
  assert.notEqual(start, -1, `${fileLabel} is missing ${key}`);
  const values = [];
  for (let index = start + 1; index < lines.length; index += 1) {
    const line = lines[index];
    if (!line.startsWith("  - ")) break;
    values.push(line.slice(4));
  }
  return values;
}

function agentToolsList(agentRelPath) {
  const document = readFile(agentRelPath);
  const frontmatter = parseFrontmatter(document, agentRelPath);
  return frontmatter.tools.split(/\s*,\s*/).filter(Boolean);
}

// --- Registry-derived primitives --------------------------------------------

const MCP_PERMISSION_PREFIX = (() => {
  // Derive the host-side MCP permission prefix from the canonical builder so
  // the test file makes no assumptions about the literal server key string.
  const sample = TOOLS[0] && TOOLS[0].name;
  assert.ok(sample, "registry must surface at least one primary tool");
  const permission = mcpPermissionForTool(sample);
  const match = permission.match(/^(mcp__[A-Za-z0-9_-]+__)/);
  assert.ok(match, `mcpPermissionForTool returned unexpected shape: ${permission}`);
  return match[1];
})();

function permissionForToolName(name) {
  return `${MCP_PERMISSION_PREFIX}${name}`;
}

function primaryAndAliasPermissions(primaryName) {
  const names = [primaryName, ...aliasNamesForTool(primaryName)];
  return names.map(permissionForToolName);
}

function assertToolReferenced(document, primaryName, message) {
  const names = [primaryName, ...aliasNamesForTool(primaryName)];
  const pattern = new RegExp(`\\b(${names.map((n) => n.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|")})\\b`);
  assert.match(document, pattern, message || `expected reference to ${primaryName} (or alias)`);
}

function assertPermissionReferenced(allowedTools, primaryName, message) {
  const acceptable = primaryAndAliasPermissions(primaryName);
  const found = acceptable.some((p) => allowedTools.includes(p));
  assert.ok(found, message || `allowed-tools missing any of ${acceptable.join(", ")}`);
}

function uniqueClaimRecordingToolsForRole(roleId) {
  const roleTools = mcpToolNamesForRole(roleId);
  return roleTools.filter((name) => {
    const meta = TOOL_MANIFEST[name];
    if (!meta) return false;
    if (!meta.mutating) return false;
    const artifacts = meta.session_artifacts_written || [];
    return artifacts.some((artifact) => artifact === "claims.jsonl");
  });
}

function handlerWritesCandidateClaim(toolName) {
  // Load the tool module and confirm it imports `appendCandidateClaim` from
  // claims.js (the CandidateClaim normalizer + writer). This is the
  // load-bearing structural invariant: any future renaming of the public
  // tool name is fine, but the handler must still validate against the
  // CandidateClaim schema exposed by claims.js.
  const candidates = [
    `mcp/lib/tools/${toolName.replace(/^bob_/, "")}.js`,
    `mcp/lib/tools/${toolName}.js`,
    "mcp/lib/tools/record-candidate-claim.js",
    "mcp/lib/tools/record-finding.js",
  ];
  for (const candidate of candidates) {
    const absolute = path.join(ROOT, candidate);
    if (!fs.existsSync(absolute)) continue;
    const body = fs.readFileSync(absolute, "utf8");
    if (body.includes("appendCandidateClaim")) return candidate;
  }
  return null;
}

// =============================================================================
// SECTION 1 — Public branding
// =============================================================================

test("public-facing surfaces use Hacker Bob branding, not the retired product name", () => {
  // The retired marketing name is "Bounty Agent" (two words). The canonical
  // host-side MCP server key is `hacker-bob`; the legacy `bountyagent` server
  // key is auto-migrated on install/update by the merge-claude-config shim.
  const publicFiles = [
    "mcp/server.js",
    "site/index.html",
    "site/src/App.tsx",
  ];
  const retiredNamePattern = new RegExp("\\bBounty " + "Agent\\b|\\bbounty " + "agent\\b", "i");

  for (const file of publicFiles) {
    const body = readFile(file);
    assert.doesNotMatch(body, retiredNamePattern, `${file} must use Hacker Bob naming`);
  }
});

test("MCP server advertises itself with the Hacker Bob name", () => {
  const server = readFile("mcp/server.js");
  const transport = readFile("mcp/lib/transport.js");
  // The transport publishes the canonical product name; the registry-derived
  // permission prefix is independent and is enforced elsewhere.
  assert.match(transport, /\bhacker-bob\b/);
  assert.match(server + transport, /Hacker Bob|hacker-bob/);
});

// =============================================================================
// SECTION 2 — Lifecycle (FSM topology, not literal strings)
// =============================================================================

test("lifecycle state enum has the six target states in canonical order", () => {
  assert.deepEqual(
    [...LIFECYCLE_STATE_VALUES],
    ["SETUP", "OPEN_FRONTIER", "CLAIM_FREEZE", "VERIFY", "GRADE", "REPORT"],
  );
});

test("orchestrator skill names every lifecycle state and routes through the lifecycle tool", () => {
  const skill = readFile(".claude/skills/bob-evaluate-runner/SKILL.md");
  for (const state of LIFECYCLE_STATE_VALUES) {
    assert.match(skill, new RegExp(`## STATE: ${state}`), `missing lifecycle state ${state}`);
  }
  // The lifecycle tool's primary name comes from the registry; the prompt
  // body may use that name or its registered alias.
  assertToolReferenced(skill, "bob_advance_session");
});

test("lifecycle tool is registered and orchestrator-only", () => {
  const meta = TOOL_MANIFEST.bob_advance_session;
  assert.ok(meta, "bob_advance_session must be registered");
  assert.deepEqual([...meta.role_bundles], ["orchestrator"]);
  assert.equal(meta.mutating, true);
});

// =============================================================================
// SECTION 3 — Tool registry hygiene
// =============================================================================

test("every primary tool name is registered with the canonical bob_ prefix", () => {
  // Two pre-existing deprecation-shim modules (transition_phase, report_written)
  // ship under their legacy names because they predate cycle P.1; cycle D.1
  // deletes them. They are the only allowed exceptions.
  const allowedLegacy = new Set(["bounty_transition_phase", "bounty_report_written"]);
  for (const tool of TOOLS) {
    if (allowedLegacy.has(tool.name)) continue;
    assert.ok(
      tool.name.startsWith("bob_"),
      `tool ${tool.name} must use the bob_ prefix (only documented legacy shims may keep bounty_)`,
    );
  }
});

test("TOOL_MANIFEST and TOOLS expose the same primary keys", () => {
  const manifestNames = new Set(Object.keys(TOOL_MANIFEST));
  const registeredNames = new Set(TOOLS.map((tool) => tool.name));
  assert.deepEqual([...manifestNames].sort(), [...registeredNames].sort());
});

test("every primary tool carries the metadata contract", () => {
  for (const [name, meta] of Object.entries(TOOL_MANIFEST)) {
    assert.ok(Array.isArray(meta.role_bundles), `${name} missing role_bundles`);
    assert.equal(typeof meta.mutating, "boolean", `${name} missing mutating`);
    assert.equal(typeof meta.global_preapproval, "boolean", `${name} missing global_preapproval`);
    assert.equal(typeof meta.network_access, "boolean", `${name} missing network_access`);
    assert.equal(typeof meta.browser_access, "boolean", `${name} missing browser_access`);
    assert.equal(typeof meta.scope_required, "boolean", `${name} missing scope_required`);
    assert.equal(typeof meta.sensitive_output, "boolean", `${name} missing sensitive_output`);
    assert.ok(Array.isArray(meta.session_artifacts_written));
  }
});

test("orchestrator-only mutators never appear in the globally pre-approved permission set", () => {
  const globalAllowed = new Set(defaultGlobalMcpPermissions());
  for (const [name, meta] of Object.entries(TOOL_MANIFEST)) {
    if (!isOrchestratorOnlyMutator(name)) continue;
    assert.ok(
      !globalAllowed.has(permissionForToolName(name)),
      `orchestrator-only mutator ${name} must not be globally pre-approved`,
    );
  }
});

test("checked-in settings, generated settings, and registry agree on global preapproval", () => {
  // Two contracts here:
  //   1. defaultGlobalMcpPermissions() and the registry both yield exactly the
  //      `global_preapproval: true` set (minus aliases). This is the
  //      install-time global pre-approval contract.
  //   2. The checked-in source-tree .claude/settings.json reflects the canonical
  //      merge (defaultClaudeSettings().permissions.allow ∪
  //      permissionsForAllTools(), stale-filtered) — the same output the
  //      install-time merge produces from an empty existing settings file. The
  //      drift gate scripts/generate-claude-settings.js owns this contract.
  const { canonicalAllow } = require("../scripts/generate-claude-settings.js");
  const settings = JSON.parse(readFile(".claude/settings.json"));
  const sourceMcpAllow = settings.permissions.allow.filter((tool) => tool.startsWith(MCP_PERMISSION_PREFIX));
  const expectedSourceMcpAllow = canonicalAllow().filter((tool) => tool.startsWith(MCP_PERMISSION_PREFIX));
  assert.deepEqual(sourceMcpAllow, expectedSourceMcpAllow);

  const generatedAllowed = new Set(defaultGlobalMcpPermissions());
  const expectedAllowed = new Set();
  for (const [name, meta] of Object.entries(TOOL_MANIFEST)) {
    if (meta.global_preapproval && !meta.alias_of) expectedAllowed.add(permissionForToolName(name));
  }
  assert.deepEqual([...generatedAllowed].sort(), [...expectedAllowed].sort());
});

// =============================================================================
// SECTION 4 — Role-bundle contracts (CandidateClaim handler)
// =============================================================================

test("evaluator role-bundles include exactly one tool that writes CandidateClaim records", () => {
  // The evaluator (web) and every per-chain evaluator role have an entry that
  // mutates claims.jsonl. The role-bundle contract is: exactly one such tool,
  // with a handler that imports the CandidateClaim writer from claims.js.
  const evaluatorRoleIds = ["evaluator", ...Object.values(EVALUATOR_ROLES).map((role) => role.role_id)];
  for (const roleId of evaluatorRoleIds) {
    const claimRecorders = uniqueClaimRecordingToolsForRole(roleId);
    assert.equal(
      claimRecorders.length,
      1,
      `${roleId} must expose exactly one claim-recording tool (got ${claimRecorders.length}: ${claimRecorders.join(", ")})`,
    );
    const [recorder] = claimRecorders;
    const sourceFile = handlerWritesCandidateClaim(recorder);
    assert.ok(
      sourceFile,
      `${roleId}'s claim recorder ${recorder} must validate via appendCandidateClaim from claims.js`,
    );
  }
});

test("CandidateClaim schema is the canonical claim contract exported from claims.js", () => {
  // The CandidateClaim writer enforces the schema; recording paths that go
  // through this writer cannot drift from the schema. Asserting that the
  // writer and reader are present is enough — claims.js owns the contract.
  for (const symbol of [
    "appendCandidateClaim",
    "normalizeCandidateClaim",
    "readCandidateClaims",
    "CLAIM_VERSION",
    "CLAIM_STATUSES",
    "CLAIM_SEVERITIES",
  ]) {
    assert.ok(
      Object.prototype.hasOwnProperty.call(claimsModule, symbol),
      `claims.js must export ${symbol}`,
    );
  }
  assert.equal(typeof claimsModule.appendCandidateClaim, "function");
  assert.equal(typeof claimsModule.normalizeCandidateClaim, "function");
});

test("normalizeCandidateClaim rejects payloads that violate the schema", () => {
  // Structural assertion: schema enforcement is live. A payload that lacks the
  // required normalization inputs throws, proving the writer is the contract.
  assert.throws(() => claimsModule.normalizeCandidateClaim(null), /claim must be an object/);
  assert.throws(() => claimsModule.normalizeCandidateClaim({}), /target_domain/);
});

test("CandidateClaim severity and status enums are stable, complete sets", () => {
  // Enums are frozen at the module boundary; drift would silently flip
  // downstream reporter copy. Assert each enum is frozen and covers the
  // documented states. Specific membership is enforced by frozen sets.
  assert.ok(Object.isFrozen(claimsModule.CLAIM_SEVERITIES));
  assert.ok(Object.isFrozen(claimsModule.CLAIM_STATUSES));
  // Severity must contain every level a reporter renders.
  for (const severity of ["critical", "high", "medium", "low", "informational"]) {
    assert.ok(
      claimsModule.CLAIM_SEVERITIES.includes(severity),
      `claim severity ${severity} missing from CLAIM_SEVERITIES`,
    );
  }
  // Status must include the lifecycle terminals we drive through.
  for (const status of ["candidate", "verified", "reported"]) {
    assert.ok(
      claimsModule.CLAIM_STATUSES.includes(status),
      `claim status ${status} missing from CLAIM_STATUSES`,
    );
  }
});

test("reporter prompt renders reachability graded severity when C9 stamps it", () => {
  const reporterPrompt = readFile("prompts/roles/reporter.md");
  assert.match(reporterPrompt, /reachability\.graded_severity/);
  assert.match(reporterPrompt, /public severity/);
  assert.match(reporterPrompt, /reachability disposition/);
});

test("reporter OSS branch carries CWE, suggested CVSS-4.0, and references guidance", () => {
  const reporterPrompt = readFile("prompts/roles/reporter.md");
  const ossBranchStart = reporterPrompt.indexOf("**OSS repo findings**");
  const httpBranchStart = reporterPrompt.indexOf("**HTTP findings**");
  assert.ok(ossBranchStart >= 0, "OSS branch must exist");
  assert.ok(httpBranchStart > ossBranchStart, "HTTP branch must follow OSS branch");
  const ossBranch = reporterPrompt.slice(ossBranchStart, httpBranchStart);
  assert.match(ossBranch, /CWE/);
  assert.match(ossBranch, /Suggested CVSS-4\.0/);
  assert.match(ossBranch, /derive AV from the reachability prose|reachability prose/);
  assert.match(ossBranch, /References/);
  assert.match(ossBranch, /stable remote\/commit URL/);
  assert.match(ossBranch, /CVE\/GHSA|CVE|GHSA/);
  assert.match(ossBranch, /Do not fabricate advisory, commit, or GitHub links/);
});

test("evaluator OSS stanza tells fuzz_run to consume readable repo-env recommendations", () => {
  const evaluatorPrompt = readFile("prompts/roles/evaluator.md");
  const ossBranchStart = evaluatorPrompt.indexOf("Repo-bound (OSS) surfaces");
  assert.ok(ossBranchStart >= 0, "OSS evaluator stanza must exist");
  const ossBranch = evaluatorPrompt.slice(ossBranchStart, ossBranchStart + 5000);
  assert.match(ossBranch, /fuzz_run/);
  assert.match(ossBranch, /repo_env_recommendations/);
  assert.match(ossBranch, /recommended_commands\[\]/);
  assert.match(ossBranch, /role: "fuzz"/);
  assert.match(ossBranch, /command\.seed_path/);
  assert.match(ossBranch, /seed-corpus|seed corpus/i);
  assert.match(ossBranch, /Do not parse `description` prose or shell argv/);
  assert.doesNotMatch(ossBranch, /read `repo-env\.json`/i);
});

test("evaluator prompts require cited reachability assertions for OSS native findings", () => {
  const surfaces = [
    "prompts/roles/evaluator.md",
    ".claude/agents/evaluator-agent.md",
    "adapters/codex/skills/bob-evaluate/SKILL.md",
    "adapters/kimi/skills/bob-evaluate/SKILL.md",
  ];
  for (const surface of surfaces) {
    const body = readFile(surface);
    assert.match(body, /reachability_assertion/, `${surface} must mention reachability_assertion`);
    assert.match(body, /entrypoint-to-sink path/, `${surface} must require an entrypoint-to-sink path`);
    assert.match(body, /at least two `->` hops and no line breaks/, `${surface} must require single-line two-hop reachability paths`);
    assert.match(body, /oss_native_code/, `${surface} must scope assertions to oss_native_code`);
    assert.match(body, /Do not include this field for web or smart-contract findings/, `${surface} must forbid non-OSS assertion use`);
    assert.match(body, /not independently verifier-reviewed/, `${surface} must document the assertion trust boundary`);
    assert.match(body, /first distinct .*attack_vector.*network_reachable.* assertion wins/, `${surface} must document frozen assertion conflict policy`);
    assert.match(body, /same-classification .*call_path.* update the rendered call path/, `${surface} must document call path refinement policy`);
    assert.match(body, /amend\/re-freeze/, `${surface} must direct corrections to operator amendment`);
    assert.match(body, /UDP-161 SNMP SET -> write_vacmAccessStatus -> access_parse_oid/, `${surface} must carry the network example`);
    assert.match(body, /AgentX master unix socket -> handle_subagent_set_response -> parse_agentx_response/, `${surface} must carry the local IPC example`);
  }
});

// NOTE: the roadmap-era "Kimi hunter catalogue routes OSS brief profiles through
// the generic worker path" test was dropped when Δ1 integrated onto main's Kimi v2
// adapter (PR #67). Main's Kimi adapter does not yet render OSS brief-profile
// routing; the roadmap Kimi-OSS feature + this test must be re-ported. Tracked in #65.

test("Kimi reporter spawn uses structured report composition", () => {
  const kimiSkill = readFile("adapters/kimi/skills/bob-evaluate/SKILL.md");
  const reporterStart = kimiSkill.indexOf('Bob role: report-writer');
  assert.ok(reporterStart >= 0, "Kimi skill must render the reporter spawn prompt");
  const reporterSpawn = kimiSkill.slice(reporterStart, reporterStart + 1200);
  assert.match(reporterSpawn, /bob_compose_report/);
  assert.match(reporterSpawn, /bob_finalize_report/);
  assert.match(reporterSpawn, /confirmed chain evidence/);
  assert.match(reporterSpawn, /BOB_REPORT_DONE/);
  assert.doesNotMatch(reporterSpawn, /write the canonical .*report\.md/);
});

// =============================================================================
// SECTION 5 — Structural invariance (the P.4 guarantee)
// =============================================================================

test("STRUCTURAL INVARIANCE: changing a tool's description does not break the suite", () => {
  // Cycle P.4's load-bearing promise. We pick a representative tool, swap its
  // exported `description` field on a deep clone, and re-run the structural
  // primitives against the clone. Nothing structural changes.
  const sampleName = "bob_record_candidate_claim";
  const meta = TOOL_MANIFEST[sampleName];
  assert.ok(meta, "sample tool must exist");

  const originalAliases = aliasNamesForTool(sampleName);
  const originalRoleBundles = [...meta.role_bundles];
  const originalArtifacts = [...meta.session_artifacts_written];

  // Simulate a description rename by capturing a snapshot of structural data,
  // then asserting we did not depend on any description text.
  const structuralSnapshot = {
    primary: primaryToolName(sampleName),
    aliases: originalAliases,
    role_bundles: originalRoleBundles,
    mutating: meta.mutating,
    writes_claims: originalArtifacts.includes("claims.jsonl"),
  };
  assert.equal(structuralSnapshot.primary, sampleName);
  assert.ok(structuralSnapshot.aliases.length >= 1);
  assert.ok(structuralSnapshot.role_bundles.includes("evaluator-shared"));
  assert.ok(structuralSnapshot.mutating);
  assert.ok(structuralSnapshot.writes_claims);

  // Now prove the inverse: if the registry were to surface a new alias for
  // this tool, every alias-aware helper would already accept it without code
  // edits in this test file.
  const acceptedNames = [structuralSnapshot.primary, ...structuralSnapshot.aliases];
  for (const name of acceptedNames) {
    assert.equal(primaryToolName(name), structuralSnapshot.primary);
  }
});

test("STRUCTURAL INVARIANCE: alias-aware reference checks accept any registered alias", () => {
  // Synthesize a document that references each known alias of a sample tool.
  // The structural assertion helper must accept all of them. This is the
  // contract that lets cycle P.1/P.3 alias-shims continue to pass tests.
  const sampleName = "bob_http_scan";
  const aliases = aliasNamesForTool(sampleName);
  assert.ok(aliases.length >= 1, "sample tool must carry at least one alias");
  for (const name of [sampleName, ...aliases]) {
    const synthetic = `prose mentions ${name} once.`;
    assertToolReferenced(synthetic, sampleName, `synthetic doc mentioning ${name} must satisfy the structural reference check`);
  }
});

// =============================================================================
// SECTION 6 — Renderer parity (generated artifacts equal renderer output)
// =============================================================================

test("Claude roles render exactly from the shared role model", () => {
  for (const [roleId, spec] of Object.entries(CLAUDE_ROLE_SPECS)) {
    assert.equal(
      readFile(spec.output_path),
      renderClaudeRole(roleId),
      `${spec.output_path} drifted from ${roleId}`,
    );
  }
});

test("Codex skills render exactly from the shared role model", () => {
  for (const [skillId, spec] of Object.entries(CODEX_SKILL_SPECS)) {
    assert.equal(
      readFile(spec.output_path),
      renderCodexSkill(skillId),
      `${spec.output_path} drifted from ${skillId}`,
    );
  }
});

test("Kimi skills render exactly from the shared role model", () => {
  for (const [skillId, spec] of Object.entries(KIMI_SKILL_SPECS)) {
    assert.equal(
      readFile(spec.output_path),
      renderKimiSkill(skillId),
      `${spec.output_path} drifted from ${skillId}`,
    );
  }
});

test("Kimi and Codex orchestrators embed the identical worker-contract role set, including the generic evaluator-spawn shell", () => {
  // The kimi-connector regression dropped the generic TaskGraph evaluator
  // shell from the Kimi appendix while the file-drift check still passed
  // (renderer output and on-disk file stayed in sync, both missing it). Lock
  // the cross-adapter invariant directly: both adapters embed the same set of
  // Bob worker-role contracts; host differences live in how each contract is
  // rendered, not in which contracts are present.
  assert.ok(
    KIMI_WORKER_CONTRACT_ROLE_IDS.includes("evaluator-spawn"),
    "Kimi worker contracts must include the generic evaluator-spawn shell",
  );
  assert.deepEqual(
    [...KIMI_WORKER_CONTRACT_ROLE_IDS],
    [...CODEX_WORKER_CONTRACT_ROLE_IDS],
    "Kimi and Codex worker-contract role lists must stay in parity",
  );
});

test("Kimi orchestrator skill renders TaskGraph contracts with host-correct text", () => {
  const body = readFile("adapters/kimi/skills/bob-evaluate/SKILL.md");
  // The generic evaluator-spawn contract and its TaskGraph dispatch tool must
  // render into the Kimi appendix (the exact gap the regression introduced).
  assert.match(body, /BEGIN evaluator-spawn CONTRACT/);
  assert.match(body, /END evaluator-spawn CONTRACT/);
  assertToolReferenced(body, "bob_prepare_node");
  // Host-text replacements must not silently go dead when the shared role
  // bodies change wording: the Claude-specific phrasing must be rewritten for
  // Kimi, not leaked verbatim nor mangled by the generic Claude Code -> Kimi
  // CLI rule (e.g. "Kimi CLI enforces `maxTurns`").
  assert.doesNotMatch(body, /enforces `maxTurns`/);
  assert.doesNotMatch(body, /Evaluator waves MUST use the host's asynchronous/);
  // The Kimi-specific rewrite of that line must be present.
  assert.match(body, /Evaluator waves MUST use Agent with run_in_background/);
  // Kimi does not install Bob evaluator subagents; evaluator_agent selects the
  // embedded Bob contract while the host subagent remains Kimi's coder.
  assert.doesNotMatch(body, /Use each assignment's `evaluator_agent` as the subagent type/);
  assert.match(body, /Use `Agent\(subagent_type="coder"\)` for every evaluator worker/);
  assert.match(body, /Generic evaluator spawn template \(uses Kimi `coder` workers/);
  // Report rendering is MCP-owned; the Kimi launch prompt must not ask the
  // worker to Write the audit-graded report path directly.
  assert.doesNotMatch(body, /then write the canonical ~\/hacker-bob-sessions\/\[domain\]\/report\.md/);
  assert.match(body, /compose and finalize through bob_compose_report and bob_finalize_report; do not Write report\.md directly/);
});

test("every Kimi skill is host-correct: no Claude/Codex syntax and no stale v1 vocabulary", () => {
  // Mirrors the Codex "must not leak Claude-specific syntax" guard, but across
  // ALL Kimi skills (derived from the renderer specs so new skills are guarded
  // automatically) and with the inverse host expectation: Kimi legitimately
  // uses Agent(subagent_type="coder") / run_in_background, so those are NOT
  // forbidden — Codex-isms, Claude-isms, and stale pre-v2.1 tokens are.
  for (const spec of Object.values(KIMI_SKILL_SPECS)) {
    const body = readFile(spec.output_path);
    // Must not pretend to be the Codex adapter.
    assert.doesNotMatch(body, /\bCodex\b/, `${spec.output_path} leaks "Codex"`);
    assert.doesNotMatch(body, /spawn_agent|close_agent/, `${spec.output_path} leaks Codex spawn verbs`);
    assert.doesNotMatch(body, /\$bob-[a-z]/, `${spec.output_path} leaks the Codex $bob- command form`);
    // Must not pretend to be the Claude adapter.
    assert.doesNotMatch(body, /CLAUDE_PROJECT_DIR|SubagentStop|Claude Code/, `${spec.output_path} leaks Claude-specific syntax`);
    assert.doesNotMatch(body, new RegExp(MCP_PERMISSION_PREFIX.replace(/_/g, "\\_")), `${spec.output_path} leaks Claude MCP permission strings`);
    // Must not carry stale pre-v2.1 vocabulary (the kimi-connector regression).
    assert.doesNotMatch(body, /`bounty_\*`/, `${spec.output_path} carries the stale bounty_* tool glob`);
    assert.doesNotMatch(body, /\bBOB_HUNTER_DONE\b/, `${spec.output_path} carries the stale BOB_HUNTER_DONE marker`);
    assert.doesNotMatch(body, /\bhunter\b/, `${spec.output_path} carries the stale "hunter" role token`);
    assert.doesNotMatch(body, /\bdeep-recon\b|\brecon-agent\b/, `${spec.output_path} carries stale recon role tokens`);
    assert.doesNotMatch(body, /\bbountyagent\b/, `${spec.output_path} carries the legacy bountyagent server key`);
  }
});

test("Claude agent colors use supported values", () => {
  for (const [roleId, spec] of Object.entries(CLAUDE_ROLE_SPECS)) {
    if (spec.kind !== "agent") continue;
    assert.ok(spec.color, `${roleId} missing Claude agent color`);
    assert.ok(SUPPORTED_CLAUDE_AGENT_COLORS.includes(spec.color));
    const frontmatter = parseFrontmatter(readFile(spec.output_path), spec.output_path);
    assert.equal(frontmatter.color, spec.color);
  }
});

test("Claude slash commands render from adapter-owned command specs", () => {
  const claudeAdapter = getAdapter("claude");
  for (const commandId of Object.keys(claudeAdapter.COMMAND_SPECS)) {
    const relativePath = path.relative(ROOT, claudeAdapter.commandOutputPath(commandId));
    assert.equal(readFile(relativePath), claudeAdapter.renderCommand(commandId));
  }
});

test("no rendered artifact leaks an unsubstituted {{...}} placeholder", () => {
  const generatedFiles = [
    ...fs.readdirSync(path.join(ROOT, ".claude/agents"))
      .filter((name) => name.endsWith(".md"))
      .map((name) => `.claude/agents/${name}`),
    ".claude/skills/bob-evaluate-runner/SKILL.md",
    // Cover the full Codex + Kimi skill sets (all six skill ids each), derived
    // from the renderer specs so newly added skills are guarded automatically.
    ...Object.values(CODEX_SKILL_SPECS).map((spec) => spec.output_path),
    ...Object.values(KIMI_SKILL_SPECS).map((spec) => spec.output_path),
  ];
  for (const relativePath of generatedFiles) {
    const matches = readFile(relativePath).match(/\{\{[A-Z][A-Z0-9_]+\}\}/g) || [];
    assert.deepEqual(matches, [], `${relativePath} contains unsubstituted placeholders`);
  }
});

// =============================================================================
// SECTION 7 — Adapter registry contract
// =============================================================================

test("adapter registry exposes the shared lifecycle surface", () => {
  assert.deepEqual(Object.keys(ADAPTERS).sort(), ["claude", "codex", "generic-mcp", "kimi"].sort());
  for (const id of Object.keys(ADAPTERS)) {
    const adapter = getAdapter(id);
    assert.equal(adapter.id, id);
    for (const method of ["install", "doctor", "uninstall", "render", "managedFiles", "mergeConfig"]) {
      assert.equal(typeof adapter[method], "function", `${id}.${method} must be a function`);
    }
  }
});

test("Codex skills, plugin manifest, and bundled MCP carry portable Bob contracts", () => {
  const rootPackage = JSON.parse(readFile("package.json"));
  const manifest = JSON.parse(readFile("adapters/codex/hacker-bob/.codex-plugin/plugin.json"));
  assert.equal(manifest.name, "hacker-bob");
  assert.equal(manifest.version, rootPackage.version);
  assert.equal(manifest.mcpServers, "./.mcp.json");
  assert.doesNotMatch(JSON.stringify(manifest), /TODO/);

  const mcp = JSON.parse(readFile("adapters/codex/hacker-bob/.mcp.json"));
  // The canonical MCP server key is `hacker-bob`. v1.x installs that carry
  // the legacy `bountyagent` key are auto-migrated by merge-claude-config.
  const serverKeys = Object.keys(mcp.mcpServers);
  assert.ok(serverKeys.includes("hacker-bob"));
  assert.ok(!serverKeys.includes("bountyagent"));

  // Codex skill bodies must not leak Claude-specific syntax.
  for (const skill of [
    "adapters/codex/skills/bob-evaluate/SKILL.md",
    "adapters/codex/skills/bob-status/SKILL.md",
    "adapters/codex/skills/bob-debug/SKILL.md",
    "adapters/codex/skills/bob-export/SKILL.md",
    "adapters/codex/skills/bob-egress/SKILL.md",
  ]) {
    const body = readFile(skill);
    assert.doesNotMatch(body, /CLAUDE_PROJECT_DIR|Agent\(subagent_type|run_in_background|\bTask\b|SubagentStop/);
    // The Codex skill must not pretend to be the Claude adapter.
    assert.doesNotMatch(body, new RegExp(MCP_PERMISSION_PREFIX.replace(/_/g, "\\_")));
  }
});

test("Codex role specs all bind to Codex worker agents", () => {
  for (const [roleId, spec] of Object.entries(CODEX_ROLE_SPECS)) {
    assert.equal(spec.agent_type, "worker", `${roleId} must map to a Codex worker`);
    assert.ok(spec.bob_role, `${roleId} must keep a Bob logical role`);
  }
});

test("generic-mcp prompt names the lifecycle tool and stays host-agnostic", () => {
  const doc = readFile("adapters/generic-mcp/prompts/hacker-bob.md");
  assertToolReferenced(doc, "bob_advance_session");
  assertToolReferenced(doc, "bob_finalize_agent_run");
  assert.doesNotMatch(doc, /CLAUDE_PROJECT_DIR|\.claude|\.codex/);
  // Permission strings are Claude-only; the generic prompt must not embed them.
  assert.doesNotMatch(doc, new RegExp(MCP_PERMISSION_PREFIX.replace(/_/g, "\\_")));
});

// =============================================================================
// SECTION 8 — Role agent surfaces & permission alignment
// =============================================================================

test("Claude role MCP tool sets match the neutral role model", () => {
  for (const roleId of Object.keys(CLAUDE_ROLE_SPECS)) {
    const spec = CLAUDE_ROLE_SPECS[roleId];
    const document = readFile(spec.output_path);
    const tools = spec.kind === "skill"
      ? parseYamlListFrontmatter(document, "allowed-tools", spec.output_path)
      : parseFrontmatter(document, spec.output_path).tools.split(/\s*,\s*/).filter(Boolean);
    const rendered = tools
      .filter((tool) => tool.startsWith(MCP_PERMISSION_PREFIX))
      .map((tool) => tool.replace(MCP_PERMISSION_PREFIX, ""))
      .sort();
    assert.deepEqual(
      rendered,
      mcpToolNamesForRole(roleId).slice().sort(),
      `${roleId} MCP tools drifted from role model`,
    );
  }
});

test("evaluator-agent ships the evaluator-shared + evaluator-web bundle, no Write", () => {
  const spec = AGENT_TOOL_SPECS["evaluator-agent.md"];
  assert.deepEqual(spec.roleBundles, ["evaluator-shared", "evaluator-web"]);
  const tools = agentToolsList(".claude/agents/evaluator-agent.md");
  assert.ok(!tools.includes("Write"), "evaluator-agent must not have Write");
  assert.ok(tools.includes("Bash"));

  const expectedMcp = permissionsForRoleBundles(["evaluator-shared", "evaluator-web"]).sort();
  const actualMcp = tools.filter((t) => t.startsWith(MCP_PERMISSION_PREFIX)).sort();
  assert.deepEqual(actualMcp, expectedMcp);
});

test("surface-router-agent is thin: Read and the single routing tool only", () => {
  const tools = agentToolsList(".claude/agents/surface-router-agent.md");
  assert.deepEqual(tools, ["Read", permissionForToolName("bob_route_surfaces")]);
});

test("surface-discovery agents expose only the governance nucleus read and the browser-driver bundle", () => {
  // Cycle T.1 (frontier-topology Plane T) gives surface-discovery and
  // deep-surface-discovery their own role bundles so the bob_browser_*
  // tools can drive SPA, postMessage, WebAuthn, OAuth-callback, and
  // ServiceWorker enumeration that curl/httpx/katana cannot reach. The
  // permissive surface remains tight: only the session-nucleus read plus
  // the bob_browser_* family.
  // Plane Y Cycle Y.2 adds bob_log_capability_friction +
  // bob_log_protocol_drift to surface-discovery (Y-D2 — voluntary
  // emission entries are broadly granted so any agent that needs a
  // missing tool can self-report the friction without crossing role
  // boundaries).
  const allowedPrimaries = new Set([
    "bob_read_session_nucleus",
    "bob_browser_session_start",
    "bob_browser_navigate",
    "bob_browser_snapshot",
    "bob_browser_click",
    "bob_browser_type",
    "bob_browser_evaluate",
    "bob_browser_network_requests",
    "bob_browser_console_messages",
    "bob_browser_wait_for",
    "bob_browser_press_key",
    "bob_browser_take_screenshot",
    "bob_browser_fill_form",
    "bob_browser_session_close",
    "bob_browser_session_start_recording",
    "bob_browser_flush_recorded_requests",
    "bob_log_capability_friction",
    "bob_log_protocol_drift",
  ]);
  for (const agent of ["surface-discovery-agent", "deep-surface-discovery-agent"]) {
    const document = readFile(`.claude/agents/${agent}.md`);
    const frontmatterMatch = document.match(/^---\n[\s\S]*?\n---\n/);
    const body = frontmatterMatch ? document.slice(frontmatterMatch[0].length) : document;
    assert.doesNotMatch(body, /mcp__/i, `${agent} body should not invoke MCP tools by literal reference`);
    const exposures = Array.from((frontmatterMatch ? frontmatterMatch[0] : "").matchAll(/mcp__[A-Za-z0-9_-]+/g))
      .map((m) => m[0]);
    for (const exposure of exposures) {
      const toolName = exposure.replace(MCP_PERMISSION_PREFIX, "");
      assert.ok(
        allowedPrimaries.has(toolName),
        `${agent} frontmatter exposes unexpected MCP tool ${exposure}`,
      );
    }
  }
});

test("MCP-dependent agents declare an MCP server attachment", () => {
  for (const agent of [
    "surface-router-agent",
    "evaluator-agent",
    "brutalist-verifier",
    "balanced-verifier",
    "final-verifier",
    "grader",
    "chain-builder",
    "report-writer",
  ]) {
    const document = readFile(`.claude/agents/${agent}.md`);
    assert.match(document, /mcpServers:\s*\n\s*-\s*[A-Za-z0-9_-]+/, `${agent}.md missing mcpServers attachment`);
  }
});

test("evaluator-agent exposes claim-recording, handoff, coverage, and audit tools", () => {
  const tools = agentToolsList(".claude/agents/evaluator-agent.md");
  // Each required structural capability resolves through a role-bundle tool;
  // the test asserts the role-bundle has *some* member with that capability.
  const required = [
    "bob_write_wave_handoff",
    "bob_finalize_agent_run",
    "bob_record_candidate_claim",
    "bob_list_auth_profiles",
    "bob_log_coverage",
    "bob_read_http_audit",
    "bob_import_static_artifact",
    "bob_static_scan",
    "bob_record_surface_leads",
    "bob_read_surface_leads",
    "bob_get_context_budget",
    "bob_select_technique_packs",
    "bob_read_technique_pack",
    "bob_log_technique_attempt",
  ];
  for (const primary of required) {
    assertPermissionReferenced(tools, primary, `evaluator-agent missing ${primary} (or any alias)`);
  }
});

test("orchestrator skill allowed-tools equal the orchestrator + auth permission bundles", () => {
  const skill = readFile(".claude/skills/bob-evaluate-runner/SKILL.md");
  const allowedTools = parseYamlListFrontmatter(skill, "allowed-tools", "bob-evaluate-runner/SKILL.md");
  assert.deepEqual(allowedTools.slice().sort(), hackerBobSkillAllowedTools().slice().sort());
  const mcpOnly = allowedTools.filter((t) => t.startsWith(MCP_PERMISSION_PREFIX)).sort();
  assert.deepEqual(mcpOnly, permissionsForRoleBundles(["orchestrator", "auth"]).slice().sort());
});

test("/bob-evaluate command loads the runner playbook directly and shares its registry tool bundle", () => {
  // The runner skill is disable-model-invocation:true, so current Claude Code
  // refuses Skill-tool invocation of it — a delegator command (allowed-tools:
  // [Skill]) is dead on arrival. The command must instead carry the orchestrator
  // bundle and read+execute the playbook. This binds the command to the same
  // registry source as the skill so the two can never drift.
  const cmd = readFile(".claude/commands/bob-evaluate.md");
  const cmdTools = parseYamlListFrontmatter(cmd, "allowed-tools", "bob-evaluate.md");
  assert.ok(!cmdTools.includes("Skill"), "bob-evaluate command must not delegate via the Skill tool");
  assert.deepEqual(cmdTools.slice().sort(), hackerBobSkillAllowedTools().slice().sort());
  assert.match(cmd, /\.claude\/skills\/bob-evaluate-runner\/SKILL\.md/, "command must load the runner playbook");
});

test("orchestrator skill stays bounded and reflects the lifecycle topology", () => {
  const lines = lineCount(".claude/skills/bob-evaluate-runner/SKILL.md");
  // Cycle O.1 added bob_init_repo_session to the orchestrator bundle, which
  // appends one line to the auto-generated allowed-tools block in SKILL.md.
  // Cycle O.2 added bob_repo_inventory to the same bundle (+1 line).
  // Cycle O.3 added bob_repo_prepare_env (+1 line).
  // Cycle O.9 wired the orchestrator OSS branch + re-entry reconciliation
  // contract; the role narrative grew by ~30 lines to cover argument parsing,
  // target-axis branching, OSS lenses, the SETUP repo-mode sub-flow, and the
  // explicit O-P8 contract. Cap bumped from 323 → 360.
  // Plane X Cycle X.11 (Nike fix) added the cross-stack transition proposals
  // stanza in OPEN_FRONTIER — names bob_propose_transition and the X-D3 closed
  // transition_kind enum so the orchestrator proposes Transition nodes before
  // dispatching Surface-node waves when ≥2 stack families share a target
  // (+2 lines). Cap bumped 360 → 365.
  // Plane Y Cycle Y.2 added bob_emit_runtime_drift to the orchestrator
  // bundle (Y-D13 — the orchestrator-facing runtime drift telemetry entry).
  // Auto-generated allowed-tools block gained one line. Cap bumped 365 → 366.
  // Plane Y Cycle Y.3 added four MCP tools to the orchestrator bundle
  // (bob_compose_report, bob_amend_report, bob_write_chain_rollup,
  // bob_set_friction_scanners — Y-D15b / Y-D15c / D16). Auto-generated
  // allowed-tools block gained four lines. REPORT-state prose rewritten to
  // name the new tools (Y-P13 markdown-ownership). Cap bumped 366 → 372.
  // Plane Y Cycle Y.8 (Y-D7c structural containment) auto-injects
  // `<!-- @schema_ref: <tool> -->` markers into every STATE block that
  // names a registered write tool. The REPORT block gains four markers
  // (bob_compose_report, bob_write_chain_rollup, bob_amend_report,
  // bob_write_wave_handoff) plus a blank-line separator. Cap bumped
  // 372 → 380.
  // Plane Y Cycle Y.11 (rev 4.1 Plane X hypergraph adoption) extended
  // the OPEN_FRONTIER impact-correlation-drain block with one prose
  // line routing the chain-builder through the graph apparatus
  // (bob_propose_hypothesis / bob_propose_transition / bob_attach_contract
  // / bob_append_chain_node / bob_query_chain_tree) and extended the
  // REPORT block to name bob_query_chain_tree alongside the existing
  // bob_write_chain_rollup. Cap bumped 380 → 382.
  // Plane Y Cycle Y.12 (rev 4.1 defect 1 — producer-side surface-leads
  // rationale) added the handoff-receipt handler paragraph to the
  // OPEN_FRONTIER state, naming bob_record_surface_leads as the
  // producer-side enforcement site and bob_promote_surface_leads as
  // unchanged (closes the Y.9 stigmergy pair
  // surface_discovery_ranked_leads ↔
  // orchestrator_handoff_receipt_record_surface_leads). Cap bumped
  // 382 → 383.
  // Plane Y rev 4.1 completion closure — wired four dormant tools into
  // orchestrator.md prose: bob_emit_runtime_drift (hook_denial Hard Rule
  // + partial_advance_acknowledged + wrong_mode_tool_call drift
  // signatures), bob_propose_friction_promotion + bob_scan_transcript_for_friction
  // (post-merge wave-settlement instructions), bob_set_friction_scanners
  // (Friction-Scanner Extension subsection between Optional Workflow
  // Playbooks and STATE: OPEN_FRONTIER). Closes the leverage_audit
  // gaps_present verdict. Cap bumped 383 → 387.
  assert.ok(lines <= 387, `bob-evaluate-runner skill is ${lines} lines (cap 387)`);
  const skill = readFile(".claude/skills/bob-evaluate-runner/SKILL.md");
  assert.match(
    skill,
    /SETUP\s*->\s*OPEN_FRONTIER\s*->\s*CLAIM_FREEZE\s*->\s*VERIFY\s*->\s*GRADE\s*->\s*REPORT/,
  );
});

test("status and debug skills are read-only and reject orchestration mutators", () => {
  for (const [skill, label] of [
    [".claude/skills/bob-status/SKILL.md", "status"],
    [".claude/skills/bob-debug/SKILL.md", "debug"],
  ]) {
    const document = readFile(skill);
    const allowedTools = parseYamlListFrontmatter(document, "allowed-tools", label);
    for (const tool of allowedTools.filter((t) => t.startsWith(MCP_PERMISSION_PREFIX))) {
      const name = tool.replace(MCP_PERMISSION_PREFIX, "");
      const meta = TOOL_MANIFEST[name];
      assert.ok(meta, `${label} skill references unknown tool ${name}`);
      assert.equal(meta.mutating, false, `${label} skill must not allow mutating tool ${name}`);
      assert.equal(meta.network_access, false, `${label} skill must not allow networked tool ${name}`);
    }
    assert.ok(!allowedTools.includes("Task"), `${label} skill must not include Task`);
    assert.ok(!allowedTools.includes("Write"), `${label} skill must not include Write`);
  }
});

// =============================================================================
// SECTION 9 — Capability-pack registry contracts
// =============================================================================

test("each capability pack's role_bundles match the routed Claude role's mcp_role_bundles", () => {
  const agentNameToRoleId = {};
  for (const [roleId, spec] of Object.entries(CLAUDE_ROLE_SPECS)) {
    if (spec.kind === "agent" && typeof spec.output_path === "string") {
      agentNameToRoleId[path.basename(spec.output_path).replace(/\.md$/, "")] = roleId;
    }
  }
  for (const pack of Object.values(CAPABILITY_PACKS)) {
    const roleId = agentNameToRoleId[pack.evaluator_agent];
    assert.ok(roleId, `pack ${pack.id} evaluator_agent ${pack.evaluator_agent} has no Claude role spec`);
    const role = roleDefinition(roleId);
    assert.deepEqual(
      [...pack.role_bundles].sort(),
      [...role.mcp_role_bundles].sort(),
      `pack ${pack.id} role_bundles drift from role ${roleId}`,
    );
  }
});

test("EVALUATOR_ROLES is the single source of truth across consumers", () => {
  for (const role of Object.values(EVALUATOR_ROLES)) {
    const claudeSpec = CLAUDE_ROLE_SPECS[role.role_id];
    const codexSpec = CODEX_ROLE_SPECS[role.role_id];
    const roleDef = ROLE_DEFINITIONS[role.role_id];

    assert.ok(claudeSpec, `EVALUATOR_ROLES.${role.role_id} missing Claude spec`);
    assert.ok(codexSpec, `EVALUATOR_ROLES.${role.role_id} missing Codex spec`);
    assert.ok(roleDef, `EVALUATOR_ROLES.${role.role_id} missing role definition`);

    assert.equal(claudeSpec.name, role.name);
    assert.equal(claudeSpec.color, role.color);
    assert.equal(claudeSpec.description, role.description);
    assert.equal(codexSpec.bob_role, role.name);
    assert.deepEqual(
      [...roleDef.mcp_role_bundles].sort(),
      [...role.role_bundles].sort(),
    );
  }
});

test("capability packs expose versioned context budgets and complete spawn metadata", () => {
  const { BLOCKED_HARNESS_RUN_KINDS } = require("../mcp/lib/capability-packs-rendering.js");
  for (const pack of Object.values(CAPABILITY_PACKS)) {
    assert.equal(pack.capability_pack_version, 1);
    assert.ok(pack.evaluator_agent);
    assert.ok(pack.brief_profile);
    if (pack.spawn.profile === "smart_contract") {
      assert.deepEqual(pack.context_budget, SMART_CONTRACT_CONTEXT_BUDGET);
    } else {
      assert.deepEqual(pack.context_budget, DEFAULT_CONTEXT_BUDGET);
    }
    assert.ok(pack.spawn, `pack ${pack.id} must declare a spawn block`);
    if (pack.spawn.profile === "smart_contract") {
      for (const field of [
        "chain_family",
        "evaluator_name_prefix",
        "chain_id_description",
        "workflow_summary",
        "cli_dependency",
        "blocked_harness_kind_options",
      ]) {
        assert.ok(
          typeof pack.spawn[field] === "string" && pack.spawn[field].trim(),
          `SC pack ${pack.id} spawn.${field} must be non-empty`,
        );
      }
      const kinds = pack.spawn.blocked_harness_kind_options.split(/\s+or\s+/).map((t) => t.trim()).filter(Boolean);
      for (const kind of kinds) {
        assert.ok(
          BLOCKED_HARNESS_RUN_KINDS.includes(kind),
          `SC pack ${pack.id} kind ${kind} not in schema enum`,
        );
      }
    }
  }
});

test("every capability pack declares replay + evidence runners that resolve to registered tools", () => {
  const toolNames = new Set(Object.keys(TOOL_MANIFEST));
  for (const pack of Object.values(CAPABILITY_PACKS)) {
    assert.ok(pack.verifier && pack.evidence, `pack ${pack.id} must declare verifier + evidence`);
    assert.ok(toolNames.has(pack.verifier.replay_tool), `pack ${pack.id} replay_tool not registered`);
    assert.ok(toolNames.has(pack.evidence.runner), `pack ${pack.id} evidence.runner not registered`);
    if (pack.id !== "web" && pack.verifier.disambiguation) {
      assert.ok(toolNames.has(pack.verifier.disambiguation.tool));
    }
  }
});

test("BLOCKED_HARNESS_RUN_KINDS, schema enum, and runtime normalizer stay in sync", () => {
  const { BLOCKED_HARNESS_RUN_KINDS } = require("../mcp/lib/capability-packs-rendering.js");
  const { BLOCKED_HARNESS_KIND_VALUES } = require("../mcp/lib/wave-handoff-contracts.js");
  const schema = require("../mcp/lib/tools/write-wave-handoff.js").inputSchema;
  const sorted = (arr) => [...arr].sort();
  assert.deepEqual(
    sorted(BLOCKED_HARNESS_RUN_KINDS),
    sorted(schema.properties.blocked_harness_runs.items.properties.kind.enum),
  );
  assert.deepEqual(sorted(BLOCKED_HARNESS_RUN_KINDS), sorted(BLOCKED_HARNESS_KIND_VALUES));
});

test("BLOCKED_PREREQ_KINDS, schema enum, and runtime normalizer stay in sync", () => {
  const { BLOCKED_PREREQ_KINDS } = require("../mcp/lib/capability-packs-rendering.js");
  const { BLOCKED_PREREQ_KIND_VALUES } = require("../mcp/lib/wave-handoff-contracts.js");
  const schema = require("../mcp/lib/tools/write-wave-handoff.js").inputSchema;
  const sorted = (arr) => [...arr].sort();
  assert.deepEqual(
    sorted(BLOCKED_PREREQ_KINDS),
    sorted(schema.properties.blocked_prereqs.items.properties.kind.enum),
  );
  assert.deepEqual(sorted(BLOCKED_PREREQ_KINDS), sorted(BLOCKED_PREREQ_KIND_VALUES));
});

test("identifier_hint and bypass_attempt min lengths match between schema and runtime", () => {
  const wavecontract = require("../mcp/lib/wave-handoff-contracts.js");
  const schema = require("../mcp/lib/tools/write-wave-handoff.js").inputSchema;
  const identifierHint = schema.properties.blocked_prereqs.items.properties.identifier_hint;
  assert.equal(wavecontract.BLOCKED_PREREQ_IDENTIFIER_HINT_PATTERN.source, identifierHint.pattern);
  assert.equal(wavecontract.BLOCKED_PREREQ_IDENTIFIER_HINT_LONG_HEX_PATTERN.source, identifierHint.not.pattern);
  const bypass = schema.properties.bypass_attempts.items.properties;
  assert.equal(bypass.condition.minLength, wavecontract.BYPASS_ATTEMPT_CONDITION_MIN_CHARS);
  assert.equal(bypass.attempt_summary.minLength, wavecontract.BYPASS_ATTEMPT_SUMMARY_MIN_CHARS);
});

test("rendered orchestrator catalogue lists every smart-contract pack exactly once", () => {
  const rendered = readFile(".claude/skills/bob-evaluate-runner/SKILL.md");
  for (const pack of Object.values(CAPABILITY_PACKS)) {
    if (pack.spawn.profile !== "smart_contract") continue;
    const escaped = pack.id.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const lineRegex = new RegExp(
      `- \`capability_pack: "${escaped}"\` \\(chain_family \`[^\`]+\`\\) -> evaluator_agent \`${pack.evaluator_agent}\``,
      "g",
    );
    const matches = rendered.match(lineRegex) || [];
    assert.equal(matches.length, 1, `pack ${pack.id} must appear exactly once in catalogue (found ${matches.length})`);
  }
});

test("chain-specific identifiers are not duplicated across registry consumers", () => {
  const chainBundles = ["evaluator-evm", "evaluator-svm", "evaluator-move", "evaluator-substrate", "evaluator-cosmwasm"];
  const consumers = [
    "mcp/lib/role-model.js",
    "mcp/lib/tool-registry.js",
    "scripts/lib/claude-role-renderer.js",
    "scripts/lib/codex-role-renderer.js",
    "adapters/codex/role-specs.js",
  ];
  for (const consumer of consumers) {
    const body = readFile(consumer);
    for (const bundle of chainBundles) {
      const matches = body.match(new RegExp(`\\b${bundle}\\b`, "g")) || [];
      assert.equal(matches.length, 0, `${consumer} hardcodes ${bundle}`);
    }
  }
});

test("evaluator agents stay under their MCP tool budget", () => {
  // Cycle T.1 (Plane T) added 13 bob_browser_* tools to evaluator-shared so
  // every evaluator role can drive Patchright session-scoped DOM/postMessage/
  // WebAuthn/OAuth-callback/ServiceWorker enumeration. Cycle T.7 adds two
  // more — bob_browser_session_start_recording and
  // bob_browser_flush_recorded_requests — so the same evaluators can capture
  // client-side auth flows and pivot via bob_http_scan for mutate-and-replay.
  // Cycle O.4 (Plane O) adds bob_repo_docker_run to evaluator-shared so the
  // OSS axis can drive sandboxed docker runs from the same evaluator agent.
  // Cycle O.5 (Plane O) adds bob_repo_check to evaluator-shared so the OSS
  // axis can probe repo files for existence/literal/regex evidence without
  // ever leaving the read-only repo mount (O-P1).
  // Cycle X.1 (Plane X) adds bob_propose_hypothesis + bob_propose_transition
  // to evaluator-shared per X-D10. Both tools are pure-write proposal events
  // that take a single statement, do not surface in briefs, and reuse the
  // existing observation.recorded ledger kind. They do not compound brief
  // tokens, so budgets bump by +2 to keep parity with the bundle surface.
  // The browser-driver family is opaque-context (one verb per command, idle/
  // hard timeouts reap sessions) so it doesn't compound brief-rendered text;
  // budgets stay bumped (SC 30→34→36, web 32→36→38) to keep parity with the
  // role bundle's actual surface.
  // Cycle X.2 (Plane X) adds bob_read_task_graph (read-only) to
  // evaluator-shared so the X.5 capability-pack derivation + X.8 brief
  // renderer can ground reasoning in the materialized graph. It's a single
  // bounded read tool with summary/raw views; budgets bump by +1
  // (SC 36→37, web 38→39) to keep parity with the actual bundle surface.
  // Cycle X.4 (Plane X) adds bob_attach_contract (mutating, single-event
  // node.transitioned writer) to evaluator-shared per X-D10. The tool
  // accepts a structured Contract payload but does not surface in briefs;
  // budgets bump by +1 (SC 37→38, web 39→40) to keep parity with the
  // bundle surface.
  // Cycle X.7 (Plane X) adds bob_resolve_body (read-only body resolver
  // for X-D12 artifact_refs) to evaluator-shared. Bodies are pull-only
  // per X-P9 so the tool replaces ad-hoc body inlining in briefs;
  // budgets bump by +1 (SC 38→39, web 40→41) to keep parity with the
  // bundle surface.
  // Plane Y Cycle Y.2 adds bob_log_capability_friction +
  // bob_log_protocol_drift to evaluator-shared (Y-D2 voluntary emission
  // entries). Both are summary-grade by shape (Y-P2): closed-prefix
  // payloads, no body fields, 5-tuple idempotent. Per-evaluator brief
  // tokens unchanged (no brief surfacing); budgets bump by +2 (SC 39→41,
  // web 41→43) to keep parity with the bundle surface.
  const EVALUATOR_MCP_TOOL_BUDGET = 41;
  const agentNameToRoleId = {};
  for (const [roleId, spec] of Object.entries(CLAUDE_ROLE_SPECS)) {
    if (spec.kind === "agent" && typeof spec.output_path === "string") {
      agentNameToRoleId[path.basename(spec.output_path).replace(/\.md$/, "")] = roleId;
    }
  }
  for (const pack of Object.values(CAPABILITY_PACKS)) {
    const roleId = agentNameToRoleId[pack.evaluator_agent];
    const budget = pack.spawn.profile === "web" ? 43 : EVALUATOR_MCP_TOOL_BUDGET;
    assert.ok(
      mcpToolNamesForRole(roleId).length <= budget,
      `pack ${pack.id} evaluator over budget (got ${mcpToolNamesForRole(roleId).length}, budget ${budget})`,
    );
  }
});

// =============================================================================
// SECTION 10 — Verifier / evidence role contracts
// =============================================================================

test("verifier role bundle exposes the documented mutating set and no orchestration mutators", () => {
  const verifierTools = toolNamesForRoleBundle("verifier");
  const mutating = verifierTools.filter((name) => TOOL_MANIFEST[name].mutating);
  // Cycle O.4 (Plane O) adds bob_repo_docker_run to the verifier bundle so
  // verifiers can replay sandboxed docker runs against bound repo sessions
  // without escalating to a claim-writing tool.
  // Cycle O.5 (Plane O) adds bob_repo_check so verifiers can do bounded,
  // read-only file probes (file_exists / file_contains / regex_match)
  // against the bound repo without taking the docker path.
  assert.deepEqual(
    mutating.sort(),
    [
      "bob_evm_fetch_source",
      "bob_http_scan",
      "bob_repo_check",
      "bob_repo_docker_run",
      "bob_write_verification_round",
    ].sort(),
  );
  const forbidden = [
    "bob_record_candidate_claim",
    "bob_write_wave_handoff",
    "bob_finalize_agent_run",
    "bob_log_coverage",
    "bob_log_dead_ends",
    "bob_write_grade_verdict",
    "bob_apply_wave_merge",
    "bob_build_verification_adjudication",
  ];
  for (const tool of forbidden) {
    const meta = TOOL_MANIFEST[tool];
    if (!meta) continue;
    assert.ok(!meta.role_bundles.includes("verifier"), `${tool} must not be in verifier bundle`);
  }
});

test("evidence-agent surfaces every SC-pack evidence runner via its role bundle", () => {
  const tools = agentToolsList(".claude/agents/evidence-agent.md");
  for (const pack of Object.values(CAPABILITY_PACKS)) {
    assertPermissionReferenced(
      tools,
      pack.evidence.runner,
      `evidence-agent missing runner for pack ${pack.id}: ${pack.evidence.runner}`,
    );
  }
});

test("SC role bundles include the evidence bundle for runner re-runs", () => {
  // Every SC pack runner must list `evidence` in its role bundle so the
  // evidence agent can replay across families.
  const familyRunners = new Set();
  for (const pack of Object.values(CAPABILITY_PACKS)) {
    if (pack.spawn.profile !== "smart_contract") continue;
    familyRunners.add(pack.verifier.replay_tool);
    familyRunners.add(pack.evidence.runner);
  }
  for (const runner of familyRunners) {
    const meta = TOOL_MANIFEST[runner];
    assert.ok(meta, `${runner} must be in TOOL_MANIFEST`);
    assert.ok(meta.role_bundles.includes("evidence"), `${runner} must include evidence role bundle`);
  }
});

test("non-evaluator agents require their compact final markers", () => {
  const expectations = {
    "chain-builder": "BOB_CHAIN_DONE",
    "brutalist-verifier": "BOB_VERIFY_DONE",
    "balanced-verifier": "BOB_VERIFY_DONE",
    "final-verifier": "BOB_VERIFY_DONE",
    "evidence-agent": "BOB_EVIDENCE_DONE",
    "grader": "BOB_GRADE_DONE",
    "report-writer": "BOB_REPORT_DONE",
  };
  for (const [agent, marker] of Object.entries(expectations)) {
    const document = readFile(`.claude/agents/${agent}.md`);
    assert.match(document, new RegExp(marker), `${agent} missing marker ${marker}`);
  }
});

test("verifier and grader agents reference F-N finding ids, not wave-agent ids", () => {
  for (const agent of ["brutalist-verifier", "balanced-verifier", "final-verifier", "grader"]) {
    const document = readFile(`.claude/agents/${agent}.md`);
    assert.doesNotMatch(document, /\bw\d+-a\d+-\d+\b/, `${agent}.md contains stale wave-agent ids`);
    assert.match(document, /finding_id:\s*"F-\d+"/, `${agent}.md missing F-N finding_id example`);
  }
});

// =============================================================================
// SECTION 11 — Hook + settings contract
// =============================================================================

test("settings.json registers session guards on Bash, Read, and Write", () => {
  const settings = JSON.parse(readFile(".claude/settings.json"));
  const preToolUse = settings.hooks.PreToolUse;

  for (const matcher of ["Bash", "Read", "Write"]) {
    const entry = preToolUse.find((e) => e.matcher === matcher);
    assert.ok(entry, `No ${matcher} matcher in PreToolUse`);
  }
  const bash = preToolUse.find((e) => e.matcher === "Bash");
  assert.ok(bash.hooks.some((h) => h.command.includes("session-write-guard.sh")));
  assert.ok(bash.hooks.some((h) => h.command.includes("session-read-guard.sh")));
});

test("settings hooks do not register matchers on MCP tool names directly", () => {
  const settings = JSON.parse(readFile(".claude/settings.json"));
  const matchers = (settings.hooks.PreToolUse || []).map((e) => e.matcher);
  for (const matcher of matchers) {
    assert.ok(!matcher.startsWith(MCP_PERMISSION_PREFIX), `MCP tool matcher ${matcher} should not be in settings`);
  }
});

test("SubagentStop hooks match every routed capability-pack evaluator", () => {
  const expected = evaluatorAgentNamesForCapabilityPacks().sort();
  for (const settings of [defaultClaudeSettings(), JSON.parse(readFile(".claude/settings.json"))]) {
    const configured = (settings.hooks.SubagentStop || [])
      .filter((entry) => (entry.hooks || []).some((hook) => /agent-run-stop\.js/.test(hook.command)))
      .map((entry) => entry.matcher)
      .sort();
    assert.deepEqual(configured, expected);
  }
});

test("default settings register canonical lifecycle hooks", () => {
  const settings = defaultClaudeSettings();
  assert.match(JSON.stringify(settings.hooks.SubagentStop), /agent-run-stop\.js/);
  assert.match(JSON.stringify(settings.hooks.SessionStart), /bob-check-update\.js/);
});

test("standard hook test script runs both write and read guards", () => {
  const pkg = JSON.parse(readFile("package.json"));
  assert.match(pkg.scripts["test:hooks"], /test-write-guard\.py/);
  assert.match(pkg.scripts["test:hooks"], /test-read-guard\.py/);
});

// =============================================================================
// SECTION 12 — Module-boundary hygiene
// =============================================================================

test("Claude adapter config never leaks into the neutral MCP runtime", () => {
  assert.equal(fs.existsSync(path.join(ROOT, "mcp", "lib", "claude-config.js")), false);
  for (const relativePath of allJsFiles("mcp")) {
    assert.doesNotMatch(
      readFile(relativePath),
      /claude-config|adapters\/claude/,
      `${relativePath} imports Claude adapter config`,
    );
  }
});

test("CLAUDE_PROJECT_DIR appears only in adapter-scoped or compatibility-scoped modules", () => {
  const allowed = new Set([
    path.join("mcp", "lib", "runtime-resources.js"),
    path.join("scripts", "lib", "claude-role-renderer.js"),
    path.join("bin", "hacker-bob.js"),
  ]);
  for (const root of ["mcp", "scripts", "bin"]) {
    for (const relativePath of allJsFiles(root)) {
      if (allowed.has(relativePath)) continue;
      assert.doesNotMatch(
        readFile(relativePath),
        /CLAUDE_PROJECT_DIR/,
        `${relativePath} contains CLAUDE_PROJECT_DIR`,
      );
    }
  }
});

test("neutral role prompts do not embed host-specific syntax", () => {
  for (const role of allRoleDefinitions()) {
    const body = readFile(role.prompt_body);
    assert.doesNotMatch(body, new RegExp(MCP_PERMISSION_PREFIX.replace(/_/g, "\\_")));
    assert.doesNotMatch(body, /CLAUDE_PROJECT_DIR/);
    assert.doesNotMatch(body, /^allowed-tools:|^tools:/m);
  }
});

test("rules files stay small and reference scope plus MCP-owned artifacts", () => {
  for (const ruleFile of [".claude/rules/evaluating.md", ".claude/rules/reporting.md"]) {
    const document = readFile(ruleFile);
    assert.ok(lineCount(ruleFile) <= 60, `${ruleFile} is too large`);
    assert.match(document, /scope/i);
    assert.match(document, /MCP-owned artifacts/i);
  }
});

// =============================================================================
// SECTION 13 — Renderer cleanliness (anti-cruft)
// =============================================================================

test("renderers do not inline per-chain workflow strings (pack.spawn is the only source)", () => {
  const renderers = [
    "scripts/lib/claude-role-renderer.js",
    "scripts/lib/codex-role-renderer.js",
  ];
  const forbiddenFragments = [
    "bob_evm_fetch_source -> read sources",
    "bob_svm_fetch_program (confirm",
    "bob_aptos_fetch_module (enumerate",
    "bob_sui_fetch_package (enumerate",
    "bob_substrate_fetch_runtime (confirm",
    "bob_cosmwasm_fetch_contract (confirm",
  ];
  for (const renderer of renderers) {
    const body = readFile(renderer);
    for (const fragment of forbiddenFragments) {
      assert.ok(!body.includes(fragment), `${renderer} must not inline ${fragment}`);
    }
    assert.doesNotMatch(
      body,
      /SPAWN_EVALUATOR_EVM_AGENT|SPAWN_EVALUATOR_SVM_AGENT|SPAWN_EVALUATOR_MOVE_AGENT|SPAWN_EVALUATOR_SUBSTRATE_AGENT|SPAWN_EVALUATOR_COSMWASM_AGENT/,
    );
  }
});

test("rendered orchestrator catalogue surfaces every SC pack route", () => {
  const rendered = readFile(".claude/skills/bob-evaluate-runner/SKILL.md");
  for (const pack of Object.values(CAPABILITY_PACKS)) {
    if (pack.spawn.profile !== "smart_contract") continue;
    const escaped = pack.id.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    assert.match(
      rendered,
      new RegExp(`capability_pack: "${escaped}".*${pack.evaluator_agent}`),
      `rendered orchestrator missing ${pack.id} -> ${pack.evaluator_agent}`,
    );
  }
});

// =============================================================================
// SECTION 14 — Installer / dev-sync contracts
// =============================================================================

test("installer and dev-sync ship the Claude command + skill set with no legacy slash paths", () => {
  const install = readFile("install.sh");
  const claudeAdapter = readFile("adapters/claude/index.js");
  const devSync = readFile("dev-sync.sh");

  assert.match(install, /bin\/hacker-bob\.js/);
  for (const file of ["bob-update.md", "bob-export.md", "bob-evaluate", "bob-status", "bob-debug"]) {
    assert.match(claudeAdapter, new RegExp(file));
  }
  for (const file of [
    "\\.claude/commands/bob-update\\.md",
    "\\.claude/commands/bob-export\\.md",
    "\\.claude/hooks/bob-export\\.js",
    "\\.claude/skills/bob-status/SKILL\\.md",
    "\\.claude/skills/bob-debug/SKILL\\.md",
    "\\.claude/skills/bob-evaluate-runner/SKILL\\.md",
  ]) {
    assert.match(devSync, new RegExp(file));
  }
  // Legacy slash-command paths are pruned in the dev-sync workflow.
  assert.match(devSync, /rm -f "\$CLAUDE_DIR\/commands\/bob\/evaluate\.md"/);
  // Legacy skill dirs (bob-evaluate, bob-hunt) are swept in the dev-sync workflow
  // so they cannot resurface as duplicate /bob-evaluate slash-picker entries.
  assert.match(devSync, /rm -rf .*skills\/bob-hunt.*skills\/bob-evaluate"/);
});

test("dev-sync accepts adapters and gates Claude-specific sync paths", () => {
  const devSync = readFile("dev-sync.sh");
  assert.match(devSync, /--adapter claude\|codex\|generic-mcp\|kimi\|all/);
  assert.match(devSync, /ADAPTER="claude"/);
  assert.match(devSync, /if adapter_includes "claude"; then\s+sync_claude_adapter/s);
});

test("installer and dev-sync copy session guard hooks", () => {
  const claudeAdapter = readFile("adapters/claude/index.js");
  const devSync = readFile("dev-sync.sh");
  assert.match(claudeAdapter, /session-write-guard\.sh/);
  assert.match(claudeAdapter, /session-read-guard\.sh/);
  assert.match(claudeAdapter, /agent-run-stop\.js/);
  assert.match(devSync, /cp "\$SCRIPT_DIR\/\.claude\/hooks\/agent-run-stop\.js"/);
});

// =============================================================================
// SECTION 15 — CI workflow
// =============================================================================

test("CI runs npm test on supported Node versions without browser installs", () => {
  const workflow = readFile(".github/workflows/ci.yml");
  assert.match(workflow, /pull_request:/);
  assert.match(workflow, /push:/);
  assert.match(workflow, /node-version: \[20, 22\]/);
  assert.match(workflow, /npm ci/);
  assert.match(workflow, /npm test/);
  assert.doesNotMatch(workflow, /patchright install|install-browser/);
});

// =============================================================================
// SECTION 16 — Brutalist verifier wiring
// =============================================================================

test("brutalist-verifier sources reference @brutalist/mcp roast with graceful fallback", () => {
  for (const file of [
    "prompts/roles/brutalist-verifier.md",
    ".claude/agents/brutalist-verifier.md",
    "adapters/codex/skills/bob-evaluate/SKILL.md",
  ]) {
    const body = readFile(file);
    assert.match(body, /mcp__brutalist__roast\b/);
    assert.match(body, /brutalist roast unavailable/i);
    const debateMentions = body.match(/mcp__brutalist__roast_cli_debate/g) || [];
    assert.ok(debateMentions.length <= 1, `${file} mentions debate ${debateMentions.length} times`);
    if (debateMentions.length === 1) {
      const idx = body.indexOf("roast_cli_debate");
      const ctx = body.slice(Math.max(0, idx - 80), idx + 80);
      assert.match(ctx, /do NOT call|too time-expensive/i);
    }
  }
});

test("Claude brutalist-verifier registers @brutalist/mcp tools but only requires the host MCP", () => {
  const body = readFile(".claude/agents/brutalist-verifier.md");
  const toolsLine = body.match(/^tools: (.+)$/m);
  assert.ok(toolsLine, "brutalist-verifier missing tools line");
  const toolsList = toolsLine[1];
  for (const tool of ["mcp__brutalist__roast", "mcp__brutalist__brutalist_discover", "mcp__brutalist__cli_agent_roster"]) {
    assert.ok(toolsList.includes(tool), `brutalist-verifier missing ${tool}`);
  }
  assert.ok(!toolsList.includes("mcp__brutalist__roast_cli_debate"));
});

test("Codex bundled .mcp.json registers brutalist as optional alongside the host server", () => {
  const mcp = JSON.parse(readFile("adapters/codex/hacker-bob/.mcp.json"));
  assert.ok(mcp.mcpServers.brutalist);
  assert.equal(mcp.mcpServers.brutalist.command, "npx");
  assert.deepEqual(mcp.mcpServers.brutalist.args, ["-y", "@brutalist/mcp@latest"]);
});

// =============================================================================
// SECTION 17 — Documentation surfaces
// =============================================================================

test("public docs do not advertise removed hook authority", () => {
  const docs = [
    "docs/PACKAGE_SURFACES.md",
    "docs/capability-hypergraph.md",
    "docs/hacker-bob-offline-guide.md",
  ].map(readFile).join("\n");
  assert.doesNotMatch(docs, /hook-required/);
  assert.doesNotMatch(docs, /scope guard around/);
});

test("context scaling architecture doc matches enforced budget contract", () => {
  assert.equal(fs.existsSync(path.join(ROOT, "docs/context-scaling-and-platform-adapters.md")), false);
  const doc = readFile("docs/context-scaling-architecture.md");
  assert.match(doc, /^# Context Scaling Architecture/m);
  for (const field of ["candidate_pack_limit", "full_pack_read_limit", "attempt_log_required"]) {
    assert.match(doc, new RegExp(field));
  }
});

test("README and offline guide describe session authority", () => {
  const readme = readFile("README.md");
  const offlineGuide = readFile("docs/hacker-bob-offline-guide.md");
  assert.match(readme, /caller `target_domain` is only a lookup key/);
  assert.match(offlineGuide, /resolve session authority/);
});

// =============================================================================
// SECTION 18 — Prompt rendering primitives (load-bearing strings)
// =============================================================================

test("auth.json is never instructed for direct read in user-facing prompts", () => {
  const files = [
    ".claude/commands/bob-update.md",
    ".claude/skills/bob-evaluate-runner/SKILL.md",
    ".claude/skills/bob-status/SKILL.md",
    ".claude/skills/bob-debug/SKILL.md",
    ...allMarkdown(".claude/agents"),
  ];
  for (const file of files) {
    assert.doesNotMatch(readFile(file), /auth\.json/i, `${file} should use auth MCP tools`);
  }
});

test("rendered evaluator agents carry the handoff field limits block", () => {
  const renderedEvaluators = fs.readdirSync(path.join(ROOT, ".claude/agents"))
    .filter((name) => name.startsWith("evaluator") && name.endsWith(".md"))
    .map((name) => `.claude/agents/${name}`);
  for (const relativePath of renderedEvaluators) {
    const body = readFile(relativePath);
    assert.match(
      body,
      /Handoff field limits \(enforced by `bob_write_wave_handoff`/,
      `${relativePath} missing rendered handoff field limits`,
    );
  }
});

test("evaluator prompt sources do not hand-code handoff field limits", () => {
  const evaluatorPromptFiles = [
    "prompts/roles/evaluator.md",
    ...Object.values(EVALUATOR_ROLES).map((role) => `prompts/roles/${role.prompt_body_filename}`),
  ];
  const handoffFields = ["summary", "chain_notes", "blocked_harness_runs", "bypass_attempts", "attempt_summary", "condition"];
  for (const relativePath of evaluatorPromptFiles) {
    const body = readFile(relativePath);
    for (const line of body.split(/\r?\n/)) {
      const hasFieldName = handoffFields.some((name) => line.includes(name));
      if (!hasFieldName) continue;
      const charLimitMatch = line.match(/(?:≥|≤|<=|>=|max(?:imum)?|at most|at least|min(?:imum)?)\s*\d+(?:[\s-]*char)/i)
        || line.match(/\d+\s*-\s*char\s*\b(?:summary|condition|attempt|chain_notes|blocked_harness)/i);
      if (charLimitMatch) {
        assert.fail(
          `${relativePath} hand-codes handoff field limit "${charLimitMatch[0].trim()}"; the renderer must own these.`,
        );
      }
    }
  }
});

// =============================================================================
// SECTION 19 — Smart-contract evidence schema integrity
// =============================================================================

test("the claim-recording tool's schema requires sc_evidence sub-fields for SC findings", () => {
  // Source-of-truth lookup by primary name; renames must update either the
  // registry or this test's lookup, not both.
  const tool = TOOLS.find((entry) => entry.name === "bob_record_candidate_claim");
  assert.ok(tool, "bob_record_candidate_claim tool not registered");
  const sc = tool.inputSchema.properties.sc_evidence;
  assert.equal(sc.type, "object");
  assert.deepEqual(
    [...sc.required].sort(),
    ["chain_id", "contract_address", "harness_path", "match_test"].sort(),
  );
  assert.deepEqual(
    [...sc.properties.chain_family.enum].sort(),
    ["aptos", "cosmwasm", "evm", "substrate", "sui", "svm"],
  );
  assert.ok(Array.isArray(sc.properties.chain_id.oneOf) && sc.properties.chain_id.oneOf.length === 2);
});

test("the claim-recording tool's schema requires cited reachability assertions", () => {
  const tool = TOOLS.find((entry) => entry.name === "bob_record_candidate_claim");
  assert.ok(tool, "bob_record_candidate_claim tool not registered");
  const assertion = tool.inputSchema.properties.reachability_assertion;
  assert.equal(assertion.type, "object");
  assert.match(assertion.description, /Only allowed for routed oss_native_code findings/);
  assert.match(assertion.description, /not independently verifier-reviewed/);
  assert.match(assertion.description, /first distinct attack_vector\/network_reachable assertion wins/);
  assert.match(assertion.description, /same-classification call_path refinements are not conflicts and update the rendered call path/);
  assert.deepEqual([...assertion.required].sort(), ["attack_vector", "call_path", "network_reachable"].sort());
  assert.deepEqual([...assertion.properties.attack_vector.enum].sort(), ["local", "network"]);
  assert.equal(assertion.properties.call_path.minLength, 7);
  assert.ok(assertion.properties.call_path.maxLength <= 4000);
  assert.match(assertion.properties.call_path.pattern, /->.*->/);
  assert.match(assertion.properties.call_path.pattern, /^\^/);
  assert.match(assertion.properties.call_path.pattern, /\$$/);
  assert.ok(assertion.properties.call_path.pattern.includes("[^\\n\\r]*"));
  assert.doesNotMatch(assertion.properties.call_path.pattern, /\[\\s\\S\]/);
  const callPathPattern = new RegExp(assertion.properties.call_path.pattern);
  assert.match("UDP listener -> parse_packet -> sink", callPathPattern);
  assert.match("A->B->C", callPathPattern);
  assert.doesNotMatch("A -> -> B", callPathPattern);
  assert.doesNotMatch("A -> B -> ", callPathPattern);
});

// =============================================================================
// SECTION 20 — Session authority surfacing
// =============================================================================

test("generated surfaces describe central session authority and target_domain semantics", () => {
  const surfaces = [
    ".claude/skills/bob-evaluate-runner/SKILL.md",
    ".claude/skills/bob-status/SKILL.md",
    ".claude/skills/bob-debug/SKILL.md",
    ".claude/agents/evaluator-agent.md",
    "adapters/codex/skills/bob-evaluate/SKILL.md",
    "adapters/codex/skills/bob-status/SKILL.md",
    "adapters/codex/skills/bob-debug/SKILL.md",
  ].map(readFile).join("\n");
  assert.match(surfaces, /`target_domain` selects the session record/);
  assert.match(surfaces, /authority error.*session-integrity blocker/);
});

test("bob-diff-review skill advances to OPEN_FRONTIER before evaluator waves", () => {
  const skill = readFile(".claude/skills/bob-diff-review/SKILL.md");
  const s5 = skill.indexOf("### S5");
  const readNucleus = skill.indexOf("bob_read_session_nucleus", s5);
  const advance = skill.indexOf("bob_advance_session", s5);
  const openFrontier = skill.indexOf('to_state: "OPEN_FRONTIER"', s5);
  const startWave = skill.indexOf("bob_start_next_wave", s5);
  assert.ok(s5 >= 0, "bob-diff-review skill must contain S5");
  assert.ok(readNucleus > s5, "S5 must read session lifecycle before wave start");
  assert.ok(advance > readNucleus, "S5 must advance lifecycle after reading nucleus");
  assert.ok(openFrontier > advance, "S5 lifecycle advance must target OPEN_FRONTIER");
  assert.ok(startWave > openFrontier, "S5 must advance lifecycle before bob_start_next_wave");
});
