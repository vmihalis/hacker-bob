#!/usr/bin/env node
"use strict";

// Cycle Y.8 — `check:skill-protocol-coherence` (Y-D7 / Y-P7 first
// coherence dimension family).
//
// Four coherence dimensions, all consuming the Y-D16 shared parser IR
// at `scripts/lib/skill-parser.js`:
//
//   D1. Structural containment (Y-D7c). For every STATE block in every
//       rendered skill / role markdown file, every write-tool token
//       (matching the `bob_write_*` / `bob_compose_*` / `bob_amend_*`
//       prefixes) that appears OUTSIDE a fenced code block MUST have a
//       matching `@schema_ref: <tool>` HTML-comment directive inside
//       the SAME state block. The generator
//       (`scripts/lib/claude-role-renderer.js` →
//       `injectSchemaRefDirectives`) auto-emits the markers from
//       TOOL_REGISTRY, so a violation here means either (a) the
//       generator was bypassed (hand-edited SKILL.md) or (b) the
//       source markdown references a write tool the registry doesn't
//       know about.
//
//   D2. Registry coherence. Every value cited in an `@schema_ref:`
//       directive MUST name a primary tool currently registered in
//       `mcp/lib/tool-registry.js` TOOL_REGISTRY. Stale directives
//       pointing at retired/renamed tools fail here.
//
//   D3. Token registry coherence. Every write-tool token that appears
//       outside a fenced code block MUST resolve to a primary tool in
//       TOOL_REGISTRY. Catches `bob_write_typo_handoff` and similar
//       drift between source markdown and the live registry.
//
//   D4. Dormant-allowlisted-tool detection (rev 4.1 closure). A closed
//       set of CRITICAL-PATH tools (`CRITICAL_DORMANT_WATCHED_TOOLS`)
//       — the ones the rev-4.1 leverage audit flagged as
//       "schemas live, no agent prompt invokes" — MUST each appear in
//       at least one non-frontmatter, non-allowed-tools-list line of
//       the rendered skill OR some agent / source role markdown file.
//       This is a positive whitelist so we catch the named gaps
//       mechanically without flagging long-allowlisted tools that may
//       be invoked from hooks, future cycles, or other call sites the
//       parser cannot inspect. Reframes the rev-4-Y.9 spec note that
//       named a phantom `check:hook-skill-coherence` — Y-D11 was
//       REMOVED in rev 3 (spec line 108 / 122 / 702 / 825), this is
//       its absorbed replacement folded into D7c.
//
// FP-rate budget: ≤2% on the curated corpus under
// `test/fixtures/skill-parser/`. The corpus is small and curated; the
// budget is enforced by `test/skill-protocol-coherence.test.js`.

const fs = require("fs");
const path = require("path");
const {
  parseSkillText,
  readSkillFile,
  discoverRoleMarkdownFiles,
} = require("./lib/skill-parser.js");
const { TOOL_REGISTRY } = require("../mcp/lib/tool-registry.js");

const ROOT = path.join(__dirname, "..");
const REGISTERED_TOOL_NAMES = new Set(
  TOOL_REGISTRY.filter((tool) => !tool.alias_of).map((tool) => tool.name),
);

// D4 positive whitelist. The rev-4.1 leverage_audit flagged these four
// tools as "schemas live, tests exist, no agent prompt invokes them" gaps.
// Each one MUST be cited in a non-frontmatter line of the rendered skill
// OR a role / agent source markdown file. Adding a new tool here turns
// the check into a regression gate for any future "wired-then-rotted"
// dormancy. The leverage audit itself remains a broader analysis; this
// list is the mechanical CI complement.
const CRITICAL_DORMANT_WATCHED_TOOLS = Object.freeze([
  "bob_emit_runtime_drift",
  "bob_set_friction_scanners",
  "bob_propose_friction_promotion",
  "bob_scan_transcript_for_friction",
]);

// D4 closed-list exceptions. Tools that are LEGITIMATELY invoked only by a
// Bob-owned hook or by the MCP server itself (no agent prompt body cites
// them) belong here with a citable caller. Today the set is empty — every
// watched dormant tool flagged by the leverage audit has been wired into
// a prompt. If a future tool genuinely cannot have a prompt-body caller,
// add it with a comment citing the caller (e.g., `.claude/hooks/foo-hook.js:NN`).
const DORMANT_DETECTION_EXCEPTIONS = Object.freeze(new Set([
  // (intentionally empty — rev 4.1 closure)
]));

const ALLOWED_TOOLS_LINE_PATTERN = /^\s*-\s+(mcp__hacker-bob__bob_[a-z0-9_]+)\s*$/;
const FRONTMATTER_DELIMITER = "---";

function parseFrontmatterAllowedTools(filePath) {
  const text = fs.readFileSync(filePath, "utf8");
  const lines = text.split(/\r?\n/);
  if (lines[0] !== FRONTMATTER_DELIMITER) {
    return { allowed_tools: [], frontmatter_end_line: 0 };
  }
  let endLine = -1;
  for (let i = 1; i < lines.length; i += 1) {
    if (lines[i] === FRONTMATTER_DELIMITER) {
      endLine = i;
      break;
    }
  }
  if (endLine < 0) {
    return { allowed_tools: [], frontmatter_end_line: 0 };
  }
  const allowedTools = [];
  let inAllowedTools = false;
  for (let i = 1; i < endLine; i += 1) {
    const line = lines[i];
    if (/^allowed-tools\s*:/.test(line)) {
      inAllowedTools = true;
      continue;
    }
    if (inAllowedTools) {
      // Allowed-tools block ends at first non-indented key (e.g. `---` or
      // another top-level key like `argument-hint:`).
      if (/^[a-zA-Z_]/.test(line)) {
        inAllowedTools = false;
        continue;
      }
      const m = line.match(ALLOWED_TOOLS_LINE_PATTERN);
      if (m) {
        allowedTools.push({ token: m[1], line_number: i + 1 });
      }
    }
  }
  return { allowed_tools: allowedTools, frontmatter_end_line: endLine + 1 };
}

function stripFrontmatter(text) {
  const lines = text.split(/\r?\n/);
  if (lines[0] !== FRONTMATTER_DELIMITER) return text;
  for (let i = 1; i < lines.length; i += 1) {
    if (lines[i] === FRONTMATTER_DELIMITER) {
      return lines.slice(i + 1).join("\n");
    }
  }
  return text;
}

function collectProseSearchCorpus(root) {
  // The prose corpus is every rendered skill BODY (minus frontmatter) plus
  // every agent markdown file. Source-side `prompts/roles/*.md` is the input
  // to the renderer; the renderer's output is what the runtime actually
  // ships, so we look there. Read all corpus files once and concatenate so
  // the existence check is a single substring scan per tool.
  const parts = [];
  const skillsDir = path.join(root, ".claude", "skills");
  if (fs.existsSync(skillsDir)) {
    for (const entry of fs.readdirSync(skillsDir, { withFileTypes: true })) {
      if (!entry.isDirectory()) continue;
      const skillMd = path.join(skillsDir, entry.name, "SKILL.md");
      if (fs.existsSync(skillMd)) {
        parts.push(stripFrontmatter(fs.readFileSync(skillMd, "utf8")));
      }
    }
  }
  const agentsDir = path.join(root, ".claude", "agents");
  if (fs.existsSync(agentsDir)) {
    for (const entry of fs.readdirSync(agentsDir, { withFileTypes: true })) {
      if (!entry.isFile() || !entry.name.endsWith(".md")) continue;
      const fullPath = path.join(agentsDir, entry.name);
      // For agents we strip frontmatter too — agents also have allowed-tools
      // frontmatter listing the same tools, but the BODY is what counts.
      parts.push(stripFrontmatter(fs.readFileSync(fullPath, "utf8")));
    }
  }
  // Also include the source-side orchestrator role file because the
  // renderer copies its body content into SKILL.md; finding the tool there
  // is sufficient (the renderer output is upstream-derived).
  const orchestratorRole = path.join(root, "prompts", "roles", "orchestrator.md");
  if (fs.existsSync(orchestratorRole)) {
    parts.push(fs.readFileSync(orchestratorRole, "utf8"));
  }
  return parts.join("\n\n");
}

function checkDormantAllowlistedTools(root) {
  const violations = [];
  const corpus = collectProseSearchCorpus(root);
  const skillsDir = path.join(root, ".claude", "skills");
  if (!fs.existsSync(skillsDir)) return violations;

  // Build a map of tool token → SKILL.md frontmatter line where the
  // critical-watched token is enumerated so violations carry citable line
  // numbers when the prose body fails to cite the tool.
  const skillRefs = new Map(); // bareName -> { file, line_number }
  for (const entry of fs.readdirSync(skillsDir, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const skillMd = path.join(skillsDir, entry.name, "SKILL.md");
    if (!fs.existsSync(skillMd)) continue;
    const { allowed_tools } = parseFrontmatterAllowedTools(skillMd);
    for (const entryToolRef of allowed_tools) {
      const bareName = entryToolRef.token.replace(/^mcp__hacker-bob__/, "");
      if (!skillRefs.has(bareName)) {
        skillRefs.set(bareName, { file: skillMd, line_number: entryToolRef.line_number });
      }
    }
  }

  for (const bareName of CRITICAL_DORMANT_WATCHED_TOOLS) {
    if (DORMANT_DETECTION_EXCEPTIONS.has(bareName)) continue;
    if (corpus.includes(bareName)) continue;
    const ref = skillRefs.get(bareName);
    violations.push({
      dimension: "D4_dormant_allowlisted_tool",
      file: ref ? ref.file : path.join(root, ".claude", "skills"),
      block: "<frontmatter:allowed-tools>",
      line: ref ? ref.line_number : 0,
      column: 1,
      token: bareName,
      message: `critical-path tool "${bareName}" is allowlisted but no agent / role / skill prose body cites it (rev 4.1 dormant-tool gate; wire the tool into the orchestrator/agent source markdown or add a closed-list exception in DORMANT_DETECTION_EXCEPTIONS with a citable hook caller)`,
    });
  }
  return violations;
}

function checkDocument(document) {
  const violations = [];
  for (const block of document.blocks) {
    if (block.kind !== "state") continue;
    const schemaRefTokens = new Set(block.tokens.schema_refs.map((r) => r.token));
    const seenWriteTokens = new Map(); // token -> { line, column }
    for (const writeRef of block.tokens.write_tools) {
      if (writeRef.in_code_block) continue;
      if (!REGISTERED_TOOL_NAMES.has(writeRef.token)) {
        violations.push({
          dimension: "D3_token_registry",
          file: block.file,
          block: block.name,
          line: writeRef.line,
          column: writeRef.column,
          token: writeRef.token,
          message: `write-tool token "${writeRef.token}" in STATE block "${block.name}" is not registered in TOOL_REGISTRY`,
        });
        continue;
      }
      if (!seenWriteTokens.has(writeRef.token)) {
        seenWriteTokens.set(writeRef.token, writeRef);
      }
    }
    for (const [token, ref] of seenWriteTokens) {
      if (!schemaRefTokens.has(token)) {
        violations.push({
          dimension: "D1_structural_containment",
          file: block.file,
          block: block.name,
          line: ref.line,
          column: ref.column,
          token,
          message: `write-tool token "${token}" appears in STATE block "${block.name}" without a matching @schema_ref directive in the same block (Y-D7c structural containment)`,
        });
      }
    }
    for (const schemaRef of block.tokens.schema_refs) {
      if (!REGISTERED_TOOL_NAMES.has(schemaRef.token)) {
        violations.push({
          dimension: "D2_registry_coherence",
          file: block.file,
          block: block.name,
          line: schemaRef.line,
          column: schemaRef.column,
          token: schemaRef.token,
          message: `@schema_ref directive cites "${schemaRef.token}" which is not registered in TOOL_REGISTRY`,
        });
      }
    }
  }
  return violations;
}

function runCheck({ root = ROOT, additionalFiles = [] } = {}) {
  const files = discoverRoleMarkdownFiles(root).concat(additionalFiles);
  const violations = [];
  const inspected = [];
  for (const filePath of files) {
    const document = readSkillFile(filePath);
    inspected.push({ file: filePath, blocks: document.blocks.length });
    for (const violation of checkDocument(document)) {
      violations.push(violation);
    }
  }
  for (const violation of checkDormantAllowlistedTools(root)) {
    violations.push(violation);
  }
  return { files_inspected: inspected, violations };
}

function formatViolation(violation) {
  const relativePath = path.relative(ROOT, violation.file);
  return `[${violation.dimension}] ${relativePath}:${violation.line}:${violation.column}  block="${violation.block}"  token=${violation.token}\n    ${violation.message}`;
}

function main() {
  const result = runCheck();
  if (result.violations.length === 0) {
    console.log(`check:skill-protocol-coherence — ${result.files_inspected.length} files OK`);
    return;
  }
  for (const violation of result.violations) {
    console.error(formatViolation(violation));
  }
  console.error(`\ncheck:skill-protocol-coherence — ${result.violations.length} violation(s) across ${result.files_inspected.length} files`);
  process.exit(1);
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    console.error(error.stack || error.message || String(error));
    process.exit(1);
  }
}

module.exports = {
  runCheck,
  checkDocument,
  checkDormantAllowlistedTools,
  parseFrontmatterAllowedTools,
  CRITICAL_DORMANT_WATCHED_TOOLS,
  DORMANT_DETECTION_EXCEPTIONS,
  REGISTERED_TOOL_NAMES,
};
