"use strict";

// Cycle Y.8 — shared skill/role markdown parser IR (Y-D16).
//
// State-block-aware AST: parses a Claude `.claude/skills/*/SKILL.md` or
// `prompts/roles/*.md` file into ordered blocks. A block is bounded by an
// H2 (`## `) heading on the open side and by the next H2, the next H3 used
// as a state-marker, or a horizontal `---` separator on the close side
// (Y-D7c "structural containment — state-block delimited by next H2/H3
// heading or `---` separator").
//
// Consumed by:
//   - scripts/check-skill-protocol-coherence.js (Y.8 three dimensions)
//   - scripts/check-skill-runtime-constraint-drift.js (Y.8 third dimension
//     via Y-D17)
//   - scripts/check-skill-scheduler-coherence.js (Y.10 CI marker check)
//   - scripts/check-stigmergy-coherence.js (Y.9, Y-P14c)
//   - terminal smoke (Y.13)
//
// The parser is intentionally minimal — it does not implement CommonMark
// in full; it recognises the small grammar Bob skill/role files actually
// use (H2/H3 ATX headings, ``` fenced code blocks, HTML comments). Code
// blocks are tracked so write-tool tokens that appear inside example
// payloads are still considered references (the call sites are real
// dispatch instructions even when written inside a fenced block), but
// the parser tags each token with its `inCodeBlock` boolean so callers
// can choose to filter.

const fs = require("fs");
const path = require("path");

// Write tools the orchestrator-side dispatch is allowed to call. The
// check scripts use these as the grep predicate when scanning bodies.
// `bob_write_*` is the catch-all canonical prefix; `bob_compose_*` and
// `bob_amend_*` cover the pre-rev-4.1 / Y.3 structured-composition writers
// (Y-D15b) that do not carry the `bob_write_` prefix.
const WRITE_TOOL_TOKEN_PATTERN = /\b(bob_write_[a-z][a-z0-9_]*|bob_compose_[a-z][a-z0-9_]*|bob_amend_[a-z][a-z0-9_]*)\b/g;

// `@schema_ref: <token>` directive emitted by the generator
// (`scripts/generate-hacker-bob-skill.js` Y.8 step 0b) into the rendered
// SKILL.md AFTER each state-block. The check script asserts every write
// token in a state-block has a matching `@schema_ref` directive in that
// same block (Y-D7c structural containment).
const SCHEMA_REF_PATTERN = /<!--\s*@schema_ref:\s*([a-z][a-z0-9_]*)\s*-->/g;

// `@precondition: <name>` directive — consumed by Y.10 scheduler-coherence
// check. Parsed here so Y.10's check shares the same IR walker.
const PRECONDITION_PATTERN = /<!--\s*@precondition:\s*([a-z][a-z0-9_]*)\s*-->/g;

const STATE_HEADING_PATTERN = /^##\s+STATE:\s+([A-Z_]+)\s*$/;
const SECTION_HEADING_PATTERN = /^##\s+(.+?)\s*$/;
const SUBSECTION_HEADING_PATTERN = /^###\s+(.+?)\s*$/;
const HORIZONTAL_RULE_PATTERN = /^---+\s*$/;
const CODE_FENCE_PATTERN = /^```/;
const FRONTMATTER_DELIMITER = "---";

function readSkillFile(filePath) {
  const text = fs.readFileSync(filePath, "utf8");
  return parseSkillText(text, { filePath });
}

function parseSkillText(text, { filePath = "<inline>" } = {}) {
  const lines = text.split(/\r?\n/);
  const document = {
    file: filePath,
    frontmatter: null,
    blocks: [],
  };

  // Strip frontmatter (Claude SKILL.md/agent.md files start with a
  // `---`-delimited YAML block). Frontmatter content is preserved on the
  // document but excluded from block parsing.
  let bodyStart = 0;
  if (lines[0] === FRONTMATTER_DELIMITER) {
    let frontmatterEnd = -1;
    for (let i = 1; i < lines.length; i += 1) {
      if (lines[i] === FRONTMATTER_DELIMITER) {
        frontmatterEnd = i;
        break;
      }
    }
    if (frontmatterEnd > 0) {
      document.frontmatter = lines.slice(1, frontmatterEnd).join("\n");
      bodyStart = frontmatterEnd + 1;
    }
  }

  // First pass: identify block boundaries. A block opens on an H2
  // heading. The implicit "preamble" block (text before the first H2) is
  // tagged kind: "preamble" so callers can ignore it without losing
  // context for token-context lookups.
  const boundaries = [];
  let inCodeFence = false;
  for (let i = bodyStart; i < lines.length; i += 1) {
    const line = lines[i];
    if (CODE_FENCE_PATTERN.test(line)) {
      inCodeFence = !inCodeFence;
      continue;
    }
    if (inCodeFence) continue;
    const stateMatch = line.match(STATE_HEADING_PATTERN);
    if (stateMatch) {
      boundaries.push({ line: i, kind: "state", name: stateMatch[1] });
      continue;
    }
    const sectionMatch = line.match(SECTION_HEADING_PATTERN);
    if (sectionMatch && !stateMatch) {
      boundaries.push({ line: i, kind: "section", name: sectionMatch[1].trim() });
      continue;
    }
  }

  // Build block ranges from boundaries. The preamble (if any) runs from
  // bodyStart to the first boundary or EOF.
  const ranges = [];
  if (boundaries.length === 0) {
    ranges.push({ kind: "preamble", name: null, headerLine: -1, start: bodyStart, end: lines.length });
  } else {
    if (boundaries[0].line > bodyStart) {
      ranges.push({ kind: "preamble", name: null, headerLine: -1, start: bodyStart, end: boundaries[0].line });
    }
    for (let i = 0; i < boundaries.length; i += 1) {
      const start = boundaries[i].line + 1;
      const end = i + 1 < boundaries.length ? boundaries[i + 1].line : lines.length;
      ranges.push({
        kind: boundaries[i].kind,
        name: boundaries[i].name,
        headerLine: boundaries[i].line,
        start,
        end,
      });
    }
  }

  for (const range of ranges) {
    const blockLines = lines.slice(range.start, range.end);
    const body = blockLines.join("\n");
    const tokens = extractTokens(body, range.start);
    document.blocks.push({
      file: filePath,
      kind: range.kind,
      name: range.name,
      header_line: range.headerLine + 1, // 1-indexed for human display
      content_start_line: range.start + 1,
      content_end_line: range.end,
      body,
      tokens,
    });
  }

  return document;
}

function extractTokens(body, startLine) {
  const writeTokens = [];
  const schemaRefs = [];
  const preconditions = [];
  const lines = body.split(/\r?\n/);
  let inCodeFence = false;
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    if (CODE_FENCE_PATTERN.test(line)) {
      inCodeFence = !inCodeFence;
      continue;
    }
    const absoluteLine = startLine + i + 1; // 1-indexed
    WRITE_TOOL_TOKEN_PATTERN.lastIndex = 0;
    let match;
    while ((match = WRITE_TOOL_TOKEN_PATTERN.exec(line)) !== null) {
      writeTokens.push({
        token: match[1],
        line: absoluteLine,
        column: match.index + 1,
        in_code_block: inCodeFence,
      });
    }
    SCHEMA_REF_PATTERN.lastIndex = 0;
    while ((match = SCHEMA_REF_PATTERN.exec(line)) !== null) {
      schemaRefs.push({
        token: match[1],
        line: absoluteLine,
        column: match.index + 1,
      });
    }
    PRECONDITION_PATTERN.lastIndex = 0;
    while ((match = PRECONDITION_PATTERN.exec(line)) !== null) {
      preconditions.push({
        token: match[1],
        line: absoluteLine,
        column: match.index + 1,
      });
    }
  }
  return Object.freeze({
    write_tools: writeTokens,
    schema_refs: schemaRefs,
    preconditions,
  });
}

// Discover the canonical set of GENERATED skill / agent markdown files
// that the Claude runtime loads at session start. The check scripts
// operate on the rendered surface (`.claude/skills/**/SKILL.md` and
// `.claude/agents/**/*.md`) because that surface is what the runtime
// actually executes — the upstream `prompts/roles/*.md` source files
// are post-processed by the renderer (which auto-injects
// `@schema_ref` markers, expands launch templates, and substitutes
// registry-driven content) so they intentionally omit the directives
// the renderer derives. Drift between source and rendered surface is
// the job of `check:agent-tools --check` and `check:skill --check`;
// coherence between rendered surface and TOOL_REGISTRY /
// runtime-constraints is the job of the Y.8 check scripts.
function discoverRoleMarkdownFiles(root) {
  const targets = [];
  const skillsDir = path.join(root, ".claude", "skills");
  if (fs.existsSync(skillsDir)) {
    for (const entry of fs.readdirSync(skillsDir, { withFileTypes: true })) {
      if (!entry.isDirectory()) continue;
      const skillMd = path.join(skillsDir, entry.name, "SKILL.md");
      if (fs.existsSync(skillMd)) targets.push(skillMd);
    }
  }
  const agentsDir = path.join(root, ".claude", "agents");
  if (fs.existsSync(agentsDir)) {
    for (const entry of fs.readdirSync(agentsDir, { withFileTypes: true })) {
      if (!entry.isFile()) continue;
      if (!entry.name.endsWith(".md")) continue;
      targets.push(path.join(agentsDir, entry.name));
    }
  }
  return targets;
}

module.exports = {
  WRITE_TOOL_TOKEN_PATTERN,
  SCHEMA_REF_PATTERN,
  PRECONDITION_PATTERN,
  readSkillFile,
  parseSkillText,
  extractTokens,
  discoverRoleMarkdownFiles,
};
