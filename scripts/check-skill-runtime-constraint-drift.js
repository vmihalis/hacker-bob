#!/usr/bin/env node
"use strict";

// Cycle Y.8 — `check:skill-runtime-constraint-drift` (Y-D17 / Y-P7
// third coherence dimension; Y-D11 replacement).
//
// Walks every committed skill / role markdown file via the Y-D16
// shared parser IR (`scripts/lib/skill-parser.js`) and evaluates every
// non-frontmatter line against the runtime-constraint registry at
// `mcp/lib/runtime-constraints.js`. The registry declares two closed
// lists of constraints the runtime enforces below the model:
//
//   * BINARY_INTERNAL — patterns the Claude Code binary enforces on
//     subagent behavior (the canonical entry cites investigation
//     w0b0v41zw H2 — the binary-internal subagent Write regex that
//     silently rejects relative-path writes from background spawns).
//
//   * BOB_OWNED — Bob-managed PreToolUse hook contracts that deny
//     specific Bash / Write / Read shapes (session-read-guard and
//     session-write-guard).
//
// A skill instruction that tells an agent to call a shape the runtime
// will reject is "runtime-constraint drift" — the prompt promises a
// behavior the runtime forbids. The check flags every such instance
// with the constraint id, the file/line/column, and the remediation
// from the registry. Exit zero means the entire committed skill
// surface is coherent with the runtime's enforcement layer.
//
// FP-rate budget: ≤2% on the curated corpus under
// `test/fixtures/skill-parser/` (shared with
// `check:skill-protocol-coherence`).

const fs = require("fs");
const path = require("path");
const {
  readSkillFile,
  discoverRoleMarkdownFiles,
} = require("./lib/skill-parser.js");
const {
  evaluateBodyAgainstConstraints,
} = require("../mcp/lib/runtime-constraints.js");

const ROOT = path.join(__dirname, "..");

function checkDocument(document) {
  const violations = [];
  for (const block of document.blocks) {
    const blockViolations = evaluateBodyAgainstConstraints(block.body, {
      filePath: document.file,
    });
    for (const violation of blockViolations) {
      // Re-anchor the violation line to the document-absolute line
      // number (the registry returns block-relative line numbers).
      const absoluteLine = block.content_start_line + violation.line - 1;
      violations.push({
        ...violation,
        block_kind: block.kind,
        block_name: block.name,
        line: absoluteLine,
      });
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
  return { files_inspected: inspected, violations };
}

function formatViolation(violation) {
  const relativePath = path.relative(ROOT, violation.file);
  const where = violation.block_name
    ? `${violation.block_kind}="${violation.block_name}"`
    : violation.block_kind;
  return `[${violation.source_kind}:${violation.constraint_id}] ${relativePath}:${violation.line}:${violation.column}  ${where}\n    subject: ${violation.subject}\n    runtime: ${violation.action}\n    snippet: ${violation.snippet}\n    remediation: ${violation.remediation}`;
}

function main() {
  const result = runCheck();
  if (result.violations.length === 0) {
    console.log(`check:skill-runtime-constraint-drift — ${result.files_inspected.length} files OK`);
    return;
  }
  for (const violation of result.violations) {
    console.error(formatViolation(violation));
  }
  console.error(`\ncheck:skill-runtime-constraint-drift — ${result.violations.length} violation(s) across ${result.files_inspected.length} files`);
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
};
