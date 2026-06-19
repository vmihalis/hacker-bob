#!/usr/bin/env node
"use strict";

// Cycle Y.10 — `check:skill-scheduler-coherence` (Y-D12 / Y-P12).
//
// Secondary CI marker check that consumes the Y-D16 shared parser IR at
// `scripts/lib/skill-parser.js` and asserts that every scheduler
// precondition declared in `mcp/lib/scheduler-preconditions.js`
// `SCHEDULER_PRECONDITION_VALUES` is referenced by at least one
// `@precondition: <name>` HTML-comment directive in the rendered Claude
// skill / agent markdown surface (`.claude/skills/**/SKILL.md` and
// `.claude/agents/**/*.md`).
//
// The primary enforcement for partial-surface advancement remains the
// runtime gate at `mcp/lib/lifecycle-gates.js#gateOpenFrontierToClaimFreeze`
// (Y-P12 primary). This CI marker check is the secondary "operator-visible
// intent" assertion: if a precondition is in the closed enum but no
// rendered state block declares it, the prompt has drifted from the
// runtime contract.
//
// FP-rate budget: ≤2% on the curated corpus under
// `test/fixtures/skill-parser/` (shared with Y.8).

const path = require("path");
const {
  readSkillFile,
  discoverRoleMarkdownFiles,
} = require("./lib/skill-parser.js");
const {
  SCHEDULER_PRECONDITION_VALUES,
} = require("../mcp/lib/scheduler-preconditions.js");

const ROOT = path.join(__dirname, "..");

function checkDocument(document) {
  const violations = [];
  const seenPreconditions = new Set();
  for (const block of document.blocks) {
    for (const directive of block.tokens.preconditions) {
      seenPreconditions.add(directive.token);
      if (!SCHEDULER_PRECONDITION_VALUES.includes(directive.token)) {
        violations.push({
          dimension: "S2_unknown_precondition",
          file: block.file,
          block: block.name,
          line: directive.line,
          column: directive.column,
          token: directive.token,
          message: `@precondition directive cites "${directive.token}" which is not in SCHEDULER_PRECONDITION_VALUES`,
        });
      }
    }
  }
  return { violations, seenPreconditions };
}

function runCheck({ root = ROOT, additionalFiles = [] } = {}) {
  const files = discoverRoleMarkdownFiles(root).concat(additionalFiles);
  const violations = [];
  const inspected = [];
  const seenPreconditions = new Set();
  for (const filePath of files) {
    const document = readSkillFile(filePath);
    const result = checkDocument(document);
    inspected.push({ file: filePath, blocks: document.blocks.length });
    for (const violation of result.violations) {
      violations.push(violation);
    }
    for (const token of result.seenPreconditions) {
      seenPreconditions.add(token);
    }
  }
  // Closed-enum coverage assertion: every declared precondition must be
  // referenced by at least one rendered state block. Drift here means a
  // precondition exists in the runtime registry but no prompt advertises it.
  for (const precondition of SCHEDULER_PRECONDITION_VALUES) {
    if (!seenPreconditions.has(precondition)) {
      violations.push({
        dimension: "S1_unreferenced_precondition",
        file: "(rendered skill/agent corpus)",
        block: null,
        line: 0,
        column: 0,
        token: precondition,
        message: `scheduler precondition "${precondition}" is in SCHEDULER_PRECONDITION_VALUES but no rendered skill/agent state block carries an @precondition directive citing it`,
      });
    }
  }
  return { files_inspected: inspected, violations, seen_preconditions: Array.from(seenPreconditions).sort() };
}

function formatViolation(violation) {
  const relativePath = violation.file === "(rendered skill/agent corpus)"
    ? violation.file
    : path.relative(ROOT, violation.file);
  const location = violation.line ? `:${violation.line}:${violation.column}` : "";
  const blockLabel = violation.block ? ` block="${violation.block}"` : "";
  return `[${violation.dimension}] ${relativePath}${location}${blockLabel}  token=${violation.token}\n    ${violation.message}`;
}

function main() {
  const result = runCheck();
  if (result.violations.length === 0) {
    console.log(`check:skill-scheduler-coherence — ${result.files_inspected.length} files OK (${result.seen_preconditions.length} precondition(s) declared)`);
    return;
  }
  for (const violation of result.violations) {
    console.error(formatViolation(violation));
  }
  console.error(`\ncheck:skill-scheduler-coherence — ${result.violations.length} violation(s) across ${result.files_inspected.length} files`);
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
