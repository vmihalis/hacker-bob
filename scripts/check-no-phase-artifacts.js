#!/usr/bin/env node
"use strict";

// `check:no-phase-artifacts` — enforces feedback_no_phase_artifacts: source,
// tests, CHANGELOG, and comments must explain the CURRENT invariant, never the
// development narrative (how the code arrived). The codebase explains the
// constraint; the PR description and release notes are the home for narrative.
//
// This gate is DIFF-AWARE: it flags dev-narrative tokens introduced in ADDED
// lines (against HEAD) only, so pre-existing committed labels do not trip it
// while every NEW leak is caught. Most narrative tends to hide in comments
// (`//`, `#`, `/* */`) and test-name strings (`test("...")` / `it("...")`), so
// the broad FORBIDDEN shapes scan only those slices. One leak class is sneakier
// — a session-local node id embedded in plain-code STRING LITERALS, fixture
// names, or assert messages (a tmpdir prefix `"bob-g4-…"`, a fake domain
// `"g6-…example.com"`, an assert message `"…g7 leak guard"`). The tightly
// anchored `node-id-literal` rule scans the WHOLE line for exactly that shape.
//
// The scan is locale-safe: input is read as UTF-8 bytes and em-dashes (U+2014)
// and en-dashes (U+2013) are normalized before matching, so a run never depends
// on LC_* / LANG and never misclassifies a multibyte dash boundary.
//
// Precision is favored over recall: the FORBIDDEN list targets unambiguous
// narrative tokens, and an ALLOWLIST exempts registry/invariant tags
// (INV-7, S3/I6/C2/X.6/Y-P13/Y-D15b/Y-R17, T-R1/T-P2/T-D3), finding ids
// (R2-HIGH), and domain chain-phase usages (F1/F2 as on-chain reachability
// phases). Better to miss an edge case than to block legitimate prose.
//
// Exit non-zero on a hit with a precise `file:line` message.
//
// Flags:
//   --root <dir>     repo root override (default: parent of scripts/)
//   --base <ref>     diff base (default: HEAD)
//   --text "<...>"   scan a literal string instead of the diff (for tests)
//   --quiet          suppress the OK line

const { execFileSync } = require("child_process");
const path = require("path");

const ROOT = path.join(__dirname, "..");

// File extensions whose ADDED lines we scan. Prose-only docs (.md) are scanned
// EXCEPT the narrative homes that are allowed to carry timeline language.
const SCANNED_EXT = new Set([".js", ".mjs", ".cjs", ".ts", ".py", ".sh", ".md"]);

// Narrative homes — these files exist to carry the development story, so their
// added lines are NOT scanned. (CHANGELOG remains scanned: the feedback names
// it explicitly as a place that must stay invariant-anchored.)
const NARRATIVE_HOME_BASENAMES = new Set([
  "README.md",
  "CONTRIBUTING.md",
]);
const NARRATIVE_HOME_DIR_PARTS = new Set(["docs"]);

// The gate's own regression fixtures deliberately embed planted narrative so the
// FORBIDDEN shapes stay covered. Exempt those two files from the diff scan, the
// way a registry orphan-check exempts the files that mirror its full token set.
const SELF_FIXTURE_RELPATHS = new Set([
  path.join("test", "no-phase-artifacts.test.js"),
  path.join("scripts", "check-no-phase-artifacts.js"),
]);

// Normalize unicode dashes (em-dash U+2014, en-dash U+2013) to ASCII hyphen so
// a dash-joined token boundary is matched the same as an ASCII run. Keeps
// matching independent of the byte encoding of the surrounding prose.
function normalizeDashes(s) {
  return s.replace(/[–—]/g, "-");
}

// FORBIDDEN — dev-narrative token shapes. Each is anchored to avoid matching
// inside larger words. Authored to be unambiguous (precision over recall).
const FORBIDDEN = [
  { id: "phase-number", re: /\bphase\s+\d+\b/i, why: "phase label" },
  { id: "phase-letter", re: /\bphase\s+[A-F]\b/i, why: "phase label" },
  { id: "step-letter", re: /\bStep[\s-]+[AB]\b/, why: "step label" },
  { id: "cycle-number", re: /\bcycle\s+\d+\b/i, why: "cycle label" },
  { id: "fixup", re: /\bfix-?up\b/i, why: "fix-up narrative tag" },
  { id: "roast", re: /\broast\b/i, why: "roast-round reference" },
  { id: "yagni", re: /\bYAGNI\b/, why: "YAGNI narrative tag" },
  // A bare session-local node id used as a LEADING label in a comment or test
  // name, e.g. "// F1-a3 …" or "// g4 host …". The ALLOWLIST below rescues the
  // legitimate homonyms (registry tags, finding ids, domain F1/F2 phases). The
  // node-id families with NO registry homonym (`F1-[a-e]\d`, `g\d`) are listed
  // here; `C\d` is intentionally NOT — every `C\d` is allowlisted as a registry
  // tag (the `[SICX]-?\d` family), so a leading `C\d` arm would be unreachable.
  { id: "leading-node-id", re: /^\s*(?:F1-[a-e]\d*|g\d+)\b/, why: "bare node-id label" },
  // The `OW` node-id family (OW1..OW5, OW2-audit, OW3-binding-precision, and the
  // hyphenated slugs OW-idx / OW-cwe / OW-induct / OW-meas / OW-D1 …) used as a
  // label ANYWHERE in a comment or test name. Case-sensitive `OW` so OWASP,
  // window, below, workflow, grow2, flow3 never match (the boundary requires an
  // uppercase O at a word edge followed by a digit or a hyphen+letter). No
  // legitimate homonym, so it is NOT allowlist-rescued.
  { id: "node-id-ow", re: /\bOW(?:\d+\b|-[A-Za-z])/, why: "OW node-id label" },
  // The `UF` (universal fan-out) arc node-id family (UF1..UF5, UF-meas, UF-D1,
  // the hyphenated slugs UF-idx-style). Same case-sensitive boundary so UTF-8,
  // buffer, stuff never match (the boundary needs an uppercase U+F at a word
  // edge followed by a digit or a hyphen+letter). No legitimate homonym.
  { id: "node-id-uf", re: /\bUF(?:\d+\b|-[A-Za-z])/, why: "UF node-id label" },
  // The same node-id families used as an in-STRING label/prefix or identifier,
  // not just a leading comment token: a tmpdir/fixture prefix ("bob-g4-…"), a
  // fake domain ("g6-…example.com"), a hyphen-joined label ("F1-a3"), or a
  // space-delimited node id inside a quoted string / assert message
  // ("…the g7 leak guard…", "…else the g3 wall is vacuous"). Two anchors:
  //   (a) the node id sits adjacent to a quote/hyphen/dot/`bob-` boundary, OR
  //   (b) a quote/space then a standalone `gN ` token followed by a lowercase
  //       narrative word.
  // Both keep ordinary letter+digit identifiers (log2, http200, sha256) and
  // domain F1/F2 prose (rescued by the allowlist) from matching.
  {
    id: "node-id-literal",
    re: /(?:["'`-]|\bbob-)(?:F1-[a-e]\d+|g\d+)(?=["'`. -])|["'`\s]g\d+ (?=[a-z])/,
    why: "node-id label in a string/identifier",
  },
];

// ALLOWLIST — legitimate tokens whose presence on a line EXEMPTS that line from
// the leading-node-id rule (and only that rule, since the other FORBIDDEN
// shapes have no legitimate homonym). Registry/invariant tags, finding ids,
// task-graph tags, and domain chain-phase usages live here.
const ALLOWLIST = [
  /\bINV-\d+\b/,                       // INV-7
  /\b[SICX]-?\d/,                      // S3 / I6 / C2 / X6 (anchored families)
  /\bX\.\d/,                           // X.6
  /\bY-[PDR]\d/,                       // Y-P13 / Y-D15b / Y-R17
  /\bT-[RPD]\d/,                       // T-R1 / T-P2 / T-D3
  /\bR\d+-(?:HIGH|MED(?:IUM)?|LOW|CRIT(?:ICAL)?|INFO)\b/, // R2-HIGH finding id
  /\bchain[_ -]?phase\b/i,             // explicit domain chain-phase prose
  /\bF[12]\b.*\b(?:chain|reach|phase|on-?chain|leaf|frontier)\b/i, // F1/F2 domain phase
];

function isScannablePath(relPath) {
  if (SELF_FIXTURE_RELPATHS.has(relPath)) return false;
  const ext = path.extname(relPath).toLowerCase();
  if (!SCANNED_EXT.has(ext)) return false;
  const base = path.basename(relPath);
  if (NARRATIVE_HOME_BASENAMES.has(base)) return false;
  const parts = relPath.split(path.sep).filter(Boolean);
  if (parts.some((p) => NARRATIVE_HOME_DIR_PARTS.has(p))) return false;
  return true;
}

// Extract the narrative-bearing slices of a line: comment bodies and the inside
// of test()/it() name strings. Returns an array of substrings to match against.
// Conservative by design — if no comment/test-name slice is found we return [],
// so plain code identifiers never trip the scan.
function narrativeSlices(line) {
  const slices = [];
  // Line comments: `// …`, `# …` (skip `#!` shebang). Capture to end of line.
  const lineComment = line.match(/(?:\/\/|#(?!!))(.*)$/);
  if (lineComment) slices.push(lineComment[1]);
  // Block-comment fragments on this line: `/* … */` or `* …` continuation.
  const block = line.match(/\/\*(.*?)(?:\*\/|$)/);
  if (block) slices.push(block[1]);
  const blockCont = line.match(/^\s*\*\s?(.*)$/);
  if (blockCont) slices.push(blockCont[1]);
  // test("name") / it('name') / test(`name`) — capture the quoted name only.
  const testName = line.match(/\b(?:test|it|describe)\s*\(\s*(["'`])([\s\S]*?)\1/);
  if (testName) slices.push(testName[2]);
  return slices;
}

// Rules that have legitimate homonyms (registry tags, finding ids, domain
// F1/F2 phases); an allowlisted tag on the same slice rescues these.
const ALLOWLIST_RESCUED = new Set(["leading-node-id", "node-id-literal"]);

// Scan ONE slice against the slice-scoped FORBIDDEN shapes (everything except
// `node-id-literal`, which is whole-line-scoped). Returns the first match, or null.
function scanSlice(rawSlice) {
  const slice = normalizeDashes(rawSlice);
  const allowed = ALLOWLIST.some((re) => re.test(slice));
  for (const rule of FORBIDDEN) {
    if (rule.id === "node-id-literal") continue; // whole-line rule, applied in scanLine
    if (ALLOWLIST_RESCUED.has(rule.id) && allowed) continue;
    if (rule.re.test(slice)) return rule;
  }
  return null;
}

// Scan a whole line. The slice-scoped shapes run over comment/test-name slices;
// the `node-id-literal` shape runs over the entire (dash-normalized) line so a
// node id hiding in a string literal / identifier / assert message is caught.
// Returns {rule, slice} or null.
function scanLine(line) {
  for (const slice of narrativeSlices(line)) {
    const rule = scanSlice(slice);
    if (rule) return { rule, slice: slice.trim() };
  }
  const whole = normalizeDashes(line);
  const allowed = ALLOWLIST.some((re) => re.test(whole));
  const nodeIdLiteral = FORBIDDEN.find((r) => r.id === "node-id-literal");
  if (!allowed && nodeIdLiteral.re.test(whole)) {
    return { rule: nodeIdLiteral, slice: line.trim() };
  }
  return null;
}

// Parse `git diff --unified=0` into { file, newLineNo, text } records for every
// ADDED line. Locale-safe: the diff is captured as a UTF-8 buffer.
function parseAddedLines(diffText) {
  const added = [];
  let file = null;
  let newLineNo = 0;
  for (const raw of diffText.split("\n")) {
    if (raw.startsWith("+++ b/")) {
      file = raw.slice("+++ b/".length);
      continue;
    }
    if (raw.startsWith("+++ ")) {
      // e.g. "+++ /dev/null" (deletion) — no new-side file.
      file = null;
      continue;
    }
    const hunk = raw.match(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
    if (hunk) {
      newLineNo = parseInt(hunk[1], 10);
      continue;
    }
    if (raw.startsWith("+") && !raw.startsWith("+++")) {
      if (file) added.push({ file, lineNo: newLineNo, text: raw.slice(1) });
      newLineNo += 1;
      continue;
    }
    if (raw.startsWith("-") || raw.startsWith("\\")) {
      // removed line / "no newline" marker — does not advance the new-side counter.
      continue;
    }
    // context line (only present with >0 context; we request 0, but be safe)
    if (!raw.startsWith("diff ") && !raw.startsWith("index ") &&
        !raw.startsWith("--- ") && !raw.startsWith("@@")) {
      newLineNo += 1;
    }
  }
  return added;
}

function getDiff(root, base) {
  // --unified=0: only changed lines, no context. -M: rename-aware. Includes
  // staged + unstaged + untracked-via-intent is NOT default; we add untracked
  // files explicitly so a brand-new leaking file is caught.
  const tracked = execFileSync(
    "git",
    ["diff", "--no-color", "--unified=0", "-M", base, "--", "."],
    { cwd: root, maxBuffer: 64 * 1024 * 1024 },
  ).toString("utf8");
  // Untracked files: diff each against /dev/null so its lines are "added".
  let untrackedDiff = "";
  const untracked = execFileSync(
    "git",
    ["ls-files", "--others", "--exclude-standard"],
    { cwd: root, maxBuffer: 16 * 1024 * 1024 },
  ).toString("utf8").split("\n").filter(Boolean);
  for (const f of untracked) {
    if (!isScannablePath(f)) continue;
    try {
      untrackedDiff += execFileSync(
        "git",
        ["diff", "--no-color", "--unified=0", "--no-index", "/dev/null", f],
        { cwd: root, maxBuffer: 64 * 1024 * 1024 },
      ).toString("utf8");
    } catch (err) {
      // --no-index exits 1 when files differ (always, vs /dev/null); the diff is
      // on stdout regardless.
      if (err.stdout) untrackedDiff += err.stdout.toString("utf8");
    }
  }
  return tracked + "\n" + untrackedDiff;
}

// run() — collect violations from the diff (or an explicit text override).
// Returns { violations: [{file, line, rule, why, slice}], scanned }.
function run({ root = ROOT, base = "HEAD", text = null } = {}) {
  if (text !== null) {
    const hit = scanLine(text);
    return {
      violations: hit ? [{ file: "<text>", line: 1, rule: hit.rule.id, why: hit.rule.why, slice: hit.slice }] : [],
      scanned: 1,
    };
  }
  const diff = getDiff(root, base);
  const added = parseAddedLines(diff);
  const violations = [];
  for (const { file, lineNo, text: lineText } of added) {
    if (!isScannablePath(file)) continue;
    const hit = scanLine(lineText);
    if (hit) {
      violations.push({
        file,
        line: lineNo,
        rule: hit.rule.id,
        why: hit.rule.why,
        slice: hit.slice,
      });
    }
  }
  return { violations, scanned: added.length };
}

function main() {
  const argv = process.argv.slice(2);
  const opts = { root: ROOT, base: "HEAD", text: null, quiet: false };
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === "--root" && argv[i + 1]) opts.root = path.resolve(argv[++i]);
    else if (argv[i] === "--base" && argv[i + 1]) opts.base = argv[++i];
    else if (argv[i] === "--text" && argv[i + 1]) opts.text = argv[++i];
    else if (argv[i] === "--quiet") opts.quiet = true;
  }
  const { violations, scanned } = run(opts);
  if (violations.length) {
    console.error(
      "no-phase-artifacts: dev-narrative tokens in ADDED lines " +
      "(anchor on the current invariant; narrative belongs in the PR/release notes):",
    );
    for (const v of violations) {
      console.error(`  ${v.file}:${v.line}  ${v.why} — "${v.slice}"`);
    }
    process.exit(1);
  }
  if (!opts.quiet) {
    console.log(`no-phase-artifacts OK: ${scanned} added line(s) scanned, no narrative tokens`);
  }
}

if (require.main === module) {
  main();
}

module.exports = {
  run,
  scanLine,
  scanSlice,
  narrativeSlices,
  parseAddedLines,
  normalizeDashes,
  isScannablePath,
  FORBIDDEN,
  ALLOWLIST,
};
