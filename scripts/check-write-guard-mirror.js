"use strict";
// E1 — write-guard mirror drift guard.
//
// The Claude write guard (.claude/hooks/session-write-guard.sh) and the Kimi
// hand-mirror (adapters/kimi/hooks/session-write-guard.sh) share a SECURITY-
// CRITICAL analysis core: everything before the `# Main` dispatch line (the
// table loader, the path resolver, check_file, and the whole shell/script
// write-detection recursion). A guard change lands in that shared core, so if a
// future edit touches one file but not the other, the mirror silently desyncs
// and the two adapters enforce different policy (split-brain). This check makes
// that impossible to land quietly.
//
// Contract:
//   * The two SHARED CORES (every line before `# Main`) must be byte-identical
//     EXCEPT a single whitelisted line-13 install-path comment. Any other core
//     divergence is a desync -> FAIL.
//   * The two `# Main` dispatch blocks ARE allowed to differ — that difference
//     is the entire documented Kimi delta (raw_input extraction + isinstance
//     hardening + the LOUD fail-open warning). To keep that delta from drifting
//     unnoticed, each main block is pinned to a blessed fingerprint; an
//     unblessed edit to EITHER main block -> FAIL with a re-bless instruction.
//
// Re-blessing a deliberate main-block change: update the matching
// EXPECTED_*_MAIN_SHA below. The core-equality assertion has no fingerprint to
// bless — it is structural and always enforced.

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const REPO_ROOT = path.join(__dirname, "..");
const CLAUDE_HOOK = path.join(REPO_ROOT, ".claude", "hooks", "session-write-guard.sh");
const KIMI_HOOK = path.join(REPO_ROOT, "adapters", "kimi", "hooks", "session-write-guard.sh");

// The Main-dispatch marker that partitions every guard into (shared core, main).
const MAIN_MARKER = "# Main";

// The ONE whitelisted shared-core divergence: the line-13 install-path comment.
// Claude: "# this hook (installed via the Claude adapter HOOK_DATA_FILES)."
// Kimi:   "# this hook (the kimi install copies it into .kimi/hooks/)."
// Both begin with this stable prefix; the check normalizes the whole line so the
// install-path wording can differ but nothing else on that line can.
const WHITELISTED_COMMENT_PREFIX = "# this hook (";

// Blessed fingerprints of each adapter's `# Main` dispatch block (joined with
// "\n", including the marker line). Re-bless by updating these after an
// intentional main-block change.
const EXPECTED_CLAUDE_MAIN_SHA =
  "4e2df0ffb16bb7c3042c711fbc4449f0146d7d14b571399a9955933292782d6e";
const EXPECTED_KIMI_MAIN_SHA =
  "b8a7d0429d01a7b7b8b711115d6d06ad649aee2e4a2edba87c6ba8c270fb6343";

function sha256(text) {
  return crypto.createHash("sha256").update(text).digest("hex");
}

function partition(filePath) {
  const lines = fs.readFileSync(filePath, "utf8").split("\n");
  const idx = lines.findIndex((l) => l.trim() === MAIN_MARKER);
  if (idx === -1) {
    throw new Error(
      `${path.relative(REPO_ROOT, filePath)}: no '${MAIN_MARKER}' marker found — ` +
        "cannot partition the guard into shared core + main dispatch."
    );
  }
  return { core: lines.slice(0, idx), main: lines.slice(idx) };
}

// Collapse the whitelisted line-13 install-path comment so its install-path
// wording (the only blessed core difference) does not register as a divergence.
function normalizeCore(coreLines) {
  return coreLines.map((line) =>
    line.startsWith(WHITELISTED_COMMENT_PREFIX) ? `${WHITELISTED_COMMENT_PREFIX}NORMALIZED)` : line
  );
}

function main() {
  const failures = [];

  const claude = partition(CLAUDE_HOOK);
  const kimi = partition(KIMI_HOOK);

  // 1) Shared-core equality (modulo the one whitelisted comment). This is the
  //    desync trap: a guard change to one core but not the other fails here.
  const claudeCore = normalizeCore(claude.core);
  const kimiCore = normalizeCore(kimi.core);
  if (claudeCore.length !== kimiCore.length) {
    failures.push(
      `Shared cores differ in length (claude=${claudeCore.length}, ` +
        `kimi=${kimiCore.length}). A guard change landed in one core but not ` +
        "the other — the write-guard mirror has desynced."
    );
  } else {
    const firstDiff = claudeCore.findIndex((l, i) => l !== kimiCore[i]);
    if (firstDiff !== -1) {
      failures.push(
        `Shared cores diverge at core line ${firstDiff + 1} (the only blessed ` +
          "difference is the line-13 install-path comment):\n" +
          `  claude: ${JSON.stringify(claude.core[firstDiff])}\n` +
          `  kimi:   ${JSON.stringify(kimi.core[firstDiff])}\n` +
          "A guard change must be applied IDENTICALLY to both hooks."
      );
    }
  }

  // 2) Each main-block fingerprint pin. The blocks are allowed to differ from
  //    each other (the documented Kimi delta), but neither may change without a
  //    conscious re-bless.
  const claudeMainSha = sha256(claude.main.join("\n"));
  const kimiMainSha = sha256(kimi.main.join("\n"));
  if (claudeMainSha !== EXPECTED_CLAUDE_MAIN_SHA) {
    failures.push(
      `Claude '${MAIN_MARKER}' block changed (sha ${claudeMainSha}, expected ` +
        `${EXPECTED_CLAUDE_MAIN_SHA}). If intentional, re-bless ` +
        "EXPECTED_CLAUDE_MAIN_SHA in scripts/check-write-guard-mirror.js."
    );
  }
  if (kimiMainSha !== EXPECTED_KIMI_MAIN_SHA) {
    failures.push(
      `Kimi '${MAIN_MARKER}' block changed (sha ${kimiMainSha}, expected ` +
        `${EXPECTED_KIMI_MAIN_SHA}). If intentional, re-bless ` +
        "EXPECTED_KIMI_MAIN_SHA in scripts/check-write-guard-mirror.js."
    );
  }

  if (failures.length) {
    console.error("check:write-guard-mirror FAILED:");
    for (const f of failures) {
      console.error(`  - ${f}`);
    }
    process.exit(1);
  }

  console.log(
    "check:write-guard-mirror OK — claude/kimi write-guard shared cores are " +
      "identical (modulo the blessed install-path comment) and both main blocks " +
      "match their blessed fingerprints."
  );
}

main();
