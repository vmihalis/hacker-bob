"use strict";
// T8 (CR-2) — MCP-owned basename inventory closure. Extends T3 (which closed the
// audit-graded subset only). Every session-root path a paths.js resolver
// produces MUST classify into exactly one write-guard class:
//   * under an MCP-owned dir          (HOOK_MCP_OWNED_DIRS),
//   * under an audit-graded dir        (AUDIT_GRADED_RELATIVE_DIRS),
//   * an audit-graded basename/pattern (AUDIT_GRADED_BASENAMES / *_FILENAME_PATTERNS),
//   * an MCP-owned basename/pattern    (HOOK_MCP_OWNED_BASENAMES / *_FILENAME_PATTERNS), or
//   * an agent-writable basename/pattern (HOOK_AGENT_WRITABLE_*).
// Any session-root basename outside all of these is UNCLASSIFIED -> this check
// FAILS, forcing a conscious allow/block decision and keeping the hand-maintained
// HOOK_MCP_OWNED_BASENAMES list closed against the resolver inventory.
//
// It ALSO closes the precedence gap T3 left: the runtime hook tests the
// agent-writable `^.*\.txt$` pattern BEFORE is_mcp_owned, so an MCP-owned `*.txt`
// basename would be silently agent-writable. This check forbids any MCP-owned
// basename (exact list or mcp-owned pattern) from being shadowed by the
// agent-writable `.txt` allow.
//
// Reuses the closure-helper PATTERN: iterate the source-of-truth (the resolver
// inventory), apply a structural predicate (classify), report offenders, and the
// caller asserts the offender array is empty.

const path = require("path");
const {
  WRITE_GUARD_TABLES,
  sessionRootPathInventory,
  INVENTORY_PROBE_DOMAIN,
  sessionDir,
} = require("../mcp/lib/paths.js");

// The agent-writable filename pattern that, when it matches an MCP-owned
// basename, would shadow it at the runtime hook (agent-allow precedes mcp-owned).
const TXT_PATTERN = /^.*\.txt$/;

function buildClasses() {
  const T = WRITE_GUARD_TABLES;
  return {
    auditBasenames: new Set(T.audit_graded_basenames),
    auditPatterns: T.audit_graded_filename_patterns.map((s) => new RegExp(s)),
    auditDirs: T.audit_graded_relative_dirs,
    mcpBasenames: new Set(T.mcp_owned_basenames),
    mcpPatterns: T.mcp_owned_filename_patterns.map((s) => new RegExp(s)),
    mcpDirs: new Set(T.mcp_owned_dirs),
    agentBasenames: new Set(T.agent_writable_basenames),
    agentPatterns: T.agent_writable_filename_patterns.map((s) => new RegExp(s)),
  };
}

// Classify ONE produced path against the hook precedence (dir membership first,
// then basename/pattern). Returns the class label or "unclassified".
function classify(abs, root, C) {
  const rel = path.relative(root, abs);
  const parts = rel.split(path.sep).filter(Boolean);
  if (parts.some((p) => C.mcpDirs.has(p))) return "mcp-owned-dir";
  if (parts.some((p) => C.auditDirs.includes(p))) return "audit-graded-dir";
  const bn = path.basename(abs);
  if (C.auditBasenames.has(bn)) return "audit-graded-basename";
  if (C.auditPatterns.some((re) => re.test(bn))) return "audit-graded-pattern";
  if (C.mcpBasenames.has(bn)) return "mcp-owned-basename";
  if (C.mcpPatterns.some((re) => re.test(bn))) return "mcp-owned-pattern";
  if (C.agentBasenames.has(bn)) return "agent-writable-basename";
  if (C.agentPatterns.some((re) => re.test(bn))) return "agent-writable-pattern";
  return "unclassified";
}

// run() — the closure report. Returns:
//   unclassified[]: { resolver, rel } for every produced session-root path with
//                   no write-guard class (drift offenders),
//   txt_shadowed[]: MCP-owned basenames that ALSO match the agent-writable `.txt`
//                   pattern (the precedence gap), and
//   total:          distinct session-root paths inventoried.
function run() {
  const C = buildClasses();
  const root = path.resolve(sessionDir(INVENTORY_PROBE_DOMAIN));
  const inventory = sessionRootPathInventory(INVENTORY_PROBE_DOMAIN);

  const seen = new Set();
  const unclassified = [];
  for (const { resolver, abs } of inventory) {
    const rel = path.relative(root, abs);
    if (seen.has(rel)) continue;
    seen.add(rel);
    if (classify(abs, root, C) === "unclassified") {
      unclassified.push({ resolver, rel });
    }
  }
  unclassified.sort((a, b) => a.rel.localeCompare(b.rel));

  // Precedence-gap leg: an MCP-owned basename (exact list OR mcp-owned pattern)
  // that matches the agent-writable `.txt` allow is silently writable at the
  // hook. Forbid it. (Pattern members are probed by a representative basename.)
  const txt_shadowed = [];
  for (const bn of WRITE_GUARD_TABLES.mcp_owned_basenames) {
    if (TXT_PATTERN.test(bn)) txt_shadowed.push(bn);
  }
  // Also assert the agent-writable patterns do not contain a `.txt` rule that
  // would precede an MCP-owned `*.txt` basename should one ever be added: if the
  // `.txt` allow exists, no current MCP-owned basename may be a `.txt` (checked
  // above) AND no MCP-owned filename pattern may match a `.txt` basename.
  for (const src of WRITE_GUARD_TABLES.mcp_owned_filename_patterns) {
    const re = new RegExp(src);
    // Probe a synthetic `.txt` basename that the mcp-owned pattern shape could
    // plausibly match; only flag if it actually does.
    const probe = src.includes("txt") ? "probe.txt" : null;
    if (probe && re.test(probe) && TXT_PATTERN.test(probe)) txt_shadowed.push(src);
  }
  txt_shadowed.sort();

  return { unclassified, txt_shadowed, total: seen.size };
}

function main() {
  const { unclassified, txt_shadowed, total } = run();
  if (unclassified.length || txt_shadowed.length) {
    if (unclassified.length) {
      console.error(
        "MCP-owned basename inventory: UNCLASSIFIED session-root basenames " +
        "(add to HOOK_MCP_OWNED_BASENAMES / an MCP-owned dir, or classify " +
        "explicitly in mcp/lib/paths.js):",
      );
      for (const u of unclassified) console.error(`  ${u.rel}  (from ${u.resolver})`);
    }
    if (txt_shadowed.length) {
      console.error(
        "MCP-owned basename inventory: precedence gap — these MCP-owned " +
        "basenames/patterns match the agent-writable `^.*\\.txt$` allow and " +
        "would be SILENTLY agent-writable at the hook:",
      );
      for (const t of txt_shadowed) console.error(`  ${t}`);
    }
    process.exit(1);
  }
  console.log(`MCP-owned basename inventory OK: ${total} session-root paths classified`);
}

if (require.main === module) {
  main();
}

module.exports = { run, classify, buildClasses };
