"use strict";

// T4 / Y-P13 — in-process audit-graded predicate + whitelist closure.
//
// Scope (honest): this asserts the IN-PROCESS predicate's behavior, the
// whitelist's FLAG↔WHITELIST closure, writer-name normalization, and the
// GROUND-TRUTH writer closure. It does NOT claim to fence the harness Write
// tool — that tool
// is intercepted only by the PreToolUse hook (.claude/hooks/session-write-guard.sh),
// which T3 already renders from paths.js WRITE_GUARD_TABLES (hook↔paths
// agreement is enforced by `npm run check:write-guard-tables`). The in-process
// predicate here guards MCP-INTERNAL writes (belief outputs + composers) as
// defense-in-depth.

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");
const { execFileSync } = require("node:child_process");

const {
  AUDIT_GRADED_PATHS,
  AUDIT_GRADED_WRITER_TOOLS,
  AUDIT_GRADED_WRITER_ALIASES,
  canonicalWriterName,
  assertAgentWriteAllowed,
  auditGradedWriterClosure,
  isAuditGradedPath,
  sessionDir,
} = require("../mcp/lib/paths.js");

const writeBase = require("../mcp/lib/tools/_write-base.js");

// Force every writer module to load so DECLARED_AUDIT_GRADED_WRITERS is the
// all-loaded snapshot before we assert closure.
const WRITER_MODULES = [
  "../mcp/lib/tools/write-verification-round.js",
  "../mcp/lib/tools/write-evidence-packs.js",
  "../mcp/lib/tools/write-grade-verdict.js",
  "../mcp/lib/tools/write-wave-handoff.js",
  "../mcp/lib/tools/write-chain-attempt.js",
  "../mcp/lib/tools/finalize-report.js",
  "../mcp/lib/tools/compose-report.js",
  "../mcp/lib/tools/write-chain-rollup.js",
  "../mcp/lib/tools/amend-report.js",
  "../mcp/lib/tools/write-proof-bundle.js",
  "../mcp/lib/tools/set-friction-scanners.js", // non-audit-graded control
];
const LOADED = WRITER_MODULES.map((m) => require(m));

const DOMAIN = "example.com";

// ---- CLASS 1: in-process null-caller fail-closes on EVERY audit-graded shape.

test("null caller throws in-process for every audit-graded basename", () => {
  for (const basename of AUDIT_GRADED_PATHS.basenames) {
    const target = path.join(sessionDir(DOMAIN), basename);
    assert.ok(isAuditGradedPath(target, DOMAIN), `${basename} must be audit-graded`);
    assert.throws(
      () => assertAgentWriteAllowed(target, DOMAIN, null),
      /MCP-composer-owned/,
      `null-caller write to ${basename} must throw in-process`,
    );
  }
});

test("null caller throws for audit-graded directory + filename-pattern members", () => {
  const dirMember = path.join(sessionDir(DOMAIN), "verification-attempts", "att-1.json");
  const patternMember = path.join(sessionDir(DOMAIN), "handoff-w1-a3.json");
  assert.throws(() => assertAgentWriteAllowed(dirMember, DOMAIN, null), /MCP-composer-owned/);
  assert.throws(() => assertAgentWriteAllowed(patternMember, DOMAIN, null), /MCP-composer-owned/);
});

test("a scratch path is allowed (predicate is scoped, not blanket)", () => {
  const scratch = path.join(sessionDir(DOMAIN), "subdomains.txt");
  assert.equal(assertAgentWriteAllowed(scratch, DOMAIN, null), path.resolve(scratch));
});

test("non-whitelisted MCP tool is treated like a null caller (fail-closed)", () => {
  const target = path.join(sessionDir(DOMAIN), "report.md");
  assert.throws(
    () => assertAgentWriteAllowed(target, DOMAIN, "bob_set_friction_scanners"),
    /MCP-composer-owned/,
  );
});

// ---- CLASS 2: every whitelisted composer is allowed under its canonical name.

test("all 10 whitelisted composers may write report.md (allowed identity)", () => {
  const target = path.join(sessionDir(DOMAIN), "report.md");
  for (const toolName of AUDIT_GRADED_WRITER_TOOLS) {
    assert.equal(
      assertAgentWriteAllowed(target, DOMAIN, toolName),
      path.resolve(target),
      `${toolName} must be allowed to write an audit-graded path`,
    );
  }
});

test("writer-name normalization is the identity now that the alias layer is removed", () => {
  // The v2.1.0 break removed the bounty_* alias layer, so the writer-name map
  // is empty and canonicalWriterName resolves every name to itself.
  assert.deepEqual(AUDIT_GRADED_WRITER_ALIASES, {});
  for (const toolName of AUDIT_GRADED_WRITER_TOOLS) {
    assert.equal(canonicalWriterName(toolName), toolName);
  }
});

test("no whitelisted writer module declares a tool alias", () => {
  // The alias layer is gone: no writer module may carry an aliases array.
  for (const mod of LOADED) {
    if (!AUDIT_GRADED_WRITER_TOOLS.includes(mod.name)) continue;
    assert.ok(
      !Object.prototype.hasOwnProperty.call(mod, "aliases"),
      `${mod.name} must not declare a tool aliases array`,
    );
  }
});

// ---- CLASS 3: FLAG↔WHITELIST closure (the new registry can't drift internally).

test("AUDIT_GRADED_WRITER_TOOLS is a bijection with declared wrapWriteTool writers", () => {
  assert.doesNotThrow(() => writeBase.assertAuditGradedWriterClosure());
  const declared = [...writeBase._internals.DECLARED_AUDIT_GRADED_WRITERS];
  const { ok, orphans, undeclared } = auditGradedWriterClosure(declared);
  assert.ok(ok, `closure violated: orphans=${orphans} undeclared=${undeclared}`);
  assert.equal(declared.length, AUDIT_GRADED_WRITER_TOOLS.length);
});

test("the flag passthrough is preserved on every frozen writer spec", () => {
  for (const mod of LOADED) {
    const expected = AUDIT_GRADED_WRITER_TOOLS.includes(mod.name);
    assert.equal(
      mod.writes_audit_graded, expected,
      `${mod.name} writes_audit_graded must be ${expected}`,
    );
  }
});

test("the non-audit-graded writer is NOT flagged and NOT whitelisted", () => {
  const friction = LOADED.find((m) => m.name === "bob_set_friction_scanners");
  assert.equal(friction.writes_audit_graded, false);
  assert.ok(!AUDIT_GRADED_WRITER_TOOLS.includes("bob_set_friction_scanners"));
});

test("a forged composer name not in the registry cannot register the flag", () => {
  assert.throws(
    () => writeBase.wrapWriteTool({
      name: "bob_evil_writer",
      writes_audit_graded: true,
      inputSchema: { type: "object" },
      handler: () => "x",
    }),
    /whitelist drift/,
  );
});

test("a whitelisted name that forgets the flag is rejected at wrap time", () => {
  assert.throws(
    () => writeBase.wrapWriteTool({
      name: "bob_compose_report", // whitelisted, but flag omitted
      inputSchema: { type: "object" },
      handler: () => "x",
    }),
    /missing declaration/,
  );
});

// ---- CLASS 4: GROUND-TRUTH writer closure (the MAJOR-2 anchor).
// The flag↔whitelist bijection is T4-maintained on both sides. The ground-truth
// guard derives the writer set from a DIFFERENT source — each spec's declared
// session_artifacts_written manifest, classified through isAuditGradedPath — so
// a future wrapWriteTool caller that writes an audit-graded path but forgets the
// flag+whitelist (the I2 class) is caught. We run the real CI guard here.

test("ground-truth writer closure (scripts/check-audit-graded-writers.js) passes", () => {
  assert.doesNotThrow(() => {
    execFileSync("node", [path.resolve(__dirname, "../scripts/check-audit-graded-writers.js")], {
      stdio: "pipe",
    });
  });
});

test("ground-truth derivation independently equals the whitelist", () => {
  // Re-derive in-process from the same independent source the CI guard uses
  // (declared session_artifacts_written), so this assertion does not depend on
  // the flag at all.
  const groundTruth = LOADED
    .filter((mod) =>
      (mod.session_artifacts_written || []).some((artifact) => {
        const normalized = artifact
          .replace(/wN/g, "w1")
          .replace(/aN/g, "a3")
          .replace(/-N-/g, "-1-")
          .replace(/\/$/, "");
        return isAuditGradedPath(path.join(sessionDir(DOMAIN), normalized), DOMAIN);
      }),
    )
    .map((mod) => mod.name)
    .sort();
  assert.deepEqual(groundTruth, [...AUDIT_GRADED_WRITER_TOOLS].sort());
});
