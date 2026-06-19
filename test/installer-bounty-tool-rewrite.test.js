"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  CANONICAL_PERMISSION_PREFIX,
  PRESERVED_BOUNTY_TOOL_NAMES,
  mergeSettings,
  migrateLegacySettings,
  rewriteLegacyToolNamePermission,
} = require("../scripts/merge-claude-config.js");
const {
  defaultClaudeSettings,
  permissionsForAllTools,
} = require("../adapters/claude/config.js");

// Build a representative v1.x .claude/settings.json that has already had its
// server key rewritten (mcp__hacker-bob__...) but still carries the legacy
// `bounty_*` tool-suffix from the pre-P.1 rename generation. This mirrors
// the empirical state observed in installs upgraded with the
// installer-cleanup-cycle shim, which handled the server prefix but not the
// tool-name suffix.
function buildV1HackerBobSettings() {
  return {
    permissions: {
      allow: [
        "mcp__hacker-bob__bounty_init_session",
        "mcp__hacker-bob__bounty_http_scan",
        // Bona-fide P.1 deprecation-shim tool — owns its own primary handler
        // and must keep the bounty_ prefix in the permission allow-list
        // because the server still dispatches it under that exact name.
        "mcp__hacker-bob__bounty_transition_phase",
        "Read",
        "Bash(echo *)",
      ],
    },
    customSetting: true,
  };
}

test("rewriteLegacyToolNamePermission rewrites canonical-prefix bounty_ suffixes to bob_", () => {
  assert.equal(
    rewriteLegacyToolNamePermission("mcp__hacker-bob__bounty_init_session"),
    "mcp__hacker-bob__bob_init_session",
  );
  assert.equal(
    rewriteLegacyToolNamePermission("mcp__hacker-bob__bounty_http_scan"),
    "mcp__hacker-bob__bob_http_scan",
  );
  // Multi-underscore suffix (bounty_list_auth_profiles -> bob_list_auth_profiles).
  assert.equal(
    rewriteLegacyToolNamePermission("mcp__hacker-bob__bounty_list_auth_profiles"),
    "mcp__hacker-bob__bob_list_auth_profiles",
  );
});

test("rewriteLegacyToolNamePermission preserves bona-fide P.1 deprecation-shim tool names", () => {
  for (const preserved of PRESERVED_BOUNTY_TOOL_NAMES) {
    const fullPermission = `${CANONICAL_PERMISSION_PREFIX}${preserved}`;
    assert.equal(
      rewriteLegacyToolNamePermission(fullPermission),
      fullPermission,
      `${preserved} must be preserved (owns its own primary handler with legacy schema)`,
    );
  }
});

test("rewriteLegacyToolNamePermission is idempotent on canonical and unrelated permissions", () => {
  // Canonical bob_ permission passes through unchanged.
  assert.equal(
    rewriteLegacyToolNamePermission("mcp__hacker-bob__bob_http_scan"),
    "mcp__hacker-bob__bob_http_scan",
  );
  // Non-bounty mcp__hacker-bob__ permission (operator-added custom tool)
  // passes through unchanged because the suffix doesn't start with `bounty_`.
  assert.equal(
    rewriteLegacyToolNamePermission("mcp__hacker-bob__custom_user_tool"),
    "mcp__hacker-bob__custom_user_tool",
  );
  // Permissions still under the legacy `mcp__bountyagent__` server prefix
  // are owned by the server-key rewrite step; this function does not touch
  // them.
  assert.equal(
    rewriteLegacyToolNamePermission("mcp__bountyagent__bounty_init_session"),
    "mcp__bountyagent__bounty_init_session",
  );
  // Unrelated permission strings pass through.
  assert.equal(rewriteLegacyToolNamePermission("Read"), "Read");
  assert.equal(rewriteLegacyToolNamePermission("Bash(echo *)"), "Bash(echo *)");
  assert.equal(rewriteLegacyToolNamePermission(undefined), undefined);
});

test("migrateLegacySettings rewrites bounty_* tool suffixes and preserves the bona-fide shim", () => {
  const v1 = buildV1HackerBobSettings();
  const result = migrateLegacySettings(v1);
  assert.equal(result.migrated, true);

  const allow = result.value.permissions.allow;
  // Rewritten canonical suffixes.
  assert.ok(
    allow.includes("mcp__hacker-bob__bob_init_session"),
    "mcp__hacker-bob__bounty_init_session must be rewritten to bob_init_session",
  );
  assert.ok(
    allow.includes("mcp__hacker-bob__bob_http_scan"),
    "mcp__hacker-bob__bounty_http_scan must be rewritten to bob_http_scan",
  );
  // Legacy strings dropped after rewrite.
  assert.ok(!allow.includes("mcp__hacker-bob__bounty_init_session"));
  assert.ok(!allow.includes("mcp__hacker-bob__bounty_http_scan"));
  // Bona-fide P.1 deprecation-shim tool is preserved verbatim.
  assert.ok(
    allow.includes("mcp__hacker-bob__bounty_transition_phase"),
    "bounty_transition_phase must be preserved (owns its own handler)",
  );
  // Operator-authored unrelated entries survive.
  assert.ok(allow.includes("Read"));
  assert.ok(allow.includes("Bash(echo *)"));
  // Unrelated keys survive.
  assert.equal(result.value.customSetting, true);
  // Dedupe: every entry appears at most once.
  assert.equal(allow.length, new Set(allow).size);
});

test("migrateLegacySettings is a no-op when no legacy bounty_* permissions are present", () => {
  // Settings without any bounty_* suffix — only canonical bob_* permissions,
  // non-mcp permissions, and the bona-fide deprecation shim (which is not a
  // "legacy" entry, it's intentional).
  const clean = {
    permissions: {
      allow: [
        "mcp__hacker-bob__bob_init_session",
        "mcp__hacker-bob__bob_http_scan",
        "mcp__hacker-bob__bounty_transition_phase",
        "mcp__hacker-bob__bounty_report_written",
        "Read",
        "Bash(echo *)",
      ],
    },
    customSetting: true,
  };
  const result = migrateLegacySettings(clean);
  assert.equal(result.migrated, false, "no rewrite should be reported when all bounty_ tokens are preserved shims");
  assert.deepEqual(result.value, clean);
});

test("migrateLegacySettings is byte-identical on the second run", () => {
  // Empirical idempotence: feed the v1 input through migrateLegacySettings
  // twice and serialize each run to JSON. The second run must produce the
  // same byte sequence so a re-install on an already-upgraded workspace
  // introduces zero diff.
  const v1 = buildV1HackerBobSettings();
  const firstRun = migrateLegacySettings(v1);
  const firstJson = JSON.stringify(firstRun.value, null, 2);

  const secondRun = migrateLegacySettings(firstRun.value);
  const secondJson = JSON.stringify(secondRun.value, null, 2);

  assert.equal(secondRun.migrated, false, "second run reports no migration");
  assert.equal(secondJson, firstJson, "second-run output must be byte-identical to first-run output");
});

test("mergeSettings adds missing canonical primary permissions on upgrade", () => {
  // Fixture: a settings.json that lacks every canonical browser-driver and
  // pack-telemetry permission. After mergeSettings runs, every canonical
  // primary tool surfaced by permissionsForAllTools() must appear in the
  // allow-list, modulo the stale-global filter.
  const existing = {
    permissions: {
      allow: [
        "mcp__hacker-bob__bob_http_scan",
        "Read",
      ],
    },
  };
  const merged = mergeSettings(existing, defaultClaudeSettings());

  // Canonical T.1/T.7 browser-driver tools land on upgrade.
  assert.ok(
    merged.permissions.allow.includes("mcp__hacker-bob__bob_browser_navigate"),
    "bob_browser_navigate must land in the allow-list on upgrade",
  );
  assert.ok(
    merged.permissions.allow.includes("mcp__hacker-bob__bob_browser_session_start"),
    "bob_browser_session_start must land in the allow-list on upgrade",
  );
  assert.ok(
    merged.permissions.allow.includes("mcp__hacker-bob__bob_browser_session_start_recording"),
    "bob_browser_session_start_recording (T.7) must land in the allow-list on upgrade",
  );
  assert.ok(
    merged.permissions.allow.includes("mcp__hacker-bob__bob_browser_flush_recorded_requests"),
    "bob_browser_flush_recorded_requests (T.7) must land in the allow-list on upgrade",
  );
  // Canonical T.8 pack-telemetry tool lands on upgrade.
  assert.ok(
    merged.permissions.allow.includes("mcp__hacker-bob__bob_set_pack_telemetry_config"),
    "bob_set_pack_telemetry_config (T.8) must land in the allow-list on upgrade",
  );

  // Pre-existing entries survive.
  assert.ok(merged.permissions.allow.includes("mcp__hacker-bob__bob_http_scan"));
  assert.ok(merged.permissions.allow.includes("Read"));

  // Allow-list is deduped.
  assert.equal(merged.permissions.allow.length, new Set(merged.permissions.allow).size);
});

test("mergeSettings is byte-identical on the second run over its own output", () => {
  // Idempotence end-to-end: run mergeSettings twice, serialize each result,
  // and assert byte equality.
  const v1 = buildV1HackerBobSettings();
  const bob = defaultClaudeSettings();
  const firstRun = mergeSettings(v1, bob);
  const firstJson = JSON.stringify(firstRun, null, 2);

  const secondRun = mergeSettings(firstRun, bob);
  const secondJson = JSON.stringify(secondRun, null, 2);

  assert.equal(secondJson, firstJson, "second mergeSettings run must produce byte-identical output");
});

test("mergeSettings on a bounty_*-laden v1 surface ends with the canonical bob_* set + bona-fide shim", () => {
  // Combined surface test: starting from buildV1HackerBobSettings(),
  // mergeSettings must produce the canonical bob_* permissions for every
  // tool plus the preserved bounty_transition_phase shim entry.
  const merged = mergeSettings(buildV1HackerBobSettings(), defaultClaudeSettings());
  const allow = merged.permissions.allow;

  // Rewrites land.
  assert.ok(allow.includes("mcp__hacker-bob__bob_init_session"));
  assert.ok(allow.includes("mcp__hacker-bob__bob_http_scan"));
  // Legacy suffix forms are gone for non-shim tools.
  assert.ok(!allow.includes("mcp__hacker-bob__bounty_init_session"));
  assert.ok(!allow.includes("mcp__hacker-bob__bounty_http_scan"));
  // Bona-fide shim survives.
  assert.ok(allow.includes("mcp__hacker-bob__bounty_transition_phase"));
  // Operator entries survive.
  assert.ok(allow.includes("Read"));
  assert.ok(allow.includes("Bash(echo *)"));
  // Unrelated keys survive.
  assert.equal(merged.customSetting, true);
});

test("permissionsForAllTools covers the canonical surfaces this migration adds", () => {
  // Sanity guard: if a future refactor changes the source of canonical
  // permissions, this test fails loudly so the migration shim can be retuned.
  const all = permissionsForAllTools();
  assert.ok(all.includes("mcp__hacker-bob__bob_browser_navigate"));
  assert.ok(all.includes("mcp__hacker-bob__bob_browser_session_start_recording"));
  assert.ok(all.includes("mcp__hacker-bob__bob_browser_flush_recorded_requests"));
  assert.ok(all.includes("mcp__hacker-bob__bob_set_pack_telemetry_config"));
});
