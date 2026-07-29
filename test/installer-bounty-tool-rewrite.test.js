"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  CANONICAL_PERMISSION_PREFIX,
  assertLegacyToolPermissionsMigratable,
  mergeSettings,
  migrateLegacySettings,
  rewriteLegacyToolNamePermission,
  unmigratableLegacyToolPermissions,
} = require("../scripts/merge-claude-config.js");
const {
  defaultClaudeSettings,
  permissionsForAllTools,
} = require("../adapters/claude/config.js");

// Build a representative v1.x .claude/settings.json that has already had its
// server key rewritten (mcp__hacker-bob__...) but still carries the legacy
// `bounty_*` tool-suffix from the pre-rename generation. Every suffix here has
// a live canonical `bob_*` twin, so the installer migrates it cleanly. A
// suffix whose twin was removed in v2.1.0 (report_written, transition_phase)
// has no clean migration and is exercised by the fail-loud tests below.
function buildV1HackerBobSettings() {
  return {
    permissions: {
      allow: [
        "mcp__hacker-bob__bounty_init_session",
        "mcp__hacker-bob__bounty_http_scan",
        "Read",
        "Bash(echo *)",
      ],
    },
    customSetting: true,
  };
}

test("rewriteLegacyToolNamePermission rewrites canonical-prefix bounty_ suffixes with a live bob_ twin", () => {
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

test("rewriteLegacyToolNamePermission fails loud on a removed bounty_* tool with no canonical twin", () => {
  // report_written was deleted (covered by bob_compose_report + bob_finalize_report);
  // transition_phase was deleted (covered by bob_advance_session). Neither has a
  // same-suffix bob_ twin, so a blind rewrite would mint a dead permission.
  for (const removed of ["bounty_report_written", "bounty_transition_phase"]) {
    const fullPermission = `${CANONICAL_PERMISSION_PREFIX}${removed}`;
    assert.throws(
      () => rewriteLegacyToolNamePermission(fullPermission),
      (err) => {
        assert.ok(err instanceof Error);
        // The error names the stale string verbatim and the bob_* replacement
        // guidance so an operator can hand-fix the allow-list.
        assert.match(err.message, /removed bounty_\* tool alias layer/);
        assert.match(err.message, /v2\.1\.0/);
        assert.ok(
          err.message.includes(fullPermission),
          `error must name the stale permission ${fullPermission}`,
        );
        assert.match(
          err.message,
          /bob_finalize_report|bob_advance_session/,
          "error must name a bob_* replacement",
        );
        return true;
      },
      `${removed} must fail loud (no canonical twin to migrate to)`,
    );
  }
});

test("PRE-FLIGHT: unmigratableLegacyToolPermissions collects every stale permission, [] when all migrate", () => {
  // A clean v1.x settings (every suffix has a live twin) → nothing stale.
  assert.deepEqual(unmigratableLegacyToolPermissions(buildV1HackerBobSettings()), []);
  // Mixed: two removed-tool pins (no twin) alongside migratable + unrelated permissions.
  const mixed = {
    permissions: {
      allow: [
        "mcp__hacker-bob__bounty_init_session", // migratable
        "mcp__hacker-bob__bounty_report_written", // removed, no twin
        "Read",
        "mcp__hacker-bob__bounty_transition_phase", // removed, no twin
        "mcp__hacker-bob__bob_http_scan", // already canonical
      ],
    },
  };
  const stale = unmigratableLegacyToolPermissions(mixed);
  assert.deepEqual(
    stale.map((s) => s.permission).sort(),
    ["mcp__hacker-bob__bounty_report_written", "mcp__hacker-bob__bounty_transition_phase"],
  );
  // Empty / shapeless settings never throw and report nothing stale.
  assert.deepEqual(unmigratableLegacyToolPermissions({}), []);
  assert.deepEqual(unmigratableLegacyToolPermissions(null), []);
});

test("PRE-FLIGHT: assertLegacyToolPermissionsMigratable throws ONE comprehensive error naming every stale pin", () => {
  const settings = {
    permissions: {
      allow: ["mcp__hacker-bob__bounty_report_written", "mcp__hacker-bob__bounty_transition_phase"],
    },
  };
  assert.throws(
    () => assertLegacyToolPermissionsMigratable(settings),
    (err) => {
      assert.ok(err instanceof Error);
      // names BOTH stale pins in one error
      assert.ok(err.message.includes("mcp__hacker-bob__bounty_report_written"));
      assert.ok(err.message.includes("mcp__hacker-bob__bounty_transition_phase"));
      assert.match(err.message, /2 stale MCP permission/);
      assert.match(err.message, /bob_finalize_report|bob_advance_session/);
      // makes the atomicity guarantee explicit
      assert.match(err.message, /no files have been modified yet/i);
      return true;
    },
  );
  // A clean settings validates silently (no throw).
  assert.doesNotThrow(() => assertLegacyToolPermissionsMigratable(buildV1HackerBobSettings()));
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

test("migrateLegacySettings rewrites bounty_* tool suffixes that have a live bob_ twin", () => {
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
  // Operator-authored unrelated entries survive.
  assert.ok(allow.includes("Read"));
  assert.ok(allow.includes("Bash(echo *)"));
  // Unrelated keys survive.
  assert.equal(result.value.customSetting, true);
  // Dedupe: every entry appears at most once.
  assert.equal(allow.length, new Set(allow).size);
});

test("migrateLegacySettings fails loud when a removed bounty_* permission is pinned", () => {
  const stale = {
    permissions: {
      allow: [
        "mcp__hacker-bob__bob_init_session",
        "mcp__hacker-bob__bounty_report_written",
        "Read",
      ],
    },
  };
  assert.throws(
    () => migrateLegacySettings(stale),
    /removed bounty_\* tool alias layer.*bob_finalize_report/s,
    "a pinned removed-tool permission must abort the migration with a helpful error",
  );
});

test("migrateLegacySettings is a no-op when no legacy bounty_* permissions are present", () => {
  const clean = {
    permissions: {
      allow: [
        "mcp__hacker-bob__bob_init_session",
        "mcp__hacker-bob__bob_http_scan",
        "Read",
        "Bash(echo *)",
      ],
    },
    customSetting: true,
  };
  const result = migrateLegacySettings(clean);
  assert.equal(result.migrated, false, "no rewrite should be reported when there are no bounty_ tokens");
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

  // Canonical browser-driver tools land on upgrade.
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
    "bob_browser_session_start_recording must land in the allow-list on upgrade",
  );
  assert.ok(
    merged.permissions.allow.includes("mcp__hacker-bob__bob_browser_flush_recorded_requests"),
    "bob_browser_flush_recorded_requests must land in the allow-list on upgrade",
  );
  // Canonical pack-telemetry tool lands on upgrade.
  assert.ok(
    merged.permissions.allow.includes("mcp__hacker-bob__bob_set_pack_telemetry_config"),
    "bob_set_pack_telemetry_config must land in the allow-list on upgrade",
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

test("mergeSettings on a bounty_*-laden v1 surface ends with the canonical bob_* set", () => {
  // Combined surface test: starting from buildV1HackerBobSettings(),
  // mergeSettings must produce the canonical bob_* permissions for every tool.
  const merged = mergeSettings(buildV1HackerBobSettings(), defaultClaudeSettings());
  const allow = merged.permissions.allow;

  // Rewrites land.
  assert.ok(allow.includes("mcp__hacker-bob__bob_init_session"));
  assert.ok(allow.includes("mcp__hacker-bob__bob_http_scan"));
  // Legacy suffix forms are gone.
  assert.ok(!allow.includes("mcp__hacker-bob__bounty_init_session"));
  assert.ok(!allow.includes("mcp__hacker-bob__bounty_http_scan"));
  // No bounty_* tool permission survives the merge.
  assert.ok(!allow.some((perm) => /^mcp__hacker-bob__bounty_/.test(perm)));
  // Operator entries survive.
  assert.ok(allow.includes("Read"));
  assert.ok(allow.includes("Bash(echo *)"));
  // Unrelated keys survive.
  assert.equal(merged.customSetting, true);
});

test("mergeSettings fails loud on a v1 surface pinning a removed bounty_* tool", () => {
  const v1WithRemoved = {
    permissions: {
      allow: [
        "mcp__hacker-bob__bounty_http_scan",
        "mcp__hacker-bob__bounty_transition_phase",
        "Read",
      ],
    },
  };
  assert.throws(
    () => mergeSettings(v1WithRemoved, defaultClaudeSettings()),
    /removed bounty_\* tool alias layer.*bob_advance_session/s,
    "an upgrade that pins a removed bounty_* tool must abort with a helpful error",
  );
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
