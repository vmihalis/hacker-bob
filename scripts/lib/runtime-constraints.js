"use strict";

// Cycle Y.8 — runtime-constraint registry (Y-D17 / Y-P7 third coherence
// dimension; Y-D11 replacement).
//
// Two closed lists declare the constraints any rendered skill or role
// markdown MUST be coherent with:
//
//   * `BINARY_INTERNAL` — patterns the Claude Code binary enforces
//     internally on subagent behavior. The canonical entry citing
//     investigation w0b0v41zw H2 documents the binary-internal subagent
//     Write regex that rejects relative paths from background spawns.
//     A skill instruction that tells a subagent to call `Write("./out")`
//     would silently fail at the binary layer; the
//     `check:skill-runtime-constraint-drift` script flags any such
//     instruction so the source markdown can be corrected before the
//     drift reaches a live run.
//
//   * `BOB_OWNED` — Bob-managed PreToolUse hook contracts that deny
//     specific Bash / Write / Read shapes (the session-write-guard and
//     session-read-guard hooks). A skill instruction that tells an
//     agent to call `Bash("cat ~/hacker-bob-sessions/.../findings.jsonl")`
//     would be blocked by session-read-guard; the check script flags it
//     so the source instructs the agent to use the MCP read tool
//     instead.
//
// Both lists are `Object.freeze`'d. Adding a constraint = one entry in
// the appropriate list plus (optionally) a curated fixture under
// `test/fixtures/skill-parser/` exercising the new entry. Removing a
// constraint requires a coordinated update to the source skill markdown
// AND the test fixtures.

const BINARY_INTERNAL = Object.freeze([
  Object.freeze({
    id: "binary_internal_subagent_write_relative_path",
    pattern: /\b(Write|Edit)\s*\(\s*["']\.\//,
    subject: "subagent Write/Edit with relative path",
    action: "rejected by Claude Code binary-internal regex on background spawns",
    source: "claude-code-binary",
    evidence: "investigation w0b0v41zw H2 — Claude Code binary-internal subagent Write regex rejects relative paths from background subagents; the surface manifests as silent no-op writes when a subagent prompt instructs `Write(\"./out/...\")`",
    remediation: "rewrite the skill instruction to pass an absolute path (e.g., `~/hacker-bob-sessions/[domain]/...`) so the binary-internal write regex accepts the call",
  }),
]);

const BOB_OWNED = Object.freeze([
  Object.freeze({
    id: "bob_owned_session_write_guard_mcp_files",
    pattern: /Bash\s*\(\s*["'][^"']*\b(cat|tee|cp|mv|rm|mkdir|touch)\b[^"']*hacker-bob-sessions\b[^"']*\b(findings\.jsonl|state\.json|auth\.json|attack_surface\.json|surface-routes\.json|wave-handoffs|verification-rounds|chains\.md|report\.md|grade\.md|evidence-packs\.md)\b/,
    subject: "Bash write/copy/remove against MCP-owned session artifact",
    action: "denied by .claude/hooks/session-write-guard.sh PreToolUse hook (exit 2)",
    source: ".claude/hooks/session-write-guard.sh",
    evidence: "session-write-guard.sh blocks Bash mutations on MCP-owned files under ~/hacker-bob-sessions/ — agents MUST use the corresponding `bob_write_*` / `bob_compose_*` MCP tools",
    remediation: "replace the Bash mutation with the canonical MCP tool (e.g., `bob_write_wave_handoff`, `bob_compose_report`, `bob_write_chain_rollup`)",
  }),
  Object.freeze({
    id: "bob_owned_session_read_guard_sensitive_files",
    pattern: /Bash\s*\(\s*["'][^"']*\b(cat|less|more|head|tail)\b[^"']*hacker-bob-sessions\b[^"']*\b(auth\.json|state\.json|findings\.jsonl)\b/,
    subject: "Bash read against sensitive MCP-owned session artifact",
    action: "denied by .claude/hooks/session-read-guard.sh PreToolUse hook (exit 2)",
    source: ".claude/hooks/session-read-guard.sh",
    evidence: "session-read-guard.sh blocks raw Bash reads of sensitive Bob session artifacts — agents MUST use the structured read tools (bob_read_session_state, bob_read_state_summary, bob_list_auth_profiles, etc.)",
    remediation: "use the structured MCP read tool that returns the summary the skill needs",
  }),
]);

// Evaluate a single role markdown body against the registry. Returns
// an array of structured violation records. A violation entry shape is:
//   { constraint_id, source_kind, subject, action, line, column, snippet,
//     remediation }
// where `source_kind` is `binary_internal` | `bob_owned`.
function evaluateBodyAgainstConstraints(body, { filePath = "<inline>" } = {}) {
  const violations = [];
  const lines = body.split(/\r?\n/);
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    for (const entry of BINARY_INTERNAL) {
      const match = line.match(entry.pattern);
      if (!match) continue;
      violations.push({
        file: filePath,
        constraint_id: entry.id,
        source_kind: "binary_internal",
        subject: entry.subject,
        action: entry.action,
        line: i + 1,
        column: (match.index || 0) + 1,
        snippet: line.trim(),
        remediation: entry.remediation,
      });
    }
    for (const entry of BOB_OWNED) {
      const match = line.match(entry.pattern);
      if (!match) continue;
      violations.push({
        file: filePath,
        constraint_id: entry.id,
        source_kind: "bob_owned",
        subject: entry.subject,
        action: entry.action,
        line: i + 1,
        column: (match.index || 0) + 1,
        snippet: line.trim(),
        remediation: entry.remediation,
      });
    }
  }
  return violations;
}

module.exports = {
  BINARY_INTERNAL,
  BOB_OWNED,
  evaluateBodyAgainstConstraints,
};
