"use strict";

// Y.3 Stage c — `bob_set_friction_scanners` (Y-D6 / D16).
//
// Operator-extensible friction-scanner registry. Defaults (`bash_curl`,
// `bash_wget`, `bash_raw_http`, `bash_cat_ledger`, and the rev-3
// `mcp_invocation_failure_scanner` D7 narrow case) ship in Y.6's
// `mcp/lib/friction-scanners.js` as a frozen registry. Operators add
// environment-specific scanners (e.g., `bash_xargs_curl`, `python_urllib`)
// here; the queue-policy ledger persists them and the Y.6 scanner consumes
// the union.
//
// Y-P9 demoted framing: this is best-effort tripwire enumeration, NOT a closed
// adversarial defense. Reviewers are expected to understand silent strategies
// trivially evade scanner enumeration.

const fs = require("fs");
const {
  ERROR_CODES,
  ToolError,
} = require("../envelope.js");
const {
  assertSafeDomain,
} = require("../paths.js");
const {
  withSessionLock,
} = require("../storage.js");
const {
  loadQueuePolicy,
  normalizeFrictionScanner,
  writeQueuePolicy,
} = require("../queue-policy.js");

function handler(args) {
  if (args == null || typeof args !== "object" || Array.isArray(args)) {
    throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, "bob_set_friction_scanners args must be a plain object");
  }
  const domain = assertSafeDomain(args.target_domain);
  const add = Array.isArray(args.add) ? args.add : [];
  const remove = Array.isArray(args.remove) ? args.remove : [];

  // Normalize each addition through the queue-policy validator so the
  // persisted shape stays in lockstep with DEFAULT_QUEUE_POLICY.friction_scanners.
  const additions = add.map((entry, i) => normalizeFrictionScanner(entry, `add[${i}]`));
  for (let i = 0; i < remove.length; i += 1) {
    if (typeof remove[i] !== "string" || !remove[i]) {
      throw new ToolError(ERROR_CODES.INVALID_ARGUMENTS, `remove[${i}] must be a non-empty scanner name`);
    }
  }

  return withSessionLock(domain, () => {
    const policy = loadQueuePolicy(domain);
    const current = Array.isArray(policy.friction_scanners) ? policy.friction_scanners : [];
    const byName = new Map(current.map((scanner) => [scanner.name, scanner]));
    for (const addition of additions) {
      byName.set(addition.name, addition);
    }
    for (const name of remove) {
      byName.delete(name);
    }
    const updated = Array.from(byName.values());
    const next = { ...policy, friction_scanners: updated };
    const persisted = writeQueuePolicy(domain, next);
    return JSON.stringify({
      version: 1,
      target_domain: domain,
      friction_scanners: persisted.friction_scanners,
      added: additions.map((scanner) => scanner.name),
      removed: remove,
    });
  });
}

const { wrapWriteTool } = require("./_write-base.js");

module.exports = wrapWriteTool({
  name: "bob_set_friction_scanners",
  description:
    "Persist operator-extensible friction scanners into queue-policy.json (Y-D6 / D16). Defaults live frozen in mcp/lib/friction-scanners.js; this tool only mutates the operator-added union. Y-P9 demoted framing: best-effort tripwire, NOT a closed adversarial defense.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
      add: {
        type: "array",
        items: {
          type: "object",
          properties: {
            name: { type: "string", maxLength: 64 },
            pattern: { type: "string", maxLength: 256 },
            fallback_used: { type: "string", maxLength: 64 },
            friction_kind: { type: "string", enum: ["tool_absent", "tool_inadequate"] },
          },
          required: ["name", "pattern", "fallback_used", "friction_kind"],
        },
      },
      remove: {
        type: "array",
        items: { type: "string", maxLength: 64 },
      },
    },
    required: ["target_domain"],
  },
  handler,
  role_bundles: ["orchestrator"],
  capability_id: "Y_self_reporting",
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["queue-policy.json"],
});
