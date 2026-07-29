"use strict";

const { assertNonEmptyString } = require("../validation.js");
const { deriveReconAnglePlan } = require("../recon-angle-plan.js");
const { runtimeClient } = require("../runtime-resources.js");
const { loadQueuePolicy } = require("../queue-policy.js");
const { spawnLedgerTotal } = require("../spawn-ledger.js");
const { statePath } = require("../paths.js");
const { readJsonFile } = require("../storage.js");

// bob_plan_recon_angles — the thin, read-only, deterministic wrapper around the
// pure deriveReconAnglePlan emitter. The orchestrator calls this at SETUP
// (after bob_init_session, before the seed-mapping spawn) to decide whether to
// fan recon out into one background worker per coverage-disjoint angle or to
// run the single sequential agent (today's byte-identical path).
//
// Why a tool and not inline orchestrator prose: the orchestrator reaches MCP
// only through tools and cannot require() the module, does not know the host
// (runtimeClient resolves it server-side from the runtime env), and
// cannot read the per-session governor (queue-policy max_total_spawned_agents
// minus the spawn-ledger total) at prose-render time. Host-fail-closed
// degradation is the load-bearing reason: only the server can read the host
// capability + the ledger and decide fanout-vs-sequential. Read-only, mutating
// nothing, pure-deterministic given the same session + host.
function handler(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");

  // deep_mode is persisted in session state; default false when the session is
  // absent or unreadable. This is an ADVISORY peek of ONE flag — the plan's angle
  // SET is invariant either way (deep only enriches the urls angle) — so it reads
  // the raw persisted flag tolerantly rather than requiring the whole state to
  // normalize, lest a partial/forward-schema state silently disable deep recon.
  let deepMode = false;
  try {
    const parsed = readJsonFile(statePath(domain), { label: "state.json" });
    deepMode = !!parsed && parsed.deep_mode === true;
  } catch {
    deepMode = false;
  }

  const policy = loadQueuePolicy(domain);
  const governor = {
    max_total_spawned_agents: policy.max_total_spawned_agents,
    total_spawned: spawnLedgerTotal(domain),
  };

  const hostId = runtimeClient();
  const plan = deriveReconAnglePlan({ deep_mode: deepMode, host_id: hostId, governor });

  return JSON.stringify({
    version: 1,
    target_domain: domain,
    host_id: hostId,
    deep_mode: deepMode,
    governor,
    plan,
  });
}

module.exports = Object.freeze({
  name: "bob_plan_recon_angles",
  description:
    "Plan the SETUP recon sweep: emit a deterministic recon-angle fan-out plan " +
    "for a target_domain. Returns plan.mode ('fanout' | 'sequential') and the " +
    "four coverage-disjoint angles (host_family, urls, nuclei, js_jwt) read off " +
    "the surface-discovery steps. Resolves the host pool server-side and the " +
    "lifetime governor (queue-policy max_total_spawned_agents minus the " +
    "spawn-ledger total): a finite-pool/unknown host or an exhausted governor " +
    "degrades to a single sequential agent (today's path) without dropping any " +
    "angle. Read-only, non-mutating, deterministic.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string" },
    },
    required: ["target_domain"],
  },
  handler,
  role_bundles: ["orchestrator"],
  mutating: false,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: [],
});
