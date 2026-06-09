"use strict";

const TOOL_MODULES = Object.freeze([
  require("./http-scan.js"),
  require("./read-http-audit.js"),
  require("./start-next-wave.js"),
  require("./start-wave.js"),
  require("./route-surfaces.js"),
  require("./read-surface-routes.js"),
  require("./import-http-traffic.js"),
  require("./public-intel.js"),
  require("./import-static-artifact.js"),
  require("./ingest-schema-doc.js"),
  require("./query-schema-contracts.js"),
  require("./run-doc-delta.js"),
  require("./read-doc-delta-results.js"),
  require("./run-auth-differential.js"),
  require("./read-auth-differential-results.js"),
  require("./static-scan.js"),
  require("./record-candidate-claim.js"),
  require("./read-candidate-claims.js"),
  require("./list-candidate-claims.js"),
  require("./write-chain-attempt.js"),
  require("./read-chain-attempts.js"),
  require("./append-chain-node.js"),
  require("./query-chain-tree.js"),
  require("./chain-frontier.js"),
  require("./chain-ancestry.js"),
  require("./write-verification-round.js"),
  require("./read-verification-round.js"),
  require("./read-verification-context.js"),
  require("./diff-verification-attempts.js"),
  require("./build-verification-adjudication.js"),
  require("./write-evidence-packs.js"),
  require("./read-evidence-packs.js"),
  require("./write-proof-bundle.js"),
  require("./write-grade-verdict.js"),
  require("./read-grade-verdict.js"),
  require("./init-session.js"),
  require("./init-repo-session.js"),
  require("./repo-inventory.js"),
  require("./repo-prepare-env.js"),
  require("./repo-docker-run.js"),
  require("./repo-check.js"),
  require("./read-session-state.js"),
  require("./read-session-nucleus.js"),
  require("./advance-session.js"),
  require("./apply-wave-merge.js"),
  require("./write-handoff.js"),
  require("./write-wave-handoff.js"),
  require("./finalize-agent-run.js"),
  require("./wave-handoff-status.js"),
  require("./merge-wave-handoffs.js"),
  require("./read-wave-handoffs.js"),
  require("./log-dead-ends.js"),
  require("./log-coverage.js"),
  require("./wave-status.js"),
  require("./temp-email.js"),
  require("./signup-detect.js"),
  require("./auth-store.js"),
  require("./list-auth-profiles.js"),
  require("./auto-signup.js"),
  require("./read-state-summary.js"),
  require("./read-session-summary.js"),
  require("./set-operator-note.js"),
  require("./clear-operator-note.js"),
  require("./clear-terminal-block.js"),
  require("./report-written.js"),
  require("./finalize-report.js"),
  require("./compose-report.js"),
  require("./amend-report.js"),
  require("./write-chain-rollup.js"),
  require("./set-friction-scanners.js"),
  require("./read-assignment-brief.js"),
  require("./read-capability-playbook.js"),
  require("./get-context-budget.js"),
  require("./select-technique-packs.js"),
  require("./read-technique-pack.js"),
  require("./log-technique-attempt.js"),
  require("./read-tool-telemetry.js"),
  require("./read-pipeline-analytics.js"),
  require("./read-capability-metrics.js"),
  require("./evaluate-capabilities.js"),
  require("./ingest-audit-report.js"),
  require("./query-audit-reports.js"),
  require("./suggest-invariants.js"),
  require("./run-invariant-for-finding.js"),
  require("./read-invariant-runs.js"),
  require("./extract-routes.js"),
  require("./build-symbol-surface-index.js"),
  require("./summarize-diff-impact.js"),
  require("./evm-call.js"),
  require("./evm-storage-read.js"),
  require("./evm-fetch-source.js"),
  require("./evm-role-table.js"),
  require("./foundry-run.js"),
  require("./halmos-run.js"),
  require("./svm-fetch-account.js"),
  require("./svm-fetch-program.js"),
  require("./anchor-run.js"),
  require("./aptos-fetch-resource.js"),
  require("./aptos-fetch-module.js"),
  require("./aptos-run.js"),
  require("./sui-fetch-object.js"),
  require("./sui-fetch-package.js"),
  require("./sui-run.js"),
  require("./substrate-run.js"),
  require("./substrate-fetch-storage.js"),
  require("./substrate-fetch-runtime.js"),
  require("./cosmwasm-run.js"),
  require("./cosmwasm-fetch-contract.js"),
  require("./cosmwasm-smart-query.js"),
  require("./record-surface-leads.js"),
  require("./read-surface-leads.js"),
  require("./promote-surface-leads.js"),
  require("./build-surface-graph.js"),
  require("./query-surface-graph.js"),
  require("./append-frontier-event.js"),
  // Plane X Cycle X.1 — TaskGraph proposal tools. The wrapper-backed
  // appendXxx helpers live in mcp/lib/task-graph-events.js; these tool
  // entries expose the proposal surface to operator + evaluator bundles.
  require("./propose-hypothesis.js"),
  require("./propose-transition.js"),
  // Plane X Cycle X.2 — TaskGraph materializer + raw/summary view. The fold
  // also runs auto-debounced via frontier-materialize-debounce.js on every
  // producer-event session-lock release; these tools are the orchestrator's
  // force-flush + the read surface for X.5 / X.8 / X.11 callers.
  require("./materialize-task-graph.js"),
  require("./read-task-graph.js"),
  // Plane X Cycle X.4 — Contract schema + attach with pre-dispatch
  // satisfiability check. Backed by mcp/lib/contracts.js (the X-D4 7-witness
  // schema + the X-D11 satisfiability gate). The attach tool emits
  // node.transitioned proposed → contracted with the canonical contract_hash.
  require("./attach-contract.js"),
  // Plane X Cycle X.7 — bob_resolve_body + storage-distilled emission retrofit.
  // The tool is the single sanctioned reader of artifact bodies addressable
  // by an X-D12 artifact_ref. Brief renderers inline distilled summaries at
  // append-time; agents pull bodies via this resolver. Backed by
  // mcp/lib/body-resolvers/ (one resolver per X-D12 prefix).
  require("./resolve-body.js"),
  // Plane X Cycle X.8 — clou-style three-call protocol: prepare-node mints
  // the prep_token + brief; finalize-node validates the token, emits
  // executed, runs the mechanical verifier first, and lands the node in
  // verified/finalized or failed with structured failure payloads. Both
  // tools are orchestrator + graph-scheduler-only.
  require("./prepare-node.js"),
  require("./finalize-node.js"),
  // Plane X Cycle X.9 — Graph-walking scheduler. Orchestrator-only tool
  // that wraps selectNextExecutableNodes(graph-scheduler.js) with a
  // graph-hash-drift check and dispatches selected Transition +
  // Hypothesis nodes via bob_prepare_node. Per X-D7 Surface + Claim
  // ride the wave-scheduler unchanged; the graph-scheduler's selection
  // filter rejects them so the two schedulers never contend for the
  // same node.
  require("./schedule-graph-nodes.js"),
  require("./materialize-frontier.js"),
  require("./read-queue-policy.js"),
  require("./set-queue-policy.js"),
  require("./schedule-tasks.js"),
  require("./browser-session-start.js"),
  require("./browser-navigate.js"),
  require("./browser-snapshot.js"),
  require("./browser-click.js"),
  require("./browser-type.js"),
  require("./browser-evaluate.js"),
  require("./browser-network-requests.js"),
  require("./browser-console-messages.js"),
  require("./browser-wait-for.js"),
  require("./browser-press-key.js"),
  require("./browser-take-screenshot.js"),
  require("./browser-fill-form.js"),
  require("./browser-session-close.js"),
  require("./browser-session-start-recording.js"),
  require("./browser-flush-recorded-requests.js"),
  require("./set-pack-telemetry-config.js"),
  // Plane Y Cycle Y.2 — capability friction + protocol drift voluntary
  // emission entries plus the orchestrator-facing runtime drift telemetry
  // tool (Y-D13). Friction + drift records ride observation.recorded as
  // payload.observation_kind siblings of OSS kinds — zero new top-level
  // FRONTIER_EVENT_KIND (Y-P1 / X-P8). Friction is 5-tuple idempotent
  // (Y-P3); drift is per-(run_id, skill_path, drift_signature) idempotent;
  // runtime-drift is per-(run_id, drift_signature, details.tool) idempotent
  // (Y-R20). bob_emit_runtime_drift is orchestrator-only at the
  // role-bundle layer — the Y.3 _write-base.js auto-emit path uses a
  // server-internal caller bundle that is NEVER grantable to agents.
  require("./log-capability-friction.js"),
  require("./log-protocol-drift.js"),
  require("./emit-runtime-drift.js"),
  // Plane Y Cycle Y.6 — friction-to-Hypothesis promotion (Y-P6 + Y-P11).
  // Orchestrator-only. Threads friction_history into the proposal's
  // suggested_contract BEFORE bob_attach_contract runs so the pack
  // widening lands BEFORE the X-D11 satisfiability gate.
  require("./propose-friction-promotion.js"),
  // Plane Y Cycle Y.7 — adversarial transcript scan (Y-D6 + Y-P9 + W2 +
  // rev-4.1 defect 1). Orchestrator-only post-run pass returning synthetic
  // capability_friction + protocol_drift records (producer_trace_dropped,
  // silent_lead_threshold_drop, large_response_body_unimported, etc.). The
  // tool is pure-read: it does not append events. The orchestrator
  // forwards each record through bob_log_capability_friction /
  // bob_log_protocol_drift so the Y-P3 5-tuple idempotency key remains
  // authoritative.
  require("./scan-transcript-for-friction.js"),
]);

module.exports = {
  TOOL_MODULES,
};
