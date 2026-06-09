"use strict";

// Plane X Cycle X.12 — end-to-end multi-stack smoke certification.
//
// The terminal cycle of Plane X. Per the spec Do step the suite carries
// THREE subtests + a wave-scheduler regression assertion + the X-P9
// brief-discipline assertion:
//
//   1. Positive subtest — a multi-stack fixture (mocked HTTP returns a
//      JWT whose payload.sub == "0xWALLET" AND mocked EVM RPC returns
//      recover_signer(tx) == "0xWALLET"). The Contract carries a
//      relational_value_match witness over the http_record + evm_call
//      artifact_refs. Agent invokes both stacks, captures evidence_refs.
//      Mechanical verifier extracts both → op `eq` holds → finalize
//      succeeds → 5-hash ReportSnapshot binds (Z.1 + C.7 hash chain
//      regression).
//
//   2. Negative subtest — same fixture but payload.sub == "0xATTACKER"
//      and recovered_signer == "0xVICTIM". Same Contract, same agent.
//      Mechanical verifier extracts both → op `eq` fails → finalize
//      emits node.transitioned executed → failed with structured
//      failure_reason.reason == "relation_did_not_hold" carrying BOTH
//      extracted values + BOTH artifact_refs. Downstream NOT ready.
//
//   3. Retry-with-recall subtest — operator re-contracts the
//      failed node with a refined Contract (a different artifact_ref
//      pair). New bob_prepare_node → brief's `prior_attempt` slice MUST
//      contain the structured failure payload from the negative-subtest
//      run (witness_id, failure_reason.reason, extracted values, refs).
//      Agent executes against the new Contract → mechanical verifier
//      passes → finalize succeeds. Proves inter-attempt recall works
//      end-to-end.
//
// Plus:
//   - Wave-scheduler regression: during the run a Surface frontier task
//     is enqueued + materialized + dispatched via the wave-scheduler
//     (scheduleTasksFromQueue → schedule_work decision row), confirming
//     X-D7's dual-write split — graph-scheduler owns Transition +
//     Hypothesis; wave-scheduler owns Surface + Claim. The graph-scheduler
//     selection MUST exclude the Surface node.
//   - X-P9 brief size + summary-vs-body discipline: positive-subtest
//     brief stays under 30KB; the `recommended_reads` slice inlines the
//     DISTILLED SUMMARY of the http_record + evm_call refs, NOT the body.
//     Negative grep: distinctive bytes from the http response body MUST
//     NOT appear in the rendered brief.
//
// Z.1 + O.10 regression preservation is structural: this test does not
// alter the Z.1 / O.10 fixtures, only consumes the same MCP-owned
// primitives. `npm test` running the full suite is the regression gate.

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { TOOL_HANDLERS } = require("../mcp/lib/tool-registry.js");
const initSessionTool = require("../mcp/lib/tools/init-session.js");
const advanceSessionTool = require("../mcp/lib/tools/advance-session.js");
const recordSurfaceLeadsTool = require("../mcp/lib/tools/record-surface-leads.js");
const promoteSurfaceLeadsTool = require("../mcp/lib/tools/promote-surface-leads.js");
const recordCandidateClaimTool = require("../mcp/lib/tools/record-candidate-claim.js");
const scheduleTasksTool = require("../mcp/lib/tools/schedule-tasks.js");
const writeVerificationRoundTool = require("../mcp/lib/tools/write-verification-round.js");
const writeEvidencePacksTool = require("../mcp/lib/tools/write-evidence-packs.js");
const writeGradeVerdictTool = require("../mcp/lib/tools/write-grade-verdict.js");
const finalizeReportTool = require("../mcp/lib/tools/finalize-report.js");

const {
  appendFrontierEvent,
  readFrontierEvents,
} = require("../mcp/lib/frontier-events.js");
const {
  TASK_GRAPH_NODE_ID_PREFIX,
  appendHypothesisProposal,
  readNodeTransitions,
} = require("../mcp/lib/task-graph-events.js");
const {
  materializeTaskGraph,
} = require("../mcp/lib/task-graph-materializer.js");
const {
  appendContract,
} = require("../mcp/lib/contracts.js");
const {
  buildClaimFreeze,
  readCurrentClaimFreeze,
} = require("../mcp/lib/claim-freeze.js");
const {
  materializeFrontier,
} = require("../mcp/lib/frontier-materializer.js");
const {
  readSchedulerDecisions,
  readGraphSchedulerDecisions,
} = require("../mcp/lib/scheduler-decisions.js");
const {
  readReportSnapshots,
} = require("../mcp/lib/report-snapshots.js");
const {
  finalVerificationHash,
  hashCanonicalJson,
} = require("../mcp/lib/verification-contracts.js");
const {
  resetForTests: resetMaterializationDebounce,
} = require("../mcp/lib/frontier-materialize-debounce.js");
const {
  appendJsonlLine,
} = require("../mcp/lib/storage.js");
const {
  claimFreezePath,
  evidencePackPaths,
  frontierEventsJsonlPath,
  gradeArtifactPaths,
  reportMarkdownPath,
  reportSnapshotsJsonlPath,
  sessionDir,
  trafficJsonlPath,
  verificationRoundPaths,
} = require("../mcp/lib/paths.js");
const {
  evmCallsJsonlPath,
} = require("../mcp/lib/body-resolvers/evm-call.js");

const HASH_HEX_RE = /^[a-f0-9]{64}$/;

function parseFencedBriefJson(value, label) {
  const match = String(value).match(/^<<UNTRUSTED_DATA nonce=([0-9a-f]{32}) label=([^>\n]+)>>\n([\s\S]*)\n<<END_UNTRUSTED_DATA nonce=\1>>$/);
  assert.ok(match, `expected fenced ${label} slice`);
  assert.equal(match[2], label);
  return JSON.parse(match[3]);
}

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-x12-smoke-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    resetMaterializationDebounce();
    if (previousHome === undefined) {
      delete process.env.HOME;
    } else {
      process.env.HOME = previousHome;
    }
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function sha256OfFile(filePath) {
  return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
}

function callTool(tool, args) {
  const response = tool.handler(args);
  return typeof response === "string" ? JSON.parse(response) : response;
}

// ─── Cross-stack fixture writers ──────────────────────────────────────
//
// The positive + negative + retry subtests all need a paired
// http_record + evm_call fixture so the relational_value_match witness
// has real X-D12 artifacts to resolve. We write directly to traffic.jsonl
// (carrying a `response_body` field the importHttpTraffic normalizer
// strips) and evm-calls.jsonl. The X.7 resolvers return the canonical
// record JSON whose shape the JSONPath extract walks.

// Use a deterministic synthetic request_id so the contract can reference
// it before we materialize anything. The X.7 resolver matches on
// `request_id` not on `R-<sha>` so any non-empty unique string works.
function writeHttpFixtureRecord(domain, {
  requestId,
  url,
  status = 200,
  responseBody,
  distinctiveBodyMarker,
}) {
  const recordTs = "2026-05-31T00:05:00.000Z";
  appendJsonlLine(trafficJsonlPath(domain), {
    version: 1,
    request_id: requestId,
    ts: recordTs,
    target_domain: domain,
    source: "x12-fixture",
    method: "POST",
    url,
    host: domain,
    path: new URL(url).pathname,
    status,
    auth_profile: null,
    has_auth: true,
    header_names: ["content-type"],
    query_keys: [],
    // The retrofit normalizer strips body fields; we are NOT going through
    // importHttpTraffic. The line carries response_body explicitly so the
    // http_record resolver returns it inside the canonical JSON.
    response_body: responseBody,
    // Per-line distinctive marker so the X-P9 negative grep below has a
    // concrete byte sequence to look for in the rendered brief.
    body_distinctive_marker: distinctiveBodyMarker,
  });
  // Pair with an http_record_observed event so the prepare_node brief's
  // recommended_reads slice can find the matching summary. The retrofit
  // builder is bypassed here — we synthesize the minimal payload shape
  // (request_id, method, url, status, content_type) directly. Stays well
  // under the X-P9 2KB hard cap by construction.
  appendFrontierEvent({
    target_domain: domain,
    kind: "observation.recorded",
    ts: recordTs,
    payload: {
      observation_kind: "http_record_observed",
      request_id: requestId,
      method: "POST",
      url,
      status,
      has_auth: true,
      content_type: "application/json",
      body_size_bytes: JSON.stringify(responseBody).length,
    },
    source: { artifact: "traffic.jsonl", ref: requestId, tool: "x12-fixture" },
  });
}

function writeEvmFixtureRecord(domain, { callId, recoveredSigner }) {
  appendJsonlLine(evmCallsJsonlPath(domain), {
    version: 1,
    call_id: callId,
    chain_id: 1,
    to: "0x000000000000000000000000000000000000dEaD",
    data: "0x1626ba7e",
    result: "0x000000000000000000000000000000000000000000000000000000001626ba7e",
    recovered_signer: recoveredSigner,
    ts: "2026-05-31T00:06:00.000Z",
  });
}

// ─── Session + Hypothesis node helpers ────────────────────────────────

// Initialize a real session (so the report-chain tools see a nucleus +
// session-events ledger) then seed the two cross-stack surfaces. The
// positive subtest drives the report chain inline so the init MUST run
// first (init_session refuses a non-empty session dir). The negative +
// retry subtests don't need the report chain so they use the lighter
// seedSessionWithoutInit helper.
function seedFullSession(domain) {
  callTool(initSessionTool, {
    target_domain: domain,
    target_url: `https://${domain}/`,
  });
  seedSurfaces(domain);
}

function seedSessionWithoutInit(domain) {
  // The X.8 prepare/finalize tools do not require a fully initialized
  // session for the relational dance — a single observation creates the
  // session dir and the materializer + verifier are happy.
  seedSurfaces(domain);
}

function seedSurfaces(domain) {
  appendFrontierEvent({
    target_domain: domain,
    kind: "surface.observed",
    ts: "2026-05-31T00:00:00.000Z",
    surface_id: "surface:web-auth",
    payload: { title: "web auth", surface_type: "web" },
  });
  appendFrontierEvent({
    target_domain: domain,
    kind: "surface.observed",
    ts: "2026-05-31T00:00:01.000Z",
    surface_id: "surface:evm-vault",
    payload: { title: "evm vault", surface_type: "smart_contract", chain_family: "evm" },
  });
}

// Build a Hypothesis node whose Contract carries a relational_value_match
// witness pointing at the http_record + evm_call fixture. The Hypothesis
// is the natural fit here (Transition nodes can also carry relational
// witnesses but require a separate transition_proposed event; this
// smoke focuses on the relational witness over real X-D12 refs).
function seedRelationalHypothesisNode(domain, {
  proposalId,
  contractId,
  severity = "high",
  leftRef,
  rightRef,
  leftPath = "$.response_body.access_token.payload.sub",
  rightPath = "$.recovered_signer",
}) {
  appendHypothesisProposal({
    target_domain: domain,
    ts: "2026-05-31T00:07:00.000Z",
    hypothesis_statement: "JWT.sub binds to EVM recovered_signer across the auth → vault handoff.",
    surface_refs: ["surface:web-auth", "surface:evm-vault"],
    proposal_id: proposalId,
  });
  materializeTaskGraph(domain, { write: true });
  const nodeId = `${TASK_GRAPH_NODE_ID_PREFIX}H-${proposalId}`;
  appendContract({
    target_domain: domain,
    node_id: nodeId,
    contract: {
      contract_id: contractId,
      severity_floor: severity,
      invariants: [{
        id: "I-identity",
        statement: "Off-chain JWT subject equals on-chain recovered signer for the same session.",
      }],
      witnesses: [{
        id: "W-relational",
        kind: "relational_value_match",
        predicate: {
          left: { artifact_ref: leftRef, extract_path: leftPath },
          op: "eq",
          right: { artifact_ref: rightRef, extract_path: rightPath },
        },
      }],
      production_paths: [{
        description: "Capture the JWT issue + the on-chain signature recovery.",
        // Two production tools so the X-D11 satisfiability gate sees a
        // path to producing each side of the relational match.
        tool_call_pattern: [
          { tool: "bob_http_scan" },
          { tool: "bob_evm_call" },
        ],
      }],
    },
    ts: "2026-05-31T00:08:00.000Z",
  });
  materializeTaskGraph(domain, { write: true });
  return nodeId;
}

// ─── Z.1-style hash-chain driver (positive subtest only) ──────────────
//
// The positive subtest binds a 5-hash ReportSnapshot per X.12 Do step 1.
// We drive the canonical operator flow inline (init → OPEN_FRONTIER →
// claims → CLAIM_FREEZE → V1 verification → VERIFY → evidence packs →
// GRADE → grade verdict → REPORT → V2 final upgrade → report.md →
// finalize_report). The 5-hash binding (claim_freeze_hash,
// final_verification_hash, evidence_hash, grade_verdict_hash,
// report_content_hash) is the C.7 invariant the X cycles preserve.

function driveReportSnapshotChain(domain, {
  promotedSurfaceTitle,
  promotedSurfacePath,
}) {
  // Surface lead promotion creates the wave-scheduler dispatch target.
  // The caller is expected to have already initialized the session via
  // seedFullSession (init_session refuses a non-empty session dir, so
  // init MUST land before any seed observations).
  callTool(recordSurfaceLeadsTool, {
    target_domain: domain,
    source: "x12-smoke",
    leads: [{
      title: promotedSurfaceTitle,
      hosts: [domain],
      endpoints: [`https://${domain}${promotedSurfacePath}`],
      priority: "HIGH",
      surface_type: "web",
      confidence: "high",
      score: 90,
      promote: true,
      bug_class_hints: ["identity_handoff"],
      evidence: ["cross-stack handoff observed in traffic"],
    }],
  });
  const promote = callTool(promoteSurfaceLeadsTool, {
    target_domain: domain,
    limit: 5,
  });
  const promotedSurfaceId = promote.promoted_surface_ids[0];

  callTool(advanceSessionTool, { target_domain: domain, to_state: "OPEN_FRONTIER" });
  materializeFrontier(domain, { write: true });

  // Wave-scheduler dispatch: schedule_tasks consumes the materialized
  // frontier and emits a SchedulerDecision (decision_kind:
  // "schedule_work") to scheduler-decisions.jsonl. This is the
  // wave-scheduler regression hook per X.12 Do step 3 — Surface nodes
  // ride the wave path (X-D7) and the graph-scheduler MUST NOT see them.
  callTool(scheduleTasksTool, { target_domain: domain });

  // Record one candidate claim grounded in the cross-stack thesis so the
  // 5-hash binding has reportable evidence.
  const claimResponse = callTool(recordCandidateClaimTool, {
    target_domain: domain,
    title: "Cross-stack identity handoff allows wallet impersonation",
    severity: "high",
    cwe: "CWE-345",
    endpoint: `https://${domain}${promotedSurfacePath}`,
    description: "JWT.sub is trusted as the on-chain wallet identity without binding to the recovered signer.",
    proof_of_concept: "Issue JWT for victim address; replay against vault — vault accepts attacker tx.",
    response_evidence: "JWT.sub == 0xVICTIM AND recover_signer(tx) == 0xATTACKER but vault dispatched anyway.",
    impact: "Wallet impersonation across the auth → vault handoff.",
    validated: true,
    auth_profile: "attacker",
    surface_id: promotedSurfaceId,
  });
  const findingIds = [claimResponse.finding_id];

  callTool(advanceSessionTool, { target_domain: domain, to_state: "CLAIM_FREEZE" });
  buildClaimFreeze(domain, { write: true });
  const freeze = readCurrentClaimFreeze(domain);

  for (const round of ["brutalist", "balanced", "final"]) {
    callTool(writeVerificationRoundTool, {
      target_domain: domain,
      round,
      notes: null,
      results: findingIds.map((findingId) => ({
        finding_id: findingId,
        disposition: "confirmed",
        severity: "high",
        reportable: true,
        reasoning: "Cross-stack relational evidence confirmed; replay holds in fresh window.",
        // Y.1 B1 lift — repro_steps + evidence_refs are inputSchema.required.
        repro_steps: ["Replay step 1 confirmed cross-stack evidence."],
        evidence_refs: [`frontier_event:${findingId}`],
      })),
    });
  }

  callTool(advanceSessionTool, { target_domain: domain, to_state: "VERIFY" });

  callTool(writeEvidencePacksTool, {
    target_domain: domain,
    packs: findingIds.map((findingId) => ({
      finding_id: findingId,
      sample_type: "cross-stack identity handoff",
      sample_count: 1,
      aggregate_counts: { affected_objects_sampled: 1 },
      representative_samples: [{
        request_ref: `http-audit:${findingId}`,
        endpoint: promotedSurfacePath,
        auth_profile: "attacker",
        status: 200,
        observed_fields: ["jwt_sub", "recovered_signer"],
        redacted_object_id: "wallet:victim_redacted",
      }],
      sensitive_clusters: ["wallet identity"],
      replay_summary: "Fresh replay reproduced the impersonation against the auth → vault handoff.",
      redaction_notes: "Wallet addresses redacted to first/last 4 chars; signatures omitted.",
      report_snippet: `An attacker can impersonate the wallet behind ${findingId}.`,
    })),
  });

  callTool(advanceSessionTool, { target_domain: domain, to_state: "GRADE" });
  callTool(writeGradeVerdictTool, {
    target_domain: domain,
    verdict: "SUBMIT",
    total_score: 75,
    findings: findingIds.map((findingId) => ({
      finding_id: findingId,
      impact: 25,
      proof_quality: 20,
      severity_accuracy: 10,
      chain_potential: 10,
      report_quality: 10,
      total_score: 75,
      feedback: "Cross-stack impact is clear and reproducible.",
    })),
    feedback: "Cross-stack handoff thesis is submission-ready.",
  });

  callTool(advanceSessionTool, { target_domain: domain, to_state: "REPORT" });

  // Upgrade V1 final round to V2 in place — the C.7 finalize tool only
  // resolves the final_verification_hash from a V2 round bound to the
  // freeze. Mirrors the Z.1 smoke's documented bridge.
  const finalPath = verificationRoundPaths(domain, "final").json;
  const v1FinalDocument = JSON.parse(fs.readFileSync(finalPath, "utf8"));
  const v2FinalDocument = {
    version: 2,
    target_domain: domain,
    round: "final",
    notes: null,
    verification_attempt_id: `attempt-${freeze.freeze_id}`,
    verification_snapshot_hash: freeze.freeze_hash,
    round_profile: "final",
    adjudication_plan_hash: crypto.createHash("sha256")
      .update(`adjudication:${freeze.freeze_id}`)
      .digest("hex"),
    results: v1FinalDocument.results,
  };
  v2FinalDocument.final_verification_hash = finalVerificationHash(v2FinalDocument);
  fs.writeFileSync(finalPath, JSON.stringify(v2FinalDocument, null, 2) + "\n");

  // Minimal report.md. The five-hash binding is hash-of-bytes; the prose
  // shape is irrelevant to the X.12 hash-chain regression.
  const reportMarkdown = [
    "# Bob Report — X.12 cross-stack smoke",
    "",
    `Target: ${domain}`,
    "",
    "## Findings",
    "",
    ...findingIds.map((findingId) => `- ${findingId}: cross-stack handoff exploitable`),
    "",
  ].join("\n") + "\n";
  fs.writeFileSync(reportMarkdownPath(domain), reportMarkdown);

  const finalizeResponse = callTool(finalizeReportTool, { target_domain: domain });
  return {
    finding_ids: findingIds,
    freeze,
    v2_final_document: v2FinalDocument,
    finalize_response: finalizeResponse,
    promoted_surface_id: promotedSurfaceId,
  };
}

// ─── Subtest 1: positive — mechanical verifier passes; 5-hash binds ──

test("X.12 positive subtest: cross-stack relational_value_match holds, finalize succeeds, 5-hash ReportSnapshot binds, brief is X-P9 distilled", () => {
  withTempHome(() => {
    const domain = "x12-positive.example.com";
    // init_session FIRST (it refuses a non-empty session dir); then seed
    // the two cross-stack surfaces and the http_record + evm_call
    // fixtures. The positive subtest drives the report chain inline so
    // the session nucleus must exist.
    seedFullSession(domain);

    // The positive fixture: JWT.sub == 0xWALLET AND recover_signer == 0xWALLET.
    const distinctiveBodyMarker = "X12-POSITIVE-BODY-MARKER-3f6e-9a82-WALLET-HANDOFF";
    const httpRequestId = "R-x12-positive-jwt-issue";
    const evmCallId = "E-x12-positive-recover-signer";
    writeHttpFixtureRecord(domain, {
      requestId: httpRequestId,
      url: `https://${domain}/api/auth/login`,
      status: 200,
      responseBody: {
        access_token: {
          jwt_raw: "eyJxxx.eyJxxx.signature",
          payload: { sub: "0xWALLET", iss: domain, aud: "vault" },
        },
        marker: distinctiveBodyMarker,
      },
      distinctiveBodyMarker,
    });
    writeEvmFixtureRecord(domain, {
      callId: evmCallId,
      recoveredSigner: "0xWALLET",
    });

    const nodeId = seedRelationalHypothesisNode(domain, {
      proposalId: "HP-x12-positive",
      contractId: "C-x12-positive",
      leftRef: `http_record:${httpRequestId}`,
      rightRef: `evm_call:${evmCallId}`,
    });

    const prep = JSON.parse(TOOL_HANDLERS.bob_prepare_node({
      target_domain: domain,
      node_id: nodeId,
    }));

    // ── X-P9 brief discipline (X.12 Do step 4) ────────────────────────
    const briefJson = JSON.stringify(prep.brief);
    const briefSize = Buffer.byteLength(briefJson, "utf8");
    assert.ok(briefSize < 30_000,
      `positive-subtest brief size ${briefSize} bytes exceeds the X-P9 30KB budget`);

    // The recommended_reads slice MUST inline distilled summaries of the
    // http_record + evm_call refs the Contract names.
    const refs = parseFencedBriefJson(prep.brief.recommended_reads, "recommended_reads").refs;
    const httpRef = refs.find((r) => r.artifact_ref === `http_record:${httpRequestId}`);
    assert.ok(httpRef, "recommended_reads must inline the http_record ref the Contract references");
    // For http_record we resolve through the paired http_record_observed
    // event (the X.7 retrofit's distilled summary shape).
    assert.equal(httpRef.kind, "http_record_observed");
    assert.equal(httpRef.summary.request_id, httpRequestId);
    assert.equal(httpRef.summary.method, "POST");
    assert.equal(httpRef.summary.status, 200);
    // The summary MUST NOT carry the full response body.
    assert.equal(Object.prototype.hasOwnProperty.call(httpRef.summary, "body"), false);
    assert.equal(Object.prototype.hasOwnProperty.call(httpRef.summary, "response_body"), false);

    const evmRef = refs.find((r) => r.artifact_ref === `evm_call:${evmCallId}`);
    assert.ok(evmRef, "recommended_reads must inline the evm_call ref the Contract references");
    // evm_call has no paired *_observed summary event so the slice
    // surfaces a typed pointer naming the resolver to call.
    assert.equal(evmRef.kind, "evm_call");
    assert.ok(evmRef.summary.hint && evmRef.summary.hint.includes("bob_resolve_body"));

    // ── Negative grep: distinctive http body bytes MUST NOT appear in
    //     the rendered brief (X.12 Do step 4 explicit). ───────────────
    assert.equal(briefJson.includes(distinctiveBodyMarker), false,
      `the distinctive http body marker (${distinctiveBodyMarker}) must NOT appear anywhere in the brief — X-P9 says distilled summaries only, bodies are pull-only via bob_resolve_body`);

    // ── Mechanical verifier passes; finalize succeeds ────────────────
    const finalized = JSON.parse(TOOL_HANDLERS.bob_finalize_node({
      target_domain: domain,
      node_id: nodeId,
      prep_token: prep.prep_token,
      agent_output: {
        tool_invocations: [
          { tool: "bob_http_scan", output: { status: 200 } },
          { tool: "bob_evm_call", output: { recovered_signer: "0xWALLET" } },
        ],
        evidence_refs: [
          { kind: "http_record", request_id: httpRequestId },
          { kind: "evm_call", call_id: evmCallId },
        ],
      },
    }));
    assert.equal(finalized.to_state, "finalized",
      `positive subtest must finalize: ${JSON.stringify(finalized.failure_reason || finalized.mechanical_verdict)}`);
    assert.equal(finalized.mechanical_verdict.satisfied, true);

    // ── Wave-scheduler regression: a Surface frontier task dispatched
    //     via scheduleTasksFromQueue lands on the SAME ledger as a
    //     schedule_work decision; the graph-scheduler MUST NOT see it.
    //     Drive a full Z.1-style hash chain so the 5-hash ReportSnapshot
    //     binding gets exercised end-to-end on the SAME session that
    //     ran the relational finalize. ──────────────────────────────
    const chainResult = driveReportSnapshotChain(domain, {
      promotedSurfaceTitle: "Cross-stack identity handoff endpoint",
      promotedSurfacePath: "/api/auth/login",
    });

    // schedule_tasks emits a SchedulerDecision (decision_kind:
    // "schedule_work"); confirm at least one such row exists post-drive.
    const waveDecisions = readSchedulerDecisions(domain)
      .filter((d) => d.decision_kind === "schedule_work");
    assert.ok(waveDecisions.length >= 1,
      "wave-scheduler must still emit schedule_work decisions in the same session as the graph-scheduler dispatch (X-D7 dual-write)");
    // Graph-scheduler ledger is independent and must NOT have absorbed
    // the wave-scheduler's Surface dispatch.
    const graphDecisions = readGraphSchedulerDecisions(domain);
    for (const decision of graphDecisions) {
      for (const selectedId of (decision.selected_node_ids || [])) {
        assert.ok(selectedId.startsWith(`${TASK_GRAPH_NODE_ID_PREFIX}T-`)
          || selectedId.startsWith(`${TASK_GRAPH_NODE_ID_PREFIX}H-`),
          `graph-scheduler selected ${selectedId}; X-D7 forbids Surface (TG-S-) and Claim (TG-C-) selections`);
      }
    }

    // ── 5-hash ReportSnapshot binding (X.12 Do step 1 / C.7 regression) ──
    const finalizeResponse = chainResult.finalize_response;
    assert.match(finalizeResponse.claim_freeze_hash, HASH_HEX_RE);
    assert.match(finalizeResponse.final_verification_hash, HASH_HEX_RE);
    assert.match(finalizeResponse.evidence_hash, HASH_HEX_RE);
    assert.match(finalizeResponse.grade_verdict_hash, HASH_HEX_RE);
    assert.match(finalizeResponse.report_content_hash, HASH_HEX_RE);

    const snapshots = readReportSnapshots(domain);
    assert.equal(snapshots.length, 1,
      "exactly one ReportSnapshot row after a single finalize");
    const row = snapshots[0];
    assert.equal(row.claim_freeze_hash, finalizeResponse.claim_freeze_hash);
    assert.equal(row.final_verification_hash, finalizeResponse.final_verification_hash);
    assert.equal(row.evidence_hash, finalizeResponse.evidence_hash);
    assert.equal(row.grade_verdict_hash, finalizeResponse.grade_verdict_hash);
    assert.equal(row.report_content_hash, finalizeResponse.report_content_hash);

    // Re-validate each hash against the on-disk artifact (C.7 invariant).
    const freezeOnDisk = JSON.parse(fs.readFileSync(claimFreezePath(domain), "utf8"));
    assert.equal(row.claim_freeze_hash, freezeOnDisk.freeze_hash);
    const finalRoundOnDisk = JSON.parse(fs.readFileSync(verificationRoundPaths(domain, "final").json, "utf8"));
    assert.equal(row.final_verification_hash, finalRoundOnDisk.final_verification_hash);
    assert.equal(finalVerificationHash(finalRoundOnDisk), finalRoundOnDisk.final_verification_hash);
    const evidenceOnDisk = JSON.parse(fs.readFileSync(evidencePackPaths(domain).json, "utf8"));
    assert.equal(row.evidence_hash, hashCanonicalJson(evidenceOnDisk.packs));
    const gradeOnDisk = JSON.parse(fs.readFileSync(gradeArtifactPaths(domain).json, "utf8"));
    assert.equal(row.grade_verdict_hash, hashCanonicalJson(gradeOnDisk));
    assert.equal(row.report_content_hash, sha256OfFile(reportMarkdownPath(domain)));

    assert.ok(fs.existsSync(reportSnapshotsJsonlPath(domain)),
      "report-snapshots.jsonl must exist after finalize");
    assert.ok(fs.existsSync(sessionDir(domain)));
  });
});

// ─── Subtest 2: negative — mechanical verifier fails with relation_did_not_hold ──

test("X.12 negative subtest: cross-stack relational_value_match fails, finalize emits failed with structured failure_reason carrying both extracted values + artifact_refs, downstream NOT ready", () => {
  withTempHome(() => {
    const domain = "x12-negative.example.com";
    seedSessionWithoutInit(domain);

    // Negative fixture: JWT.sub == 0xATTACKER ≠ recovered_signer == 0xVICTIM.
    const httpRequestId = "R-x12-negative-jwt-issue";
    const evmCallId = "E-x12-negative-recover-signer";
    writeHttpFixtureRecord(domain, {
      requestId: httpRequestId,
      url: `https://${domain}/api/auth/login`,
      status: 200,
      responseBody: {
        access_token: {
          payload: { sub: "0xATTACKER", iss: domain, aud: "vault" },
        },
      },
      distinctiveBodyMarker: "X12-NEGATIVE-BODY-MARKER",
    });
    writeEvmFixtureRecord(domain, {
      callId: evmCallId,
      recoveredSigner: "0xVICTIM",
    });

    const nodeId = seedRelationalHypothesisNode(domain, {
      proposalId: "HP-x12-negative",
      contractId: "C-x12-negative",
      leftRef: `http_record:${httpRequestId}`,
      rightRef: `evm_call:${evmCallId}`,
    });

    const prep = JSON.parse(TOOL_HANDLERS.bob_prepare_node({
      target_domain: domain,
      node_id: nodeId,
    }));
    const finalized = JSON.parse(TOOL_HANDLERS.bob_finalize_node({
      target_domain: domain,
      node_id: nodeId,
      prep_token: prep.prep_token,
      agent_output: {
        tool_invocations: [
          { tool: "bob_http_scan", output: { status: 200 } },
          { tool: "bob_evm_call", output: { recovered_signer: "0xVICTIM" } },
        ],
        evidence_refs: [
          { kind: "http_record", request_id: httpRequestId },
          { kind: "evm_call", call_id: evmCallId },
        ],
      },
    }));

    assert.equal(finalized.to_state, "failed",
      `negative subtest must fail finalize: ${JSON.stringify(finalized)}`);
    assert.equal(finalized.mechanical_verdict.satisfied, false);
    assert.ok(finalized.failure_reason);
    assert.equal(finalized.failure_reason.reason, "mechanical_verifier_failed");

    // Structured failure payload: BOTH extracted values + BOTH artifact_refs.
    const witnessFailure = finalized.failure_reason.failures.find((f) => f.witness_id === "W-relational");
    assert.ok(witnessFailure, "witness W-relational must surface in failures[]");
    assert.equal(witnessFailure.reason, "relation_did_not_hold",
      "the verifier MUST surface relation_did_not_hold for an eq mismatch (X.12 spec)");
    assert.equal(witnessFailure.left_artifact_ref, `http_record:${httpRequestId}`);
    assert.equal(witnessFailure.right_artifact_ref, `evm_call:${evmCallId}`);
    assert.equal(witnessFailure.left_value, "0xATTACKER");
    assert.equal(witnessFailure.right_value, "0xVICTIM");
    assert.equal(witnessFailure.op, "eq");

    // Downstream NOT ready: the node is in `failed` state, so any
    // downstream contracted node sharing surfaces must NOT have moved.
    // We assert this structurally: the node itself is `failed` and the
    // ledger holds no `dispatched → finalized` transitions for it.
    materializeTaskGraph(domain, { write: true });
    const doc = materializeTaskGraph(domain, { write: false }).document;
    const liveNode = doc.nodes.find((n) => n.node_id === nodeId);
    assert.equal(liveNode.state, "failed");
    const transitions = readNodeTransitions(domain).filter(
      (e) => e.payload && e.payload.node_id === nodeId,
    );
    const finalizedTransitions = transitions.filter(
      (e) => e.payload.to_state === "finalized",
    );
    assert.equal(finalizedTransitions.length, 0,
      "negative subtest must NOT emit a finalized transition; downstream remains gated");
  });
});

// ─── Subtest 3: retry-with-recall ─────────────────────────────────────

test("X.12 retry-with-recall subtest: re-contract the failed node, new prepare_node brief inlines prior_attempt slice with structured failure payload, refined Contract finalizes", () => {
  withTempHome(() => {
    const domain = "x12-retry-with-recall.example.com";
    seedSessionWithoutInit(domain);

    // Two paired fixtures. The first run fails (extracted values mismatch
    // on the original Contract); the operator re-contracts against a
    // second fixture pair whose values match.
    const httpRequestId1 = "R-x12-rwr-attempt-1";
    const evmCallId1 = "E-x12-rwr-attempt-1";
    writeHttpFixtureRecord(domain, {
      requestId: httpRequestId1,
      url: `https://${domain}/api/auth/login`,
      status: 200,
      responseBody: {
        access_token: { payload: { sub: "0xATTACKER" } },
      },
      distinctiveBodyMarker: "X12-RWR-ATTEMPT-1-BODY",
    });
    writeEvmFixtureRecord(domain, {
      callId: evmCallId1,
      recoveredSigner: "0xVICTIM",
    });

    // (1) Attempt 1 with the failing Contract.
    const nodeId = seedRelationalHypothesisNode(domain, {
      proposalId: "HP-x12-rwr",
      contractId: "C-x12-rwr-attempt-1",
      leftRef: `http_record:${httpRequestId1}`,
      rightRef: `evm_call:${evmCallId1}`,
    });
    const prep1 = JSON.parse(TOOL_HANDLERS.bob_prepare_node({
      target_domain: domain,
      node_id: nodeId,
    }));
    const fin1 = JSON.parse(TOOL_HANDLERS.bob_finalize_node({
      target_domain: domain,
      node_id: nodeId,
      prep_token: prep1.prep_token,
      agent_output: {
        tool_invocations: [
          { tool: "bob_http_scan", output: { status: 200 } },
          { tool: "bob_evm_call", output: { recovered_signer: "0xVICTIM" } },
        ],
      },
    }));
    assert.equal(fin1.to_state, "failed", "attempt-1 must fail mechanically");
    const priorWitnessFailure = fin1.failure_reason.failures.find((f) => f.witness_id === "W-relational");
    assert.equal(priorWitnessFailure.reason, "relation_did_not_hold");
    assert.equal(priorWitnessFailure.left_value, "0xATTACKER");
    assert.equal(priorWitnessFailure.right_value, "0xVICTIM");

    // (2) Re-contract: operator inspects the failure (extracted values
    // surface in the failure payload), discovers a DIFFERENT artifact_ref
    // pair (the second http_record + evm_call) whose values do match,
    // and attaches a refined Contract. The X.8 failed → contracted path
    // is the documented re-contract entry.
    const httpRequestId2 = "R-x12-rwr-attempt-2";
    const evmCallId2 = "E-x12-rwr-attempt-2";
    writeHttpFixtureRecord(domain, {
      requestId: httpRequestId2,
      url: `https://${domain}/api/auth/refresh`,
      status: 200,
      responseBody: {
        access_token: { payload: { sub: "0xCORRECTLY_BOUND" } },
      },
      distinctiveBodyMarker: "X12-RWR-ATTEMPT-2-BODY",
    });
    writeEvmFixtureRecord(domain, {
      callId: evmCallId2,
      recoveredSigner: "0xCORRECTLY_BOUND",
    });
    const refinedContract = {
      contract_id: "C-x12-rwr-attempt-2-refined",
      severity_floor: "high",
      invariants: [{
        id: "I-refined",
        statement: "Refined: JWT.sub on /refresh binds to the EVM recovered signer.",
      }],
      witnesses: [{
        id: "W-relational",
        kind: "relational_value_match",
        predicate: {
          left: {
            artifact_ref: `http_record:${httpRequestId2}`,
            extract_path: "$.response_body.access_token.payload.sub",
          },
          op: "eq",
          right: {
            artifact_ref: `evm_call:${evmCallId2}`,
            extract_path: "$.recovered_signer",
          },
        },
      }],
      production_paths: [{
        description: "Capture refresh-flow JWT + EVM signature recovery.",
        tool_call_pattern: [
          { tool: "bob_http_scan" },
          { tool: "bob_evm_call" },
        ],
      }],
    };
    const reAttach = JSON.parse(TOOL_HANDLERS.bob_attach_contract({
      target_domain: domain,
      node_id: nodeId,
      contract: refinedContract,
    }));
    assert.equal(reAttach.from_state, "failed",
      "X.8 retry-with-recall re-contracts from failed → contracted");
    assert.equal(reAttach.to_state, "contracted");

    // (3) prepare_node again — brief MUST surface the prior failure via
    // the `prior_attempt` slice (X.12 Do step 1 retry-with-recall).
    const prep2 = JSON.parse(TOOL_HANDLERS.bob_prepare_node({
      target_domain: domain,
      node_id: nodeId,
    }));
    assert.ok(prep2.brief.prior_attempt,
      "prior_attempt slice MUST be present on re-prepare after a prior failed attempt");
    const surfacedAttempt = parseFencedBriefJson(prep2.brief.prior_attempt, "prior_attempt").attempts[0];
    assert.equal(surfacedAttempt.failure_reason.reason, "mechanical_verifier_failed");
    const surfacedWitnessFailure = surfacedAttempt.failure_reason.failures.find((f) => f.witness_id === "W-relational");
    assert.ok(surfacedWitnessFailure,
      "prior_attempt slice MUST surface the W-relational witness failure");
    assert.equal(surfacedWitnessFailure.reason, "relation_did_not_hold");
    // The extracted values from the prior failure are inlined per X.12
    // Do step 1 retry-with-recall ("the structured failure_reason +
    // extracted values").
    assert.equal(surfacedWitnessFailure.left_value, "0xATTACKER");
    assert.equal(surfacedWitnessFailure.right_value, "0xVICTIM");
    // The artifact_refs from the prior Contract are inlined so the
    // operator can compare against the new Contract's refs.
    assert.equal(surfacedWitnessFailure.left_artifact_ref, `http_record:${httpRequestId1}`);
    assert.equal(surfacedWitnessFailure.right_artifact_ref, `evm_call:${evmCallId1}`);

    // (4) Second finalize against the refined Contract — succeeds.
    const fin2 = JSON.parse(TOOL_HANDLERS.bob_finalize_node({
      target_domain: domain,
      node_id: nodeId,
      prep_token: prep2.prep_token,
      agent_output: {
        tool_invocations: [
          { tool: "bob_http_scan", output: { status: 200 } },
          { tool: "bob_evm_call", output: { recovered_signer: "0xCORRECTLY_BOUND" } },
        ],
        evidence_refs: [
          { kind: "http_record", request_id: httpRequestId2 },
          { kind: "evm_call", call_id: evmCallId2 },
        ],
      },
    }));
    assert.equal(fin2.to_state, "finalized",
      `retry-with-recall second finalize must succeed: ${JSON.stringify(fin2.failure_reason || fin2.mechanical_verdict)}`);
    assert.equal(fin2.mechanical_verdict.satisfied, true);

    // Sanity: the prior failure event remains on the ledger so future
    // operators can audit the retry history.
    const allFailures = readNodeTransitions(domain).filter(
      (e) => e.payload && e.payload.node_id === nodeId && e.payload.to_state === "failed",
    );
    assert.equal(allFailures.length, 1,
      "the prior failure event remains on the ledger; the refined attempt finalizes alongside it");
  });
});
