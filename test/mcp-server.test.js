const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("crypto");
const { spawnSync } = require("child_process");
const { EventEmitter } = require("events");
const Module = require("module");
const { Readable } = require("stream");
const dns = require("dns");
const fs = require("fs");
const http = require("http");
const https = require("https");
const os = require("os");
const path = require("path");

const REMOVED_HOOK_AUTHORITY_FIELD = ["hook", "required"].join("_");

const serverModule = require("../mcp/server.js");
const {
  VERIFICATION_REPLAY_LEASE_TTL_MS,
  replayExecutionPolicy,
  runWithReplaySafety,
} = require("../mcp/lib/verification-replay-safety.js");
const {
  computeAdjudicationPlanHash,
} = require("../mcp/lib/verification-contracts.js");
const {
  verificationReplayLeaseDir,
} = require("../mcp/lib/paths.js");
const {
  TECHNIQUE_FULL_ITEM_MAX_CHARS,
  TECHNIQUE_FULL_ITEMS_PER_KIND,
  TECHNIQUE_SELECTION_MAX_CHARS,
  TECHNIQUE_SUMMARY_ITEM_MAX_CHARS,
  TECHNIQUE_SUMMARY_ITEMS_PER_KIND,
} = require("../mcp/lib/technique-packs.js");
const egressProfiles = require("../mcp/lib/egress-profiles.js");
const {
  TOOL_HANDLERS,
} = require("../mcp/lib/dispatch.js");
const {
  buildToolRegistry,
  capabilityToolMapFromRegistry,
  defineTool,
  TOOL_REGISTRY,
} = require("../mcp/lib/tool-registry.js");
const {
  TOOL_MODULES,
} = require("../mcp/lib/tools/index.js");
const {
  createMcpMessageHandler,
  createStdioServer,
} = require("../mcp/lib/transport.js");
const {
  COVERAGE_LOG_MAX_RECORDS,
  HTTP_AUDIT_LOG_MAX_RECORDS,
  STATIC_ARTIFACT_MAX_CHARS,
  TRAFFIC_IMPORT_MAX_ENTRIES,
  TRAFFIC_LOG_MAX_RECORDS,
} = require("../mcp/lib/constants.js");
const {
  appendHttpAuditRecord,
} = require("../mcp/lib/http-records.js");
const {
  acquireSessionLock,
  DEFAULT_ARTIFACT_READ_MAX_BYTES,
  loadJsonDocumentStrict,
  readFileUtf8,
  readSessionLockSnapshot,
  removeStaleSessionLock,
  trimJsonlFile,
  withSessionLock,
  writeFileExclusiveAtomic,
} = require("../mcp/lib/storage.js");
const {
  safeFetch,
} = require("../mcp/lib/safe-fetch.js");
const {
  fetchTextWithTimeout,
} = require("../mcp/lib/public-intel.js");
const {
  normalizeAutoSignupResult,
} = require("../mcp/lib/signup.js");
const {
  toolInvocationSidecarPath,
  toolInvocationTelemetryPath,
  appendToolInvocationTelemetryEvent,
  appendToolTelemetryEvent,
  buildToolInvocationTelemetryEvent,
  readToolTelemetry,
  toolTelemetryPath,
} = require("../mcp/lib/tool-telemetry.js");
const {
  bobVersion,
  readResourceText,
  resolveResourcePath,
  runtimeClient,
} = require("../mcp/lib/runtime-resources.js");
const {
  candidateAuthDomains,
} = require("../mcp/lib/auth.js");
const {
  appendPipelineEventDirect,
} = require("../mcp/lib/pipeline-events.js");
const {
  buildGovernanceContext,
} = require("../mcp/lib/governance-context.js");
const {
  attachHandoffOrigin,
  BLOCKED_PREREQ_KIND_VALUES,
  HANDOFF_PROVENANCE_MODEL,
  normalizeBlockedPrereqs,
  sha256Hex,
  signHandoffProvenance,
  validateWaveHandoffPayload,
} = require("../mcp/lib/wave-handoff-contracts.js");

const ROOT = path.join(__dirname, "..");
const PACKAGE_VERSION = require("../package.json").version;

const {
  TOOLS,
  TOOL_MANIFEST,
  executeTool,
  startServer,
} = serverModule;
const {
  SESSION_LOCK_STALE_MS,
} = require("../mcp/lib/constants.js");
const {
  assertSafeDomain,
  attackSurfacePath,
  chainAttemptsJsonlPath,
  claimsJsonlPath,
  coverageJsonlPath,
  evidencePackPaths,
  gradeArtifactPaths,
  handoffSigningKeyPath,
  httpAuditJsonlPath,
  pipelineEventsJsonlPath,
  publicIntelPath,
  reportMarkdownPath,
  sessionDir,
  sessionLockPath,
  sessionsRoot,
  statePath,
  staticArtifactImportDir,
  staticArtifactPath,
  staticArtifactsJsonlPath,
  staticScanResultsJsonlPath,
  surfaceIndexPath,
  surfaceLeadsPath,
  surfaceRoutesPath,
  techniqueAttemptsJsonlPath,
  techniquePackReadsJsonlPath,
  trafficJsonlPath,
  verificationAdjudicationPath,
  verificationAttemptsDir,
  verificationManifestPath,
  verificationRoundPaths,
  verificationSnapshotPath,
} = require("../mcp/lib/paths.js");
const {
  appendJsonlLine,
  writeFileAtomic,
} = require("../mcp/lib/storage.js");
const {
  loadWaveAssignments,
} = require("../mcp/lib/assignments.js");
const {
  clearOperatorNote,
  clearTerminalBlock,
  initSession,
  readSessionState,
  advanceSession,
  reportWritten,
  setOperatorNote,
  readStateSummary,
} = require("../mcp/lib/session-state.js");
const {
  compactSessionState,
} = require("../mcp/lib/session-state-contracts.js");
const {
  readSessionSummary,
} = require("../mcp/lib/session-summary.js");
const {
  routeSurfaces,
} = require("../mcp/lib/surface-router.js");
const {
  buildCoverageSummaryForSurface,
  computeCoverageRequeueSurfaceIds,
  logCoverage,
  normalizeCoverageRecord,
  readCoverageRecordsFromJsonl,
} = require("../mcp/lib/coverage.js");
const {
  buildCircuitBreakerSummary,
  normalizeHttpAuditRecord,
  normalizeTrafficRecord,
  readHttpAuditRecordsFromJsonl,
  readTrafficRecordsFromJsonl,
} = require("../mcp/lib/http-records.js");
const {
  readStaticArtifactRecordsFromJsonl,
  readStaticScanResultsFromJsonl,
  summarizeStaticScanHints,
} = require("../mcp/lib/static-artifacts.js");
const {
  validateScanUrl,
} = require("../mcp/lib/url-surface.js");
const recordCandidateClaimTool = require("../mcp/lib/tools/record-candidate-claim.js");
const listCandidateClaimsTool = require("../mcp/lib/tools/list-candidate-claims.js");
const readCandidateClaimsTool = require("../mcp/lib/tools/read-candidate-claims.js");
const { appendCandidateClaim } = require("../mcp/lib/claims.js");
const recordFinding = recordCandidateClaimTool.handler;
const listFindings = listCandidateClaimsTool.handler;
const readFindings = readCandidateClaimsTool.handler;
const {
  findingPayloadsFromClaims: readFindingsFromJsonl,
} = require("../mcp/lib/tools/record-candidate-claim.js");

// Cycle D.2: findings.jsonl/findings.md are gone; tests that previously
// asserted on those paths now operate on claims.jsonl. Provide local aliases so
// the call sites do not have to know about the renamed artifact.
const findingsJsonlPath = (domain) => claimsJsonlPath(domain);
const findingsMarkdownPath = (domain) => path.join(sessionDir(domain), "claims.md");
const {
  normalizeGradeVerdictDocument,
  readGradeVerdict,
  renderGradeVerdictMarkdown,
  writeGradeVerdict,
} = require("../mcp/lib/grade-verdict-store.js");
const {
  normalizeVerificationRoundDocument,
  readVerificationRound,
  renderVerificationRoundMarkdown,
  writeVerificationRound,
} = require("../mcp/lib/verification-round-store.js");
const {
  normalizeFindingRecord,
  renderFindingMarkdownEntry,
  summarizeFindings,
} = require("../mcp/lib/finding-contracts.js");
const {
  normalizeEvidencePacksDocument,
  readEvidencePacks,
  renderEvidencePacksMarkdown,
  writeEvidencePacks,
} = require("../mcp/lib/evidence.js");
const {
  buildVerificationAdjudication,
  readVerificationContext,
  refreshVerificationManifest,
} = require("../mcp/lib/verification.js");
const {
  readChainAttempts,
  readChainAttemptsFromJsonl,
  writeChainAttempt,
} = require("../mcp/lib/chain-attempts.js");
const {
  rankAttackSurfaces,
} = require("../mcp/lib/ranking.js");
const {
  assertHttpScopeDomain,
  filterExclusionsByHosts,
  readScopeExclusions,
  validateHttpScanScope,
} = require("../mcp/lib/scope.js");
const {
  readAssignmentBrief,
  resolveEvaluatorKnowledge,
} = require("../mcp/lib/assignment-brief.js");
const {
  readCapabilityPlaybook,
} = require("../mcp/lib/capability-playbooks.js");
const {
  getContextBudget,
} = require("../mcp/lib/context-budget.js");
const {
  loadTechniqueRegistry,
  logTechniqueAttempt,
  readTechniqueAttemptRecordsFromJsonl,
  readTechniquePack,
  readTechniquePackReadRecordsFromJsonl,
  selectTechniquePacks,
} = require("../mcp/lib/technique-packs.js");
const {
  authStore,
  buildHeaderProfile,
  listAuthProfiles,
  migrateAuthJson,
  readAuthJson,
  resolveAuthJsonPath,
} = require("../mcp/lib/auth.js");
const {
  tempEmail,
} = require("../mcp/lib/temp-email.js");
const {
  autoSignup,
  signupDetect,
} = require("../mcp/lib/signup.js");
const {
  finalizeAgentRun,
} = require("../mcp/lib/agent-run-completion.js");
const {
  applyWaveMerge,
  mergeWaveHandoffs,
  readWaveHandoffs,
  startNextWave,
  startWave,
  waveHandoffStatus,
  waveStatus,
  writeHandoff,
  writeWaveHandoff: writeWaveHandoffRaw,
} = require("../mcp/lib/waves.js");
const {
  ensureHandoffSigningKey,
} = require("../mcp/lib/handoff-signing-key.js");
const {
  readPipelineAnalytics,
  readPipelineEvents,
  readSessionArtifactSummary,
} = require("../mcp/lib/pipeline-analytics.js");
const {
  promoteSurfaceLeads,
  readSurfaceLeads,
  recordSurfaceLeads,
} = require("../mcp/lib/surface-leads.js");
const {
  importHttpTraffic,
} = require("../mcp/lib/tools/import-http-traffic.js");
const {
  bountyPublicIntel,
} = require("../mcp/lib/tools/public-intel.js");
const {
  importStaticArtifact,
} = require("../mcp/lib/tools/import-static-artifact.js");
const {
  readHttpAudit,
} = require("../mcp/lib/tools/read-http-audit.js");
const {
  staticScan,
} = require("../mcp/lib/tools/static-scan.js");
const {
  redactTextSensitiveValues,
  redactUrlSensitiveValues,
} = require("../mcp/redaction.js");

const EXPECTED_TOOL_NAMES = [
  "bob_http_scan",
  "bob_read_http_audit",
  "bob_start_next_wave",
  "bob_start_wave",
  "bob_route_surfaces",
  "bob_read_surface_routes",
  "bob_import_http_traffic",
  "bob_public_intel",
  "bob_import_static_artifact",
  "bob_ingest_schema_doc",
  "bob_query_schema_contracts",
  "bob_run_doc_delta",
  "bob_read_doc_delta_results",
  "bob_run_auth_differential",
  "bob_read_auth_differential_results",
  "bob_static_scan",
  "bob_record_candidate_claim",
  "bob_read_candidate_claims",
  "bob_list_candidate_claims",
  "bob_write_chain_attempt",
  "bob_read_chain_attempts",
  "bob_append_chain_node",
  "bob_query_chain_tree",
  "bob_chain_frontier",
  "bob_chain_ancestry",
  "bob_write_verification_round",
  "bob_read_verification_round",
  "bob_read_verification_context",
  "bob_diff_verification_attempts",
  "bob_build_verification_adjudication",
  "bob_write_evidence_packs",
  "bob_read_evidence_packs",
  "bob_write_grade_verdict",
  "bob_read_grade_verdict",
  "bob_init_session",
  "bob_init_repo_session",
  "bob_repo_inventory",
  "bob_repo_prepare_env",
  "bob_repo_docker_run",
  "bob_repo_check",
  "bob_read_session_state",
  "bob_read_session_nucleus",
  "bob_advance_session",
  "bob_apply_wave_merge",
  "bob_write_handoff",
  "bob_write_wave_handoff",
  "bob_finalize_agent_run",
  "bob_wave_handoff_status",
  "bob_merge_wave_handoffs",
  "bob_read_wave_handoffs",
  "bob_log_dead_ends",
  "bob_log_coverage",
  "bob_wave_status",
  "bob_temp_email",
  "bob_signup_detect",
  "bob_auth_store",
  "bob_list_auth_profiles",
  "bob_auto_signup",
  "bob_read_state_summary",
  "bob_read_session_summary",
  "bob_set_operator_note",
  "bob_clear_operator_note",
  "bob_clear_terminal_block",
  "bounty_report_written",
  "bob_finalize_report",
  "bob_compose_report",
  "bob_amend_report",
  "bob_write_chain_rollup",
  "bob_set_friction_scanners",
  "bob_read_assignment_brief",
  "bob_read_capability_playbook",
  "bob_get_context_budget",
  "bob_select_technique_packs",
  "bob_read_technique_pack",
  "bob_log_technique_attempt",
  "bob_read_tool_telemetry",
  "bob_read_pipeline_analytics",
  "bob_read_capability_metrics",
  "bob_evaluate_capabilities",
  "bob_ingest_audit_report",
  "bob_query_audit_reports",
  "bob_suggest_invariants",
  "bob_run_invariant_for_finding",
  "bob_read_invariant_runs",
  "bob_extract_routes",
  "bob_build_symbol_surface_index",
  "bob_summarize_diff_impact",
  "bob_evm_call",
  "bob_evm_storage_read",
  "bob_evm_fetch_source",
  "bob_evm_role_table",
  "bob_foundry_run",
  "bob_halmos_run",
  "bob_svm_fetch_account",
  "bob_svm_fetch_program",
  "bob_anchor_run",
  "bob_aptos_fetch_resource",
  "bob_aptos_fetch_module",
  "bob_aptos_run",
  "bob_sui_fetch_object",
  "bob_sui_fetch_package",
  "bob_sui_run",
  "bob_substrate_run",
  "bob_substrate_fetch_storage",
  "bob_substrate_fetch_runtime",
  "bob_cosmwasm_run",
  "bob_cosmwasm_fetch_contract",
  "bob_cosmwasm_smart_query",
  "bob_record_surface_leads",
  "bob_read_surface_leads",
  "bob_promote_surface_leads",
  "bob_build_surface_graph",
  "bob_query_surface_graph",
  "bob_append_frontier_event",
  "bob_propose_hypothesis",
  "bob_propose_transition",
  "bob_materialize_task_graph",
  "bob_read_task_graph",
  "bob_attach_contract",
  "bob_resolve_body",
  "bob_prepare_node",
  "bob_finalize_node",
  "bob_schedule_graph_nodes",
  "bob_materialize_frontier",
  "bob_read_queue_policy",
  "bob_set_queue_policy",
  "bob_schedule_tasks",
  "bob_browser_session_start",
  "bob_browser_navigate",
  "bob_browser_snapshot",
  "bob_browser_click",
  "bob_browser_type",
  "bob_browser_evaluate",
  "bob_browser_network_requests",
  "bob_browser_console_messages",
  "bob_browser_wait_for",
  "bob_browser_press_key",
  "bob_browser_take_screenshot",
  "bob_browser_fill_form",
  "bob_browser_session_close",
  "bob_browser_session_start_recording",
  "bob_browser_flush_recorded_requests",
  "bob_set_pack_telemetry_config",
  // Plane Y Cycle Y.2 — capability friction + protocol drift voluntary
  // emission tools plus the Y-D13 runtime drift telemetry entry.
  "bob_log_capability_friction",
  "bob_log_protocol_drift",
  "bob_emit_runtime_drift",
  // Plane Y Cycle Y.6 — orchestrator-only friction-to-Hypothesis promotion
  // (Y-P6 + Y-P11). Threads friction_history into suggested_contract
  // BEFORE bob_attach_contract runs.
  "bob_propose_friction_promotion",
  // Plane Y Cycle Y.7 — adversarial transcript scan (Y-D6 + Y-P9).
  // Orchestrator-only pure read returning synthetic capability_friction +
  // protocol_drift records (W2 + rev-4.1 silent_lead_threshold_drop).
  "bob_scan_transcript_for_friction",
];

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-test-"));
  process.env.HOME = tempHome;

  const cleanup = () => {
    if (previousHome === undefined) {
      delete process.env.HOME;
    } else {
      process.env.HOME = previousHome;
    }
    fs.rmSync(tempHome, { recursive: true, force: true });
  };

  try {
    const result = fn(tempHome);
    if (result && typeof result.then === "function") {
      return result.finally(cleanup);
    }
    cleanup();
    return result;
  } catch (error) {
    cleanup();
    throw error;
  }
}

function withEnv(overrides, fn) {
  const previous = {};
  for (const key of Object.keys(overrides)) {
    previous[key] = process.env[key];
    if (overrides[key] === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = overrides[key];
    }
  }

  const cleanup = () => {
    for (const key of Object.keys(overrides)) {
      if (previous[key] === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = previous[key];
      }
    }
  };

  try {
    const result = fn();
    if (result && typeof result.then === "function") {
      return result.finally(cleanup);
    }
    cleanup();
    return result;
  } catch (error) {
    cleanup();
    throw error;
  }
}

test("PSL-backed HTTP scope rejects public suffix tokens and isolates tenant domains", () => {
  assert.throws(
    () => assertHttpScopeDomain("co.uk"),
    /registrable domain, not only a public suffix/,
  );
  assert.throws(
    () => assertHttpScopeDomain("github.io"),
    /registrable domain, not only a public suffix/,
  );

  assert.equal(assertHttpScopeDomain("foo.github.io"), "foo.github.io");
  const allowed = validateHttpScanScope("https://app.foo.github.io/login", "foo.github.io");
  assert.equal(allowed.allowed, true);
  assert.equal(allowed.registrable_domain, "foo.github.io");
  assert.equal(allowed.public_suffix, "github.io");
  assert.equal(allowed.public_suffix_source, "psl");

  assert.throws(
    () => validateHttpScanScope("https://bar.github.io/login", "foo.github.io"),
    /outside target_domain foo\.github\.io/,
  );
});

test("HTTP scope normalizes IDN hostnames to ASCII before PSL lookup", () => {
  const asciiDomain = "xn--85x722f.com.cn";
  assert.equal(assertHttpScopeDomain("食狮.com.cn"), asciiDomain);

  const decision = validateHttpScanScope("https://食狮.com.cn/path", "食狮.com.cn");
  assert.equal(decision.allowed, true);
  assert.equal(decision.host, asciiDomain);
  assert.equal(decision.target_domain, asciiDomain);
  assert.equal(decision.registrable_domain, asciiDomain);
  assert.equal(decision.public_suffix, "com.cn");
});

test("HTTP scope rejects malformed, internal, IP, and public-suffix-only domains", () => {
  for (const domain of ["localhost", "foo.local", "foo.internal", "127.0.0.1", "bad_label_.com", "com"]) {
    assert.throws(
      () => assertHttpScopeDomain(domain),
      /target_domain/,
      domain,
    );
  }
});

test("local PSL overlay can add stale public suffixes without network refresh", () => {
  withTempHome((home) => {
    const overlayPath = path.join(home, "psl-overlay.txt");
    fs.writeFileSync(overlayPath, "# local operator overlay\nplatform.example\n", "utf8");

    withEnv({ BOB_PSL_OVERLAY_FILE: overlayPath }, () => {
      assert.throws(
        () => assertHttpScopeDomain("platform.example"),
        /registrable domain, not only a public suffix/,
      );
      assert.equal(assertHttpScopeDomain("tenant.platform.example"), "tenant.platform.example");

      const decision = validateHttpScanScope(
        "https://app.tenant.platform.example/login",
        "tenant.platform.example",
      );
      assert.equal(decision.allowed, true);
      assert.equal(decision.registrable_domain, "tenant.platform.example");
      assert.equal(decision.public_suffix, "platform.example");
      assert.equal(decision.public_suffix_source, "operator_overlay");
      assert.equal(decision.psl_overlay_file, overlayPath);

      assert.throws(
        () => validateHttpScanScope("https://other.platform.example/login", "tenant.platform.example"),
        /outside target_domain tenant\.platform\.example/,
      );
    });
  });
});

test("local PSL overlay cache reloads when the overlay file changes", () => {
  withTempHome((home) => {
    const overlayPath = path.join(home, "psl-overlay-reload.txt");
    fs.writeFileSync(overlayPath, "platform.example\n", "utf8");

    withEnv({ BOB_PSL_OVERLAY_FILE: overlayPath }, () => {
      assert.throws(
        () => assertHttpScopeDomain("platform.example"),
        /registrable domain, not only a public suffix/,
      );

      fs.writeFileSync(overlayPath, "newplatform.example\n", "utf8");
      const future = new Date(Date.now() + 5000);
      fs.utimesSync(overlayPath, future, future);

      assert.throws(
        () => assertHttpScopeDomain("newplatform.example"),
        /registrable domain, not only a public suffix/,
      );
    });
  });
});

test("HTTP audit logs local PSL overlay source for allowed scoped requests", async () => {
  await withTempHome(async (home) => {
    const overlayPath = path.join(home, "psl-overlay.txt");
    const domain = "tenant.platform.example";
    fs.writeFileSync(overlayPath, "# local operator overlay\nplatform.example\n", "utf8");
    seedSessionState(domain);

    await withEnv({ BOB_PSL_OVERLAY_FILE: overlayPath }, async () => {
      await withMockSafeFetch({
        [`https://app.${domain}/ok`]: { status: 200, statusText: "OK", body: "ok" },
        [`https://app.${domain}/fail`]: { error: new Error("connection reset") },
      }, async () => {
        const result = await executeTool("bob_http_scan", {
          target_domain: domain,
          method: "GET",
          url: `https://app.${domain}/ok`,
          response_mode: "status_only",
        });

        assert.equal(result.ok, true);
        const missingAuth = await executeTool("bob_http_scan", {
          target_domain: domain,
          method: "GET",
          url: `https://app.${domain}/missing-auth`,
          auth_profile: "missing",
          response_mode: "status_only",
        });
        assert.equal(missingAuth.ok, false);
        assert.equal(missingAuth.error.code, "AUTH_MISSING");

        const requestError = await executeTool("bob_http_scan", {
          target_domain: domain,
          method: "GET",
          url: `https://app.${domain}/fail`,
          response_mode: "status_only",
        });
        assert.equal(requestError.ok, false);

        const records = readHttpAuditRecordsFromJsonl(domain);
        assert.equal(records.length, 3);
        for (const record of records) {
          assert.equal(record.registrable_domain, domain);
          assert.equal(record.public_suffix, "platform.example");
          assert.equal(record.public_suffix_source, "operator_overlay");
          assert.equal(record.psl_overlay_file, overlayPath);
        }
        assert.deepEqual(records.map((record) => record.scope_decision), [
          "allowed",
          "auth_missing",
          "network_unreachable_target",
        ]);
        const audit = JSON.parse(readHttpAudit({ target_domain: domain }));
        const okSummary = audit.summary.recent.find((record) => record.url.endsWith("/ok"));
        assert.equal(okSummary.public_suffix_source, "operator_overlay");
        assert.equal(okSummary.psl_overlay_file, overlayPath);
      });
    });
  });
});

test("bob_init_session validates PSL-backed target_domain before writing state", async () => {
  await withTempHome(async () => {
    const publicSuffix = await executeTool("bob_init_session", {
      target_domain: "github.io",
      target_url: "https://foo.github.io",
    });
    assert.equal(publicSuffix.ok, false);
    assert.equal(publicSuffix.error.code, "INVALID_ARGUMENTS");
    assert.match(publicSuffix.error.message, /registrable domain, not only a public suffix/);

    const offTargetUrl = await executeTool("bob_init_session", {
      target_domain: "foo.github.io",
      target_url: "https://bar.github.io",
    });
    assert.equal(offTargetUrl.ok, false);
    assert.equal(offTargetUrl.error.code, "SCOPE_BLOCKED");
    assert.match(offTargetUrl.error.message, /outside target_domain foo\.github\.io/);
  });
});

test("scoped tool policy normalizes IDN target_domain before handlers run", async () => {
  await withTempHome(async () => {
    const asciiDomain = "xn--85x722f.com.cn";
    seedSessionState(asciiDomain);
    await withMockSafeFetch({
      [`https://${asciiDomain}/ok`]: { status: 200, statusText: "OK", body: "ok" },
    }, async (requestedUrls) => {
      const result = await executeTool("bob_http_scan", {
        target_domain: "食狮.com.cn",
        method: "GET",
        url: "https://食狮.com.cn/ok",
        response_mode: "status_only",
      });

      assert.equal(result.ok, true);
      assert.equal(result.data.status, 200);
      assert.deepEqual(requestedUrls, [`https://${asciiDomain}/ok`]);
    });
  });
});

function withTempTechniqueKnowledge(document, fn) {
  return withTempTechniqueKnowledgeText(`${JSON.stringify(document, null, 2)}\n`, fn);
}

function withTempTechniqueKnowledgeText(contents, fn) {
  const previousProjectDir = process.env.CLAUDE_PROJECT_DIR;
  const previousBobResourceDir = process.env.BOB_RESOURCE_DIR;
  const previousBobProjectDir = process.env.BOB_PROJECT_DIR;
  const tempProjectDir = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-techniques-"));
  const knowledgeDir = path.join(tempProjectDir, ".claude", "knowledge");
  fs.mkdirSync(knowledgeDir, { recursive: true });
  fs.writeFileSync(
    path.join(knowledgeDir, "evaluator-techniques.json"),
    contents,
    "utf8",
  );
  process.env.CLAUDE_PROJECT_DIR = tempProjectDir;
  delete process.env.BOB_RESOURCE_DIR;
  delete process.env.BOB_PROJECT_DIR;

  const cleanup = () => {
    if (previousProjectDir === undefined) {
      delete process.env.CLAUDE_PROJECT_DIR;
    } else {
      process.env.CLAUDE_PROJECT_DIR = previousProjectDir;
    }
    if (previousBobResourceDir === undefined) {
      delete process.env.BOB_RESOURCE_DIR;
    } else {
      process.env.BOB_RESOURCE_DIR = previousBobResourceDir;
    }
    if (previousBobProjectDir === undefined) {
      delete process.env.BOB_PROJECT_DIR;
    } else {
      process.env.BOB_PROJECT_DIR = previousBobProjectDir;
    }
    fs.rmSync(tempProjectDir, { recursive: true, force: true });
  };

  try {
    const result = fn(tempProjectDir);
    if (result && typeof result.then === "function") {
      return result.finally(cleanup);
    }
    cleanup();
    return result;
  } catch (error) {
    cleanup();
    throw error;
  }
}

function oversizedTechniqueKnowledge({
  packCount = 8,
  itemCount = 20,
  itemChars = 1500,
} = {}) {
  return {
    version: 99,
    entries: Array.from({ length: packCount }, (_, packIndex) => ({
      id: `oversized-${packIndex}`,
      version: 99,
      title: `Oversized ${packIndex}`,
      capability_packs: ["web"],
      match: {
        tech: ["OversizedStack"],
        endpoints: ["/oversized"],
        params: ["oversized_id"],
        hints: ["oversized-hint"],
      },
      techniques: Array.from(
        { length: itemCount },
        (_, itemIndex) => `technique ${packIndex}-${itemIndex} ${"T".repeat(itemChars)}`,
      ),
      payload_hints: Array.from(
        { length: itemCount },
        (_, itemIndex) => `payload ${packIndex}-${itemIndex} ${"P".repeat(itemChars)}`,
      ),
    })),
  };
}

function withDefaultEgressConfig(document, fn) {
  const projectRoot = fs.mkdtempSync(path.join(os.tmpdir(), "bob-egress-project-"));
  const filePath = egressProfiles.egressProfilesPath(projectRoot);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(document, null, 2)}\n`, "utf8");
  const previousProjectDir = process.env.BOB_PROJECT_DIR;
  process.env.BOB_PROJECT_DIR = projectRoot;

  const cleanup = () => {
    if (previousProjectDir === undefined) {
      delete process.env.BOB_PROJECT_DIR;
    } else {
      process.env.BOB_PROJECT_DIR = previousProjectDir;
    }
    fs.rmSync(projectRoot, { recursive: true, force: true });
  };

  try {
    const result = fn();
    if (result && typeof result.then === "function") {
      return result.finally(cleanup);
    }
    cleanup();
    return result;
  } catch (error) {
    cleanup();
    throw error;
  }
}

function readJsonl(filePath) {
  if (!fs.existsSync(filePath)) return [];
  return fs.readFileSync(filePath, "utf8")
    .split(/\r?\n/)
    .filter((line) => line.trim())
    .map((line) => JSON.parse(line));
}

// Test compat shim. Cycle D.1 retired the bounty_transition_phase tool and
// its handler; tests that drove the legacy phase machine via direct
// transitionPhase(...) calls now route through bob_advance_session. The
// legacy phase-to-lifecycle mapping is the same one the registry alias
// uses (see mcp/lib/tools/advance-session.js arg_adapter). When the target
// lifecycle state equals the current one (e.g., legacy AUTH -> EVALUATE both
// collapse to OPEN_FRONTIER), the helper returns a synthetic success
// envelope instead of calling advanceSession so existing legacy chains keep
// driving fixtures forward without hitting the "no transition" gate.
const LEGACY_PHASE_TO_LIFECYCLE_STATE = Object.freeze({
  SURFACE_DISCOVERY: "SETUP",
  AUTH: "OPEN_FRONTIER",
  EVALUATE: "OPEN_FRONTIER",
  CHAIN: "OPEN_FRONTIER",
  EXPLORE: "OPEN_FRONTIER",
  VERIFY: "VERIFY",
  GRADE: "GRADE",
  REPORT: "REPORT",
});

function readCurrentLifecycleState(domain) {
  try {
    const nucleusPath = require("../mcp/lib/paths.js").sessionNucleusPath(domain);
    if (fs.existsSync(nucleusPath)) {
      const parsed = JSON.parse(fs.readFileSync(nucleusPath, "utf8"));
      if (parsed && typeof parsed.lifecycle_state === "string") return parsed.lifecycle_state;
    }
  } catch {}
  try {
    const sp = statePath(domain);
    if (fs.existsSync(sp)) {
      const parsed = JSON.parse(fs.readFileSync(sp, "utf8"));
      if (parsed && typeof parsed.lifecycle_state === "string") return parsed.lifecycle_state;
      if (parsed && typeof parsed.phase === "string") {
        return LEGACY_PHASE_TO_LIFECYCLE_STATE[parsed.phase] || null;
      }
    }
  } catch {}
  return null;
}

// The legacy phase machine had 1-step edges that span multiple lifecycle
// states in the new world (CHAIN -> VERIFY collapses to OPEN_FRONTIER ->
// CLAIM_FREEZE -> VERIFY). The shim walks the canonical six-state path
// SETUP -> OPEN_FRONTIER -> CLAIM_FREEZE -> VERIFY -> GRADE -> REPORT and
// invokes bob_advance_session one edge at a time. Each intermediate hop is
// override-forced when an override_reason was supplied, mirroring the
// legacy "single transition + reason" semantics for blocked gates.
const CANONICAL_FORWARD_LIFECYCLE = Object.freeze([
  "SETUP",
  "OPEN_FRONTIER",
  "CLAIM_FREEZE",
  "VERIFY",
  "GRADE",
  "REPORT",
]);

function lifecyclePathBetween(fromState, toState) {
  const fromIndex = CANONICAL_FORWARD_LIFECYCLE.indexOf(fromState);
  const toIndex = CANONICAL_FORWARD_LIFECYCLE.indexOf(toState);
  if (fromIndex < 0 || toIndex < 0) return null;
  if (fromIndex === toIndex) return [];
  if (fromIndex < toIndex) {
    return CANONICAL_FORWARD_LIFECYCLE.slice(fromIndex + 1, toIndex + 1);
  }
  // Backward transitions in the legacy machine (e.g., GRADE -> EVALUATE)
  // are re-entry edges in the new lifecycle: every later state can return
  // to OPEN_FRONTIER directly. The legacy chain collapses to a single
  // OPEN_FRONTIER hop.
  return ["OPEN_FRONTIER"];
}

// Synchronize the nucleus's lifecycle_state to match state.json's legacy
// phase. Tests that manually rewrite state.json (e.g., to simulate orphan
// recovery) need the nucleus to reflect the same lifecycle so the next
// transitionPhase shim call performs a real advance instead of a no-op.
function syncNucleusFromStateJson(domain) {
  try {
    const sp = statePath(domain);
    if (!fs.existsSync(sp)) return;
    const stateDoc = JSON.parse(fs.readFileSync(sp, "utf8"));
    const expectedState = LEGACY_PHASE_TO_LIFECYCLE_STATE[stateDoc.phase] || null;
    if (!expectedState) return;
    const nucleusPath = require("../mcp/lib/paths.js").sessionNucleusPath(domain);
    if (!fs.existsSync(nucleusPath)) return;
    const nucleus = JSON.parse(fs.readFileSync(nucleusPath, "utf8"));
    if (nucleus.lifecycle_state === expectedState) return;
    const { buildSessionNucleus } = require("../mcp/lib/governance-contracts.js");
    const { writeJsonDocument } = require("../mcp/lib/fabric-common.js");
    const next = buildSessionNucleus({
      target_domain: nucleus.target_domain,
      target_url: nucleus.scope_policy && nucleus.scope_policy.target_url,
      scope_policy: nucleus.scope_policy,
      egress_identity: nucleus.egress_identity,
      auth_context: nucleus.auth_context,
      operator_constraint: nucleus.operator_constraint,
      lifecycle_state: expectedState,
    });
    writeJsonDocument(nucleusPath, next);
  } catch {}
}

function transitionPhase(args) {
  const safe = (args && typeof args === "object" && !Array.isArray(args)) ? args : {};
  const targetDomain = typeof safe.target_domain === "string" ? safe.target_domain : null;
  const targetState = typeof safe.to_phase === "string"
    ? (LEGACY_PHASE_TO_LIFECYCLE_STATE[safe.to_phase] || safe.to_phase)
    : null;
  if (!targetDomain || !targetState) {
    return advanceSession({ target_domain: targetDomain, to_state: targetState });
  }
  // If a test manually rewrote state.json to a "regression" phase, the
  // nucleus may still hold the previous lifecycle_state; sync so the next
  // legacy transition can land its expected event sequence.
  if (targetDomain) syncNucleusFromStateJson(targetDomain);
  const overrideReason = typeof safe.override_reason === "string" && safe.override_reason.trim()
    ? safe.override_reason
    : null;
  const currentState = readCurrentLifecycleState(targetDomain);
  if (currentState && currentState === targetState) {
    return JSON.stringify({
      version: 1,
      advanced: false,
      idempotent: true,
      from_state: currentState,
      to_state: targetState,
    });
  }
  const path = lifecyclePathBetween(currentState, targetState);
  if (!path || path.length === 0) {
    return advanceSession({
      target_domain: targetDomain,
      to_state: targetState,
      ...(overrideReason ? { override: "operator_force", override_reason: overrideReason } : {}),
    });
  }
  let lastResult = null;
  for (const hop of path) {
    const hopArgs = {
      target_domain: targetDomain,
      to_state: hop,
      ...(overrideReason ? { override: "operator_force", override_reason: overrideReason } : {}),
    };
    lastResult = advanceSession(hopArgs);
  }
  return lastResult;
}

function seedSessionState(domain, overrides = {}) {
  const dir = sessionDir(domain);
  fs.mkdirSync(dir, { recursive: true });
  // Cycle D.3 deleted state.explored / state.terminally_blocked /
  // state.lead_surface_ids from the contract. Legacy fixtures may still
  // pass these via overrides; the contract's normalizer silently drops
  // them. The seed itself no longer carries the fields by default so the
  // serialized state.json matches the post-D.3 shape.
  const state = {
    target: domain,
    target_url: `https://${domain}`,
    deep_mode: false,
    checkpoint_mode: "normal",
    block_internal_hosts: false,
    block_internal_hosts_source: "legacy_default",
    phase: "EVALUATE",
    evaluation_wave: 0,
    pending_wave: null,
    total_findings: 0,
    prereq_registry_snapshots: [],
    blocked_prereq_history: [],
    terminal_block_clear_history: [],
    dead_ends: [],
    waf_blocked_endpoints: [],
    scope_exclusions: [],
    hold_count: 0,
    auth_status: "pending",
    ...legacyEgressStateFields(),
    operator_note: null,
    verification_schema_version: null,
    verification_attempt_id: null,
    verification_snapshot_hash: null,
    verification_entered_at: null,
    ...overrides,
  };
  // Translate legacy overrides into frontier events so downstream
  // projections see the seeded state. The legacy fields are stripped from
  // the on-disk state.json after this translation.
  const legacyClosures = Array.isArray(overrides.explored) ? overrides.explored : null;
  const legacyBlockers = Array.isArray(overrides.terminally_blocked) ? overrides.terminally_blocked : null;
  const legacyLeadSurfaces = Array.isArray(overrides.lead_surface_ids) ? overrides.lead_surface_ids : null;
  delete state.explored;
  delete state.terminally_blocked;
  delete state.lead_surface_ids;
  // Mirror production wave-merge-settler: each terminally-blocked seed entry
  // also lands in state.blocked_prereq_history so summarizeBlockedPrereqs
  // (which now groups history by (kind, identifier_hint) restricted to the
  // current frontier blocker set) can see the seeded blockers.
  if (legacyBlockers && legacyBlockers.length > 0) {
    const seededHistory = Array.isArray(state.blocked_prereq_history)
      ? state.blocked_prereq_history.slice()
      : [];
    for (const entry of legacyBlockers) {
      if (!entry || typeof entry.surface_id !== "string") continue;
      const wave = Number.isInteger(entry.blocked_at_wave) && entry.blocked_at_wave >= 1
        ? entry.blocked_at_wave
        : 1;
      const blockers = Array.isArray(entry.blockers) ? entry.blockers : [];
      for (const blocker of blockers) {
        if (!blocker || typeof blocker.kind !== "string") continue;
        const record = {
          wave,
          surface_id: entry.surface_id,
          kind: blocker.kind,
        };
        if (blocker.identifier_hint) record.identifier_hint = blocker.identifier_hint;
        if (blocker.reason) record.reason = blocker.reason;
        seededHistory.push(record);
      }
    }
    state.blocked_prereq_history = seededHistory;
  }
  writeFileAtomic(statePath(domain), `${JSON.stringify(state, null, 2)}\n`);
  // Cycle D.1: tests that seed legacy state.json must also produce a session
  // nucleus so bob_advance_session has the lifecycle authority it expects.
  // Skip when overrides already wrote a nucleus or the fixture is testing
  // legacy-only normalization.
  try {
    const nucleusPath = require("../mcp/lib/paths.js").sessionNucleusPath(domain);
    if (!fs.existsSync(nucleusPath)) {
      const { buildSessionNucleus } = require("../mcp/lib/governance-contracts.js");
      const { writeJsonDocument } = require("../mcp/lib/fabric-common.js");
      const lifecycleState = state.lifecycle_state
        || LEGACY_PHASE_TO_LIFECYCLE_STATE[state.phase]
        || "SETUP";
      const nucleus = buildSessionNucleus({
        target_domain: domain,
        target_url: state.target_url,
        scope_policy: {
          target_url: state.target_url,
          checkpoint_mode: state.checkpoint_mode,
          deep_mode: state.deep_mode,
          block_internal_hosts: state.block_internal_hosts,
          allow_internal_hosts: false,
        },
        egress_identity: {
          egress_profile: state.egress_profile,
          egress_region: state.egress_region,
          proxy_configured: state.proxy_configured,
          egress_profile_identity_hash: state.egress_profile_identity_hash,
          egress_profile_identity_version: state.egress_profile_identity_version,
        },
        auth_context: { auth_status: state.auth_status || "pending" },
        operator_constraint: {},
        lifecycle_state: lifecycleState,
      });
      writeJsonDocument(nucleusPath, nucleus);
    }
  } catch {}
  // Translate legacy projection overrides into frontier events so
  // downstream projections (currentClosures / currentBlockers /
  // currentLeadSurfaceIds) see the seeded state after D.3 removed the
  // state.json arrays.
  try {
    const { appendFrontierEvent } = require("../mcp/lib/frontier-events.js");
    if (legacyClosures && legacyClosures.length > 0) {
      for (const surfaceId of legacyClosures) {
        if (typeof surfaceId !== "string" || !surfaceId) continue;
        appendFrontierEvent({
          target_domain: domain,
          kind: "closure.recorded",
          surface_id: surfaceId,
          payload: { surface_fully_explored: true, reason: "seeded_legacy_explored" },
          source: { artifact: "wave-merge", tool: "bob_apply_wave_merge" },
        });
      }
    }
    if (legacyBlockers && legacyBlockers.length > 0) {
      for (const entry of legacyBlockers) {
        if (!entry || typeof entry.surface_id !== "string") continue;
        const firstBlocker = Array.isArray(entry.blockers) && entry.blockers.length > 0 ? entry.blockers[0] : null;
        appendFrontierEvent({
          target_domain: domain,
          kind: "blocker.asserted",
          surface_id: entry.surface_id,
          payload: {
            terminally_blocked: true,
            wave: entry.blocked_at_wave || 1,
            kind: firstBlocker ? firstBlocker.kind : "auth_missing",
            identifier_hint: firstBlocker ? firstBlocker.identifier_hint || null : null,
            reason: firstBlocker ? firstBlocker.reason || null : null,
          },
          source: { artifact: "wave-merge", tool: "bob_apply_wave_merge" },
        });
      }
    }
    if (legacyLeadSurfaces && legacyLeadSurfaces.length > 0) {
      for (const surfaceId of legacyLeadSurfaces) {
        if (typeof surfaceId !== "string" || !surfaceId) continue;
        appendFrontierEvent({
          target_domain: domain,
          kind: "surface.observed",
          surface_id: surfaceId,
          payload: { labels: ["promoted_surface_lead", "seeded_legacy_lead_surface"] },
          source: { artifact: "wave-handoff", tool: "bob_apply_wave_merge" },
        });
      }
    }
  } catch {}
  return state;
}

const SEEDED_HANDOFF_TOKENS = new Map();

function seededHandoffTokenKey(domain, waveNumber, agent) {
  return `${domain}\u0000${waveNumber}\u0000${agent}`;
}

function seededHandoffToken(domain, waveNumber, agent) {
  const key = seededHandoffTokenKey(domain, waveNumber, agent);
  let token = SEEDED_HANDOFF_TOKENS.get(key);
  if (!token) {
    token = `test-handoff-token:${domain}:w${waveNumber}:${agent}`;
    SEEDED_HANDOFF_TOKENS.set(key, token);
  }
  return token;
}

function writeWaveHandoff(args) {
  const waveNumber = Number(String(args.wave || "").replace(/^w/i, ""));
  if (!args.handoff_token && Number.isInteger(waveNumber) && waveNumber > 0) {
    const token = SEEDED_HANDOFF_TOKENS.get(
      seededHandoffTokenKey(args.target_domain, waveNumber, args.agent),
    );
    if (token) {
      return writeWaveHandoffRaw({ ...args, handoff_token: token });
    }
  }
  return writeWaveHandoffRaw(args);
}

function writeSignedStoredHandoff(domain, waveNumber, agent, payload) {
  const dir = sessionDir(domain);
  const assignment = loadWaveAssignments(domain, waveNumber).assignmentByAgent.get(agent);
  assert.ok(assignment, `missing seeded assignment for ${agent}`);
  const signed = signHandoffProvenance(
    payload.provenance == null ? { ...payload, provenance: "verified" } : payload,
    ensureHandoffSigningKey(domain),
    { assignment },
  );
  writeFileAtomic(
    path.join(dir, `handoff-w${waveNumber}-${agent}.json`),
    `${JSON.stringify(signed, null, 2)}\n`,
  );
  return signed;
}

function seedAssignments(domain, waveNumber, assignments) {
  const dir = sessionDir(domain);
  fs.mkdirSync(dir, { recursive: true });
  // Production invariant: a wave cannot start without an attack_surface.json.
  // Mirror that here so writeWaveHandoff's strict surface_type lookup succeeds.
  const surfacePath = attackSurfacePath(domain);
  if (!fs.existsSync(surfacePath)) {
    const surfaceIds = Array.from(new Set(assignments.map((a) => a.surface_id))).filter(Boolean);
    seedAttackSurface(domain, surfaceIds.length > 0 ? surfaceIds : ["surface-a"]);
  }
  // Mirror production startWave: capture surface_type from attack_surface.json
  // into the immutable assignment file. Tests that seed an SC surface get the
  // same enforcement path the runtime takes.
  const surfaceById = new Map();
  try {
    const surfaceDoc = JSON.parse(fs.readFileSync(surfacePath, "utf8"));
    for (const surface of surfaceDoc.surfaces || []) {
      if (!surface || typeof surface !== "object") continue;
      surfaceById.set(surface.id, surface);
    }
  } catch {}
  // Also mirror startWave's call to routeSurfacesInternal: classify each
  // surface to derive capability_pack/evaluator_agent/brief_profile so the
  // assignment file is shaped exactly as production writes it. Without
  // this, normalizeAssignmentRouteMetadata throws on any SC assignment.
  // Test cases that explicitly want to forge alternate route metadata
  // pass it directly on the assignment and we preserve it.
  const { classifySurfaceCapability } = require("../mcp/lib/capability-packs.js");
  const persistedAssignments = assignments.map((assignment) => {
    const surface = surfaceById.get(assignment.surface_id);
    const surfaceTypeRaw = surface && typeof surface.surface_type === "string"
      ? surface.surface_type.trim()
      : "";
    const surfaceType = surfaceTypeRaw !== "" ? surfaceTypeRaw : null;
    const persisted = { ...assignment };
    if (surfaceType && persisted.surface_type == null) {
      persisted.surface_type = surfaceType;
    }
    if (surface
      && persisted.capability_pack == null
      && persisted.evaluator_agent == null
      && persisted.brief_profile == null
    ) {
      const route = classifySurfaceCapability(surface);
      persisted.capability_pack = route.capability_pack;
      persisted.evaluator_agent = route.evaluator_agent;
      persisted.brief_profile = route.brief_profile;
    }
    if (persisted.handoff_token_required == null) {
      persisted.handoff_token_required = true;
    }
    if (persisted.handoff_token_sha256 == null) {
      persisted.handoff_token_sha256 = sha256Hex(
        seededHandoffToken(domain, waveNumber, persisted.agent),
      );
    }
    return persisted;
  });
  writeFileAtomic(path.join(dir, `wave-${waveNumber}-assignments.json`), `${JSON.stringify({
    wave_number: waveNumber,
    handoff_tokens_required: true,
    assignments: persistedAssignments,
  }, null, 2)}\n`);
  ensureHandoffSigningKey(domain);
}

function seedAttackSurface(domain, surfaceIds = ["surface-a", "surface-b", "surface-c"]) {
  const surfaces = surfaceIds.map((surfaceId) => ({
    id: surfaceId,
    hosts: [`https://${domain}`],
  }));
  writeFileAtomic(attackSurfacePath(domain), `${JSON.stringify({ surfaces }, null, 2)}\n`);
}

function seedAttackSurfaces(domain, surfaces) {
  writeFileAtomic(attackSurfacePath(domain), `${JSON.stringify({ surfaces }, null, 2)}\n`);
}

function expectedWebContextBudget() {
  return {
    candidate_pack_limit: 5,
    full_pack_read_limit: 2,
    attempt_log_required: true,
  };
}

function expectedTaskBudget() {
  return {
    max_steps: 6,
    max_context_tokens: 24000,
  };
}

function defaultEgressStateFields() {
  return {
    ...egressProfiles.egressProfileIdentityFields(egressProfiles.resolveEgressProfile("default")),
    egress_profile_identity_bound_at: null,
    egress_profile_identity_bind_source: null,
    egress_profile_legacy_migration: null,
  };
}

function legacyEgressStateFields() {
  return {
    egress_profile: "default",
    egress_region: null,
    proxy_configured: false,
    egress_profile_identity_hash: null,
    egress_profile_identity_version: null,
    egress_profile_identity_source: {
      proxy_url_source: "none",
      proxy_env_var: null,
      proxy_url_redacted: null,
      resolved_proxy: null,
    },
    egress_profile_identity_bound_at: null,
    egress_profile_identity_bind_source: null,
    egress_profile_legacy_migration: null,
  };
}

function expectedSmartContractContextBudget() {
  return {
    candidate_pack_limit: 5,
    full_pack_read_limit: 2,
    attempt_log_required: false,
  };
}

function seedTechniqueAttempt(domain, {
  wave = "w1",
  agent = "a1",
  surface_id = "surface-a",
  pack_id = "generic-rest-api",
  status = "attempted",
  evidence = "Technique attempt recorded before finalization.",
} = {}) {
  return JSON.parse(logTechniqueAttempt({
    target_domain: domain,
    wave,
    agent,
    surface_id,
    pack_id,
    status,
    evidence,
  }));
}

function writeUnexpectedHandoff(domain, wave, agent, payload = {}) {
  const dir = sessionDir(domain);
  fs.mkdirSync(dir, { recursive: true });
  writeFileAtomic(path.join(dir, `handoff-${wave}-${agent}.json`), `${JSON.stringify({
    target_domain: domain,
    wave,
    agent,
    surface_id: "surface-z",
    surface_status: "complete",
    dead_ends: [],
    waf_blocked_endpoints: [],
    lead_surface_ids: [],
    ...payload,
  }, null, 2)}\n`);
}

function ensureFindingAssignment(domain, wave, agent) {
  if (wave == null || agent == null) {
    return null;
  }

  const waveNumber = Number(String(wave).slice(1));
  const assignmentsPath = path.join(sessionDir(domain), `wave-${waveNumber}-assignments.json`);
  if (fs.existsSync(assignmentsPath)) {
    const assignmentDoc = JSON.parse(fs.readFileSync(assignmentsPath, "utf8"));
    const assignment = assignmentDoc.assignments.find((item) => item.agent === agent);
    return assignment ? assignment.surface_id : "surface-a";
  }

  seedAssignments(domain, waveNumber, [
    { agent, surface_id: "surface-a" },
  ]);
  return "surface-a";
}

function seedFinding(domain, overrides = {}) {
  const wave = Object.prototype.hasOwnProperty.call(overrides, "wave") ? overrides.wave : "w1";
  const agent = Object.prototype.hasOwnProperty.call(overrides, "agent") ? overrides.agent : "a1";
  const assignedSurfaceId = ensureFindingAssignment(domain, wave, agent);
  const surfaceId = Object.prototype.hasOwnProperty.call(overrides, "surface_id")
    ? overrides.surface_id
    : assignedSurfaceId;

  return JSON.parse(recordFinding({
    target_domain: domain,
    title: "IDOR on account export",
    severity: "high",
    cwe: "CWE-639",
    endpoint: "/api/export",
    description: "Authenticated user can export another account's data by changing account_id.",
    proof_of_concept: "curl https://example.com/api/export?account_id=2",
    response_evidence: "{\"account_id\":2}",
    impact: "Cross-account PII disclosure.",
    validated: true,
    wave,
    agent,
    surface_id: surfaceId,
    ...overrides,
  }));
}

function seedVerificationPipeline(domain, results) {
  const readContext = () => {
    try {
      return JSON.parse(readVerificationContext({ target_domain: domain }));
    } catch (error) {
      throw new Error(`seedVerificationPipeline: failed to read verification context for ${domain}: ${error.message || error}`);
    }
  };
  // Preserve the test's seeded state across the v2 bootstrap so that downstream
  // assertions about phase, hold_count, evaluation_wave etc. still hold. The bootstrap
  // below transitions CHAIN -> VERIFY, which clobbers those fields.
  let originalState = null;
  if (fs.existsSync(statePath(domain))) {
    try {
      originalState = JSON.parse(fs.readFileSync(statePath(domain), "utf8"));
    } catch {}
  }
  let context = readContext();
  if (context && context.schema_version === 2 && (!context.current_attempt_id || !context.snapshot_hash)) {
    // Clean up any stale v2 artifacts from prior fixture iterations on the same
    // session dir; otherwise bootstrap collides on `attempt-unknown` archives
    // because state.json no longer references them.
    const verifyDir = sessionDir(domain);
    for (const name of [
      "verification-input-snapshot.json",
      "verification-adjudication.json",
      "verification-manifest.json",
      "evidence-packs.json",
      "evidence-packs.md",
    ]) {
      try { fs.rmSync(path.join(verifyDir, name), { force: true }); } catch {}
    }
    for (const round of ["brutalist", "balanced", "final"]) {
      const paths = verificationRoundPaths(domain, round);
      try { fs.rmSync(paths.json, { force: true }); } catch {}
      try { fs.rmSync(paths.markdown, { force: true }); } catch {}
    }
    try { fs.rmSync(path.join(verifyDir, "verification-attempts"), { recursive: true, force: true }); } catch {}
    seedSessionState(domain, { phase: "CHAIN" });
    JSON.parse(transitionPhase({
      target_domain: domain,
      to_phase: "VERIFY",
      override_reason: "fixture bootstrap for seedVerificationPipeline",
    }));
    context = readContext();
  }
  if (context && context.schema_version === 2 && context.current_attempt_id && context.snapshot_hash) {
    const v2Results = results.map((result) => ({
      ...result,
      confidence: result.confidence || "high",
      confidence_reasons: Array.isArray(result.confidence_reasons)
        ? result.confidence_reasons
        : ["fresh_replay_passed"],
      state_sensitive: result.state_sensitive === true,
      artifact_hashes: result.artifact_hashes || {},
    }));
    for (const round of ["brutalist", "balanced"]) {
      writeVerificationRound({
        target_domain: domain,
        round,
        notes: null,
        verification_attempt_id: context.current_attempt_id,
        verification_snapshot_hash: context.snapshot_hash,
        round_profile: round,
        results: v2Results,
      });
    }
    const adjudication = JSON.parse(buildVerificationAdjudication({ target_domain: domain }));
    writeVerificationRound({
      target_domain: domain,
      round: "final",
      notes: null,
      verification_attempt_id: context.current_attempt_id,
      verification_snapshot_hash: context.snapshot_hash,
      round_profile: "final",
      adjudication_plan_hash: adjudication.adjudication_plan_hash,
      results: v2Results,
    });
    // Restore the test's pre-bootstrap state, grafting on the v2 attempt fields.
    if (originalState) {
      const verifyState = JSON.parse(fs.readFileSync(statePath(domain), "utf8"));
      const restored = {
        ...originalState,
        verification_schema_version: verifyState.verification_schema_version,
        verification_attempt_id: verifyState.verification_attempt_id,
        verification_snapshot_hash: verifyState.verification_snapshot_hash,
        verification_entered_at: verifyState.verification_entered_at,
      };
      writeFileAtomic(statePath(domain), `${JSON.stringify(restored, null, 2)}\n`);
    }
    return;
  }
  if (context && context.schema_version === 2) {
    throw new Error(
      `seedVerificationPipeline: v2 bootstrap for ${domain} did not produce a current attempt; ` +
      "verification-input-snapshot.json is missing or stale",
    );
  }
  for (const round of ["brutalist", "balanced", "final"]) {
    writeVerificationRound({ target_domain: domain, round, notes: null, results });
  }
}

function evidencePack(findingId = "F-1", overrides = {}) {
  return {
    finding_id: findingId,
    sample_type: "cross-account replay",
    sample_count: 1,
    aggregate_counts: { affected_objects_sampled: 1 },
    representative_samples: [{
      request_ref: "http-audit:1",
      endpoint: "/api/export",
      auth_profile: "attacker",
      status: 200,
      observed_fields: ["account_id", "email"],
      redacted_object_id: "acct_...002",
    }],
    sensitive_clusters: ["profile metadata"],
    replay_summary: "Fresh replay returned another account's private metadata.",
    redaction_notes: "Object IDs and personal values redacted; auth material omitted.",
    report_snippet: "An attacker can retrieve another account's private metadata by changing the account ID.",
    ...overrides,
  };
}

function v2VerificationResult(findingId = "F-1", overrides = {}) {
  return {
    finding_id: findingId,
    disposition: "confirmed",
    severity: "high",
    reportable: true,
    reasoning: "Fresh replay confirmed the finding.",
    confidence: "high",
    confidence_reasons: ["fresh_replay_passed"],
    state_sensitive: false,
    artifact_hashes: {},
    ...overrides,
  };
}

function enterVerifyV2(domain) {
  seedSessionState(domain, { phase: "CHAIN" });
  seedFinding(domain);
  return JSON.parse(transitionPhase({ target_domain: domain, to_phase: "VERIFY" }));
}

function replayContextFromVerificationContext(context, overrides = {}) {
  return {
    purpose: "verification_replay",
    verification_attempt_id: context.current_attempt_id,
    verification_snapshot_hash: context.snapshot_hash,
    round: "brutalist",
    finding_id: "F-1",
    ...overrides,
  };
}

function replayLeaseFileFor(domain, context, capabilityPack = "web") {
  const key = `${domain}:${context.verification_attempt_id}:${capabilityPack}`;
  return path.join(
    verificationReplayLeaseDir(domain),
    `${crypto.createHash("sha256").update(key).digest("hex")}.json`,
  );
}

function flushMicrotasks() {
  return new Promise((resolve) => setImmediate(resolve));
}

function holdingHandler(leasePath) {
  let entered = false;
  let snapshot = null;
  let releaseFn;
  const deferred = new Promise((resolve) => { releaseFn = resolve; });
  return {
    handler: async () => {
      entered = true;
      try {
        snapshot = JSON.parse(fs.readFileSync(leasePath, "utf8"));
      } catch (err) {
        snapshot = { error: err.message || String(err) };
      }
      await deferred;
    },
    entered: () => entered,
    leaseSnapshot: () => snapshot,
    release: () => releaseFn(),
  };
}

function assertCompleteReplayLeaseSnapshot(snapshot, expected) {
  assert.ok(snapshot);
  assert.equal(snapshot.error, undefined);
  assert.equal(snapshot.lease_id, expected.lease_id);
  assert.equal(snapshot.target_domain, expected.target_domain);
  assert.equal(snapshot.tool, expected.tool);
  assert.equal(snapshot.capability_pack, expected.capability_pack);
  assert.equal(snapshot.lease_scope, expected.lease_scope);
  assert.equal(snapshot.replay_purpose, expected.replay_purpose);
  assert.equal(snapshot.verification_attempt_id, expected.verification_attempt_id);
  assert.equal(snapshot.verification_snapshot_hash, expected.verification_snapshot_hash);
  assert.equal(snapshot.round, expected.round);
  assert.equal(snapshot.finding_id, expected.finding_id);
  assert.ok(snapshot.acquired_at);
  assert.ok(snapshot.expires_at);
  assert.equal(snapshot.pid, process.pid);
}

async function withMockSafeFetch(routes, fn, { dnsRecords = {} } = {}) {
  const originalLookup = dns.lookup;
  const originalHttpRequest = http.request;
  const originalHttpsRequest = https.request;
  const requestedUrls = [];

  dns.lookup = (hostname, options, callback) => {
    const cb = typeof options === "function" ? options : callback;
    const records = dnsRecords[hostname] || [{ address: "93.184.216.34", family: 4 }];
    if (Array.isArray(records)) {
      cb(null, records);
    } else {
      cb(null, [records]);
    }
  };

  const makeRequest = (requestOptions, callback) => {
    const protocol = requestOptions.protocol || "https:";
    const host = requestOptions.hostname;
    const port = requestOptions.port ? `:${requestOptions.port}` : "";
    const requestPath = requestOptions.path || "/";
    const url = `${protocol}//${host}${port}${requestPath}`;
    requestedUrls.push(url);

    const req = new EventEmitter();
    req.write = () => {};
    req.setTimeout = () => req;
    req.destroy = (error) => {
      if (error) process.nextTick(() => req.emit("error", error));
    };
    req.end = () => {
      process.nextTick(() => {
        if (typeof requestOptions.lookup === "function") {
          let lookupFailed = null;
          requestOptions.lookup(host, { all: true }, (error, addresses) => {
            if (error) {
              lookupFailed = error;
              return;
            }
            if (!Array.isArray(addresses) || !addresses[0] || !addresses[0].address) {
              lookupFailed = new Error("mock lookup all mode did not return address records");
            }
          });
          if (lookupFailed) {
            req.emit("error", lookupFailed);
            return;
          }
        }

        const route = typeof routes === "function" ? routes(url, requestOptions) : routes[url];
        if (!route) {
          req.emit("error", new Error(`No mock route for ${url}`));
          return;
        }
        if (route.error) {
          req.emit("error", route.error);
          return;
        }

        const body = Buffer.isBuffer(route.body)
          ? route.body
          : Buffer.from(route.body == null ? "" : String(route.body));
        const res = Readable.from([body]);
        res.statusCode = route.status || 200;
        res.statusMessage = route.statusText || "OK";
        res.headers = route.headers || { "content-type": "text/plain" };
        callback(res);
      });
    };
    return req;
  };

  http.request = makeRequest;
  https.request = makeRequest;

  try {
    return await fn(requestedUrls);
  } finally {
    dns.lookup = originalLookup;
    http.request = originalHttpRequest;
    https.request = originalHttpsRequest;
  }
}

async function withMockSmartContractRpcLookup(dnsRecords, fn) {
  const {
    setSmartContractRpcLookupForTesting,
  } = require("../mcp/lib/sc-egress-policy.js");
  setSmartContractRpcLookupForTesting((hostname, options, callback) => {
    const cb = typeof options === "function" ? options : callback;
    const records = dnsRecords[hostname] || [{ address: "93.184.216.34", family: 4 }];
    cb(null, Array.isArray(records) ? records : [records]);
  });
  try {
    return await fn();
  } finally {
    setSmartContractRpcLookupForTesting(null);
  }
}

async function withMockSmartContractHttpRequest(handler, fn) {
  const {
    setSmartContractHttpRequestForTesting,
  } = require("../mcp/lib/sc-http-client.js");
  setSmartContractHttpRequestForTesting(handler);
  try {
    return await fn();
  } finally {
    setSmartContractHttpRequestForTesting(null);
  }
}

function runEvaluatorSubagentStop(payload, { home, env = {} }) {
  return spawnSync(process.execPath, [path.join(__dirname, "..", ".claude", "hooks", "agent-run-stop.js")], {
    input: JSON.stringify(payload),
    encoding: "utf8",
    env: { ...process.env, HOME: home, CLAUDE_PROJECT_DIR: path.join(__dirname, ".."), ...env },
  });
}

test("mcp server public exports remain stable", () => {
  assert.deepEqual(Object.keys(serverModule).sort(), [
    "TOOLS",
    "TOOL_MANIFEST",
    "executeTool",
    "startServer",
  ]);
});

test("MCP tool registry and dispatch cases stay in sync", async () => {
  // Cycle P.1: TOOLS publishes only primary names. TOOL_REGISTRY carries both
  // primaries and bounty_* deprecation aliases for handler routing; aliases
  // are registry-only entries (alias_of set) that share their primary's
  // metadata. EXPECTED_TOOL_NAMES enumerates the primary surface.
  const toolNames = TOOLS.map((tool) => tool.name);
  const primaryRegistryNames = TOOL_REGISTRY
    .filter((tool) => !tool.alias_of)
    .map((tool) => tool.name);
  assert.deepEqual(toolNames, EXPECTED_TOOL_NAMES);
  assert.deepEqual(primaryRegistryNames, EXPECTED_TOOL_NAMES);
  assert.deepEqual(TOOL_MODULES.map((tool) => defineTool(tool).name), EXPECTED_TOOL_NAMES);
  assert.deepEqual([...toolNames].sort(), [...new Set(toolNames)].sort(), "tool names must be unique");
  assert.ok(toolNames.every((name) => name.startsWith("bounty_") || name.startsWith("bob_")));
  assert.ok(!toolNames.includes("bob_auth_manual"));
  assert.ok(!toolNames.includes("bob_read_handoff"));
  assert.equal(
    TOOLS.find((tool) => tool.name === "bob_static_scan").inputSchema.properties.artifact_id.pattern,
    "^SA-[1-9][0-9]*$",
  );

  // Every primary that declares aliases must have a corresponding registry
  // entry for each alias. Aliases must point back to a registered primary.
  // Aliases may be plain strings or descriptor objects with .name; both
  // shapes are materialized by buildToolRegistry into top-level alias
  // entries with tool.alias_of pointing at the primary.
  const allRegistryNames = new Set(TOOL_REGISTRY.map((tool) => tool.name));
  for (const tool of TOOL_REGISTRY) {
    if (tool.alias_of) {
      assert.ok(allRegistryNames.has(tool.alias_of), `alias ${tool.name} points to unknown primary ${tool.alias_of}`);
    } else if (Array.isArray(tool.aliases)) {
      for (const alias of tool.aliases) {
        const aliasName = typeof alias === "string" ? alias : alias.name;
        assert.ok(allRegistryNames.has(aliasName), `${tool.name} declares missing alias ${aliasName}`);
      }
    }
  }

  // Dispatch resolves both primary and alias names so existing clients that
  // still call bounty_* can route through the same handler.
  const dispatchNames = Object.keys(TOOL_HANDLERS);
  const dispatchPrimaryNames = dispatchNames.filter((name) => {
    const tool = TOOL_REGISTRY.find((entry) => entry.name === name);
    return tool && !tool.alias_of;
  });
  assert.deepEqual(dispatchPrimaryNames, toolNames);
  assert.deepEqual(Object.keys(TOOL_MANIFEST), toolNames);
  for (const tool of TOOL_REGISTRY) {
    assert.equal(TOOL_HANDLERS[tool.name], tool.handler);
    if (!tool.alias_of) {
      assert.equal(TOOLS.find((item) => item.name === tool.name).inputSchema, tool.inputSchema);
    }
  }
  await withTempHome(async () => {
    assert.deepEqual(await executeTool("__unknown_tool__", {}), {
      ok: false,
      error: { code: "UNKNOWN_TOOL", message: "Unknown tool: __unknown_tool__" },
      meta: { tool: "__unknown_tool__", version: 1 },
    });
  });
});

test("MCP tool manifest exposes required policy metadata for every tool", () => {
  for (const tool of TOOLS) {
    const metadata = TOOL_MANIFEST[tool.name];
    assert.ok(metadata, `${tool.name} missing manifest metadata`);
    assert.ok(Array.isArray(metadata.role_bundles) && metadata.role_bundles.length > 0);
    assert.equal(Object.isFrozen(metadata.role_bundles), true, `${tool.name} role_bundles should be frozen`);
    assert.equal(typeof metadata.mutating, "boolean");
    assert.equal(typeof metadata.global_preapproval, "boolean");
    assert.equal(typeof metadata.network_access, "boolean");
    assert.equal(typeof metadata.browser_access, "boolean");
    assert.equal(typeof metadata.scope_required, "boolean");
    assert.equal(typeof metadata.sensitive_output, "boolean");
    assert.ok(Array.isArray(metadata.session_artifacts_written));
    assert.equal(
      Object.isFrozen(metadata.session_artifacts_written),
      true,
      `${tool.name} session_artifacts_written should be frozen`,
    );
    assert.equal(Object.prototype.hasOwnProperty.call(metadata, REMOVED_HOOK_AUTHORITY_FIELD), false);
    assert.ok(metadata.capability_id === null || typeof metadata.capability_id === "string");
    assert.ok(Array.isArray(metadata.scope_url_fields));
    assert.equal(Object.isFrozen(metadata.scope_url_fields), true, `${tool.name} scope_url_fields should be frozen`);
    assert.equal(Object.isFrozen(tool.inputSchema), true, `${tool.name} inputSchema should be frozen`);
  }
  const httpScanSchema = TOOLS.find((tool) => tool.name === "bob_http_scan").inputSchema;
  assert.equal(Object.isFrozen(httpScanSchema.properties), true);
  assert.equal(Object.isFrozen(httpScanSchema.required), true);
});

test("MCP tool registry exposes capability metadata for metric and eval tools", () => {
  const capabilityMap = capabilityToolMapFromRegistry();
  assert.equal(TOOL_MANIFEST.bob_http_scan.capability_id, null);
  assert.equal(TOOL_MANIFEST.bob_ingest_schema_doc.capability_id, "C2_doc_vs_behavior");
  assert.equal(Object.isFrozen(capabilityMap), true);
  for (const tools of Object.values(capabilityMap)) {
    assert.equal(Object.isFrozen(tools), true);
  }
  assert.deepEqual(capabilityMap, {
    C2_doc_vs_behavior: [
      "bob_ingest_schema_doc",
      "bob_query_schema_contracts",
      "bob_run_doc_delta",
      "bob_read_doc_delta_results",
    ],
    C4_multi_account_differential: [
      "bob_run_auth_differential",
      "bob_read_auth_differential_results",
    ],
    I7_chain_state_tree: [
      "bob_append_chain_node",
      "bob_query_chain_tree",
      "bob_chain_frontier",
      "bob_chain_ancestry",
    ],
    X2_verification_attempt_diff: [
      "bob_diff_verification_attempts",
    ],
    I1_surface_graph: [
      "bob_build_surface_graph",
      "bob_query_surface_graph",
    ],
    // Plane Y Cycle Y.2 — capability friction + protocol drift voluntary
    // emission tools plus the orchestrator-facing runtime drift telemetry
    // entry. All three share the Y_self_reporting capability_id so operators
    // can grep telemetry by source.
    Y_self_reporting: [
      "bob_compose_report",
      "bob_amend_report",
      "bob_write_chain_rollup",
      "bob_set_friction_scanners",
      "bob_log_capability_friction",
      "bob_log_protocol_drift",
      "bob_emit_runtime_drift",
      "bob_scan_transcript_for_friction",
    ],
  });
});

test("bob_read_capability_playbook reads playbooks and rejects invalid capability IDs", async () => {
  const valid = await executeTool("bob_read_capability_playbook", {
    capability_id: "C2_doc_vs_behavior",
  });
  assert.equal(valid.ok, true);
  assert.equal(valid.data.capability_id, "C2_doc_vs_behavior");
  assert.equal(valid.data.path, path.join("prompts", "playbooks", "C2_doc_vs_behavior.md"));
  assert.match(valid.data.playbook, /Doc-vs-Behavior Differential/);
  assert.match(valid.data.playbook, /schema_slice/);

  for (const capability_id of ["", " C2_doc_vs_behavior", "-bad", "bad space", "a".repeat(129), null, 42]) {
    const invalid = await executeTool("bob_read_capability_playbook", { capability_id });
    assert.equal(invalid.ok, false);
    assert.equal(invalid.error.code, "INVALID_ARGUMENTS");
  }
});

test("MCP per-tool modules preserve representative tool behavior", () => {
  const byName = new Map(TOOLS.map((tool) => [tool.name, tool]));
  assert.equal(byName.get("bob_read_http_audit").inputSchema.required[0], "target_domain");
  assert.equal(byName.get("bob_start_next_wave").inputSchema.additionalProperties, false);
  assert.equal(byName.get("bob_start_next_wave").inputSchema.properties.target_domain.minLength, 1);
  assert.equal(byName.get("bob_start_next_wave").inputSchema.properties.dry_run.type, "boolean");
  assert.equal(byName.get("bob_start_wave").inputSchema.properties.assignments.type, "array");
  assert.deepEqual(TOOL_MANIFEST.bob_route_surfaces.role_bundles, ["orchestrator", "router"]);
  assert.equal(TOOL_MANIFEST.bob_route_surfaces.mutating, true);
  assert.equal(TOOL_MANIFEST.bob_route_surfaces.global_preapproval, false);
  assert.equal(TOOL_MANIFEST.bob_route_surfaces.network_access, false);
  assert.equal(TOOL_MANIFEST.bob_route_surfaces.browser_access, false);
  assert.equal(TOOL_MANIFEST.bob_route_surfaces.sensitive_output, false);
  assert.deepEqual(TOOL_MANIFEST.bob_route_surfaces.session_artifacts_written, ["surface-routes.json"]);
  assert.equal(byName.get("bob_http_scan").inputSchema.properties.url.type, "string");
  assert.equal(byName.get("bob_http_scan").inputSchema.properties.egress_profile.type, "string");
  assert.deepEqual(byName.get("bob_http_scan").inputSchema.required, ["method", "url", "target_domain"]);
  assert.equal(TOOL_MANIFEST.bob_read_http_audit.mutating, false);
  assert.equal(byName.get("bob_write_chain_attempt").inputSchema.properties.outcome.enum.includes("inconclusive"), true);
  assert.deepEqual(TOOL_MANIFEST.bob_write_chain_attempt.role_bundles, ["chain"]);
  assert.deepEqual(TOOL_MANIFEST.bob_read_chain_attempts.role_bundles, ["chain", "verifier", "grader", "reporter", "orchestrator"]);
  assert.equal(byName.get("bob_write_evidence_packs").inputSchema.properties.packs.items.properties.finding_id.pattern, "^F-[1-9][0-9]*$");
  assert.deepEqual(TOOL_MANIFEST.bob_write_evidence_packs.role_bundles, ["evidence"]);
  assert.deepEqual(TOOL_MANIFEST.bob_write_evidence_packs.session_artifacts_written, ["evidence-packs.json", "evidence-packs.md", "verification-manifest.json"]);
  assert.deepEqual(TOOL_MANIFEST.bob_read_evidence_packs.role_bundles, ["evidence", "grader", "reporter", "orchestrator"]);
  // bob_advance_session replaces the legacy bounty_transition_phase tool;
  // the registry alias is exercised by the dispatch tests below.
  assert.deepEqual(TOOL_MANIFEST.bob_advance_session.session_artifacts_written, [
    "session-nucleus.json",
    "session-events.jsonl",
  ]);
  assert.deepEqual(TOOL_MANIFEST.bob_write_verification_round.session_artifacts_written, ["brutalist.json", "balanced.json", "verified-final.json", "verification-manifest.json"]);
  assert.deepEqual(TOOL_MANIFEST.bob_build_verification_adjudication.role_bundles, ["orchestrator"]);
  assert.equal(TOOL_MANIFEST.bob_build_verification_adjudication.mutating, true);
  assert.equal(TOOL_MANIFEST.bob_build_verification_adjudication.global_preapproval, false);
  assert.deepEqual(TOOL_MANIFEST.bob_build_verification_adjudication.session_artifacts_written, ["verification-adjudication.json", "verification-manifest.json"]);
  assert.equal(TOOL_MANIFEST.bob_start_next_wave.mutating, true);
  assert.equal(TOOL_MANIFEST.bob_start_next_wave.global_preapproval, false);
  assert.deepEqual(TOOL_MANIFEST.bob_start_next_wave.session_artifacts_written, [
    "surface-routes.json",
    "wave-N-assignments.json",
    "state.json",
    "surface-leads.json",
    "frontier-events.jsonl",
    "surface-index.json",
    "task-queue.json",
    "task-graph.json",
  ]);
  assert.equal(TOOL_MANIFEST.bob_start_wave.mutating, true);
  assert.equal(TOOL_MANIFEST.bob_start_wave.global_preapproval, false);
  assert.deepEqual(TOOL_MANIFEST.bob_start_wave.session_artifacts_written, [
    "surface-routes.json",
    "wave-N-assignments.json",
    "state.json",
  ]);
  assert.equal(TOOL_MANIFEST.bob_http_scan.network_access, true);
  assert.equal(TOOL_MANIFEST.bob_http_scan.global_preapproval, true);
  assert.equal(TOOL_MANIFEST.bob_http_scan.scope_required, true);
  assert.deepEqual(TOOL_MANIFEST.bob_http_scan.scope_url_fields, []);
  assert.deepEqual(TOOL_MANIFEST.bob_run_doc_delta.scope_url_fields, ["base_url"]);
  assert.deepEqual(TOOL_MANIFEST.bob_run_auth_differential.scope_url_fields, ["base_url"]);
  assert.deepEqual(TOOL_MANIFEST.bob_signup_detect.scope_url_fields, ["target_url"]);
  assert.deepEqual(TOOL_MANIFEST.bob_auto_signup.scope_url_fields, ["signup_url"]);
  assert.equal(TOOL_MANIFEST.bob_read_tool_telemetry.mutating, false);
  assert.equal(TOOL_MANIFEST.bob_read_tool_telemetry.global_preapproval, false);
  assert.deepEqual(TOOL_MANIFEST.bob_read_tool_telemetry.role_bundles, ["orchestrator"]);
  assert.equal(TOOL_MANIFEST.bob_read_pipeline_analytics.mutating, false);
  assert.equal(TOOL_MANIFEST.bob_read_pipeline_analytics.global_preapproval, false);
  assert.deepEqual(TOOL_MANIFEST.bob_read_pipeline_analytics.role_bundles, ["orchestrator"]);
  assert.equal(TOOL_MANIFEST.bob_finalize_agent_run.mutating, true);
  assert.equal(TOOL_MANIFEST.bob_finalize_agent_run.global_preapproval, true);
  assert.deepEqual(TOOL_MANIFEST.bob_finalize_agent_run.role_bundles, ["evaluator-shared"]);
  assert.deepEqual(TOOL_MANIFEST.bob_record_surface_leads.role_bundles, ["evaluator-web", "orchestrator"]);
  assert.equal(TOOL_MANIFEST.bob_record_surface_leads.mutating, true);
  assert.equal(TOOL_MANIFEST.bob_record_surface_leads.global_preapproval, true);
  assert.equal(TOOL_MANIFEST.bob_record_surface_leads.network_access, false);
  assert.equal(TOOL_MANIFEST.bob_record_surface_leads.browser_access, false);
  assert.equal(TOOL_MANIFEST.bob_record_surface_leads.scope_required, false);
  assert.equal(TOOL_MANIFEST.bob_record_surface_leads.sensitive_output, false);
  assert.deepEqual(TOOL_MANIFEST.bob_record_surface_leads.session_artifacts_written, ["surface-leads.json"]);
  assert.deepEqual(TOOL_MANIFEST.bob_read_surface_leads.role_bundles, ["evaluator-web", "orchestrator"]);
  assert.equal(TOOL_MANIFEST.bob_read_surface_leads.mutating, false);
  assert.equal(TOOL_MANIFEST.bob_read_surface_leads.global_preapproval, true);
  assert.equal(TOOL_MANIFEST.bob_read_surface_leads.network_access, false);
  assert.equal(TOOL_MANIFEST.bob_read_surface_leads.browser_access, false);
  assert.equal(TOOL_MANIFEST.bob_read_surface_leads.scope_required, false);
  assert.equal(TOOL_MANIFEST.bob_read_surface_leads.sensitive_output, false);
  assert.deepEqual(TOOL_MANIFEST.bob_read_surface_leads.session_artifacts_written, []);
  assert.deepEqual(TOOL_MANIFEST.bob_promote_surface_leads.role_bundles, ["orchestrator"]);
  assert.equal(TOOL_MANIFEST.bob_promote_surface_leads.mutating, true);
  assert.equal(TOOL_MANIFEST.bob_promote_surface_leads.global_preapproval, false);
  assert.equal(TOOL_MANIFEST.bob_promote_surface_leads.network_access, false);
  assert.equal(TOOL_MANIFEST.bob_promote_surface_leads.browser_access, false);
  assert.equal(TOOL_MANIFEST.bob_promote_surface_leads.scope_required, false);
  assert.equal(TOOL_MANIFEST.bob_promote_surface_leads.sensitive_output, false);
  assert.deepEqual(TOOL_MANIFEST.bob_promote_surface_leads.session_artifacts_written, [
    "surface-leads.json",
    "frontier-events.jsonl",
    "surface-index.json",
    "task-queue.json",
    "task-graph.json",
  ]);
  assert.deepEqual(TOOL_MANIFEST.bob_get_context_budget.role_bundles, ["evaluator-shared", "orchestrator"]);
  assert.equal(TOOL_MANIFEST.bob_get_context_budget.mutating, false);
  assert.equal(TOOL_MANIFEST.bob_get_context_budget.network_access, false);
  assert.equal(TOOL_MANIFEST.bob_get_context_budget.browser_access, false);
  assert.equal(TOOL_MANIFEST.bob_get_context_budget.scope_required, false);
  assert.deepEqual(TOOL_MANIFEST.bob_get_context_budget.session_artifacts_written, []);
  assert.deepEqual(TOOL_MANIFEST.bob_select_technique_packs.role_bundles, ["evaluator-web", "orchestrator"]);
  assert.equal(TOOL_MANIFEST.bob_select_technique_packs.mutating, false);
  assert.deepEqual(TOOL_MANIFEST.bob_read_technique_pack.role_bundles, ["evaluator-web", "orchestrator"]);
  assert.equal(TOOL_MANIFEST.bob_read_technique_pack.mutating, true);
  assert.equal(byName.get("bob_read_technique_pack").inputSchema.properties.mode.enum.includes("full"), true);
  assert.deepEqual(TOOL_MANIFEST.bob_read_technique_pack.session_artifacts_written, ["technique-pack-reads.jsonl"]);
  assert.deepEqual(TOOL_MANIFEST.bob_log_technique_attempt.role_bundles, ["evaluator-web", "orchestrator"]);
  assert.equal(TOOL_MANIFEST.bob_log_technique_attempt.mutating, true);
  assert.equal(TOOL_MANIFEST.bob_log_technique_attempt.network_access, false);
  assert.equal(TOOL_MANIFEST.bob_log_technique_attempt.browser_access, false);
  assert.equal(TOOL_MANIFEST.bob_log_technique_attempt.scope_required, false);
  assert.equal(TOOL_MANIFEST.bob_log_technique_attempt.sensitive_output, false);
  assert.deepEqual(TOOL_MANIFEST.bob_log_technique_attempt.session_artifacts_written, ["technique-attempts.jsonl"]);
  assert.equal(TOOL_MANIFEST.bob_read_session_summary.mutating, false);
  assert.equal(TOOL_MANIFEST.bob_read_session_summary.global_preapproval, true);
  assert.deepEqual(TOOL_MANIFEST.bob_read_session_summary.role_bundles, ["orchestrator", "reporter"]);
  assert.equal(TOOL_MANIFEST.bob_set_operator_note.mutating, true);
  assert.equal(TOOL_MANIFEST.bob_set_operator_note.global_preapproval, false);
  assert.deepEqual(TOOL_MANIFEST.bob_set_operator_note.role_bundles, ["orchestrator"]);
  assert.equal(TOOL_MANIFEST.bob_clear_operator_note.mutating, true);
  assert.equal(TOOL_MANIFEST.bob_clear_operator_note.global_preapproval, false);
  assert.deepEqual(TOOL_MANIFEST.bob_clear_operator_note.role_bundles, ["orchestrator"]);
});

test("MCP tool registry validation rejects incomplete or inconsistent entries", () => {
  const completeModule = {
    name: "bob_test_tool",
    description: "Test tool.",
    inputSchema: { type: "object", properties: {} },
    handler: () => ({}),
    role_bundles: ["evaluator-shared"],
    mutating: false,
    global_preapproval: true,
    network_access: false,
    browser_access: false,
    scope_required: false,
    sensitive_output: false,
    session_artifacts_written: [],
  };

  assert.equal(
    buildToolRegistry({ toolModules: [completeModule] })[0].capability_id,
    null,
  );
  assert.equal(
    buildToolRegistry({ toolModules: [{ ...completeModule, capability_id: "C2_doc_vs_behavior" }] })[0].capability_id,
    "C2_doc_vs_behavior",
  );
  assert.throws(
    () => buildToolRegistry({ toolModules: [{ ...completeModule, [REMOVED_HOOK_AUTHORITY_FIELD]: false }] }),
    /removed hook authority metadata/,
  );
  assert.deepEqual(
    buildToolRegistry({
      toolModules: [{
        ...completeModule,
        inputSchema: { type: "object", properties: { target_domain: { type: "string" }, base_url: { type: "string" } } },
        scope_required: true,
        scope_url_fields: ["base_url"],
      }],
    })[0].scope_url_fields,
    ["base_url"],
  );

  assert.throws(
    () => buildToolRegistry({
      toolModules: [completeModule, { ...completeModule }],
    }),
    /Duplicate tool name/,
  );

  assert.throws(
    () => buildToolRegistry({
      toolModules: [{ ...completeModule, handler: undefined }],
    }),
    /has no handler/,
  );

  const missingGlobalPreapproval = { ...completeModule };
  delete missingGlobalPreapproval.global_preapproval;
  assert.throws(
    () => buildToolRegistry({
      toolModules: [missingGlobalPreapproval],
    }),
    /missing global_preapproval/,
  );

  assert.throws(
    () => buildToolRegistry({
      toolModules: [{ ...completeModule, global_preapproval: "yes" }],
    }),
    /invalid global_preapproval/,
  );

  assert.throws(
    () => buildToolRegistry({
      toolModules: [{ ...completeModule, role_bundles: ["mystery"] }],
    }),
    /unknown role bundle mystery/,
  );

  assert.throws(
    () => buildToolRegistry({
      toolModules: [{ ...completeModule, scope_url_fields: ["base_url"] }],
    }),
    /unknown scope_url_fields item base_url/,
  );

  assert.throws(
    () => buildToolRegistry({
      toolModules: [{
        ...completeModule,
        inputSchema: { type: "object", properties: { base_url: { type: "string" } } },
        scope_url_fields: ["base_url"],
      }],
    }),
    /declares scope_url_fields without scope_required/,
  );

  for (const capability_id of ["", " C2_doc_vs_behavior", "-bad", "bad space", "a".repeat(129), null, 42]) {
    assert.throws(
      () => buildToolRegistry({
        toolModules: [{ ...completeModule, capability_id }],
      }),
      /invalid capability_id/,
    );
  }
});

test("MCP runtime no longer imports legacy split tool definition files", () => {
  const mcpRoot = path.join(__dirname, "..", "mcp");
  const forbiddenFiles = [
    path.join(mcpRoot, "lib", "tool-definitions.js"),
    path.join(mcpRoot, "lib", "tool-manifest.js"),
    path.join(mcpRoot, "lib", "tool-handlers.js"),
  ];
  for (const filePath of forbiddenFiles) {
    assert.equal(fs.existsSync(filePath), false, `${path.basename(filePath)} should be removed`);
  }

  const jsFiles = [];
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const entryPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(entryPath);
      } else if (entry.isFile() && entry.name.endsWith(".js")) {
        jsFiles.push(entryPath);
      }
    }
  };
  walk(mcpRoot);

  for (const filePath of jsFiles) {
    const content = fs.readFileSync(filePath, "utf8");
    assert.equal(content.includes("tool-definitions.js"), false, `${filePath} imports legacy definitions`);
    assert.equal(content.includes("tool-manifest.js"), false, `${filePath} imports legacy manifest`);
    assert.equal(content.includes("tool-handlers.js"), false, `${filePath} imports legacy handlers`);
  }
});

test("executeTool rejects unknown top-level arguments while allowing nested map-like fields", async () => {
  await withTempHome(async () => {
    const unknown = await executeTool("bob_http_scan", {
      method: "GET",
      url: "https://example.com/",
      target_domain: "example.com",
      surprise: true,
    });
    assert.equal(unknown.ok, false);
    assert.equal(unknown.error.code, "INVALID_ARGUMENTS");
    assert.match(unknown.error.message, /surprise is not allowed/);

    const init = await executeTool("bob_init_session", {
      target_domain: "example.com",
      target_url: "https://example.com",
    });
    assert.equal(init.ok, true);

    const traffic = await executeTool("bob_import_http_traffic", {
      target_domain: "example.com",
      source: "har",
      entries: [{
        request: {
          method: "GET",
          url: "https://example.com/api",
          headers: [{ name: "X-Test", value: "1", arbitrary_har_field: "kept" }],
        },
        response: { status: 200, nested_har_field: true },
      }],
    });
    assert.equal(traffic.ok, true);
    assert.equal(traffic.data.imported, 1);

    const auth = await executeTool("bob_auth_store", {
      target_domain: "example.com",
      profile_name: "attacker",
      headers: { "X-Custom": "ok" },
      cookies: { session: "abc" },
      local_storage: { access_token: "eyJabc" },
    });
    assert.equal(auth.ok, true);
    assert.equal(auth.data.success, true);
  });
});

test("executeTool returns standard envelopes and recursively validates schema arguments", async () => {
  await withTempHome(async () => {
    const unknown = await executeTool("__unknown_tool__", {});
    assert.deepEqual(unknown, {
      ok: false,
      error: { code: "UNKNOWN_TOOL", message: "Unknown tool: __unknown_tool__" },
      meta: { tool: "__unknown_tool__", version: 1 },
    });

    const missingTargetDomain = await executeTool("bob_http_scan", {
      method: "GET",
      url: "https://example.com/",
    });
    assert.equal(missingTargetDomain.ok, false);
    assert.equal(missingTargetDomain.error.code, "INVALID_ARGUMENTS");
    assert.match(missingTargetDomain.error.message, /target_domain is required/);

    const nested = await executeTool("bob_auth_store", {
      target_domain: "example.com",
      profile_name: "attacker",
      credentials: {
        email: "a@example.com",
        password: "secret",
        unexpected: true,
      },
    });
    assert.equal(nested.ok, false);
    assert.equal(nested.error.code, "INVALID_ARGUMENTS");
    assert.match(nested.error.message, /credentials\.unexpected is not allowed/);

    const badWave = await executeTool("bob_log_coverage", {
      target_domain: "example.com",
      wave: "1",
      agent: "a1",
      surface_id: "surface-a",
      entries: [],
    });
    assert.equal(badWave.ok, false);
    assert.equal(badWave.error.code, "INVALID_ARGUMENTS");
    assert.match(badWave.error.message, /wave must match pattern \^w\[1-9\]\[0-9\]\*\$/);

    const zeroWave = await executeTool("bob_log_coverage", {
      target_domain: "example.com",
      wave: "w0",
      agent: "a1",
      surface_id: "surface-a",
      entries: [],
    });
    assert.equal(zeroWave.ok, false);
    assert.equal(zeroWave.error.code, "INVALID_ARGUMENTS");
    assert.match(zeroWave.error.message, /wave must match pattern \^w\[1-9\]\[0-9\]\*\$/);

    const zeroAgent = await executeTool("bob_start_wave", {
      target_domain: "example.com",
      wave_number: 1,
      assignments: [{ agent: "a0", surface_id: "surface-a" }],
    });
    assert.equal(zeroAgent.ok, false);
    assert.equal(zeroAgent.error.code, "INVALID_ARGUMENTS");
    assert.match(zeroAgent.error.message, /assignments\[0\]\.agent must match pattern \^a\[1-9\]\[0-9\]\*\$/);

    const badEntries = await executeTool("bob_log_coverage", {
      target_domain: "example.com",
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      entries: "not-array",
    });
    assert.equal(badEntries.ok, false);
    assert.equal(badEntries.error.code, "INVALID_ARGUMENTS");
    assert.match(badEntries.error.message, /entries must be array/);

    seedSessionState("example.com");
    const traffic = await executeTool("bob_import_http_traffic", {
      target_domain: "example.com",
      source: "har",
      entries: [{
        request: {
          method: "GET",
          url: "https://example.com/api",
          headers: [{ name: "X-Test", value: "1", arbitrary_har_field: "kept" }],
        },
        response: { status: 200, nested_har_field: true },
      }],
    });
    assert.equal(traffic.ok, true);
    assert.equal(traffic.data.imported, 1);
  });
});

test("executeTool enforces target URL scope for direct and composite HTTP tools", async () => {
  await withTempHome(async () => {
    seedSessionState("example.com");
    await withMockSafeFetch({
      "https://api.example.com/ok": { status: 200, statusText: "OK", body: "ok" },
    }, async (requestedUrls) => {
      const allowed = await executeTool("bob_http_scan", {
        target_domain: "example.com",
        method: "GET",
        url: "https://api.example.com/ok",
        response_mode: "status_only",
      });
      assert.equal(allowed.ok, true);

      const directBlocked = await executeTool("bob_http_scan", {
        target_domain: "example.com",
        method: "GET",
        url: "https://api.other.test/secret",
        response_mode: "status_only",
      });
      assert.equal(directBlocked.ok, false);
      assert.equal(directBlocked.error.code, "SCOPE_BLOCKED");
      assert.match(directBlocked.error.message, /outside target_domain example\.com/);

      const invalidScopeRoot = await executeTool("bob_http_scan", {
        target_domain: "com",
        method: "GET",
        url: "https://example.com/secret",
        response_mode: "status_only",
      });
      assert.equal(invalidScopeRoot.ok, false);
      assert.equal(invalidScopeRoot.error.code, "INVALID_ARGUMENTS");
      assert.match(invalidScopeRoot.error.message, /registrable domain/);

      const internalScopeRoot = await executeTool("bob_http_scan", {
        target_domain: "127.0.0.1",
        method: "GET",
        url: "http://127.0.0.1/secret",
        response_mode: "status_only",
      });
      assert.equal(internalScopeRoot.ok, false);
      assert.equal(internalScopeRoot.error.code, "INVALID_ARGUMENTS");
      assert.match(internalScopeRoot.error.message, /public DNS domain/);

      const docDeltaBlocked = await executeTool("bob_run_doc_delta", {
        target_domain: "example.com",
        base_url: "https://docs.other.test",
      });
      assert.equal(docDeltaBlocked.ok, false);
      assert.equal(docDeltaBlocked.error.code, "SCOPE_BLOCKED");
      assert.match(docDeltaBlocked.error.message, /base_url is outside target scope/);

      const authDifferentialBlocked = await executeTool("bob_run_auth_differential", {
        target_domain: "example.com",
        base_url: "https://auth.other.test",
        endpoints: ["/api/me"],
        auth_profiles: ["attacker", "victim"],
      });
      assert.equal(authDifferentialBlocked.ok, false);
      assert.equal(authDifferentialBlocked.error.code, "SCOPE_BLOCKED");
      assert.match(authDifferentialBlocked.error.message, /base_url is outside target scope/);

      const signupBlocked = await executeTool("bob_signup_detect", {
        target_domain: "example.com",
        target_url: "https://signup.other.test",
      });
      assert.equal(signupBlocked.ok, false);
      assert.equal(signupBlocked.error.code, "SCOPE_BLOCKED");
      assert.match(signupBlocked.error.message, /target_url is outside target scope/);

      assert.deepEqual(requestedUrls, ["https://api.example.com/ok"]);
    });
  });
});

test("executeTool writes telemetry rows for success and dispatcher failure modes", async () => {
  await withTempHome(async () => {
    await withEnv({ BOUNTY_TELEMETRY: undefined, BOUNTY_TELEMETRY_DIR: undefined }, async () => {
      seedSessionState("example.com");
      const success = await executeTool("bob_list_auth_profiles", { target_domain: "example.com" });
      assert.equal(success.ok, true);

      const unknown = await executeTool("__unknown_tool__", {});
      assert.equal(unknown.error.code, "UNKNOWN_TOOL");

      const invalid = await executeTool("bob_log_coverage", {
        target_domain: "example.com",
        wave: "w1",
        agent: "a1",
        surface_id: "surface-a",
        entries: "not-array",
      });
      assert.equal(invalid.error.code, "INVALID_ARGUMENTS");

      const thrown = await executeTool("bob_read_session_state", { target_domain: "missing.example" });
      assert.equal(thrown.error.code, "STATE_CONFLICT");

      const blocked = await executeTool("bob_http_scan", {
        method: "GET",
        url: "http://127.0.0.1/",
        target_domain: "example.com",
        block_internal_hosts: true,
      });
      assert.equal(blocked.error.code, "SCOPE_BLOCKED");

      const rows = readJsonl(toolTelemetryPath());
      assert.equal(rows.length, 5);
      assert.equal(rows.every((row) => row.bob_version === PACKAGE_VERSION), true);

      assert.equal(rows[0].tool, "bob_list_auth_profiles");
      assert.equal(rows[0].ok, true);
      assert.equal(rows[0].error_code, null);
      assert.equal(rows[0].target_domain, "example.com");
      assert.equal(rows[0].registry.global_preapproval, true);
      assert.equal(rows[0].registry.mutating, false);
      assert.equal(typeof rows[0].elapsed_ms, "number");

      assert.equal(rows[1].tool, "__unknown_tool__");
      assert.equal(rows[1].ok, false);
      assert.equal(rows[1].error_code, "UNKNOWN_TOOL");
      assert.equal(rows[1].registry, null);
      assert.equal(rows[1].error_message, "Unknown tool");

      assert.equal(rows[2].tool, "bob_log_coverage");
      assert.equal(rows[2].error_code, "INVALID_ARGUMENTS");
      assert.equal(rows[2].wave, "w1");
      assert.equal(rows[2].agent, "a1");
      assert.equal(rows[2].surface_id, "surface-a");
      assert.match(rows[2].error_message, /entries must be array/);

      assert.equal(rows[3].tool, "bob_read_session_state");
      assert.equal(rows[3].error_code, "STATE_CONFLICT");
      assert.match(rows[3].error_message, /Session authority is missing/);

      assert.equal(rows[4].tool, "bob_http_scan");
      assert.equal(rows[4].error_code, "SCOPE_BLOCKED");
      assert.equal(rows[4].target_domain, "example.com");
      assert.equal(rows[4].registry.sensitive_output, true);
      assert.equal(Object.prototype.hasOwnProperty.call(rows[4], "error_message"), false);
    });
  });
});

test("tool telemetry can be disabled and writer failures never change envelopes", async () => {
  await withTempHome(async () => {
    seedSessionState("example.com");
    await withEnv({ BOUNTY_TELEMETRY: "0", BOUNTY_TELEMETRY_DIR: undefined }, async () => {
      const result = await executeTool("bob_list_auth_profiles", { target_domain: "example.com" });
      assert.equal(result.ok, true);
      assert.equal(fs.existsSync(toolTelemetryPath()), false);
    });
  });

  await withTempHome(async () => {
    seedSessionState("example.com");
    const blockingPath = path.join(os.tmpdir(), `hacker-bob-telemetry-block-${process.pid}-${Date.now()}`);
    fs.writeFileSync(blockingPath, "not a directory\n");
    try {
      await withEnv({ BOUNTY_TELEMETRY: undefined, BOUNTY_TELEMETRY_DIR: blockingPath }, async () => {
        const result = await executeTool("bob_list_auth_profiles", { target_domain: "example.com" });
        assert.equal(result.ok, true);
        assert.equal(result.data.version, 1);
        assert.equal(result.data.target_domain, "example.com");
        assert.deepEqual(result.data.profiles, []);
        assert.deepEqual(result.meta, { tool: "bob_list_auth_profiles", version: 1 });
      });
    } finally {
      fs.rmSync(blockingPath, { force: true });
    }
  });
});

test("central session authority blocks raw target and target_url drift before handlers", async () => {
  await withTempHome(async () => {
    const domain = "authority-drift.example.com";
    const init = await executeTool("bob_init_session", {
      target_domain: domain,
      target_url: `https://${domain}`,
    });
    assert.equal(init.ok, true);

    const rawTargetDrift = JSON.parse(fs.readFileSync(statePath(domain), "utf8"));
    rawTargetDrift.target = "other.example.com";
    fs.writeFileSync(statePath(domain), `${JSON.stringify(rawTargetDrift, null, 2)}\n`, "utf8");

    const targetResult = await executeTool("bob_read_session_state", { target_domain: domain });
    assert.equal(targetResult.ok, false);
    assert.equal(targetResult.error.code, "SCOPE_BLOCKED");
    assert.equal(targetResult.error.details.authority.authority_error_code, "raw_target_drift");
    assert.equal(targetResult.error.details.authority.authority_result, "blocked");

    rawTargetDrift.target = domain;
    rawTargetDrift.target_url = "https://outside.example.net";
    rawTargetDrift.egress_profile = "vpn-us";
    rawTargetDrift.egress_region = "us";
    rawTargetDrift.proxy_configured = true;
    rawTargetDrift.egress_profile_identity_hash = "authority-telemetry-poison";
    rawTargetDrift.egress_profile_identity_version = 1;
    fs.writeFileSync(statePath(domain), `${JSON.stringify(rawTargetDrift, null, 2)}\n`, "utf8");

    const urlResult = await executeTool("bob_read_session_state", { target_domain: domain });
    assert.equal(urlResult.ok, false);
    assert.equal(urlResult.error.code, "SCOPE_BLOCKED");
    assert.equal(urlResult.error.details.authority.authority_error_code, "target_url_drift");

    const telemetryRows = readJsonl(toolTelemetryPath())
      .filter((row) => row.tool === "bob_read_session_state");
    assert.equal(telemetryRows.length, 2);
    assert.deepEqual(
      telemetryRows.map((row) => row.authority.authority_error_code),
      ["raw_target_drift", "target_url_drift"],
    );
    assert.equal(JSON.stringify(telemetryRows).includes("outside.example.net"), false);
    assert.equal(JSON.stringify(telemetryRows).includes("authority-telemetry-poison"), false);

    const telemetrySummary = await executeTool("bob_read_tool_telemetry", { limit: 10 });
    assert.equal(telemetrySummary.ok, true);
    assert.equal(JSON.stringify(telemetrySummary).includes("authority-telemetry-poison"), false);
  });
});

test("central session authority backfills missing v1.3.4-shaped fields instead of fail-closing", async () => {
  await withTempHome(async () => {
    const domain = "v134-resume.example.com";
    fs.mkdirSync(sessionDir(domain), { recursive: true });
    // A v1.3.4 session predates checkpoint_mode, block_internal_hosts*, and
    // the egress identity / verification fields. The normalizer must backfill
    // safe defaults on read; the legacy-fail-closed list must NOT reject it.
    const legacyShape = {
      target: domain,
      target_url: `https://${domain}`,
      deep_mode: false,
      phase: "EVALUATE",
      evaluation_wave: 0,
      pending_wave: null,
      total_findings: 0,
      explored: [],
      terminally_blocked: [],
      prereq_registry_snapshots: [],
      blocked_prereq_history: [],
      terminal_block_clear_history: [],
      dead_ends: [],
      waf_blocked_endpoints: [],
      lead_surface_ids: [],
      scope_exclusions: [],
      hold_count: 0,
      auth_status: "pending",
      operator_note: null,
    };
    fs.writeFileSync(statePath(domain), `${JSON.stringify(legacyShape, null, 2)}\n`, "utf8");

    const result = await executeTool("bob_read_session_state", { target_domain: domain });
    assert.equal(result.ok, true, `expected v1.3.4 session to load; got ${JSON.stringify(result.error)}`);
    const state = result.data.state;
    assert.equal(state.target, domain);
    assert.equal(state.target_url, `https://${domain}`);
    // Backfilled defaults from normalizeSessionStateDocument
    assert.equal(state.egress_profile, "default");
    assert.equal(state.proxy_configured, false);
    assert.equal(state.verification_schema_version, null);
  });
});

test("central session authority shadow mode is bounded to missing read-only sessions", async () => {
  await withTempHome(async () => {
    const missing = await executeTool("bob_read_session_state", {
      target_domain: "missing-authority.example.com",
    });
    assert.equal(missing.ok, false);
    assert.equal(missing.error.code, "STATE_CONFLICT");
    assert.equal(missing.error.details.authority.authority_error_code, "no_session");
    assert.equal(missing.error.details.authority.authority_shadowed, false);
  });

  await withTempHome(async () => {
    await withEnv({ BOB_SESSION_AUTHORITY_MODE: "shadow" }, async () => {
      const readOnly = await executeTool("bob_read_session_state", {
        target_domain: "shadow-missing.example.com",
      });
      assert.equal(readOnly.ok, false);
      assert.equal(readOnly.error.code, "NOT_FOUND");
      assert.equal(readOnly.error.message.includes(process.env.HOME), false);
      assert.equal(readOnly.error.message.includes("bounty-agent-sessions"), false);
      assert.equal(readOnly.error.message.includes("hacker-bob-sessions"), false);

      const mutating = await executeTool("bob_log_coverage", {
        target_domain: "shadow-missing.example.com",
        wave: "w1",
        agent: "a1",
        surface_id: "surface-a",
        entries: [],
      });
      assert.equal(mutating.ok, false);
      assert.equal(mutating.error.code, "STATE_CONFLICT");
      assert.equal(mutating.error.details.authority.authority_shadowed, false);

      const rows = readJsonl(toolTelemetryPath());
      const readRow = rows.find((row) => row.tool === "bob_read_session_state");
      const writeRow = rows.find((row) => row.tool === "bob_log_coverage");
      assert.equal(readRow.authority.authority_result, "shadow_blocked");
      assert.equal(readRow.authority.authority_error_code, "no_session");
      assert.equal(readRow.authority.authority_shadowed, true);
      assert.equal(JSON.stringify(readRow).includes(process.env.HOME), false);
      assert.equal(JSON.stringify(readRow).includes("bounty-agent-sessions"), false);
      assert.equal(JSON.stringify(readRow).includes("hacker-bob-sessions"), false);
      assert.equal(writeRow.authority.authority_result, "blocked");
      assert.equal(writeRow.authority.authority_error_code, "no_session");
      assert.equal(writeRow.authority.authority_shadowed, false);
    });
  });
});

test("central session authority does not persist raw invalid target_domain telemetry", async () => {
  await withTempHome(async () => {
    const hostileTarget = "https://example.com/?access_token=secret";
    const result = await executeTool("bob_read_session_state", {
      target_domain: hostileTarget,
    });
    assert.equal(result.ok, false);
    assert.equal(result.error.details.authority.authority_error_code, "normalization_failed");
    assert.equal(result.error.details.authority.argument_target_domain, null);

    const rows = readJsonl(toolTelemetryPath());
    assert.equal(rows.length, 1);
    assert.equal(rows[0].target_domain, null);
    assert.equal(rows[0].authority.argument_target_domain, null);
    assert.equal(JSON.stringify(rows[0]).includes(hostileTarget), false);
    assert.equal(JSON.stringify(rows[0]).includes("secret"), false);
  });
});

test("central session authority records allowed bootstrap and initialized-session telemetry", async () => {
  await withTempHome(async () => {
    const init = await executeTool("bob_init_session", {
      target_domain: "Telemetry-Authority.Example.COM.",
      target_url: "https://telemetry-authority.example.com",
    });
    assert.equal(init.ok, true);
    assert.equal(init.data.state.target, "telemetry-authority.example.com");

    const read = await executeTool("bob_read_session_state", {
      target_domain: "telemetry-authority.example.com",
    });
    assert.equal(read.ok, true);

    const rows = readJsonl(toolTelemetryPath());
    const initRow = rows.find((row) => row.tool === "bob_init_session");
    const readRow = rows.find((row) => row.tool === "bob_read_session_state");
    assert.equal(initRow.authority.authority_class, "bootstrap_session");
    assert.equal(initRow.authority.authority_source, "bootstrap");
    assert.equal(initRow.authority.authority_result, "allowed");
    assert.equal(initRow.authority.authority_target_domain, "telemetry-authority.example.com");
    assert.equal(readRow.authority.authority_class, "initialized_session_read");
    assert.equal(readRow.authority.authority_source, "session_state");
    assert.equal(readRow.authority.authority_result, "allowed");
    assert.equal(readRow.authority.authority_session_present, true);
    assert.equal(readRow.authority.authority_match, true);
  });
});

test("tool telemetry rows do not store raw secret-bearing payloads", async () => {
  await withTempHome(async () => {
    await withEnv({ BOUNTY_TELEMETRY: undefined, BOUNTY_TELEMETRY_DIR: undefined }, async () => {
      seedSessionState("example.com");

      const authFailure = await executeTool("bob_auth_store", {
        target_domain: "example.com",
        profile_name: "attacker",
        credentials: {
          email: "a@example.com",
          password: "super-secret-password",
          unexpected: true,
        },
      });
      assert.equal(authFailure.error.code, "INVALID_ARGUMENTS");

      const authSuccess = await executeTool("bob_auth_store", {
        target_domain: "example.com",
        profile_name: "attacker",
        headers: { Authorization: "Bearer raw-auth-token" },
        cookies: { session: "raw-cookie-value" },
        local_storage: { access_token: "raw-local-storage-token" },
        credentials: {
          email: "a@example.com",
          password: "stored-secret-password",
        },
      });
      assert.equal(authSuccess.ok, true);

      const httpBlocked = await executeTool("bob_http_scan", {
        method: "POST",
        url: "http://127.0.0.1/?token=raw-query-token",
        target_domain: "example.com",
        headers: { Authorization: "Bearer request-header-token" },
        body: "request-body-secret",
        block_internal_hosts: true,
      });
      assert.equal(httpBlocked.error.code, "SCOPE_BLOCKED");

      const artifact = await executeTool("bob_import_static_artifact", {
        target_domain: "example.com",
        artifact_type: "evm_token_contract",
        content: "contract Secret { string constant password = 'static-artifact-secret'; }",
        label: "token",
      });
      assert.equal(artifact.ok, true);

      const telemetry = JSON.stringify(readJsonl(toolTelemetryPath()));
      for (const forbidden of [
        "super-secret-password",
        "raw-auth-token",
        "raw-cookie-value",
        "raw-local-storage-token",
        "stored-secret-password",
        "raw-query-token",
        "request-header-token",
        "request-body-secret",
        "static-artifact-secret",
      ]) {
        assert.equal(telemetry.includes(forbidden), false, `${forbidden} leaked into telemetry`);
      }

      const authRows = readJsonl(toolTelemetryPath())
        .filter((row) => row.tool === "bob_auth_store" && row.ok === false);
      assert.equal(authRows.length, 1);
      assert.equal(Object.prototype.hasOwnProperty.call(authRows[0], "error_message"), false);
    });
  });
});

test("tool telemetry reader summarizes at read time and skips malformed lines", () => {
  const telemetryRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-telemetry-"));
  const env = { ...process.env, BOUNTY_TELEMETRY: "1", BOUNTY_TELEMETRY_DIR: telemetryRoot };
  try {
    const base = {
      version: 1,
      bob_version: "1.2.1",
      ts: "2026-04-24T00:00:00.000Z",
      ok: true,
      error_code: null,
      target_domain: "example.com",
      wave: null,
      agent: null,
      surface_id: null,
      registry: null,
    };
    const allowedHttpAuthority = {
      authority_version: 1,
      authority_class: "scoped_http_network",
      authority_mode: "enforce",
      authority_source: "session_state",
      authority_result: "allowed",
      authority_error_code: "none",
      authority_block_reason: "none",
      authority_shadowed: false,
    };
    appendToolTelemetryEvent({
      ...base,
      tool: "bob_http_scan",
      elapsed_ms: 10,
      authority: allowedHttpAuthority,
    }, { env });
    appendToolTelemetryEvent({
      ...base,
      tool: "bob_http_scan",
      ok: false,
      elapsed_ms: 20,
      error_code: "SCOPE_BLOCKED",
      error_message: "blocked",
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      authority: {
        ...allowedHttpAuthority,
        authority_result: "blocked",
        authority_error_code: "scoped_url_drift",
        authority_block_reason: "scoped_url_drift",
      },
    }, { env });
    const egressTelemetryHash = "a".repeat(64);
    appendToolTelemetryEvent({
      ...base,
      tool: "bob_http_scan",
      elapsed_ms: 30,
      egress_profile: "operator-eu",
      egress_region: "EU",
      proxy_configured: true,
      egress_profile_identity_hash: egressTelemetryHash,
      egress_profile_identity_version: 1,
      authority: allowedHttpAuthority,
    }, { env });
    appendToolTelemetryEvent({
      ...base,
      tool: "bob_read_session_state",
      ok: false,
      elapsed_ms: 40,
      error_code: "NOT_FOUND",
      error_message: "Missing session state /tmp/bounty-agent-sessions/example.com/state.json https://example.com/?token=raw-secret-token",
      authority: {
        authority_version: 1,
        authority_class: "initialized_session_read",
        authority_mode: "enforce",
        authority_source: "session_state",
        authority_result: "blocked",
        authority_error_code: "no_session",
        authority_block_reason: "no_session",
        authority_shadowed: false,
      },
    }, { env });
    appendToolTelemetryEvent({
      ...base,
      tool: "bob_http_scan",
      bob_version: "1.2.2",
      target_domain: "other.example",
      elapsed_ms: 50,
      authority: {
        ...allowedHttpAuthority,
        authority_version: 2,
      },
    }, { env });
    appendToolTelemetryEvent({
      ...base,
      tool: "bob_read_session_state",
      ok: false,
      elapsed_ms: 60,
      target_domain: "https://example.com/?access_token=raw-target-secret",
      egress_profile: "https://user:pass@proxy.example",
      egress_region: "region?token=raw-region-secret",
      egress_profile_identity_hash: "not-a-hash-secret",
      error_code: "LEGACY",
      error_message: "legacy row",
    }, { env });
    appendToolTelemetryEvent({
      ...base,
      tool: "bob_auth_store",
      ok: false,
      elapsed_ms: 70,
      target_domain: "https://sensitive.example/?token=raw-sensitive-target",
      error_code: "LEGACY_SENSITIVE",
      error_message: "customer email exposed in response",
      registry: { sensitive_output: true },
    }, { env });
    appendToolTelemetryEvent({
      ...base,
      bob_version: "https://version.example/?token=raw-bob-version-secret",
      ts: "https://ts.example/?token=raw-ts-secret",
      tool: "https://tool.example/?token=raw-tool-secret",
      ok: false,
      elapsed_ms: 80,
      target_domain: "poison.example",
      wave: "w1?token=raw-wave-secret",
      agent: "a1?token=raw-agent-secret",
      surface_id: "https://surface.example/?token=raw-surface-secret",
      error_code: "ERR?token=raw-error-code-secret",
      error_message: "failed https://example.com/admin/reset",
      authority: {
        authority_version: "https://authority.example/?token=raw-authority-version-secret",
        authority_class: "https://authority.example/?token=raw-authority-class-secret",
        authority_mode: "enforce",
        authority_source: "session_state",
        authority_result: "blocked",
        authority_error_code: "https://authority.example/?token=raw-authority-error-secret",
        authority_block_reason: "/tmp/bounty-agent-sessions/raw-authority-reason-secret/state.json",
        authority_shadowed: false,
      },
    }, { env });
    fs.appendFileSync(toolTelemetryPath(env), "{not-json\n", "utf8");

    const summary = readToolTelemetry({ target_domain: "example.com", limit: 2 }, { env });
    assert.equal(summary.enabled, true);
    assert.equal(summary.telemetry_path, "[telemetry-dir]/tool-events.jsonl");
    assert.equal(summary.bob_version, PACKAGE_VERSION);
    assert.deepEqual(summary.observed_bob_versions, ["1.2.1"]);
    assert.equal(summary.total_events, 4);
    assert.equal(summary.malformed_lines, 1);
    assert.equal(summary.totals.calls, 4);
    assert.equal(summary.totals.successes, 2);
    assert.equal(summary.totals.failures, 2);
    assert.equal(summary.totals.success_rate, 0.5);
    assert.deepEqual(summary.totals.error_codes, {
      SCOPE_BLOCKED: 1,
      NOT_FOUND: 1,
    });
    assert.deepEqual(summary.authority, {
      total_events: 4,
      by_version: { 1: 4 },
      by_class: {
        scoped_http_network: 3,
        initialized_session_read: 1,
      },
      by_result: {
        allowed: 2,
        blocked: 2,
      },
      by_error_code: {
        none: 2,
        scoped_url_drift: 1,
        no_session: 1,
      },
    });
    assert.deepEqual(summary.totals.authority, summary.authority);
    assert.equal(JSON.stringify(summary).includes("raw-secret-token"), false);
    assert.equal(JSON.stringify(summary).includes("bounty-agent-sessions"), false);
    assert.equal(JSON.stringify(summary).includes("hacker-bob-sessions"), false);

    const httpSummary = summary.tools.find((toolSummary) => toolSummary.tool === "bob_http_scan");
    assert.ok(httpSummary);
    assert.equal(httpSummary.calls, 3);
    assert.equal(httpSummary.successes, 2);
    assert.equal(httpSummary.failures, 1);
    assert.equal(httpSummary.success_rate, 0.6667);
    assert.deepEqual(httpSummary.latency_ms, { p50: 20, p95: 30 });
    assert.deepEqual(httpSummary.error_codes, { SCOPE_BLOCKED: 1 });
    assert.equal(httpSummary.last_call.elapsed_ms, 30);
    assert.equal(httpSummary.last_call.egress_profile, "operator-eu");
    assert.equal(httpSummary.last_call.egress_profile_identity_hash, egressTelemetryHash);
    assert.equal(httpSummary.last_call.egress_profile_identity_version, 1);
    assert.equal(httpSummary.last_call.proxy_configured, true);
    assert.deepEqual(httpSummary.authority.by_result, { allowed: 2, blocked: 1 });
    assert.deepEqual(httpSummary.authority.by_error_code, { none: 2, scoped_url_drift: 1 });
    assert.equal(httpSummary.recent_failures.length, 1);
    assert.equal(httpSummary.recent_failures[0].error_message, "blocked");
    assert.deepEqual(httpSummary.recent_failures[0].authority, {
      authority_version: 1,
      authority_class: "scoped_http_network",
      authority_mode: "enforce",
      authority_source: "session_state",
      authority_result: "blocked",
      authority_error_code: "scoped_url_drift",
      authority_block_reason: "scoped_url_drift",
      authority_shadowed: false,
    });

    const filtered = readToolTelemetry({ tool: "bob_http_scan" }, { env });
    assert.equal(filtered.telemetry_path, "[telemetry-dir]/tool-events.jsonl");
    assert.equal(filtered.total_events, 4);
    assert.deepEqual(filtered.observed_bob_versions, ["1.2.1", "1.2.2"]);
    assert.equal(filtered.tools.length, 1);
    assert.equal(filtered.tools[0].tool, "bob_http_scan");
    assert.equal(filtered.tools[0].calls, 4);
    assert.deepEqual(filtered.authority.by_version, { 1: 3, 2: 1 });
    const unfiltered = readToolTelemetry({ limit: 5 }, { env });
    const unfilteredJson = JSON.stringify(unfiltered);
    assert.equal(unfilteredJson.includes("raw-target-secret"), false);
    assert.equal(unfilteredJson.includes("user:pass"), false);
    assert.equal(unfilteredJson.includes("raw-region-secret"), false);
    assert.equal(unfilteredJson.includes("not-a-hash-secret"), false);
    assert.equal(unfilteredJson.includes("customer email exposed"), false);
    assert.equal(unfilteredJson.includes("raw-tool-secret"), false);
    assert.equal(unfilteredJson.includes("raw-wave-secret"), false);
    assert.equal(unfilteredJson.includes("raw-agent-secret"), false);
    assert.equal(unfilteredJson.includes("raw-surface-secret"), false);
    assert.equal(unfilteredJson.includes("raw-error-code-secret"), false);
    assert.equal(unfilteredJson.includes("raw-bob-version-secret"), false);
    assert.equal(unfilteredJson.includes("raw-ts-secret"), false);
    assert.equal(unfilteredJson.includes("/admin/reset"), false);
    assert.equal(unfilteredJson.includes("raw-authority-version-secret"), false);
    assert.equal(unfilteredJson.includes("raw-authority-class-secret"), false);
    assert.equal(unfilteredJson.includes("raw-authority-error-secret"), false);
    assert.equal(unfilteredJson.includes("raw-authority-reason-secret"), false);

    const poisonedFilter = readToolTelemetry({
      target_domain: "https://example.com/?access_token=reader-filter-secret",
      tool: "bob_http_scan?token=reader-tool-secret",
    }, { env });
    assert.equal(poisonedFilter.total_events, 0);
    assert.equal(poisonedFilter.filters.target_domain, null);
    assert.equal(poisonedFilter.filters.tool, null);
    assert.equal(JSON.stringify(poisonedFilter).includes("reader-filter-secret"), false);
    assert.equal(JSON.stringify(poisonedFilter).includes("reader-tool-secret"), false);
  } finally {
    fs.rmSync(telemetryRoot, { recursive: true, force: true });
  }
});

test("tool telemetry reader can include filtered evaluator run telemetry summaries", () => {
  const telemetryRoot = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-telemetry-"));
  const env = { ...process.env, BOUNTY_TELEMETRY: "1", BOUNTY_TELEMETRY_DIR: telemetryRoot };
  try {
    const allowed = buildToolInvocationTelemetryEvent({
      run_type: "evaluator",
      status: "allowed",
      target_domain: "example.com",
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      transcript_path: "/tmp/transcript-a.jsonl",
      handoff: {
        present: true,
        valid: true,
        provenance: "verified",
        surface_status: "complete",
        summary_present: true,
        chain_notes_count: 1,
      },
      coverage: { total: 2, by_status: { tested: 1, promising: 1 } },
      findings: { count: 1 },
      now: new Date("2026-04-24T00:00:00.000Z"),
    });
    const missing = buildToolInvocationTelemetryEvent({
      run_type: "evaluator",
      status: "blocked",
      block_code: "missing_handoff",
      target_domain: "example.com",
      wave: "w1",
      agent: "a2",
      surface_id: "surface-b",
      transcript_path: "/tmp/transcript-b.jsonl",
      handoff: { present: false, valid: false },
      now: new Date("2026-04-24T00:01:00.000Z"),
    });
    const other = buildToolInvocationTelemetryEvent({
      run_type: "evaluator",
      status: "blocked",
      block_code: "malformed_marker",
      target_domain: "https://other.example/?token=raw-agent-target-secret",
      wave: "w2",
      agent: "a1",
      surface_id: "surface-x",
      now: new Date("2026-04-24T00:02:00.000Z"),
    });
    appendToolInvocationTelemetryEvent(allowed, { env });
    appendToolInvocationTelemetryEvent(missing, { env });
    appendToolInvocationTelemetryEvent(other, { env });
    fs.appendFileSync(toolInvocationTelemetryPath(env), `${JSON.stringify({
      version: 1,
      bob_version: "https://version.example/?token=raw-agent-bob-version-secret",
      ts: "https://ts.example/?token=raw-agent-ts-secret",
      run_id: "https://run.example/?token=raw-agent-run-id-secret",
      run_type: "evaluator?token=raw-agent-run-type-secret",
      status: "blocked",
      block_code: "malformed?token=raw-agent-block-secret",
      target_domain: "poison.example",
      wave: "w9?token=raw-agent-wave-secret",
      agent: "a9?token=raw-agent-label-secret",
      surface_id: "https://surface.example/?token=raw-agent-surface-secret",
      transcript_path: "/tmp/raw-agent-transcript-secret.jsonl",
      handoff: {
        present: false,
        valid: false,
        provenance: "verified?token=raw-agent-provenance-secret",
        surface_status: "partial?token=raw-agent-status-secret",
      },
      coverage: {
        total: 1,
        by_status: {
          "tested?token=raw-agent-coverage-secret": 1,
        },
      },
      findings: { count: 1 },
      telemetry_source: "source?token=raw-agent-telemetry-source-secret",
    })}\n`, "utf8");
    fs.appendFileSync(toolInvocationTelemetryPath(env), "{not-json\n", "utf8");

    const withoutRuns = readToolTelemetry({ target_domain: "example.com" }, { env });
    assert.equal(Object.prototype.hasOwnProperty.call(withoutRuns, "agent_runs"), false);

    const summary = readToolTelemetry({ include_agent_runs: true, target_domain: "example.com", limit: 2 }, { env });
    assert.equal(summary.total_events, 0);
    assert.equal(summary.agent_runs.telemetry_path, "[telemetry-dir]/tool-invocations.jsonl");
    assert.deepEqual(summary.agent_runs.observed_bob_versions, [PACKAGE_VERSION]);
    assert.equal(summary.agent_runs.total_runs, 2);
    assert.equal(summary.agent_runs.malformed_lines, 1);
    assert.deepEqual(summary.agent_runs.totals.by_status, { allowed: 1, blocked: 1 });
    assert.deepEqual(summary.agent_runs.totals.by_block_code, { missing_handoff: 1 });
    assert.equal(summary.agent_runs.latest_run.run_id, missing.run_id);
    assert.equal(summary.agent_runs.latest_run.transcript_path, "[transcript-path]");
    assert.equal(summary.agent_runs.recent_blocked_runs.length, 1);
    assert.equal(summary.agent_runs.recent_blocked_runs[0].block_code, "missing_handoff");
    assert.equal(summary.agent_runs.recent_blocked_runs[0].transcript_path, "[transcript-path]");

    const filtered = readToolTelemetry({
      include_agent_runs: true,
      target_domain: "example.com",
      agent_run_type: "evaluator",
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
    }, { env });
    assert.equal(filtered.agent_runs.total_runs, 1);
    assert.equal(filtered.agent_runs.latest_run.run_id, allowed.run_id);
    assert.equal(filtered.agent_runs.latest_run.transcript_path, "[transcript-path]");
    assert.deepEqual(filtered.agent_runs.latest_run.coverage.by_status, { tested: 1, promising: 1 });
    assert.equal(filtered.agent_runs.latest_run.findings.count, 1);
    const unfiltered = readToolTelemetry({ include_agent_runs: true, limit: 5 }, { env });
    const unfilteredJson = JSON.stringify(unfiltered);
    assert.equal(unfilteredJson.includes("raw-agent-target-secret"), false);
    assert.equal(unfilteredJson.includes("raw-agent-run-id-secret"), false);
    assert.equal(unfilteredJson.includes("raw-agent-run-type-secret"), false);
    assert.equal(unfilteredJson.includes("raw-agent-block-secret"), false);
    assert.equal(unfilteredJson.includes("raw-agent-wave-secret"), false);
    assert.equal(unfilteredJson.includes("raw-agent-label-secret"), false);
    assert.equal(unfilteredJson.includes("raw-agent-surface-secret"), false);
    assert.equal(unfilteredJson.includes("raw-agent-transcript-secret"), false);
    assert.equal(unfilteredJson.includes("raw-agent-bob-version-secret"), false);
    assert.equal(unfilteredJson.includes("raw-agent-ts-secret"), false);
    assert.equal(unfilteredJson.includes("raw-agent-provenance-secret"), false);
    assert.equal(unfilteredJson.includes("raw-agent-status-secret"), false);
    assert.equal(unfilteredJson.includes("raw-agent-coverage-secret"), false);
    assert.equal(unfilteredJson.includes("raw-agent-telemetry-source-secret"), false);

    const poisonedFilter = readToolTelemetry({
      include_agent_runs: true,
      target_domain: "https://example.com/?token=reader-agent-target-secret",
      agent_run_type: "evaluator?token=reader-type-secret",
      wave: "w1?token=reader-wave-secret",
      agent: "a1?token=reader-agent-secret",
      surface_id: "surface-a?token=reader-surface-secret",
    }, { env });
    assert.equal(poisonedFilter.agent_runs.total_runs, 0);
    assert.equal(poisonedFilter.agent_runs.filters.target_domain, null);
    assert.equal(poisonedFilter.agent_runs.filters.agent_run_type, null);
    assert.equal(poisonedFilter.agent_runs.filters.wave, null);
    assert.equal(poisonedFilter.agent_runs.filters.agent, null);
    assert.equal(poisonedFilter.agent_runs.filters.surface_id, null);
    const poisonedFilterJson = JSON.stringify(poisonedFilter);
    assert.equal(poisonedFilterJson.includes("reader-agent-target-secret"), false);
    assert.equal(poisonedFilterJson.includes("reader-type-secret"), false);
    assert.equal(poisonedFilterJson.includes("reader-wave-secret"), false);
    assert.equal(poisonedFilterJson.includes("reader-agent-secret"), false);
    assert.equal(poisonedFilterJson.includes("reader-surface-secret"), false);
  } finally {
    fs.rmSync(telemetryRoot, { recursive: true, force: true });
  }
});

test("pipeline analytics records metadata-only events for a complete synthetic run", () => {
  withTempHome(() => {
    const domain = "example.com";
    const rawPocSecret = "pipeline-raw-poc-secret";
    const rawHandoffSecret = "pipeline-raw-handoff-secret";
    const rawCoverageSecret = "pipeline-raw-coverage-secret";
    const rawTechniqueSecret = "pipeline-raw-technique-attempt-secret";
    const rawEvidenceText = "metadata-only analytics must not copy this evidence pack text";

    JSON.parse(initSession({ target_domain: domain, target_url: "https://example.com" }));
    seedAttackSurfaces(domain, [{ id: "surface-a", hosts: [`https://${domain}`], priority: "HIGH" }]);
    JSON.parse(transitionPhase({ target_domain: domain, to_phase: "AUTH" }));
    JSON.parse(transitionPhase({ target_domain: domain, to_phase: "EVALUATE", auth_status: "authenticated" }));
    const started = JSON.parse(startWave({
      target_domain: domain,
      wave_number: 1,
      assignments: [{ agent: "a1", surface_id: "surface-a" }],
    }));

    JSON.parse(logCoverage({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      entries: [{
        endpoint: "/api/export",
        method: "GET",
        bug_class: "idor",
        status: "tested",
        evidence_summary: rawCoverageSecret,
      }],
    }));
    JSON.parse(logTechniqueAttempt({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      pack_id: "generic-rest-api",
      status: "attempted",
      outcome: "no_finding",
      evidence: rawTechniqueSecret,
    }));
    JSON.parse(recordFinding({
      target_domain: domain,
      title: "IDOR on export",
      severity: "high",
      endpoint: "/api/export",
      description: "Cross-account export is possible.",
      proof_of_concept: rawPocSecret,
      response_evidence: "metadata-only analytics must not copy this evidence",
      impact: "PII disclosure.",
      validated: true,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
    }));
    JSON.parse(writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      handoff_token: started.assignments[0].handoff_token,
      summary: "surface complete",
      chain_notes: ["chain context"],
      content: `# Handoff\n\n${rawHandoffSecret}`,
    }));
    JSON.parse(applyWaveMerge({ target_domain: domain, wave_number: 1, force_merge: false }));
    JSON.parse(transitionPhase({ target_domain: domain, to_phase: "CHAIN" }));
    JSON.parse(writeChainAttempt({
      target_domain: domain,
      finding_ids: ["F-1"],
      surface_ids: ["surface-a"],
      hypothesis: "Single finding plus chain note does not produce an demonstrable chain.",
      steps: ["Reviewed chain note and replay context."],
      outcome: "not_applicable",
      evidence_summary: "No second issue or request sequence amplifies F-1.",
    }));
    JSON.parse(transitionPhase({ target_domain: domain, to_phase: "VERIFY" }));

    const verified = [{
      finding_id: "F-1",
      disposition: "confirmed",
      severity: "high",
      reportable: true,
      reasoning: "Confirmed.",
    }];
    seedVerificationPipeline(domain, verified);
    JSON.parse(writeEvidencePacks({
      target_domain: domain,
      packs: [{
        finding_id: "F-1",
        sample_type: "cross-account export",
        sample_count: 1,
        aggregate_counts: { private_exports_sampled: 1 },
        representative_samples: [{
          request_ref: "http-audit:1",
          endpoint: "/api/export",
          auth_profile: "attacker",
          status: 200,
          observed_fields: ["account_id"],
          redacted_object_id: "acct_...002",
        }],
        sensitive_clusters: ["account export metadata"],
        replay_summary: "Fresh replay returned another account export.",
        redaction_notes: "Object IDs and personal values redacted; auth material omitted.",
        report_snippet: rawEvidenceText,
      }],
    }));
    JSON.parse(transitionPhase({ target_domain: domain, to_phase: "GRADE" }));
    JSON.parse(writeGradeVerdict({
      target_domain: domain,
      verdict: "SUBMIT",
      total_score: 45,
      findings: [{
        finding_id: "F-1",
        impact: 20,
        proof_quality: 10,
        severity_accuracy: 5,
        chain_potential: 5,
        report_quality: 5,
        total_score: 45,
        feedback: null,
      }],
      feedback: null,
    }));
    JSON.parse(transitionPhase({ target_domain: domain, to_phase: "REPORT" }));
    writeFileAtomic(reportMarkdownPath(domain), "# Report\n");

    const rows = readJsonl(pipelineEventsJsonlPath(domain));
    assert.ok(rows.length >= 10);
    assert.equal(rows.every((row) => row.bob_version === PACKAGE_VERSION), true);
    assert.deepEqual(new Set(rows.map((row) => row.type)), new Set([
      "session_started",
      "lifecycle_advanced",
      "wave_started",
      "coverage_logged",
      "technique_attempt_logged",
      "finding_recorded",
      "wave_merged",
      "verification_snapshot_created",
      "verification_written",
      "verification_adjudication_built",
      "evidence_written",
      "grade_written",
    ]));
    assert.equal(rows.every((row) => row.target_domain === domain), true);
    assert.equal(rows.some((row) => row.type === "finding_recorded" && row.counts.findings === 1), true);
    const adjudicationEvent = rows.find((row) => row.type === "verification_adjudication_built");
    assert.match(adjudicationEvent.adjudication_plan_hash, /^[a-f0-9]{64}$/);
    assert.equal(Object.hasOwn(adjudicationEvent, "plan_hash"), false);
    const finalVerificationEvent = rows.find((row) => row.type === "verification_written" && row.status === "final");
    assert.equal(finalVerificationEvent.adjudication_plan_hash, adjudicationEvent.adjudication_plan_hash);
    assert.equal(Object.hasOwn(finalVerificationEvent, "plan_hash"), false);

    const analyticsText = readPipelineAnalytics({ target_domain: domain, include_events: true, limit: 100 });
    const analytics = JSON.parse(analyticsText);
    assert.equal(analytics.mode, "session");
    assert.deepEqual(analytics.analytics_bounds, {
      session_scan_limit: 1,
      sessions_available: 1,
      sessions_considered: 1,
      sessions_truncated: false,
      telemetry_reads_reused: false,
      tool_events_loaded: analytics.tool_health.total_events,
      evaluator_events_loaded: analytics.evaluator_health.total_runs,
    });
    assert.equal(analytics.event_log.exists, true);
    assert.equal(analytics.event_log.backfilled, false);
    assert.equal(analytics.sessions[0].health.status, "healthy");
    assert.equal(analytics.sessions[0].lifecycle_state, "REPORT");
    assert.equal(analytics.sessions[0].findings.total, 1);
    assert.equal(analytics.sessions[0].chain_attempts_count, 1);
    assert.equal(analytics.sessions[0].chain_attempts_by_outcome.not_applicable, 1);
    assert.equal(analytics.sessions[0].technique_attempts.total, 1);
    assert.equal(analytics.sessions[0].technique_attempts.by_status.attempted, 1);
    assert.equal(analytics.sessions[0].technique_attempts.surface_count, 1);
    assert.equal(analytics.sessions[0].technique_attempts.pack_count, 1);
    assert.equal(typeof analytics.sessions[0].claim_freeze_duration_ms, "number");
    assert.equal(analytics.sessions[0].final_verification_count, 1);
    assert.equal(readSessionArtifactSummary(domain).verification.adjudication.adjudication_plan_hash, adjudicationEvent.adjudication_plan_hash);
    assert.equal(analytics.sessions[0].evidence.valid, true);
    assert.equal(analytics.sessions[0].evidence.packs_count, 1);
    assert.equal(analytics.sessions[0].grade_verdict, "SUBMIT");
    assert.equal(analytics.sessions[0].report_present, true);
    assert.equal(analytics.funnel.reached.REPORT, 1);
    assert.equal(analytics.bottlenecks.length, 0);
    assert.equal(analytics.events.every((event) => event.bob_version === PACKAGE_VERSION), true);
    const normalizedAdjudicationEvent = analytics.events.find((event) => event.type === "verification_adjudication_built");
    assert.equal(normalizedAdjudicationEvent.adjudication_plan_hash, adjudicationEvent.adjudication_plan_hash);
    assert.equal(Object.hasOwn(normalizedAdjudicationEvent, "plan_hash"), false);

    for (const forbidden of [rawPocSecret, rawHandoffSecret, rawCoverageSecret, rawTechniqueSecret, "metadata-only analytics must not copy this evidence", rawEvidenceText]) {
      assert.equal(analyticsText.includes(forbidden), false, `${forbidden} leaked into pipeline analytics`);
      assert.equal(JSON.stringify(rows).includes(forbidden), false, `${forbidden} leaked into pipeline events`);
    }
  });
});

test("pipeline analytics backfills legacy sessions from artifacts without an event log", () => {
  withTempHome(() => {
    const domain = "legacy.example";
    seedSessionState(domain, {
      phase: "REPORT",
      evaluation_wave: 1,
      pending_wave: null,
      total_findings: 1,
      explored: ["surface-a"],
      auth_status: "authenticated",
    });
    seedAttackSurfaces(domain, [{ id: "surface-a", hosts: [`https://${domain}`], priority: "HIGH" }]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    writeSignedStoredHandoff(domain, 1, "a1", {
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "a1 completed surface-a.",
      dead_ends: [],
      waf_blocked_endpoints: [],
      lead_surface_ids: [],
    });
    appendCandidateClaim({
      target_domain: domain,
      title: "Legacy IDOR",
      summary: "Legacy finding migrated from an older run.",
      severity: "high",
      status: "candidate",
      surface_ids: ["surface-a"],
      impact: "Cross-account metadata disclosure.",
      evidence_refs: [{
        kind: "finding",
        finding_id: "F-1",
        content_hash: "0".repeat(64),
      }],
      payload: {
        attack_class: "CWE-639",
        finding: {
          id: "F-1",
          target_domain: domain,
          title: "Legacy IDOR",
          severity: "high",
          cwe: "CWE-639",
          endpoint: "/api/export",
          description: "Legacy finding migrated from an older run.",
          proof_of_concept: "curl https://legacy.example/api/export?account_id=2",
          response_evidence: "200 OK with redacted account metadata",
          impact: "Cross-account metadata disclosure.",
          validated: true,
          wave: "w1",
          agent: "a1",
          surface_id: "surface-a",
        },
      },
    });
    writeFileAtomic(techniqueAttemptsJsonlPath(domain), `${JSON.stringify({
      version: 1,
      ts: "2026-01-01T00:00:00.000Z",
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      pack_id: "generic-rest-api",
      pack_version: 1,
      registry_version: 1,
      capability_pack: "web",
      capability_pack_version: 1,
      status: "attempted",
      outcome: "no_finding",
      evidence: "Legacy session attempted the generic REST API pack.",
    })}\n`);
    writeFileAtomic(techniquePackReadsJsonlPath(domain), `${JSON.stringify({
      version: 1,
      ts: "2026-01-01T00:00:00.000Z",
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      pack_id: "generic-rest-api",
      pack_version: 1,
      registry_version: 1,
      capability_pack: "web",
      capability_pack_version: 1,
      mode: "full",
    })}\n`);
    for (const round of ["brutalist", "balanced", "final"]) {
      writeFileAtomic(verificationRoundPaths(domain, round).json, `${JSON.stringify({
        version: 1,
        target_domain: domain,
        round,
        notes: `Legacy ${round} verification confirmed the finding.`,
        results: [{
          finding_id: "F-1",
          disposition: "confirmed",
          severity: "high",
          reportable: true,
          reasoning: "Legacy verification confirmed the finding.",
          repro_steps: [
            "Authenticate as a legacy account holder.",
            "Request /api/export with another account_id value.",
          ],
          evidence_refs: ["candidate_claim:F-1"],
        }],
      }, null, 2)}\n`);
    }
    writeFileAtomic(evidencePackPaths(domain).json, `${JSON.stringify({
      version: 1,
      target_domain: domain,
      packs: [{
        finding_id: "F-1",
        sample_type: "legacy sample",
        sample_count: 1,
        aggregate_counts: { examples: 1 },
        representative_samples: [{ request_ref: "legacy:1", status: 200 }],
        sensitive_clusters: ["redacted private metadata"],
        replay_summary: "Legacy evidence was collected before grading.",
        redaction_notes: "Values redacted.",
        report_snippet: "Legacy evidence pack covers F-1.",
      }],
    }, null, 2)}\n`);
    writeFileAtomic(gradeArtifactPaths(domain).json, `${JSON.stringify({
      version: 1,
      target_domain: domain,
      verdict: "SUBMIT",
      total_score: 45,
      findings: [{ finding_id: "F-1", total_score: 45 }],
    }, null, 2)}\n`);
    writeFileAtomic(reportMarkdownPath(domain), "# Legacy report\n");

    assert.equal(fs.existsSync(pipelineEventsJsonlPath(domain)), false);
    assert.equal(sessionsRoot(), path.join(process.env.HOME, "hacker-bob-sessions"));

    const artifactSummary = readSessionArtifactSummary(domain, { validateAuthority: true });
    assert.equal(artifactSummary.state.checkpoint_mode, "normal");
    assert.equal(artifactSummary.state.block_internal_hosts, false);
    assert.equal(artifactSummary.state.block_internal_hosts_source, "legacy_default");
    assert.equal(artifactSummary.technique_attempts.total_records, 1);
    assert.equal(artifactSummary.technique_attempts.by_status.attempted, 1);
    assert.equal(artifactSummary.technique_pack_reads.full_reads, 1);

    const eventRead = readPipelineEvents(domain);
    assert.equal(eventRead.backfilled, true);
    assert.equal(eventRead.events.some((event) => event.source === "artifact_backfill"), true);
    assert.equal(eventRead.events.some((event) => event.type === "technique_attempt_logged" && event.source === "artifact_backfill"), true);

    const analytics = JSON.parse(readPipelineAnalytics({ target_domain: domain, include_events: true }));
    assert.equal(analytics.event_log.backfilled, true);
    assert.equal(analytics.sessions[0].health.status, "healthy");
    assert.equal(analytics.sessions[0].checkpoint_mode, "normal");
    assert.equal(analytics.sessions[0].block_internal_hosts, false);
    assert.equal(analytics.sessions[0].block_internal_hosts_source, "legacy_default");
    assert.equal(analytics.sessions[0].report_present, true);
    assert.equal(analytics.sessions[0].technique_attempts.total, 1);
    assert.equal(analytics.sessions[0].technique_attempts.by_status.attempted, 1);
    assert.equal(analytics.sessions[0].technique_pack_reads.full_reads, 1);
    assert.equal(analytics.events.some((event) => event.source === "artifact_backfill"), true);
    assert.equal(analytics.events.every((event) => event.checkpoint_mode === "normal"), true);
    assert.equal(analytics.events.every((event) => event.block_internal_hosts === false), true);
    assert.equal(analytics.events.every((event) => event.block_internal_hosts_source === "legacy_default"), true);

    const crossSession = JSON.parse(readPipelineAnalytics({ window_days: 1 }));
    assert.equal(crossSession.mode, "cross_session");
    assert.ok(crossSession.sessions.some((session) => session.target_domain === domain));
    assert.equal(crossSession.funnel.sessions_total, 1);
  });
});

test("pipeline analytics blocks authority-invalid cross-session state exports", () => {
  withTempHome(() => {
    const writePoisonEvent = (domain, hash) => {
      fs.mkdirSync(sessionDir(domain), { recursive: true });
      fs.appendFileSync(pipelineEventsJsonlPath(domain), `${JSON.stringify({
        version: 1,
        bob_version: PACKAGE_VERSION,
        ts: new Date().toISOString(),
        target_domain: domain,
        type: "phase_transitioned",
        to_phase: "EVALUATE",
        checkpoint_mode: "normal",
        block_internal_hosts: true,
        block_internal_hosts_source: "explicit_block",
        egress_profile: "vpn-us",
        egress_region: "us",
        proxy_configured: true,
        egress_profile_identity_hash: hash,
        egress_profile_identity_version: 1,
      })}\n`, "utf8");
    };
    const domain = "analytics-drift.example";
    seedSessionState(domain, {
      phase: "EVALUATE",
      checkpoint_mode: "normal",
      block_internal_hosts: true,
      block_internal_hosts_source: "explicit_block",
      egress_profile: "vpn-us",
      egress_region: "us",
      proxy_configured: true,
      egress_profile_identity_hash: "authority-sensitive-hash",
      egress_profile_identity_version: 1,
    });

    const drifted = JSON.parse(fs.readFileSync(statePath(domain), "utf8"));
    drifted.target_url = "https://outside.example.net";
    fs.writeFileSync(statePath(domain), `${JSON.stringify(drifted, null, 2)}\n`, "utf8");
    writePoisonEvent(domain, "authority-sensitive-hash");

    const missingDomain = "analytics-missing-state.example";
    writePoisonEvent(missingDomain, "missing-state-authority-hash");

    const malformedDomain = "analytics-malformed-state.example";
    fs.mkdirSync(sessionDir(malformedDomain), { recursive: true });
    fs.writeFileSync(statePath(malformedDomain), "{not-json\n", "utf8");
    writePoisonEvent(malformedDomain, "malformed-state-authority-hash");

    const artifactSummary = readSessionArtifactSummary(domain, { validateAuthority: true });
    assert.ok(artifactSummary.artifact_errors.includes("Session authority invalid: target_url_drift"));
    assert.equal(artifactSummary.state.phase, null);
    assert.equal(artifactSummary.state.block_internal_hosts, null);
    assert.equal(artifactSummary.state.block_internal_hosts_source, null);
    assert.equal(artifactSummary.state.egress_profile, null);
    assert.equal(artifactSummary.state.proxy_configured, null);

    const crossSession = JSON.parse(readPipelineAnalytics({ window_days: 1, include_events: true }));
    const row = crossSession.sessions.find((session) => session.target_domain === domain);
    assert.ok(row);
    assert.equal(row.health.status, "blocked");
    assert.deepEqual(row.health.reasons, ["unreadable_artifacts"]);
    assert.equal(row.block_internal_hosts, null);
    assert.equal(row.block_internal_hosts_source, null);
    assert.equal(row.egress_profile_identity.egress_profile, null);
    assert.equal(row.egress_profile_identity.proxy_configured, null);
    assert.equal(row.latest_event.egress_profile_identity_hash, undefined);
    assert.equal(row.latest_event.block_internal_hosts, undefined);
    assert.equal(crossSession.events.every((event) => event.egress_profile_identity_hash == null), true);
    assert.equal(crossSession.events.every((event) => event.block_internal_hosts == null), true);
    assert.equal(JSON.stringify(row).includes("outside.example.net"), false);
    assert.equal(JSON.stringify(crossSession).includes("authority-sensitive-hash"), false);
    for (const invalidDomain of [missingDomain, malformedDomain]) {
      const invalidRow = crossSession.sessions.find((session) => session.target_domain === invalidDomain);
      assert.ok(invalidRow);
      assert.equal(invalidRow.health.status, "blocked");
      assert.equal(invalidRow.latest_event.egress_profile_identity_hash, undefined);
      assert.equal(invalidRow.latest_event.block_internal_hosts, undefined);
    }
    assert.equal(JSON.stringify(crossSession).includes("missing-state-authority-hash"), false);
    assert.equal(JSON.stringify(crossSession).includes("malformed-state-authority-hash"), false);
  });
});

test("pipeline analytics flags blocked pending waves and malformed event lines", () => {
  withTempHome(() => {
    const domain = "blocked.example";
    seedSessionState(domain, { phase: "EVALUATE", pending_wave: 1, evaluation_wave: 0 });
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    fs.mkdirSync(sessionDir(domain), { recursive: true });
    fs.appendFileSync(pipelineEventsJsonlPath(domain), "{not-json\n", "utf8");
    fs.appendFileSync(pipelineEventsJsonlPath(domain), `${JSON.stringify({
      version: 1,
      ts: "2026-04-24T00:00:00.000Z",
      target_domain: domain,
      type: "wave_started",
      wave_number: 1,
      status: "started",
      source: "test",
      counts: { assignments: 1 },
    })}\n`, "utf8");

    const summary = readSessionArtifactSummary(domain);
    assert.equal(summary.state.pending_wave, 1);
    assert.equal(summary.waves[0].missing_agents.length, 1);

    const analytics = JSON.parse(readPipelineAnalytics({ target_domain: domain, include_events: true }));
    assert.equal(analytics.event_log.malformed_lines, 1);
    assert.equal(analytics.event_log.backfilled, false);
    assert.equal(analytics.sessions[0].health.status, "blocked");
    assert.ok(analytics.sessions[0].health.reasons.includes("evaluator_handoff_failures"));
    assert.ok(analytics.bottlenecks.some((bottleneck) => bottleneck.code === "evaluator_handoff_failures"));
    assert.ok(analytics.next_actions.some((action) => /handoffs/.test(action.action)));
  });
});

test("pipeline event appends are reentrant under the session lock", () => {
  withTempHome(() => {
    const domain = "pipeline-lock.example";
    const state = seedSessionState(domain, { phase: "EVALUATE" });
    const governanceContext = buildGovernanceContext(state);

    withSessionLock(domain, () => {
      const event = appendPipelineEventDirect(domain, "report_written", {
        status: "written",
        source: "lock-test",
        counts: { report_size_bytes: 12 },
      }, governanceContext);
      assert.equal(event.type, "report_written");
      assert.ok(fs.existsSync(sessionLockPath(domain)));
    });

    assert.ok(!fs.existsSync(sessionLockPath(domain)));
    const rows = readJsonl(pipelineEventsJsonlPath(domain));
    assert.equal(rows.length, 1);
    assert.equal(rows[0].source, "lock-test");
  });
});

test("pipeline analytics uses recent technique-pack read artifacts as pending-wave activity", () => {
  withTempHome(() => {
    const domain = "recent-pack-read.example";
    const oldDate = new Date(Date.now() - 4 * 60 * 60 * 1000);
    const oldIso = oldDate.toISOString();
    seedSessionState(domain, { phase: "EVALUATE", pending_wave: 1, evaluation_wave: 0 });
    seedAttackSurface(domain, ["surface-a"]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    fs.appendFileSync(pipelineEventsJsonlPath(domain), `${JSON.stringify({
      version: 1,
      ts: oldIso,
      target_domain: domain,
      type: "wave_started",
      wave_number: 1,
      status: "started",
      source: "test",
      counts: { assignments: 1 },
    })}\n`, "utf8");
    fs.utimesSync(statePath(domain), oldDate, oldDate);
    fs.utimesSync(attackSurfacePath(domain), oldDate, oldDate);

    writeFileAtomic(techniquePackReadsJsonlPath(domain), `${JSON.stringify({
      version: 1,
      ts: new Date().toISOString(),
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      pack_id: "generic-rest-api",
      pack_version: 1,
      registry_version: 1,
      capability_pack: "web",
      capability_pack_version: 1,
      mode: "full",
    })}\n`);

    const analytics = JSON.parse(readPipelineAnalytics({ target_domain: domain, include_events: true }));
    const row = analytics.sessions[0];
    assert.equal(row.technique_pack_reads.full_reads, 1);
    assert.ok(row.health.reasons.includes("evaluator_handoff_failures"));
    assert.equal(row.health.reasons.includes("stale_pending_wave"), false);
    assert.equal(row.latest_event.ts, oldIso);
    assert.ok(Date.now() - Date.parse(row.latest_activity_ts) < 60_000);
  });
});

test("pipeline analytics reports chain attempts, chain duration, and no-attempt bottleneck", () => {
  withTempHome(() => {
    const domain = "chain-analytics.example.com";
    seedSessionState(domain, { phase: "VERIFY" });
    seedAttackSurfaces(domain, [
      { id: "surface-a", hosts: [`https://${domain}`], priority: "HIGH" },
    ]);
    seedFinding(domain, { title: "IDOR export", endpoint: "/api/export" });
    seedFinding(domain, { title: "Open redirect", endpoint: "/oauth/callback" });
    JSON.parse(writeChainAttempt({
      target_domain: domain,
      finding_ids: ["F-1", "F-2"],
      surface_ids: ["surface-a"],
      hypothesis: "Open redirect may amplify export access.",
      steps: ["Started replay but could not complete before auth expired."],
      outcome: "inconclusive",
      evidence_summary: "Auth expired before a terminal result.",
    }));
    writeFileAtomic(pipelineEventsJsonlPath(domain), [
      {
        version: 1,
        ts: "2026-04-24T00:00:00.000Z",
        target_domain: domain,
        type: "lifecycle_advanced",
        from_state: "OPEN_FRONTIER",
        to_state: "CLAIM_FREEZE",
        lifecycle_state: "CLAIM_FREEZE",
      },
      {
        version: 1,
        ts: "2026-04-24T00:01:00.000Z",
        target_domain: domain,
        type: "lifecycle_advanced",
        from_state: "CLAIM_FREEZE",
        to_state: "VERIFY",
        lifecycle_state: "VERIFY",
      },
    ].map((event) => JSON.stringify(event)).join("\n") + "\n");

    const analytics = JSON.parse(readPipelineAnalytics({ target_domain: domain, include_events: true }));
    assert.equal(analytics.sessions[0].chain_attempts_count, 1);
    assert.equal(analytics.sessions[0].chain_attempts_by_outcome.inconclusive, 1);
    assert.equal(analytics.sessions[0].claim_freeze_duration_ms, 60_000);
    assert.equal(analytics.sessions[0].health.status, "blocked");
    assert.ok(analytics.sessions[0].health.reasons.includes("chain_phase_no_attempts"));
    assert.ok(analytics.bottlenecks.some((bottleneck) => bottleneck.code === "chain_phase_no_attempts"));
  });
});

test("pipeline analytics counts chain_notes when assignment file is missing (capped) but drops on validation failure", () => {
  withTempHome(() => {
    const domain = "chain-notes-resilience.example.com";
    seedSessionState(domain, { phase: "VERIFY" });
    seedAttackSurface(domain, ["surface-a"]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);

    writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "Tested with chain notes.",
      content: "# w1-a1",
      chain_notes: ["Cookie reuse possible.", "Open redirect amplifies."],
    });

    // R1-HIGH-#3 resilience: deleting the assignment file used to drop the
    // handoff's chain_notes from analytics entirely. With the fix, the notes
    // are counted up to the per-session cap and surfaced via
    // unsigned_handoff_count so operators see the gap.
    fs.unlinkSync(path.join(sessionDir(domain), "wave-1-assignments.json"));

    const analytics = JSON.parse(readPipelineAnalytics({ target_domain: domain, include_events: false }));
    const row = analytics.sessions[0];
    // The chain_phase_no_attempts issue fires because phase >= CHAIN and
    // chain_notes_count > 0 but no terminal chain attempts exist. Its
    // `handoff_chain_notes` detail surfaces our counted notes.
    const issue = (analytics.bottlenecks || []).find((b) => b.code === "chain_phase_no_attempts");
    assert.ok(issue, "expected chain_phase_no_attempts bottleneck");
    assert.ok(row.health.reasons.includes("chain_phase_no_attempts"));
  });
});

test("pipeline analytics flags missing evidence only for final reportable findings", () => {
  withTempHome(() => {
    const domain = "missing-evidence.example.com";
    seedSessionState(domain, { phase: "GRADE" });
    seedFinding(domain);
    seedVerificationPipeline(domain, [{
      finding_id: "F-1",
      disposition: "confirmed",
      severity: "high",
      reportable: true,
      reasoning: "Confirmed.",
    }]);

    const analytics = JSON.parse(readPipelineAnalytics({ target_domain: domain, include_events: true }));
    assert.equal(analytics.sessions[0].evidence.valid, false);
    assert.deepEqual(analytics.sessions[0].evidence.missing_finding_ids, ["F-1"]);
    assert.ok(analytics.sessions[0].health.reasons.includes("missing_evidence"));
    assert.ok(analytics.bottlenecks.some((bottleneck) => bottleneck.code === "missing_evidence"));

    const noReportableDomain = "no-evidence-needed.example.com";
    seedSessionState(noReportableDomain, { phase: "GRADE" });
    seedFinding(noReportableDomain);
    seedVerificationPipeline(noReportableDomain, [{
      finding_id: "F-1",
      disposition: "denied",
      severity: null,
      reportable: false,
      reasoning: "Not reproducible.",
    }]);

    const noReportable = JSON.parse(readPipelineAnalytics({ target_domain: noReportableDomain, include_events: true }));
    assert.equal(noReportable.sessions[0].evidence.valid, true);
    assert.equal(noReportable.sessions[0].evidence.skipped, undefined);
    assert.ok(!noReportable.sessions[0].health.reasons.includes("missing_evidence"));
    assert.ok(!noReportable.bottlenecks.some((bottleneck) => bottleneck.code === "missing_evidence"));
  });
});

test("pipeline analytics flags only HOLD as needs_attention; both SKIP variants are healthy by construction", () => {
  // writeGradeVerdict rejects any SKIP that does not satisfy
  // `!hasReportableMedium || total_score < GRADE_HOLD_MIN_SCORE`. SKIP at
  // read time is therefore either "no reportables" (clean exit) or
  // "low-score reportables below the HOLD threshold" (grader correctly
  // applied its scoring rule). Neither is anomalous — only HOLD asks for
  // operator action.
  withTempHome(() => {
    const skipCleanDomain = "skip-clean.example.com";
    seedSessionState(skipCleanDomain, { phase: "REPORT" });
    seedVerificationPipeline(skipCleanDomain, []);
    writeGradeVerdict({
      target_domain: skipCleanDomain,
      verdict: "SKIP",
      total_score: 0,
      findings: [],
    });
    const skipClean = JSON.parse(readPipelineAnalytics({ target_domain: skipCleanDomain, include_events: true }));
    assert.ok(!skipClean.sessions[0].health.reasons.includes("grade_hold"));
    assert.ok(!skipClean.sessions[0].health.reasons.includes("grade_hold_skip"));
    assert.ok(!skipClean.bottlenecks.some((bottleneck) => bottleneck.code.startsWith("grade_")));

    const skipLowScoreDomain = "skip-low-score.example.com";
    seedSessionState(skipLowScoreDomain, { phase: "REPORT" });
    seedFinding(skipLowScoreDomain);
    seedVerificationPipeline(skipLowScoreDomain, [{
      finding_id: "F-1",
      disposition: "confirmed",
      severity: "high",
      reportable: true,
      reasoning: "Confirmed by replay.",
    }]);
    writeEvidencePacks({ target_domain: skipLowScoreDomain, packs: [evidencePack("F-1")] });
    writeGradeVerdict({
      target_domain: skipLowScoreDomain,
      verdict: "SKIP",
      total_score: 5,
      findings: [{
        finding_id: "F-1",
        impact: 1,
        proof_quality: 1,
        severity_accuracy: 1,
        chain_potential: 1,
        report_quality: 1,
        total_score: 5,
        feedback: "Below HOLD_MIN_SCORE despite confirmation; grader contract.",
      }],
    });
    const skipLowScore = JSON.parse(readPipelineAnalytics({ target_domain: skipLowScoreDomain, include_events: true }));
    assert.ok(!skipLowScore.sessions[0].health.reasons.includes("grade_hold"));
    assert.ok(!skipLowScore.bottlenecks.some((bottleneck) => bottleneck.code.startsWith("grade_")));

    const holdDomain = "grade-hold.example.com";
    seedSessionState(holdDomain, { phase: "GRADE" });
    seedFinding(holdDomain);
    seedVerificationPipeline(holdDomain, [{
      finding_id: "F-1",
      disposition: "confirmed",
      severity: "high",
      reportable: true,
      reasoning: "Confirmed.",
    }]);
    writeEvidencePacks({ target_domain: holdDomain, packs: [evidencePack("F-1")] });
    writeGradeVerdict({
      target_domain: holdDomain,
      verdict: "HOLD",
      total_score: 30,
      findings: [{
        finding_id: "F-1",
        impact: 10,
        proof_quality: 5,
        severity_accuracy: 5,
        chain_potential: 5,
        report_quality: 5,
        total_score: 30,
        feedback: "Promising but needs deeper repro.",
      }],
    });
    const hold = JSON.parse(readPipelineAnalytics({ target_domain: holdDomain, include_events: true }));
    assert.ok(hold.sessions[0].health.reasons.includes("grade_hold"));
    assert.ok(hold.bottlenecks.some((bottleneck) => bottleneck.code === "grade_hold"));
  });
});

test("pipeline analytics treats malformed evidence packs as invalid metadata", () => {
  withTempHome(() => {
    const domain = "malformed-evidence.example.com";
    seedSessionState(domain, { phase: "GRADE" });
    seedFinding(domain);
    seedVerificationPipeline(domain, [{
      finding_id: "F-1",
      disposition: "confirmed",
      severity: "high",
      reportable: true,
      reasoning: "Confirmed.",
    }]);
    writeFileAtomic(evidencePackPaths(domain).json, `${JSON.stringify({
      packs: [{ finding_id: "F-1" }],
    }, null, 2)}\n`);

    const artifactSummary = readSessionArtifactSummary(domain);
    const analytics = JSON.parse(readPipelineAnalytics({ target_domain: domain, include_events: true }));
    assert.equal(analytics.sessions[0].evidence.valid, false);
    assert.equal(analytics.sessions[0].evidence.packs_count, 1);
    assert.equal(analytics.sessions[0].evidence.reportable_findings_covered, 1);
    assert.ok(analytics.sessions[0].health.reasons.includes("missing_evidence"));
    assert.ok(analytics.bottlenecks.some((bottleneck) => bottleneck.code === "missing_evidence"));
    assert.match(artifactSummary.evidence.error, /Evidence packs.*target_domain|version/);
  });
});

test("MCP message handler lists tools, routes calls, serializes envelopes, and wraps thrown errors", async () => {
  const sent = [];
  const calls = [];
  const successEnvelope = {
    ok: true,
    data: { args: { x: 1 } },
    meta: { tool: "bob_fake", version: 1 },
  };
  const handleMessage = createMcpMessageHandler({
    tools: [{ name: "bob_fake", inputSchema: { type: "object" } }],
    executeTool: async (name, args) => {
      calls.push({ name, args });
      if (name === "bob_throw") {
        throw new Error("boom");
      }
      return successEnvelope;
    },
    send: (message) => sent.push(message),
  });

  await handleMessage({ jsonrpc: "2.0", id: 1, method: "tools/list" });
  await handleMessage({
    jsonrpc: "2.0",
    id: 2,
    method: "tools/call",
    params: { name: "bob_fake", arguments: { x: 1 } },
  });
  await handleMessage({
    jsonrpc: "2.0",
    id: 3,
    method: "tools/call",
    params: { name: "bob_throw", arguments: {} },
  });

  assert.deepEqual(sent[0], {
    jsonrpc: "2.0",
    id: 1,
    result: { tools: [{ name: "bob_fake", inputSchema: { type: "object" } }] },
  });
  assert.deepEqual(calls, [
    { name: "bob_fake", args: { x: 1 } },
    { name: "bob_throw", args: {} },
  ]);
  assert.equal(sent[1].result.content[0].type, "text");
  assert.equal(sent[1].result.content[0].text, JSON.stringify(successEnvelope));
  assert.deepEqual(JSON.parse(sent[1].result.content[0].text), successEnvelope);
  assert.deepEqual(JSON.parse(sent[2].result.content[0].text), {
    ok: false,
    error: { code: "INTERNAL_ERROR", message: "boom" },
    meta: { tool: "bob_throw", version: 1 },
  });
});

test("MCP message handler responds to unknown methods when id is 0", async () => {
  const sent = [];
  const handleMessage = createMcpMessageHandler({
    tools: [],
    executeTool: async () => ({ ok: true }),
    send: (message) => sent.push(message),
  });

  await handleMessage({ jsonrpc: "2.0", id: 0, method: "missing/method" });

  assert.deepEqual(sent, [{
    jsonrpc: "2.0",
    id: 0,
    error: { code: -32601, message: "Method not found: missing/method" },
  }]);
});

test("stdio transport accepts framed and raw JSON-RPC messages", () => {
  const framedOutput = [];
  const framedServer = createStdioServer({
    tools: [],
    executeTool: async () => ({ ok: true }),
    stdin: {
      setEncoding() {},
      on() {},
    },
    stdout: { write: (chunk) => framedOutput.push(String(chunk)) },
    stderr: { write() {} },
  });
  const framedBody = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" });

  framedServer.handleChunk(`Content-Length: ${Buffer.byteLength(framedBody)}\r\n\r\n${framedBody}`);

  const framedResponse = framedOutput.join("");
  const framedPayload = JSON.parse(framedResponse.slice(framedResponse.indexOf("\r\n\r\n") + 4));
  assert.deepEqual(framedPayload, { jsonrpc: "2.0", id: 1, result: {} });

  const rawOutput = [];
  const rawServer = createStdioServer({
    tools: [],
    executeTool: async () => ({ ok: true }),
    stdin: {
      setEncoding() {},
      on() {},
    },
    stdout: { write: (chunk) => rawOutput.push(String(chunk)) },
    stderr: { write() {} },
  });

  rawServer.handleChunk(`${JSON.stringify({ jsonrpc: "2.0", id: 2, method: "ping" })}\n`);

  assert.deepEqual(JSON.parse(rawOutput.join("").trim()), { jsonrpc: "2.0", id: 2, result: {} });
});

test("stdio transport counts framed Content-Length in bytes for unicode payloads", () => {
  const output = [];
  const server = createStdioServer({
    tools: [],
    executeTool: async () => ({ ok: true }),
    stdin: { on() {} },
    stdout: { write: (chunk) => output.push(Buffer.from(String(chunk), "utf8")) },
    stderr: { write() {} },
  });
  const body = JSON.stringify({
    jsonrpc: "2.0",
    id: 7,
    method: "ping",
    params: { marker: "unicode: snowman \u2603 and han \u6f22\u5b57" },
  });
  const header = Buffer.from(`Content-Length: ${Buffer.byteLength(body)}\r\n\r\n`, "ascii");
  const bodyBytes = Buffer.from(body, "utf8");
  const frame = Buffer.concat([header, bodyBytes]);
  const splitAt = header.length + bodyBytes.length - 2;

  server.handleChunk(frame.subarray(0, splitAt));
  assert.equal(output.length, 0);
  server.handleChunk(frame.subarray(splitAt));

  const response = Buffer.concat(output).toString("utf8");
  const payload = JSON.parse(response.slice(response.indexOf("\r\n\r\n") + 4));
  assert.deepEqual(payload, { jsonrpc: "2.0", id: 7, result: {} });
});

test("stdio transport rejects oversized framed messages", () => {
  const output = [];
  const server = createStdioServer({
    tools: [],
    executeTool: async () => ({ ok: true }),
    stdin: { on() {} },
    stdout: { write: (chunk) => output.push(String(chunk)) },
    stderr: { write() {} },
    maxFrameBytes: 24,
  });
  const body = JSON.stringify({ jsonrpc: "2.0", id: 8, method: "ping", params: { pad: "x".repeat(40) } });

  server.handleChunk(`Content-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`);

  const response = output.join("");
  const payload = JSON.parse(response.slice(response.indexOf("\r\n\r\n") + 4));
  assert.equal(payload.jsonrpc, "2.0");
  assert.equal(payload.id, null);
  assert.equal(payload.error.code, -32600);
  assert.match(payload.error.message, /frame exceeds 24 bytes/);
});

test("bob_init_session creates the initial state and bob_read_session_state returns public fields only", () => {
  withTempHome(() => {
    const domain = "example.com";
    const targetUrl = "https://example.com";
    // Cycle D.3 removed state.explored / state.terminally_blocked /
    // state.lead_surface_ids; the lifecycle_state field is the canonical
    // projection of nucleus.lifecycle_state into state.json (D.1 + D.3).
    const expectedState = {
      target: domain,
      target_url: targetUrl,
      deep_mode: false,
      checkpoint_mode: "normal",
      block_internal_hosts: false,
      block_internal_hosts_source: "mode_default",
      phase: "SURFACE_DISCOVERY",
      lifecycle_state: "SETUP",
      evaluation_wave: 0,
      pending_wave: null,
      total_findings: 0,
      prereq_registry_snapshots: [],
      blocked_prereq_history: [],
      terminal_block_clear_history: [],
      dead_ends: [],
      waf_blocked_endpoints: [],
      scope_exclusions: [],
      hold_count: 0,
      auth_status: "pending",
      ...defaultEgressStateFields(),
      operator_note: null,
      verification_schema_version: null,
      verification_attempt_id: null,
      verification_snapshot_hash: null,
      verification_entered_at: null,
      handoff_provenance_required: true,
    };

    const created = JSON.parse(initSession({ target_domain: domain, target_url: targetUrl }));
    assert.deepEqual(created, {
      version: 1,
      created: true,
      session_dir: sessionDir(domain),
      state: expectedState,
    });

    const rawState = JSON.parse(fs.readFileSync(statePath(domain), "utf8"));
    assert.deepEqual(rawState, expectedState);
    const stateResponse = JSON.parse(readSessionState({ target_domain: domain }));
    assert.equal(stateResponse.version, 1);
    assert.deepEqual(stateResponse.state, expectedState);
    // F.2: readSessionState surfaces materialized view hashes when the views
    // exist on disk. init_session emits a session.seeded frontier event which
    // triggers the debounced materializer on outer-lock release, so the views
    // are populated by the time the read returns.
    assert.equal(typeof stateResponse.frontier_view_hashes, "object");
    assert.equal(typeof stateResponse.frontier_view_hashes.surface_index_hash, "string");
    assert.equal(typeof stateResponse.frontier_view_hashes.task_queue_hash, "string");
    assert.match(stateResponse.frontier_view_hashes.surface_index_hash, /^[0-9a-f]{64}$/);
    assert.match(stateResponse.frontier_view_hashes.task_queue_hash, /^[0-9a-f]{64}$/);

    const deepDomain = "deep.example.com";
    const deepCreated = JSON.parse(initSession({
      target_domain: deepDomain,
      target_url: "https://deep.example.com",
      deep_mode: true,
    }));
    assert.equal(deepCreated.state.deep_mode, true);
    assert.equal(JSON.parse(readStateSummary({ target_domain: deepDomain })).state.deep_mode, true);
  });
});

test("bob_init_session rejects existing state and non-empty session dirs", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "SURFACE_DISCOVERY" });
    assert.throws(
      () => initSession({ target_domain: domain, target_url: "https://example.com" }),
      /Session already initialized:/,
    );

    const otherDomain = "example.org";
    const otherDir = sessionDir(otherDomain);
    fs.mkdirSync(otherDir, { recursive: true });
    fs.writeFileSync(path.join(otherDir, "stray.txt"), "x");
    assert.throws(
      () => initSession({ target_domain: otherDomain, target_url: "https://example.org" }),
      /Session directory is not empty:/,
    );
  });
});

test("bob_init_session ignores .session.lock when checking if the session dir is empty", () => {
  withTempHome(() => {
    const domain = "example.com";
    const dir = sessionDir(domain);
    fs.mkdirSync(dir, { recursive: true });
    fs.mkdirSync(sessionLockPath(domain));

    const staleDate = new Date(Date.now() - SESSION_LOCK_STALE_MS - 1_000);
    fs.utimesSync(sessionLockPath(domain), staleDate, staleDate);

    const result = JSON.parse(initSession({ target_domain: domain, target_url: "https://example.com" }));
    assert.equal(result.created, true);
    assert.ok(fs.existsSync(statePath(domain)));
  });
});

test("bob_init_session persists selected-mode internal-host blocking policy", async () => {
  await withTempHome(async () => {
    const normal = await executeTool("bob_init_session", {
      target_domain: "normal.example.com",
      target_url: "https://normal.example.com",
    });
    assert.equal(normal.ok, true);
    assert.equal(normal.data.state.checkpoint_mode, "normal");
    assert.equal(normal.data.state.block_internal_hosts, false);
    assert.equal(normal.data.state.block_internal_hosts_source, "mode_default");

    const yolo = await executeTool("bob_init_session", {
      target_domain: "yolo.example.com",
      target_url: "https://yolo.example.com",
      checkpoint_mode: "yolo",
    });
    assert.equal(yolo.ok, true);
    assert.equal(yolo.data.state.block_internal_hosts, false);
    assert.equal(yolo.data.state.block_internal_hosts_source, "mode_default");

    const paranoid = await executeTool("bob_init_session", {
      target_domain: "paranoid.example.com",
      target_url: "https://paranoid.example.com",
      checkpoint_mode: "paranoid",
    });
    assert.equal(paranoid.ok, true);
    assert.equal(paranoid.data.state.checkpoint_mode, "paranoid");
    assert.equal(paranoid.data.state.block_internal_hosts, true);
    assert.equal(paranoid.data.state.block_internal_hosts_source, "paranoid_default");
    const paranoidSummary = JSON.parse(readStateSummary({ target_domain: "paranoid.example.com" })).state;
    assert.equal(paranoidSummary.block_internal_hosts, true);
    assert.equal(paranoidSummary.block_internal_hosts_source, "paranoid_default");
    const paranoidSessionSummary = JSON.parse(readSessionSummary({ target_domain: "paranoid.example.com" })).summary;
    assert.equal(paranoidSessionSummary.block_internal_hosts, true);

    const allow = await executeTool("bob_init_session", {
      target_domain: "allow.example.com",
      target_url: "https://allow.example.com",
      checkpoint_mode: "paranoid",
      allow_internal_hosts: true,
    });
    assert.equal(allow.ok, true);
    assert.equal(allow.data.state.block_internal_hosts, false);
    assert.equal(allow.data.state.block_internal_hosts_source, "explicit_allow");

    const forced = await executeTool("bob_init_session", {
      target_domain: "forced.example.com",
      target_url: "https://forced.example.com",
      checkpoint_mode: "normal",
      block_internal_hosts: true,
    });
    assert.equal(forced.ok, true);
    assert.equal(forced.data.state.block_internal_hosts, true);
    assert.equal(forced.data.state.block_internal_hosts_source, "explicit_block");

    const conflicting = await executeTool("bob_init_session", {
      target_domain: "conflict.example.com",
      target_url: "https://conflict.example.com",
      block_internal_hosts: true,
      allow_internal_hosts: true,
    });
    assert.equal(conflicting.ok, false);
    assert.equal(conflicting.error.code, "INVALID_ARGUMENTS");
    assert.match(conflicting.error.message, /cannot both be true/);
  });
});

test("bob_init_session rejects proxy-backed sessions that would claim internal-host blocking", async () => {
  await withTempHome(async () => {
    const document = {
      version: 1,
      profiles: [
        egressProfiles.defaultEgressProfile(),
        {
          name: "operator-eu",
          proxy_url: "${BOB_EGRESS_OPERATOR_PROXY}",
          region: "EU",
          description: "Operator egress profile",
          enabled: true,
        },
      ],
    };

    await withDefaultEgressConfig(document, async () => {
      await withEnv({ BOB_EGRESS_OPERATOR_PROXY: "http://proxy.example:8080" }, async () => {
        const rejected = await executeTool("bob_init_session", {
          target_domain: "proxy-paranoid.example.com",
          target_url: "https://proxy-paranoid.example.com",
          checkpoint_mode: "paranoid",
          egress_profile: "operator-eu",
        });
        assert.equal(rejected.ok, false);
        assert.equal(rejected.error.code, "SCOPE_BLOCKED");
        assert.match(rejected.error.message, /block_internal_hosts cannot be enforced with proxy-backed egress_profile "operator-eu"/);
        assert.equal(fs.existsSync(statePath("proxy-paranoid.example.com")), false);

        const allowed = await executeTool("bob_init_session", {
          target_domain: "proxy-allow.example.com",
          target_url: "https://proxy-allow.example.com",
          checkpoint_mode: "paranoid",
          allow_internal_hosts: true,
          egress_profile: "operator-eu",
        });
        assert.equal(allowed.ok, true);
        assert.equal(allowed.data.state.proxy_configured, true);
        assert.equal(allowed.data.state.block_internal_hosts, false);
        assert.equal(allowed.data.state.block_internal_hosts_source, "explicit_allow");
      });
    });
  });
});

test("missing session state errors surface on read and mutating state tools", () => {
  withTempHome(() => {
    const domain = "example.com";

    assert.throws(() => readSessionState({ target_domain: domain }), /Missing session state:/);
    assert.throws(() => transitionPhase({ target_domain: domain, to_phase: "AUTH" }), /Missing session state:/);
    assert.throws(
      () => startWave({ target_domain: domain, wave_number: 1, assignments: [{ agent: "a1", surface_id: "surface-a" }] }),
      /Missing session state:/,
    );
    assert.throws(
      () => applyWaveMerge({ target_domain: domain, wave_number: 1, force_merge: false }),
      /Missing session state:/,
    );
  });
});

test("legacy state normalization is applied while unknown fields remain on disk across writes", () => {
  withTempHome(() => {
    const domain = "example.com";
    writeFileAtomic(statePath(domain), `${JSON.stringify({
      target: "other.com",
      target_url: "https://example.com",
      phase: "SURFACE_DISCOVERY",
      extra_field: "keep-me",
    }, null, 2)}\n`);

    assert.deepEqual(JSON.parse(readSessionState({ target_domain: domain })), {
      version: 1,
      state: {
        target: domain,
        target_url: "https://example.com",
        deep_mode: false,
        checkpoint_mode: "normal",
        block_internal_hosts: false,
        block_internal_hosts_source: "legacy_default",
        phase: "SURFACE_DISCOVERY",
        lifecycle_state: "SETUP",
        evaluation_wave: 0,
        pending_wave: null,
        total_findings: 0,
        prereq_registry_snapshots: [],
        blocked_prereq_history: [],
        terminal_block_clear_history: [],
        dead_ends: [],
        waf_blocked_endpoints: [],
        scope_exclusions: [],
        hold_count: 0,
        auth_status: "pending",
        ...legacyEgressStateFields(),
        operator_note: null,
        verification_schema_version: null,
        verification_attempt_id: null,
        verification_snapshot_hash: null,
        verification_entered_at: null,
        handoff_provenance_required: false,
      },
      // F.2: state.json was hand-written without a frontier-events.jsonl, so
      // the materialized views never produced and frontier_view_hashes is null.
      frontier_view_hashes: null,
    });

    // Cycle D.1 routes the legacy AUTH transition through bob_advance_session.
    // The legacy session has no nucleus on disk; readSessionNucleus synthesizes
    // one from state.json, the advance lands on lifecycle_state OPEN_FRONTIER,
    // and the legacy phase projection in state.json is refreshed to "EVALUATE".
    // unknown-field preservation, target normalization, and the rewritten state
    // all continue to apply.
    JSON.parse(transitionPhase({ target_domain: domain, to_phase: "AUTH" }));
    const rawState = JSON.parse(fs.readFileSync(statePath(domain), "utf8"));
    assert.equal(rawState.extra_field, "keep-me");
    assert.equal(rawState.target, domain);
    assert.equal(rawState.phase, "EVALUATE");
  });
});

test("malformed legacy state hard-fails session reads", () => {
  withTempHome(() => {
    const domain = "example.com";
    writeFileAtomic(statePath(domain), `${JSON.stringify({
      target_url: "https://example.com",
      phase: "BOGUS",
    }, null, 2)}\n`);

    assert.throws(() => readSessionState({ target_domain: domain }), /Malformed session state:/);
  });
});

test("operator note set read and clear works and rejects secret-looking values", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "EVALUATE" });

    const set = JSON.parse(setOperatorNote({
      target_domain: domain,
      operator_note: "Use operator-approved EU egress on the next resume.",
    }));
    assert.equal(set.updated, true);
    assert.equal(set.state.operator_note, "Use operator-approved EU egress on the next resume.");
    assert.equal(
      JSON.parse(readStateSummary({ target_domain: domain })).state.operator_note,
      "Use operator-approved EU egress on the next resume.",
    );

    assert.throws(
      () => setOperatorNote({
        target_domain: domain,
        operator_note: "Authorization: Bearer abcdefghijklmnop",
      }),
      /secrets, auth headers, cookies, or tokens/,
    );

    const cleared = JSON.parse(clearOperatorNote({ target_domain: domain }));
    assert.equal(cleared.cleared, true);
    assert.equal(JSON.parse(readStateSummary({ target_domain: domain })).state.operator_note, null);
  });
});

test("bob_read_session_summary derives compact status without raw proof evidence or report text", () => {
  withTempHome(() => {
    const domain = "summary.example.com";
    const rawPoc = "raw-poc-text-that-must-not-escape";
    const rawEvidence = "raw-evidence-text-that-must-not-escape";
    const fullReport = "full report text that the summary must not include";
    seedSessionState(domain, {
      phase: "REPORT",
      evaluation_wave: 2,
      auth_status: "authenticated",
      operator_note: "Summarize only.",
    });
    seedFinding(domain, {
      proof_of_concept: rawPoc,
      response_evidence: rawEvidence,
    });
    seedVerificationPipeline(domain, [{
      finding_id: "F-1",
      disposition: "confirmed",
      severity: "high",
      reportable: true,
      reasoning: "Confirmed.",
    }]);
    JSON.parse(writeEvidencePacks({
      target_domain: domain,
      packs: [evidencePack("F-1", {
        replay_summary: "Bounded replay returned private metadata.",
        report_snippet: "Private metadata exposure.",
      })],
    }));
    JSON.parse(writeGradeVerdict({
      target_domain: domain,
      verdict: "SUBMIT",
      total_score: 40,
      findings: [{
        finding_id: "F-1",
        impact: 20,
        proof_quality: 10,
        severity_accuracy: 5,
        chain_potential: 0,
        report_quality: 5,
        total_score: 40,
        feedback: null,
      }],
      feedback: null,
    }));
    fs.writeFileSync(reportMarkdownPath(domain), fullReport, "utf8");

    const result = JSON.parse(readSessionSummary({ target_domain: domain }));
    assert.equal(result.version, 1);
    assert.equal(result.summary.target, domain);
    assert.equal(result.summary.phase, "REPORT");
    assert.equal(result.summary.auth_status, "authenticated");
    assert.equal(result.summary.waves_run, 2);
    assert.equal(result.summary.finding_total, 1);
    assert.equal(result.summary.final_reportable_count, 1);
    assert.equal(result.summary.evidence_status.status, "valid");
    assert.equal(result.summary.grade_verdict, "SUBMIT");
    assert.equal(result.summary.report.present, true);
    assert.equal(result.summary.report.path, reportMarkdownPath(domain));
    assert.equal(result.summary.operator_note, "Summarize only.");
    assert.deepEqual(result.summary.blockers, []);
    assert.doesNotMatch(JSON.stringify(result), new RegExp(rawPoc));
    assert.doesNotMatch(JSON.stringify(result), new RegExp(rawEvidence));
    assert.doesNotMatch(JSON.stringify(result), new RegExp(fullReport));
    assert.doesNotMatch(JSON.stringify(result), /representative_samples/);
  });
});

test("bob_read_session_summary aggregates blocked_prereqs by (kind, identifier_hint)", () => {
  withTempHome(() => {
    const domain = "summary-blocked.example.com";
    seedSessionState(domain, {
      phase: "REPORT",
      evaluation_wave: 3,
      terminally_blocked: [
        buildTerminallyBlockedEntry("surface-a", "auth_missing", "attacker", { reason: "no attacker profile registered" }),
        buildTerminallyBlockedEntry("surface-b", "auth_missing", "attacker", { reason: "blocked second surface" }),
        buildTerminallyBlockedEntry("surface-c", "egress_unreachable", null, { reason: "default egress unreachable" }),
      ],
    });
    const summary = JSON.parse(readSessionSummary({ target_domain: domain })).summary;
    assert.equal(summary.blocked_prereqs.total_blocked_surfaces, 3);
    // by_kind ordered by actionability: auth_missing (rank 0) before egress_unreachable (rank 1).
    assert.equal(summary.blocked_prereqs.by_kind[0].kind, "auth_missing");
    assert.equal(summary.blocked_prereqs.by_kind[1].kind, "egress_unreachable");
    const authGroup = summary.blocked_prereqs.by_kind.find((g) => g.kind === "auth_missing" && g.identifier_hint === "attacker");
    assert.ok(authGroup, "expected auth_missing/attacker group");
    assert.equal(authGroup.surface_count, 2);
    assert.deepEqual(authGroup.surface_ids.sort(), ["surface-a", "surface-b"]);
    assert.match(authGroup.latest_reason || "", /blocked second surface|no attacker profile/);
    const egressGroup = summary.blocked_prereqs.by_kind.find((g) => g.kind === "egress_unreachable");
    assert.ok(egressGroup, "expected egress_unreachable group");
    assert.equal(egressGroup.identifier_hint, null);
    assert.equal(egressGroup.surface_count, 1);
  });
});

test("bob_write_chain_attempt records normalized attempts and bob_read_chain_attempts summarizes outcomes", async () => {
  await withTempHome(async () => {
    const domain = "chain-attempt.example.com";
    seedSessionState(domain, { phase: "CHAIN" });
    seedAttackSurfaces(domain, [
      { id: "surface-a", hosts: [`https://${domain}`], priority: "HIGH" },
    ]);
    seedFinding(domain, { title: "IDOR export", endpoint: "/api/export" });
    seedFinding(domain, { title: "OAuth redirect", endpoint: "/oauth/callback" });

    const written = JSON.parse(writeChainAttempt({
      target_domain: domain,
      finding_ids: ["F-1", "F-2"],
      surface_ids: ["surface-a"],
      hypothesis: "F-2 open redirect can capture a token that amplifies F-1 export.",
      steps: [
        "Reviewed finding PoCs and handoff notes.",
        "Replayed redirect with attacker profile and checked whether token material was exposed.",
      ],
      outcome: "denied",
      evidence_summary: "Redirect does not receive token material, so the chain is denied.",
      request_refs: ["http-audit:C-1"],
      auth_profiles: ["attacker"],
    }));

    assert.equal(written.written, true);
    assert.equal(written.attempt_id, "C-1");
    assert.equal(written.summary.total, 1);
    assert.equal(written.summary.by_outcome.denied, 1);
    assert.ok(fs.existsSync(chainAttemptsJsonlPath(domain)));

    const directRead = JSON.parse(readChainAttempts({ target_domain: domain }));
    assert.equal(directRead.attempts.length, 1);
    assert.equal(directRead.summary.terminal_count, 1);
    assert.equal(directRead.summary.has_terminal_attempt, true);
    assert.deepEqual(readChainAttemptsFromJsonl(domain).map((attempt) => attempt.attempt_id), ["C-1"]);

    const envelope = await executeTool("bob_read_chain_attempts", { target_domain: domain });
    assert.equal(envelope.ok, true);
    assert.equal(envelope.data.summary.by_outcome.denied, 1);
  });
});

test("bob_write_chain_attempt rejects malformed references and invalid outcomes", async () => {
  await withTempHome(async () => {
    const domain = "chain-validation.example.com";
    seedSessionState(domain, { phase: "CHAIN" });
    seedAttackSurfaces(domain, [
      { id: "surface-a", hosts: [`https://${domain}`], priority: "HIGH" },
    ]);
    seedFinding(domain, { title: "IDOR export", endpoint: "/api/export" });

    const base = {
      target_domain: domain,
      finding_ids: ["F-1"],
      surface_ids: ["surface-a"],
      hypothesis: "F-1 may combine with another weakness.",
      steps: ["Reviewed evidence and attempted a replay."],
      outcome: "blocked",
      evidence_summary: "Replay was blocked by expired auth.",
    };

    assert.throws(
      () => writeChainAttempt({ ...base, finding_ids: ["finding-1"] }),
      /finding_ids must match F-N/,
    );
    assert.throws(
      () => writeChainAttempt({ ...base, finding_ids: ["F-999"] }),
      /unknown finding_id: F-999/,
    );
    assert.throws(
      () => writeChainAttempt({ ...base, hypothesis: " " }),
      /hypothesis must be a non-empty string/,
    );
    assert.throws(
      () => writeChainAttempt({ ...base, surface_ids: ["surface-missing"] }),
      /unknown surface_id: surface-missing/,
    );

    const invalidOutcome = await executeTool("bob_write_chain_attempt", {
      ...base,
      outcome: "maybe",
    });
    assert.equal(invalidOutcome.ok, false);
    assert.equal(invalidOutcome.error.code, "INVALID_ARGUMENTS");
    assert.match(invalidOutcome.error.message, /outcome must be one of/);

    const wrongDomain = "chain-wrong-domain.example.com";
    appendJsonlLine(chainAttemptsJsonlPath(wrongDomain), {
      version: 1,
      ts: new Date().toISOString(),
      attempt_id: "C-1",
      target_domain: "other.example.com",
      finding_ids: [],
      surface_ids: [],
      hypothesis: "No chain applies.",
      steps: ["Checked candidates."],
      outcome: "not_applicable",
      evidence_summary: "Wrong-domain fixture.",
      request_refs: [],
      auth_profiles: [],
    });
    assert.throws(
      () => readChainAttemptsFromJsonl(wrongDomain),
      /target_domain mismatch/,
    );
  });
});

// Cycle D.1 deleted the bounty_transition_phase / transitionPhase tests
// because the legacy phase FSM and its gating helpers no longer exist; the
// replacement coverage lives in bob_advance_session and lifecycle-gates
// tests. The bounty_transition_phase tool name survives as a registry alias
// that arg-adapts onto bob_advance_session; its dispatch and deprecation
// telemetry are exercised by the registry/dispatch tests.

test("session lock busy blocks mutating tools and stale locks are recoverable", () => {
  withTempHome(() => {
    const domain = "example.com";
    fs.mkdirSync(sessionDir(domain), { recursive: true });
    fs.mkdirSync(sessionLockPath(domain));

    assert.throws(
      () => transitionPhase({ target_domain: domain, to_phase: "AUTH" }),
      new RegExp(`Session lock busy: ${sessionDir(domain).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`),
    );
    assert.throws(
      () => startWave({ target_domain: domain, wave_number: 1, assignments: [{ agent: "a1", surface_id: "surface-a" }] }),
      new RegExp(`Session lock busy: ${sessionDir(domain).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`),
    );
    assert.throws(
      () => applyWaveMerge({ target_domain: domain, wave_number: 1, force_merge: false }),
      new RegExp(`Session lock busy: ${sessionDir(domain).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`),
    );
    assert.throws(
      () => initSession({ target_domain: domain, target_url: "https://example.com" }),
      new RegExp(`Session lock busy: ${sessionDir(domain).replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`),
    );

    const staleDate = new Date(Date.now() - SESSION_LOCK_STALE_MS - 1_000);
    fs.utimesSync(sessionLockPath(domain), staleDate, staleDate);
    const created = JSON.parse(initSession({ target_domain: domain, target_url: "https://example.com" }));
    assert.equal(created.created, true);
  });
});

test("capability routing maps current web surface types to the web pack", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAttackSurfaces(domain, [
      { id: "S-api", surface_type: "api", hosts: [`https://api.${domain}`] },
      { id: "S-graphql", surface_type: "GraphQL", hosts: [`https://app.${domain}`] },
      { id: "S-upload", surface_type: "upload", hosts: [`https://app.${domain}`] },
      { id: "S-billing", surface_type: "billing", hosts: [`https://app.${domain}`] },
      { id: "S-unknown", surface_type: "unknown", hosts: [`https://app.${domain}`] },
      { id: "S-missing", hosts: [`https://app.${domain}`] },
    ]);

    const result = JSON.parse(routeSurfaces({ target_domain: domain }));
    assert.equal(result.routed, true);
    assert.equal(result.surface_count, 6);
    assert.deepEqual(result.counts, { web: 6 });
    assert.equal(result.surface_routes_path, surfaceRoutesPath(domain));

    const routes = JSON.parse(fs.readFileSync(surfaceRoutesPath(domain), "utf8")).routes;
    assert.deepEqual(routes.map((route) => route.capability_pack), Array(6).fill("web"));
    assert.deepEqual(routes.map((route) => route.capability_pack_version), Array(6).fill(1));
    assert.deepEqual(routes.map((route) => route.evaluator_agent), Array(6).fill("evaluator-agent"));
    assert.deepEqual(routes.map((route) => route.brief_profile), Array(6).fill("web"));
    for (const route of routes) {
      assert.deepEqual(route.context_budget, expectedWebContextBudget());
    }
    assert.equal(routes.find((route) => route.surface_id === "S-graphql").surface_type, "graphql");
    assert.deepEqual(routes.find((route) => route.surface_id === "S-api").reasons, ["surface_type:api"]);
    assert.deepEqual(routes.find((route) => route.surface_id === "S-missing").reasons, ["surface_type:missing"]);
  });
});

test("bob_route_surfaces writes bounded current routes and removes stale routes", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAttackSurfaces(domain, [{
      id: "S-1",
      surface_type: "api",
      hosts: [`https://api.${domain}`],
      endpoints: ["/api/private/export?token=secret"],
      evidence: ["large surface-discovery details that should not be copied into surface-routes.json"],
    }]);

    JSON.parse(routeSurfaces({ target_domain: domain }));
    let routeText = fs.readFileSync(surfaceRoutesPath(domain), "utf8");
    assert.doesNotMatch(routeText, /private\/export|large surface-discovery details/);
    assert.deepEqual(JSON.parse(routeText).routes.map((route) => Object.keys(route).sort()), [[
      "brief_profile",
      "capability_pack",
      "capability_pack_version",
      "confidence",
      "context_budget",
      "evaluator_agent",
      "reasons",
      "surface_id",
      "surface_type",
    ]]);

    seedAttackSurfaces(domain, [{ id: "S-2", surface_type: "admin", hosts: [`https://admin.${domain}`] }]);
    const result = JSON.parse(routeSurfaces({ target_domain: domain }));
    routeText = fs.readFileSync(surfaceRoutesPath(domain), "utf8");
    assert.deepEqual(result.counts, { web: 1 });
    assert.deepEqual(JSON.parse(routeText).routes.map((route) => route.surface_id), ["S-2"]);
    assert.doesNotMatch(routeText, /S-1/);
  });
});

test("bob_route_surfaces reports missing or malformed attack surface without writing routes", () => {
  withTempHome(() => {
    const domain = "example.com";
    assert.throws(
      () => routeSurfaces({ target_domain: domain }),
      /Missing attack surface JSON:/,
    );
    assert.equal(fs.existsSync(surfaceRoutesPath(domain)), false);

    fs.mkdirSync(sessionDir(domain), { recursive: true });
    writeFileAtomic(attackSurfacePath(domain), "{bad json");
    assert.throws(
      () => routeSurfaces({ target_domain: domain }),
      /Malformed attack surface JSON:/,
    );
    assert.equal(fs.existsSync(surfaceRoutesPath(domain)), false);
  });
});

test("bob_start_wave validates inputs, writes assignments, and updates pending_wave", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "EVALUATE", evaluation_wave: 1 });
    seedAttackSurface(domain, ["surface-a", "surface-b"]);
    const expectedState = {
      target: domain,
      deep_mode: false,
      checkpoint_mode: "normal",
      block_internal_hosts: false,
      block_internal_hosts_source: "legacy_default",
      phase: "EVALUATE",
      lifecycle_state: "OPEN_FRONTIER",
      evaluation_wave: 1,
      pending_wave: 2,
      total_findings: 0,
      explored_count: 0,
      terminally_blocked_count: 0,
      dead_ends_count: 0,
      waf_blocked_count: 0,
      lead_surface_ids: [],
      hold_count: 0,
      auth_status: "pending",
      ...legacyEgressStateFields(),
      operator_note: null,
      verification_schema_version: null,
      verification_attempt_id: null,
      verification_snapshot_hash: null,
      verification_entered_at: null,
      handoff_provenance_required: false,
    };

    const result = JSON.parse(startWave({
      target_domain: domain,
      wave_number: 2,
      assignments: [
        { agent: "a1", surface_id: "surface-a" },
        { agent: "a2", surface_id: "surface-b" },
      ],
    }));

    assert.deepEqual({
      ...result,
      assignments: result.assignments.map(({ handoff_token, ...assignment }) => {
        assert.match(handoff_token, /^[A-Za-z0-9_-]{32}$/);
        return assignment;
      }),
    }, {
      version: 1,
      started: true,
      wave_number: 2,
      assignments: [
        {
          agent: "a1",
          surface_id: "surface-a",
          capability_pack: "web",
          capability_pack_version: 1,
          evaluator_agent: "evaluator-agent",
          brief_profile: "web",
          context_budget: expectedWebContextBudget(),
          task_lens: "surface_scout",
          budget: expectedTaskBudget(),
        },
        {
          agent: "a2",
          surface_id: "surface-b",
          capability_pack: "web",
          capability_pack_version: 1,
          evaluator_agent: "evaluator-agent",
          brief_profile: "web",
          context_budget: expectedWebContextBudget(),
          task_lens: "surface_scout",
          budget: expectedTaskBudget(),
        },
      ],
      assignments_path: path.join(sessionDir(domain), "wave-2-assignments.json"),
      state: expectedState,
    });
	    const assignmentDoc = JSON.parse(fs.readFileSync(path.join(sessionDir(domain), "wave-2-assignments.json"), "utf8"));
	    assert.equal(assignmentDoc.version, 1);
	    assert.equal(assignmentDoc.handoff_tokens_required, true);
	    assert.equal(assignmentDoc.handoff_provenance_model, HANDOFF_PROVENANCE_MODEL);
	    assert.ok(assignmentDoc.assignments.every((assignment) => /^[a-f0-9]{64}$/.test(assignment.handoff_token_sha256)));
	    assert.ok(assignmentDoc.assignments.every((assignment) => assignment.handoff_token_required === true));
	    assert.ok(assignmentDoc.assignments.every((assignment) => assignment.capability_pack === "web"));
    assert.ok(assignmentDoc.assignments.every((assignment) => assignment.capability_pack_version === 1));
    assert.ok(assignmentDoc.assignments.every((assignment) => assignment.evaluator_agent === "evaluator-agent"));
    assert.ok(assignmentDoc.assignments.every((assignment) => assignment.brief_profile === "web"));
    assert.ok(assignmentDoc.assignments.every((assignment) => assignment.task_lens === "surface_scout"));
    for (const assignment of assignmentDoc.assignments) {
      assert.deepEqual(assignment.context_budget, expectedWebContextBudget());
      assert.deepEqual(assignment.budget, expectedTaskBudget());
	    }
	    assert.equal(fs.existsSync(handoffSigningKeyPath(domain)), true);
	    assert.doesNotMatch(JSON.stringify(assignmentDoc), new RegExp(result.assignments[0].handoff_token));
    assert.deepEqual(
      JSON.parse(fs.readFileSync(surfaceRoutesPath(domain), "utf8")).routes.map((route) => route.surface_id),
      ["surface-a", "surface-b"],
    );
  });
});

test("bob_start_wave rejects invalid state, duplicate inputs, and pre-existing assignment files", () => {
  withTempHome(() => {
    const domain = "example.com";

    // Cycle D.1: phase AUTH maps to lifecycle OPEN_FRONTIER, so the lifecycle
    // gate is satisfied; use a VERIFY-equivalent state to surface the gate
    // failure rather than the downstream missing-assignment file error.
    seedSessionState(domain, { phase: "VERIFY" });
    assert.throws(
      () => startWave({ target_domain: domain, wave_number: 1, assignments: [{ agent: "a1", surface_id: "surface-a" }] }),
      /Wave start requires lifecycle_state OPEN_FRONTIER/,
    );

    seedSessionState(domain, { phase: "EVALUATE", pending_wave: 3 });
    assert.throws(
      () => startWave({ target_domain: domain, wave_number: 4, assignments: [{ agent: "a1", surface_id: "surface-a" }] }),
      /Wave start requires pending_wave null/,
    );

    seedSessionState(domain, { phase: "EVALUATE", evaluation_wave: 1 });
    assert.throws(
      () => startWave({ target_domain: domain, wave_number: 5, assignments: [{ agent: "a1", surface_id: "surface-a" }] }),
      /wave_number must equal evaluation_wave \+ 1/,
    );
    assert.throws(
      () => startWave({
        target_domain: domain,
        wave_number: 2,
        assignments: [
          { agent: "a1", surface_id: "surface-a" },
          { agent: "a1", surface_id: "surface-b" },
        ],
      }),
      /Duplicate assignment for a1/,
    );
    assert.throws(
      () => startWave({
        target_domain: domain,
        wave_number: 2,
        assignments: [
          { agent: "a1", surface_id: "surface-a" },
          { agent: "a2", surface_id: "surface-a" },
        ],
      }),
      /Duplicate surface_id in assignments: surface-a/,
    );
    seedAttackSurface(domain, ["surface-a"]);
    assert.throws(
      () => startWave({ target_domain: domain, wave_number: 2, assignments: [{ agent: "a1", surface_id: "surface-z" }] }),
      /Unknown surface_id in assignments: surface-z/,
    );

    seedAssignments(domain, 2, [{ agent: "a1", surface_id: "surface-a" }]);
    assert.throws(
      () => startWave({ target_domain: domain, wave_number: 2, assignments: [{ agent: "a1", surface_id: "surface-a" }] }),
      /Assignment file already exists:/,
    );
  });
});

test("bob_start_wave rolls back the assignment file if the state write fails", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "EVALUATE", evaluation_wave: 0 });
    seedAttackSurface(domain, ["surface-a"]);

    const originalRenameSync = fs.renameSync;
    fs.renameSync = (from, to) => {
      if (to === statePath(domain)) {
        throw new Error("boom");
      }
      return originalRenameSync(from, to);
    };

    try {
      assert.throws(
        () => startWave({ target_domain: domain, wave_number: 1, assignments: [{ agent: "a1", surface_id: "surface-a" }] }),
        /State write failed after writing assignments; rollback succeeded:/,
      );
    } finally {
      fs.renameSync = originalRenameSync;
    }

    assert.ok(!fs.existsSync(path.join(sessionDir(domain), "wave-1-assignments.json")));
    assert.equal(JSON.parse(fs.readFileSync(statePath(domain), "utf8")).pending_wave, null);
  });
});

test("bob_start_next_wave dry_run plans normal assignments and previews deep promotion without writes", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "EVALUATE", evaluation_wave: 0, deep_mode: true });
    seedAttackSurfaces(domain, [
      { id: "surface-high", hosts: [`https://${domain}`], priority: "HIGH", ranking: { version: 1, score: 70, priority: "HIGH", reasons: [] } },
      { id: "surface-med", hosts: [`https://${domain}`], priority: "MEDIUM", ranking: { version: 1, score: 40, priority: "MEDIUM", reasons: [] } },
    ]);
    JSON.parse(recordSurfaceLeads({
      target_domain: domain,
      source: "test",
      leads: [{
        title: "Dry run lead",
        hosts: [`https://lead.${domain}`],
        endpoints: ["/graphql"],
        confidence: "high",
        score: 88,
      }],
    }));

    const attackBefore = fs.readFileSync(attackSurfacePath(domain), "utf8");
    const leadsBefore = fs.readFileSync(surfaceLeadsPath(domain), "utf8");
    const result = JSON.parse(startNextWave({ target_domain: domain, dry_run: true }));

    assert.equal(result.started, false);
    assert.equal(result.decision, "start_wave");
    assert.equal(result.next_action.kind, "stop");
    assert.deepEqual(result.promotion.would_promote_lead_ids, ["SL-1"]);
    assert.deepEqual(result.promotion.promoted_surface_ids, []);
    assert.deepEqual(result.plan.assignments, [
      { agent: "a1", surface_id: "surface-high", task_lens: "surface_scout", budget: expectedTaskBudget() },
      { agent: "a2", surface_id: "surface-med", task_lens: "surface_scout", budget: expectedTaskBudget() },
    ]);
    assert.equal(result.assignments, undefined);
    assert.equal(fs.readFileSync(attackSurfacePath(domain), "utf8"), attackBefore);
    assert.equal(fs.readFileSync(surfaceLeadsPath(domain), "utf8"), leadsBefore);
    assert.equal(fs.existsSync(surfaceRoutesPath(domain)), false);
    assert.equal(fs.existsSync(path.join(sessionDir(domain), "wave-1-assignments.json")), false);
    assert.equal(JSON.parse(fs.readFileSync(statePath(domain), "utf8")).pending_wave, null);
  });
});

test("bob_start_next_wave promotes deep leads, re-ranks, starts a wave, and attributes the event source", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "EVALUATE", evaluation_wave: 0, deep_mode: true });
    seedAttackSurfaces(domain, [
      { id: "surface-low", hosts: [`https://${domain}`], priority: "LOW" },
    ]);
    JSON.parse(recordSurfaceLeads({
      target_domain: domain,
      source: "test",
      leads: [{
        title: "Promoted Admin API",
        hosts: [`https://admin.${domain}`],
        endpoints: ["/api/admin/users"],
        priority: "HIGH",
        surface_type: "admin",
        confidence: "high",
        score: 91,
      }],
    }));

    const result = JSON.parse(startNextWave({ target_domain: domain }));
    assert.equal(result.started, true);
    assert.equal(result.decision, "start_wave");
    assert.equal(result.wave_number, 1);
    assert.equal(result.next_action.kind, "spawn_evaluators");
    assert.equal(result.next_action.assignments, undefined);
    assert.deepEqual(result.promotion.would_promote_lead_ids, ["SL-1"]);
    assert.deepEqual(result.promotion.promoted_surface_ids, ["lead-promoted-admin-api"]);
    assert.deepEqual(result.state.lead_surface_ids, ["lead-promoted-admin-api"]);
    assert.equal(result.assignments[0].surface_id, "lead-promoted-admin-api");
    assert.match(result.assignments[0].handoff_token, /^[A-Za-z0-9_-]{32}$/);

    // Cycle D.3: promotion writes the new surface to surface-index.json
    // (materialized from frontier.surface.observed events). attack_surface.json
    // is no longer mutated by the promotion path.
    const surfaceIndex = JSON.parse(fs.readFileSync(surfaceIndexPath(domain), "utf8"));
    assert.ok(surfaceIndex.surfaces.some((surface) => surface.surface_id === "lead-promoted-admin-api"));
    const leads = JSON.parse(readSurfaceLeads({ target_domain: domain, limit: 10 }));
    assert.equal(leads.leads[0].status, "promoted");

    const routes = JSON.parse(fs.readFileSync(surfaceRoutesPath(domain), "utf8"));
    assert.ok(routes.routes.some((route) => route.surface_id === "lead-promoted-admin-api"));
    const events = JSON.parse(readPipelineAnalytics({ target_domain: domain, include_events: true })).events;
    const startedEvent = events.find((event) => event.type === "wave_started");
    assert.equal(startedEvent.source, "bob_start_next_wave");
    assert.equal(startedEvent.started_by, "bob_start_next_wave");
  });
});

test("bob_start_next_wave returns settle and no-candidate decisions without writing", () => {
  withTempHome(() => {
    const pendingDomain = "pending.example";
    seedSessionState(pendingDomain, { phase: "EVALUATE", evaluation_wave: 0, pending_wave: 1 });
    seedAttackSurface(pendingDomain, ["surface-a"]);
    const pendingBefore = fs.readFileSync(statePath(pendingDomain), "utf8");
    const pending = JSON.parse(startNextWave({ target_domain: pendingDomain }));
    assert.equal(pending.started, false);
    assert.equal(pending.decision, "pending_wave_settle");
    assert.deepEqual(pending.next_action, {
      kind: "call_tool",
      tool: "bob_apply_wave_merge",
      arguments: {
        target_domain: pendingDomain,
        wave_number: 1,
        force_merge: false,
      },
    });
    assert.equal(fs.readFileSync(statePath(pendingDomain), "utf8"), pendingBefore);
    assert.equal(fs.existsSync(path.join(sessionDir(pendingDomain), "wave-2-assignments.json")), false);

    const emptyDomain = "empty.example";
    seedSessionState(emptyDomain, { phase: "EXPLORE", evaluation_wave: 2, explored: ["surface-a"] });
    seedAttackSurface(emptyDomain, ["surface-a"]);
    const emptyBefore = fs.readFileSync(statePath(emptyDomain), "utf8");
    const empty = JSON.parse(startNextWave({ target_domain: emptyDomain }));
    assert.equal(empty.started, false);
    assert.equal(empty.decision, "no_assignable_candidates");
    assert.equal(empty.next_action.kind, "stop");
    assert.match(empty.next_action.reason, /phase decisions belong to the orchestrator/i);
    assert.equal(fs.readFileSync(statePath(emptyDomain), "utf8"), emptyBefore);
    assert.equal(fs.existsSync(surfaceRoutesPath(emptyDomain)), false);
  });
});

test("bob_start_next_wave rolls back promotion artifacts if wave start state write fails", () => {
  withTempHome(() => {
    const domain = "rollback.example";
    seedSessionState(domain, { phase: "EVALUATE", evaluation_wave: 0, deep_mode: true });
    seedAttackSurface(domain, ["surface-a"]);
    JSON.parse(recordSurfaceLeads({
      target_domain: domain,
      source: "test",
      leads: [{
        title: "Rollback Lead",
        hosts: [`https://lead.${domain}`],
        endpoints: ["/api/rollback"],
        confidence: "high",
        score: 90,
      }],
    }));
    const attackBefore = fs.readFileSync(attackSurfacePath(domain), "utf8");
    const leadsBefore = fs.readFileSync(surfaceLeadsPath(domain), "utf8");

    const originalRenameSync = fs.renameSync;
    fs.renameSync = (from, to) => {
      if (to === statePath(domain)) {
        throw new Error("boom");
      }
      return originalRenameSync(from, to);
    };

    try {
      assert.throws(
        () => startNextWave({ target_domain: domain }),
        /State write failed after writing assignments; rollback succeeded:/,
      );
    } finally {
      fs.renameSync = originalRenameSync;
    }

    assert.equal(fs.readFileSync(attackSurfacePath(domain), "utf8"), attackBefore);
    assert.equal(fs.readFileSync(surfaceLeadsPath(domain), "utf8"), leadsBefore);
    assert.equal(fs.existsSync(surfaceRoutesPath(domain)), false);
    assert.equal(fs.existsSync(path.join(sessionDir(domain), "wave-1-assignments.json")), false);
    assert.equal(JSON.parse(fs.readFileSync(statePath(domain), "utf8")).pending_wave, null);
  });
});

test("bob_apply_wave_merge returns pending without mutating state when handoffs are incomplete", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "EVALUATE", pending_wave: 1 });
    seedAssignments(domain, 1, [
      { agent: "a1", surface_id: "surface-a" },
      { agent: "a2", surface_id: "surface-b" },
    ]);
    writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "A1 complete.",
      content: "# A1",
    });

    const before = fs.readFileSync(statePath(domain), "utf8");
    const result = JSON.parse(applyWaveMerge({
      target_domain: domain,
      wave_number: 1,
      force_merge: false,
    }));

    assert.deepEqual(result, {
      version: 1,
      status: "pending",
      wave_number: 1,
      force_merge: false,
      readiness: {
        assignments_total: 2,
        handoffs_total: 1,
        received_agents: ["a1"],
        missing_agents: ["a2"],
        invalid_agents: [],
        unexpected_agents: [],
        is_complete: false,
      },
      state: JSON.parse(readStateSummary({ target_domain: domain })).state,
    });
    assert.equal(fs.readFileSync(statePath(domain), "utf8"), before);
  });
});

function setStatePendingWave(domain, waveNumber) {
  const stateFilePath = statePath(domain);
  const stateDoc = JSON.parse(fs.readFileSync(stateFilePath, "utf8"));
  stateDoc.pending_wave = waveNumber;
  fs.writeFileSync(stateFilePath, JSON.stringify(stateDoc, null, 2) + "\n");
}

function seedPrereqSnapshot(domain, wave, { auth_handles = [], egress_handles = [] } = {}) {
  const stateFilePath = statePath(domain);
  const stateDoc = JSON.parse(fs.readFileSync(stateFilePath, "utf8"));
  stateDoc.prereq_registry_snapshots = [
    ...((stateDoc.prereq_registry_snapshots || []).filter((s) => s.wave !== wave)),
    { wave, auth_handles, egress_handles },
  ].sort((a, b) => a.wave - b.wave);
  fs.writeFileSync(stateFilePath, JSON.stringify(stateDoc, null, 2) + "\n");
}

function buildTerminallyBlockedEntry(surfaceId, kind, identifierHint, options = {}) {
  return {
    surface_id: surfaceId,
    blocked_at_wave: options.blocked_at_wave || 2,
    blockers: [
      {
        kind,
        ...(identifierHint != null ? { identifier_hint: identifierHint } : {}),
        ...(options.reason ? { reason: options.reason } : {}),
      },
    ],
  };
}

test("compactSessionState exposes terminally_blocked_count derived from frontier blocker projection", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, {
      phase: "EVALUATE",
      evaluation_wave: 1,
    });
    // Cycle D.3 moved blocker authority to frontier-events.jsonl; the
    // terminally_blocked_count surfaced by compactSessionState now folds
    // blocker.asserted events with the surface-state markers.
    const { appendFrontierEvent } = require("../mcp/lib/frontier-events.js");
    appendFrontierEvent({
      target_domain: domain,
      kind: "blocker.asserted",
      surface_id: "surface-a",
      payload: { terminally_blocked: true, kind: "auth_missing", identifier_hint: "attacker", reason: "no attacker profile registered" },
      source: { artifact: "wave-merge", tool: "bob_apply_wave_merge" },
    });
    appendFrontierEvent({
      target_domain: domain,
      kind: "blocker.asserted",
      surface_id: "surface-b",
      payload: { terminally_blocked: true, kind: "egress_unreachable", reason: "default egress unreachable" },
      source: { artifact: "wave-merge", tool: "bob_apply_wave_merge" },
    });
    const summary = JSON.parse(readStateSummary({ target_domain: domain }));
    assert.equal(summary.state.terminally_blocked_count, 2);
  });
});

test("compactSessionState reports terminally_blocked_count: 0 when the frontier projection is empty", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "EVALUATE", evaluation_wave: 1 });
    const summary = JSON.parse(readStateSummary({ target_domain: domain }));
    assert.equal(summary.state.terminally_blocked_count, 0);
  });
});

test("normalizeSessionStateDocument silently drops legacy explored / terminally_blocked / lead_surface_ids", () => {
  withTempHome(() => {
    const domain = "example.com";
    // Cycle D.3 removed these fields from the contract; legacy fixtures
    // routing the arrays through seedSessionState get them translated
    // into frontier events instead. The normalized state.json no longer
    // exposes the deleted fields.
    seedSessionState(domain, {
      phase: "EVALUATE",
      evaluation_wave: 1,
      explored: ["surface-a"],
      terminally_blocked: [
        buildTerminallyBlockedEntry("surface-b", "auth_missing", "attacker"),
      ],
      lead_surface_ids: ["surface-c"],
    });
    // Provide a materialized surface so currentLeadSurfaceIds' attack-surface
    // membership filter accepts the seeded lead.
    seedAttackSurface(domain, ["surface-c"]);
    const response = JSON.parse(readStateSummary({ target_domain: domain }));
    assert.ok(!Object.prototype.hasOwnProperty.call(response.state, "explored"));
    assert.ok(!Object.prototype.hasOwnProperty.call(response.state, "terminally_blocked"));
    // lead_surface_ids in the compact summary derives from the frontier
    // projection; the seeded lead is visible once the surface is in the
    // materialized projection.
    assert.deepEqual(response.state.lead_surface_ids, ["surface-c"]);
  });
});

test("computeOpenRequeueSurfaceIds excludes terminally_blocked surfaces (options-bag signature)", () => {
  const { computeOpenRequeueSurfaceIds } = require("../mcp/lib/frontier-readiness.js");
  const records = [
    { surface_id: "surface-a", endpoint: "GET /a", status: "requeue", logged_at: "2026-05-02T00:00:00Z", wave: "w1", agent: "a1" },
    { surface_id: "surface-b", endpoint: "GET /b", status: "requeue", logged_at: "2026-05-02T00:00:00Z", wave: "w1", agent: "a1" },
    { surface_id: "surface-c", endpoint: "GET /c", status: "needs_auth", logged_at: "2026-05-02T00:00:00Z", wave: "w1", agent: "a1" },
  ];
  const result = computeOpenRequeueSurfaceIds(records, {
    exploredSurfaceIds: ["surface-a"],
    terminallyBlockedSurfaceIds: ["surface-c"],
  });
  assert.deepEqual(result, ["surface-b"]);
});

test("EVALUATE -> CHAIN gate exposes blocked_high_surface_ids and blocks transition on it", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAttackSurfaces(domain, [
      { id: "surface-a", hosts: [`https://${domain}`], priority: "HIGH" },
      { id: "surface-b", hosts: [`https://${domain}`], priority: "HIGH" },
      { id: "surface-c", hosts: [`https://${domain}`], priority: "HIGH" },
    ]);
    seedSessionState(domain, {
      phase: "EVALUATE",
      evaluation_wave: 1,
      explored: ["surface-a"],
      terminally_blocked: [
        buildTerminallyBlockedEntry("surface-b", "auth_missing", "attacker", { reason: "no profile" }),
      ],
    });
    const { computeFrontierReadiness } = require("../mcp/lib/frontier-readiness.js");
    const fullState = JSON.parse(fs.readFileSync(statePath(domain), "utf8"));
    const gate = computeFrontierReadiness(domain, fullState);
    assert.equal(gate.coverage.non_low_explored, 1);
    assert.equal(gate.coverage.non_low_terminally_blocked, 1);
    assert.equal(gate.coverage.non_low_closed, 2);
    assert.deepEqual(gate.coverage.unexplored_high_surface_ids, ["surface-c"]);
    assert.deepEqual(gate.coverage.blocked_high_surface_ids, ["surface-b"]);
    assert.equal(gate.coverage.coverage_pct, 33);
    assert.equal(gate.coverage.closed_pct, 67);
    // Both unexplored and blocked HIGH surfaces produce distinct blockers.
    const codes = gate.transition_blockers.map((b) => b.code);
    assert.ok(codes.includes("unexplored_high_surfaces"), "expected unexplored_high_surfaces blocker");
    assert.ok(codes.includes("blocked_high_surfaces"), "expected blocked_high_surfaces blocker");
  });
});

test("bob_start_wave rejects assignment of terminally_blocked surfaces", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAttackSurface(domain, ["surface-a", "surface-b"]);
    seedSessionState(domain, {
      phase: "EVALUATE",
      evaluation_wave: 1,
      terminally_blocked: [
        buildTerminallyBlockedEntry("surface-a", "auth_missing", "attacker", { reason: "missing" }),
      ],
    });
    assert.throws(() => startWave({
      target_domain: domain,
      wave_number: 2,
      assignments: [
        { agent: "a1", surface_id: "surface-a" },
        { agent: "a2", surface_id: "surface-b" },
      ],
    }), /Cannot assign terminally-blocked surfaces.*surface-a/);
  });
});

test("bob_apply_wave_merge adds surface_status: complete surfaces to state.explored even when coverage rows are unfinished", () => {
  // The structured handoff is the contract. Coverage rows are advisory
  // history. A evaluator that wrote `surface_status: complete` AND has stale
  // unfinished coverage rows for the same wave is internally inconsistent,
  // but the merge layer trusts the handoff — silently downgrading
  // complete to "still requeued" stranded the surface in EVALUATE forever
  // (the veda.tech regression).
  withTempHome(() => {
    const domain = "trust-handoff.example.com";
    seedSessionState(domain, {
      phase: "EVALUATE",
      pending_wave: 1,
    });
    seedAttackSurface(domain, ["surface-a"]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    logCoverage({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      entries: [{
        endpoint: "/api/legacy",
        method: "GET",
        bug_class: "idor",
        status: "requeue",
        evidence_summary: "endpoint-level requeue logged earlier in the wave",
      }],
    });
    writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "Surface tested; one endpoint marked requeue while triaging others, then closed.",
      content: "# A1",
    });

    const result = JSON.parse(applyWaveMerge({
      target_domain: domain,
      wave_number: 1,
      force_merge: false,
    }));
    assert.equal(result.status, "merged");
    assert.equal(result.state.explored_count, 1);
    // Verify the surface landed in the frontier closure projection (D.3).
    const { currentClosures } = require("../mcp/lib/frontier-projections.js");
    assert.deepEqual(currentClosures(domain).map((c) => c.surface_id), ["surface-a"]);
  });
});

test("bob_apply_wave_merge merges state, findings, requeues, and scope exclusions", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, {
      phase: "EVALUATE",
      pending_wave: 1,
      dead_ends: ["/existing"],
      waf_blocked_endpoints: ["/old-waf"],
      lead_surface_ids: ["surface-c"],
    });
    seedAssignments(domain, 1, [
      { agent: "a1", surface_id: "surface-a" },
      { agent: "a2", surface_id: "surface-b" },
    ]);
    seedAttackSurface(domain, ["surface-a", "surface-b", "surface-c", "surface-d"]);

    writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "A1 complete.",
      content: "# A1",
      dead_ends: ["/new-dead-end"],
      lead_surface_ids: ["surface-a", "surface-c"],
    });
    writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a2",
      surface_id: "surface-b",
      surface_status: "partial",
      summary: "A2 partial.",
      content: "# A2",
      waf_blocked_endpoints: ["/new-waf"],
      lead_surface_ids: ["surface-d", "surface-x"],
    });

    seedFinding(domain, { wave: "w1", agent: "a1", severity: "high" });
    seedFinding(domain, {
      wave: "w1",
      agent: "a2",
      title: "Verbose stack trace leak",
      severity: "low",
      endpoint: "/boom",
      description: "Exception page leaks internal paths.",
      proof_of_concept: "curl https://example.com/boom",
      response_evidence: "ReferenceError",
      impact: "Improves proof development.",
    });

    fs.writeFileSync(path.join(sessionDir(domain), "scope-warnings.log"), [
      "[2026-01-01T00:00:00Z] OUT-OF-SCOPE: OOS.example.net (command: curl https://OOS.example.net)",
      "[2026-01-01T00:00:01Z] OUT-OF-SCOPE (http_scan): api.other.example (url: https://api.other.example/admin)",
    ].join("\n"));

    const result = JSON.parse(applyWaveMerge({
      target_domain: domain,
      wave_number: 1,
      force_merge: false,
    }));

    assert.deepEqual(result.readiness, {
      assignments_total: 2,
      handoffs_total: 2,
      received_agents: ["a1", "a2"],
      missing_agents: [],
      invalid_agents: [],
      unexpected_agents: [],
      is_complete: true,
    });
	    assert.deepEqual(result.merge, {
	      received_agents: ["a1", "a2"],
	      invalid_agents: [],
	      invalid_handoffs: [],
	      unexpected_agents: [],
      completed_surface_ids: ["surface-a"],
      partial_surface_ids: ["surface-b"],
      missing_surface_ids: [],
      requeue_surface_ids: ["surface-b"],
      new_dead_ends_count: 1,
      new_waf_blocked_count: 1,
      lead_surface_ids: ["surface-a", "surface-c", "surface-d", "surface-x"],
      blocked_harness_runs: [],
      blocked_harness_runs_grouped: [],
      blocked_prereqs: [],
      blocked_prereqs_grouped: [],
      terminally_blocked_promoted: [],
      bypass_attempts: [],
      bypass_attempts_grouped: [],
      suspicion_flags: [],
      provenance: {
        verified_agents: ["a1", "a2"],
      },
    });
    assert.deepEqual(result.findings, {
      total: 2,
      by_severity: { critical: 0, high: 1, medium: 0, low: 1, info: 0 },
      has_high_or_critical: true,
    });
    // compact state returns counts, not arrays — verify via full state read
    assert.equal(result.state.explored_count, 1);
    assert.equal(result.state.dead_ends_count, 2);
    assert.equal(result.state.waf_blocked_count, 2);
    assert.deepEqual(result.state.lead_surface_ids, ["surface-c", "surface-d"]);
    assert.equal(result.state.pending_wave, null);
    assert.equal(result.state.evaluation_wave, 1);
    assert.equal(result.state.total_findings, 2);
    // verify state.json (D.3 removed state.explored / state.terminally_blocked
    // / state.lead_surface_ids; arrays for dead_ends, waf, scope still live).
    const fullState = JSON.parse(readSessionState({ target_domain: domain })).state;
    assert.deepEqual(fullState.dead_ends, ["/existing", "/new-dead-end"]);
    assert.deepEqual(fullState.waf_blocked_endpoints, ["/old-waf", "/new-waf"]);
    assert.deepEqual(fullState.scope_exclusions, ["oos.example.net", "api.other.example"]);
    assert.deepEqual(readScopeExclusions(domain), ["oos.example.net", "api.other.example"]);
    // explored / terminally_blocked / lead_surface_ids are absent from state.json.
    assert.ok(!Object.prototype.hasOwnProperty.call(fullState, "explored"));
    assert.ok(!Object.prototype.hasOwnProperty.call(fullState, "terminally_blocked"));
    // The frontier projection now sources surface state; verify the closure
    // event landed in the ledger.
    const { currentClosures } = require("../mcp/lib/frontier-projections.js");
    const closures = currentClosures(domain);
    assert.deepEqual(closures.map((c) => c.surface_id), ["surface-a"]);
  });
});

test("surface leads are compact, promotable, and wave assignable", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "EVALUATE", deep_mode: true });
    seedAttackSurfaces(domain, [
      {
        id: "surface-a",
        hosts: [`https://${domain}`],
        tech_stack: [],
        endpoints: [],
        interesting_params: [],
        nuclei_hits: [],
        priority: "LOW",
      },
    ]);

    const recorded = JSON.parse(recordSurfaceLeads({
      target_domain: domain,
      source: "test",
      leads: [{
        title: "Admin API from JS bundle",
        hosts: [`https://admin.${domain}`],
        endpoints: ["/api/admin/users?account_id=1"],
        interesting_params: ["account_id"],
        tech_stack: ["Next.js"],
        priority: "HIGH",
        surface_type: "admin",
        bug_class_hints: ["idor", "authz"],
        high_value_flows: ["admin", "exports"],
        evidence: ["JS bundle references /api/admin/users?account_id="],
        confidence: "high",
        score: 86,
      }],
    }));
    assert.equal(recorded.recorded, 1);
    assert.ok(fs.existsSync(surfaceLeadsPath(domain)));

    const leads = JSON.parse(readSurfaceLeads({ target_domain: domain, limit: 5 }));
    assert.equal(leads.total, 1);
    assert.equal(leads.high_confidence_unpromoted, 1);
    assert.equal(leads.leads[0].id, "SL-1");

    const promoted = JSON.parse(promoteSurfaceLeads({ target_domain: domain, limit: 3, min_score: 60 }));
    assert.deepEqual(promoted.promoted_surface_ids, ["lead-admin-api-from-js-bundle"]);
    const promotedSurfaceId = promoted.promoted_surface_ids[0];
    const state = JSON.parse(readStateSummary({ target_domain: domain })).state;
    assert.deepEqual(state.lead_surface_ids, [promotedSurfaceId]);

    // Cycle D.3: surface-index.json (materialized from frontier.surface.observed
    // events) is the authoritative surface set after promotion. attack_surface.json
    // is no longer mutated by the promotion path.
    const surfaceIndex = JSON.parse(fs.readFileSync(surfaceIndexPath(domain), "utf8"));
    assert.ok(surfaceIndex.surfaces.some((surface) => surface.surface_id === promotedSurfaceId));
    const started = JSON.parse(startWave({
      target_domain: domain,
      wave_number: 1,
      assignments: [{ agent: "a1", surface_id: promotedSurfaceId }],
    }));
    assert.equal(started.assignments[0].surface_id, promotedSurfaceId);
  });
});

test("explicit medium surface lead promotion stays MEDIUM while becoming wave assignable", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "EVALUATE", deep_mode: true });
    seedAttackSurfaces(domain, [
      {
        id: "surface-a",
        hosts: [`https://${domain}`],
        tech_stack: [],
        endpoints: [],
        interesting_params: [],
        nuclei_hits: [],
        priority: "LOW",
      },
    ]);

    const recorded = JSON.parse(recordSurfaceLeads({
      target_domain: domain,
      source: "test",
      leads: [{
        title: "Brand-linked sibling properties lightly probed",
        hosts: ["https://brand-example.com"],
        priority: "MEDIUM",
        surface_type: "unknown",
        evidence: ["https://brand-example.com [200] [Cloudflare] Brand login"],
        confidence: "medium",
        score: 55,
        promote: true,
      }],
    }));
    assert.equal(recorded.recorded, 1);

    const promoted = JSON.parse(promoteSurfaceLeads({ target_domain: domain, limit: 3, min_score: 60 }));
    assert.equal(promoted.promoted, 1);
    assert.deepEqual(promoted.promoted_surface_ids, ["lead-brand-linked-sibling-properties-lightly-probed"]);
    const promotedSurfaceId = promoted.promoted_surface_ids[0];

    const state = JSON.parse(readStateSummary({ target_domain: domain })).state;
    assert.deepEqual(state.lead_surface_ids, [promotedSurfaceId]);

    // Cycle D.3: surface-index.json (materialized from frontier events) is the
    // authoritative surface set after promotion; priority is captured into the
    // materialized projection. The original lead score persists on
    // surface-leads.json (the intake projection); ranking is recomputed on read.
    const surfaceIndex = JSON.parse(fs.readFileSync(surfaceIndexPath(domain), "utf8"));
    const promotedSurface = surfaceIndex.surfaces.find((surface) => surface.surface_id === promotedSurfaceId);
    assert.ok(promotedSurface);
    assert.equal(promotedSurface.priority, "MEDIUM");
    const promotedLead = JSON.parse(readSurfaceLeads({ target_domain: domain, limit: 10 }))
      .leads.find((lead) => lead.promoted_surface_id === promotedSurfaceId);
    assert.ok(promotedLead);
    assert.equal(promotedLead.score, 55);
  });
});

test("unassignable high-confidence surface leads are not promoted or counted as deep lead debt", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "EVALUATE", deep_mode: true });
    seedAttackSurfaces(domain, [
      {
        id: "surface-a",
        hosts: [`https://${domain}`],
        tech_stack: [],
        endpoints: [],
        interesting_params: [],
        nuclei_hits: [],
        priority: "LOW",
      },
    ]);

    const recorded = JSON.parse(recordSurfaceLeads({
      target_domain: domain,
      source: "test",
      leads: [{
        title: "Vague external research note",
        evidence: ["High confidence prose without an assignable host or endpoint."],
        confidence: "high",
        score: 95,
        promote: true,
      }],
    }));
    assert.equal(recorded.recorded, 1);

    const leads = JSON.parse(readSurfaceLeads({ target_domain: domain, limit: 5 }));
    assert.equal(leads.total, 1);
    assert.equal(leads.high_confidence_unpromoted, 0);

    const promoted = JSON.parse(promoteSurfaceLeads({ target_domain: domain, limit: 3, min_score: 60 }));
    assert.deepEqual(promoted.promoted_surface_ids, []);
    assert.equal(promoted.promoted, 0);

    const attackSurface = JSON.parse(fs.readFileSync(attackSurfacePath(domain), "utf8"));
    assert.deepEqual(attackSurface.surfaces.map((surface) => surface.id), ["surface-a"]);

    const status = JSON.parse(waveStatus({ target_domain: domain }));
    assert.deepEqual(status.surface_leads, {
      total: 1,
      high_confidence_unpromoted: 0,
      promoted: 0,
    });
    assert.deepEqual(status.transition_blockers, []);
  });
});

test("bob_write_wave_handoff persists evaluator surface_leads through the session lock", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAssignments(domain, 1, [
      { agent: "a1", surface_id: "surface-a" },
      { agent: "a2", surface_id: "surface-b" },
    ]);

    const release = acquireSessionLock(domain);
    try {
      assert.throws(
        () => writeWaveHandoff({
          target_domain: domain,
          wave: "w1",
          agent: "a1",
          surface_id: "surface-a",
          surface_status: "complete",
          summary: "a1 complete",
          content: "# a1",
          surface_leads: [{
            title: "Locked lead should not be written",
            hosts: [`https://locked.${domain}`],
            confidence: "high",
            score: 80,
          }],
        }),
        /Session lock busy/,
      );
    } finally {
      release();
    }
    assert.ok(!fs.existsSync(path.join(sessionDir(domain), "handoff-w1-a1.json")));
    assert.equal(fs.existsSync(surfaceLeadsPath(domain)), false);

    const first = JSON.parse(writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "a1 complete",
      content: "# a1",
      surface_leads: [{
        title: "Admin API from a1",
        hosts: [`https://admin.${domain}`],
        endpoints: ["/api/admin/users"],
        confidence: "high",
        score: 82,
      }],
    }));
    const second = JSON.parse(writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a2",
      surface_id: "surface-b",
      surface_status: "complete",
      summary: "a2 complete",
      content: "# a2",
      surface_leads: [{
        title: "Billing API from a2",
        hosts: [`https://billing.${domain}`],
        endpoints: ["/api/billing/invoices"],
        confidence: "high",
        score: 81,
      }],
    }));

    assert.deepEqual(first.surface_lead_ids, ["SL-1"]);
    assert.deepEqual(second.surface_lead_ids, ["SL-2"]);

    const leads = JSON.parse(readSurfaceLeads({ target_domain: domain, limit: 10 }));
    assert.equal(leads.total, 2);
    assert.deepEqual(
      leads.leads.map((lead) => lead.title).sort(),
      ["Admin API from a1", "Billing API from a2"],
    );
    assert.deepEqual(
      JSON.parse(fs.readFileSync(path.join(sessionDir(domain), "handoff-w1-a1.json"), "utf8")).surface_lead_ids,
      ["SL-1"],
    );
    assert.deepEqual(
      JSON.parse(fs.readFileSync(path.join(sessionDir(domain), "handoff-w1-a2.json"), "utf8")).surface_lead_ids,
      ["SL-2"],
    );
  });
});

test("deep wave merge records handoff surface leads but leaves automatic promotion to bob_start_next_wave", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "EVALUATE", pending_wave: 1, deep_mode: true });
    seedAttackSurface(domain, ["surface-a"]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);

    writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "Found sibling GraphQL lead.",
      content: "# A1",
      surface_leads: [{
        title: "Sibling GraphQL API",
        hosts: [`https://api.${domain}`],
        endpoints: ["/graphql"],
        priority: "HIGH",
        surface_type: "graphql",
        bug_class_hints: ["graphql", "authz"],
        evidence: ["Assigned surface links to api.example.com/graphql"],
        confidence: "high",
        score: 78,
      }],
    });

    const merged = JSON.parse(applyWaveMerge({
      target_domain: domain,
      wave_number: 1,
      force_merge: false,
    }));
    assert.equal(merged.merge.deep_promoted_surface_ids, undefined);
    assert.deepEqual(merged.state.lead_surface_ids, []);
    const leads = JSON.parse(readSurfaceLeads({ target_domain: domain, limit: 5 }));
    assert.equal(leads.high_confidence_unpromoted, 1);
    assert.equal(leads.leads[0].status, "new");
  });
});

test("bob_apply_wave_merge requeues unfinished coverage without treating tested or blocked as unfinished", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "EVALUATE", pending_wave: 1 });
    seedAssignments(domain, 1, [
      { agent: "a1", surface_id: "surface-a" },
      { agent: "a2", surface_id: "surface-b" },
      { agent: "a3", surface_id: "surface-c" },
      { agent: "a4", surface_id: "surface-d" },
      { agent: "a5", surface_id: "surface-e" },
    ]);
    seedAttackSurface(domain, ["surface-a", "surface-b", "surface-c", "surface-d", "surface-e"]);

    logCoverage({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      entries: [{
        endpoint: "/api/v1/export",
        method: "GET",
        bug_class: "idor",
        auth_profile: "attacker-victim",
        status: "promising",
        evidence_summary: "victim replay changed response size",
        next_step: "test CSV export variant",
      }],
    });
    logCoverage({
      target_domain: domain,
      wave: "w1",
      agent: "a2",
      surface_id: "surface-b",
      entries: [
        {
          endpoint: "/api/v1/users/123",
          method: "GET",
          bug_class: "idor",
          status: "promising",
          evidence_summary: "initial IDOR suspicion",
        },
        {
          endpoint: "/api/v1/users/123",
          method: "GET",
          bug_class: "idor",
          status: "tested",
          evidence_summary: "latest replay returned 403 for attacker and victim",
        },
      ],
    });
    logCoverage({
      target_domain: domain,
      wave: "w1",
      agent: "a3",
      surface_id: "surface-c",
      entries: [{
        endpoint: "/search",
        method: "POST",
        bug_class: "xss",
        status: "blocked",
        evidence_summary: "WAF blocks reflected payloads",
      }],
    });
    logCoverage({
      target_domain: domain,
      wave: "w1",
      agent: "a4",
      surface_id: "surface-d",
      entries: [{
        endpoint: "/billing/refunds",
        method: "POST",
        bug_class: "business_logic",
        status: "needs_auth",
        evidence_summary: "refund path requires a victim billing role",
        next_step: "retry after victim billing profile exists",
      }],
    });
    logCoverage({
      target_domain: domain,
      wave: "w1",
      agent: "a5",
      surface_id: "surface-e",
      entries: [{
        endpoint: "/api/v2/admin/export",
        method: "GET",
        bug_class: "authz",
        status: "requeue",
        evidence_summary: "admin export route discovered late in the wave",
        next_step: "test admin role boundaries",
      }],
    });

    for (const [agent, surfaceId] of [
      ["a1", "surface-a"],
      ["a2", "surface-b"],
      ["a3", "surface-c"],
      ["a4", "surface-d"],
      ["a5", "surface-e"],
    ]) {
      writeWaveHandoff({
        target_domain: domain,
        wave: "w1",
        agent,
        surface_id: surfaceId,
        surface_status: "complete",
        summary: `${agent} complete.`,
        content: `# ${agent}`,
      });
    }

    const result = JSON.parse(applyWaveMerge({
      target_domain: domain,
      wave_number: 1,
      force_merge: false,
    }));

    assert.deepEqual(result.merge.completed_surface_ids, ["surface-a", "surface-b", "surface-c", "surface-d", "surface-e"]);
    assert.deepEqual(result.merge.partial_surface_ids, []);
    // Coverage-derived requeue is the next-wave assignment hint: a, d, e
    // each have at least one promising/needs_auth/requeue endpoint row, so
    // the orchestrator may re-queue them for a fresh look.
    assert.deepEqual(result.merge.requeue_surface_ids, ["surface-a", "surface-d", "surface-e"]);

    // Cycle D.3 moved surface-closure authority to the frontier ledger.
    // All five evaluators declared complete, so the frontier-projections
    // currentClosures returns all five.
    const { currentClosures } = require("../mcp/lib/frontier-projections.js");
    const closureIds = currentClosures(domain).map((closure) => closure.surface_id).sort();
    assert.deepEqual(closureIds, ["surface-a", "surface-b", "surface-c", "surface-d", "surface-e"]);
  });
});

test("bob_apply_wave_merge preserves existing scope exclusions when the log is absent", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, {
      phase: "EVALUATE",
      pending_wave: 1,
      scope_exclusions: ["legacy.example"],
    });
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    seedAttackSurface(domain, ["surface-a"]);
    writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "A1 complete.",
      content: "# A1",
    });

    const result = JSON.parse(applyWaveMerge({
      target_domain: domain,
      wave_number: 1,
      force_merge: false,
    }));

    // compact state doesn't include scope_exclusions — verify via full state read
    const fullState = JSON.parse(readSessionState({ target_domain: domain })).state;
    assert.deepEqual(fullState.scope_exclusions, ["legacy.example"]);
  });
});

test("bob_apply_wave_merge force-merges missing and invalid handoffs and computes requeue_surface_ids", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "EVALUATE", pending_wave: 2, evaluation_wave: 1 });
    seedAssignments(domain, 2, [
      { agent: "a1", surface_id: "surface-a" },
      { agent: "a2", surface_id: "surface-b" },
      { agent: "a3", surface_id: "surface-c" },
    ]);
    seedAttackSurface(domain, ["surface-a", "surface-b", "surface-c"]);

    writeFileAtomic(path.join(sessionDir(domain), "handoff-w2-a1.json"), "{bad json");
    writeWaveHandoff({
      target_domain: domain,
      wave: "w2",
      agent: "a3",
      surface_id: "surface-c",
      surface_status: "partial",
      summary: "A3 partial.",
      content: "# A3",
    });

    const result = JSON.parse(applyWaveMerge({
      target_domain: domain,
      wave_number: 2,
      force_merge: true,
      force_merge_reason: "a1 handoff is malformed and a2 handoff is missing after agent termination; merge is safe because both surfaces are requeued.",
    }));

    assert.equal(result.status, "merged");
    assert.equal(result.force_merge, true);
    assert.match(result.force_merge_reason, /a1 handoff is malformed/);
    assert.deepEqual(result.merge.invalid_agents, ["a1"]);
    // R1-HIGH-#2 fix: invalid handoff surfaces now propagate to
    // missing_surface_ids so the orchestrator can't lose track of them.
    // Requeue order: partial first, then missing (which now includes both
    // a1's invalid surface-a and a2's truly-missing surface-b).
    assert.deepEqual(result.merge.missing_surface_ids.sort(), ["surface-a", "surface-b"]);
    assert.deepEqual(result.merge.partial_surface_ids, ["surface-c"]);
    assert.deepEqual(result.merge.requeue_surface_ids, ["surface-c", "surface-a", "surface-b"]);
    assert.equal(result.state.pending_wave, null);
    assert.equal(result.state.evaluation_wave, 2);

    const rows = readJsonl(pipelineEventsJsonlPath(domain));
    const mergeEvent = rows.find((row) => row.type === "wave_merged" && row.wave_number === 2);
    assert.equal(mergeEvent.force_merge, true);
    assert.match(mergeEvent.force_merge_reason, /a2 handoff is missing/);

    const normalizedEvent = readPipelineEvents(domain).events
      .find((row) => row.type === "wave_merged" && row.wave_number === 2);
    assert.equal(normalizedEvent.force_merge, true);
    assert.match(normalizedEvent.force_merge_reason, /merge is safe/);
  });
});

test("bob_apply_wave_merge requires a force_merge_reason for forced settlement", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "EVALUATE", pending_wave: 1 });
    seedAssignments(domain, 1, [
      { agent: "a1", surface_id: "surface-a" },
    ]);
    seedAttackSurface(domain, ["surface-a"]);

    assert.throws(
      () => applyWaveMerge({ target_domain: domain, wave_number: 1, force_merge: true }),
      /force_merge_reason is required/,
    );
    assert.throws(
      () => applyWaveMerge({
        target_domain: domain,
        wave_number: 1,
        force_merge: false,
        force_merge_reason: "not used for normal pending checks",
      }),
      /force_merge_reason is only allowed/,
    );
  });
});

test("bob_apply_wave_merge promotes recurring blocked_prereqs to state.terminally_blocked when registry is unchanged", () => {
  withTempHome(() => {
    const domain = "promote.example.com";
    seedAttackSurfaces(domain, [
      { id: "surface-auth", hosts: [`https://${domain}/auth`], priority: "HIGH" },
    ]);
    seedSessionState(domain, { phase: "EVALUATE", pending_wave: 1, evaluation_wave: 0 });
    seedPrereqSnapshot(domain, 1, { auth_handles: [], egress_handles: [] });
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-auth" }]);
    writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-auth",
      surface_status: "partial",
      summary: "auth profile not registered; cannot test org-scoped IDOR",
      content: "# A1",
      blocked_prereqs: [
        { kind: "auth_missing", identifier_hint: "attacker", reason: "no attacker profile registered" },
      ],
    });
    JSON.parse(applyWaveMerge({ target_domain: domain, wave_number: 1, force_merge: false }));
    let fullState = JSON.parse(readSessionState({ target_domain: domain })).state;
    const { currentBlockers } = require("../mcp/lib/frontier-projections.js");
    assert.equal(currentBlockers(domain).length, 0);
    assert.equal(fullState.blocked_prereq_history.length, 1);

    setStatePendingWave(domain, 2);
    seedPrereqSnapshot(domain, 2, { auth_handles: [], egress_handles: [] });
    seedAssignments(domain, 2, [{ agent: "a1", surface_id: "surface-auth" }]);
    writeWaveHandoff({
      target_domain: domain,
      wave: "w2",
      agent: "a1",
      surface_id: "surface-auth",
      surface_status: "partial",
      summary: "still no attacker profile registered after wave 1; same blocker",
      content: "# A1 wave 2",
      blocked_prereqs: [
        { kind: "auth_missing", identifier_hint: "attacker", reason: "no attacker profile registered" },
      ],
    });
    const result = JSON.parse(applyWaveMerge({ target_domain: domain, wave_number: 2, force_merge: false }));
    assert.equal(result.merge.terminally_blocked_promoted.length, 1);
    assert.equal(result.merge.terminally_blocked_promoted[0].surface_id, "surface-auth");
    assert.equal(result.merge.terminally_blocked_promoted[0].blockers[0].kind, "auth_missing");
    assert.equal(result.merge.terminally_blocked_promoted[0].blockers[0].identifier_hint, "attacker");

    fullState = JSON.parse(readSessionState({ target_domain: domain })).state;
    const blockers = currentBlockers(domain);
    assert.equal(blockers.length, 1);
    assert.equal(blockers[0].surface_id, "surface-auth");
    assert.equal(fullState.blocked_prereq_history.length, 2);
    assert.ok(!result.merge.requeue_surface_ids.includes("surface-auth"));
  });
});

test("bob_apply_wave_merge does NOT promote auth_missing when the named handle was added between waves", () => {
  withTempHome(() => {
    const domain = "registry-grew.example.com";
    seedAttackSurfaces(domain, [
      { id: "surface-auth", hosts: [`https://${domain}/auth`], priority: "HIGH" },
    ]);
    seedSessionState(domain, { phase: "EVALUATE", pending_wave: 1, evaluation_wave: 0 });
    seedPrereqSnapshot(domain, 1, { auth_handles: [], egress_handles: [] });
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-auth" }]);
    writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-auth",
      surface_status: "partial",
      summary: "auth profile not registered; cannot test org-scoped IDOR",
      content: "# A1",
      blocked_prereqs: [
        { kind: "auth_missing", identifier_hint: "attacker", reason: "no attacker profile registered" },
      ],
    });
    JSON.parse(applyWaveMerge({ target_domain: domain, wave_number: 1, force_merge: false }));

    setStatePendingWave(domain, 2);
    // Operator added the SPECIFIC handle the blocker named ("attacker") between waves.
    seedPrereqSnapshot(domain, 2, { auth_handles: ["attacker"], egress_handles: [] });
    seedAssignments(domain, 2, [{ agent: "a1", surface_id: "surface-auth" }]);
    writeWaveHandoff({
      target_domain: domain,
      wave: "w2",
      agent: "a1",
      surface_id: "surface-auth",
      surface_status: "partial",
      summary: "marker repeated even though attacker profile was added between waves",
      content: "# A1 wave 2",
      blocked_prereqs: [
        { kind: "auth_missing", identifier_hint: "attacker", reason: "marker repeated" },
      ],
    });
    const result = JSON.parse(applyWaveMerge({ target_domain: domain, wave_number: 2, force_merge: false }));
    assert.equal(result.merge.terminally_blocked_promoted.length, 0);
    const { currentBlockers } = require("../mcp/lib/frontier-projections.js");
    assert.equal(currentBlockers(domain).length, 0);
  });
});

test("bob_apply_wave_merge DOES promote auth_missing when an unrelated handle was added (closes count-based amnesty bug)", () => {
  withTempHome(() => {
    const domain = "unrelated-handle.example.com";
    seedAttackSurfaces(domain, [
      { id: "surface-auth", hosts: [`https://${domain}/auth`], priority: "HIGH" },
    ]);
    seedSessionState(domain, { phase: "EVALUATE", pending_wave: 1, evaluation_wave: 0 });
    seedPrereqSnapshot(domain, 1, { auth_handles: [], egress_handles: [] });
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-auth" }]);
    writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-auth",
      surface_status: "partial",
      summary: "needs attacker profile to test org-scoped IDOR",
      content: "# A1",
      blocked_prereqs: [
        { kind: "auth_missing", identifier_hint: "attacker", reason: "attacker profile required" },
      ],
    });
    JSON.parse(applyWaveMerge({ target_domain: domain, wave_number: 1, force_merge: false }));

    setStatePendingWave(domain, 2);
    // Operator added "victim" — UNRELATED to the "attacker" blocker.
    // The previous count-based delta would have given amnesty (count grew
    // 0 -> 1) and silently skipped promotion. The handle-set check refuses.
    seedPrereqSnapshot(domain, 2, { auth_handles: ["victim"], egress_handles: [] });
    seedAssignments(domain, 2, [{ agent: "a1", surface_id: "surface-auth" }]);
    writeWaveHandoff({
      target_domain: domain,
      wave: "w2",
      agent: "a1",
      surface_id: "surface-auth",
      surface_status: "partial",
      summary: "attacker still missing in wave 2",
      content: "# A1 wave 2",
      blocked_prereqs: [
        { kind: "auth_missing", identifier_hint: "attacker", reason: "attacker still missing" },
      ],
    });
    const result = JSON.parse(applyWaveMerge({ target_domain: domain, wave_number: 2, force_merge: false }));
    assert.equal(result.merge.terminally_blocked_promoted.length, 1);
    assert.equal(result.merge.terminally_blocked_promoted[0].blockers[0].identifier_hint, "attacker");
  });
});

test("bob_apply_wave_merge promotes funded_wallet_missing on 2-wave recurrence (no registry-delta path)", () => {
  withTempHome(() => {
    const domain = "wallet-blocked.example.com";
    seedAttackSurfaces(domain, [
      { id: "surface-siwe", hosts: [`https://${domain}/siwe`], priority: "HIGH" },
    ]);
    seedSessionState(domain, { phase: "EVALUATE", pending_wave: 1, evaluation_wave: 0 });
    seedPrereqSnapshot(domain, 1, { auth_handles: [], egress_handles: [] });
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-siwe" }]);
    writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-siwe",
      surface_status: "partial",
      summary: "SIWE flow reaches verified-address balance gate; no funded wallet",
      content: "# A1",
      blocked_prereqs: [
        { kind: "funded_wallet_missing", identifier_hint: "sepolia.funded", reason: "balance gate requires funded wallet" },
      ],
    });
    JSON.parse(applyWaveMerge({ target_domain: domain, wave_number: 1, force_merge: false }));

    setStatePendingWave(domain, 2);
    seedPrereqSnapshot(domain, 2, { auth_handles: [], egress_handles: [] });
    seedAssignments(domain, 2, [{ agent: "a1", surface_id: "surface-siwe" }]);
    writeWaveHandoff({
      target_domain: domain,
      wave: "w2",
      agent: "a1",
      surface_id: "surface-siwe",
      surface_status: "partial",
      summary: "second wave still lacks the funded wallet so the gate cannot be probed",
      content: "# A1 wave 2",
      blocked_prereqs: [
        { kind: "funded_wallet_missing", identifier_hint: "sepolia.funded", reason: "still no funded wallet" },
      ],
    });
    const result = JSON.parse(applyWaveMerge({ target_domain: domain, wave_number: 2, force_merge: false }));
    assert.equal(result.merge.terminally_blocked_promoted.length, 1);
    assert.equal(result.merge.terminally_blocked_promoted[0].blockers[0].kind, "funded_wallet_missing");
  });
});

test("bob_clear_terminal_block removes a surface from terminally_blocked and records the clear in state", () => {
  withTempHome(() => {
    const domain = "clear-block.example.com";
    seedSessionState(domain, {
      phase: "EVALUATE",
      evaluation_wave: 2,
      blocked_prereq_history: [
        { wave: 1, surface_id: "surface-auth", kind: "auth_missing", identifier_hint: "attacker", reason: "no profile" },
        { wave: 2, surface_id: "surface-auth", kind: "auth_missing", identifier_hint: "attacker", reason: "still no profile" },
        { wave: 1, surface_id: "surface-other", kind: "egress_unreachable", identifier_hint: "us-west", reason: "default egress unreachable" },
      ],
    });
    // Cycle D.3 moved blocker authority to frontier-events.jsonl; the
    // clear path reads the ledger, not state.terminally_blocked. Seed a
    // blocker.asserted event to drive the projection.
    const { appendFrontierEvent } = require("../mcp/lib/frontier-events.js");
    appendFrontierEvent({
      target_domain: domain,
      kind: "blocker.asserted",
      surface_id: "surface-auth",
      payload: { terminally_blocked: true, wave: 2, kind: "auth_missing", identifier_hint: "attacker", reason: "no profile registered" },
      source: { artifact: "wave-merge", tool: "bob_apply_wave_merge" },
    });

    const result = JSON.parse(clearTerminalBlock({
      target_domain: domain,
      surface_id: "surface-auth",
      reason: "operator added attacker auth profile via auth_store",
    }));
    assert.equal(result.cleared, true);
    assert.equal(result.surface_id, "surface-auth");
    assert.equal(result.cleared_at_wave, 2);
    assert.equal(result.previously_blocked_at_wave, 2);
    assert.equal(result.previous_blockers[0].kind, "auth_missing");
    assert.equal(result.state.terminally_blocked_count, 0);

    const fullState = JSON.parse(readSessionState({ target_domain: domain })).state;
    // History is RETAINED for debugging; loop detector uses clear epoch.
    assert.equal(fullState.blocked_prereq_history.length, 3);
    // Clear is recorded durably in state, not just in pipeline event.
    assert.equal(fullState.terminal_block_clear_history.length, 1);
    assert.equal(fullState.terminal_block_clear_history[0].surface_id, "surface-auth");
    assert.equal(fullState.terminal_block_clear_history[0].cleared_at_wave, 2);
    assert.match(fullState.terminal_block_clear_history[0].reason, /attacker auth profile/);
    assert.equal(fullState.terminal_block_clear_history[0].previous_blockers[0].kind, "auth_missing");
  });
});

test("bob_clear_terminal_block rejects clearing while a wave is pending", () => {
  withTempHome(() => {
    const domain = "pending-clear.example.com";
    seedSessionState(domain, {
      phase: "EVALUATE",
      evaluation_wave: 1,
      pending_wave: 2,
    });
    const { appendFrontierEvent } = require("../mcp/lib/frontier-events.js");
    appendFrontierEvent({
      target_domain: domain,
      kind: "blocker.asserted",
      surface_id: "surface-a",
      payload: { terminally_blocked: true, kind: "auth_missing", identifier_hint: "attacker", reason: "no profile" },
      source: { artifact: "wave-merge", tool: "bob_apply_wave_merge" },
    });
    assert.throws(() => clearTerminalBlock({
      target_domain: domain,
      surface_id: "surface-a",
      reason: "operator wants to clear during a pending wave",
    }), /Cannot clear a terminal block while wave 2 is pending/);
  });
});

test("bob_clear_terminal_block rejects clearing a surface that was never terminally blocked", () => {
  withTempHome(() => {
    const domain = "never-blocked.example.com";
    seedSessionState(domain, {
      phase: "EVALUATE",
      evaluation_wave: 1,
    });
    // No blocker.asserted event was emitted; the projection has no entry
    // for surface-z, so the clear rejects.
    assert.throws(() => clearTerminalBlock({
      target_domain: domain,
      surface_id: "surface-z",
      reason: "operator wants to clear a non-blocked surface",
    }), /not terminally blocked in the frontier ledger/);
  });
});

test("bob_clear_terminal_block rejects a reason that contains credentials", () => {
  withTempHome(() => {
    const domain = "secret-reason.example.com";
    seedSessionState(domain, {
      phase: "EVALUATE",
      evaluation_wave: 1,
      terminally_blocked: [
        buildTerminallyBlockedEntry("surface-a", "auth_missing", "attacker", { reason: "no profile" }),
      ],
    });
    assert.throws(() => clearTerminalBlock({
      target_domain: domain,
      surface_id: "surface-a",
      reason: "Authorization: Bearer eyJabcdefghij.eyJklmnopqr.sigabcdefghij was added",
    }), /appears to contain secrets/);
  });
});

test("bob_clear_terminal_block requires a reason of at least 20 characters", () => {
  withTempHome(() => {
    const domain = "short-reason.example.com";
    seedSessionState(domain, {
      phase: "EVALUATE",
      evaluation_wave: 1,
      terminally_blocked: [
        buildTerminallyBlockedEntry("surface-a", "auth_missing", "attacker", { reason: "no profile" }),
      ],
    });
    assert.throws(() => clearTerminalBlock({
      target_domain: domain,
      surface_id: "surface-a",
      reason: "too short",
    }), /reason is required and must be at least 20 characters/);
  });
});

test("bob_apply_wave_merge emits a surface_terminally_blocked event per (surface, blocker) pair on promotion", () => {
  withTempHome(() => {
    const domain = "promote-event.example.com";
    seedAttackSurfaces(domain, [
      { id: "surface-auth", hosts: [`https://${domain}/auth`], priority: "HIGH" },
    ]);
    seedSessionState(domain, { phase: "EVALUATE", pending_wave: 1, evaluation_wave: 0 });
    seedPrereqSnapshot(domain, 1, { auth_handles: [], egress_handles: [] });
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-auth" }]);
    writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-auth",
      surface_status: "partial",
      summary: "missing attacker profile",
      content: "# A1",
      blocked_prereqs: [
        { kind: "auth_missing", identifier_hint: "attacker", reason: "no profile" },
      ],
    });
    JSON.parse(applyWaveMerge({ target_domain: domain, wave_number: 1, force_merge: false }));

    setStatePendingWave(domain, 2);
    seedPrereqSnapshot(domain, 2, { auth_handles: [], egress_handles: [] });
    seedAssignments(domain, 2, [{ agent: "a1", surface_id: "surface-auth" }]);
    writeWaveHandoff({
      target_domain: domain,
      wave: "w2",
      agent: "a1",
      surface_id: "surface-auth",
      surface_status: "partial",
      summary: "still missing attacker profile",
      content: "# A1 wave 2",
      blocked_prereqs: [
        { kind: "auth_missing", identifier_hint: "attacker", reason: "still none" },
      ],
    });
    JSON.parse(applyWaveMerge({ target_domain: domain, wave_number: 2, force_merge: false }));

    const eventsResult = readPipelineEvents(domain);
    const events = eventsResult.events.filter((e) => e.type === "surface_terminally_blocked");
    assert.equal(events.length, 1);
    assert.equal(events[0].surface_id, "surface-auth");
    assert.equal(events[0].kind, "auth_missing");
    assert.equal(events[0].identifier_hint, "attacker");
    assert.equal(events[0].wave_number, 2);
  });
});

test("bounty_report_written emits report_written when report.md is present", () => {
  withTempHome(() => {
    const domain = "report-event.example.com";
    const dir = sessionDir(domain);
    fs.mkdirSync(dir, { recursive: true });
    seedSessionState(domain, { phase: "REPORT", evaluation_wave: 1 });
    fs.writeFileSync(path.join(dir, "report.md"), "# Report\n\nNo findings.\n");

    const result = JSON.parse(reportWritten({ target_domain: domain }));
    assert.equal(result.report_written, true);
    assert.ok(result.size_bytes > 0);

    const eventsResult = readPipelineEvents(domain);
    const events = eventsResult.events.filter((e) => e.type === "report_written");
    assert.equal(events.length, 1);
    assert.ok(events[0].counts.report_size_bytes > 0);
  });
});

test("bounty_report_written rejects when report.md is absent", () => {
  withTempHome(() => {
    const domain = "no-report.example.com";
    seedSessionState(domain, { phase: "REPORT", evaluation_wave: 1 });
    assert.throws(() => reportWritten({ target_domain: domain }), /report\.md is not present/);
  });
});

test("pipeline analytics distinguishes SUBMIT grade with missing canonical report path", () => {
  withTempHome(() => {
    const domain = "report-path.example.com";
    seedSessionState(domain, { phase: "REPORT", evaluation_wave: 1 });
    const gradePaths = gradeArtifactPaths(domain);
    writeFileAtomic(gradePaths.json, `${JSON.stringify({
      version: 1,
      target_domain: domain,
      verdict: "SUBMIT",
      total_score: 80,
      findings: [],
    }, null, 2)}\n`);

    const analytics = JSON.parse(readPipelineAnalytics({ target_domain: domain }));
    const pending = analytics.bottlenecks.find((b) => b.code === "report_pending_canonical_path");
    assert.ok(pending, "SUBMIT without canonical report should use the specific report-path warning");
    assert.equal(analytics.bottlenecks.some((b) => b.code === "missing_report"), false);
    const nextAction = analytics.next_actions.find((action) => /report_pending_canonical_path/.test(action.reason));
    assert.match(nextAction.action, /canonical session report\.md/);
  });
});

test("low_coverage analytics fires on closed_pct (not coverage_pct) so terminally_blocked surfaces count as closed", () => {
  withTempHome(() => {
    const domain = "low-cov.example.com";
    seedAttackSurfaces(domain, [
      { id: "surface-a", hosts: [`https://${domain}/a`], priority: "HIGH" },
      { id: "surface-b", hosts: [`https://${domain}/b`], priority: "HIGH" },
    ]);
    seedSessionState(domain, {
      phase: "CHAIN",
      evaluation_wave: 1,
      explored: ["surface-a"],
      terminally_blocked: [
        buildTerminallyBlockedEntry("surface-b", "auth_missing", "attacker", { reason: "no profile", blocked_at_wave: 1 }),
      ],
    });

    const analytics = JSON.parse(readPipelineAnalytics({ target_domain: domain }));
    const lowCoverage = analytics.bottlenecks.find((b) => b.code === "low_coverage");
    // 1 explored + 1 terminally_blocked out of 2 non-low surfaces = 100% closed.
    // Old (count-based) coverage_pct would be 50% (only explored). New
    // closed_pct is 100%, so low_coverage does NOT fire.
    assert.equal(lowCoverage, undefined, "low_coverage should not fire when all non-low surfaces are explored or terminally_blocked");
  });
});

test("bob_clear_terminal_block lets a re-blocked surface start fresh recurrence count via clear epoch", () => {
  withTempHome(() => {
    const domain = "reblock.example.com";
    seedAttackSurfaces(domain, [
      { id: "surface-auth", hosts: [`https://${domain}/auth`], priority: "HIGH" },
    ]);
    seedSessionState(domain, {
      phase: "EVALUATE",
      evaluation_wave: 2,
      pending_wave: null,
      terminally_blocked: [
        buildTerminallyBlockedEntry("surface-auth", "auth_missing", "attacker", { blocked_at_wave: 2, reason: "no profile" }),
      ],
      blocked_prereq_history: [
        { wave: 1, surface_id: "surface-auth", kind: "auth_missing", identifier_hint: "attacker", reason: "no profile" },
        { wave: 2, surface_id: "surface-auth", kind: "auth_missing", identifier_hint: "attacker", reason: "still none" },
      ],
    });

    JSON.parse(clearTerminalBlock({
      target_domain: domain,
      surface_id: "surface-auth",
      reason: "operator registered attacker profile and is unblocking",
    }));

    // Wave 3 still hits the same blocker (e.g., the new profile didn't help).
    setStatePendingWave(domain, 3);
    seedPrereqSnapshot(domain, 3, { auth_handles: ["attacker"], egress_handles: [] });
    seedAssignments(domain, 3, [{ agent: "a1", surface_id: "surface-auth" }]);
    writeWaveHandoff({
      target_domain: domain,
      wave: "w3",
      agent: "a1",
      surface_id: "surface-auth",
      surface_status: "partial",
      summary: "still blocked even after profile added",
      content: "# A1 wave 3",
      blocked_prereqs: [
        { kind: "auth_missing", identifier_hint: "attacker", reason: "blocker reappeared" },
      ],
    });
    const result = JSON.parse(applyWaveMerge({ target_domain: domain, wave_number: 3, force_merge: false }));
    // After the clear, history is RETAINED but the loop detector ignores
    // entries from waves <= cleared_at_wave (which was 2). Wave 3's
    // blocker has no qualifying prior, so no promotion. History is still
    // available for debugging.
    assert.equal(result.merge.terminally_blocked_promoted.length, 0);
    const fullState = JSON.parse(readSessionState({ target_domain: domain })).state;
    assert.ok(fullState.blocked_prereq_history.length >= 2, "history should be retained, not pruned");
  });
});

test("bob_apply_wave_merge rejects invalid lifecycle and wave-number invariants", () => {
  withTempHome(() => {
    const domain = "example.com";
    // Cycle D.3: wave-merge no longer reads attack_surface.json; the merge
    // path operates on handoffs + frontier projections, so the legacy
    // "missing attack_surface.json" hard-fail is replaced by the lifecycle
    // and pending-wave invariants below.
    seedSessionState(domain, { phase: "VERIFY", pending_wave: 1 });
    assert.throws(
      () => applyWaveMerge({ target_domain: domain, wave_number: 1, force_merge: false }),
      /Wave merge requires lifecycle_state OPEN_FRONTIER/,
    );

    // pending_wave must match the requested wave_number.
    seedSessionState(domain, { phase: "EVALUATE", pending_wave: 2 });
    assert.throws(
      () => applyWaveMerge({ target_domain: domain, wave_number: 1, force_merge: false }),
      /Wave merge requires pending_wave 1, found 2/,
    );

    // No pending wave at all.
    seedSessionState(domain, { phase: "EVALUATE", pending_wave: null });
    assert.throws(
      () => applyWaveMerge({ target_domain: domain, wave_number: 1, force_merge: false }),
      /Wave merge requires pending_wave to be set/,
    );
  });
});

test("bob_write_wave_handoff rejects unassigned or mismatched handoffs", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);

    assert.throws(
      () => writeWaveHandoff({
        target_domain: domain,
        wave: "w1",
        agent: "a2",
        surface_id: "surface-b",
        surface_status: "complete",
        summary: "Invalid agent handoff.",
        content: "# nope",
      }),
      /Agent a2 is not assigned in wave w1/,
    );

    assert.throws(
      () => writeWaveHandoff({
        target_domain: domain,
        wave: "w1",
        agent: "a1",
        surface_id: "surface-b",
        surface_status: "complete",
        summary: "Mismatched surface handoff.",
        content: "# nope",
      }),
      /Agent a1 is assigned surface surface-a, not surface-b/,
    );
  });
});

test("wave handoff contract normalizes blocked prereqs and validates assignment identity", () => {
  assert.ok(BLOCKED_PREREQ_KIND_VALUES.includes("auth_missing"));
  assert.deepEqual(
    attachHandoffOrigin(normalizeBlockedPrereqs([{
      kind: "auth_missing",
      identifier_hint: "attacker",
      reason: "Registered attacker profile was not available to the evaluator.",
    }]), { agent: "a1", surfaceId: "surface-a" }),
    [{
      kind: "auth_missing",
      identifier_hint: "attacker",
      reason: "Registered attacker profile was not available to the evaluator.",
      agent: "a1",
      surface_id: "surface-a",
    }],
  );

  assert.throws(
    () => validateWaveHandoffPayload({
      target_domain: "example.com",
      wave: "w1",
      agent: "a2",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "wrong agent",
    }, {
      targetDomain: "example.com",
      wave: "w1",
      agent: "a1",
      surfaceId: "surface-a",
      effectiveSurfaceType: "web",
      findingsForRun: [],
    }),
    /handoff agent does not match assignment/,
  );
});

test("bob_record_finding rejects partial or invalid wave metadata and still allows null/null", () => {
  withTempHome(() => {
    const domain = "example.com";

    assert.throws(
      () => recordFinding({
        target_domain: domain,
        title: "A",
        severity: "high",
        endpoint: "/a",
        description: "d",
        proof_of_concept: "poc",
        validated: true,
        wave: "w1",
      }),
      /wave and agent must either both be provided or both be omitted/,
    );

    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    assert.throws(
      () => recordFinding({
        target_domain: domain,
        title: "A",
        severity: "high",
        endpoint: "/a",
        description: "d",
        proof_of_concept: "poc",
        validated: true,
        wave: "w1",
        agent: "a1",
      }),
      /surface_id must be a non-empty string/,
    );
    assert.throws(
      () => recordFinding({
        target_domain: domain,
        title: "A",
        severity: "high",
        endpoint: "/a",
        description: "d",
        proof_of_concept: "poc",
        validated: true,
        wave: "w1",
        agent: "a2",
        surface_id: "surface-a",
      }),
      /Agent a2 is not assigned in wave w1/,
    );

    const recorded = JSON.parse(recordFinding({
      target_domain: domain,
      title: "Unscoped finding",
      severity: "low",
      endpoint: "/b",
      description: "d",
      proof_of_concept: "poc",
      validated: true,
      wave: null,
      agent: null,
    }));
    assert.equal(recorded.recorded, true);

    const [finding] = readFindingsFromJsonl(domain);
    assert.equal(finding.wave, null);
    assert.equal(finding.agent, null);
    assert.equal(finding.surface_id, null);
    assert.equal(finding.auth_profile, null);
  });
});

test("bob_write_handoff still writes SESSION_HANDOFF.md without wave fields", () => {
  withTempHome(() => {
    const domain = "example.com";
    const result = JSON.parse(writeHandoff({
      target_domain: domain,
      session_number: 7,
      target_url: "https://example.com",
      explored_with_results: ["surface-a"],
      must_do_next: [{ priority: "P1", description: "Keep testing surface-a" }],
    }));

    const handoffPath = path.join(sessionDir(domain), "SESSION_HANDOFF.md");
    assert.equal(result.written, handoffPath);
    assert.ok(fs.existsSync(handoffPath));

    const content = fs.readFileSync(handoffPath, "utf8");
    assert.match(content, /# Handoff — Session 7/);
    assert.match(content, /## Explored/);
    assert.doesNotMatch(content, /handoff-w7-a1/);
  });
});

test("bob_write_wave_handoff writes matching markdown and json with normalized defaults", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    const content = "# Handoff\n\nFreeform markdown.";
    const result = JSON.parse(writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "Freeform handoff summary.",
      content,
    }));

    assert.ok(fs.existsSync(result.written_md));
    assert.ok(fs.existsSync(result.written_json));
    assert.equal(fs.readFileSync(result.written_md, "utf8"), content);

    const payload = JSON.parse(fs.readFileSync(result.written_json, "utf8"));
    assert.equal(payload.target_domain, domain);
    assert.equal(payload.wave, "w1");
    assert.equal(payload.agent, "a1");
    assert.equal(payload.surface_id, "surface-a");
    assert.equal(payload.surface_type, null);
    assert.equal(payload.surface_status, "complete");
    assert.equal(payload.provenance, "verified");
    assert.equal(payload.provenance_model, HANDOFF_PROVENANCE_MODEL);
    assert.match(payload.provenance_assignment_hash, /^[0-9a-f]{64}$/);
    assert.ok(payload.provenance_signature);
    assert.equal(payload.summary, "Freeform handoff summary.");
    assert.deepEqual(payload.chain_notes, []);
    assert.deepEqual(payload.blocked_harness_runs, []);
    assert.deepEqual(payload.blocked_prereqs, []);
    assert.deepEqual(payload.bypass_attempts, []);
    assert.deepEqual(payload.dead_ends, []);
    assert.deepEqual(payload.waf_blocked_endpoints, []);
    assert.deepEqual(payload.lead_surface_ids, []);
  });
});

test("bob_write_wave_handoff rejects oversized markdown content", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);

    assert.throws(
      () => writeWaveHandoff({
        target_domain: domain,
        wave: "w1",
        agent: "a1",
        surface_id: "surface-a",
        surface_status: "complete",
        summary: "Oversized handoff summary.",
        content: "x".repeat(120001),
      }),
      /content must be at most 120000 characters/,
    );
  });
});

test("bob_write_wave_handoff rejects surface_status: complete with blocked_harness_runs", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    assert.throws(() => writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "Tried but blocked.",
      content: "# Handoff\n",
      blocked_harness_runs: [
        { kind: "foundry_fork", harness: "foundry-fork-mainnet", reason: "RPC timeout at block 19000000", needed_for: "PSM donation invariant" },
      ],
    }), /surface_status cannot be 'complete' when blocked_harness_runs is non-empty/);
  });
});

test("bob_write_wave_handoff accepts surface_status: partial with blocked_harness_runs", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    const result = JSON.parse(writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "partial",
      summary: "Blocked harnesses recorded.",
      content: "# Handoff\n",
      blocked_harness_runs: [
        { kind: "foundry_fork", harness: "foundry-fork-mainnet", reason: "RPC timeout at block 19000000", needed_for: "PSM donation invariant" },
      ],
    }));
    const payload = JSON.parse(fs.readFileSync(result.written_json, "utf8"));
    assert.equal(payload.surface_status, "partial");
    assert.equal(payload.blocked_harness_runs.length, 1);
    assert.equal(payload.blocked_harness_runs[0].kind, "foundry_fork");
    assert.equal(payload.blocked_harness_runs[0].harness, "foundry-fork-mainnet");
    assert.equal(payload.blocked_harness_runs[0].needed_for, "PSM donation invariant");
  });
});

test("bob_write_wave_handoff accepts surface_status: partial with blocked_prereqs", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    const result = JSON.parse(writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "partial",
      summary: "Blocked by missing auth profiles.",
      content: "# Handoff\n",
      blocked_prereqs: [
        {
          kind: "auth_missing",
          identifier_hint: "attacker",
          reason: "Org-scoped IDOR test requires attacker session; bob_list_auth_profiles returned []",
          needed_for: "cross-org dashboard authz check",
        },
        {
          kind: "egress_unreachable",
          identifier_hint: "us-west-egress",
          reason: "thegraph.kiln.fi returned ECONNREFUSED across 5 attempts on default egress",
          evidence_summary: "circuit-breaker reports 5 failures past threshold for thegraph.kiln.fi",
        },
      ],
    }));
    const payload = JSON.parse(fs.readFileSync(result.written_json, "utf8"));
    assert.equal(payload.surface_status, "partial");
    assert.equal(payload.blocked_prereqs.length, 2);
    assert.equal(payload.blocked_prereqs[0].kind, "auth_missing");
    assert.equal(payload.blocked_prereqs[0].identifier_hint, "attacker");
    assert.equal(payload.blocked_prereqs[0].needed_for, "cross-org dashboard authz check");
    assert.equal(payload.blocked_prereqs[1].kind, "egress_unreachable");
    assert.equal(payload.blocked_prereqs[1].identifier_hint, "us-west-egress");
    assert.match(payload.blocked_prereqs[1].evidence_summary, /circuit-breaker/);
  });
});

test("bob_write_wave_handoff rejects surface_status: complete with blocked_prereqs", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    assert.throws(() => writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "Pretending to be done despite missing material.",
      content: "# Handoff\n",
      blocked_prereqs: [
        { kind: "auth_missing", identifier_hint: "attacker", reason: "no profile loaded" },
      ],
    }), /surface_status cannot be 'complete' when blocked_prereqs is non-empty/);
  });
});

test("bob_write_wave_handoff rejects blocked_prereqs with unknown kind", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    assert.throws(() => writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "partial",
      summary: "Trying a kind that does not exist in the registry.",
      content: "# Handoff\n",
      blocked_prereqs: [
        { kind: "captcha_missing", identifier_hint: "captcha", reason: "captcha solver not configured" },
      ],
    }), /blocked_prereqs\[0\]\.kind must be one of/);
  });
});

test("bob_write_wave_handoff rejects blocked_prereqs identifier_hint that looks like a secret", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    // Mixed-case JWT shape rejected by the format regex.
    assert.throws(() => writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "partial",
      summary: "Operator pasted a credential into identifier_hint by accident.",
      content: "# Handoff\n",
      blocked_prereqs: [
        { kind: "auth_missing", identifier_hint: "eyJhbGciOiJIUzI1NiJ9.eyJpZCI6MX0", reason: "JWT token leaked into hint" },
      ],
    }), /identifier_hint must match/);
    // Lowercase JWT shape passes the format regex but the sensitive-material
    // validator catches the dotted JWT structure.
    assert.throws(() => writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "partial",
      summary: "Operator pasted a lowercase JWT into identifier_hint.",
      content: "# Handoff\n",
      blocked_prereqs: [
        { kind: "auth_missing", identifier_hint: "eyjabcdefghij.eyjklmnopqr.sigabcdefghij", reason: "lowercase JWT" },
      ],
    }), /appears to contain secrets/);
    // 64-char lowercase hex (private key / SHA-256 shape) rejected by the
    // long-hex screen even though the format regex accepts it.
    assert.throws(() => writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "partial",
      summary: "Operator pasted a hex hash into identifier_hint.",
      content: "# Handoff\n",
      blocked_prereqs: [
        { kind: "key_material_missing", identifier_hint: "a".repeat(64), reason: "hex hash leaked" },
      ],
    }), /looks like a hex private key, address, or hash/);
    // 65-char lowercase still rejected because of maxLength.
    assert.throws(() => writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "partial",
      summary: "Operator pasted a long lowercase token into identifier_hint.",
      content: "# Handoff\n",
      blocked_prereqs: [
        { kind: "key_material_missing", identifier_hint: "a".repeat(65), reason: "long lowercase token" },
      ],
    }), /identifier_hint must be at most 64 characters/);
    // Leading hyphen / non-alphanumeric start rejected.
    assert.throws(() => writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "partial",
      summary: "Operator used leading hyphen.",
      content: "# Handoff\n",
      blocked_prereqs: [
        { kind: "auth_missing", identifier_hint: "-attacker", reason: "leading hyphen" },
      ],
    }), /identifier_hint must match/);
  });
});

test("bob_write_wave_handoff accepts blocked_prereqs without identifier_hint", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    const result = JSON.parse(writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "partial",
      summary: "Egress unreachable; no specific egress profile would obviously help.",
      content: "# Handoff\n",
      blocked_prereqs: [
        {
          kind: "egress_unreachable",
          reason: "thegraph.kiln.fi unreachable across 5 attempts on default egress",
        },
      ],
    }));
    const payload = JSON.parse(fs.readFileSync(result.written_json, "utf8"));
    assert.equal(payload.blocked_prereqs.length, 1);
    assert.equal(payload.blocked_prereqs[0].kind, "egress_unreachable");
    assert.equal(payload.blocked_prereqs[0].identifier_hint, undefined);
  });
});

test("bob_write_wave_handoff rejects blocked_prereqs reason with embedded secrets", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    assert.throws(() => writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "partial",
      summary: "Reason field contains a leaked credential.",
      content: "# Handoff\n",
      blocked_prereqs: [
        {
          kind: "auth_missing",
          reason: "Tried Authorization: Bearer eyJabcdefghij.eyJklmnopqr.sigabcdefghij from previous run",
        },
      ],
    }), /appears to contain secrets/);
  });
});

test("bob_write_wave_handoff rejects blocked_prereqs reason past 240 chars", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    assert.throws(() => writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "partial",
      summary: "Reason is too long.",
      content: "# Handoff\n",
      blocked_prereqs: [
        { kind: "auth_missing", identifier_hint: "attacker", reason: "x".repeat(241) },
      ],
    }), /blocked_prereqs\[0\]\.reason must be at most 240 characters/);
  });
});

test("bob_write_wave_handoff rejects more than 20 blocked_prereqs", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    const overflow = Array.from({ length: 21 }, (_, i) => ({
      kind: "auth_missing",
      identifier_hint: `attacker${i}`,
      reason: `entry ${i}`,
    }));
    assert.throws(() => writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "partial",
      summary: "Too many blocked_prereqs entries.",
      content: "# Handoff\n",
      blocked_prereqs: overflow,
    }), /blocked_prereqs must contain at most 20 entries/);
  });
});

test("bob_write_wave_handoff rejects smart_contract complete without findings or bypass_attempts", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAttackSurfaces(domain, [{ id: "surface-a", hosts: [`https://${domain}`], surface_type: "smart_contract", chain_family: "evm" }]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    assert.throws(() => writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "Audit confirms fixed; nothing to test.",
      content: "# Handoff\n",
    }), /smart_contract surfaces cannot be marked 'complete' without evidence of attempted invariant breaks/);
  });
});

test("bob_write_wave_handoff accepts smart_contract complete with bypass_attempts entry", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAttackSurfaces(domain, [{ id: "surface-a", hosts: [`https://${domain}`], surface_type: "smart_contract", chain_family: "evm" }]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    const result = JSON.parse(writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "Tested admin bypass; no finding.",
      content: "# Handoff\n",
      bypass_attempts: [
        {
          condition: "admin_eoa_compromise",
          attempt_summary: "Forge test calls admin function from a non-admin EOA. Reverts with 'caller is not admin'. Tested from forked mainnet.",
          outcome: "no_finding",
        },
      ],
    }));
    const payload = JSON.parse(fs.readFileSync(result.written_json, "utf8"));
    assert.equal(payload.surface_status, "complete");
    assert.equal(payload.surface_type, "smart_contract");
    assert.equal(payload.bypass_attempts.length, 1);
    assert.equal(payload.bypass_attempts[0].condition, "admin_eoa_compromise");
    assert.equal(payload.bypass_attempts[0].outcome, "no_finding");
  });
});

test("bob_write_wave_handoff accepts smart_contract complete when a finding is recorded for the surface", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAttackSurfaces(domain, [{ id: "surface-a", hosts: [`https://${domain}`], surface_type: "smart_contract", chain_family: "evm" }]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    seedFinding(domain, {
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      sc_evidence: {
        chain_id: 1,
        contract_address: "0x" + "11".repeat(20),
        harness_path: os.homedir(),
        match_test: "test_reentrancy_drain",
        fork_block: 19_000_000,
      },
    });
    const result = JSON.parse(writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "Found and recorded a critical reentrancy bug.",
      content: "# Handoff\n",
    }));
    const payload = JSON.parse(fs.readFileSync(result.written_json, "utf8"));
    assert.equal(payload.surface_status, "complete");
    assert.equal(payload.surface_type, "smart_contract");
  });
});

test("bob_write_wave_handoff requires finding_id when bypass_attempts.outcome is finding_recorded", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAttackSurfaces(domain, [{ id: "surface-a", hosts: [`https://${domain}`], surface_type: "smart_contract", chain_family: "evm" }]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    assert.throws(() => writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "partial",
      summary: "Forgot finding_id.",
      content: "# Handoff\n",
      bypass_attempts: [
        {
          condition: "oracle_manipulation",
          attempt_summary: "Forge test attempts to flash-loan-manipulate the TWAP cache to a stale price; observed the read still passes through.",
          outcome: "finding_recorded",
        },
      ],
    }), /finding_id is required when outcome is "finding_recorded"/);
  });
});

test("bob_write_wave_handoff allows non-smart_contract surfaces to complete without bypass_attempts", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAttackSurfaces(domain, [{ id: "surface-a", hosts: [`https://${domain}`], surface_type: "api" }]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    const result = JSON.parse(writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "API surface tested with no findings.",
      content: "# Handoff\n",
    }));
    const payload = JSON.parse(fs.readFileSync(result.written_json, "utf8"));
    assert.equal(payload.surface_status, "complete");
    assert.equal(payload.surface_type, "api");
    assert.deepEqual(payload.bypass_attempts, []);
  });
});

test("smart_contract gate ignores agent-mutated attack_surface.json (assignment is the authority)", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAttackSurfaces(domain, [{ id: "surface-a", hosts: [`https://${domain}`], surface_type: "smart_contract", chain_family: "evm" }]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);

    // Simulate a evaluator that mutates attack_surface.json after assignments are written,
    // downgrading the surface from smart_contract -> api in an attempt to disable the gate.
    seedAttackSurfaces(domain, [{ id: "surface-a", hosts: [`https://${domain}`], surface_type: "api" }]);

    // The gate must still fire because surface_type was captured into the
    // immutable assignment at start_wave (here, seedAssignments) time.
    assert.throws(() => writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "Tampered with attack_surface.json; expected to bypass gate.",
      content: "# Handoff\n",
    }), /smart_contract surfaces cannot be marked 'complete' without evidence of attempted invariant breaks/);
  });
});

test("merge re-derives smart_contract surface_type even when stored handoff caches null", () => {
  withTempHome(() => {
    const domain = "example.com";
    // Surface marked smart_contract in attack_surface.json from the start.
    seedAttackSurfaces(domain, [{ id: "surface-a", hosts: [`https://${domain}`], surface_type: "smart_contract", chain_family: "evm" }]);
    seedSessionState(domain, { phase: "EVALUATE", pending_wave: 1 });
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);

    // Simulate a handoff written when the attack_surface lookup had failed (cached surface_type: null)
    // by manually crafting the stored payload. The merge must re-derive and reject.
    const dir = sessionDir(domain);
    fs.mkdirSync(dir, { recursive: true });
    writeSignedStoredHandoff(domain, 1, "a1", {
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_type: null,
      surface_status: "complete",
      provenance: "verified",
      summary: "Audit confirms fixed.",
      chain_notes: [],
      blocked_harness_runs: [],
      bypass_attempts: [],
      dead_ends: [],
      waf_blocked_endpoints: [],
      lead_surface_ids: [],
    });

    const merged = JSON.parse(mergeWaveHandoffs({ target_domain: domain, wave_number: 1 }));
    // Stored null is overridden by attack_surface.json re-derive: SC gate fires,
    // handoff is rejected at merge as invalid (no findings, no bypass_attempts).
    assert.deepEqual(merged.invalid_agents, ["a1"]);
    assert.deepEqual(merged.completed_surface_ids, []);
  });
});

test("merge emits sc_complete_with_zero_evidence suspicion flag when all bypass_attempts are no_finding", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAttackSurfaces(domain, [{ id: "surface-a", hosts: [`https://${domain}`], surface_type: "smart_contract", chain_family: "evm" }]);
    seedSessionState(domain, { phase: "EVALUATE", pending_wave: 1 });
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "Tested several conditions, no finding.",
      content: "# Handoff\n",
      bypass_attempts: [
        { condition: "admin_eoa_compromise", attempt_summary: "Forge test calls admin function from a non-admin EOA. Reverts as expected.", outcome: "no_finding" },
        { condition: "oracle_staleness", attempt_summary: "Forge test pushes time forward 30 minutes; price oracle returns stale read but the consumer rejects.", outcome: "no_finding" },
      ],
    });
    const merged = JSON.parse(mergeWaveHandoffs({ target_domain: domain, wave_number: 1 }));
    assert.equal(merged.suspicion_flags.length, 1);
    assert.equal(merged.suspicion_flags[0].flag, "sc_complete_with_zero_evidence");
    assert.equal(merged.suspicion_flags[0].surface_id, "surface-a");
  });
});

test("merge groups blocked_harness_runs and bypass_attempts by (kind, harness) and (condition, outcome)", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAttackSurfaces(domain, [
      { id: "surface-a", hosts: [`https://${domain}`], surface_type: "smart_contract", chain_family: "evm" },
      { id: "surface-b", hosts: [`https://${domain}`], surface_type: "smart_contract", chain_family: "evm" },
    ]);
    seedSessionState(domain, { phase: "EVALUATE", pending_wave: 1 });
    seedAssignments(domain, 1, [
      { agent: "a1", surface_id: "surface-a" },
      { agent: "a2", surface_id: "surface-b" },
    ]);
    const sharedAttempt = { condition: "admin_eoa_compromise", attempt_summary: "Forge test calls admin function from a non-admin EOA. Reverts with caller is not admin.", outcome: "no_finding" };
    writeWaveHandoff({
      target_domain: domain, wave: "w1", agent: "a1", surface_id: "surface-a",
      surface_status: "partial", summary: "RPC down.", content: "# A1",
      blocked_harness_runs: [{ kind: "foundry_fork", harness: "foundry-fork-mainnet", reason: "RPC timeout" }],
      bypass_attempts: [sharedAttempt],
    });
    writeWaveHandoff({
      target_domain: domain, wave: "w1", agent: "a2", surface_id: "surface-b",
      surface_status: "partial", summary: "RPC down too.", content: "# A2",
      blocked_harness_runs: [{ kind: "foundry_fork", harness: "foundry-fork-mainnet", reason: "RPC timeout again" }],
      bypass_attempts: [sharedAttempt],
    });
    const merged = JSON.parse(mergeWaveHandoffs({ target_domain: domain, wave_number: 1 }));
    assert.equal(merged.blocked_harness_runs_grouped.length, 1);
    assert.equal(merged.blocked_harness_runs_grouped[0].kind, "foundry_fork");
    assert.equal(merged.blocked_harness_runs_grouped[0].harness, "foundry-fork-mainnet");
    assert.equal(merged.blocked_harness_runs_grouped[0].count, 2);
    assert.deepEqual(merged.blocked_harness_runs_grouped[0].agents, ["a1", "a2"]);
    assert.deepEqual(merged.blocked_harness_runs_grouped[0].surface_ids, ["surface-a", "surface-b"]);
    assert.equal(merged.bypass_attempts_grouped.length, 1);
    assert.equal(merged.bypass_attempts_grouped[0].condition, "admin_eoa_compromise");
    assert.equal(merged.bypass_attempts_grouped[0].outcome, "no_finding");
    assert.equal(merged.bypass_attempts_grouped[0].count, 2);
  });
});

test("bypass_attempts enforces minimum length floors", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAttackSurfaces(domain, [{ id: "surface-a", hosts: [`https://${domain}`], surface_type: "smart_contract", chain_family: "evm" }]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    assert.throws(() => writeWaveHandoff({
      target_domain: domain, wave: "w1", agent: "a1", surface_id: "surface-a",
      surface_status: "partial", summary: "Lazy.", content: "# Handoff\n",
      bypass_attempts: [{ condition: "x", attempt_summary: "x", outcome: "no_finding" }],
    }), /condition must be at least 4 characters/);
    assert.throws(() => writeWaveHandoff({
      target_domain: domain, wave: "w1", agent: "a1", surface_id: "surface-a",
      surface_status: "partial", summary: "Lazy.", content: "# Handoff\n",
      bypass_attempts: [{ condition: "admin", attempt_summary: "short", outcome: "no_finding" }],
    }), /attempt_summary must be at least 30 characters/);
  });
});

test("bypass_attempts.finding_id existence is cross-checked against findings.jsonl when supplied", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAttackSurfaces(domain, [{ id: "surface-a", hosts: [`https://${domain}`], surface_type: "smart_contract", chain_family: "evm" }]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    assert.throws(() => writeWaveHandoff({
      target_domain: domain, wave: "w1", agent: "a1", surface_id: "surface-a",
      surface_status: "partial", summary: "References nonexistent finding.", content: "# Handoff\n",
      bypass_attempts: [{
        condition: "admin_eoa_compromise",
        attempt_summary: "Forge test attempted to call admin function with a non-admin EOA and observed revert.",
        outcome: "finding_recorded",
        finding_id: "F-9999",
      }],
    }), /F-9999 does not match any recorded finding for this run/);
  });
});

test("tokenized wave handoffs require the correct token and report verified provenance", async () => {
  await withTempHome(async () => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "EVALUATE", evaluation_wave: 0 });
    seedAttackSurface(domain, ["surface-a"]);

    const started = await executeTool("bob_start_wave", {
      target_domain: domain,
      wave_number: 1,
      assignments: [{ agent: "a1", surface_id: "surface-a" }],
    });
    assert.equal(started.ok, true);
    const token = started.data.assignments[0].handoff_token;
    const assignmentText = fs.readFileSync(path.join(sessionDir(domain), "wave-1-assignments.json"), "utf8");
	    assert.doesNotMatch(assignmentText, new RegExp(token));
	    assert.match(assignmentText, /handoff_token_sha256/);
	    assert.match(assignmentText, /handoff_token_required/);

    const missing = await executeTool("bob_write_wave_handoff", {
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "Tested the assigned surface.",
      content: "# handoff",
    });
    assert.equal(missing.ok, false);
    assert.equal(missing.error.code, "INVALID_ARGUMENTS");
    assert.match(missing.error.message, /handoff_token is required/);

    const wrong = await executeTool("bob_write_wave_handoff", {
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      handoff_token: "wrong-token-value",
      summary: "Tested the assigned surface.",
      content: "# handoff",
    });
    assert.equal(wrong.ok, false);
    assert.equal(wrong.error.code, "INVALID_ARGUMENTS");
    assert.match(wrong.error.message, /handoff_token does not match/);

    const written = await executeTool("bob_write_wave_handoff", {
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      handoff_token: token,
      summary: "Tested the assigned surface.",
      chain_notes: ["No chainable primitive found."],
      content: "# handoff",
    });
    assert.equal(written.ok, true);
    assert.equal(written.data.provenance, "verified");
    assert.equal(written.data.provenance_model, HANDOFF_PROVENANCE_MODEL);
    const keyPath = handoffSigningKeyPath(domain);
    assert.equal(fs.existsSync(keyPath), true);
    assert.equal(fs.statSync(keyPath).mode & 0o777, 0o600);
    const handoffText = fs.readFileSync(path.join(sessionDir(domain), "handoff-w1-a1.json"), "utf8");
    assert.doesNotMatch(handoffText, new RegExp(token));
	    assert.match(handoffText, /"provenance_model": "session_file_hmac_v1"/);
	    assert.match(handoffText, /"provenance_assignment_hash": "[0-9a-f]{64}"/);
	    assert.match(handoffText, /"provenance_signature"/);

    const handoffs = await executeTool("bob_read_wave_handoffs", {
      target_domain: domain,
      wave_number: 1,
    });
    assert.equal(handoffs.ok, true);
    assert.equal(handoffs.data.handoffs[0].provenance, "verified");
    assert.equal(handoffs.data.handoffs[0].summary, "Tested the assigned surface.");
    assert.deepEqual(handoffs.data.handoffs[0].chain_notes, ["No chainable primitive found."]);

    const merged = await executeTool("bob_apply_wave_merge", {
      target_domain: domain,
      wave_number: 1,
      force_merge: false,
    });
    assert.equal(merged.ok, true);
    assert.equal(merged.data.status, "merged");
    assert.deepEqual(merged.data.merge.provenance, {
      verified_agents: ["a1"],
    });
  });
});

test("tampered tokenized handoff JSON is invalid and cannot complete the surface", async () => {
  await withTempHome(async () => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "EVALUATE", evaluation_wave: 0 });
    seedAttackSurface(domain, ["surface-a"]);

    const started = await executeTool("bob_start_wave", {
      target_domain: domain,
      wave_number: 1,
      assignments: [{ agent: "a1", surface_id: "surface-a" }],
    });
    assert.equal(started.ok, true);
    const token = started.data.assignments[0].handoff_token;

    const written = await executeTool("bob_write_wave_handoff", {
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      handoff_token: token,
      summary: "Tested the assigned surface.",
      content: "# handoff",
    });
    assert.equal(written.ok, true);

    const handoffPath = path.join(sessionDir(domain), "handoff-w1-a1.json");
    const tampered = JSON.parse(fs.readFileSync(handoffPath, "utf8"));
    tampered.summary = "Tampered after MCP write.";
    writeFileAtomic(handoffPath, `${JSON.stringify(tampered, null, 2)}\n`);

    const handoffs = await executeTool("bob_read_wave_handoffs", {
      target_domain: domain,
      wave_number: 1,
    });
    assert.equal(handoffs.ok, true);
    assert.deepEqual(handoffs.data.handoffs, []);
    assert.equal(handoffs.data.invalid_handoffs.length, 1);
    assert.match(handoffs.data.invalid_handoffs[0].error, /signature does not match/);

    // R1-HIGH-#2 fix: the readiness gate now validates handoff signatures,
    // so a tampered handoff causes apply_wave_merge to gate as "pending" with
    // is_complete:false until the operator explicitly force_merges. Previously
    // the gate ran on file presence only and silently merged.
    const pending = await executeTool("bob_apply_wave_merge", {
      target_domain: domain,
      wave_number: 1,
      force_merge: false,
    });
    assert.equal(pending.ok, true);
    assert.equal(pending.data.status, "pending");
    assert.equal(pending.data.readiness.is_complete, false);
    assert.deepEqual(pending.data.readiness.invalid_agents, ["a1"]);

    const merged = await executeTool("bob_apply_wave_merge", {
      target_domain: domain,
      wave_number: 1,
      force_merge: true,
      force_merge_reason: "Tampered handoff for a1 caused a signature failure; the surface is requeued.",
    });
    assert.equal(merged.ok, true);
    assert.equal(merged.data.status, "merged");
    assert.deepEqual(merged.data.merge.invalid_agents, ["a1"]);
    assert.deepEqual(merged.data.merge.completed_surface_ids, []);
    assert.deepEqual(merged.data.merge.requeue_surface_ids, ["surface-a"]);
    // Cycle D.3: state.explored was deleted; surface closures are now
    // projected from frontier-events.jsonl. The tampered handoff was
    // requeued, so no closures should have been recorded.
    const { currentClosures } = require("../mcp/lib/frontier-projections.js");
    assert.deepEqual(currentClosures(domain), []);
  });
});

test("tokenized assignment cannot downgrade to legacy by losing its token hash", async () => {
  await withTempHome(async () => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "EVALUATE", evaluation_wave: 0 });
    seedAttackSurface(domain, ["surface-a"]);

    const started = await executeTool("bob_start_wave", {
      target_domain: domain,
      wave_number: 1,
      assignments: [{ agent: "a1", surface_id: "surface-a" }],
    });
    assert.equal(started.ok, true);

    const assignmentsPath = path.join(sessionDir(domain), "wave-1-assignments.json");
    const assignmentDoc = JSON.parse(fs.readFileSync(assignmentsPath, "utf8"));
    delete assignmentDoc.assignments[0].handoff_token_sha256;
    writeFileAtomic(assignmentsPath, `${JSON.stringify(assignmentDoc, null, 2)}\n`);

    const attempted = await executeTool("bob_write_wave_handoff", {
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      handoff_token: started.data.assignments[0].handoff_token,
      summary: "Tested the assigned surface.",
      content: "# handoff",
    });
    assert.equal(attempted.ok, false);
    assert.equal(attempted.error.code, "STATE_CONFLICT");
    assert.match(attempted.error.message, /missing handoff_token_sha256/);
  });
});

test("tokenized handoff provenance rejects permissive signing key files", async () => {
  await withTempHome(async () => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "EVALUATE", evaluation_wave: 0 });
    seedAttackSurface(domain, ["surface-a"]);

    const started = await executeTool("bob_start_wave", {
      target_domain: domain,
      wave_number: 1,
      assignments: [{ agent: "a1", surface_id: "surface-a" }],
    });
    assert.equal(started.ok, true);

    const written = await executeTool("bob_write_wave_handoff", {
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      handoff_token: started.data.assignments[0].handoff_token,
      summary: "Tested the assigned surface.",
      content: "# handoff",
    });
    assert.equal(written.ok, true);

    fs.chmodSync(handoffSigningKeyPath(domain), 0o644);
    const handoffs = await executeTool("bob_read_wave_handoffs", {
      target_domain: domain,
      wave_number: 1,
    });
    assert.equal(handoffs.ok, true);
    assert.deepEqual(handoffs.data.handoffs, []);
    assert.equal(handoffs.data.invalid_handoffs.length, 1);
    assert.match(handoffs.data.invalid_handoffs[0].error, /owner-only 0600/);
  });
});

test("bob_finalize_agent_run blocks missing invalid and mismatched handoffs", async () => {
  await withTempHome(async () => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "EVALUATE", evaluation_wave: 1, pending_wave: 1 });
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);

    const missing = await executeTool("bob_finalize_agent_run", {
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
    });
    assert.equal(missing.ok, false);
    assert.equal(missing.error.code, "STATE_CONFLICT");
    assert.equal(missing.error.details.block_code, "missing_handoff");
    assert.equal(missing.error.details.handoff.present, false);

    writeFileAtomic(path.join(sessionDir(domain), "handoff-w1-a1.json"), "{bad json");
    const invalid = await executeTool("bob_finalize_agent_run", {
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
    });
    assert.equal(invalid.ok, false);
    assert.equal(invalid.error.details.block_code, "invalid_handoff");
    assert.equal(invalid.error.details.handoff.present, true);
    assert.equal(invalid.error.details.handoff.valid, false);

    writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "A1 complete.",
      chain_notes: ["No chain."],
      content: "# a1",
    });
    const mismatch = await executeTool("bob_finalize_agent_run", {
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-b",
    });
    assert.equal(mismatch.ok, false);
    assert.equal(mismatch.error.details.block_code, "handoff_mismatch");
    assert.equal(mismatch.error.details.handoff.valid, true);
    assert.equal(mismatch.error.details.handoff.surface_status, "complete");
    assert.equal(mismatch.error.details.handoff.chain_notes_count, 1);

    const rows = readJsonl(toolInvocationTelemetryPath());
    assert.deepEqual(rows.map((row) => row.status), ["blocked", "blocked", "blocked"]);
    assert.deepEqual(rows.map((row) => row.block_code), [
      "missing_handoff",
      "invalid_handoff",
      "handoff_mismatch",
    ]);
    assert.ok(rows.every((row) => row.telemetry_source === "bob_finalize_agent_run"));

    const pipelineRows = readJsonl(pipelineEventsJsonlPath(domain));
    assert.deepEqual(
      pipelineRows.filter((row) => row.type === "evaluator_stopped").map((row) => row.source),
      ["bob_finalize_agent_run", "bob_finalize_agent_run", "bob_finalize_agent_run"],
    );
  });
});

test("bob_finalize_agent_run blocks unreadable wave assignments and records telemetry", async () => {
  await withTempHome(async () => {
    const domain = "unreadable-assignments.example";
    seedSessionState(domain, { phase: "EVALUATE", evaluation_wave: 1, pending_wave: 1 });

    const missing = await executeTool("bob_finalize_agent_run", {
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
    });
    assert.equal(missing.ok, false);
    assert.equal(missing.error.code, "STATE_CONFLICT");
    assert.equal(missing.error.details.block_code, "unreadable_wave_assignments");
    assert.match(missing.error.message, /could not read wave assignments/);

    writeFileAtomic(path.join(sessionDir(domain), "wave-1-assignments.json"), "{bad json");
    const malformed = await executeTool("bob_finalize_agent_run", {
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
    });
    assert.equal(malformed.ok, false);
    assert.equal(malformed.error.code, "STATE_CONFLICT");
    assert.equal(malformed.error.details.block_code, "unreadable_wave_assignments");

    const rows = readJsonl(toolInvocationTelemetryPath());
    assert.deepEqual(rows.map((row) => row.status), ["blocked", "blocked"]);
    assert.deepEqual(rows.map((row) => row.block_code), [
      "unreadable_wave_assignments",
      "unreadable_wave_assignments",
    ]);
    assert.ok(rows.every((row) => row.telemetry_source === "bob_finalize_agent_run"));

    const pipelineRows = readJsonl(pipelineEventsJsonlPath(domain));
    assert.deepEqual(
      pipelineRows.filter((row) => row.type === "evaluator_stopped").map((row) => row.block_code),
      ["unreadable_wave_assignments", "unreadable_wave_assignments"],
    );
  });
});

test("bob_finalize_agent_run allows valid handoff and records metadata-only telemetry", async () => {
  await withTempHome(async () => {
    const domain = "example.com";
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "A1 complete.",
      chain_notes: ["No chain."],
      content: "# a1\n\nraw handoff body is not telemetry",
    });
    logCoverage({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      entries: [{
        endpoint: "/tested",
        method: "GET",
        bug_class: "idor",
        status: "tested",
        evidence_summary: "tested",
      }],
    });
    recordFinding({
      target_domain: domain,
      title: "IDOR",
      severity: "high",
      endpoint: "/tested",
      description: "Cross-account access.",
      proof_of_concept: "raw finding proof should not enter telemetry",
      validated: true,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
    });
    seedTechniqueAttempt(domain);

    const direct = JSON.parse(finalizeAgentRun({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
    }));
    assert.equal(direct.status, "allowed");
    assert.equal(direct.message, "handoff valid");
    assert.deepEqual(direct.handoff, {
      present: true,
      valid: true,
      provenance: "verified",
      surface_status: "complete",
      summary_present: true,
      chain_notes_count: 1,
    });

    const rows = readJsonl(toolInvocationTelemetryPath());
    assert.equal(rows.length, 1);
    assert.equal(rows[0].status, "allowed");
    assert.equal(rows[0].block_code, null);
    assert.equal(rows[0].telemetry_source, "bob_finalize_agent_run");
    assert.deepEqual(rows[0].coverage, { total: 1, by_status: { tested: 1 } });
    assert.deepEqual(rows[0].findings, { count: 1 });
    assert.equal(JSON.stringify(rows[0]).includes("raw handoff body"), false);
    assert.equal(JSON.stringify(rows[0]).includes("raw finding proof"), false);
  });
});

test("bob_finalize_agent_run enforces web technique attempt requirement", async () => {
  await withTempHome(async () => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "EVALUATE", evaluation_wave: 1, pending_wave: 1 });
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "A1 complete.",
      content: "# a1",
    });

    const blocked = await executeTool("bob_finalize_agent_run", {
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
    });
    assert.equal(blocked.ok, false);
    assert.equal(blocked.error.code, "STATE_CONFLICT");
    assert.equal(blocked.error.details.block_code, "missing_technique_attempt_log");
    assert.match(blocked.error.message, /bob_log_technique_attempt/);

    seedTechniqueAttempt(domain, {
      status: "selected",
      evidence: "Selected a candidate technique pack but did not execute it yet.",
    });
    const selectedOnly = await executeTool("bob_finalize_agent_run", {
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
    });
    assert.equal(selectedOnly.ok, false);
    assert.equal(selectedOnly.error.code, "STATE_CONFLICT");
    assert.equal(selectedOnly.error.details.block_code, "missing_technique_attempt_log");
    assert.match(selectedOnly.error.message, /real attempt outcome/);

    seedTechniqueAttempt(domain);
    const allowed = await executeTool("bob_finalize_agent_run", {
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
    });
    assert.equal(allowed.ok, true);
    assert.equal(allowed.data.status, "allowed");

    const rows = readJsonl(toolInvocationTelemetryPath());
    assert.deepEqual(rows.map((row) => row.status), ["blocked", "blocked", "allowed"]);
    assert.deepEqual(rows.map((row) => row.block_code), ["missing_technique_attempt_log", "missing_technique_attempt_log", null]);
  });
});

test("bob_finalize_agent_run allows smart-contract handoff without technique attempts", async () => {
  await withTempHome(async () => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "EVALUATE", evaluation_wave: 1, pending_wave: 1 });
    seedAttackSurfaces(domain, [{
      id: "surface-evm-1",
      surface_type: "smart_contract",
      chain_family: "evm",
      chain_id: "1",
      hosts: [`https://${domain}`],
      foundry_harness_path: "/tmp/harness/evm",
    }]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-evm-1" }]);

    const brief = JSON.parse(readAssignmentBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
    assert.equal(brief.run_context.capability_pack, "smart_contract_evm");
    assert.deepEqual(brief.run_context.context_budget, expectedSmartContractContextBudget());

    writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-evm-1",
      surface_status: "complete",
      summary: "EVM surface complete.",
      content: "# evm",
      bypass_attempts: [{
        condition: "oracle_staleness",
        attempt_summary: "Ran a forked oracle staleness harness and confirmed no demonstrable stale-price path.",
        outcome: "no_finding",
      }],
    });

    const direct = JSON.parse(finalizeAgentRun({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-evm-1",
    }));
    assert.equal(direct.status, "allowed");
    assert.equal(readTechniqueAttemptRecordsFromJsonl(domain).length, 0);
  });
});

test("executeTool smoke path uses envelopes for init, wave, handoff, attempt, and merge", async () => {
  await withTempHome(async () => {
    const domain = "smoke.example";
    const init = await executeTool("bob_init_session", {
      target_domain: domain,
      target_url: `https://${domain}`,
    });
    assert.equal(init.ok, true);

    seedAttackSurface(domain, ["surface-a"]);
    // Cycle D.1: SETUP -> OPEN_FRONTIER replaces the legacy SURFACE_DISCOVERY
    // -> AUTH -> EVALUATE chain because the new lifecycle treats per-claim
    // frontier work as a single state with task lenses.
    assert.equal((await executeTool("bob_advance_session", { target_domain: domain, to_state: "OPEN_FRONTIER" })).ok, true);

    const started = await executeTool("bob_start_wave", {
      target_domain: domain,
      wave_number: 1,
      assignments: [{ agent: "a1", surface_id: "surface-a" }],
    });
    assert.equal(started.ok, true);

    const handoff = await executeTool("bob_write_wave_handoff", {
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      handoff_token: started.data.assignments[0].handoff_token,
      summary: "Smoke handoff summary.",
      chain_notes: ["Smoke chain note."],
      content: "# Smoke",
    });
    assert.equal(handoff.ok, true);

    const attempt = await executeTool("bob_log_technique_attempt", {
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      pack_id: "generic-rest-api",
      status: "attempted",
      evidence: "Smoke test recorded a bounded web technique attempt before finalization.",
    });
    assert.equal(attempt.ok, true);

    const finalized = await executeTool("bob_finalize_agent_run", {
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
    });
    assert.equal(finalized.ok, true);
    assert.equal(finalized.data.status, "allowed");

    const merged = await executeTool("bob_apply_wave_merge", {
      target_domain: domain,
      wave_number: 1,
      force_merge: false,
    });
    assert.equal(merged.ok, true);
    assert.equal(merged.data.status, "merged");
    assert.equal(merged.data.state.evaluation_wave, 1);
  });
});

test("evaluator SubagentStop hook blocks missing final marker", () => {
  withTempHome((tempHome) => {
    const result = runEvaluatorSubagentStop({
      last_assistant_message: "I wrote notes but no marker.",
    }, { home: tempHome });

    assert.equal(result.status, 2);
    assert.match(result.stderr, /BOB_AGENT_RUN_DONE/);
    assert.match(result.stderr, /bob_write_wave_handoff/);

    const rows = readJsonl(toolInvocationTelemetryPath());
    assert.equal(rows.length, 1);
    assert.equal(rows[0].run_type, "evaluator");
    assert.equal(rows[0].status, "blocked");
    assert.equal(rows[0].block_code, "missing_marker");
    assert.equal(rows[0].target_domain, null);
    assert.equal(rows[0].telemetry_source, "agent-run-stop");
  });
});

test("evaluator SubagentStop hook rejects malformed, zero wave, and zero agent markers", () => {
  withTempHome((tempHome) => {
    const malformed = runEvaluatorSubagentStop({
      last_assistant_message: 'BOB_AGENT_RUN_DONE {"target_domain":"example.com","wave":"w1","agent":"a1","surface_id":}',
    }, { home: tempHome });
    assert.equal(malformed.status, 2);
    assert.match(malformed.stderr, /BOB_AGENT_RUN_DONE/);

    const zeroWave = runEvaluatorSubagentStop({
      last_assistant_message: 'BOB_AGENT_RUN_DONE {"target_domain":"example.com","wave":"w0","agent":"a1","surface_id":"surface-a"}',
    }, { home: tempHome });
    assert.equal(zeroWave.status, 2);
    assert.match(zeroWave.stderr, /positive wN/);

    const zeroAgent = runEvaluatorSubagentStop({
      last_assistant_message: 'BOB_AGENT_RUN_DONE {"target_domain":"example.com","wave":"w1","agent":"a0","surface_id":"surface-a"}',
    }, { home: tempHome });
    assert.equal(zeroAgent.status, 2);
    assert.match(zeroAgent.stderr, /positive aN/);

    const rows = readJsonl(toolInvocationTelemetryPath());
    assert.equal(rows.length, 3);
    assert.deepEqual(rows.map((row) => row.block_code), [
      "malformed_marker",
      "malformed_marker",
      "malformed_marker",
    ]);
    assert.equal(rows[1].wave, "w0");
    assert.equal(rows[2].agent, "a0");
  });
});

test("evaluator SubagentStop hook allows post-report evidence markers without wave handoffs", () => {
  withTempHome((tempHome) => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "REPORT", evaluation_wave: 2 });

    const result = runEvaluatorSubagentStop({
      last_assistant_message: 'Catalog complete. BOB_AGENT_RUN_DONE {"target_domain":"example.com","mode":"evidence","surface_id":"F-1","summary":"cataloged exposed records"}',
    }, { home: tempHome });

    assert.equal(result.status, 0);
    assert.match(result.stdout, /post-report evidence run accepted/);

    const rows = readJsonl(toolInvocationTelemetryPath());
    assert.equal(rows.length, 1);
    assert.equal(rows[0].run_type, "evidence");
    assert.equal(rows[0].status, "allowed");
    assert.equal(rows[0].target_domain, domain);
    assert.equal(rows[0].wave, null);
    assert.equal(rows[0].agent, null);
    assert.equal(rows[0].surface_id, "F-1");
    assert.equal(rows[0].handoff.present, false);
    assert.equal(rows[0].handoff.valid, true);
    assert.equal(rows[0].handoff.provenance, "post_report_evidence");
    assert.equal(rows[0].handoff.surface_status, "evidence");
    assert.equal(rows[0].telemetry_source, "evaluator-evidence-stop");

    const pipelineRows = readJsonl(pipelineEventsJsonlPath(domain));
    const stopped = pipelineRows.find((row) => row.type === "evaluator_stopped");
    assert.ok(stopped);
    assert.equal(stopped.status, "allowed");
    assert.equal(stopped.source, "evaluator-evidence-stop");
    assert.equal(Object.prototype.hasOwnProperty.call(stopped, "wave_number"), false);
    assert.equal(stopped.surface_id, "F-1");
  });
});

test("evaluator SubagentStop hook blocks evidence markers before REPORT or EXPLORE", () => {
  withTempHome((tempHome) => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "EVALUATE", evaluation_wave: 1 });

    const result = runEvaluatorSubagentStop({
      last_assistant_message: 'BOB_AGENT_RUN_DONE {"target_domain":"example.com","mode":"evidence","surface_id":"F-1","summary":"too early"}',
    }, { home: tempHome });

    assert.equal(result.status, 2);
    assert.match(result.stderr, /REPORT or EXPLORE/);

    const rows = readJsonl(toolInvocationTelemetryPath());
    assert.equal(rows.length, 1);
    assert.equal(rows[0].run_type, "evidence");
    assert.equal(rows[0].status, "blocked");
    assert.equal(rows[0].block_code, "evidence_phase_mismatch");
    assert.equal(rows[0].target_domain, domain);
  });
});

test("evaluator SubagentStop hook blocks missing structured handoff", async () => {
  await withTempHome(async (tempHome) => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "EVALUATE", evaluation_wave: 0 });
    seedAttackSurface(domain, ["surface-a"]);
    await executeTool("bob_start_wave", {
      target_domain: domain,
      wave_number: 1,
      assignments: [{ agent: "a1", surface_id: "surface-a" }],
    });

    const result = runEvaluatorSubagentStop({
      last_assistant_message: 'BOB_AGENT_RUN_DONE {"target_domain":"example.com","wave":"w1","agent":"a1","surface_id":"surface-a"}',
    }, { home: tempHome });

    assert.equal(result.status, 2);
    assert.match(result.stderr, /must call bob_write_wave_handoff/);

    const rows = readJsonl(toolInvocationTelemetryPath());
    assert.equal(rows.length, 1);
    assert.equal(rows[0].status, "blocked");
    assert.equal(rows[0].block_code, "missing_handoff");
    assert.equal(rows[0].target_domain, domain);
    assert.equal(rows[0].wave, "w1");
    assert.equal(rows[0].agent, "a1");
    assert.equal(rows[0].surface_id, "surface-a");
    assert.deepEqual(rows[0].handoff, {
      present: false,
      valid: false,
      provenance: null,
      surface_status: null,
      summary_present: false,
      chain_notes_count: 0,
    });

    const pipelineRows = readJsonl(pipelineEventsJsonlPath(domain));
    const stopped = pipelineRows.find((row) => row.type === "evaluator_stopped");
    assert.ok(stopped);
    assert.equal(stopped.status, "blocked");
    assert.equal(stopped.block_code, "missing_handoff");
    assert.equal(stopped.wave_number, 1);
    assert.equal(stopped.agent, "a1");
    assert.equal(stopped.surface_id, "surface-a");
  });
});

test("evaluator SubagentStop hook blocks invalid structured handoff", () => {
  withTempHome((tempHome) => {
    const domain = "example.com";
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    writeFileAtomic(path.join(sessionDir(domain), "handoff-w1-a1.json"), "{bad json");

    const result = runEvaluatorSubagentStop({
      last_assistant_message: 'BOB_AGENT_RUN_DONE {"target_domain":"example.com","wave":"w1","agent":"a1","surface_id":"surface-a"}',
    }, { home: tempHome });

    assert.equal(result.status, 2);
    assert.match(result.stderr, /wrote an invalid handoff/);

    const rows = readJsonl(toolInvocationTelemetryPath());
    assert.equal(rows.length, 1);
    assert.equal(rows[0].status, "blocked");
    assert.equal(rows[0].block_code, "invalid_handoff");
    assert.equal(rows[0].handoff.present, true);
    assert.equal(rows[0].handoff.valid, false);
  });
});

test("evaluator SubagentStop hook blocks marker and handoff mismatch", () => {
  withTempHome((tempHome) => {
    const domain = "example.com";
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "a1 complete",
      chain_notes: ["no chain"],
      content: "# a1",
    });

    const result = runEvaluatorSubagentStop({
      last_assistant_message: 'BOB_AGENT_RUN_DONE {"target_domain":"example.com","wave":"w1","agent":"a1","surface_id":"surface-b"}',
    }, { home: tempHome });

    assert.equal(result.status, 2);
    assert.match(result.stderr, /does not match structured handoff/);

    const rows = readJsonl(toolInvocationTelemetryPath());
    assert.equal(rows.length, 1);
    assert.equal(rows[0].status, "blocked");
    assert.equal(rows[0].block_code, "handoff_mismatch");
    assert.equal(rows[0].surface_id, "surface-b");
    assert.equal(rows[0].handoff.present, true);
    assert.equal(rows[0].handoff.valid, true);
    assert.equal(rows[0].handoff.surface_status, "complete");
    assert.equal(rows[0].handoff.summary_present, true);
    assert.equal(rows[0].handoff.chain_notes_count, 1);
  });
});

test("evaluator SubagentStop hook allows incomplete waves without merging", async () => {
  await withTempHome(async (tempHome) => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "EVALUATE", evaluation_wave: 0 });
    seedAttackSurface(domain, ["surface-a", "surface-b"]);
    const started = await executeTool("bob_start_wave", {
      target_domain: domain,
      wave_number: 1,
      assignments: [
        { agent: "a1", surface_id: "surface-a" },
        { agent: "a2", surface_id: "surface-b" },
      ],
    });
    const token = started.data.assignments.find((assignment) => assignment.agent === "a1").handoff_token;
    await executeTool("bob_write_wave_handoff", {
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      handoff_token: token,
      summary: "a1 complete",
      content: "# a1",
    });
    seedTechniqueAttempt(domain);

    const result = runEvaluatorSubagentStop({
      last_assistant_message: 'BOB_AGENT_RUN_DONE {"target_domain":"example.com","wave":"w1","agent":"a1","surface_id":"surface-a"}',
    }, { home: tempHome });

    assert.equal(result.status, 0);
    const state = JSON.parse(readStateSummary({ target_domain: domain })).state;
    assert.equal(state.pending_wave, 1);
    assert.equal(state.evaluation_wave, 0);
  });
});

test("evaluator SubagentStop hook allows a complete wave without merging", async () => {
  await withTempHome(async (tempHome) => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "EVALUATE", evaluation_wave: 0 });
    seedAttackSurface(domain, ["surface-a"]);
    const started = await executeTool("bob_start_wave", {
      target_domain: domain,
      wave_number: 1,
      assignments: [{ agent: "a1", surface_id: "surface-a" }],
    });
    await executeTool("bob_write_wave_handoff", {
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      handoff_token: started.data.assignments[0].handoff_token,
      summary: "a1 complete",
      content: "# a1",
    });
    seedTechniqueAttempt(domain);

    const result = runEvaluatorSubagentStop({
      last_assistant_message: 'BOB_AGENT_RUN_DONE {"target_domain":"example.com","wave":"w1","agent":"a1","surface_id":"surface-a"}',
    }, { home: tempHome });

    assert.equal(result.status, 0);
    assert.match(result.stdout, /handoff valid/);
    const state = JSON.parse(readStateSummary({ target_domain: domain })).state;
    assert.equal(state.pending_wave, 1);
    assert.equal(state.evaluation_wave, 0);
  });
});

test("evaluator SubagentStop hook writes metadata-only allowed run telemetry", () => {
  withTempHome((tempHome) => {
    const domain = "example.com";
    const transcriptPath = path.join(tempHome, "transcript.jsonl");
    const rawTranscriptSecret = "raw-transcript-secret";
    const rawHandoffSecret = "raw-handoff-markdown-secret";
    const rawFindingSecret = "raw-finding-poc-secret";
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "a1 complete",
      chain_notes: ["no chain"],
      content: `# a1\n\n${rawHandoffSecret}`,
    });
    seedTechniqueAttempt(domain);
    logCoverage({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      entries: [
        {
          endpoint: "/tested",
          method: "GET",
          bug_class: "idor",
          status: "tested",
          evidence_summary: "tested",
        },
        {
          endpoint: "/promising",
          method: "POST",
          bug_class: "xss",
          status: "promising",
          evidence_summary: "promising",
        },
      ],
    });
    recordFinding({
      target_domain: domain,
      title: "IDOR",
      severity: "high",
      endpoint: "/tested",
      description: "Cross-account access.",
      proof_of_concept: rawFindingSecret,
      validated: true,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
    });
    fs.writeFileSync(transcriptPath, `${JSON.stringify({
      message: {
        role: "assistant",
        content: [{ text: `${rawTranscriptSecret}\nBOB_AGENT_RUN_DONE {"target_domain":"example.com","wave":"w1","agent":"a1","surface_id":"surface-a"}` }],
      },
    })}\n`);

    const result = runEvaluatorSubagentStop({ transcript_path: transcriptPath }, { home: tempHome });

    assert.equal(result.status, 0);
    assert.match(result.stdout, /handoff valid/);

    const rows = readJsonl(toolInvocationTelemetryPath());
    assert.equal(rows.length, 1);
    const event = rows[0];
    assert.equal(event.version, 1);
    assert.equal(event.bob_version, PACKAGE_VERSION);
    assert.match(event.run_id, /^[a-f0-9]{16}$/);
    assert.equal(event.run_type, "evaluator");
    assert.equal(event.status, "allowed");
    assert.equal(event.block_code, null);
    assert.equal(event.target_domain, domain);
    assert.equal(event.wave, "w1");
    assert.equal(event.agent, "a1");
    assert.equal(event.surface_id, "surface-a");
    assert.equal(event.transcript_path, transcriptPath);
    assert.deepEqual(event.handoff, {
      present: true,
      valid: true,
      provenance: "verified",
      surface_status: "complete",
      summary_present: true,
      chain_notes_count: 1,
    });
    assert.deepEqual(event.coverage, {
      total: 2,
      by_status: { tested: 1, promising: 1 },
    });
    assert.deepEqual(event.findings, { count: 1 });
    assert.equal(event.telemetry_source, "agent-run-stop");

    const sidecar = JSON.parse(fs.readFileSync(toolInvocationSidecarPath(event.run_id), "utf8"));
    assert.deepEqual(sidecar, event);

    const telemetryText = JSON.stringify(event);
    assert.equal(telemetryText.includes(rawTranscriptSecret), false);
    assert.equal(telemetryText.includes(rawHandoffSecret), false);
    assert.equal(telemetryText.includes(rawFindingSecret), false);
  });
});

test("evaluator SubagentStop telemetry can be disabled and write failures do not alter hook results", () => {
  withTempHome((tempHome) => {
    const domain = "example.com";
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "a1 complete",
      content: "# a1",
    });
    seedTechniqueAttempt(domain);

    const disabled = runEvaluatorSubagentStop({
      last_assistant_message: 'BOB_AGENT_RUN_DONE {"target_domain":"example.com","wave":"w1","agent":"a1","surface_id":"surface-a"}',
    }, { home: tempHome, env: { BOUNTY_TELEMETRY: "0" } });
    assert.equal(disabled.status, 0);
    assert.equal(fs.existsSync(toolInvocationTelemetryPath()), false);

    const blockingPath = path.join(tempHome, "telemetry-root-file");
    fs.writeFileSync(blockingPath, "not a directory\n");
    const allowed = runEvaluatorSubagentStop({
      last_assistant_message: 'BOB_AGENT_RUN_DONE {"target_domain":"example.com","wave":"w1","agent":"a1","surface_id":"surface-a"}',
    }, { home: tempHome, env: { BOUNTY_TELEMETRY_DIR: blockingPath } });
    assert.equal(allowed.status, 0);
    assert.match(allowed.stdout, /handoff valid/);

    const blocked = runEvaluatorSubagentStop({
      last_assistant_message: "No marker.",
    }, { home: tempHome, env: { BOUNTY_TELEMETRY_DIR: blockingPath } });
    assert.equal(blocked.status, 2);
    assert.match(blocked.stderr, /BOB_AGENT_RUN_DONE/);
  });
});

test("evaluator SubagentStop hook treats stale completion notifications as valid handoffs", async () => {
  await withTempHome(async (tempHome) => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "EVALUATE", evaluation_wave: 0 });
    seedAttackSurface(domain, ["surface-a"]);
    const started = await executeTool("bob_start_wave", {
      target_domain: domain,
      wave_number: 1,
      assignments: [{ agent: "a1", surface_id: "surface-a" }],
    });
    await executeTool("bob_write_wave_handoff", {
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      handoff_token: started.data.assignments[0].handoff_token,
      summary: "a1 complete",
      content: "# a1",
    });
    seedTechniqueAttempt(domain);
    const merged = await executeTool("bob_apply_wave_merge", {
      target_domain: domain,
      wave_number: 1,
      force_merge: false,
    });
    assert.equal(merged.ok, true);
    assert.equal(merged.data.status, "merged");

    const result = runEvaluatorSubagentStop({
      last_assistant_message: 'BOB_AGENT_RUN_DONE {"target_domain":"example.com","wave":"w1","agent":"a1","surface_id":"surface-a"}',
    }, { home: tempHome });

    assert.equal(result.status, 0);
    assert.match(result.stdout, /handoff valid/);
    const state = JSON.parse(readStateSummary({ target_domain: domain })).state;
    assert.equal(state.pending_wave, null);
    assert.equal(state.evaluation_wave, 1);
  });
});

test("bob_log_coverage appends validated records to coverage.jsonl", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);

    const result = JSON.parse(logCoverage({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      entries: [
        {
          endpoint: "/api/v1/users/123",
          method: "get",
          bug_class: "IDOR",
          auth_profile: "attacker-victim",
          status: "tested",
          evidence_summary: "attacker/victim replay both returned 403",
          next_step: "try legacy export route",
        },
        {
          endpoint: "/api/v1/export",
          bug_class: "business_logic",
          status: "promising",
          evidence_summary: "export job accepted attacker-controlled account_id",
        },
      ],
    }));

    assert.equal(result.appended, 2);
    assert.equal(result.log_path, coverageJsonlPath(domain));
    assert.deepEqual(result.statuses, {
      tested: 1,
      blocked: 0,
      promising: 1,
      needs_auth: 0,
      requeue: 0,
    });

    const records = readCoverageRecordsFromJsonl(domain);
    assert.equal(records.length, 2);
    assert.equal(records[0].target_domain, domain);
    assert.equal(records[0].method, "GET");
    assert.equal(records[0].bug_class, "idor");
    assert.equal(records[0].auth_profile, "attacker-victim");
    assert.equal(records[0].next_step, "try legacy export route");
    assert.equal(records[1].method, null);
  });
});

test("appendJsonlLine retention keeps the newest records", () => {
  withTempHome((tempHome) => {
    const logPath = path.join(tempHome, "retention.jsonl");
    for (let index = 0; index < 5; index += 1) {
      appendJsonlLine(logPath, { index }, { maxRecords: 3 });
    }

    assert.deepEqual(
      fs.readFileSync(logPath, "utf8").trim().split("\n").map((line) => JSON.parse(line).index),
      [2, 3, 4],
    );

    const trimResult = trimJsonlFile(logPath, 2);
    assert.deepEqual(trimResult, { trimmed: true, total: 3, retained: 2 });
    assert.deepEqual(
      fs.readFileSync(logPath, "utf8").trim().split("\n").map((line) => JSON.parse(line).index),
      [3, 4],
    );
  });
});

test("readFileUtf8 rejects artifacts beyond the configured read cap", () => {
  withTempHome((tempHome) => {
    const filePath = path.join(tempHome, "oversized.jsonl");
    fs.writeFileSync(filePath, "x".repeat(33), "utf8");

    assert.equal(readFileUtf8(filePath, { maxBytes: 33 }), "x".repeat(33));
    assert.throws(
      () => readFileUtf8(filePath, { label: "oversized.jsonl", maxBytes: 32 }),
      /oversized\.jsonl exceeds read cap of 32 bytes/,
    );
    assert.ok(DEFAULT_ARTIFACT_READ_MAX_BYTES > 32);
  });
});

test("JSONL retention can recover files beyond the normal read cap", () => {
  withTempHome((tempHome) => {
    const logPath = path.join(tempHome, "recover-retention.jsonl");
    fs.writeFileSync(
      logPath,
      `${JSON.stringify({ index: 0, pad: "x".repeat(DEFAULT_ARTIFACT_READ_MAX_BYTES) })}\n${JSON.stringify({ index: 1 })}\n`,
      "utf8",
    );

    assert.throws(() => readFileUtf8(logPath), /recover-retention\.jsonl exceeds read cap/);
    assert.deepEqual(trimJsonlFile(logPath, 1), { trimmed: true, total: 2, retained: 1 });
    assert.deepEqual(
      fs.readFileSync(logPath, "utf8").trim().split("\n").map((line) => JSON.parse(line).index),
      [1],
    );
  });
});

test("loadJsonDocumentStrict reports oversized JSON as a read-cap failure", () => {
  withTempHome((tempHome) => {
    const filePath = path.join(tempHome, "large.json");
    fs.writeFileSync(filePath, JSON.stringify({ pad: "x".repeat(DEFAULT_ARTIFACT_READ_MAX_BYTES) }), "utf8");

    assert.throws(
      () => loadJsonDocumentStrict(filePath, "large JSON"),
      /large JSON exceeds read cap/,
    );
  });
});

test("coverage log retention keeps newest records under the session cap", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);

    const entries = Array.from({ length: COVERAGE_LOG_MAX_RECORDS + 1 }, (_, index) => ({
      endpoint: `/api/coverage-${index}`,
      bug_class: "idor",
      status: "tested",
      evidence_summary: `coverage ${index}`,
    }));

    logCoverage({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      entries,
    });

    const records = readCoverageRecordsFromJsonl(domain);
    assert.equal(records.length, COVERAGE_LOG_MAX_RECORDS);
    assert.equal(records[0].endpoint, "/api/coverage-1");
    assert.equal(records.at(-1).endpoint, `/api/coverage-${COVERAGE_LOG_MAX_RECORDS}`);
  });
});

test("HTTP audit retention keeps newest records under the session cap", () => {
  withTempHome(() => {
    const domain = "example.com";
    for (let index = 0; index < HTTP_AUDIT_LOG_MAX_RECORDS + 1; index += 1) {
      appendHttpAuditRecord({
        version: 1,
        ts: new Date(index).toISOString(),
        target_domain: domain,
        method: "GET",
        url: `https://${domain}/audit-${index}`,
        host: domain,
        scope_decision: "allowed",
        status: 200,
      });
    }

    const records = readHttpAuditRecordsFromJsonl(domain);
    assert.equal(records.length, HTTP_AUDIT_LOG_MAX_RECORDS);
    assert.equal(records[0].path, "/audit-1");
    assert.equal(records.at(-1).path, `/audit-${HTTP_AUDIT_LOG_MAX_RECORDS}`);
  });
});

test("imported traffic retention keeps newest records under the session cap", () => {
  withTempHome(() => {
    const domain = "example.com";
    let nextIndex = 0;
    const totalEntries = TRAFFIC_LOG_MAX_RECORDS + 1;

    while (nextIndex < totalEntries) {
      const batchSize = Math.min(TRAFFIC_IMPORT_MAX_ENTRIES, totalEntries - nextIndex);
      const entries = Array.from({ length: batchSize }, (_, offset) => {
        const index = nextIndex + offset;
        return {
          method: "GET",
          url: `https://${domain}/traffic-${index}`,
          status: 200,
        };
      });

      importHttpTraffic({
        target_domain: domain,
        source: "manual",
        entries,
      });
      nextIndex += batchSize;
    }

    const records = readTrafficRecordsFromJsonl(domain);
    assert.equal(records.length, TRAFFIC_LOG_MAX_RECORDS);
    assert.equal(records[0].path, "/traffic-1");
    assert.equal(records.at(-1).path, `/traffic-${TRAFFIC_LOG_MAX_RECORDS}`);
  });
});

test("bob_log_coverage rejects invalid assignment metadata and malformed entries", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    const validEntry = {
      endpoint: "/api/v1/users/123",
      bug_class: "idor",
      status: "tested",
      evidence_summary: "403 for attacker and victim",
    };

    assert.throws(
      () => logCoverage({ target_domain: domain, wave: "1", agent: "a1", surface_id: "surface-a", entries: [validEntry] }),
      /wave must match wN/,
    );
    assert.throws(
      () => logCoverage({ target_domain: domain, wave: "w1", agent: "agent1", surface_id: "surface-a", entries: [validEntry] }),
      /agent must match aN/,
    );
    assert.throws(
      () => logCoverage({ target_domain: domain, wave: "w1", agent: "a2", surface_id: "surface-a", entries: [validEntry] }),
      /Agent a2 is not assigned in wave w1/,
    );
    assert.throws(
      () => logCoverage({ target_domain: domain, wave: "w1", agent: "a1", surface_id: "surface-b", entries: [validEntry] }),
      /Agent a1 is assigned surface surface-a, not surface-b/,
    );
    assert.throws(
      () => logCoverage({ target_domain: domain, wave: "w1", agent: "a1", surface_id: "surface-a", entries: [] }),
      /entries must be a non-empty array/,
    );
    assert.throws(
      () => logCoverage({
        target_domain: domain,
        wave: "w1",
        agent: "a1",
        surface_id: "surface-a",
        entries: [{ ...validEntry, status: "done" }],
      }),
      /entries\[0\]\.status must be one of tested, blocked, promising, needs_auth, requeue/,
    );
    assert.throws(
      () => logCoverage({
        target_domain: domain,
        wave: "w1",
        agent: "a1",
        surface_id: "surface-a",
        entries: [{ ...validEntry, endpoint: " " }],
      }),
      /entries\[0\]\.endpoint must be a non-empty string/,
    );
  });
});

test("bob_wave_handoff_status reports complete when all assigned handoffs exist", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAssignments(domain, 1, [
      { agent: "a1", surface_id: "surface-a" },
      { agent: "a2", surface_id: "surface-b" },
    ]);

    writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "A1 complete.",
      content: "# A1",
    });

    writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a2",
      surface_id: "surface-b",
      surface_status: "partial",
      summary: "A2 partial.",
      content: "# A2",
    });

    const status = JSON.parse(waveHandoffStatus({ target_domain: domain, wave_number: 1 }));

    assert.deepEqual(status, {
      assignments_total: 2,
      handoffs_total: 2,
      received_agents: ["a1", "a2"],
      missing_agents: [],
      invalid_agents: [],
      unexpected_agents: [],
      is_complete: true,
    });
  });
});

test("markdown-only handoffs do not satisfy readiness or advance merges", () => {
  withTempHome(() => {
    const domain = "example.com";
    const dir = sessionDir(domain);
    seedSessionState(domain, { phase: "EVALUATE", pending_wave: 1 });
    seedAttackSurface(domain, ["surface-a"]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    writeFileAtomic(path.join(dir, "handoff-w1-a1.md"), "# markdown only\n");

    const before = fs.readFileSync(statePath(domain), "utf8");
    const status = JSON.parse(waveHandoffStatus({ target_domain: domain, wave_number: 1 }));
    assert.deepEqual(status, {
      assignments_total: 1,
      handoffs_total: 0,
      received_agents: [],
      missing_agents: ["a1"],
      invalid_agents: [],
      unexpected_agents: [],
      is_complete: false,
    });

    const pending = JSON.parse(applyWaveMerge({
      target_domain: domain,
      wave_number: 1,
      force_merge: false,
    }));
    assert.equal(pending.status, "pending");
    assert.deepEqual(pending.readiness, status);
    assert.equal(fs.readFileSync(statePath(domain), "utf8"), before);
    assert.ok(!fs.existsSync(path.join(dir, "wave-2-assignments.json")));

    writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "Structured handoff summary.",
      content: "# structured handoff",
    });

    const merged = JSON.parse(applyWaveMerge({
      target_domain: domain,
      wave_number: 1,
      force_merge: false,
    }));
    assert.equal(merged.status, "merged");
    assert.deepEqual(merged.readiness, {
      assignments_total: 1,
      handoffs_total: 1,
      received_agents: ["a1"],
      missing_agents: [],
      invalid_agents: [],
      unexpected_agents: [],
      is_complete: true,
    });
  });
});

test("bob_wave_handoff_status reports partial completion and surfaces invalid handoffs", () => {
  withTempHome(() => {
    const domain = "example.com";
    const dir = sessionDir(domain);
    fs.mkdirSync(dir, { recursive: true });

    seedAssignments(domain, 2, [
      { agent: "a1", surface_id: "surface-a" },
      { agent: "a2", surface_id: "surface-b" },
      { agent: "a3", surface_id: "surface-c" },
    ]);

    writeFileAtomic(path.join(dir, "handoff-w2-a1.json"), "{bad json");
    writeUnexpectedHandoff(domain, "w2", "a9");

    const status = JSON.parse(waveHandoffStatus({ target_domain: domain, wave_number: 2 }));

    // a1's handoff file exists but is malformed; the readiness must classify
    // it as invalid (not received) so the gate sees is_complete:false instead
    // of silently passing the merge and dropping surface-a from tracking.
    assert.deepEqual(status, {
      assignments_total: 3,
      handoffs_total: 2,
      received_agents: [],
      missing_agents: ["a2", "a3"],
      invalid_agents: ["a1"],
      unexpected_agents: ["a9"],
      is_complete: false,
    });
  });
});

test("bob_wave_handoff_status hard-fails when the assignment file is missing", () => {
  withTempHome(() => {
    assert.throws(
      () => waveHandoffStatus({ target_domain: "example.com", wave_number: 7 }),
      /Missing assignment file/,
    );
  });
});

test("bob_merge_wave_handoffs merges valid handoffs and dedupes optional arrays", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAssignments(domain, 2, [
      { agent: "a1", surface_id: "surface-a" },
      { agent: "a2", surface_id: "surface-b" },
    ]);

    writeWaveHandoff({
      target_domain: domain,
      wave: "w2",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "A1 complete.",
      content: "# A1",
      dead_ends: [" /users/1 ", "/users/1", ""],
      waf_blocked_endpoints: ["/admin"],
      lead_surface_ids: ["surface-b", "surface-b", "surface-c"],
    });

    writeWaveHandoff({
      target_domain: domain,
      wave: "w2",
      agent: "a2",
      surface_id: "surface-b",
      surface_status: "partial",
      summary: "A2 partial.",
      content: "# A2",
      dead_ends: ["/billing"],
      waf_blocked_endpoints: ["/admin", " /reports "],
      lead_surface_ids: ["surface-c", "surface-d"],
    });

    const merged = JSON.parse(mergeWaveHandoffs({ target_domain: domain, wave_number: 2 }));

	    assert.deepEqual(merged, {
	      assignments_total: 2,
	      handoffs_total: 2,
	      received_agents: ["a1", "a2"],
	      invalid_agents: [],
	      invalid_handoffs: [],
	      unexpected_agents: [],
      completed_surface_ids: ["surface-a"],
      partial_surface_ids: ["surface-b"],
      missing_surface_ids: [],
      dead_ends: ["/users/1", "/billing"],
      waf_blocked_endpoints: ["/admin", "/reports"],
      lead_surface_ids: ["surface-b", "surface-c", "surface-d"],
      blocked_harness_runs: [],
      blocked_harness_runs_grouped: [],
      blocked_prereqs: [],
      blocked_prereqs_grouped: [],
      bypass_attempts: [],
      bypass_attempts_grouped: [],
      suspicion_flags: [],
      provenance: {
        verified_agents: ["a1", "a2"],
      },
    });
  });
});

test("bob_merge_wave_handoffs requeues missing and invalid assigned handoffs while ignoring unexpected agents", () => {
  withTempHome(() => {
    const domain = "example.com";
    const dir = sessionDir(domain);
    fs.mkdirSync(dir, { recursive: true });

    seedAssignments(domain, 3, [
      { agent: "a1", surface_id: "surface-a" },
      { agent: "a2", surface_id: "surface-b" },
    ]);

    writeFileAtomic(path.join(dir, "handoff-w3-a1.json"), "{bad json");
    writeUnexpectedHandoff(domain, "w3", "a9", { dead_ends: ["/ignored"] });

    const merged = JSON.parse(mergeWaveHandoffs({ target_domain: domain, wave_number: 3 }));
    assert.match(merged.invalid_handoffs[0]?.error || "", /JSON at position 1/);

	    assert.deepEqual(merged, {
	      assignments_total: 2,
	      handoffs_total: 2,
	      received_agents: [],
	      invalid_agents: ["a1"],
	      invalid_handoffs: [{
	        agent: "a1",
	        surface_id: "surface-a",
	        error: merged.invalid_handoffs[0].error,
	      }],
	      unexpected_agents: ["a9"],
      completed_surface_ids: [],
      partial_surface_ids: [],
      // R1-HIGH-#2 fix: invalid handoff surface_ids propagate to
      // missing_surface_ids; a1's surface-a now reaches the orchestrator.
      missing_surface_ids: ["surface-a", "surface-b"],
      dead_ends: [],
      waf_blocked_endpoints: [],
      lead_surface_ids: [],
      blocked_harness_runs: [],
      blocked_harness_runs_grouped: [],
      blocked_prereqs: [],
      blocked_prereqs_grouped: [],
      bypass_attempts: [],
      bypass_attempts_grouped: [],
      suspicion_flags: [],
      provenance: {
        verified_agents: [],
      },
    });
  });
});

test("bob_read_wave_handoffs returns validated structured summaries and ignores markdown", () => {
  withTempHome(() => {
    const domain = "example.com";
    const dir = sessionDir(domain);
    fs.mkdirSync(dir, { recursive: true });
    seedAssignments(domain, 1, [
      { agent: "a1", surface_id: "surface-a" },
      { agent: "a2", surface_id: "surface-b" },
    ]);
    writeWaveHandoff({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_status: "complete",
      summary: "A1 complete with an old dead end.",
      chain_notes: ["Old endpoint may chain into surface-b."],
      content: "# ignored markdown details",
      dead_ends: ["/old"],
      lead_surface_ids: ["surface-b"],
    });
    writeFileAtomic(path.join(dir, "handoff-w1-a2.md"), "# markdown only\n");

    const result = JSON.parse(readWaveHandoffs({ target_domain: domain }));
    assert.deepEqual(result.wave_numbers, [1]);
    assert.deepEqual(result.handoffs, [{
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      surface_type: null,
      surface_status: "complete",
      provenance: "verified",
      summary: "A1 complete with an old dead end.",
      chain_notes: ["Old endpoint may chain into surface-b."],
      blocked_harness_runs: [],
      blocked_prereqs: [],
      bypass_attempts: [],
      dead_ends: ["/old"],
      waf_blocked_endpoints: [],
      lead_surface_ids: ["surface-b"],
    }]);
    assert.deepEqual(result.missing_handoffs, [{ wave: "w1", agent: "a2", surface_id: "surface-b" }]);
    assert.deepEqual(result.invalid_handoffs, []);
    assert.deepEqual(result.unexpected_handoffs, []);
  });
});

test("bob_merge_wave_handoffs hard-fails when the assignment file is missing", () => {
  withTempHome(() => {
    assert.throws(
      () => mergeWaveHandoffs({ target_domain: "example.com", wave_number: 4 }),
      /Missing assignment file/,
    );
  });
});

test("bob_record_finding appends findings.jsonl and bob_read_findings preserves insertion order", () => {
  withTempHome(() => {
    const domain = "example.com";
    const first = seedFinding(domain);
    const second = seedFinding(domain, {
      title: "Stored XSS in comments",
      severity: "medium",
      endpoint: "/comments",
      description: "Unsanitized comment body executes in admin view.",
      proof_of_concept: "<script>alert(1)</script>",
      response_evidence: "<script>alert(1)</script>",
      impact: "Admin session compromise.",
      wave: "w2",
      agent: "a2",
    });

    assert.equal(first.finding_id, "F-1");
    assert.equal(second.finding_id, "F-2");

    const claimsPath = claimsJsonlPath(domain);
    const jsonlLines = fs.readFileSync(claimsPath, "utf8").trim().split("\n");
    assert.equal(jsonlLines.length, 2);
    assert.equal(JSON.parse(jsonlLines[0]).payload.finding.id, "F-1");
    assert.equal(JSON.parse(jsonlLines[1]).payload.finding.id, "F-2");

    const readResult = JSON.parse(readFindings({ target_domain: domain }));
    assert.match(readResult.findings[0].dedupe_key, /^[a-f0-9]{24}$/);
    assert.match(readResult.findings[1].dedupe_key, /^[a-f0-9]{24}$/);
    const readResultWithoutDedupeKeys = {
      ...readResult,
      findings: readResult.findings.map(({ dedupe_key, ...finding }) => finding),
    };
    assert.deepEqual(readResultWithoutDedupeKeys, {
      version: 1,
      target_domain: domain,
      findings: [
        {
          id: "F-1",
          target_domain: domain,
          title: "IDOR on account export",
          severity: "high",
          cwe: "CWE-639",
          endpoint: "/api/export",
          file_path: null,
          symbol: null,
          manifest: null,
          affected_package: null,
          affected_version_range: null,
          repro_command: null,
          description: "Authenticated user can export another account's data by changing account_id.",
          proof_of_concept: "curl https://example.com/api/export?account_id=2",
          response_evidence: "{\"account_id\":2}",
          impact: "Cross-account PII disclosure.",
          validated: true,
          wave: "w1",
          agent: "a1",
          surface_id: "surface-a",
          surface_type: "web",
          capability_pack: "web",
          evaluator_agent: "evaluator-agent",
          brief_profile: "web",
          sc_evidence: null,
          auth_profile: null,
        },
        {
          id: "F-2",
          target_domain: domain,
          title: "Stored XSS in comments",
          severity: "medium",
          cwe: "CWE-639",
          endpoint: "/comments",
          file_path: null,
          symbol: null,
          manifest: null,
          affected_package: null,
          affected_version_range: null,
          repro_command: null,
          description: "Unsanitized comment body executes in admin view.",
          proof_of_concept: "<script>alert(1)</script>",
          response_evidence: "<script>alert(1)</script>",
          impact: "Admin session compromise.",
          validated: true,
          wave: "w2",
          agent: "a2",
          surface_id: "surface-a",
          surface_type: "web",
          capability_pack: "web",
          evaluator_agent: "evaluator-agent",
          brief_profile: "web",
          sc_evidence: null,
          auth_profile: null,
        },
      ],
    });
  });
});

test("bob_record_finding stamps surface_type from the assignment and treats SC findings as requiring sc_evidence", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAttackSurfaces(domain, [
      { id: "surface-web", hosts: [`https://${domain}`], surface_type: "api" },
      { id: "surface-sc", hosts: [`https://${domain}`], surface_type: "smart_contract", chain_family: "evm" },
    ]);
    seedAssignments(domain, 1, [
      { agent: "a1", surface_id: "surface-web" },
      { agent: "a2", surface_id: "surface-sc" },
    ]);

    const webFinding = JSON.parse(recordFinding({
      target_domain: domain,
      title: "IDOR on account export",
      severity: "high",
      cwe: "CWE-639",
      endpoint: "/api/export",
      description: "Authenticated user can export another account's data by changing account_id.",
      proof_of_concept: "curl https://example.com/api/export?account_id=2",
      response_evidence: "{\"account_id\":2}",
      impact: "Cross-account PII disclosure.",
      validated: true,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-web",
    }));
    assert.equal(webFinding.recorded, true);
    const webRow = readFindings({ target_domain: domain });
    const webRowFindings = JSON.parse(webRow).findings;
    assert.equal(webRowFindings[0].surface_type, "web");
    assert.equal(webRowFindings[0].sc_evidence, null);

    // SC finding without sc_evidence must be rejected
    assert.throws(() => recordFinding({
      target_domain: domain,
      title: "Reentrancy in Vault.borrow",
      severity: "high",
      cwe: "CWE-841",
      endpoint: "0x" + "11".repeat(20) + ":borrow(uint256)",
      description: "Reentrancy via callback before balance update.",
      proof_of_concept: "See harness test",
      response_evidence: "Drained 1000 ETH",
      impact: "Permanent loss of all vault funds.",
      validated: true,
      wave: "w1",
      agent: "a2",
      surface_id: "surface-sc",
    }), /smart-contract findings must include sc_evidence/);

    // Web finding with sc_evidence must be rejected
    assert.throws(() => recordFinding({
      target_domain: domain,
      title: "XSS",
      severity: "low",
      cwe: "CWE-79",
      endpoint: "/admin",
      description: "Reflected XSS",
      proof_of_concept: "?q=<script>",
      response_evidence: "<script>",
      impact: "Session compromise",
      validated: true,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-web",
      sc_evidence: {
        chain_id: 1,
        contract_address: "0x" + "11".repeat(20),
        harness_path: os.homedir(),
        match_test: "test_x",
      },
    }), /sc_evidence is only allowed on smart_contract findings/);

    // SC finding with valid sc_evidence is accepted and persisted
    const scResult = JSON.parse(recordFinding({
      target_domain: domain,
      title: "Reentrancy in Vault.borrow",
      severity: "high",
      cwe: "CWE-841",
      endpoint: "0x" + "11".repeat(20) + ":borrow(uint256)",
      description: "Reentrancy via callback before balance update.",
      proof_of_concept: "See harness test",
      response_evidence: "Drained 1000 ETH",
      impact: "Permanent loss of all vault funds.",
      validated: true,
      wave: "w1",
      agent: "a2",
      surface_id: "surface-sc",
      sc_evidence: {
        chain_id: 1,
        contract_address: "0x" + "AB".repeat(20),
        harness_path: os.homedir(),
        match_test: "test_borrow_reentrancy",
        fork_block: 19_000_000,
        function_signature: "borrow(uint256)",
      },
    }));
    assert.equal(scResult.recorded, true);
    const scRows = JSON.parse(readFindings({ target_domain: domain })).findings;
    const scFinding = scRows.find((f) => f.id === scResult.finding_id);
    assert.equal(scFinding.surface_type, "smart_contract");
    assert.equal(scFinding.sc_evidence.chain_id, 1);
    // contract_address normalized to lowercase
    assert.equal(scFinding.sc_evidence.contract_address, "0x" + "ab".repeat(20));
    assert.equal(scFinding.sc_evidence.fork_block, 19_000_000);
  });
});

test("bob_record_finding persists capability_pack metadata from the assignment", () => {
  // Web evaluator: the assignment carries the web pack triple and recordFinding
  // must persist all three fields verbatim into findings.jsonl.
  withTempHome(() => {
    const domain = "example.com";
    seedAttackSurfaces(domain, [
      { id: "surface-web", hosts: [`https://${domain}`], surface_type: "api" },
    ]);
    seedAssignments(domain, 1, [{
      agent: "a1",
      surface_id: "surface-web",
      capability_pack: "web",
      evaluator_agent: "evaluator-agent",
      brief_profile: "web",
    }]);
    JSON.parse(recordFinding({
      target_domain: domain,
      title: "IDOR on account export",
      severity: "high",
      cwe: "CWE-639",
      endpoint: "/api/export",
      description: "Cross-account export.",
      proof_of_concept: "curl ...",
      response_evidence: "{}",
      impact: "PII.",
      validated: true,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-web",
    }));
    const finding = JSON.parse(readFindings({ target_domain: domain })).findings[0];
    assert.equal(finding.capability_pack, "web");
    assert.equal(finding.evaluator_agent, "evaluator-agent");
    assert.equal(finding.brief_profile, "web");
    assert.equal(finding.surface_type, "web");
  });
});

test("bob_record_finding persists smart_contract_evm pack metadata for an EVM evaluator wave", () => {
  // SC evaluator: the routed pack is smart_contract_evm. Persisting it on the
  // finding lets verifier/grader/reporter dispatch on the routed decision
  // rather than re-deriving from sc_evidence.chain_family.
  withTempHome(() => {
    const domain = "example.com";
    seedAttackSurfaces(domain, [
      { id: "surface-evm", hosts: [`https://${domain}`], surface_type: "smart_contract", chain_family: "evm" },
    ]);
    seedAssignments(domain, 1, [{
      agent: "a1",
      surface_id: "surface-evm",
      capability_pack: "smart_contract_evm",
      evaluator_agent: "evaluator-evm-agent",
      brief_profile: "smart_contract_evm",
    }]);
    JSON.parse(recordFinding({
      target_domain: domain,
      title: "Reentrancy in Vault.borrow",
      severity: "high",
      cwe: "CWE-841",
      endpoint: "0x" + "11".repeat(20) + ":borrow(uint256)",
      description: "Reentrancy via callback before balance update.",
      proof_of_concept: "See harness test",
      response_evidence: "Drained 1000 ETH",
      impact: "Loss of vault funds.",
      validated: true,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-evm",
      sc_evidence: {
        chain_family: "evm",
        chain_id: 1,
        contract_address: "0x" + "11".repeat(20),
        harness_path: os.homedir(),
        match_test: "test_borrow_reentrancy",
      },
    }));
    const finding = JSON.parse(readFindings({ target_domain: domain })).findings[0];
    assert.equal(finding.capability_pack, "smart_contract_evm");
    assert.equal(finding.evaluator_agent, "evaluator-evm-agent");
    assert.equal(finding.brief_profile, "smart_contract_evm");
    assert.equal(finding.surface_type, "smart_contract");
  });
});

test("bob_record_finding persists smart_contract_substrate pack metadata for a Substrate evaluator wave", () => {
  // Sanity that non-EVM SC packs round-trip too.
  withTempHome(() => {
    const domain = "example.com";
    seedAttackSurfaces(domain, [
      { id: "surface-sub", hosts: [`https://${domain}`], surface_type: "smart_contract", chain_family: "substrate" },
    ]);
    seedAssignments(domain, 1, [{
      agent: "a1",
      surface_id: "surface-sub",
      capability_pack: "smart_contract_substrate",
      evaluator_agent: "evaluator-substrate-agent",
      brief_profile: "smart_contract_substrate",
    }]);
    JSON.parse(recordFinding({
      target_domain: domain,
      title: "Selector collision in ink contract",
      severity: "medium",
      cwe: "CWE-840",
      endpoint: "5GrwvaEF...:transfer(u128)",
      description: "Two messages share the same 4-byte selector.",
      proof_of_concept: "See cargo test",
      response_evidence: "wrong message dispatched",
      impact: "Incorrect call routing.",
      validated: true,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-sub",
      sc_evidence: {
        chain_family: "substrate",
        chain_id: "polkadot",
        contract_address: "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
        harness_path: os.homedir(),
        match_test: "test_selector_collision",
      },
    }));
    const finding = JSON.parse(readFindings({ target_domain: domain })).findings[0];
    assert.equal(finding.capability_pack, "smart_contract_substrate");
    assert.equal(finding.evaluator_agent, "evaluator-substrate-agent");
    assert.equal(finding.brief_profile, "smart_contract_substrate");
  });
});

test("normalizeFindingRecord backfills capability_pack metadata for legacy web rows", () => {
  // Old findings.jsonl rows from before routing-metadata existed did not
  // carry capability_pack. Read-side derives the pack triple from
  // surface_type so downstream consumers never see null and don't need to
  // re-implement the surface_type→pack mapping.
  const { normalizeFindingRecord } = require("../mcp/lib/finding-contracts.js");
  const legacyFinding = normalizeFindingRecord({
    id: "F-1",
    target_domain: "example.com",
    title: "Legacy IDOR",
    severity: "high",
    endpoint: "/api/x",
    description: "Legacy row written by an older Bob version.",
    proof_of_concept: "curl ...",
    validated: true,
    wave: "w1",
    agent: "a1",
    surface_id: "surface-a",
    surface_type: "web",
  });
  assert.equal(legacyFinding.capability_pack, "web");
  assert.equal(legacyFinding.evaluator_agent, "evaluator-agent");
  assert.equal(legacyFinding.brief_profile, "web");
  assert.equal(legacyFinding.surface_type, "web");
});

test("normalizeFindingRecord backfills capability_pack metadata for legacy SC rows from chain_family", () => {
  // Legacy SC findings carry sc_evidence.chain_family. Backfill must derive
  // the right pack — smart_contract_evm for chain_family="evm",
  // smart_contract_substrate for chain_family="substrate", etc.
  const { normalizeFindingRecord } = require("../mcp/lib/finding-contracts.js");
  const legacyEvm = normalizeFindingRecord({
    id: "F-1",
    target_domain: "example.com",
    title: "Legacy reentrancy",
    severity: "high",
    endpoint: "0x" + "ab".repeat(20) + ":withdraw()",
    description: "Pre-Phase-C SC row.",
    proof_of_concept: "See harness",
    validated: true,
    wave: "w1",
    agent: "a1",
    surface_id: "surface-evm",
    surface_type: "smart_contract",
    sc_evidence: {
      chain_family: "evm",
      chain_id: 1,
      contract_address: "0x" + "ab".repeat(20),
      harness_path: os.homedir(),
      match_test: "test_reentrancy",
    },
  });
  assert.equal(legacyEvm.capability_pack, "smart_contract_evm");
  assert.equal(legacyEvm.evaluator_agent, "evaluator-evm-agent");
  assert.equal(legacyEvm.brief_profile, "smart_contract_evm");

  const legacySvm = normalizeFindingRecord({
    id: "F-2",
    target_domain: "example.com",
    title: "Legacy SVM",
    severity: "medium",
    endpoint: "Programs:11111111111111111111111111111111:transfer",
    description: "Pre-Phase-C SVM row.",
    proof_of_concept: "See harness",
    validated: true,
    wave: "w1",
    agent: "a2",
    surface_id: "surface-svm",
    surface_type: "smart_contract",
    sc_evidence: {
      chain_family: "svm",
      chain_id: "mainnet-beta",
      contract_address: "11111111111111111111111111111111",
      harness_path: os.homedir(),
      match_test: "test_x",
    },
  });
  assert.equal(legacySvm.capability_pack, "smart_contract_svm");
  assert.equal(legacySvm.evaluator_agent, "evaluator-svm-agent");
  assert.equal(legacySvm.brief_profile, "smart_contract_svm");
});

test("bob_record_finding rejects sc_evidence in the no-wave/no-agent path so SC findings stay routed", () => {
  // The no-wave path hardcodes the web pack triple. If a future caller
  // tries to record SC evidence without wave/agent, the routed pack would
  // silently be web — downstream verifier/evidence dispatch would route to
  // evaluator-agent for an SC finding. Local assert keeps the invariant honest
  // at the call site.
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "EVALUATE" });
    seedAttackSurfaces(domain, [
      { id: "surface-evm", hosts: [`https://${domain}`], surface_type: "smart_contract", chain_family: "evm" },
    ]);
    assert.throws(() => recordFinding({
      target_domain: domain,
      title: "SC finding via no-wave",
      severity: "high",
      cwe: "CWE-841",
      endpoint: "0x" + "ab".repeat(20) + ":withdraw()",
      description: "should be rejected",
      proof_of_concept: "x",
      response_evidence: "x",
      impact: "x",
      validated: true,
      sc_evidence: {
        chain_family: "evm",
        chain_id: 1,
        contract_address: "0x" + "ab".repeat(20),
        harness_path: os.homedir(),
        match_test: "test_x",
      },
    }), /sc_evidence findings must be recorded with wave and agent/);
  });
});

test("classifySurfaceCapability throws on smart_contract surface with missing or unsupported chain_family", () => {
  // Pre-fix the router silently fell back to the web pack for SC surfaces
  // with no chain_family, producing surface_type="smart_contract" routed to
  // evaluator-agent (a contradiction). Now the router fails loudly so the
  // operator either fixes the surface or registers the missing pack.
  const { classifySurfaceCapability } = require("../mcp/lib/capability-packs.js");
  assert.throws(
    () => classifySurfaceCapability({ id: "surface-mystery", surface_type: "smart_contract" }),
    /missing chain_family/,
  );
  assert.throws(
    () => classifySurfaceCapability({ id: "surface-near", surface_type: "smart_contract", chain_family: "near" }),
    /unsupported chain_family/,
  );
});

test("normalizeAssignmentRouteMetadata throws on smart_contract assignment without route metadata", () => {
  // The all-null shortcut used to silently substitute web defaults for any
  // assignment lacking the triple. That meant a smart_contract assignment
  // whose route metadata had been dropped (forged file, half-rolled-back
  // upgrade, etc.) got rubber-stamped as web. Fail loudly instead.
  const { normalizeAssignmentRouteMetadata } = require("../mcp/lib/capability-packs.js");
  assert.throws(
    () => normalizeAssignmentRouteMetadata({
      agent: "a1",
      surface_id: "surface-evm",
      surface_type: "smart_contract",
    }),
    /surface_type=smart_contract is missing capability_pack/,
  );
  assert.throws(
    () => normalizeAssignmentRouteMetadata({
      agent: "a1",
      surface_id: "surface-web",
      surface_type: "api",
      capability_pack_version: 1,
    }),
    /assignment route metadata has invalid capability_pack/,
  );
  assert.throws(
    () => normalizeAssignmentRouteMetadata({
      agent: "a1",
      surface_id: "surface-web",
      surface_type: "api",
      context_budget: expectedWebContextBudget(),
    }),
    /assignment route metadata has invalid capability_pack/,
  );
  // Web assignment with no route metadata still legitimately defaults to web.
  const webMeta = normalizeAssignmentRouteMetadata({
    agent: "a1",
    surface_id: "surface-web",
    surface_type: "api",
  });
  assert.equal(webMeta.capability_pack, "web");
});

test("recordFinding stamps the routed capability pack on the embedded claim payload", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAttackSurfaces(domain, [
      { id: "surface-evm", hosts: [`https://${domain}`], surface_type: "smart_contract", chain_family: "evm" },
    ]);
    seedAssignments(domain, 1, [{
      agent: "a1",
      surface_id: "surface-evm",
      capability_pack: "smart_contract_evm",
      evaluator_agent: "evaluator-evm-agent",
      brief_profile: "smart_contract_evm",
    }]);
    JSON.parse(recordFinding({
      target_domain: domain,
      title: "EVM reentrancy",
      severity: "critical",
      cwe: "CWE-841",
      endpoint: "0x" + "ab".repeat(20) + ":withdraw()",
      description: "Reentrancy on withdraw.",
      proof_of_concept: "See harness",
      response_evidence: "Drained.",
      impact: "Funds loss.",
      validated: true,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-evm",
      sc_evidence: {
        chain_family: "evm",
        chain_id: 1,
        contract_address: "0x" + "ab".repeat(20),
        harness_path: os.homedir(),
        match_test: "test_reentrancy",
      },
    }));
    const [finding] = readFindingsFromJsonl(domain);
    assert.equal(finding.capability_pack, "smart_contract_evm");
    assert.equal(finding.evaluator_agent, "evaluator-evm-agent");
  });
});

test("normalizeFindingRecord forbids sc_evidence on legacy null-surface rows (back-compat smuggling)", () => {
  const { normalizeFindingRecord } = require("../mcp/lib/finding-contracts.js");
  // A legacy row may have surface_type=null. The original guard forbade
  // sc_evidence only on surface_type="web", so a malicious or buggy row
  // could carry SC replay data while being routed as web by verifiers.
  // sc_evidence is now allowed only when surface_type === "smart_contract".
  assert.throws(() => normalizeFindingRecord({
    id: "F-1",
    target_domain: "example.com",
    title: "Looks web",
    severity: "low",
    cwe: null,
    endpoint: "/x",
    description: "x",
    proof_of_concept: "y",
    response_evidence: null,
    impact: null,
    validated: true,
    wave: null,
    agent: null,
    surface_id: null,
    surface_type: null,
    sc_evidence: {
      chain_id: 1,
      contract_address: "0x" + "11".repeat(20),
      harness_path: os.homedir(),
      match_test: "test_x",
    },
  }), /sc_evidence is only allowed on smart_contract findings/);
});

test("bob_record_finding rejects sc_evidence with a symlink that escapes $HOME (realpath check)", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAttackSurfaces(domain, [
      { id: "surface-sc", hosts: [`https://${domain}`], surface_type: "smart_contract", chain_family: "evm" },
    ]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-sc" }]);
    // Plant $HOME/escape -> /tmp/outside-home (a directory outside the
    // ephemeral $HOME). Lexical containment passes; realpath escapes.
    const home = os.homedir();
    const tmpRoot = path.join(os.tmpdir(), "bob-symlink-bypass-" + Math.random().toString(36).slice(2));
    fs.mkdirSync(tmpRoot, { recursive: true });
    const linkPath = path.join(home, "escape-link");
    try { fs.unlinkSync(linkPath); } catch {}
    fs.symlinkSync(tmpRoot, linkPath, "dir");
    try {
      assert.throws(() => recordFinding({
        target_domain: domain,
        title: "Reentrancy",
        severity: "high",
        endpoint: "0x" + "11".repeat(20) + ":borrow",
        description: "x",
        proof_of_concept: "y",
        validated: true,
        wave: "w1",
        agent: "a1",
        surface_id: "surface-sc",
        sc_evidence: {
          chain_id: 1,
          contract_address: "0x" + "11".repeat(20),
          harness_path: linkPath,
          match_test: "test_x",
        },
      }), /must live under the user home directory/);
    } finally {
      try { fs.unlinkSync(linkPath); } catch {}
      try { fs.rmdirSync(tmpRoot); } catch {}
    }
  });
});

test("bob_record_finding rejects sc_evidence with harness_path outside the user home", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAttackSurfaces(domain, [
      { id: "surface-sc", hosts: [`https://${domain}`], surface_type: "smart_contract", chain_family: "evm" },
    ]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-sc" }]);
    assert.throws(() => recordFinding({
      target_domain: domain,
      title: "Reentrancy",
      severity: "high",
      endpoint: "0x" + "11".repeat(20) + ":borrow",
      description: "x",
      proof_of_concept: "y",
      validated: true,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-sc",
      sc_evidence: {
        chain_id: 1,
        contract_address: "0x" + "11".repeat(20),
        harness_path: "/etc",
        match_test: "test_x",
      },
    }), /harness_path must live under the user home directory/);
  });
});

test("bob_record_finding accepts SVM sc_evidence with chain_family='svm' and base58 program id", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAttackSurfaces(domain, [
      { id: "surface-svm", hosts: [`https://${domain}`], surface_type: "smart_contract", chain_family: "svm" },
    ]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-svm" }]);
    // System Program 11111111111111111111111111111111 is the canonical short
    // base58 32-byte all-zero pubkey — useful as a deterministic fixture.
    const programId = "11111111111111111111111111111111";
    const result = JSON.parse(recordFinding({
      target_domain: domain,
      title: "Missing signer check on Vault.withdraw",
      severity: "high",
      cwe: "CWE-862",
      endpoint: programId + ":withdraw",
      description: "Withdraw instruction does not require the vault authority signer.",
      proof_of_concept: "anchor test --grep withdraw_unauthorized",
      response_evidence: "Drained 1000 SOL via missing signer check",
      impact: "Permanent loss of all vault deposits.",
      validated: true,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-svm",
      sc_evidence: {
        chain_family: "svm",
        chain_id: "mainnet-beta",
        contract_address: programId,
        harness_path: os.homedir(),
        match_test: "withdraw_unauthorized",
        fork_block: 250_000_000,
        function_signature: "Withdraw{amount: u64}",
      },
    }));
    assert.equal(result.recorded, true);
    const rows = JSON.parse(readFindings({ target_domain: domain })).findings;
    const svmFinding = rows.find((f) => f.id === result.finding_id);
    assert.equal(svmFinding.surface_type, "smart_contract");
    assert.equal(svmFinding.sc_evidence.chain_family, "svm");
    assert.equal(svmFinding.sc_evidence.chain_id, "mainnet-beta");
    // base58 is case-sensitive — verbatim preservation
    assert.equal(svmFinding.sc_evidence.contract_address, programId);
    assert.equal(svmFinding.sc_evidence.fork_block, 250_000_000);
  });
});

test("sc_evidence rejects chain_family='svm' with EVM-style 0x address", () => {
  const { normalizeFindingRecord } = require("../mcp/lib/finding-contracts.js");
  assert.throws(() => normalizeFindingRecord({
    id: "F-1",
    target_domain: "example.com",
    title: "x",
    severity: "low",
    cwe: null,
    endpoint: "x",
    description: "x",
    proof_of_concept: "y",
    response_evidence: null,
    impact: null,
    validated: true,
    wave: null,
    agent: null,
    surface_id: null,
    surface_type: "smart_contract",
    sc_evidence: {
      chain_family: "svm",
      chain_id: "mainnet-beta",
      contract_address: "0x" + "11".repeat(20),
      harness_path: os.homedir(),
      match_test: "test_x",
    },
  }), /contract_address must be a base58 32-44 char Solana program id/);
});

test("sc_evidence rejects chain_family='evm' with base58 svm pubkey", () => {
  const { normalizeFindingRecord } = require("../mcp/lib/finding-contracts.js");
  assert.throws(() => normalizeFindingRecord({
    id: "F-1",
    target_domain: "example.com",
    title: "x",
    severity: "low",
    cwe: null,
    endpoint: "x",
    description: "x",
    proof_of_concept: "y",
    response_evidence: null,
    impact: null,
    validated: true,
    wave: null,
    agent: null,
    surface_id: null,
    surface_type: "smart_contract",
    sc_evidence: {
      chain_family: "evm",
      chain_id: 1,
      contract_address: "11111111111111111111111111111111",
      harness_path: os.homedir(),
      match_test: "test_x",
    },
  }), /contract_address must be a 0x-prefixed 40-hex EVM address/);
});

test("sc_evidence rejects chain_family='svm' with unknown cluster", () => {
  const { normalizeFindingRecord } = require("../mcp/lib/finding-contracts.js");
  assert.throws(() => normalizeFindingRecord({
    id: "F-1",
    target_domain: "example.com",
    title: "x",
    severity: "low",
    cwe: null,
    endpoint: "x",
    description: "x",
    proof_of_concept: "y",
    response_evidence: null,
    impact: null,
    validated: true,
    wave: null,
    agent: null,
    surface_id: null,
    surface_type: "smart_contract",
    sc_evidence: {
      chain_family: "svm",
      chain_id: "rogue-cluster",
      contract_address: "11111111111111111111111111111111",
      harness_path: os.homedir(),
      match_test: "test_x",
    },
  }), /chain_id must be one of: mainnet-beta, devnet, testnet/);
});

test("sc_evidence rejects chain_family='svm' with base58 alphabet violation (0/O/I/l)", () => {
  const { normalizeFindingRecord } = require("../mcp/lib/finding-contracts.js");
  // "0" is not in the base58 alphabet — a pubkey that contains it must be rejected.
  // System Program prefix with one '0' substituted in.
  assert.throws(() => normalizeFindingRecord({
    id: "F-1",
    target_domain: "example.com",
    title: "x",
    severity: "low",
    cwe: null,
    endpoint: "x",
    description: "x",
    proof_of_concept: "y",
    response_evidence: null,
    impact: null,
    validated: true,
    wave: null,
    agent: null,
    surface_id: null,
    surface_type: "smart_contract",
    sc_evidence: {
      chain_family: "svm",
      chain_id: "mainnet-beta",
      contract_address: "0111111111111111111111111111111", // contains '0' (invalid in base58)
      harness_path: os.homedir(),
      match_test: "test_x",
    },
  }), /contract_address must be a base58 32-44 char Solana program id/);
});

test("sc_evidence rejects unknown chain_family value", () => {
  const { normalizeFindingRecord } = require("../mcp/lib/finding-contracts.js");
  assert.throws(() => normalizeFindingRecord({
    id: "F-1",
    target_domain: "example.com",
    title: "x",
    severity: "low",
    cwe: null,
    endpoint: "x",
    description: "x",
    proof_of_concept: "y",
    response_evidence: null,
    impact: null,
    validated: true,
    wave: null,
    agent: null,
    surface_id: null,
    surface_type: "smart_contract",
    sc_evidence: {
      chain_family: "tron",
      chain_id: 1,
      contract_address: "0x" + "11".repeat(20),
      harness_path: os.homedir(),
      match_test: "test_x",
    },
  }), /chain_family must be one of: evm, svm, aptos, sui, substrate, cosmwasm/);
});

test("sc_evidence chain_family defaults to 'evm' when omitted (back-compat)", () => {
  const { normalizeFindingRecord } = require("../mcp/lib/finding-contracts.js");
  // A legacy row may have no chain_family field at all. The normalizer
  // defaults to 'evm' so existing findings.jsonl rows keep validating.
  const finding = normalizeFindingRecord({
    id: "F-1",
    target_domain: "example.com",
    title: "Reentrancy",
    severity: "high",
    cwe: "CWE-841",
    endpoint: "0x" + "11".repeat(20) + ":borrow",
    description: "x",
    proof_of_concept: "y",
    response_evidence: null,
    impact: null,
    validated: true,
    wave: null,
    agent: null,
    surface_id: null,
    surface_type: "smart_contract",
    sc_evidence: {
      // no chain_family
      chain_id: 1,
      contract_address: "0x" + "AB".repeat(20),
      harness_path: os.homedir(),
      match_test: "test_x",
    },
  });
  assert.equal(finding.sc_evidence.chain_family, "evm");
  assert.equal(finding.sc_evidence.chain_id, 1);
  assert.equal(finding.sc_evidence.contract_address, "0x" + "ab".repeat(20));
});

test("foundry runner translates Success/Failure to Pass/Fail and caps tests[] at 100", () => {
  const { summarizeForgeJson } = require("../mcp/lib/foundry-runner.js");
  // Two suites, mix of statuses including unknown.
  const result = summarizeForgeJson({
    "Vault.t.sol:VaultTest": {
      test_results: {
        "test_borrow_reentrancy": { status: "Success", reason: null },
        "test_repay_revert": { status: "Failure", reason: "expected revert" },
        "test_skip_branch": { status: "Skipped" },
      },
    },
  });
  assert.equal(result.total, 3);
  assert.equal(result.passed, 1);
  assert.equal(result.failed, 2);
  assert.equal(result.tests[0].status, "Pass");
  assert.equal(result.tests[0].status_raw, "Success");
  assert.equal(result.tests[1].status, "Fail");
  assert.equal(result.tests[1].status_raw, "Failure");
  assert.equal(result.tests[2].status, "Skipped");
  assert.equal(result.truncated, false);

  // Synthesize 150 tests in a single suite to assert cap + truncated flag.
  const big = { "Big.t.sol:BigTest": { test_results: {} } };
  for (let i = 0; i < 150; i += 1) {
    big["Big.t.sol:BigTest"].test_results[`test_${i}`] = { status: "Success" };
  }
  const capped = summarizeForgeJson(big);
  assert.equal(capped.total, 150);
  assert.equal(capped.passed, 150);
  assert.equal(capped.tests.length, 100, "tests[] must be capped at 100");
  assert.equal(capped.truncated, true);
});

test("sc_evidence svm pubkey rejects strings that pass alphabet but decode to <32 bytes", () => {
  const { normalizeFindingRecord } = require("../mcp/lib/finding-contracts.js");
  // 32 chars of valid base58 alphabet that are NOT leading-1s decode to ~23 bytes
  // (32 * log2(58) / 8 ≈ 23.4). The alphabet+length regex passes; the decode-length
  // check must catch it. Use a deterministic 32-char string with no leading "1".
  assert.throws(() => normalizeFindingRecord({
    id: "F-1",
    target_domain: "example.com",
    title: "x",
    severity: "low",
    cwe: null,
    endpoint: "x",
    description: "x",
    proof_of_concept: "y",
    response_evidence: null,
    impact: null,
    validated: true,
    wave: null,
    agent: null,
    surface_id: null,
    surface_type: "smart_contract",
    sc_evidence: {
      chain_family: "svm",
      chain_id: "mainnet-beta",
      contract_address: "AaBbCcDdEeFfGgHhJjKkMmNnPpQqRrSs", // 32 chars no leading 1
      harness_path: os.homedir(),
      match_test: "test_x",
    },
  }), /must base58-decode to exactly 32 bytes/);
});

test("bob_record_finding accepts Aptos sc_evidence with chain_family='aptos' and 0x64-hex module address", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAttackSurfaces(domain, [
      { id: "surface-aptos", hosts: [`https://${domain}`], surface_type: "smart_contract", chain_family: "aptos" },
    ]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-aptos" }]);
    const moduleAddr = "0x" + "ab".repeat(32); // 64 hex chars
    const result = JSON.parse(recordFinding({
      target_domain: domain,
      title: "Capability leak in CoinStore::deposit",
      severity: "high",
      cwe: "CWE-862",
      endpoint: moduleAddr + "::CoinStore::deposit",
      description: "Capability acquire happens outside has_capability gate.",
      proof_of_concept: "aptos move test --filter test_capability_leak",
      response_evidence: "Drained 1000 APT via missing capability check",
      impact: "Permanent loss of all CoinStore deposits.",
      validated: true,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-aptos",
      sc_evidence: {
        chain_family: "aptos",
        chain_id: "mainnet",
        contract_address: moduleAddr,
        harness_path: os.homedir(),
        match_test: "test_capability_leak",
        fork_block: 1_500_000,
        function_signature: "CoinStore::deposit",
      },
    }));
    assert.equal(result.recorded, true);
    const rows = JSON.parse(readFindings({ target_domain: domain })).findings;
    const aptosFinding = rows.find((f) => f.id === result.finding_id);
    assert.equal(aptosFinding.surface_type, "smart_contract");
    assert.equal(aptosFinding.sc_evidence.chain_family, "aptos");
    assert.equal(aptosFinding.sc_evidence.chain_id, "mainnet");
    assert.equal(aptosFinding.sc_evidence.contract_address, moduleAddr);
    assert.equal(aptosFinding.sc_evidence.fork_block, 1_500_000);
  });
});

test("bob_record_finding accepts Sui sc_evidence with chain_family='sui' and 0x64-hex package id", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAttackSurfaces(domain, [
      { id: "surface-sui", hosts: [`https://${domain}`], surface_type: "smart_contract", chain_family: "sui" },
    ]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-sui" }]);
    const packageId = "0x" + "cd".repeat(32);
    const result = JSON.parse(recordFinding({
      target_domain: domain,
      title: "Object ownership violation in Vault::withdraw",
      severity: "critical",
      cwe: "CWE-863",
      endpoint: packageId + "::vault::withdraw",
      description: "Public entry function transfers Coin without verifying owner.",
      proof_of_concept: "sui move test --filter test_object_ownership",
      response_evidence: "Drained 1M SUI via wrong-owner withdrawal",
      impact: "Permanent loss of all vault deposits.",
      validated: true,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-sui",
      sc_evidence: {
        chain_family: "sui",
        chain_id: "mainnet",
        contract_address: packageId,
        harness_path: os.homedir(),
        match_test: "test_object_ownership",
        fork_block: 67_000_000,
        function_signature: "vault::withdraw",
      },
    }));
    assert.equal(result.recorded, true);
    const rows = JSON.parse(readFindings({ target_domain: domain })).findings;
    const suiFinding = rows.find((f) => f.id === result.finding_id);
    assert.equal(suiFinding.surface_type, "smart_contract");
    assert.equal(suiFinding.sc_evidence.chain_family, "sui");
    assert.equal(suiFinding.sc_evidence.chain_id, "mainnet");
    assert.equal(suiFinding.sc_evidence.contract_address, packageId);
    assert.equal(suiFinding.sc_evidence.fork_block, 67_000_000);
  });
});

test("sc_evidence normalizes Move shorthand address (0x1) to canonical 64-hex form", () => {
  const { normalizeFindingRecord } = require("../mcp/lib/finding-contracts.js");
  // Aptos prints framework addresses as shorthand: "0x1" is the std lib,
  // canonically "0x000...001". The normalizer must left-pad so two findings
  // recorded against "0x1" and "0x0000...0001" share the same dedupe key.
  const finding = normalizeFindingRecord({
    id: "F-1",
    target_domain: "example.com",
    title: "x",
    severity: "low",
    cwe: null,
    endpoint: "x",
    description: "x",
    proof_of_concept: "y",
    response_evidence: null,
    impact: null,
    validated: true,
    wave: null,
    agent: null,
    surface_id: null,
    surface_type: "smart_contract",
    sc_evidence: {
      chain_family: "aptos",
      chain_id: "mainnet",
      contract_address: "0x1",
      harness_path: os.homedir(),
      match_test: "test_x",
    },
  });
  // 0x + 63 zeros + "1"
  assert.equal(finding.sc_evidence.contract_address, "0x" + "0".repeat(63) + "1");
});

test("sc_evidence rejects chain_family='aptos' with unknown network", () => {
  const { normalizeFindingRecord } = require("../mcp/lib/finding-contracts.js");
  assert.throws(() => normalizeFindingRecord({
    id: "F-1",
    target_domain: "example.com",
    title: "x",
    severity: "low",
    cwe: null,
    endpoint: "x",
    description: "x",
    proof_of_concept: "y",
    response_evidence: null,
    impact: null,
    validated: true,
    wave: null,
    agent: null,
    surface_id: null,
    surface_type: "smart_contract",
    sc_evidence: {
      chain_family: "aptos",
      chain_id: "rogue-net",
      contract_address: "0x" + "ab".repeat(32),
      harness_path: os.homedir(),
      match_test: "test_x",
    },
  }), /chain_id must be one of: mainnet, testnet, devnet/);
});

test("sc_evidence rejects chain_family='sui' with unknown network", () => {
  const { normalizeFindingRecord } = require("../mcp/lib/finding-contracts.js");
  assert.throws(() => normalizeFindingRecord({
    id: "F-1",
    target_domain: "example.com",
    title: "x",
    severity: "low",
    cwe: null,
    endpoint: "x",
    description: "x",
    proof_of_concept: "y",
    response_evidence: null,
    impact: null,
    validated: true,
    wave: null,
    agent: null,
    surface_id: null,
    surface_type: "smart_contract",
    sc_evidence: {
      chain_family: "sui",
      chain_id: "rogue-net",
      contract_address: "0x" + "ab".repeat(32),
      harness_path: os.homedir(),
      match_test: "test_x",
    },
  }), /chain_id must be one of: mainnet, testnet, devnet, localnet/);
});

test("sc_evidence rejects Move family with non-hex address", () => {
  const { normalizeFindingRecord } = require("../mcp/lib/finding-contracts.js");
  // Aptos evaluator accidentally pasted a base58 svm pubkey. Move normalizer
  // must reject because address fails the 0x+hex regex.
  assert.throws(() => normalizeFindingRecord({
    id: "F-1",
    target_domain: "example.com",
    title: "x",
    severity: "low",
    cwe: null,
    endpoint: "x",
    description: "x",
    proof_of_concept: "y",
    response_evidence: null,
    impact: null,
    validated: true,
    wave: null,
    agent: null,
    surface_id: null,
    surface_type: "smart_contract",
    sc_evidence: {
      chain_family: "aptos",
      chain_id: "mainnet",
      contract_address: "11111111111111111111111111111111",
      harness_path: os.homedir(),
      match_test: "test_x",
    },
  }), /contract_address must be a 0x-prefixed hex address \(1-64 hex chars\) when chain_family='aptos'/);
});

test("sc_evidence rejects Move family with empty 0x address (no hex chars)", () => {
  const { normalizeFindingRecord } = require("../mcp/lib/finding-contracts.js");
  // 0x with zero hex chars is technically not a Move address (Aptos shorthand
  // requires at least one hex char). Regex {1,64} prevents the empty case.
  assert.throws(() => normalizeFindingRecord({
    id: "F-1",
    target_domain: "example.com",
    title: "x",
    severity: "low",
    cwe: null,
    endpoint: "x",
    description: "x",
    proof_of_concept: "y",
    response_evidence: null,
    impact: null,
    validated: true,
    wave: null,
    agent: null,
    surface_id: null,
    surface_type: "smart_contract",
    sc_evidence: {
      chain_family: "sui",
      chain_id: "mainnet",
      contract_address: "0x",
      harness_path: os.homedir(),
      match_test: "test_x",
    },
  }), /contract_address must be a 0x-prefixed hex address \(1-64 hex chars\) when chain_family='sui'/);
});

test("sc_evidence rejects chain_family='aptos' with integer chain_id (must be string network)", () => {
  const { normalizeFindingRecord } = require("../mcp/lib/finding-contracts.js");
  // Aptos has an integer chain_id (1 = mainnet) used for replay protection,
  // but our schema keys RPC pools by network NAME. Reject integers to avoid
  // ambiguity with EVM chain_id integer convention.
  assert.throws(() => normalizeFindingRecord({
    id: "F-1",
    target_domain: "example.com",
    title: "x",
    severity: "low",
    cwe: null,
    endpoint: "x",
    description: "x",
    proof_of_concept: "y",
    response_evidence: null,
    impact: null,
    validated: true,
    wave: null,
    agent: null,
    surface_id: null,
    surface_type: "smart_contract",
    sc_evidence: {
      chain_family: "aptos",
      chain_id: 1,
      contract_address: "0x" + "ab".repeat(32),
      harness_path: os.homedir(),
      match_test: "test_x",
    },
  }), /chain_id must be one of: mainnet, testnet, devnet/);
});

test("bob_record_finding accepts Substrate sc_evidence with chain_family='substrate' and SS58 address", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAttackSurfaces(domain, [
      { id: "surface-substrate", hosts: [`https://${domain}`], surface_type: "smart_contract", chain_family: "substrate" },
    ]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-substrate" }]);
    // Alice's well-known generic-substrate SS58 address (prefix 42).
    const alice = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY";
    const result = JSON.parse(recordFinding({
      target_domain: domain,
      title: "Reentrancy via cross-contract call in ink! marketplace",
      severity: "high",
      cwe: "CWE-841",
      endpoint: alice + "::buy",
      description: "Cross-contract call to buyer-supplied receiver enables reentrancy.",
      proof_of_concept: "cargo test --features e2e-tests test_reentrancy",
      response_evidence: "Drained 100 DOT after recursive buy()",
      impact: "Drain of marketplace escrow.",
      validated: true,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-substrate",
      sc_evidence: {
        chain_family: "substrate",
        chain_id: "polkadot",
        contract_address: alice,
        harness_path: os.homedir(),
        match_test: "test_reentrancy",
        fork_block: 19_000_000,
        function_signature: "marketplace::buy",
      },
    }));
    assert.equal(result.recorded, true);
    const rows = JSON.parse(readFindings({ target_domain: domain })).findings;
    const subFinding = rows.find((f) => f.id === result.finding_id);
    assert.equal(subFinding.surface_type, "smart_contract");
    assert.equal(subFinding.sc_evidence.chain_family, "substrate");
    assert.equal(subFinding.sc_evidence.chain_id, "polkadot");
    assert.equal(subFinding.sc_evidence.contract_address, alice); // case preserved
    assert.equal(subFinding.sc_evidence.fork_block, 19_000_000);
  });
});

test("bob_record_finding accepts CosmWasm sc_evidence with chain_family='cosmwasm' and bech32 address", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAttackSurfaces(domain, [
      { id: "surface-cosmwasm", hosts: [`https://${domain}`], surface_type: "smart_contract", chain_family: "cosmwasm" },
    ]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-cosmwasm" }]);
    // Generated bech32 with HRP=osmo and 32-byte content; verifies the polymod
    // checksum so this is a valid bech32 string. Real osmosis governance and
    // CW contract addresses share this shape.
    const osmoAddr = "osmo1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7rusq4z5ese";
    const result = JSON.parse(recordFinding({
      target_domain: domain,
      title: "Sub-message reply allows balance overwrite",
      severity: "critical",
      cwe: "CWE-841",
      endpoint: osmoAddr + "/execute",
      description: "Reply handler trusts attacker-supplied result without re-checking caller.",
      proof_of_concept: "cargo test test_reply_overwrite",
      response_evidence: "User balance set to attacker_value",
      impact: "Drain via crafted sub-message reply.",
      validated: true,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-cosmwasm",
      sc_evidence: {
        chain_family: "cosmwasm",
        chain_id: "osmosis",
        contract_address: osmoAddr,
        harness_path: os.homedir(),
        match_test: "test_reply_overwrite",
        fork_block: 14_500_000,
        function_signature: "execute::Withdraw",
      },
    }));
    assert.equal(result.recorded, true);
    const rows = JSON.parse(readFindings({ target_domain: domain })).findings;
    const cwFinding = rows.find((f) => f.id === result.finding_id);
    assert.equal(cwFinding.surface_type, "smart_contract");
    assert.equal(cwFinding.sc_evidence.chain_family, "cosmwasm");
    assert.equal(cwFinding.sc_evidence.chain_id, "osmosis");
    assert.equal(cwFinding.sc_evidence.contract_address, osmoAddr); // already lowercase
    assert.equal(cwFinding.sc_evidence.fork_block, 14_500_000);
  });
});

test("sc_evidence rejects chain_family='substrate' with unknown network", () => {
  const { normalizeFindingRecord } = require("../mcp/lib/finding-contracts.js");
  assert.throws(() => normalizeFindingRecord({
    id: "F-1",
    target_domain: "example.com",
    title: "x",
    severity: "low",
    cwe: null,
    endpoint: "x",
    description: "x",
    proof_of_concept: "y",
    response_evidence: null,
    impact: null,
    validated: true,
    wave: null,
    agent: null,
    surface_id: null,
    surface_type: "smart_contract",
    sc_evidence: {
      chain_family: "substrate",
      chain_id: "ethereum",
      contract_address: "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
      harness_path: os.homedir(),
      match_test: "test_x",
    },
  }), /chain_id must be one of: polkadot, kusama, astar, shiden, rococo, westend, localnet/);
});

test("sc_evidence rejects chain_family='cosmwasm' with unknown network", () => {
  const { normalizeFindingRecord } = require("../mcp/lib/finding-contracts.js");
  assert.throws(() => normalizeFindingRecord({
    id: "F-1",
    target_domain: "example.com",
    title: "x",
    severity: "low",
    cwe: null,
    endpoint: "x",
    description: "x",
    proof_of_concept: "y",
    response_evidence: null,
    impact: null,
    validated: true,
    wave: null,
    agent: null,
    surface_id: null,
    surface_type: "smart_contract",
    sc_evidence: {
      chain_family: "cosmwasm",
      chain_id: "kusama",
      contract_address: "osmo1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7rusq4z5ese",
      harness_path: os.homedir(),
      match_test: "test_x",
    },
  }), /chain_id must be one of: osmosis, juno, neutron, archway, sei, stargaze, terra, kava, localnet/);
});

test("sc_evidence rejects chain_family='substrate' with EVM 0x... address (alphabet violation)", () => {
  const { normalizeFindingRecord } = require("../mcp/lib/finding-contracts.js");
  // SS58 alphabet excludes 0/O/I/l, so an EVM address fails the base58 check.
  assert.throws(() => normalizeFindingRecord({
    id: "F-1",
    target_domain: "example.com",
    title: "x",
    severity: "low",
    cwe: null,
    endpoint: "x",
    description: "x",
    proof_of_concept: "y",
    response_evidence: null,
    impact: null,
    validated: true,
    wave: null,
    agent: null,
    surface_id: null,
    surface_type: "smart_contract",
    sc_evidence: {
      chain_family: "substrate",
      chain_id: "polkadot",
      contract_address: "0x" + "ab".repeat(20),
      harness_path: os.homedir(),
      match_test: "test_x",
    },
  }), /contract_address must be a valid SS58-encoded substrate address/);
});

test("sc_evidence rejects chain_family='substrate' with too-short SS58", () => {
  const { normalizeFindingRecord } = require("../mcp/lib/finding-contracts.js");
  // 30 chars is below the 45-char SS58 length floor.
  assert.throws(() => normalizeFindingRecord({
    id: "F-1",
    target_domain: "example.com",
    title: "x",
    severity: "low",
    cwe: null,
    endpoint: "x",
    description: "x",
    proof_of_concept: "y",
    response_evidence: null,
    impact: null,
    validated: true,
    wave: null,
    agent: null,
    surface_id: null,
    surface_type: "smart_contract",
    sc_evidence: {
      chain_family: "substrate",
      chain_id: "polkadot",
      contract_address: "5Grwvaef5zxb26fz9rcqpdws57",
      harness_path: os.homedir(),
      match_test: "test_x",
    },
  }), /contract_address must be a valid SS58-encoded substrate address/);
});

test("sc_evidence rejects chain_family='cosmwasm' with bad bech32 checksum", () => {
  const { normalizeFindingRecord } = require("../mcp/lib/finding-contracts.js");
  // Last 6 chars of valid bech32 mutated to break the polymod checksum.
  assert.throws(() => normalizeFindingRecord({
    id: "F-1",
    target_domain: "example.com",
    title: "x",
    severity: "low",
    cwe: null,
    endpoint: "x",
    description: "x",
    proof_of_concept: "y",
    response_evidence: null,
    impact: null,
    validated: true,
    wave: null,
    agent: null,
    surface_id: null,
    surface_type: "smart_contract",
    sc_evidence: {
      chain_family: "cosmwasm",
      chain_id: "osmosis",
      contract_address: "osmo1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7rusqaaaaaa",
      harness_path: os.homedir(),
      match_test: "test_x",
    },
  }), /contract_address must be a valid bech32-encoded CosmWasm address/);
});

test("sc_evidence rejects chain_family='cosmwasm' with EVM 0x... address (no bech32 separator)", () => {
  const { normalizeFindingRecord } = require("../mcp/lib/finding-contracts.js");
  assert.throws(() => normalizeFindingRecord({
    id: "F-1",
    target_domain: "example.com",
    title: "x",
    severity: "low",
    cwe: null,
    endpoint: "x",
    description: "x",
    proof_of_concept: "y",
    response_evidence: null,
    impact: null,
    validated: true,
    wave: null,
    agent: null,
    surface_id: null,
    surface_type: "smart_contract",
    sc_evidence: {
      chain_family: "cosmwasm",
      chain_id: "osmosis",
      contract_address: "0x" + "ab".repeat(20),
      harness_path: os.homedir(),
      match_test: "test_x",
    },
  }), /contract_address must be a valid bech32-encoded CosmWasm address/);
});

test("sc_evidence rejects chain_family='cosmwasm' with mixed-case bech32 (spec violation)", () => {
  const { normalizeFindingRecord } = require("../mcp/lib/finding-contracts.js");
  // BIP-0173 explicitly forbids mixed-case in bech32; either fully lowercase
  // or fully uppercase is allowed, but never both. We mirror that rule.
  assert.throws(() => normalizeFindingRecord({
    id: "F-1",
    target_domain: "example.com",
    title: "x",
    severity: "low",
    cwe: null,
    endpoint: "x",
    description: "x",
    proof_of_concept: "y",
    response_evidence: null,
    impact: null,
    validated: true,
    wave: null,
    agent: null,
    surface_id: null,
    surface_type: "smart_contract",
    sc_evidence: {
      chain_family: "cosmwasm",
      chain_id: "osmosis",
      contract_address: "Osmo1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7rusq4z5ese",
      harness_path: os.homedir(),
      match_test: "test_x",
    },
  }), /contract_address must be a valid bech32-encoded CosmWasm address/);
});

test("sc_evidence svm pubkey accepts the 32-char System Program (all-zero pubkey)", () => {
  const { normalizeFindingRecord } = require("../mcp/lib/finding-contracts.js");
  // 11111111111111111111111111111111 — 32 chars, base58-decodes to 32 zero
  // bytes. The System Program is a legitimate Solana pubkey at 32 chars.
  // The new decode-length check must not regress on this fixture.
  const finding = normalizeFindingRecord({
    id: "F-1",
    target_domain: "example.com",
    title: "x",
    severity: "low",
    cwe: null,
    endpoint: "x",
    description: "x",
    proof_of_concept: "y",
    response_evidence: null,
    impact: null,
    validated: true,
    wave: null,
    agent: null,
    surface_id: null,
    surface_type: "smart_contract",
    sc_evidence: {
      chain_family: "svm",
      chain_id: "mainnet-beta",
      contract_address: "11111111111111111111111111111111",
      harness_path: os.homedir(),
      match_test: "test_x",
    },
  });
  assert.equal(finding.sc_evidence.contract_address, "11111111111111111111111111111111");
});

test("anchor runner classifies cargo/solana/yarn missing as anchor_dependency_missing", () => {
  const { classifyAnchorFailure } = require("../mcp/lib/anchor-runner.js");
  const cargoMissing = classifyAnchorFailure(
    { ok: false, exit_code: 127, stderr: "/bin/sh: cargo: command not found", stdout: "" },
    false,
  );
  assert.equal(cargoMissing, "anchor_dependency_missing");

  const solanaMissing = classifyAnchorFailure(
    { ok: false, exit_code: 127, stderr: "anchor: solana command not found in PATH", stdout: "" },
    false,
  );
  assert.equal(solanaMissing, "anchor_dependency_missing");

  const validatorMissing = classifyAnchorFailure(
    { ok: false, exit_code: 127, stderr: "Error: solana-test-validator: No such file or directory", stdout: "" },
    false,
  );
  assert.equal(validatorMissing, "anchor_dependency_missing");

  const yarnMissing = classifyAnchorFailure(
    { ok: false, exit_code: 127, stderr: "/bin/sh: yarn: command not found", stdout: "" },
    false,
  );
  assert.equal(yarnMissing, "anchor_dependency_missing");

  // No deps mentioned, just a generic shell error → unclassified (returns null)
  const generic = classifyAnchorFailure(
    { ok: false, exit_code: 1, stderr: "Error: build failed", stdout: "" },
    false,
  );
  assert.equal(generic, null);

  // ok=true → no classification needed
  const success = classifyAnchorFailure({ ok: true, stderr: "", stdout: "{...}" }, true);
  assert.equal(success, null);
});

test("anchor runner classifies jest/ts-mocha config as anchor_test_runner_unknown", () => {
  const { classifyAnchorFailure } = require("../mcp/lib/anchor-runner.js");
  const jestRunner = classifyAnchorFailure(
    { ok: false, exit_code: 1, stderr: "Running test command: jest --testPathPattern=...", stdout: "" },
    false, // parseResult.ok = false (no mocha JSON)
  );
  assert.equal(jestRunner, "anchor_test_runner_unknown");

  const tsMocha = classifyAnchorFailure(
    { ok: false, exit_code: 2, stderr: "ts-mocha: cannot find ts file", stdout: "" },
    false,
  );
  assert.equal(tsMocha, "anchor_test_runner_unknown");

  const customRunner = classifyAnchorFailure(
    { ok: false, exit_code: 1, stderr: "Cannot find module './reporter/json'", stdout: "" },
    false,
  );
  assert.equal(customRunner, "anchor_test_runner_unknown");

  // dependency-missing wins over runner-unknown when both patterns match
  const both = classifyAnchorFailure(
    { ok: false, exit_code: 127, stderr: "yarn: command not found\nts-mocha: missing", stdout: "" },
    false,
  );
  assert.equal(both, "anchor_dependency_missing");

  // If parseResult.ok is true (mocha JSON present), runner-unknown does not fire.
  const parsedFine = classifyAnchorFailure(
    { ok: false, exit_code: 1, stderr: "ts-mocha hint", stdout: "{stats:...}" },
    true,
  );
  assert.equal(parsedFine, null);
});

test("anchor runner summarizes mocha JSON Pass/Fail and caps tests[] at 100", () => {
  const { summarizeAnchorMochaJson } = require("../mcp/lib/anchor-runner.js");
  // Mocha JSON shape: stats + tests array. err empty = passed; err present = failed.
  const result = summarizeAnchorMochaJson({
    stats: { tests: 3, passes: 1, failures: 1, pending: 1 },
    tests: [
      { title: "drains the vault", fullTitle: "Vault drains the vault", duration: 412, err: {} },
      { title: "rejects unauthorized signer", fullTitle: "Vault rejects unauthorized signer", duration: 89, err: { message: "AssertionError: expected revert" } },
      { title: "skipped when feature flag is off", fullTitle: "Vault skipped when feature flag is off", duration: 0, err: {}, pending: true },
    ],
  });
  assert.equal(result.total, 3);
  assert.equal(result.passed, 1);
  assert.equal(result.failed, 1);
  assert.equal(result.tests[0].status, "Pass");
  assert.equal(result.tests[0].status_raw, "success");
  assert.equal(result.tests[1].status, "Fail");
  assert.equal(result.tests[1].status_raw, "failure");
  assert.equal(result.tests[1].reason, "AssertionError: expected revert");
  assert.equal(result.tests[2].status, "Skipped");
  assert.equal(result.truncated, false);

  // 150 passing tests → capped at 100, truncated flag.
  const big = { stats: { tests: 150 }, tests: [] };
  for (let i = 0; i < 150; i += 1) {
    big.tests.push({ title: `t_${i}`, fullTitle: `Suite t_${i}`, duration: 1, err: {} });
  }
  const capped = summarizeAnchorMochaJson(big);
  assert.equal(capped.total, 150);
  assert.equal(capped.passed, 150);
  assert.equal(capped.tests.length, 100, "tests[] must be capped at 100");
  assert.equal(capped.truncated, true);
});

test("anchor runner rejects extra_args not in the allowlist", async () => {
  const { runAnchorTest } = require("../mcp/lib/anchor-runner.js");
  // Use os.homedir() as the workdir (real, under-home, exists). The args
  // validator runs before subprocess spawn, so this assertion fires without
  // requiring anchor in PATH.
  await assert.rejects(async () => runAnchorTest({
    workdir: os.homedir(),
    matchTest: "test_x",
    cluster: "mainnet-beta",
    extraArgs: ["--provider.cluster", "https://malicious.example/rpc"],
    timeoutMs: 5000,
  }), /not in the anchor allowlist/);
});

test("anchor runner rejects symlink-escaping harness paths", async () => {
  const { runAnchorTest } = require("../mcp/lib/anchor-runner.js");
  const home = os.homedir();
  const tmpRoot = path.join(os.tmpdir(), "bob-anchor-symlink-" + Math.random().toString(36).slice(2));
  fs.mkdirSync(tmpRoot, { recursive: true });
  const linkPath = path.join(home, "anchor-escape-link");
  try { fs.unlinkSync(linkPath); } catch {}
  fs.symlinkSync(tmpRoot, linkPath, "dir");
  try {
    await assert.rejects(async () => runAnchorTest({
      workdir: linkPath,
      matchTest: "test_x",
      cluster: "mainnet-beta",
      timeoutMs: 5000,
    }), /must live under the user home directory/);
  } finally {
    try { fs.unlinkSync(linkPath); } catch {}
    try { fs.rmdirSync(tmpRoot); } catch {}
  }
});

test("svm rpc pool resolves cluster ladders and rejects private hosts", () => {
  const { resolveSvmRpcEndpoints, isPublicHttpsUrl } = require("../mcp/lib/svm-rpc-pool.js");
  const mainnet = resolveSvmRpcEndpoints("mainnet-beta");
  assert.ok(Array.isArray(mainnet) && mainnet.length >= 2, "mainnet-beta has multiple endpoints");
  assert.ok(mainnet.every((url) => url.startsWith("https://")), "all endpoints are https");
  const devnet = resolveSvmRpcEndpoints("devnet");
  assert.ok(devnet.length >= 1, "devnet has at least one endpoint");
  assert.equal(isPublicHttpsUrl("https://api.mainnet-beta.solana.com"), true);
  assert.equal(isPublicHttpsUrl("http://localhost:8899"), false);
  assert.equal(isPublicHttpsUrl("https://192.168.1.1:8899"), false);
});

test("svm rpc pool env override is read with the dashed-cluster key shape", () => {
  const { resolveSvmRpcEndpoints, envKeyForCluster } = require("../mcp/lib/svm-rpc-pool.js");
  // mainnet-beta should map to BOB_SVM_RPCS_MAINNET_BETA
  assert.equal(envKeyForCluster("mainnet-beta"), "BOB_SVM_RPCS_MAINNET_BETA");
  const previous = process.env.BOB_SVM_RPCS_MAINNET_BETA;
  process.env.BOB_SVM_RPCS_MAINNET_BETA = "https://override.example.com/rpc";
  try {
    const result = resolveSvmRpcEndpoints("mainnet-beta");
    assert.equal(result[0], "https://override.example.com/rpc", "env override is tried first");
  } finally {
    if (previous === undefined) delete process.env.BOB_SVM_RPCS_MAINNET_BETA;
    else process.env.BOB_SVM_RPCS_MAINNET_BETA = previous;
  }
});

test("svm-fetch-program parses BPFLoaderUpgradeable Program account discriminator", () => {
  const svmFetchProgram = require("../mcp/lib/tools/svm-fetch-program.js");
  const { parseProgramAccount, parseProgramDataAccount, base58Encode } = svmFetchProgram._internals;
  // System Program zeroed pubkey (32 bytes).
  const sysProgramBytes = Buffer.alloc(32, 0);
  const programDataPubkeyB58 = base58Encode(sysProgramBytes);
  // Program account: discriminator=2 little-endian + 32 bytes programdata addr.
  const programData = Buffer.alloc(36);
  programData.writeUInt32LE(2, 0);
  sysProgramBytes.copy(programData, 4);
  const parsed = parseProgramAccount(programData);
  assert.equal(parsed.kind, "program");
  assert.equal(parsed.programdata_address, programDataPubkeyB58);

  // ProgramData account: discriminator=3 + slot u64 + option(1) + Pubkey(32).
  // Use upgrade authority = 32 bytes of 0x11.
  const authBytes = Buffer.alloc(32, 0x11);
  const pdData = Buffer.alloc(45);
  pdData.writeUInt32LE(3, 0);
  pdData.writeBigUInt64LE(123456n, 4);
  pdData.writeUInt8(1, 12); // option Some
  authBytes.copy(pdData, 13);
  const pdParsed = parseProgramDataAccount(pdData);
  assert.equal(pdParsed.kind, "programdata");
  assert.equal(pdParsed.deployed_slot, 123456);
  assert.equal(pdParsed.upgrade_authority, base58Encode(authBytes));

  // Frozen ProgramData (option=None).
  const frozenData = Buffer.alloc(13);
  frozenData.writeUInt32LE(3, 0);
  frozenData.writeBigUInt64LE(99n, 4);
  frozenData.writeUInt8(0, 12); // option None
  const frozenParsed = parseProgramDataAccount(frozenData);
  assert.equal(frozenParsed.upgrade_authority, null);
  assert.equal(frozenParsed.deployed_slot, 99);
});

test("svm tools register with verifier and evidence role bundles (so balanced/brutalist/final + evidence-agent can re-run SVM PoCs)", () => {
  const tools = ["bob_svm_fetch_account", "bob_svm_fetch_program", "bob_anchor_run"];
  for (const name of tools) {
    const meta = TOOL_MANIFEST[name];
    assert.ok(meta, `${name} is in TOOL_MANIFEST`);
    assert.deepEqual(meta.role_bundles, ["evaluator-svm", "verifier", "evidence"], `${name} exposes role_bundles=[evaluator-svm, verifier, evidence]`);
    assert.equal(meta.network_access, true, `${name} declares network_access`);
  }
});

// ----------------------------------------------------------------------
// Move (Aptos + Sui) primitives
// ----------------------------------------------------------------------

test("aptos rpc pool resolves network ladders and rejects private hosts", () => {
  const { resolveAptosRpcEndpoints, isPublicHttpsUrl } = require("../mcp/lib/aptos-rpc-pool.js");
  const mainnet = resolveAptosRpcEndpoints("mainnet");
  assert.ok(Array.isArray(mainnet) && mainnet.length >= 1, "mainnet has at least one endpoint");
  assert.ok(mainnet.every((url) => url.startsWith("https://")), "all endpoints are https");
  // Aptos URLs include /v1 in the suffix because the REST API is path-anchored.
  assert.ok(mainnet.every((url) => url.endsWith("/v1")), "Aptos endpoints carry /v1 suffix");
  const testnet = resolveAptosRpcEndpoints("testnet");
  assert.ok(testnet.length >= 1, "testnet has at least one endpoint");
  assert.equal(isPublicHttpsUrl("https://api.mainnet.aptoslabs.com/v1"), true);
  assert.equal(isPublicHttpsUrl("http://localhost:8080"), false);
  assert.equal(isPublicHttpsUrl("https://192.168.1.1/v1"), false);
});

test("aptos rpc pool env override is read with BOB_APTOS_RPCS_<NETWORK>", () => {
  const { resolveAptosRpcEndpoints, envKeyForNetwork } = require("../mcp/lib/aptos-rpc-pool.js");
  assert.equal(envKeyForNetwork("mainnet"), "BOB_APTOS_RPCS_MAINNET");
  const previous = process.env.BOB_APTOS_RPCS_MAINNET;
  process.env.BOB_APTOS_RPCS_MAINNET = "https://override.example.com/v1";
  try {
    const result = resolveAptosRpcEndpoints("mainnet");
    assert.equal(result[0], "https://override.example.com/v1", "env override is tried first");
  } finally {
    if (previous === undefined) delete process.env.BOB_APTOS_RPCS_MAINNET;
    else process.env.BOB_APTOS_RPCS_MAINNET = previous;
  }
});

test("sui rpc pool resolves network ladders and rejects private hosts", () => {
  const { resolveSuiRpcEndpoints, isPublicHttpsUrl } = require("../mcp/lib/sui-rpc-pool.js");
  const mainnet = resolveSuiRpcEndpoints("mainnet");
  assert.ok(Array.isArray(mainnet) && mainnet.length >= 1, "mainnet has at least one endpoint");
  assert.ok(mainnet.every((url) => url.startsWith("https://")), "all endpoints are https");
  const testnet = resolveSuiRpcEndpoints("testnet");
  assert.ok(testnet.length >= 1, "testnet has at least one endpoint");
  // localnet has no public RPC default; env overrides stay ignored until a
  // recorded per-family opt-in policy exists.
  const localnet = resolveSuiRpcEndpoints("localnet");
  assert.deepEqual(localnet, []);
  assert.equal(isPublicHttpsUrl("https://fullnode.mainnet.sui.io:443"), true);
  assert.equal(isPublicHttpsUrl("http://localhost:9000"), false);
});

test("sui rpc pool env override is read with BOB_SUI_RPCS_<NETWORK> while localnet stays unsupported by default", () => {
  const { resolveSuiRpcEndpoints, envKeyForNetwork } = require("../mcp/lib/sui-rpc-pool.js");
  assert.equal(envKeyForNetwork("mainnet"), "BOB_SUI_RPCS_MAINNET");
  withEnv({
    BOB_SUI_RPCS_MAINNET: "https://override.example.com/rpc",
    BOB_SUI_RPCS_LOCALNET: "https://localnet-override.example.com:9000",
  }, () => {
    const mainnet = resolveSuiRpcEndpoints("mainnet");
    assert.equal(mainnet[0], "https://override.example.com/rpc", "public HTTPS env override is tried first");
    assert.deepEqual(resolveSuiRpcEndpoints("localnet"), [], "localnet RPC override is ignored until an explicit opt-in policy exists");
  });
});

test("smart-contract RPC pools enforce HTTPS/public-host policy on env overrides", () => {
  const { resolveEvmRpcEndpoints } = require("../mcp/lib/evm-rpc-pool.js");
  const { resolveSvmRpcEndpoints } = require("../mcp/lib/svm-rpc-pool.js");
  const { resolveAptosRpcEndpoints } = require("../mcp/lib/aptos-rpc-pool.js");
  const { resolveSuiRpcEndpoints } = require("../mcp/lib/sui-rpc-pool.js");
  const { resolveSubstrateRpcEndpoints } = require("../mcp/lib/substrate-rpc-pool.js");
  const { resolveCosmwasmRpcEndpoints } = require("../mcp/lib/cosmwasm-rpc-pool.js");

  withEnv({
    BOB_EVM_RPCS_1: "http://public.example/rpc,https://127.0.0.1/rpc,https://public-rpc.example/rpc",
    BOB_SVM_RPCS_MAINNET_BETA: "http://public.example/rpc,https://10.0.0.5/rpc,https://svm-rpc.example/rpc",
    BOB_SVM_RPCS_LOCALNET: "https://svm-localnet.example/rpc",
    BOB_APTOS_RPCS_MAINNET: "http://public.example/v1,https://192.168.1.2/v1,https://aptos-rpc.example/v1",
    BOB_APTOS_RPCS_LOCALNET: "https://aptos-localnet.example/v1",
    BOB_SUI_RPCS_LOCALNET: "https://sui-localnet.example/rpc",
    BOB_SUBSTRATE_RPCS_LOCALNET: "https://substrate-localnet.example/rpc",
    BOB_COSMWASM_RPCS_LOCALNET: "https://cosmwasm-localnet.example",
  }, () => {
    assert.equal(resolveEvmRpcEndpoints(1)[0], "https://public-rpc.example/rpc");
    assert.equal(resolveSvmRpcEndpoints("mainnet-beta")[0], "https://svm-rpc.example/rpc");
    assert.deepEqual(resolveSvmRpcEndpoints("localnet"), []);
    assert.equal(resolveAptosRpcEndpoints("mainnet")[0], "https://aptos-rpc.example/v1");
    assert.deepEqual(resolveAptosRpcEndpoints("localnet"), []);
    assert.deepEqual(resolveSuiRpcEndpoints("localnet"), []);
    assert.deepEqual(resolveSubstrateRpcEndpoints("localnet"), []);
    assert.deepEqual(resolveCosmwasmRpcEndpoints("localnet"), []);
  });
});

test("smart-contract egress policy blocks DNS-private RPC endpoints before fetch and redacts secrets", async () => {
  const { isPublicHttpsUrl } = require("../mcp/lib/sc-egress-policy.js");
  const { isBlockedInternalHost } = require("../mcp/lib/url-surface.js");
  assert.equal(isPublicHttpsUrl("https://198.18.0.1/rpc"), false);
  assert.equal(isPublicHttpsUrl("https://[2001:db8::1]/rpc"), false);
  assert.equal(isPublicHttpsUrl("https://[64:ff9b::0a00:1]/rpc"), false);
  assert.equal(isPublicHttpsUrl("https://[64:ff9b:1::1]/rpc"), false);
  assert.equal(isPublicHttpsUrl("https://[2002:0a00:0001::]/rpc"), false);
  assert.equal(isPublicHttpsUrl("https://[3fff::1]/rpc"), false);
  assert.equal(isPublicHttpsUrl("https://[5f00::1]/rpc"), false);
  assert.equal(isBlockedInternalHost("fe80::1%eth0"), true);

  let called = false;
  await withMockSmartContractHttpRequest(async () => {
    called = true;
    return { ok: true, status: 200, text: JSON.stringify({ jsonrpc: "2.0", id: 1, result: "0x1" }) };
  }, async () => {
    const secret = "rpc-secret-token";
    const result = await withMockSmartContractRpcLookup({
      "rpc.example.test": [{ address: "198.18.0.9", family: 4 }],
    }, () => executeTool("bob_evm_call", {
      chain_id: 1,
      to: "0x" + "11".repeat(20),
      data: "0x",
      endpoints: [`https://rpc.example.test/rpc?api_key=${secret}`],
    }));
    assert.equal(result.ok, false);
    assert.equal(called, false, "HTTP request must not run after DNS-private policy rejection");
    assert.match(result.error.message, /no public HTTPS RPC endpoints/);
    assert.equal(result.error.details.rpc_policy_rejections[0].reason, "blocked_internal_dns_address");
    assert.match(result.error.details.rpc_policy_rejections[0].endpoint, /api_key=REDACTED/);
    assert.doesNotMatch(JSON.stringify(result), new RegExp(secret));
  });
});

test("smart-contract HTTP client pins the request lookup to the preflight DNS answer", async () => {
  const { requestPublicHttpsText } = require("../mcp/lib/sc-http-client.js");
  let observedAddress = null;
  const response = await withMockSmartContractRpcLookup({
    "rpc.example.test": [{ address: "93.184.216.34", family: 4 }],
  }, () => withMockSmartContractHttpRequest(async (_url, request) => {
    assert.equal(request.hostname, "rpc.example.test");
    assert.deepEqual(request.pinned_addresses, [{ address: "93.184.216.34", family: 4 }]);
    request.pinned_lookup("rpc.example.test", {}, (error, address, family) => {
      assert.ifError(error);
      observedAddress = address;
      assert.equal(address, "93.184.216.34");
      assert.equal(family, 4);
    });
    request.pinned_lookup("evil.example.test", {}, (error) => {
      assert.match(error.message, /unexpected host/);
    });
    return { ok: true, status: 200, text: "ok" };
  }, () => requestPublicHttpsText("https://rpc.example.test/rpc", { maxBytes: 8 })));
  assert.equal(response.ok, true);
  assert.equal(response.text, "ok");
  assert.equal(observedAddress, "93.184.216.34");
});

test("smart-contract HTTP client pins IPv6 answers", async () => {
  const { requestPublicHttpsText } = require("../mcp/lib/sc-http-client.js");
  let observedAddress = null;
  const response = await withMockSmartContractRpcLookup({
    "rpc-v6.example.test": [{ address: "2606:4700:4700::1111", family: 6 }],
  }, () => withMockSmartContractHttpRequest(async (_url, request) => {
    assert.equal(request.hostname, "rpc-v6.example.test");
    request.pinned_lookup("rpc-v6.example.test", { family: 6 }, (error, address, family) => {
      assert.ifError(error);
      observedAddress = address;
      assert.equal(address, "2606:4700:4700::1111");
      assert.equal(family, 6);
    });
    return { ok: true, status: 200, text: "ok-v6" };
  }, () => requestPublicHttpsText("https://rpc-v6.example.test/rpc")));
  assert.equal(response.ok, true);
  assert.equal(response.text, "ok-v6");
  assert.equal(observedAddress, "2606:4700:4700::1111");
});

test("smart-contract HTTP client fails closed after its byte cap", async () => {
  const { requestPublicHttpsText } = require("../mcp/lib/sc-http-client.js");
  let requestDestroyed = false;
  let responseDestroyed = false;
  const requestImpl = (requestOptions, callback) => {
    const req = new EventEmitter();
    req.write = () => {};
    req.setTimeout = () => req;
    req.destroy = () => {
      requestDestroyed = true;
      process.nextTick(() => req.emit("error", Object.assign(new Error("socket closed"), { code: "ECONNRESET" })));
    };
    req.end = () => {
      process.nextTick(() => {
        requestOptions.lookup("rpc.example.test", {}, (error, address, family) => {
          assert.ifError(error);
          assert.equal(address, "93.184.216.34");
          assert.equal(family, 4);
        });
        const resp = new EventEmitter();
        resp.statusCode = 200;
        resp.headers = { "content-type": "text/plain" };
        resp.destroy = () => {
          responseDestroyed = true;
        };
        callback(resp);
        resp.emit("data", Buffer.from("abcdef"));
        resp.emit("data", Buffer.from("ignored"));
        resp.emit("end");
      });
    };
    return req;
  };

  await assert.rejects(() => withMockSmartContractRpcLookup({
    "rpc.example.test": [{ address: "93.184.216.34", family: 4 }],
  }, () => requestPublicHttpsText("https://rpc.example.test/rpc", {
    maxBytes: 4,
    requestImpl,
  })), /SC HTTP response exceeded 4 bytes/);
  assert.equal(requestDestroyed, true);
  assert.equal(responseDestroyed, true);
});

test("smart-contract HTTP client does not follow redirects", async () => {
  const { requestPublicHttpsText } = require("../mcp/lib/sc-http-client.js");
  let calls = 0;
  const response = await withMockSmartContractRpcLookup({
    "rpc.example.test": [{ address: "93.184.216.34", family: 4 }],
  }, () => withMockSafeFetch((url, request) => {
    calls += 1;
    assert.equal(request.agent, false);
    assert.equal(url, "https://rpc.example.test:443/rpc");
    return {
      status: 302,
      headers: { location: "https://attacker.example.test/rpc" },
      body: "redirect",
    };
  }, () => requestPublicHttpsText("https://rpc.example.test/rpc"), {
    dnsRecords: {
      "rpc.example.test": [{ address: "93.184.216.34", family: 4 }],
      "attacker.example.test": [{ address: "93.184.216.35", family: 4 }],
    },
  }));
  assert.equal(response.ok, false);
  assert.equal(response.status, 302);
  assert.equal(response.text, "redirect");
  assert.equal(calls, 1);
});

test("smart-contract egress policy blocks DNS rebinding before pinned HTTP request", async () => {
  const { requestPublicHttpsText } = require("../mcp/lib/sc-http-client.js");
  let called = false;
  await assert.rejects(
    () => withMockSmartContractRpcLookup({
      "rpc-rebind.example.test": [{ address: "10.0.0.5", family: 4 }],
    }, () => withMockSmartContractHttpRequest(async () => {
      called = true;
      return { ok: true, status: 200, text: "should not happen" };
    }, () => requestPublicHttpsText("https://rpc-rebind.example.test/rpc"))),
    /Blocked internal\/private DNS address/,
  );
  assert.equal(called, false, "pinned HTTP request must not run after private DNS preflight");

  let nat64Called = false;
  await assert.rejects(
    () => withMockSmartContractRpcLookup({
      "rpc-nat64.example.test": [{ address: "64:ff9b::0a00:0001", family: 6 }],
    }, () => withMockSmartContractHttpRequest(async () => {
      nat64Called = true;
      return { ok: true, status: 200, text: "should not happen" };
    }, () => requestPublicHttpsText("https://rpc-nat64.example.test/rpc"))),
    /Blocked internal\/private DNS address/,
  );
  assert.equal(nat64Called, false, "NAT64 private IPv4 DNS answers must not reach HTTP request");
});

test("smart-contract egress policy bounds DNS lookup time before fetch", async () => {
  const { filterResolvedPublicRpcEndpoints } = require("../mcp/lib/sc-egress-policy.js");
  const started = Date.now();
  const result = await filterResolvedPublicRpcEndpoints(["https://slow-rpc.example.test/rpc"], {
    lookup: () => {},
    dnsTimeoutMs: 5,
  });
  assert.deepEqual(result.endpoints, []);
  assert.equal(result.rejected.length, 1);
  assert.equal(result.rejected[0].reason, "dns_lookup_failed");
  assert.match(result.rejected[0].message, /DNS lookup timed out/);
  assert.ok(Date.now() - started < 1000, "DNS timeout should be bounded");
});

test("smart-contract egress policy redacts malformed endpoint secrets and strips proxy env for runners", () => {
  const {
    directSmartContractSubprocessEnv,
    redactRpcEndpoint,
  } = require("../mcp/lib/sc-egress-policy.js");
  const secret = "rpc-secret-token";
  const redacted = redactRpcEndpoint(`not-a-url api_key=${secret}#fragment`);
  assert.doesNotMatch(redacted, new RegExp(secret));
  assert.doesNotMatch(redacted, /fragment/);

  const previous = {
    HTTPS_PROXY: process.env.HTTPS_PROXY,
    http_proxy: process.env.http_proxy,
    ANCHOR_PROVIDER_URL: process.env.ANCHOR_PROVIDER_URL,
    SOLANA_URL: process.env.SOLANA_URL,
    APTOS_NODE_URL: process.env.APTOS_NODE_URL,
    SUI_FULLNODE_URL: process.env.SUI_FULLNODE_URL,
    COSMOS_REST_URL: process.env.COSMOS_REST_URL,
    BOB_ETHERSCAN_API_KEY: process.env.BOB_ETHERSCAN_API_KEY,
    NPM_TOKEN: process.env.NPM_TOKEN,
  };
  process.env.HTTPS_PROXY = "http://proxy.example:8080";
  process.env.http_proxy = "http://proxy.example:8081";
  process.env.ANCHOR_PROVIDER_URL = "http://127.0.0.1:8899";
  process.env.SOLANA_URL = "http://127.0.0.1:8899";
  process.env.APTOS_NODE_URL = "http://127.0.0.1:8080";
  process.env.SUI_FULLNODE_URL = "http://127.0.0.1:9000";
  process.env.COSMOS_REST_URL = "http://127.0.0.1:1317";
  process.env.BOB_ETHERSCAN_API_KEY = "etherscan-secret";
  process.env.NPM_TOKEN = "npm-secret";
  try {
    const env = directSmartContractSubprocessEnv({
      HTTPS_PROXY: "http://override.example:8080",
      API_KEY: "extra-secret",
      BOB_SVM_FORK_URL: "https://rpc.example/rpc?token=fork-secret",
      BOB_APTOS_FORK_URL: "https://aptos.example/v1?api_key=fork-secret",
      BOB_EVM_RPCS_1: "https://alchemy.example/v2/path-secret",
      MAINNET_RPC_URL: "https://rpc.example/private",
      SUI_FULLNODE_URL: "https://sui.example/private",
    });
    assert.equal(env.HTTPS_PROXY, undefined);
    assert.equal(env.http_proxy, undefined);
    assert.equal(env.BOB_ETHERSCAN_API_KEY, undefined);
    assert.equal(env.NPM_TOKEN, undefined);
    assert.equal(env.API_KEY, undefined);
    assert.equal(env.BOB_SVM_FORK_URL, "https://rpc.example/rpc?token=fork-secret");
    assert.equal(env.BOB_APTOS_FORK_URL, "https://aptos.example/v1?api_key=fork-secret");
    assert.equal(env.BOB_EVM_RPCS_1, undefined);
    assert.equal(env.MAINNET_RPC_URL, undefined);
    assert.equal(env.ANCHOR_PROVIDER_URL, undefined);
    assert.equal(env.SOLANA_URL, undefined);
    assert.equal(env.APTOS_NODE_URL, undefined);
    assert.equal(env.SUI_FULLNODE_URL, undefined);
    assert.equal(env.COSMOS_REST_URL, undefined);
    if (process.env.PATH) assert.equal(env.PATH, process.env.PATH);
  } finally {
    if (previous.HTTPS_PROXY === undefined) delete process.env.HTTPS_PROXY;
    else process.env.HTTPS_PROXY = previous.HTTPS_PROXY;
    if (previous.http_proxy === undefined) delete process.env.http_proxy;
    else process.env.http_proxy = previous.http_proxy;
    if (previous.ANCHOR_PROVIDER_URL === undefined) delete process.env.ANCHOR_PROVIDER_URL;
    else process.env.ANCHOR_PROVIDER_URL = previous.ANCHOR_PROVIDER_URL;
    if (previous.SOLANA_URL === undefined) delete process.env.SOLANA_URL;
    else process.env.SOLANA_URL = previous.SOLANA_URL;
    if (previous.APTOS_NODE_URL === undefined) delete process.env.APTOS_NODE_URL;
    else process.env.APTOS_NODE_URL = previous.APTOS_NODE_URL;
    if (previous.SUI_FULLNODE_URL === undefined) delete process.env.SUI_FULLNODE_URL;
    else process.env.SUI_FULLNODE_URL = previous.SUI_FULLNODE_URL;
    if (previous.COSMOS_REST_URL === undefined) delete process.env.COSMOS_REST_URL;
    else process.env.COSMOS_REST_URL = previous.COSMOS_REST_URL;
    if (previous.BOB_ETHERSCAN_API_KEY === undefined) delete process.env.BOB_ETHERSCAN_API_KEY;
    else process.env.BOB_ETHERSCAN_API_KEY = previous.BOB_ETHERSCAN_API_KEY;
    if (previous.NPM_TOKEN === undefined) delete process.env.NPM_TOKEN;
    else process.env.NPM_TOKEN = previous.NPM_TOKEN;
  }
});

test("smart-contract source fetch errors redact Etherscan API keys from response bodies", async () => {
  const { fetchVerifiedSource } = require("../mcp/lib/evm-source.js");
  const secret = "etherscan-body-secret";
  await withMockSmartContractHttpRequest(async (url) => {
    const urlText = String(url);
    if (urlText.includes("sourcify.dev")) {
      return { ok: false, status: 404, text: "not found" };
    }
    return {
      ok: false,
      status: 403,
      text: `Invalid API Key ${secret}`,
    };
  }, async () => {
    const result = await withEnv({ BOB_ETHERSCAN_API_KEY: secret }, () => withMockSmartContractRpcLookup({
      "sourcify.dev": [{ address: "93.184.216.34", family: 4 }],
      "api.etherscan.io": [{ address: "93.184.216.35", family: 4 }],
    }, () => fetchVerifiedSource({
      domain: `etherscan-redaction-${crypto.randomBytes(4).toString("hex")}.example`,
      chainId: 1,
      address: "0x" + "12".repeat(20),
      force: true,
    })));
    assert.equal(result.ok, false);
    assert.doesNotMatch(JSON.stringify(result), new RegExp(secret));
    assert.match(JSON.stringify(result), /Invalid API Key REDACTED/);
  });
});

test("every smart-contract client and fork runner uses the shared DNS-aware egress policy", () => {
  const policyFiles = [
    "mcp/lib/evm-client.js",
    "mcp/lib/svm-client.js",
    "mcp/lib/aptos-client.js",
    "mcp/lib/sui-client.js",
    "mcp/lib/substrate-client.js",
    "mcp/lib/cosmwasm-client.js",
    "mcp/lib/foundry-runner.js",
    "mcp/lib/anchor-runner.js",
    "mcp/lib/aptos-runner.js",
    "mcp/lib/sui-runner.js",
    "mcp/lib/substrate-runner.js",
    "mcp/lib/cosmwasm-runner.js",
  ];
  for (const file of policyFiles) {
    const source = fs.readFileSync(path.join(ROOT, file), "utf8");
    assert.match(source, /filterResolvedPublicRpcEndpoints/, `${file} must apply DNS-aware SC RPC policy`);
    assert.match(source, /redactRpcEndpoint/, `${file} must redact RPC endpoints in returned evidence`);
    assert.doesNotMatch(source, /filter\(isPublicHttpsUrl\)/, `${file} must not silently drop back to sync-only endpoint filtering`);
  }
  const nodeHttpFiles = [
    "mcp/lib/evm-client.js",
    "mcp/lib/svm-client.js",
    "mcp/lib/aptos-client.js",
    "mcp/lib/sui-client.js",
    "mcp/lib/substrate-client.js",
    "mcp/lib/cosmwasm-client.js",
    "mcp/lib/evm-source.js",
  ];
  for (const file of nodeHttpFiles) {
    const source = fs.readFileSync(path.join(ROOT, file), "utf8");
    assert.match(source, /requestPublicHttpsText/, `${file} must use the shared pinned SC HTTPS client`);
    assert.doesNotMatch(source, /\bfetch\s*\(/, `${file} must not use ambient fetch for SC HTTP`);
  }
  const pinnedHttpSource = fs.readFileSync(path.join(ROOT, "mcp/lib/sc-http-client.js"), "utf8");
  assert.match(pinnedHttpSource, /https\.request/, "SC HTTP client must own the direct HTTPS socket");
  assert.match(pinnedHttpSource, /lookup:\s*pinnedLookup/, "SC HTTP client must pass the pinned lookup into the HTTPS request");
  assert.match(pinnedHttpSource, /agent:\s*false/, "SC HTTP client must not reuse https.globalAgent sockets");
  const runnerFiles = [
    "mcp/lib/foundry-runner.js",
    "mcp/lib/halmos-runner.js",
    "mcp/lib/anchor-runner.js",
    "mcp/lib/aptos-runner.js",
    "mcp/lib/sui-runner.js",
    "mcp/lib/substrate-runner.js",
    "mcp/lib/cosmwasm-runner.js",
  ];
  for (const file of runnerFiles) {
    const source = fs.readFileSync(path.join(ROOT, file), "utf8");
    assert.match(source, /directSmartContractSubprocessEnv/, `${file} must strip proxy env from direct-only SC subprocesses`);
    assert.match(source, /redactRpcEndpointText/, `${file} must redact raw subprocess excerpts`);
    assert.doesNotMatch(source, /env:\s*\{\s*\.\.\.process\.env/, `${file} must not inherit proxy env wholesale`);
  }
  for (const file of ["mcp/lib/aptos-client.js", "mcp/lib/cosmwasm-client.js"]) {
    const source = fs.readFileSync(path.join(ROOT, file), "utf8");
    assert.match(source, /requestPublicHttpsText\(url/, `${file} must re-check and pin the constructed REST URL before request`);
  }
});

test("smart-contract runner parsers redact endpoint secrets from structured failures", () => {
  const { summarizeForgeJson } = require("../mcp/lib/foundry-runner.js");
  const { summarizeHalmosOutput } = require("../mcp/lib/halmos-runner.js");
  const secret = "parser-secret-token";
  const endpoint = `https://rpc.example/rpc?api_key=${secret}`;

  const forge = summarizeForgeJson({
    Suite: {
      test_results: {
        testLeak: {
          status: "Failure",
          reason: `reverted while reading ${endpoint}`,
          counterexample: { endpoint },
        },
      },
    },
  });
  assert.equal(forge.tests[0].status, "Fail");
  assert.doesNotMatch(JSON.stringify(forge), new RegExp(secret));
  assert.match(JSON.stringify(forge), /api_key=REDACTED/);

  const halmos = summarizeHalmosOutput({
    results: [{
      test: "testLeak",
      status: "Fail",
      counterexample: { endpoint },
    }],
  });
  assert.equal(halmos.tests[0].status, "Fail");
  assert.doesNotMatch(JSON.stringify(halmos), new RegExp(secret));
  assert.match(JSON.stringify(halmos), /api_key=REDACTED/);
});

test("parseMoveTestStdout parses Move unit test output line-by-line", () => {
  const { parseMoveTestStdout } = require("../mcp/lib/move-test-output.js");
  const stdout = [
    "Running Move unit tests",
    "[ PASS    ] 0x42::vault::test_deposit_ok",
    "[ FAIL    ] 0x42::vault::test_withdraw_unauthorized",
    "        ┌── test_withdraw_unauthorized ──────",
    "        │ error[E11001]: aborted with code 100",
    "        └────────────────────────────────────",
    "[ TIMEOUT ] 0x42::vault::test_loop",
    "Test result: FAILED. Total tests: 3; passed: 1; failed: 2",
  ].join("\n");
  const r = parseMoveTestStdout(stdout);
  assert.equal(r.ok, true);
  assert.equal(r.total, 3);
  assert.equal(r.passed, 1);
  assert.equal(r.failed, 2);
  assert.equal(r.timed_out, 1);
  assert.equal(r.tests[0].test_id, "0x42::vault::test_deposit_ok");
  assert.equal(r.tests[0].status, "Pass");
  assert.equal(r.tests[1].status, "Fail");
  assert.equal(r.tests[1].test_id, "0x42::vault::test_withdraw_unauthorized");
  // Diagnostic line follows [ FAIL ] — captured as reason.
  assert.match(r.tests[1].reason || "", /aborted with code 100|error\[E11001\]/);
  // TIMEOUT normalizes to status=Fail (so verifier sees the assertion held).
  assert.equal(r.tests[2].status, "Fail");
  assert.equal(r.tests[2].status_raw, "TIMEOUT");
});

test("parseMoveTestStdout captures inline failure reason from Sui-style '; ABORTED at code N' suffix", () => {
  const { parseMoveTestStdout } = require("../mcp/lib/move-test-output.js");
  // Sui adds the abort code/module on the same line as [ FAIL ].
  const stdout = [
    "Running Move unit tests",
    "[ PASS    ] 0x0::game::test_play",
    "[ FAIL    ] 0x0::game::test_replay; ABORTED at code 100 in module game",
    "Test result: FAILED. Total tests: 2; passed: 1; failed: 1",
  ].join("\n");
  const r = parseMoveTestStdout(stdout);
  assert.equal(r.ok, true);
  assert.equal(r.tests[1].status, "Fail");
  assert.match(r.tests[1].reason || "", /ABORTED at code 100/);
});

test("parseMoveTestStdout redacts endpoint secrets in failure reasons", () => {
  const { parseMoveTestStdout } = require("../mcp/lib/move-test-output.js");
  const secret = "move-parser-secret";
  const stdout = [
    "Running Move unit tests",
    `[ FAIL    ] 0x0::game::test_replay; failed against https://rpc.example/rpc?api_key=${secret}`,
    "Test result: FAILED. Total tests: 1; passed: 0; failed: 1",
  ].join("\n");
  const r = parseMoveTestStdout(stdout);
  assert.equal(r.ok, true);
  assert.doesNotMatch(JSON.stringify(r), new RegExp(secret));
  assert.match(r.tests[0].reason || "", /api_key=REDACTED/);
});

test("smart-contract text redaction handles JSON, bearer, path secrets, and preserves non-secret hashes", () => {
  const pathSecret = "pathSecret1234567890abcdef";
  const bearer = "bearerSecret123";
  const jsonSecret = "jsonSecret123";
  const redacted = redactTextSensitiveValues([
    `rpc=https://eth-mainnet.g.alchemy.com/v2/${pathSecret}`,
    "short=https://rpc.example/project/abc1234",
    "marked=https://rpc.example/pathTokenAbc123",
    `{"api_key":"${jsonSecret}"}`,
    `Authorization: Bearer ${bearer}`,
    "assertion failed at line #42",
    "#[derive(Debug)]",
  ].join("\n"));
  assert.doesNotMatch(redacted, new RegExp(pathSecret));
  assert.doesNotMatch(redacted, new RegExp(bearer));
  assert.doesNotMatch(redacted, new RegExp(jsonSecret));
  assert.doesNotMatch(redacted, /abc1234/);
  assert.doesNotMatch(redacted, /pathTokenAbc123/);
  assert.match(redacted, /\/v2\/REDACTED/);
  assert.match(redacted, /\/project\/REDACTED/);
  assert.match(redacted, /"api_key":"REDACTED"/);
  assert.match(redacted, /Authorization: REDACTED/);
  assert.match(redacted, /line #42/);
  assert.match(redacted, /#\[derive\(Debug\)\]/);
});

test("parseMoveTestStdout caps tests[] at 100 and sets truncated", () => {
  const { parseMoveTestStdout, MOVE_TESTS_CAP } = require("../mcp/lib/move-test-output.js");
  assert.equal(MOVE_TESTS_CAP, 100);
  const lines = ["Running Move unit tests"];
  for (let i = 0; i < 150; i += 1) {
    lines.push(`[ PASS    ] 0x42::big::test_${i}`);
  }
  lines.push("Test result: OK. Total tests: 150; passed: 150; failed: 0");
  const r = parseMoveTestStdout(lines.join("\n"));
  assert.equal(r.total, 150);
  assert.equal(r.tests.length, 100);
  assert.equal(r.truncated, true);
});

test("parseMoveTestStdout returns ok=false when the stdout has no test lines or result line", () => {
  const { parseMoveTestStdout } = require("../mcp/lib/move-test-output.js");
  // Compiler crash output — no [ PASS ]/[ FAIL ] and no "Test result:".
  const stdout = "error[E04001]: ...build failed\nCompilation aborted.\n";
  const r = parseMoveTestStdout(stdout);
  assert.equal(r.ok, false);
  assert.equal(r.reason, "no_test_lines");
});

test("aptos runner classifies cargo/move-cli missing as aptos_dependency_missing", () => {
  const { classifyAptosFailure } = require("../mcp/lib/aptos-runner.js");
  const cargoMissing = classifyAptosFailure(
    { ok: false, exit_code: 127, stderr: "/bin/sh: cargo: command not found", stdout: "" },
    false,
  );
  assert.equal(cargoMissing, "aptos_dependency_missing");
  const moveMissing = classifyAptosFailure(
    { ok: false, exit_code: 127, stderr: "Error: move-cli: No such file or directory", stdout: "" },
    false,
  );
  assert.equal(moveMissing, "aptos_dependency_missing");
});

test("aptos runner classifies Move compilation errors as move_compile_failed", () => {
  const { classifyAptosFailure } = require("../mcp/lib/aptos-runner.js");
  const compilerErr = classifyAptosFailure(
    { ok: false, exit_code: 1, stderr: "", stdout: "error[E04001]: name not in scope" },
    false,
  );
  assert.equal(compilerErr, "move_compile_failed");
  // Generic exit-1 with no compile signal → unclassified.
  const generic = classifyAptosFailure(
    { ok: false, exit_code: 1, stderr: "Error: misc", stdout: "" },
    false,
  );
  assert.equal(generic, null);
});

test("sui runner classifies cargo/move-cli missing as sui_dependency_missing", () => {
  const { classifySuiFailure } = require("../mcp/lib/sui-runner.js");
  const cargoMissing = classifySuiFailure(
    { ok: false, exit_code: 127, stderr: "/bin/sh: cargo: command not found", stdout: "" },
    false,
  );
  assert.equal(cargoMissing, "sui_dependency_missing");
});

test("aptos runner rejects extra_args not in the allowlist", async () => {
  const { runAptosTest } = require("../mcp/lib/aptos-runner.js");
  await assert.rejects(async () => runAptosTest({
    workdir: os.homedir(),
    matchTest: "test_x",
    network: "mainnet",
    extraArgs: ["--profile", "/etc/passwd"],
    timeoutMs: 5000,
  }), /not in the aptos allowlist/);
});

test("sui runner rejects extra_args not in the allowlist", async () => {
  const { runSuiTest } = require("../mcp/lib/sui-runner.js");
  await assert.rejects(async () => runSuiTest({
    workdir: os.homedir(),
    matchTest: "test_x",
    network: "mainnet",
    extraArgs: ["--client.config", "/etc/passwd"],
    timeoutMs: 5000,
  }), /not in the sui allowlist/);
});

test("aptos runner rejects symlink-escaping harness paths", async () => {
  const { runAptosTest } = require("../mcp/lib/aptos-runner.js");
  const home = os.homedir();
  const tmpRoot = path.join(os.tmpdir(), "bob-aptos-symlink-" + Math.random().toString(36).slice(2));
  fs.mkdirSync(tmpRoot, { recursive: true });
  const linkPath = path.join(home, "aptos-escape-link");
  try { fs.unlinkSync(linkPath); } catch {}
  fs.symlinkSync(tmpRoot, linkPath, "dir");
  try {
    await assert.rejects(async () => runAptosTest({
      workdir: linkPath,
      matchTest: "test_x",
      network: "mainnet",
      timeoutMs: 5000,
    }), /must live under the user home directory/);
  } finally {
    try { fs.unlinkSync(linkPath); } catch {}
    try { fs.rmdirSync(tmpRoot); } catch {}
  }
});

test("aptos-client normalizes Move shorthand 0x1 to canonical 64-hex form", () => {
  const { normalizeMoveAddress, isMoveAddress } = require("../mcp/lib/aptos-client.js");
  assert.equal(isMoveAddress("0x1"), true);
  assert.equal(isMoveAddress("0x"), false);
  assert.equal(isMoveAddress("11111111111111111111111111111111"), false);
  assert.equal(normalizeMoveAddress("0x1"), "0x" + "0".repeat(63) + "1");
  assert.equal(normalizeMoveAddress("0xABCD"), "0x" + "0".repeat(60) + "abcd");
});

test("sui-client normalizes Move shorthand 0x2 to canonical 64-hex form", () => {
  const { normalizeMoveAddress, isMoveAddress } = require("../mcp/lib/sui-client.js");
  assert.equal(isMoveAddress("0x2"), true);
  assert.equal(normalizeMoveAddress("0x2"), "0x" + "0".repeat(63) + "2");
});

test("Aptos and CosmWasm REST clients append paths before query-bearing endpoint secrets", async () => {
  const { getAccountResource } = require("../mcp/lib/aptos-client.js");
  const { getContractInfo } = require("../mcp/lib/cosmwasm-client.js");
  const requested = [];
  await withMockSmartContractHttpRequest(async (url) => {
    requested.push(String(url));
    return {
      ok: true,
      status: 200,
      headers: {},
      text: "{}",
    };
  }, async () => {
    await withMockSmartContractRpcLookup({
      "aptos.example.test": [{ address: "93.184.216.34", family: 4 }],
      "cosmos.example.test": [{ address: "93.184.216.35", family: 4 }],
    }, async () => {
      await getAccountResource({
        network: "mainnet",
        address: "0x1",
        resourceType: "0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>",
        endpoints: ["https://aptos.example.test/v1?api_key=aptos-secret"],
      });
      await getContractInfo({
        network: "osmosis",
        address: "osmo1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7rusq4z5ese",
        endpoints: ["https://cosmos.example.test/cosmos?api_key=cosmos-secret"],
      });
    });
  });
  assert.match(requested[0], /^https:\/\/aptos\.example\.test\/v1\/accounts\//);
  assert.match(requested[0], /\?api_key=aptos-secret$/);
  assert.match(requested[1], /^https:\/\/cosmos\.example\.test\/cosmos\/cosmwasm\/wasm\/v1\/contract\//);
  assert.match(requested[1], /\?api_key=cosmos-secret$/);
});

test("assignment-brief summarizeRpcPoolForBrief dispatches to aptos and sui pool summaries", () => {
  const { summarizeRpcPoolForBrief } = require("../mcp/lib/evm-rpc-pool.js");
  const aptos = summarizeRpcPoolForBrief("aptos", "mainnet");
  assert.equal(aptos.chain_family, "aptos");
  assert.equal(aptos.network, "mainnet");
  assert.ok(Array.isArray(aptos.endpoints) && aptos.endpoints.length >= 1, "aptos mainnet pool surfaces endpoints");
  const sui = summarizeRpcPoolForBrief("sui", "mainnet");
  assert.equal(sui.chain_family, "sui");
  assert.equal(sui.network, "mainnet");
  assert.ok(Array.isArray(sui.endpoints) && sui.endpoints.length >= 1, "sui mainnet pool surfaces endpoints");
});

test("assignment-brief RPC pool summaries redact credentialed operator endpoints", () => {
  const { summarizeRpcPoolForBrief } = require("../mcp/lib/evm-rpc-pool.js");
  const secret = "brief-secret-token";
  withEnv({
    BOB_EVM_RPCS_1: `https://user:pass@rpc.example/rpc?api_key=${secret}`,
  }, () => {
    const evm = summarizeRpcPoolForBrief("evm", 1);
    assert.equal(evm.endpoints[0], "https://REDACTED:REDACTED@rpc.example/rpc?api_key=REDACTED");
    assert.doesNotMatch(JSON.stringify(evm), new RegExp(secret));
  });
});

test("assignment-brief summarizeRpcPoolForBrief dispatches to substrate and cosmwasm pool summaries", () => {
  const { summarizeRpcPoolForBrief } = require("../mcp/lib/evm-rpc-pool.js");
  const substrate = summarizeRpcPoolForBrief("substrate", "polkadot");
  assert.equal(substrate.chain_family, "substrate");
  assert.equal(substrate.network, "polkadot");
  assert.ok(Array.isArray(substrate.endpoints) && substrate.endpoints.length >= 1, "substrate polkadot pool surfaces endpoints");
  const cosmwasm = summarizeRpcPoolForBrief("cosmwasm", "osmosis");
  assert.equal(cosmwasm.chain_family, "cosmwasm");
  assert.equal(cosmwasm.network, "osmosis");
  assert.ok(Array.isArray(cosmwasm.endpoints) && cosmwasm.endpoints.length >= 1, "cosmwasm osmosis pool surfaces endpoints");
});

test("parseCargoTestStdout parses cargo unit test output line-by-line", () => {
  const { parseCargoTestStdout } = require("../mcp/lib/cargo-test-output.js");
  const stdout = [
    "running 4 tests",
    "test tests::works ... ok",
    "test tests::fails_assert ... FAILED",
    "test slow_test ... ignored",
    "test tests::passes_too ... ok",
    "",
    "failures:",
    "",
    "---- tests::fails_assert stdout ----",
    "thread (tests::fails_assert) panicked at assertion failed: x == 5",
    "",
    "test result: FAILED. 2 passed; 1 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.05s",
  ].join("\n");
  const r = parseCargoTestStdout(stdout);
  assert.equal(r.ok, true);
  assert.equal(r.total, 4);
  assert.equal(r.passed, 2);
  assert.equal(r.failed, 1);
  assert.equal(r.ignored, 1);
  assert.equal(r.tests[0].test_id, "tests::works");
  assert.equal(r.tests[0].status, "Pass");
  assert.equal(r.tests[1].status, "Fail");
  assert.match(r.tests[1].reason || "", /panicked at assertion failed/);
  assert.equal(r.tests[2].status, "Skipped");
  assert.equal(r.tests[2].status_raw, "ignored");
});

test("parseCargoTestStdout redacts endpoint secrets in failure reasons", () => {
  const { parseCargoTestStdout } = require("../mcp/lib/cargo-test-output.js");
  const secret = "cargo-parser-secret";
  const stdout = [
    "running 1 test",
    "test tests::leaks ... FAILED",
    "",
    "failures:",
    "",
    "---- tests::leaks stdout ----",
    `thread panicked after querying https://rpc.example/rpc?token=${secret}`,
    "",
    "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.05s",
  ].join("\n");
  const r = parseCargoTestStdout(stdout);
  assert.equal(r.ok, true);
  assert.doesNotMatch(JSON.stringify(r), new RegExp(secret));
  assert.match(r.tests[0].reason || "", /token=REDACTED/);
});

test("parseCargoTestStdout caps tests[] at 100 and sets truncated", () => {
  const { parseCargoTestStdout, CARGO_TESTS_CAP } = require("../mcp/lib/cargo-test-output.js");
  assert.equal(CARGO_TESTS_CAP, 100);
  const lines = ["running 150 tests"];
  for (let i = 0; i < 150; i += 1) {
    lines.push(`test mod::test_${i} ... ok`);
  }
  lines.push("test result: ok. 150 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.05s");
  const r = parseCargoTestStdout(lines.join("\n"));
  assert.equal(r.total, 150);
  assert.equal(r.tests.length, 100);
  assert.equal(r.truncated, true);
});

test("parseCargoTestStdout returns ok=false when stdout has no test lines or result line", () => {
  const { parseCargoTestStdout } = require("../mcp/lib/cargo-test-output.js");
  const stdout = "error[E0432]: unresolved import\nCompilation aborted.\n";
  const r = parseCargoTestStdout(stdout);
  assert.equal(r.ok, false);
  assert.equal(r.reason, "no_test_lines");
});

test("substrate runner classifies cargo missing as substrate_dependency_missing", () => {
  const { classifySubstrateFailure } = require("../mcp/lib/substrate-runner.js");
  const cargoMissing = classifySubstrateFailure(
    { ok: false, exit_code: 127, stderr: "/bin/sh: cargo: command not found", stdout: "" },
    false,
  );
  assert.equal(cargoMissing, "substrate_dependency_missing");
  // CLI usage error (older cargo rejecting --exact)
  const cliErr = classifySubstrateFailure(
    { ok: false, exit_code: 2, stderr: "error: Found argument '--exact' which wasn't expected", stdout: "" },
    false,
  );
  assert.equal(cliErr, "substrate_dependency_missing");
  // Compile error from rustc
  const compileErr = classifySubstrateFailure(
    { ok: false, exit_code: 1, stderr: "", stdout: "error[E0432]: unresolved import" },
    false,
  );
  assert.equal(compileErr, "cargo_compile_failed");
});

test("cosmwasm runner classifies cargo missing as cosmwasm_dependency_missing", () => {
  const { classifyCosmwasmFailure } = require("../mcp/lib/cosmwasm-runner.js");
  const cargoMissing = classifyCosmwasmFailure(
    { ok: false, exit_code: 127, stderr: "/bin/sh: cargo: command not found", stdout: "" },
    false,
  );
  assert.equal(cargoMissing, "cosmwasm_dependency_missing");
  const wasmdMissing = classifyCosmwasmFailure(
    { ok: false, exit_code: 127, stderr: "wasmd: command not found", stdout: "" },
    false,
  );
  assert.equal(wasmdMissing, "cosmwasm_dependency_missing");
  const compileErr = classifyCosmwasmFailure(
    { ok: false, exit_code: 1, stderr: "", stdout: "error[E0599]: no method named foo" },
    false,
  );
  assert.equal(compileErr, "cargo_compile_failed");
});

test("substrate runner rejects extra_args not in the cargo allowlist", async () => {
  const { runSubstrateTest } = require("../mcp/lib/substrate-runner.js");
  // Need a real Cargo.toml to pass the harness path check. Use a temp dir.
  const tmpRoot = path.join(os.homedir(), "bob-substrate-allowlist-test-" + Math.random().toString(36).slice(2));
  fs.mkdirSync(tmpRoot, { recursive: true });
  fs.writeFileSync(path.join(tmpRoot, "Cargo.toml"), "[package]\nname = \"test\"\nversion = \"0.1.0\"\n");
  try {
    await assert.rejects(async () => runSubstrateTest({
      workdir: tmpRoot,
      matchTest: "test_x",
      network: null,
      extraArgs: ["--release"],
      timeoutMs: 5000,
    }), /not in the substrate cargo allowlist/);
    // --workspace is intentionally NOT allowlisted; running tests across
    // every workspace member compounds compile-time blast radius.
    await assert.rejects(async () => runSubstrateTest({
      workdir: tmpRoot,
      matchTest: "test_x",
      network: null,
      extraArgs: ["--workspace"],
      timeoutMs: 5000,
    }), /not in the substrate cargo allowlist/);
  } finally {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  }
});

test("cosmwasm runner rejects extra_args not in the cargo allowlist", async () => {
  const { runCosmwasmTest } = require("../mcp/lib/cosmwasm-runner.js");
  const tmpRoot = path.join(os.homedir(), "bob-cosmwasm-allowlist-test-" + Math.random().toString(36).slice(2));
  fs.mkdirSync(tmpRoot, { recursive: true });
  fs.writeFileSync(path.join(tmpRoot, "Cargo.toml"), "[package]\nname = \"test\"\nversion = \"0.1.0\"\n");
  try {
    await assert.rejects(async () => runCosmwasmTest({
      workdir: tmpRoot,
      matchTest: "test_x",
      network: null,
      extraArgs: ["--target=wasm32-unknown-unknown"],
      timeoutMs: 5000,
    }), /not in the cosmwasm cargo allowlist/);
  } finally {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  }
});

test("substrate runner rejects harness without Cargo.toml at root", async () => {
  const { runSubstrateTest } = require("../mcp/lib/substrate-runner.js");
  const tmpRoot = path.join(os.homedir(), "bob-substrate-no-cargo-" + Math.random().toString(36).slice(2));
  fs.mkdirSync(tmpRoot, { recursive: true });
  try {
    await assert.rejects(async () => runSubstrateTest({
      workdir: tmpRoot,
      matchTest: "test_x",
      network: null,
      timeoutMs: 5000,
    }), /must contain Cargo.toml at the root/);
  } finally {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  }
});

test("cosmwasm runner rejects harness without Cargo.toml at root", async () => {
  const { runCosmwasmTest } = require("../mcp/lib/cosmwasm-runner.js");
  const tmpRoot = path.join(os.homedir(), "bob-cosmwasm-no-cargo-" + Math.random().toString(36).slice(2));
  fs.mkdirSync(tmpRoot, { recursive: true });
  try {
    await assert.rejects(async () => runCosmwasmTest({
      workdir: tmpRoot,
      matchTest: "test_x",
      network: null,
      timeoutMs: 5000,
    }), /must contain Cargo.toml at the root/);
  } finally {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  }
});

test("bech32 mixed-case rejection happens at findings layer with stable error shape", () => {
  const { normalizeBech32Address } = require("../mcp/lib/finding-contracts.js");
  // BIP-0173 forbids mixed-case bech32 — the spec is explicit. We test the
  // normalizer directly so it's clear which layer enforces this.
  assert.equal(normalizeBech32Address("Osmo1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7rusq4z5ese"), null);
  assert.equal(normalizeBech32Address("OSMO1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7rusq4z5ese"), null);
  // All-uppercase is accepted (BIP-0173 allows it; we lowercase for dedup).
  assert.equal(
    normalizeBech32Address("OSMO1QYPQXPQ9QCRSSZG2PVXQ6RS0ZQG3YYC5Z5TPWXQERGD3C8G7RUSQ4Z5ESE"),
    "osmo1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7rusq4z5ese",
  );
  // Internal whitespace is rejected: bech32 chars are ASCII 33..126, space=32.
  assert.equal(normalizeBech32Address("osmo1qypq xpq9"), null);
});

test("substrate-client rejects malformed SS58", () => {
  const { isSs58Address } = require("../mcp/lib/substrate-client.js");
  assert.equal(isSs58Address("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"), true);
  assert.equal(isSs58Address("0x" + "ab".repeat(20)), false);
  assert.equal(isSs58Address("osmo1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5"), false);
  assert.equal(isSs58Address("short"), false);
  assert.equal(isSs58Address(""), false);
});

test("cosmwasm-client rejects malformed bech32", () => {
  const { isBech32Address } = require("../mcp/lib/cosmwasm-client.js");
  assert.equal(isBech32Address("osmo1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7rusq4z5ese"), true);
  assert.equal(isBech32Address("0x" + "ab".repeat(20)), false);
  assert.equal(isBech32Address("5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"), false);
  assert.equal(isBech32Address("noseparator"), false);
});

test("sc_evidence rejects EVM-canonical 40-hex address when chain_family is aptos or sui", () => {
  const { normalizeFindingRecord } = require("../mcp/lib/finding-contracts.js");
  // A evaluator pastes Vitalik's address (or any 0x + 40 hex EVM address) into a
  // Move-family sc_evidence. Without the EVM-shape rejection, the address
  // would silently be left-padded to 64 hex and stored as a Move address
  // belonging to the wrong family. The new check refuses 0x + 40 hex.
  const evmAddress = "0x742d35Cc6634C0532925a3b844Bc9e7595f7AbCD";
  for (const family of ["aptos", "sui"]) {
    const networkValue = family === "aptos" ? "mainnet" : "mainnet";
    assert.throws(() => normalizeFindingRecord({
      id: "F-1",
      target_domain: "example.com",
      title: "x",
      severity: "low",
      cwe: null,
      endpoint: "x",
      description: "x",
      proof_of_concept: "y",
      response_evidence: null,
      impact: null,
      validated: true,
      wave: null,
      agent: null,
      surface_id: null,
      surface_type: "smart_contract",
      sc_evidence: {
        chain_family: family,
        chain_id: networkValue,
        contract_address: evmAddress,
        harness_path: os.homedir(),
        match_test: "test_x",
      },
    }), /looks like a canonical EVM address.*chain_family='/, `Move family '${family}' must reject EVM 40-hex shape`);
  }
  // Real Move addresses with 12 leading zero bytes are still accepted in
  // canonical 64-hex form.
  const finding = normalizeFindingRecord({
    id: "F-1",
    target_domain: "example.com",
    title: "x",
    severity: "low",
    cwe: null,
    endpoint: "x",
    description: "x",
    proof_of_concept: "y",
    response_evidence: null,
    impact: null,
    validated: true,
    wave: null,
    agent: null,
    surface_id: null,
    surface_type: "smart_contract",
    sc_evidence: {
      chain_family: "aptos",
      chain_id: "mainnet",
      contract_address: "0x" + "0".repeat(24) + "742d35cc6634c0532925a3b844bc9e7595f7abcd",
      harness_path: os.homedir(),
      match_test: "test_x",
    },
  });
  assert.equal(
    finding.sc_evidence.contract_address,
    "0x" + "0".repeat(24) + "742d35cc6634c0532925a3b844bc9e7595f7abcd",
    "canonical 64-hex address with 12 leading zero bytes is still accepted",
  );
});

test("aptos runner classifies CLI usage errors as aptos_dependency_missing", () => {
  const { classifyAptosFailure } = require("../mcp/lib/aptos-runner.js");
  // Old aptos CLI (pre-1.0) doesn't support --package-dir.
  const oldPackageDir = classifyAptosFailure(
    { ok: false, exit_code: 1, stderr: "error: unrecognized argument --package-dir", stdout: "" },
    false,
  );
  assert.equal(oldPackageDir, "aptos_dependency_missing");
  const wrongFlag = classifyAptosFailure(
    { ok: false, exit_code: 1, stderr: "error: Found argument '--filter' which wasn't expected, or isn't valid in this context", stdout: "" },
    false,
  );
  assert.equal(wrongFlag, "aptos_dependency_missing");
  const missingPositional = classifyAptosFailure(
    { ok: false, exit_code: 1, stderr: "error: The following required arguments were not provided:\n  <PACKAGE_PATH>", stdout: "" },
    false,
  );
  assert.equal(missingPositional, "aptos_dependency_missing");
});

test("sui runner classifies CLI usage errors as sui_dependency_missing", () => {
  const { classifySuiFailure } = require("../mcp/lib/sui-runner.js");
  // Older sui CLIs may not accept --filter / --path.
  const oldFilter = classifySuiFailure(
    { ok: false, exit_code: 1, stderr: "error: unrecognized argument --filter", stdout: "" },
    false,
  );
  assert.equal(oldFilter, "sui_dependency_missing");
  const oldPath = classifySuiFailure(
    { ok: false, exit_code: 1, stderr: "error: unexpected argument '--path' found", stdout: "" },
    false,
  );
  assert.equal(oldPath, "sui_dependency_missing");
});

test("Move tools register with verifier and evidence role bundles (so balanced/brutalist/final + evidence-agent can re-run Aptos/Sui PoCs)", () => {
  const tools = [
    "bob_aptos_fetch_resource",
    "bob_aptos_fetch_module",
    "bob_aptos_run",
    "bob_sui_fetch_object",
    "bob_sui_fetch_package",
    "bob_sui_run",
  ];
  for (const name of tools) {
    const meta = TOOL_MANIFEST[name];
    assert.ok(meta, `${name} is in TOOL_MANIFEST`);
    assert.deepEqual(meta.role_bundles, ["evaluator-move", "verifier", "evidence"], `${name} exposes role_bundles=[evaluator-move, verifier, evidence]`);
    assert.equal(meta.network_access, true, `${name} declares network_access`);
  }
});

test("bob_record_finding deduplicates exact findings unless force_record is set", () => {
  withTempHome(() => {
    const domain = "example.com";
    const first = seedFinding(domain);
    const duplicate = seedFinding(domain);

    assert.equal(first.finding_id, "F-1");
    assert.equal(duplicate.recorded, false);
    assert.equal(duplicate.duplicate, true);
    assert.equal(duplicate.finding_id, "F-1");
    assert.equal(fs.readFileSync(claimsJsonlPath(domain), "utf8").trim().split("\n").length, 1);

    const forced = seedFinding(domain, { force_record: true });
    assert.equal(forced.recorded, true);
    assert.equal(forced.finding_id, "F-2");
    assert.equal(forced.force_record, true);

    const records = readFindingsFromJsonl(domain);
    assert.equal(records.length, 2);
    assert.equal(records[1].force_record, true);
    assert.equal(records[0].dedupe_key, records[1].dedupe_key);
  });
});


test("bob_read_findings, bob_list_findings, and bob_wave_status return empty-state results when findings.jsonl is absent", () => {
  withTempHome(() => {
    const domain = "example.com";

    assert.deepEqual(JSON.parse(readFindings({ target_domain: domain })), {
      version: 1,
      target_domain: domain,
      findings: [],
    });
    assert.deepEqual(JSON.parse(listFindings({ target_domain: domain })), {
      count: 0,
      findings: [],
    });
    const status = JSON.parse(waveStatus({ target_domain: domain }));
    assert.deepEqual(status, {
      total: 0,
      by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      has_high_or_critical: false,
      coverage: null,
      transition_blockers: [{
        code: "state_unavailable",
        message: "session state could not be read for frontier readiness",
        error: `Missing session state: ${statePath(domain)}`,
      }],
      http_audit: {
        total: 0,
        shown: 0,
        omitted: 0,
        cap: 0,
        by_status_class: { "2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, other: 0 },
        errors: 0,
        scope_blocked: 0,
        network_unreachable_target: 0,
        egress: { by_profile: {}, by_region: {}, by_identity_hash: {}, unbound: 0, identities: [] },
        geofence_warning: { threshold: 3, warning: false, code: null, note: null, hosts: [] },
        recent: [],
      },
      traffic: { total: 0, shown: 0, omitted: 0, cap: 0, authenticated_count: 0, by_status_class: { "2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, other: 0 }, recent: [] },
      circuit_breaker: { threshold: 3, tripped_hosts: [], tripped_count: 0, below_threshold_hosts: [], below_threshold_count: 0, note: null },
      surface_leads: { total: 0, high_confidence_unpromoted: 0, promoted: 0 },
      findings_summary: [],
    });
  });
});

test("malformed claims.jsonl hard-fails bob_read_findings, bob_list_findings, and bob_wave_status", () => {
  withTempHome(() => {
    const domain = "example.com";
    const dir = sessionDir(domain);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(claimsJsonlPath(domain), "not-json\n");

    assert.throws(() => readFindings({ target_domain: domain }), /claims\.jsonl/);
    assert.throws(() => listFindings({ target_domain: domain }), /claims\.jsonl/);
    assert.throws(() => waveStatus({ target_domain: domain }), /claims\.jsonl/);
  });
});

test("bob_list_findings and bob_wave_status keep their external shapes while reading findings.jsonl", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedFinding(domain, { severity: "critical" });
    seedFinding(domain, {
      title: "Verbose stack trace leak",
      severity: "low",
      endpoint: "/boom",
      description: "Exception page leaks internal paths.",
      proof_of_concept: "curl https://example.com/boom",
      response_evidence: "ReferenceError",
      impact: "Improves proof development.",
      wave: null,
      agent: null,
    });

    assert.deepEqual(JSON.parse(listFindings({ target_domain: domain })), {
      count: 2,
      findings: [
        {
          id: "F-1",
          severity: "critical",
          title: "IDOR on account export",
          endpoint: "/api/export",
        },
        {
          id: "F-2",
          severity: "low",
          title: "Verbose stack trace leak",
          endpoint: "/boom",
        },
      ],
    });

    assert.deepEqual(JSON.parse(waveStatus({ target_domain: domain })), {
      total: 2,
      by_severity: { critical: 1, high: 0, medium: 0, low: 1, info: 0 },
      has_high_or_critical: true,
      coverage: null,
      transition_blockers: [{
        code: "state_unavailable",
        message: "session state could not be read for frontier readiness",
        error: `Missing session state: ${statePath(domain)}`,
      }],
      http_audit: {
        total: 0,
        shown: 0,
        omitted: 0,
        cap: 0,
        by_status_class: { "2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, other: 0 },
        errors: 0,
        scope_blocked: 0,
        network_unreachable_target: 0,
        egress: { by_profile: {}, by_region: {}, by_identity_hash: {}, unbound: 0, identities: [] },
        geofence_warning: { threshold: 3, warning: false, code: null, note: null, hosts: [] },
        recent: [],
      },
      traffic: { total: 0, shown: 0, omitted: 0, cap: 0, authenticated_count: 0, by_status_class: { "2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, other: 0 }, recent: [] },
      circuit_breaker: { threshold: 3, tripped_hosts: [], tripped_count: 0, below_threshold_hosts: [], below_threshold_count: 0, note: null },
      surface_leads: { total: 0, high_confidence_unpromoted: 0, promoted: 0 },
      findings_summary: [
        {
          id: "F-1",
          severity: "critical",
          title: "IDOR on account export",
          endpoint: "/api/export",
          wave_agent: "w1/a1",
        },
        {
          id: "F-2",
          severity: "low",
          title: "Verbose stack trace leak",
          endpoint: "/boom",
          wave_agent: null,
        },
      ],
    });
  });
});

test("bob_write_verification_round writes the correct JSON and markdown pair for each round", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedFinding(domain);

    for (const round of ["brutalist", "balanced", "final"]) {
      const result = JSON.parse(writeVerificationRound({
        target_domain: domain,
        round,
        notes: null,
        results: [],
      }));
      const paths = verificationRoundPaths(domain, round);

      assert.equal(result.round, round);
      assert.equal(result.results_count, 0);
      assert.equal(result.written_json, paths.json);
      assert.equal(result.written_md, paths.markdown);

      assert.deepEqual(JSON.parse(fs.readFileSync(paths.json, "utf8")), {
        version: 1,
        target_domain: domain,
        round,
        notes: null,
        results: [],
      });
      assert.match(fs.readFileSync(paths.markdown, "utf8"), /No verification results recorded\./);

      assert.deepEqual(JSON.parse(readVerificationRound({ target_domain: domain, round })), {
        version: 1,
        target_domain: domain,
        round,
        notes: null,
        results: [],
      });
    }
  });
});

test("bob_write_verification_round accepts notes null and validates duplicate and unknown finding_ids", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedFinding(domain);

    assert.throws(() => writeVerificationRound({
      target_domain: domain,
      round: "brutalist",
      notes: null,
      results: [
        {
          finding_id: "F-1",
          disposition: "confirmed",
          severity: "high",
          reportable: true,
          reasoning: "Still demonstrable.",
        },
        {
          finding_id: "F-1",
          disposition: "downgraded",
          severity: "medium",
          reportable: true,
          reasoning: "Duplicate entry should fail.",
        },
      ],
    }), /Duplicate finding_id in results: F-1/);

    assert.throws(() => writeVerificationRound({
      target_domain: domain,
      round: "balanced",
      notes: null,
      results: [
        {
          finding_id: "F-99",
          disposition: "denied",
          severity: null,
          reportable: false,
          reasoning: "Unknown ID.",
        },
      ],
    }), /Unknown finding_id: F-99/);
  });
});

test("bob_write_verification_round rejects balanced/final rounds that drop prior-round findings", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedFinding(domain);
    seedFinding(domain, { title: "Second finding", endpoint: "/api/second" });

    const fullResult = (id) => ({
      finding_id: id,
      disposition: "confirmed",
      severity: "high",
      reportable: true,
      reasoning: "Valid.",
    });

    // Write brutalist round with both findings
    writeVerificationRound({
      target_domain: domain,
      round: "brutalist",
      notes: null,
      results: [fullResult("F-1"), fullResult("F-2")],
    });

    // Balanced round missing F-2 should fail
    assert.throws(() => writeVerificationRound({
      target_domain: domain,
      round: "balanced",
      notes: null,
      results: [fullResult("F-1")],
    }), /balanced round is missing 1 finding.*F-2/);

    // Balanced round with both findings should succeed
    writeVerificationRound({
      target_domain: domain,
      round: "balanced",
      notes: null,
      results: [fullResult("F-1"), fullResult("F-2")],
    });

    // Final round missing F-1 should fail
    assert.throws(() => writeVerificationRound({
      target_domain: domain,
      round: "final",
      notes: null,
      results: [fullResult("F-2")],
    }), /final round is missing 1 finding.*F-1/);

    // Final round with both findings should succeed
    writeVerificationRound({
      target_domain: domain,
      round: "final",
      notes: null,
      results: [fullResult("F-1"), fullResult("F-2")],
    });
  });
});

test("bob_write_verification_round requires valid prior round artifacts", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedFinding(domain);

    assert.throws(() => writeVerificationRound({
      target_domain: domain,
      round: "balanced",
      notes: null,
      results: [],
    }), /Missing brutalist verification round JSON/);

    writeVerificationRound({
      target_domain: domain,
      round: "brutalist",
      notes: null,
      results: [],
    });
    assert.throws(() => writeVerificationRound({
      target_domain: domain,
      round: "final",
      notes: null,
      results: [],
    }), /Missing balanced verification round JSON/);
  });
});

test("bob_read_verification_round hard-fails on missing or malformed JSON", () => {
  withTempHome(() => {
    const domain = "example.com";

    assert.throws(
      () => readVerificationRound({ target_domain: domain, round: "final" }),
      /Missing final verification round JSON/,
    );

    const paths = verificationRoundPaths(domain, "final");
    fs.mkdirSync(path.dirname(paths.json), { recursive: true });
    fs.writeFileSync(paths.json, "{bad json");

    assert.throws(
      () => readVerificationRound({ target_domain: domain, round: "final" }),
      /Malformed final verification round JSON/,
    );
  });
});

test("bob_read_verification_round rejects JSON that references non-existent findings", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedFinding(domain);

    const paths = verificationRoundPaths(domain, "balanced");
    fs.mkdirSync(path.dirname(paths.json), { recursive: true });
    fs.writeFileSync(paths.json, `${JSON.stringify({
      version: 1,
      target_domain: domain,
      round: "balanced",
      notes: null,
      results: [
        {
          finding_id: "F-99",
          disposition: "denied",
          severity: null,
          reportable: false,
          reasoning: "Manually edited bad artifact.",
        },
      ],
    }, null, 2)}\n`);

    assert.throws(
      () => readVerificationRound({ target_domain: domain, round: "balanced" }),
      /Unknown finding_id: F-99/,
    );
  });
});

test("verification v2 attempt is created only on CHAIN -> VERIFY and context reports current status", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "CHAIN" });
    seedFinding(domain);

    const before = JSON.parse(readVerificationContext({ target_domain: domain }));
    assert.equal(before.schema_version, 2);
    assert.equal(before.current_attempt_id, null);
    assert.equal(fs.existsSync(verificationSnapshotPath(domain)), false);

    const transitioned = JSON.parse(transitionPhase({ target_domain: domain, to_phase: "VERIFY" }));
    assert.equal(transitioned.verification.schema_version, 2);
    assert.match(transitioned.verification.attempt_id, /^[0-9T]+-[a-f0-9]{8}$/);
    assert.equal(fs.existsSync(verificationSnapshotPath(domain)), true);

    const context = JSON.parse(readVerificationContext({ target_domain: domain }));
    assert.equal(context.current_attempt_id, transitioned.verification.attempt_id);
    assert.equal(context.snapshot_hash, transitioned.verification.snapshot_hash);
    assert.equal(context.round_status.brutalist.exists, false);
    assert.equal(context.adjudication_status.exists, false);
    assert.match(context.next_action, /brutalist and balanced/);
  });
});

test("verification v2 archive recovers attempt_id from snapshot when state has lost it", () => {
  withTempHome(() => {
    const domain = "orphaned-attempt.example.com";
    seedSessionState(domain, { phase: "CHAIN" });
    seedFinding(domain);
    JSON.parse(transitionPhase({ target_domain: domain, to_phase: "VERIFY" }));
    const firstSnapshot = JSON.parse(fs.readFileSync(verificationSnapshotPath(domain), "utf8"));
    const firstAttemptId = firstSnapshot.verification_attempt_id;

    // Simulate state.json losing the attempt fields (manual edit / partial recovery)
    // while the snapshot file remains on disk. Without the orphan-recovery fix,
    // the next CHAIN -> VERIFY archives this artifact set as `attempt-unknown`
    // and a second iteration collides on the same path.
    const stateDoc = JSON.parse(fs.readFileSync(statePath(domain), "utf8"));
    delete stateDoc.verification_attempt_id;
    delete stateDoc.verification_snapshot_hash;
    delete stateDoc.verification_entered_at;
    stateDoc.phase = "CHAIN";
    writeFileAtomic(statePath(domain), `${JSON.stringify(stateDoc, null, 2)}\n`);

    JSON.parse(transitionPhase({
      target_domain: domain,
      to_phase: "VERIFY",
      override_reason: "regression: orphaned attempt archives by inferred id",
    }));

    const archivesDir = path.join(sessionDir(domain), "verification-attempts");
    const archived = fs.readdirSync(archivesDir).filter((name) => name.startsWith("attempt-"));
    assert.equal(archived.length, 1);
    assert.equal(archived[0], `attempt-${firstAttemptId}`);

    // Re-run the same recovery dance: drop attempt fields and trigger a fresh
    // bootstrap. The new attempt's snapshot replaced the previous one, so its
    // attempt_id is what should land on disk this time. Critically, the second
    // archive must NOT collide with the first.
    const secondSnapshot = JSON.parse(fs.readFileSync(verificationSnapshotPath(domain), "utf8"));
    const secondAttemptId = secondSnapshot.verification_attempt_id;
    const stateDoc2 = JSON.parse(fs.readFileSync(statePath(domain), "utf8"));
    delete stateDoc2.verification_attempt_id;
    delete stateDoc2.verification_snapshot_hash;
    delete stateDoc2.verification_entered_at;
    stateDoc2.phase = "CHAIN";
    writeFileAtomic(statePath(domain), `${JSON.stringify(stateDoc2, null, 2)}\n`);
    JSON.parse(transitionPhase({
      target_domain: domain,
      to_phase: "VERIFY",
      override_reason: "regression: second orphaned recovery must not collide",
    }));

    const archivedAfter = fs.readdirSync(archivesDir).filter((name) => name.startsWith("attempt-")).sort();
    assert.equal(archivedAfter.length, 2);
    assert.ok(archivedAfter.includes(`attempt-${firstAttemptId}`));
    assert.ok(archivedAfter.includes(`attempt-${secondAttemptId}`));
  });
});

test("verification v2 CHAIN -> VERIFY rejects when manifest refresh fails", () => {
  withTempHome(() => {
    const domain = "manifest-fail.example.com";
    seedSessionState(domain, { phase: "CHAIN" });
    seedFinding(domain);
    const manifestPath = verificationManifestPath(domain);
    // writeFileAtomic uses fs.renameSync to move a tempfile onto the target path.
    // Intercept the rename when the destination is the manifest to simulate a
    // manifest write failure without touching the snapshot or state writes.
    const originalRenameSync = fs.renameSync;
    fs.renameSync = (from, to) => {
      if (to === manifestPath) {
        throw new Error("simulated manifest write failure");
      }
      return originalRenameSync(from, to);
    };
    try {
      assert.throws(
        () => transitionPhase({ target_domain: domain, to_phase: "VERIFY" }),
        /simulated manifest write failure/,
      );
    } finally {
      fs.renameSync = originalRenameSync;
    }
    // The transition should have refused to publish the new attempt as durable
    // state once the manifest write fails. The CR-flagged race was that state
    // would advance silently while the manifest was missing.
    const stateOnDisk = JSON.parse(fs.readFileSync(statePath(domain), "utf8"));
    assert.equal(stateOnDisk.phase, "CHAIN");
    assert.equal(stateOnDisk.verification_attempt_id ?? null, null);
    assert.equal(stateOnDisk.verification_snapshot_hash ?? null, null);
  });
});

test("verification v2 round and final hashes are stable across confidence_reasons and artifact_hashes ordering", () => {
  withTempHome(() => {
    const domain = "determinism.example.com";
    enterVerifyV2(domain);
    const ctx = JSON.parse(readVerificationContext({ target_domain: domain }));

    const reasonsA = ["fresh_replay_passed", "auth_expired", "tooling_blocked"];
    const reasonsB = ["tooling_blocked", "fresh_replay_passed", "auth_expired"];
    const hashesA = {
      foundry_run: "1".repeat(64),
      http_audit: "2".repeat(64),
      roast: "3".repeat(64),
    };
    const hashesB = {
      roast: "3".repeat(64),
      foundry_run: "1".repeat(64),
      http_audit: "2".repeat(64),
    };

    const writeOnce = (reasons, hashes) => {
      const result = v2VerificationResult("F-1", {
        confidence_reasons: reasons,
        artifact_hashes: hashes,
      });
      for (const round of ["brutalist", "balanced"]) {
        writeVerificationRound({
          target_domain: domain,
          round,
          notes: null,
          verification_attempt_id: ctx.current_attempt_id,
          verification_snapshot_hash: ctx.snapshot_hash,
          round_profile: round,
          results: [result],
        });
      }
      const adj = JSON.parse(buildVerificationAdjudication({ target_domain: domain }));
      const final = JSON.parse(writeVerificationRound({
        target_domain: domain,
        round: "final",
        notes: null,
        verification_attempt_id: ctx.current_attempt_id,
        verification_snapshot_hash: ctx.snapshot_hash,
        round_profile: "final",
        adjudication_plan_hash: adj.adjudication_plan_hash,
        results: [result],
      }));
      const onDisk = JSON.parse(fs.readFileSync(verificationRoundPaths(domain, "brutalist").json, "utf8"));
      return {
        adjudicationPlanHash: adj.adjudication_plan_hash,
        finalHash: final.final_verification_hash,
        brutalistOnDisk: onDisk,
      };
    };

    const baseline = writeOnce(reasonsA, hashesA);
    const permuted = writeOnce(reasonsB, hashesB);

    assert.equal(permuted.adjudicationPlanHash, baseline.adjudicationPlanHash);
    assert.equal(permuted.finalHash, baseline.finalHash);
    assert.deepEqual(
      permuted.brutalistOnDisk.results[0].confidence_reasons,
      baseline.brutalistOnDisk.results[0].confidence_reasons,
    );
    assert.deepEqual(
      Object.keys(permuted.brutalistOnDisk.results[0].artifact_hashes),
      Object.keys(baseline.brutalistOnDisk.results[0].artifact_hashes),
    );
  });
});

test("verification v2 round results sort deterministically across multi-finding writes", () => {
  withTempHome(() => {
    const domain = "multi-finding.example.com";
    seedSessionState(domain, { phase: "CHAIN" });
    seedFinding(domain, { title: "First" });
    seedFinding(domain, { title: "Second" });
    seedFinding(domain, { title: "Third" });
    JSON.parse(transitionPhase({
      target_domain: domain,
      to_phase: "VERIFY",
      override_reason: "deterministic-results-ordering smoke fixture",
    }));
    const ctx = JSON.parse(readVerificationContext({ target_domain: domain }));

    const ordered = ["F-1", "F-2", "F-3"].map((id) => v2VerificationResult(id));
    const reversed = [...ordered].reverse();

    const hashFor = (results) => {
      writeVerificationRound({
        target_domain: domain,
        round: "brutalist",
        notes: null,
        verification_attempt_id: ctx.current_attempt_id,
        verification_snapshot_hash: ctx.snapshot_hash,
        round_profile: "brutalist",
        results,
      });
      const onDiskPath = verificationRoundPaths(domain, "brutalist").json;
      const onDiskBytes = fs.readFileSync(onDiskPath);
      const onDisk = JSON.parse(onDiskBytes.toString("utf8"));
      return {
        ids: onDisk.results.map((r) => r.finding_id),
        artifact_hash: require("crypto").createHash("sha256").update(onDiskBytes).digest("hex"),
      };
    };

    const a = hashFor(ordered);
    const b = hashFor(reversed);
    assert.deepEqual(a.ids, ["F-1", "F-2", "F-3"]);
    assert.deepEqual(b.ids, ["F-1", "F-2", "F-3"]);
    assert.equal(a.artifact_hash, b.artifact_hash);
  });
});

test("verification v2 supports independent round order, deterministic adjudication, final hash, and evidence binding", () => {
  withTempHome(() => {
    const domain = "example.com";
    enterVerifyV2(domain);
    const context = JSON.parse(readVerificationContext({ target_domain: domain }));
    const result = v2VerificationResult("F-1");
    const initialManifest = JSON.parse(fs.readFileSync(verificationManifestPath(domain), "utf8"));
    assert.equal(initialManifest.artifacts.snapshot.current, true);
    assert.equal(initialManifest.artifacts.rounds.brutalist.exists, false);
    assert.equal(initialManifest.chain_complete, false);

    assert.throws(() => writeVerificationRound({
      target_domain: domain,
      round: "balanced",
      notes: null,
      verification_attempt_id: context.current_attempt_id,
      verification_snapshot_hash: context.snapshot_hash,
      round_profile: "balanced",
      results: [],
    }), /balanced must cover exactly the current VERIFY snapshot finding IDs/);

    const balanced = JSON.parse(writeVerificationRound({
      target_domain: domain,
      round: "balanced",
      notes: null,
      verification_attempt_id: context.current_attempt_id,
      verification_snapshot_hash: context.snapshot_hash,
      round_profile: "balanced",
      results: [result],
    }));
    assert.equal(balanced.schema_version, 2);
    let manifest = JSON.parse(fs.readFileSync(verificationManifestPath(domain), "utf8"));
    assert.equal(manifest.artifacts.rounds.balanced.current, true);
    assert.equal(manifest.artifacts.rounds.brutalist.exists, false);
    assert.equal(manifest.chain_complete, false);
    assert.doesNotMatch(JSON.stringify(manifest), /\.md/);

    const brutalist = JSON.parse(writeVerificationRound({
      target_domain: domain,
      round: "brutalist",
      notes: null,
      verification_attempt_id: context.current_attempt_id,
      verification_snapshot_hash: context.snapshot_hash,
      round_profile: "brutalist",
      results: [result],
    }));
    assert.equal(brutalist.schema_version, 2);
    manifest = JSON.parse(fs.readFileSync(verificationManifestPath(domain), "utf8"));
    assert.equal(manifest.artifacts.rounds.brutalist.current, true);
    assert.equal(manifest.artifacts.adjudication.exists, false);
    assert.equal(manifest.chain_complete, false);

    let adjudication = JSON.parse(buildVerificationAdjudication({ target_domain: domain }));
    const adjudicationAgain = JSON.parse(buildVerificationAdjudication({ target_domain: domain }));
    assert.equal(adjudication.adjudication_plan_hash, adjudicationAgain.adjudication_plan_hash);
    assert.equal(Object.hasOwn(adjudication, "plan_hash"), false);
    assert.deepEqual(adjudication.counts, {
      findings: 1,
      agreed: 1,
      disagreements: 0,
      union_reportables: 1,
      replay_required: 1,
      qa_sampled: 0,
    });
    const adjudicationDoc = JSON.parse(fs.readFileSync(verificationAdjudicationPath(domain), "utf8"));
    assert.equal(adjudicationDoc.adjudication_plan_hash, adjudication.adjudication_plan_hash);
    assert.equal(Object.hasOwn(adjudicationDoc, "plan_hash"), false);
    assert.equal(
      computeAdjudicationPlanHash({
        ...adjudicationDoc,
        built_at: "changed",
        adjudication_plan_hash: "changed",
      }),
      adjudication.adjudication_plan_hash,
    );
    manifest = JSON.parse(fs.readFileSync(verificationManifestPath(domain), "utf8"));
    assert.equal(manifest.adjudication_plan_hash, adjudication.adjudication_plan_hash);
    assert.equal(manifest.artifacts.adjudication.current, true);
    assert.equal(manifest.chain_hashes.adjudication_plan_hash, adjudication.adjudication_plan_hash);
    assert.equal(Object.hasOwn(manifest, "plan_hash"), false);
    let verificationContext = JSON.parse(readVerificationContext({ target_domain: domain }));
    assert.equal(verificationContext.adjudication_context.current, true);
    assert.equal(verificationContext.adjudication_context.adjudication_plan_hash, adjudication.adjudication_plan_hash);
    assert.deepEqual(verificationContext.adjudication_context.finding_ids, ["F-1"]);
    assert.equal(verificationContext.adjudication_context.findings[0].finding_id, "F-1");
    assert.equal(verificationContext.adjudication_context.findings[0].replay_required, true);
    assert.equal(Object.hasOwn(verificationContext.adjudication_context.findings[0], "reasoning"), false);
    assert.doesNotMatch(JSON.stringify(verificationContext.adjudication_context), /curl|account_id|proof_of_concept|response_evidence/i);

    const staleAdjudicationHash = adjudication.adjudication_plan_hash;
    writeVerificationRound({
      target_domain: domain,
      round: "balanced",
      notes: "Balanced round revised after adjudication.",
      verification_attempt_id: context.current_attempt_id,
      verification_snapshot_hash: context.snapshot_hash,
      round_profile: "balanced",
      results: [v2VerificationResult("F-1", {
        confidence: "medium",
        confidence_reasons: ["manual_inference"],
        reasoning: "Balanced round revised after adjudication.",
      })],
    });
    manifest = JSON.parse(fs.readFileSync(verificationManifestPath(domain), "utf8"));
    assert.equal(manifest.artifacts.adjudication.current, false);
    assert.match(
      manifest.artifacts.adjudication.blocker_reason,
      /input_round_hashes\.balanced does not match current balanced round/,
    );
    verificationContext = JSON.parse(readVerificationContext({ target_domain: domain }));
    assert.equal(verificationContext.adjudication_context.current, false);
    assert.equal(verificationContext.adjudication_context.stale, true);
    assert.match(
      verificationContext.adjudication_context.blocker_reason,
      /input_round_hashes\.balanced does not match current balanced round/,
    );
    assert.equal(Object.hasOwn(verificationContext.adjudication_context, "findings"), false);
    assert.throws(() => writeVerificationRound({
      target_domain: domain,
      round: "final",
      notes: null,
      verification_attempt_id: context.current_attempt_id,
      verification_snapshot_hash: context.snapshot_hash,
      round_profile: "final",
      adjudication_plan_hash: staleAdjudicationHash,
      results: [result],
    }), /input_round_hashes\.balanced does not match current balanced round/);
    adjudication = JSON.parse(buildVerificationAdjudication({ target_domain: domain }));
    assert.notEqual(adjudication.adjudication_plan_hash, staleAdjudicationHash);
    manifest = JSON.parse(fs.readFileSync(verificationManifestPath(domain), "utf8"));
    assert.equal(manifest.artifacts.adjudication.current, true);
    assert.equal(manifest.adjudication_plan_hash, adjudication.adjudication_plan_hash);

    assert.throws(() => writeVerificationRound({
      target_domain: domain,
      round: "final",
      notes: null,
      verification_attempt_id: context.current_attempt_id,
      verification_snapshot_hash: context.snapshot_hash,
      round_profile: "final",
      plan_hash: adjudication.adjudication_plan_hash,
      adjudication_plan_hash: adjudication.adjudication_plan_hash,
      results: [result],
    }), /plan_hash is not supported/);

    assert.throws(() => writeVerificationRound({
      target_domain: domain,
      round: "final",
      notes: null,
      verification_attempt_id: context.current_attempt_id,
      verification_snapshot_hash: context.snapshot_hash,
      round_profile: "final",
      adjudication_plan_hash: "wrong",
      results: [result],
    }), /adjudication_plan_hash does not match/);

    const final = JSON.parse(writeVerificationRound({
      target_domain: domain,
      round: "final",
      notes: null,
      verification_attempt_id: context.current_attempt_id,
      verification_snapshot_hash: context.snapshot_hash,
      round_profile: "final",
      adjudication_plan_hash: adjudication.adjudication_plan_hash,
      results: [result],
    }));
    assert.match(final.final_verification_hash, /^[a-f0-9]{64}$/);
    manifest = JSON.parse(fs.readFileSync(verificationManifestPath(domain), "utf8"));
    assert.equal(manifest.artifacts.rounds.final.current, true);
    assert.equal(manifest.artifacts.rounds.final.adjudication_plan_hash, adjudication.adjudication_plan_hash);
    assert.equal(manifest.artifacts.evidence.current, false);
    assert.equal(manifest.chain_complete, false);

    const evidence = JSON.parse(writeEvidencePacks({
      target_domain: domain,
      packs: [evidencePack("F-1")],
    }));
    assert.equal(evidence.verification_attempt_id, context.current_attempt_id);
    assert.equal(evidence.verification_snapshot_hash, context.snapshot_hash);
    assert.equal(evidence.final_verification_hash, final.final_verification_hash);
    manifest = JSON.parse(fs.readFileSync(verificationManifestPath(domain), "utf8"));
    assert.equal(manifest.artifacts.evidence.current, true);
    assert.equal(manifest.artifacts.evidence.exists, true);
    assert.equal(manifest.chain_complete, true);

    const evidenceDoc = JSON.parse(readEvidencePacks({ target_domain: domain }));
    assert.equal(evidenceDoc.final_verification_hash, final.final_verification_hash);
    assert.doesNotThrow(() => transitionPhase({ target_domain: domain, to_phase: "GRADE" }));
  });
});

test("verification v2 manifest treats no-reportable final evidence as skipped without materializing evidence", () => {
  withTempHome(() => {
    const domain = "example.com";
    enterVerifyV2(domain);
    const context = JSON.parse(readVerificationContext({ target_domain: domain }));
    const result = v2VerificationResult("F-1", {
      disposition: "denied",
      severity: null,
      reportable: false,
      reasoning: "Fresh replay denied the finding.",
    });
    for (const round of ["brutalist", "balanced"]) {
      writeVerificationRound({
        target_domain: domain,
        round,
        notes: null,
        verification_attempt_id: context.current_attempt_id,
        verification_snapshot_hash: context.snapshot_hash,
        round_profile: round,
        results: [result],
      });
    }
    const adjudication = JSON.parse(buildVerificationAdjudication({ target_domain: domain }));
    writeVerificationRound({
      target_domain: domain,
      round: "final",
      notes: null,
      verification_attempt_id: context.current_attempt_id,
      verification_snapshot_hash: context.snapshot_hash,
      round_profile: "final",
      adjudication_plan_hash: adjudication.adjudication_plan_hash,
      results: [result],
    });

    const evidencePaths = evidencePackPaths(domain);
    assert.equal(fs.existsSync(evidencePaths.json), false);
    const manifest = JSON.parse(fs.readFileSync(verificationManifestPath(domain), "utf8"));
    assert.equal(manifest.artifacts.evidence.exists, false);
    assert.equal(manifest.artifacts.evidence.skipped, true);
    assert.equal(manifest.artifacts.evidence.current, true);
    assert.equal(manifest.chain_complete, true);
    assert.equal(fs.existsSync(evidencePaths.json), false);
  });
});

test("verification v2 blocks grading when adjudication goes stale after final evidence", () => {
  withTempHome(() => {
    const domain = "stale-after-final.example.com";
    enterVerifyV2(domain);
    const context = JSON.parse(readVerificationContext({ target_domain: domain }));
    seedVerificationPipeline(domain, [v2VerificationResult("F-1")]);
    writeEvidencePacks({ target_domain: domain, packs: [evidencePack("F-1")] });

    const before = JSON.parse(readVerificationContext({ target_domain: domain }));
    assert.equal(before.adjudication_context.current, true);
    assert.equal(before.round_status.final.current, true);
    assert.equal(before.evidence_match_status.valid, true);

    writeVerificationRound({
      target_domain: domain,
      round: "balanced",
      notes: "Balanced round revised after final and evidence were already written.",
      verification_attempt_id: context.current_attempt_id,
      verification_snapshot_hash: context.snapshot_hash,
      round_profile: "balanced",
      results: [v2VerificationResult("F-1", {
        confidence: "medium",
        confidence_reasons: ["manual_inference"],
        reasoning: "Revised balanced view after final.",
      })],
    });

    const after = JSON.parse(readVerificationContext({ target_domain: domain }));
    assert.equal(after.adjudication_status.current, false);
    assert.match(after.adjudication_status.blocker_reason, /input_round_hashes\.balanced/);
    assert.equal(after.adjudication_context.current, false);
    assert.equal(Object.hasOwn(after.adjudication_context, "findings"), false);
    assert.equal(after.round_status.final.current, false);
    assert.match(after.round_status.final.blocker_reason, /input_round_hashes\.balanced/);
    assert.equal(after.evidence_match_status.valid, false);
    assert.match(after.evidence_match_status.blocker_reason, /input_round_hashes\.balanced/);

    assert.throws(
      () => transitionPhase({ target_domain: domain, to_phase: "GRADE" }),
      /VERIFY -> GRADE blocked: .*verification v2 chain is incomplete or stale.*input_round_hashes\.balanced/is,
    );
    assert.throws(() => writeGradeVerdict({
      target_domain: domain,
      verdict: "SUBMIT",
      total_score: 45,
      findings: [{
        finding_id: "F-1",
        impact: 20,
        proof_quality: 10,
        severity_accuracy: 5,
        chain_potential: 5,
        report_quality: 5,
        total_score: 45,
        feedback: null,
      }],
      feedback: null,
    }), /input_round_hashes\.balanced/);
  });
});

test("verification v2 archives previous current attempts and stale old artifacts no longer satisfy GRADE", () => {
  withTempHome(() => {
    const domain = "example.com";
    enterVerifyV2(domain);
    const context = JSON.parse(readVerificationContext({ target_domain: domain }));
    seedVerificationPipeline(domain, [v2VerificationResult("F-1")]);
    writeEvidencePacks({ target_domain: domain, packs: [evidencePack("F-1")] });

    const state = JSON.parse(fs.readFileSync(statePath(domain), "utf8"));
    writeFileAtomic(statePath(domain), `${JSON.stringify({
      ...state,
      phase: "CHAIN",
    }, null, 2)}\n`);
    const next = JSON.parse(transitionPhase({ target_domain: domain, to_phase: "VERIFY" }));

    assert.notEqual(next.verification.attempt_id, context.current_attempt_id);
    const archiveDir = path.join(verificationAttemptsDir(domain), `attempt-${context.current_attempt_id}`);
    assert.equal(fs.existsSync(path.join(archiveDir, "manifest.json")), true);
    const manifest = JSON.parse(fs.readFileSync(path.join(archiveDir, "manifest.json"), "utf8"));
    assert.equal(manifest.attempt_id, context.current_attempt_id);
    assert.equal(typeof manifest.adjudication_plan_hash, "string");
    assert.equal(Object.hasOwn(manifest, "plan_hash"), false);
    assert.ok(manifest.files["verified-final.json"]);
    assert.ok(manifest.files["evidence-packs.json"]);
    const archivedActiveManifest = JSON.parse(fs.readFileSync(path.join(archiveDir, "verification-manifest.json"), "utf8"));
    assert.equal(archivedActiveManifest.adjudication_plan_hash, manifest.adjudication_plan_hash);
    assert.equal(Object.hasOwn(archivedActiveManifest, "plan_hash"), false);

    const staleFinal = JSON.parse(readVerificationRound({ target_domain: domain, round: "final" }));
    assert.equal(staleFinal.current, false);
    assert.equal(staleFinal.stale, true);
    assert.throws(
      () => transitionPhase({ target_domain: domain, to_phase: "GRADE" }),
      /VERIFY -> GRADE blocked:/,
    );
  });
});

test("verification v2 verifies the frozen claim batch even when findings.jsonl changes after snapshot", () => {
  // Cycle C.4: the snapshot is sourced from the immutable claim-freeze.json
  // payload, so mutating findings.jsonl after the snapshot is created must
  // not change the verification target set. The freeze is the source of
  // truth; the live findings ledger is no longer re-read on every write.
  withTempHome(() => {
    const domain = "example.com";
    enterVerifyV2(domain);
    const context = JSON.parse(readVerificationContext({ target_domain: domain }));
    seedFinding(domain, { title: "Second finding", endpoint: "/second" });

    assert.doesNotThrow(() => writeVerificationRound({
      target_domain: domain,
      round: "brutalist",
      notes: null,
      verification_attempt_id: context.current_attempt_id,
      verification_snapshot_hash: context.snapshot_hash,
      round_profile: "brutalist",
      results: [v2VerificationResult("F-1")],
    }));
  });
});

test("verification v2 rejects self-corrupted snapshot artifacts before coverage use", () => {
  withTempHome(() => {
    const domain = "corrupt-snapshot.example.com";
    enterVerifyV2(domain);
    const context = JSON.parse(readVerificationContext({ target_domain: domain }));
    const snapshotPath = verificationSnapshotPath(domain);
    const snapshot = JSON.parse(fs.readFileSync(snapshotPath, "utf8"));
    writeFileAtomic(snapshotPath, `${JSON.stringify({
      ...snapshot,
      finding_ids: ["F-2"],
    }, null, 2)}\n`);

    assert.throws(() => writeVerificationRound({
      target_domain: domain,
      round: "brutalist",
      notes: null,
      verification_attempt_id: context.current_attempt_id,
      verification_snapshot_hash: context.snapshot_hash,
      round_profile: "brutalist",
      results: [v2VerificationResult("F-2")],
    }), /Current VERIFY v2 snapshot artifact hash mismatch/);
  });
});

test("verification v2 read context marks current-attempt round coverage corruption stale", () => {
  withTempHome(() => {
    const domain = "corrupt-round.example.com";
    enterVerifyV2(domain);
    const context = JSON.parse(readVerificationContext({ target_domain: domain }));
    const paths = verificationRoundPaths(domain, "brutalist");
    writeFileAtomic(paths.json, `${JSON.stringify({
      version: 2,
      target_domain: domain,
      round: "brutalist",
      verification_attempt_id: context.current_attempt_id,
      verification_snapshot_hash: context.snapshot_hash,
      round_profile: "brutalist",
      notes: null,
      results: [],
    }, null, 2)}\n`);

    const round = JSON.parse(readVerificationRound({ target_domain: domain, round: "brutalist" }));
    assert.equal(round.current, false);
    assert.equal(round.stale, true);
    assert.match(round.blocker_reason, /must cover exactly the current VERIFY snapshot finding IDs/);
    const nextContext = JSON.parse(readVerificationContext({ target_domain: domain }));
    assert.equal(nextContext.round_status.brutalist.current, false);
    assert.match(nextContext.round_status.brutalist.blocker_reason, /must cover exactly/);
  });
});

test("verification v2 snapshot ignores time-derived auth expiry booleans", () => {
  withTempHome(() => {
    const domain = "auth-expiry.example.com";
    seedSessionState(domain, { phase: "CHAIN" });
    seedFinding(domain);
    const baseNow = Date.now();
    const authPath = resolveAuthJsonPath(domain);
    writeFileAtomic(authPath, `${JSON.stringify({
      version: 2,
      profiles: {
        attacker: {
          Cookie: "sid=redacted",
          expires_at: new Date(baseNow + 1_000).toISOString(),
        },
      },
    }, null, 2)}\n`);

    const originalDateNow = Date.now;
    try {
      Date.now = () => baseNow;
      const transitioned = JSON.parse(transitionPhase({ target_domain: domain, to_phase: "VERIFY" }));
      Date.now = () => baseNow + 2_000;
      assert.doesNotThrow(() => writeVerificationRound({
        target_domain: domain,
        round: "brutalist",
        notes: null,
        verification_attempt_id: transitioned.verification.attempt_id,
        verification_snapshot_hash: transitioned.verification.snapshot_hash,
        round_profile: "brutalist",
        results: [v2VerificationResult("F-1")],
      }));
    } finally {
      Date.now = originalDateNow;
    }
  });
});

test("verification v2 validates artifact hashes and canonicalizes result ordering", () => {
  withTempHome(() => {
    const domain = "canonical-v2.example.com";
    seedSessionState(domain, { phase: "CHAIN" });
    seedFinding(domain);
    seedFinding(domain, { title: "Second finding", endpoint: "/api/second" });
    const transitioned = JSON.parse(transitionPhase({
      target_domain: domain,
      to_phase: "VERIFY",
      override_reason: "canonicalization regression test enters VERIFY without chain attempt",
    }));
    const context = {
      current_attempt_id: transitioned.verification.attempt_id,
      snapshot_hash: transitioned.verification.snapshot_hash,
    };
    const f1 = v2VerificationResult("F-1", {
      confidence_reasons: ["manual_inference", "fresh_replay_passed"],
      artifact_hashes: {
        "z-run": "b".repeat(64),
        "a-run": "a".repeat(64),
      },
    });
    const f2 = v2VerificationResult("F-2", {
      confidence_reasons: ["fresh_replay_passed"],
      artifact_hashes: {
        "http-audit:42": "c".repeat(64),
      },
    });

    writeVerificationRound({
      target_domain: domain,
      round: "brutalist",
      notes: null,
      verification_attempt_id: context.current_attempt_id,
      verification_snapshot_hash: context.snapshot_hash,
      round_profile: "brutalist",
      results: [f2, f1],
    });
    const brutalistDoc = JSON.parse(fs.readFileSync(verificationRoundPaths(domain, "brutalist").json, "utf8"));
    assert.deepEqual(brutalistDoc.results.map((result) => result.finding_id), ["F-1", "F-2"]);
    assert.deepEqual(brutalistDoc.results[0].confidence_reasons, ["fresh_replay_passed", "manual_inference"]);
    assert.deepEqual(Object.keys(brutalistDoc.results[0].artifact_hashes), ["a-run", "z-run"]);

    writeVerificationRound({
      target_domain: domain,
      round: "balanced",
      notes: null,
      verification_attempt_id: context.current_attempt_id,
      verification_snapshot_hash: context.snapshot_hash,
      round_profile: "balanced",
      results: [f2, f1],
    });
    const adjudication = JSON.parse(buildVerificationAdjudication({ target_domain: domain }));
    const finalA = JSON.parse(writeVerificationRound({
      target_domain: domain,
      round: "final",
      notes: null,
      verification_attempt_id: context.current_attempt_id,
      verification_snapshot_hash: context.snapshot_hash,
      round_profile: "final",
      adjudication_plan_hash: adjudication.adjudication_plan_hash,
      results: [f2, f1],
    }));
    const finalB = JSON.parse(writeVerificationRound({
      target_domain: domain,
      round: "final",
      notes: null,
      verification_attempt_id: context.current_attempt_id,
      verification_snapshot_hash: context.snapshot_hash,
      round_profile: "final",
      adjudication_plan_hash: adjudication.adjudication_plan_hash,
      results: [
        { ...f1, confidence_reasons: ["fresh_replay_passed", "manual_inference"], artifact_hashes: { "a-run": "a".repeat(64), "z-run": "b".repeat(64) } },
        f2,
      ],
    }));
    assert.equal(finalA.final_verification_hash, finalB.final_verification_hash);

    assert.throws(() => writeVerificationRound({
      target_domain: domain,
      round: "brutalist",
      notes: null,
      verification_attempt_id: context.current_attempt_id,
      verification_snapshot_hash: context.snapshot_hash,
      round_profile: "brutalist",
      results: [v2VerificationResult("F-1", { artifact_hashes: { bad: "A".repeat(64) } }), f2],
    }), /lower-case md5 \(32 hex\) or sha256 \(64 hex\) hash|must match pattern/);

    assert.throws(() => writeVerificationRound({
      target_domain: domain,
      round: "brutalist",
      notes: null,
      verification_attempt_id: context.current_attempt_id,
      verification_snapshot_hash: context.snapshot_hash,
      round_profile: "brutalist",
      results: [v2VerificationResult("F-1", { artifact_hashes: { "bad key": "a".repeat(64) } }), f2],
    }), /artifact_hashes key/);

    assert.throws(() => writeVerificationRound({
      target_domain: domain,
      round: "brutalist",
      notes: null,
      verification_attempt_id: context.current_attempt_id,
      verification_snapshot_hash: context.snapshot_hash,
      round_profile: "brutalist",
      results: [v2VerificationResult("F-1", {
        artifact_hashes: Object.fromEntries(Array.from({ length: 21 }, (_, index) => [`h${index}`, "a".repeat(64)])),
      }), f2],
    }), /at most 20 entries/);
  });
});

test("existing v1 verification artifacts pin VERIFY transition to v1 for the session lifetime", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "CHAIN" });
    seedFinding(domain);
    writeVerificationRound({
      target_domain: domain,
      round: "brutalist",
      notes: null,
      results: [{
        finding_id: "F-1",
        disposition: "denied",
        severity: null,
        reportable: false,
        reasoning: "Legacy v1 artifact pins this session.",
      }],
    });

    const transitioned = JSON.parse(transitionPhase({ target_domain: domain, to_phase: "VERIFY" }));
    assert.equal(transitioned.verification.schema_version, 1);
    assert.equal(JSON.parse(readSessionState({ target_domain: domain })).state.verification_schema_version, 1);
    assert.equal(fs.existsSync(verificationSnapshotPath(domain)), false);
  });
});

test("replay-capable tools require context only for verification and evidence replay purposes", async () => {
  await withTempHome(async () => {
    const domain = "example.com";
    seedSessionState(domain);
    const missingContext = await executeTool("bob_http_scan", {
      target_domain: domain,
      method: "GET",
      url: "https://example.com/",
      replay_context: { purpose: "verification_replay" },
    });
    assert.equal(missingContext.ok, false);
    assert.equal(missingContext.error.code, "INVALID_ARGUMENTS");
    assert.match(missingContext.error.message, /replay_context\.verification_attempt_id/);

    const unknownPurpose = await executeTool("bob_http_scan", {
      target_domain: domain,
      method: "GET",
      url: "not a url",
      replay_context: { purpose: "operator_probe" },
    });
    assert.equal(unknownPurpose.ok, false);
    assert.doesNotMatch(unknownPurpose.error.message, /replay_context\.verification_attempt_id/);
  });
});

test("concurrent acquire cannot observe a partial lease file", async () => {
  await withTempHome(async () => {
    const domain = "lease-partial-window.example.com";
    enterVerifyV2(domain);
    const context = JSON.parse(readVerificationContext({ target_domain: domain }));
    const replayContext = replayContextFromVerificationContext(context);
    const leasePath = replayLeaseFileFor(domain, replayContext);
    const tool = { name: "bob_http_scan" };
    const args = { target_domain: domain, replay_context: replayContext };
    const originalOpenSync = fs.openSync;
    let triggered = false;
    let secondHandlerEntered = false;
    let secondPromise = null;

    fs.openSync = function patchedOpenSync(target, flags, mode) {
      if (target === leasePath && flags === "wx" && !triggered) {
        const fd = originalOpenSync.call(fs, target, flags, mode);
        triggered = true;
        secondPromise = runWithReplaySafety(tool, args, async () => {
          secondHandlerEntered = true;
        });
        secondPromise.catch(() => {});
        return fd;
      }
      return originalOpenSync.call(fs, target, flags, mode);
    };

    try {
      assert.equal(
        await runWithReplaySafety(tool, args, async () => "first lease acquired"),
        "first lease acquired",
      );
      assert.equal(secondHandlerEntered, false);
    } finally {
      if (secondPromise) await secondPromise.catch(() => {});
      fs.openSync = originalOpenSync;
    }
    assert.equal(fs.existsSync(leasePath), false);
  });
});

test("acquire never calls openSync(wx) on the lease path", async () => {
  await withTempHome(async () => {
    const domain = "lease-open-wx-pin.example.com";
    enterVerifyV2(domain);
    const context = JSON.parse(readVerificationContext({ target_domain: domain }));
    const replayContext = replayContextFromVerificationContext(context);
    const leasePath = replayLeaseFileFor(domain, replayContext);
    const originalOpenSync = fs.openSync;
    const openWxCalls = [];

    fs.openSync = function patchedOpenSync(target, flags, mode) {
      if (target === leasePath && flags === "wx") {
        openWxCalls.push({ target, flags });
      }
      return originalOpenSync.call(fs, target, flags, mode);
    };

    try {
      assert.equal(
        await runWithReplaySafety(
          { name: "bob_http_scan" },
          { target_domain: domain, replay_context: replayContext },
          async () => "ok",
        ),
        "ok",
      );
      assert.deepEqual(openWxCalls, []);
    } finally {
      fs.openSync = originalOpenSync;
    }
  });
});

test("replayExecutionPolicy without a domain does not scan active lease directories", () => {
  const originalExistsSync = fs.existsSync;
  let touchedLeaseDir = false;
  fs.existsSync = function patchedExistsSync(target) {
    if (String(target).includes("verification-replay-leases")) {
      touchedLeaseDir = true;
    }
    return originalExistsSync.apply(fs, arguments);
  };
  try {
    const policy = replayExecutionPolicy();
    assert.ok(policy.length > 0);
    assert.ok(policy.every((pack) => Array.isArray(pack.active_leases) && pack.active_leases.length === 0));
  } finally {
    fs.existsSync = originalExistsSync;
  }
  assert.equal(touchedLeaseDir, false);
});

test("verification replay safety stays operational across findings.jsonl mutations because the snapshot is frozen", async () => {
  // Cycle C.4: the verification snapshot is derived from the immutable
  // claim-freeze artifact, so adding new findings to findings.jsonl after the
  // snapshot was taken cannot drift the replay lease state. The replay safety
  // path checks freeze integrity (claim_freeze_id + claim_freeze_hash), not a
  // live re-scan of findings.
  await withTempHome(async () => {
    const domain = "stale-replay-snapshot.example.com";
    enterVerifyV2(domain);
    const context = JSON.parse(readVerificationContext({ target_domain: domain }));
    const replayContext = replayContextFromVerificationContext(context);
    seedFinding(domain, {
      title: "Second finding changes findings.jsonl after snapshot",
      endpoint: "/api/changed-after-snapshot",
      proof_of_concept: "curl https://example.com/api/changed-after-snapshot",
      response_evidence: "{\"changed\":true}",
    });

    const result = await runWithReplaySafety(
      { name: "bob_http_scan" },
      { target_domain: domain, replay_context: replayContext },
      () => "frozen-batch-still-valid",
    );
    assert.equal(result, "frozen-batch-still-valid");
  });
});

test("verification replay policy events preserve acquired event shape and active lease count", async () => {
  await withTempHome(async () => {
    const domain = "lease-event-shape.example.com";
    enterVerifyV2(domain);
    const context = JSON.parse(readVerificationContext({ target_domain: domain }));
    const replayContext = replayContextFromVerificationContext(context);

    assert.equal(
      await runWithReplaySafety(
        { name: "bob_http_scan" },
        { target_domain: domain, replay_context: replayContext },
        async () => "ok",
      ),
      "ok",
    );

    const rows = readJsonl(pipelineEventsJsonlPath(domain));
    const event = rows.find((row) => row.type === "verification_replay_policy_applied");
    assert.ok(event);
    // Cycle D.3: pipeline events use lifecycle_state instead of legacy phase.
    assert.equal(event.lifecycle_state, "VERIFY");
    assert.equal(event.status, "lease_acquired");
    assert.equal(event.source, "bob_http_scan");
    assert.equal(event.verification_attempt_id, replayContext.verification_attempt_id);
    assert.equal(event.verification_snapshot_hash, replayContext.verification_snapshot_hash);
    assert.equal(event.capability_pack, "web");
    assert.equal(event.lease_scope, "attempt_pack");
    assert.equal(event.replay_purpose, "verification_replay");
    assert.deepEqual(event.counts, { active_leases: 1 });
  });
});

test("verification replay leases serialize same-process and expose active file leases in context", async () => {
  await withTempHome(async () => {
    const domain = "lease-same-process.example.com";
    enterVerifyV2(domain);
    const context = JSON.parse(readVerificationContext({ target_domain: domain }));
    const replayContext = replayContextFromVerificationContext(context);
    let release;
    const first = runWithReplaySafety(
      { name: "bob_http_scan" },
      { target_domain: domain, replay_context: replayContext },
      () => new Promise((resolve) => { release = resolve; }),
    );
    await flushMicrotasks();

    const leasePath = replayLeaseFileFor(domain, replayContext);
    assert.equal(fs.existsSync(leasePath), true);
    const leaseDoc = JSON.parse(fs.readFileSync(leasePath, "utf8"));
    assert.deepEqual(Object.keys(leaseDoc).sort(), [
      "acquired_at",
      "capability_pack",
      "expires_at",
      "finding_id",
      "lease_id",
      "lease_scope",
      "pid",
      "replay_purpose",
      "round",
      "target_domain",
      "tool",
      "verification_attempt_id",
      "verification_snapshot_hash",
      "version",
    ]);
    assert.doesNotMatch(JSON.stringify(leaseDoc), /url|headers|cookie|authorization|body|request/i);

    const activeContext = JSON.parse(readVerificationContext({ target_domain: domain }));
    const webPolicy = activeContext.replay_execution_policy.find((item) => item.capability_pack === "web");
    assert.equal(webPolicy.active_leases.length, 1);
    assert.equal(webPolicy.active_leases[0].tool, "bob_http_scan");

    await assert.rejects(
      () => runWithReplaySafety(
        { name: "bob_http_scan" },
        { target_domain: domain, replay_context: replayContext },
        () => "should not run",
      ),
      /Replay lease busy/,
    );

    release("ok");
    assert.equal(await first, "ok");
    assert.equal(fs.existsSync(leasePath), false);
  });
});

test("verification replay leases reject simulated cross-process locks and clean stale locks", async () => {
  await withTempHome(async () => {
    const domain = "lease-cross-process.example.com";
    enterVerifyV2(domain);
    const context = JSON.parse(readVerificationContext({ target_domain: domain }));
    const replayContext = replayContextFromVerificationContext(context);
    const leasePath = replayLeaseFileFor(domain, replayContext);
    fs.mkdirSync(path.dirname(leasePath), { recursive: true });
    const leaseId = path.basename(leasePath, ".json");
    writeFileAtomic(leasePath, `${JSON.stringify({
      version: 1,
      lease_id: leaseId,
      target_domain: domain,
      tool: "bob_http_scan",
      capability_pack: "web",
      lease_scope: "attempt_pack",
      replay_purpose: "verification_replay",
      verification_attempt_id: replayContext.verification_attempt_id,
      verification_snapshot_hash: replayContext.verification_snapshot_hash,
      round: replayContext.round,
      finding_id: replayContext.finding_id,
      acquired_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + VERIFICATION_REPLAY_LEASE_TTL_MS).toISOString(),
      pid: 999999,
    }, null, 2)}\n`);

    await assert.rejects(
      () => runWithReplaySafety(
        { name: "bob_http_scan" },
        { target_domain: domain, replay_context: replayContext },
        () => "should not run",
      ),
      /Replay lease busy/,
    );

    writeFileAtomic(leasePath, `${JSON.stringify({
      version: 1,
      lease_id: leaseId,
      target_domain: domain,
      tool: "bob_http_scan",
      capability_pack: "web",
      lease_scope: "attempt_pack",
      replay_purpose: "verification_replay",
      verification_attempt_id: replayContext.verification_attempt_id,
      verification_snapshot_hash: replayContext.verification_snapshot_hash,
      round: replayContext.round,
      finding_id: replayContext.finding_id,
      acquired_at: new Date(Date.now() - VERIFICATION_REPLAY_LEASE_TTL_MS - 1000).toISOString(),
      expires_at: new Date(Date.now() - 1000).toISOString(),
      pid: 999999,
    }, null, 2)}\n`);

    const result = await runWithReplaySafety(
      { name: "bob_http_scan" },
      { target_domain: domain, replay_context: replayContext },
      () => "fresh lease acquired",
    );
    assert.equal(result, "fresh lease acquired");
    assert.equal(fs.existsSync(leasePath), false);
  });
});

test("verification replay leases do not clean expired leases from live owners", async () => {
  await withTempHome(async () => {
    const domain = "lease-expired-live-owner.example.com";
    enterVerifyV2(domain);
    const context = JSON.parse(readVerificationContext({ target_domain: domain }));
    const replayContext = replayContextFromVerificationContext(context);
    const leasePath = replayLeaseFileFor(domain, replayContext);
    fs.mkdirSync(path.dirname(leasePath), { recursive: true });
    const leaseId = path.basename(leasePath, ".json");
    writeFileAtomic(leasePath, `${JSON.stringify({
      version: 1,
      lease_id: leaseId,
      target_domain: domain,
      tool: "bob_http_scan",
      capability_pack: "web",
      lease_scope: "attempt_pack",
      replay_purpose: "verification_replay",
      verification_attempt_id: replayContext.verification_attempt_id,
      verification_snapshot_hash: replayContext.verification_snapshot_hash,
      round: replayContext.round,
      finding_id: replayContext.finding_id,
      acquired_at: new Date(Date.now() - VERIFICATION_REPLAY_LEASE_TTL_MS - 1000).toISOString(),
      expires_at: new Date(Date.now() - 1000).toISOString(),
      pid: process.pid,
    }, null, 2)}\n`);

    let handlerEntered = false;
    await assert.rejects(
      () => runWithReplaySafety(
        { name: "bob_http_scan" },
        { target_domain: domain, replay_context: replayContext },
        () => {
          handlerEntered = true;
          return "should not run";
        },
      ),
      /Replay lease busy/,
    );
    assert.equal(handlerEntered, false);
    assert.equal(fs.existsSync(leasePath), true);
  });
});

test("externally-created empty lease is cleaned up and acquired", async () => {
  await withTempHome(async () => {
    const domain = "lease-empty-external.example.com";
    enterVerifyV2(domain);
    const context = JSON.parse(readVerificationContext({ target_domain: domain }));
    const replayContext = replayContextFromVerificationContext(context);
    const leasePath = replayLeaseFileFor(domain, replayContext);
    fs.mkdirSync(path.dirname(leasePath), { recursive: true });
    fs.writeFileSync(leasePath, "");
    const leaseId = path.basename(leasePath, ".json");
    const h = holdingHandler(leasePath);
    const wrapperPromise = runWithReplaySafety(
      { name: "bob_http_scan" },
      { target_domain: domain, replay_context: replayContext },
      h.handler,
    );

    try {
      await flushMicrotasks();
      assert.equal(h.entered(), true);
      assertCompleteReplayLeaseSnapshot(h.leaseSnapshot(), {
        lease_id: leaseId,
        target_domain: domain,
        tool: "bob_http_scan",
        capability_pack: "web",
        lease_scope: "attempt_pack",
        replay_purpose: replayContext.purpose,
        verification_attempt_id: replayContext.verification_attempt_id,
        verification_snapshot_hash: replayContext.verification_snapshot_hash,
        round: replayContext.round,
        finding_id: replayContext.finding_id,
      });
    } finally {
      h.release();
    }

    await wrapperPromise;
    assert.equal(fs.existsSync(leasePath), false);
  });
});

test("lease release does not remove a replacement lease owned by another process", async () => {
  await withTempHome(async () => {
    const domain = "lease-release-replacement.example.com";
    enterVerifyV2(domain);
    const context = JSON.parse(readVerificationContext({ target_domain: domain }));
    const replayContext = replayContextFromVerificationContext(context);
    const leasePath = replayLeaseFileFor(domain, replayContext);

    const result = await runWithReplaySafety(
      { name: "bob_http_scan" },
      { target_domain: domain, replay_context: replayContext },
      async () => {
        const replacement = {
          ...JSON.parse(fs.readFileSync(leasePath, "utf8")),
          lease_id: "replacement-lease",
          acquired_at: new Date(Date.now() + 1).toISOString(),
          expires_at: new Date(Date.now() + VERIFICATION_REPLAY_LEASE_TTL_MS).toISOString(),
          pid: 999999,
        };
        writeFileAtomic(leasePath, `${JSON.stringify(replacement, null, 2)}\n`);
        return "ok";
      },
    );

    assert.equal(result, "ok");
    assert.equal(JSON.parse(fs.readFileSync(leasePath, "utf8")).lease_id, "replacement-lease");
  });
});

test("handler exception releases the lease file", async () => {
  await withTempHome(async () => {
    const domain = "lease-handler-exception.example.com";
    enterVerifyV2(domain);
    const context = JSON.parse(readVerificationContext({ target_domain: domain }));
    const replayContext = replayContextFromVerificationContext(context);
    const leasePath = replayLeaseFileFor(domain, replayContext);

    await assert.rejects(
      () => runWithReplaySafety(
        { name: "bob_http_scan" },
        { target_domain: domain, replay_context: replayContext },
        async () => { throw new Error("boom"); },
      ),
      /boom/,
    );
    assert.equal(fs.existsSync(leasePath), false);
  });
});

test("two concurrent acquires on the new model: second wins, first rejects", async () => {
  await withTempHome(async () => {
    const domain = "lease-link-race.example.com";
    enterVerifyV2(domain);
    const context = JSON.parse(readVerificationContext({ target_domain: domain }));
    const replayContext = replayContextFromVerificationContext(context);
    const leasePath = replayLeaseFileFor(domain, replayContext);
    const leaseId = path.basename(leasePath, ".json");
    const tool = { name: "bob_http_scan" };
    const args = { target_domain: domain, replay_context: replayContext };
    const originalLinkSync = fs.linkSync;
    let triggered = false;
    let holdingHandler2 = null;
    let secondPromise = null;

    fs.linkSync = function patchedLinkSync(src, dest) {
      if (dest === leasePath && !triggered) {
        triggered = true;
        holdingHandler2 = holdingHandler(leasePath);
        secondPromise = runWithReplaySafety(tool, args, holdingHandler2.handler);
        secondPromise.catch(() => {});
      }
      return originalLinkSync.call(fs, src, dest);
    };

    try {
      const firstPromise = runWithReplaySafety(tool, args, async () => "should not run");
      assert.ok(holdingHandler2);
      assert.equal(holdingHandler2.entered(), true);
      await assert.rejects(
        firstPromise,
        (err) => {
          assert.equal(err.code, "STATE_CONFLICT");
          assert.match(err.message, /Replay lease busy/);
          return true;
        },
      );
      assertCompleteReplayLeaseSnapshot(holdingHandler2.leaseSnapshot(), {
        lease_id: leaseId,
        target_domain: domain,
        tool: "bob_http_scan",
        capability_pack: "web",
        lease_scope: "attempt_pack",
        replay_purpose: replayContext.purpose,
        verification_attempt_id: replayContext.verification_attempt_id,
        verification_snapshot_hash: replayContext.verification_snapshot_hash,
        round: replayContext.round,
        finding_id: replayContext.finding_id,
      });
    } finally {
      try {
        if (holdingHandler2) holdingHandler2.release();
        if (secondPromise) await secondPromise;
        assert.equal(fs.existsSync(leasePath), false);
      } finally {
        fs.linkSync = originalLinkSync;
      }
    }
  });
});

test("linkSync EEXIST during retry triggers stale cleanup once", async () => {
  await withTempHome(async () => {
    const domain = "lease-link-stale-retry.example.com";
    enterVerifyV2(domain);
    const context = JSON.parse(readVerificationContext({ target_domain: domain }));
    const replayContext = replayContextFromVerificationContext(context);
    const leasePath = replayLeaseFileFor(domain, replayContext);
    fs.mkdirSync(path.dirname(leasePath), { recursive: true });
    const leaseId = path.basename(leasePath, ".json");
    writeFileAtomic(leasePath, `${JSON.stringify({
      version: 1,
      lease_id: leaseId,
      target_domain: domain,
      tool: "bob_http_scan",
      capability_pack: "web",
      lease_scope: "attempt_pack",
      replay_purpose: "verification_replay",
      verification_attempt_id: replayContext.verification_attempt_id,
      verification_snapshot_hash: replayContext.verification_snapshot_hash,
      round: replayContext.round,
      finding_id: replayContext.finding_id,
      acquired_at: new Date(Date.now() - VERIFICATION_REPLAY_LEASE_TTL_MS - 1000).toISOString(),
      expires_at: new Date(Date.now() - 1000).toISOString(),
      pid: 999999,
    }, null, 2)}\n`);
    const originalLinkSync = fs.linkSync;
    let triggered = false;

    fs.linkSync = function patchedLinkSync(src, dest) {
      if (dest === leasePath && !triggered) {
        triggered = true;
        const error = new Error("EEXIST");
        error.code = "EEXIST";
        throw error;
      }
      return originalLinkSync.call(fs, src, dest);
    };

    try {
      const result = await runWithReplaySafety(
        { name: "bob_http_scan" },
        { target_domain: domain, replay_context: replayContext },
        async () => "fresh lease acquired",
      );
      assert.equal(result, "fresh lease acquired");
      assert.equal(triggered, true);
      assert.equal(fs.existsSync(leasePath), false);
    } finally {
      fs.linkSync = originalLinkSync;
    }
  });
});

test("bob_write_evidence_packs writes JSON and markdown mirror", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedFinding(domain);
    seedVerificationPipeline(domain, [{
      finding_id: "F-1",
      disposition: "confirmed",
      severity: "high",
      reportable: true,
      reasoning: "Confirmed.",
    }]);

    const result = JSON.parse(writeEvidencePacks({
      target_domain: domain,
      packs: [evidencePack("F-1")],
    }));
    const paths = evidencePackPaths(domain);

    assert.equal(result.packs_count, 1);
    assert.equal(result.representative_samples_count, 1);
    assert.equal(result.reportable_findings_covered, 1);
    assert.equal(result.written_json, paths.json);
    assert.equal(result.written_md, paths.markdown);
    const ctx = JSON.parse(readVerificationContext({ target_domain: domain }));
    const onDisk = JSON.parse(fs.readFileSync(paths.json, "utf8"));
    const finalDoc = ctx.schema_version === 2
      ? JSON.parse(fs.readFileSync(verificationRoundPaths(domain, "final").json, "utf8"))
      : null;
    const expectedShape = {
      version: 1,
      target_domain: domain,
      packs: [evidencePack("F-1")],
      ...(ctx.schema_version === 2 ? {
        verification_attempt_id: ctx.current_attempt_id,
        verification_snapshot_hash: ctx.snapshot_hash,
        final_verification_hash: finalDoc.final_verification_hash,
      } : {}),
    };
    if (ctx.schema_version === 2) {
      assert.equal(onDisk.final_verification_hash, finalDoc.final_verification_hash);
    }
    assert.deepEqual(onDisk, expectedShape);
    assert.match(fs.readFileSync(paths.markdown, "utf8"), /# Evidence Packs/);
    assert.deepEqual(JSON.parse(readEvidencePacks({ target_domain: domain })), expectedShape);

    const rows = readJsonl(pipelineEventsJsonlPath(domain));
    const evidenceEvent = rows.find((row) => row.type === "evidence_written");
    assert.ok(evidenceEvent);
    assert.deepEqual(evidenceEvent.counts, {
      packs: 1,
      representative_samples: 1,
      reportable_findings_covered: 1,
    });
  });
});

test("bob_write_evidence_packs rejects unknown and duplicate finding IDs", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedFinding(domain);
    seedVerificationPipeline(domain, [{
      finding_id: "F-1",
      disposition: "confirmed",
      severity: "high",
      reportable: true,
      reasoning: "Confirmed.",
    }]);

    assert.throws(() => writeEvidencePacks({
      target_domain: domain,
      packs: [evidencePack("F-99")],
    }), /Unknown finding_id: F-99/);

    assert.throws(() => writeEvidencePacks({
      target_domain: domain,
      packs: [evidencePack("F-1"), evidencePack("F-1")],
    }), /Duplicate finding_id in evidence packs: F-1/);
  });
});

test("bob_write_evidence_packs requires coverage for all final reportable findings", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedFinding(domain);
    seedFinding(domain, { title: "Second IDOR", endpoint: "/api/second" });
    seedVerificationPipeline(domain, [
      {
        finding_id: "F-1",
        disposition: "confirmed",
        severity: "high",
        reportable: true,
        reasoning: "Confirmed.",
      },
      {
        finding_id: "F-2",
        disposition: "confirmed",
        severity: "medium",
        reportable: true,
        reasoning: "Confirmed.",
      },
    ]);

    assert.throws(() => writeEvidencePacks({
      target_domain: domain,
      packs: [evidencePack("F-1")],
    }), /Evidence packs missing final reportable finding\(s\): F-2/);

    assert.doesNotThrow(() => writeEvidencePacks({
      target_domain: domain,
      packs: [evidencePack("F-1"), evidencePack("F-2")],
    }));
  });
});

test("bob_read_evidence_packs allows skip only when final verification has no reportable findings", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedFinding(domain);
    seedVerificationPipeline(domain, [{
      finding_id: "F-1",
      disposition: "denied",
      severity: null,
      reportable: false,
      reasoning: "Not reproducible.",
    }]);

    const skipCtx = JSON.parse(readVerificationContext({ target_domain: domain }));
    const finalDoc = skipCtx.schema_version === 2
      ? JSON.parse(fs.readFileSync(verificationRoundPaths(domain, "final").json, "utf8"))
      : null;
    assert.deepEqual(JSON.parse(readEvidencePacks({ target_domain: domain })), {
      version: 1,
      target_domain: domain,
      packs: [],
      skipped: true,
      ...(skipCtx.schema_version === 2 ? {
        verification_attempt_id: skipCtx.current_attempt_id,
        verification_snapshot_hash: skipCtx.snapshot_hash,
        final_verification_hash: finalDoc.final_verification_hash,
      } : {}),
    });
    assert.doesNotThrow(() => writeEvidencePacks({ target_domain: domain, packs: [] }));

    const reportableDomain = "reportable.example.com";
    seedFinding(reportableDomain);
    seedVerificationPipeline(reportableDomain, [{
      finding_id: "F-1",
      disposition: "confirmed",
      severity: "high",
      reportable: true,
      reasoning: "Confirmed.",
    }]);

    assert.throws(() => readEvidencePacks({ target_domain: reportableDomain }), /Missing evidence packs JSON/);
    assert.throws(() => writeEvidencePacks({ target_domain: reportableDomain, packs: [] }), /Evidence packs missing final reportable finding\(s\): F-1/);
  });
});

test("bob_write_grade_verdict writes grade.json and grade.md and accepts empty findings", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedFinding(domain);
    seedVerificationPipeline(domain, [{
      finding_id: "F-1",
      disposition: "denied",
      severity: null,
      reportable: false,
      reasoning: "Not reproducible.",
    }]);

    const result = JSON.parse(writeGradeVerdict({
      target_domain: domain,
      verdict: "SKIP",
      total_score: 0,
      findings: [],
      feedback: null,
    }));
    const paths = gradeArtifactPaths(domain);

    assert.equal(result.verdict, "SKIP");
    assert.equal(result.findings_count, 0);
    assert.equal(result.written_json, paths.json);
    assert.equal(result.written_md, paths.markdown);
    // Cycle C.6: grade verdicts carry claim_freeze_id when a freeze exists.
    // The v2 seedVerificationPipeline path auto-freezes when entering VERIFY,
    // so a non-null id is expected here.
    const persisted = JSON.parse(fs.readFileSync(paths.json, "utf8"));
    const expectedFreezeId = persisted.claim_freeze_id;
    assert.equal(typeof expectedFreezeId, "string");
    assert.match(expectedFreezeId, /^CF-/);
    assert.deepEqual(persisted, {
      version: 1,
      target_domain: domain,
      verdict: "SKIP",
      total_score: 0,
      findings: [],
      feedback: null,
      claim_freeze_id: expectedFreezeId,
    });
    assert.match(fs.readFileSync(paths.markdown, "utf8"), /No graded findings\./);

    assert.deepEqual(JSON.parse(readGradeVerdict({ target_domain: domain })), {
      version: 1,
      target_domain: domain,
      verdict: "SKIP",
      total_score: 0,
      findings: [],
      feedback: null,
      claim_freeze_id: expectedFreezeId,
    });
  });
});

test("bob_write_grade_verdict requires valid final verification before grading", async () => {
  await withTempHome(async () => {
    const domain = "example.com";
    seedSessionState(domain);
    seedFinding(domain);

    const result = await executeTool("bob_write_grade_verdict", {
      target_domain: domain,
      verdict: "SKIP",
      total_score: 0,
      findings: [],
      feedback: "No graded findings.",
    });

    assert.equal(result.ok, false);
    assert.equal(result.error.code, "STATE_CONFLICT");
    assert.match(result.error.message, /Final verification must exist and be valid before grading/);
    assert.match(result.error.message, /Missing final verification round JSON/);

    const finalPaths = verificationRoundPaths(domain, "final");
    fs.mkdirSync(path.dirname(finalPaths.json), { recursive: true });
    fs.writeFileSync(finalPaths.json, "{bad json");
    const malformed = await executeTool("bob_write_grade_verdict", {
      target_domain: domain,
      verdict: "SKIP",
      total_score: 0,
      findings: [],
      feedback: "No graded findings.",
    });
    assert.equal(malformed.ok, false);
    assert.equal(malformed.error.code, "STATE_CONFLICT");
    assert.match(malformed.error.message, /Malformed final verification round JSON/);
  });
});

test("bob_write_grade_verdict enforces score totals, thresholds, and final reportability", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedFinding(domain, { severity: "high" });
    const verified = [{
      finding_id: "F-1",
      disposition: "confirmed",
      severity: "high",
      reportable: true,
      reasoning: "Confirmed.",
    }];
    seedVerificationPipeline(domain, verified);
    JSON.parse(writeEvidencePacks({ target_domain: domain, packs: [evidencePack("F-1")] }));

    const gradeFinding = {
      finding_id: "F-1",
      impact: 20,
      proof_quality: 10,
      severity_accuracy: 5,
      chain_potential: 5,
      report_quality: 5,
      total_score: 45,
      feedback: null,
    };

    const valid = JSON.parse(writeGradeVerdict({
      target_domain: domain,
      verdict: "SUBMIT",
      total_score: 45,
      findings: [gradeFinding],
      feedback: null,
    }));
    assert.equal(valid.verdict, "SUBMIT");

    assert.throws(() => writeGradeVerdict({
      target_domain: domain,
      verdict: "SUBMIT",
      total_score: 44,
      findings: [gradeFinding],
      feedback: null,
    }), /total_score must equal the maximum per-finding score/);

    assert.throws(() => writeGradeVerdict({
      target_domain: domain,
      verdict: "HOLD",
      total_score: 45,
      findings: [gradeFinding],
      feedback: null,
    }), /expected SUBMIT/);
  });
});

test("bob_write_grade_verdict requires evidence packs for final reportables before writing", () => {
  withTempHome(() => {
    const domain = "grade-evidence-required.example.com";
    seedFinding(domain, { severity: "high" });
    seedVerificationPipeline(domain, [{
      finding_id: "F-1",
      disposition: "confirmed",
      severity: "high",
      reportable: true,
      reasoning: "Confirmed.",
    }]);

    assert.throws(() => writeGradeVerdict({
      target_domain: domain,
      verdict: "SUBMIT",
      total_score: 45,
      findings: [{
        finding_id: "F-1",
        impact: 20,
        proof_quality: 10,
        severity_accuracy: 5,
        chain_potential: 5,
        report_quality: 5,
        total_score: 45,
        feedback: null,
      }],
      feedback: null,
    }), /Evidence packs.*Missing evidence packs JSON/);

    assert.throws(() => writeGradeVerdict({
      target_domain: domain,
      verdict: "HOLD",
      total_score: 25,
      findings: [{
        finding_id: "F-1",
        impact: 10,
        proof_quality: 5,
        severity_accuracy: 5,
        chain_potential: 0,
        report_quality: 5,
        total_score: 25,
        feedback: null,
      }],
      feedback: "Evidence collection did not run.",
    }), /Evidence packs.*Missing evidence packs JSON/);
  });
});

test("bob_write_grade_verdict permits only SKIP when final verification has no medium-or-higher reportable finding", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedFinding(domain, { severity: "high" });
    const unreportable = [{
      finding_id: "F-1",
      disposition: "denied",
      severity: null,
      reportable: false,
      reasoning: "Not reproducible.",
    }];
    seedVerificationPipeline(domain, unreportable);

    const gradeFinding = {
      finding_id: "F-1",
      impact: 20,
      proof_quality: 10,
      severity_accuracy: 5,
      chain_potential: 5,
      report_quality: 5,
      total_score: 45,
      feedback: null,
    };

    const skipped = JSON.parse(writeGradeVerdict({
      target_domain: domain,
      verdict: "SKIP",
      total_score: 45,
      findings: [gradeFinding],
      feedback: "No reportable medium-or-higher finding survived final verification.",
    }));
    assert.equal(skipped.verdict, "SKIP");

    assert.throws(() => writeGradeVerdict({
      target_domain: domain,
      verdict: "SUBMIT",
      total_score: 45,
      findings: [gradeFinding],
      feedback: null,
    }), /expected SKIP/);

    assert.throws(() => writeGradeVerdict({
      target_domain: domain,
      verdict: "HOLD",
      total_score: 45,
      findings: [gradeFinding],
      feedback: null,
    }), /expected SKIP/);
  });
});

test("bob_write_grade_verdict rejects duplicate or unknown finding_ids", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedFinding(domain);

    assert.throws(() => writeGradeVerdict({
      target_domain: domain,
      verdict: "HOLD",
      total_score: 80,
      findings: [
        {
          finding_id: "F-1",
          impact: 20,
          proof_quality: 20,
          severity_accuracy: 15,
          chain_potential: 10,
          report_quality: 15,
          total_score: 80,
          feedback: null,
        },
        {
          finding_id: "F-1",
          impact: 10,
          proof_quality: 10,
          severity_accuracy: 10,
          chain_potential: 10,
          report_quality: 10,
          total_score: 50,
          feedback: "duplicate",
        },
      ],
      feedback: "Need stronger chain.",
    }), /Duplicate finding_id in findings: F-1/);

    assert.throws(() => writeGradeVerdict({
      target_domain: domain,
      verdict: "SUBMIT",
      total_score: 80,
      findings: [
        {
          finding_id: "F-99",
          impact: 20,
          proof_quality: 20,
          severity_accuracy: 15,
          chain_potential: 10,
          report_quality: 15,
          total_score: 80,
          feedback: null,
        },
      ],
      feedback: null,
    }), /Unknown finding_id: F-99/);
  });
});

test("dispatch validator accepts explicit null for required+nullable fields", async () => {
  await withTempHome(async () => {
    const domain = "example.com";
    seedFinding(domain);
    seedVerificationPipeline(domain, [{
      finding_id: "F-1",
      disposition: "confirmed",
      severity: "high",
      reportable: true,
      reasoning: "Confirmed.",
    }]);

    const round = await executeTool("bob_write_verification_round", {
      target_domain: domain,
      round: "brutalist",
      notes: null,
      results: [{
        finding_id: "F-1",
        disposition: "confirmed",
        severity: "high",
        reportable: true,
        reasoning: "Confirmed.",
      }],
    });
    assert.ok(!round.error || !/notes is required/.test(round.error.message || ""),
      `bob_write_verification_round rejected notes:null at dispatch: ${round.error && round.error.message}`);

    const pack = await executeTool("bob_write_evidence_packs", {
      target_domain: domain,
      packs: [{ ...evidencePack("F-1"), redaction_notes: null }],
    });
    assert.ok(!pack.error || !/redaction_notes is required/.test(pack.error.message || ""),
      `bob_write_evidence_packs rejected redaction_notes:null at dispatch: ${pack.error && pack.error.message}`);

    const verdict = await executeTool("bob_write_grade_verdict", {
      target_domain: domain,
      verdict: "SKIP",
      total_score: 0,
      findings: [{
        finding_id: "F-1",
        severity: "high",
        reportable_input: true,
        reportable_final: false,
        impact: 0,
        novelty: 0,
        chain_potential: 0,
        report_quality: 0,
        total_score: 0,
        feedback: null,
      }],
      feedback: null,
    });
    assert.ok(!verdict.error || !/feedback is required/.test(verdict.error.message || ""),
      `bob_write_grade_verdict rejected feedback:null at dispatch: ${verdict.error && verdict.error.message}`);
  });
});

test("bob_read_grade_verdict hard-fails on missing or malformed JSON", () => {
  withTempHome(() => {
    const domain = "example.com";
    const paths = gradeArtifactPaths(domain);

    assert.throws(
      () => readGradeVerdict({ target_domain: domain }),
      /Missing grade verdict JSON/,
    );

    fs.mkdirSync(path.dirname(paths.json), { recursive: true });
    fs.writeFileSync(paths.json, "{bad json");

    assert.throws(
      () => readGradeVerdict({ target_domain: domain }),
      /Malformed grade verdict JSON/,
    );
  });
});

test("bob_read_grade_verdict rejects grade artifacts when final verification is missing", async () => {
  await withTempHome(async () => {
    const domain = "example.com";
    seedSessionState(domain);
    seedFinding(domain);
    const paths = gradeArtifactPaths(domain);
    fs.mkdirSync(path.dirname(paths.json), { recursive: true });
    fs.writeFileSync(paths.json, `${JSON.stringify({
      version: 1,
      target_domain: domain,
      verdict: "SKIP",
      total_score: 0,
      findings: [],
      feedback: null,
    }, null, 2)}\n`);

    const result = await executeTool("bob_read_grade_verdict", { target_domain: domain });
    assert.equal(result.ok, false);
    assert.equal(result.error.code, "STATE_CONFLICT");
    assert.match(result.error.message, /Final verification must exist and be valid before grading/);
  });
});

test("bob_read_grade_verdict rejects JSON that references non-existent findings", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedFinding(domain);

    const paths = gradeArtifactPaths(domain);
    fs.mkdirSync(path.dirname(paths.json), { recursive: true });
    fs.writeFileSync(paths.json, `${JSON.stringify({
      version: 1,
      target_domain: domain,
      verdict: "HOLD",
      total_score: 10,
      findings: [
        {
          finding_id: "F-99",
          impact: 2,
          proof_quality: 2,
          severity_accuracy: 2,
          chain_potential: 2,
          report_quality: 2,
          total_score: 10,
          feedback: null,
        },
      ],
      feedback: "Bad manual edit.",
    }, null, 2)}\n`);

    assert.throws(
      () => readGradeVerdict({ target_domain: domain }),
      /Unknown finding_id: F-99/,
    );
  });
});

// ── bob_auth_store tests ──

test("bob_auth_store writes v2 auth.json with attacker profile", async () => {
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-test-"));
  const previousHome = process.env.HOME;
  process.env.HOME = tempHome;
  try {
    const sessionsDir = path.join(tempHome, "hacker-bob-sessions");
    fs.mkdirSync(path.join(sessionsDir, "target.com"), { recursive: true });
    seedSessionState("target.com");

    const result = await executeTool("bob_auth_store", {
      target_domain: "target.com",
      profile_name: "attacker",
      headers: { "Authorization": "Bearer atok" },
      cookies: { "session": "abc123" },
    });

    assert.equal(result.ok, true);
    assert.equal(result.data.success, true);
    assert.equal(result.data.profile_name, "attacker");
    assert.equal(result.data.has_attacker, true);
    assert.equal(result.data.has_victim, false);

    const saved = JSON.parse(fs.readFileSync(path.join(sessionsDir, "target.com", "auth.json"), "utf8"));
    assert.equal(saved.version, 2);
    assert.ok(saved.profiles.attacker);
    assert.equal(saved.profiles.attacker.Authorization, "Bearer atok");
    assert.equal(saved.profiles.attacker.Cookie, "session=abc123");
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("bob_auth_store adds victim profile to existing v2 auth.json", async () => {
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-test-"));
  const previousHome = process.env.HOME;
  process.env.HOME = tempHome;
  try {
    const sessionsDir = path.join(tempHome, "hacker-bob-sessions");
    const targetDir = path.join(sessionsDir, "target.com");
    fs.mkdirSync(targetDir, { recursive: true });
    seedSessionState("target.com");

    // Write attacker first
    await executeTool("bob_auth_store", {
      target_domain: "target.com",
      profile_name: "attacker",
      headers: { "Authorization": "Bearer atok" },
    });

    // Now add victim
    const result = await executeTool("bob_auth_store", {
      target_domain: "target.com",
      profile_name: "victim",
      headers: { "Authorization": "Bearer vtok" },
    });

    assert.equal(result.ok, true);
    assert.equal(result.data.success, true);
    assert.equal(result.data.has_attacker, true);
    assert.equal(result.data.has_victim, true);

    const saved = JSON.parse(fs.readFileSync(path.join(targetDir, "auth.json"), "utf8"));
    assert.equal(saved.version, 2);
    assert.equal(saved.profiles.attacker.Authorization, "Bearer atok");
    assert.equal(saved.profiles.victim.Authorization, "Bearer vtok");
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("bob_auth_store accepts arbitrary profile names without clobbering existing profiles", async () => {
  await withTempHome(async () => {
    seedSessionState("target.com");
    await executeTool("bob_auth_store", {
      target_domain: "target.com",
      profile_name: "attacker",
      headers: { Authorization: "Bearer attacker" },
    });
    await executeTool("bob_auth_store", {
      target_domain: "target.com",
      profile_name: "tenant_b",
      headers: { Authorization: "Bearer tenant-b" },
    });

    const saved = JSON.parse(fs.readFileSync(path.join(sessionDir("target.com"), "auth.json"), "utf8"));
    assert.equal(saved.profiles.attacker.Authorization, "Bearer attacker");
    assert.equal(saved.profiles.tenant_b.Authorization, "Bearer tenant-b");
    assert.deepEqual(Object.keys(saved.profiles).sort(), ["attacker", "tenant_b"]);
  });
});

test("bob_auth_store migrates legacy auth.json", async () => {
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-test-"));
  const previousHome = process.env.HOME;
  process.env.HOME = tempHome;
  try {
    const sessionsDir = path.join(tempHome, "hacker-bob-sessions");
    const targetDir = path.join(sessionsDir, "target.com");
    fs.mkdirSync(targetDir, { recursive: true });
    seedSessionState("target.com");

    // Write legacy format (flat object, no version)
    fs.writeFileSync(path.join(targetDir, "auth.json"), JSON.stringify({
      Authorization: "Bearer legacy",
      Cookie: "old=val",
    }));

    // Add victim — should migrate legacy to attacker and add victim
    const result = await executeTool("bob_auth_store", {
      target_domain: "target.com",
      profile_name: "victim",
      headers: { "Authorization": "Bearer vtok" },
    });

    assert.equal(result.ok, true);
    assert.equal(result.data.success, true);
    assert.equal(result.data.has_attacker, true);
    assert.equal(result.data.has_victim, true);

    const saved = JSON.parse(fs.readFileSync(path.join(targetDir, "auth.json"), "utf8"));
    assert.equal(saved.version, 2);
    assert.equal(saved.profiles.attacker.Authorization, "Bearer legacy");
    assert.equal(saved.profiles.victim.Authorization, "Bearer vtok");
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("bob_auth_store stores credentials alongside headers", async () => {
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-test-"));
  const previousHome = process.env.HOME;
  process.env.HOME = tempHome;
  try {
    const sessionsDir = path.join(tempHome, "hacker-bob-sessions");
    fs.mkdirSync(path.join(sessionsDir, "target.com"), { recursive: true });
    seedSessionState("target.com");

    await executeTool("bob_auth_store", {
      target_domain: "target.com",
      profile_name: "attacker",
      headers: { "Authorization": "Bearer t" },
      credentials: { email: "test@mail.tm", password: "secret123" },
    });

    const saved = JSON.parse(fs.readFileSync(path.join(sessionsDir, "target.com", "auth.json"), "utf8"));
    assert.equal(saved.profiles.attacker.credentials.email, "test@mail.tm");
    assert.equal(saved.profiles.attacker.credentials.password, "secret123");
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("bob_auth_store writes and migrates auth.json with 0600 permissions", async () => {
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-test-"));
  const previousHome = process.env.HOME;
  process.env.HOME = tempHome;
  try {
    const targetDir = path.join(tempHome, "hacker-bob-sessions", "target.com");
    const authPath = path.join(targetDir, "auth.json");
    fs.mkdirSync(targetDir, { recursive: true });
    seedSessionState("target.com");

    await executeTool("bob_auth_store", {
      target_domain: "target.com",
      profile_name: "attacker",
      cookies: { sessionid: "abc" },
    });
    assert.equal(fs.statSync(authPath).mode & 0o777, 0o600);

    fs.writeFileSync(authPath, JSON.stringify({ Authorization: "Bearer legacy" }), { mode: 0o644 });
    await executeTool("bob_auth_store", {
      target_domain: "target.com",
      profile_name: "victim",
      headers: { Authorization: "Bearer victim" },
    });
    assert.equal(fs.statSync(authPath).mode & 0o777, 0o600);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("bob_auth_store reports persistence failures instead of claiming success", async () => {
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-test-"));
  const previousHome = process.env.HOME;
  process.env.HOME = tempHome;
  try {
    const authPath = path.join(tempHome, "hacker-bob-sessions", "target.com", "auth.json");
    seedSessionState("target.com");
    fs.mkdirSync(authPath, { recursive: true });

    const envelope = await executeTool("bob_auth_store", {
      target_domain: "target.com",
      profile_name: "attacker",
      headers: { "Authorization": "Bearer atok" },
    });

    assert.equal(envelope.ok, false);
    assert.equal(envelope.error.code, "INTERNAL_ERROR");
    assert.equal(envelope.error.details.auth_path, authPath);
    assert.equal(envelope.error.details.success, false);
    assert.match(envelope.error.message, /failed to persist auth profile/i);
    assert.equal(envelope.error.details.auth_path, authPath);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("bob_auth_store preserves concurrent attacker and victim profile writes", async () => {
  await withTempHome(async () => {
    seedSessionState("target.com");
    await Promise.all([
      executeTool("bob_auth_store", {
        target_domain: "target.com",
        profile_name: "attacker",
        headers: { Authorization: "Bearer attacker" },
      }),
      executeTool("bob_auth_store", {
        target_domain: "target.com",
        profile_name: "victim",
        headers: { Authorization: "Bearer victim" },
      }),
    ]);

    const saved = JSON.parse(fs.readFileSync(path.join(sessionDir("target.com"), "auth.json"), "utf8"));
    assert.equal(saved.profiles.attacker.Authorization, "Bearer attacker");
    assert.equal(saved.profiles.victim.Authorization, "Bearer victim");
  });
});

test("bob_list_auth_profiles redacts secrets while reporting profile status", async () => {
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-test-"));
  const previousHome = process.env.HOME;
  process.env.HOME = tempHome;
  try {
    seedSessionState("target.com");
    await executeTool("bob_auth_store", {
      target_domain: "target.com",
      profile_name: "attacker",
      headers: { "Authorization": "Bearer secret-token" },
      cookies: { sessionid: "cookie-secret" },
      credentials: { email: "attacker@example.com", password: "password-secret" },
    });

    const result = JSON.parse(listAuthProfiles({ target_domain: "target.com" }));
    assert.equal(result.has_attacker, true);
    assert.equal(result.profiles[0].profile_name, "attacker");
    assert.deepEqual(result.profiles[0].header_keys.sort(), ["Authorization", "Cookie"].sort());
    assert.deepEqual(result.profiles[0].cookie_names, ["sessionid"]);
    assert.equal(result.profiles[0].has_credentials, true);
    assert.deepEqual(result.profiles[0].credential_fields.sort(), ["email", "password"].sort());
    assert.doesNotMatch(JSON.stringify(result), /secret-token|cookie-secret|password-secret|attacker@example\.com/);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

test("candidateAuthDomains binds auth lookup to the request host", () => {
  assert.deepEqual(
    candidateAuthDomains("target.com", "https://api.target.com/private"),
    ["target.com"],
  );
  assert.deepEqual(
    candidateAuthDomains("api.target.com", "https://api.target.com/private"),
    ["api.target.com"],
  );
  assert.deepEqual(
    candidateAuthDomains("api.target.com", "https://target.com/private"),
    [],
  );
  assert.deepEqual(
    candidateAuthDomains("target.com", "https://api.other.com/private"),
    [],
  );
  assert.deepEqual(
    candidateAuthDomains("Target.COM.", "https://API.Target.COM./private"),
    ["target.com"],
  );
  assert.deepEqual(
    candidateAuthDomains("target.com", null),
    ["target.com"],
  );
});

test("bob_http_scan resolves auth by explicit target_domain and first-party subdomain only", async () => {
  await withTempHome(async () => {
    seedSessionState("target.com");
    seedSessionState("missing.com");
    await executeTool("bob_auth_store", {
      target_domain: "target.com",
      profile_name: "attacker",
      headers: { Authorization: "Bearer target-token" },
    });
    await executeTool("bob_auth_store", {
      target_domain: "other.com",
      profile_name: "attacker",
      headers: { Authorization: "Bearer other-token" },
    });
    const listed = JSON.parse(listAuthProfiles({ target_domain: "api.target.com" }));
    assert.equal(listed.has_attacker, false);

    await withMockSafeFetch((url, requestOptions) => ({
      status: requestOptions.headers.Authorization === "Bearer target-token" ? 200 : 401,
      body: "ok",
    }), async (requestedUrls) => {
      const allowed = await executeTool("bob_http_scan", {
        target_domain: "target.com",
        method: "GET",
        url: "https://api.target.com/private",
        auth_profile: "attacker",
        response_mode: "status_only",
      });
      assert.equal(allowed.ok, true);
      assert.equal(allowed.data.status, 200);

      const blocked = await executeTool("bob_http_scan", {
        target_domain: "missing.com",
        method: "GET",
        url: "https://api.missing.com/private",
        auth_profile: "attacker",
        response_mode: "status_only",
      });
      assert.equal(blocked.ok, false);
      assert.equal(blocked.error.code, "AUTH_MISSING");
      assert.match(blocked.error.message, /auth_profile "attacker" requested but not found/);

      const crossHost = await executeTool("bob_http_scan", {
        target_domain: "target.com",
        method: "GET",
        url: "https://api.other.com/private",
        auth_profile: "attacker",
        response_mode: "status_only",
      });
      assert.equal(crossHost.ok, false);
      assert.equal(crossHost.error.code, "SCOPE_BLOCKED");
      assert.match(crossHost.error.message, /outside target_domain target\.com/);
      assert.deepEqual(requestedUrls, ["https://api.target.com/private"]);
    });
  });
});

test("bob_evm_call resolves the latest block via eth_blockNumber and returns block_used", async () => {
  let callCount = 0;
  await withMockSmartContractHttpRequest(async (_url, request) => {
    callCount += 1;
    const body = JSON.parse(request.body);
    if (body.method === "eth_call") {
      return {
        ok: true,
        status: 200,
        headers: { "content-type": "application/json" },
        text: JSON.stringify({ jsonrpc: "2.0", id: body.id, result: "0x" + "00".repeat(31) + "01" }),
      };
    }
    if (body.method === "eth_blockNumber") {
      // Return decimal 19_500_000 in hex
      return {
        ok: true,
        status: 200,
        headers: { "content-type": "application/json" },
        text: JSON.stringify({ jsonrpc: "2.0", id: body.id, result: "0x129a8c0" }),
      };
    }
    return { ok: false, status: 500, text: "" };
  }, async () => {
    const result = await withMockSmartContractRpcLookup({
      "eth.llamarpc.com": [{ address: "93.184.216.34", family: 4 }],
    }, () => executeTool("bob_evm_call", {
      chain_id: 1,
      to: "0x" + "11".repeat(20),
      data: "0x70a08231" + "00".repeat(32),
      endpoints: ["https://eth.llamarpc.com"],
    }));
    assert.equal(result.ok, true);
    assert.equal(result.data.block, "latest");
    // Hex 0x129a8c0 = 19_507_392
    assert.equal(result.data.block_used, 19_507_392);
    assert.ok(callCount >= 2, "expected at least one eth_call and one eth_blockNumber");
  });
});

// ── bob_temp_email tests ──

test("bob_temp_email create returns email with mocked mail.tm", async () => {
  const originalFetch = global.fetch;
  try {
    global.fetch = async (url, opts) => {
      if (url.includes("mail.tm/domains")) {
        return { ok: true, json: async () => ({ "hydra:member": [{ domain: "test.tm" }] }) };
      }
      if (url.includes("mail.tm/accounts")) {
        return { ok: true, status: 201, json: async () => ({ id: "abc", address: "x@test.tm" }) };
      }
      if (url.includes("mail.tm/token")) {
        return { ok: true, json: async () => ({ token: "jwt123" }) };
      }
      return { ok: false, status: 500 };
    };

    const result = await executeTool("bob_temp_email", { operation: "create" });
    assert.equal(result.ok, true);
    assert.equal(result.data.success, true);
    assert.ok(result.data.email_address.endsWith("@test.tm"));
    assert.equal(result.data.provider, "mail.tm");
    assert.ok(result.data.password.length > 0);
  } finally {
    global.fetch = originalFetch;
  }
});

test("bob_temp_email create falls back to guerrillamail on mail.tm failure", async () => {
  const originalFetch = global.fetch;
  try {
    global.fetch = async (url) => {
      if (url.includes("mail.tm")) {
        return { ok: false, status: 500, text: async () => "Service Unavailable" };
      }
      if (url.includes("guerrillamail") && url.includes("get_email_address")) {
        return { ok: true, json: async () => ({ email_addr: "test_user@guerrillamail.com", sid_token: "sid123" }) };
      }
      return { ok: false, status: 500, text: async () => "" };
    };

    const result = await executeTool("bob_temp_email", { operation: "create" });
    assert.equal(result.ok, true);
    assert.equal(result.data.success, true);
    assert.equal(result.data.email_address, "test_user@guerrillamail.com");
    assert.equal(result.data.provider, "guerrillamail");
  } finally {
    global.fetch = originalFetch;
  }
});

test("bob_temp_email create returns error when all providers fail", async () => {
  const originalFetch = global.fetch;
  try {
    global.fetch = async () => ({ ok: false, status: 500, text: async () => "Internal Server Error" });

    const result = await executeTool("bob_temp_email", { operation: "create" });
    assert.equal(result.ok, false);
    assert.equal(result.error.code, "INTERNAL_ERROR");
    assert.equal(result.error.details.success, false);
    assert.ok(result.error.details.providers_tried.length > 0);
  } finally {
    global.fetch = originalFetch;
  }
});

test("bob_temp_email poll returns messages with mocked mail.tm", async () => {
  const originalFetch = global.fetch;
  try {
    // First create a mailbox to populate tempMailboxes
    global.fetch = async (url) => {
      if (url.includes("mail.tm/domains")) {
        return { ok: true, json: async () => ({ "hydra:member": [{ domain: "test.tm" }] }) };
      }
      if (url.includes("mail.tm/accounts")) {
        return { ok: true, status: 201, json: async () => ({ id: "abc" }) };
      }
      if (url.includes("mail.tm/token")) {
        return { ok: true, json: async () => ({ token: "jwt123" }) };
      }
      if (url.includes("mail.tm/messages") && !url.includes("/messages/")) {
        return {
          ok: true,
          json: async () => ({
            "hydra:member": [
              { id: "msg1", from: { address: "noreply@target.com" }, subject: "Verify your email", createdAt: "2026-01-01" },
            ],
          }),
        };
      }
      return { ok: false, status: 500 };
    };

    const createResult = await executeTool("bob_temp_email", { operation: "create" });
    assert.equal(createResult.ok, true);
    const pollResult = await executeTool("bob_temp_email", {
      operation: "poll",
      email_address: createResult.data.email_address,
    });

    assert.equal(pollResult.ok, true);
    assert.equal(pollResult.data.success, true);
    assert.equal(pollResult.data.messages.length, 1);
    assert.equal(pollResult.data.messages[0].from, "noreply@target.com");
  } finally {
    global.fetch = originalFetch;
  }
});

test("bob_temp_email extract finds codes and links", async () => {
  const originalFetch = global.fetch;
  try {
    // Create mailbox first
    global.fetch = async (url) => {
      if (url.includes("mail.tm/domains")) {
        return { ok: true, json: async () => ({ "hydra:member": [{ domain: "test.tm" }] }) };
      }
      if (url.includes("mail.tm/accounts")) {
        return { ok: true, status: 201, json: async () => ({ id: "abc" }) };
      }
      if (url.includes("mail.tm/token")) {
        return { ok: true, json: async () => ({ token: "jwt123" }) };
      }
      if (url.includes("mail.tm/messages/msg1")) {
        return {
          ok: true,
          json: async () => ({
            text: "Your verification code is 847291. Or click https://target.com/verify?token=abc123 to confirm.",
          }),
        };
      }
      return { ok: false, status: 500 };
    };

    const createResult = await executeTool("bob_temp_email", { operation: "create" });
    assert.equal(createResult.ok, true);
    const extractResult = await executeTool("bob_temp_email", {
      operation: "extract",
      email_address: createResult.data.email_address,
      message_id: "msg1",
    });

    assert.equal(extractResult.ok, true);
    assert.equal(extractResult.data.success, true);
    assert.ok(extractResult.data.verification_codes.includes("847291"));
    assert.ok(extractResult.data.verification_links.some((l) => l.includes("target.com/verify")));
  } finally {
    global.fetch = originalFetch;
  }
});

test("bob_temp_email poll for unknown email returns error", async () => {
  const result = await executeTool("bob_temp_email", {
    operation: "poll",
    email_address: "nonexistent@nowhere.com",
  });
  assert.equal(result.ok, false);
  assert.equal(result.error.code, "INTERNAL_ERROR");
  assert.ok(result.error.message.includes("Unknown email"));
});

test("auto-signup result normalization fails ambiguous states and preserves diagnostics", () => {
  const signupUrl = "https://example.com/signup/";
  const ambiguous = normalizeAutoSignupResult({
    success: true,
    submitted: true,
    redirect_url: "https://example.com/signup#done",
    page_errors: [],
    filled_fields: { email: true, password: true },
    cookies: { theme: "light" },
    headers: {},
    local_storage: {},
    session_storage: {},
  }, signupUrl);

  assert.equal(ambiguous.success, false);
  assert.equal(ambiguous.fallback, "manual");
  assert.equal(ambiguous.diagnostics.submitted, true);
  assert.deepEqual(ambiguous.auth_evidence.cookie_keys, []);

  const successful = normalizeAutoSignupResult({
    success: true,
    submitted: true,
    redirect_url: "https://example.com/dashboard",
    page_errors: [],
    filled_fields: { email: true, password: true },
    cookies: { sessionid: "abc" },
    headers: {},
    local_storage: {},
    session_storage: {},
  }, signupUrl);
  assert.equal(successful.success, true);
  assert.deepEqual(successful.auth_evidence.cookie_keys, ["sessionid"]);
});

test("bob_auto_signup returns ok true manual fallback when browser automation is unavailable", async () => {
  await withTempHome(async () => {
    seedSessionState("example.com");
    const originalResolve = Module._resolveFilename;
    Module._resolveFilename = function patchedResolve(request, parent, isMain, options) {
      if (request === "patchright") {
        throw new Error("Cannot find module 'patchright'");
      }
      return originalResolve.call(this, request, parent, isMain, options);
    };
    try {
      const result = await executeTool("bob_auto_signup", {
        target_domain: "example.com",
        signup_url: "https://example.com/signup",
        email: "a@example.test",
        password: "Password123!",
      });

      assert.equal(result.ok, true);
      assert.equal(result.data.success, false);
      assert.equal(result.data.fallback, "manual");
      assert.equal(result.data.reason, "patchright_unavailable");
      assert.match(result.data.message, /Patchright is not installed/);
      assert.equal(Object.prototype.hasOwnProperty.call(result.data, "error"), false);
    } finally {
      Module._resolveFilename = originalResolve;
    }
  });
});

test("bob_auto_signup rejects raw proxy arguments and uses egress profiles only", async () => {
  await withTempHome(async () => {
    seedSessionState("example.com");
    const rawProxySecret = ["browser", "proxy", "secret"].join("-");
    const rawProxy = ["http://user:", rawProxySecret, "@proxy.example:8080"].join("");
    const rejected = await executeTool("bob_auto_signup", {
      target_domain: "example.com",
      signup_url: "https://example.com/signup",
      email: "a@example.test",
      password: "Password123!",
      proxy: rawProxy,
    });

    assert.equal(rejected.ok, false);
    assert.equal(rejected.error.code, "INVALID_ARGUMENTS");
    assert.doesNotMatch(JSON.stringify(rejected), new RegExp(rawProxySecret));

    const document = {
      version: 1,
      profiles: [
        egressProfiles.defaultEgressProfile(),
        {
          name: "browser-eu",
          proxy_url: "${BOB_EGRESS_BROWSER_PROXY}",
          region: "EU",
          description: "Browser automation proxy",
          enabled: true,
        },
      ],
    };

    await withDefaultEgressConfig(document, async () => {
      await withEnv({ BOB_EGRESS_BROWSER_PROXY: rawProxy }, async () => {
        const originalResolve = Module._resolveFilename;
        Module._resolveFilename = function patchedResolve(request, parent, isMain, options) {
          if (request === "patchright") {
            throw new Error("Cannot find module 'patchright'");
          }
          return originalResolve.call(this, request, parent, isMain, options);
        };
        try {
          const result = await executeTool("bob_auto_signup", {
            target_domain: "example.com",
            signup_url: "https://example.com/signup",
            email: "a@example.test",
            password: "Password123!",
            egress_profile: "browser-eu",
          });

          assert.equal(result.ok, true);
          assert.equal(result.data.egress_profile, "browser-eu");
          assert.equal(result.data.egress_region, "EU");
          assert.equal(result.data.proxy_configured, true);
          assert.match(result.data.egress_profile_identity_hash, /^[a-f0-9]{64}$/);
          assert.equal(result.data.reason, "patchright_unavailable");
          assert.doesNotMatch(JSON.stringify(result), new RegExp(rawProxySecret));
        } finally {
          Module._resolveFilename = originalResolve;
        }
      });
    });
  });
});

test("bob_signup_detect uses egress profiles and rejects proxy-backed strict mode", async () => {
  await withTempHome(async () => {
    seedSessionState("example.com");
    const rawProxySecret = ["signup", "detect", "proxy", "secret"].join("-");
    const proxyAuthority = ["user", rawProxySecret].join(":");
    const document = {
      version: 1,
      profiles: [
        egressProfiles.defaultEgressProfile(),
        {
          name: "detect-eu",
          proxy_url: "${BOB_EGRESS_DETECT_PROXY}",
          region: "EU",
          description: "Signup detection proxy",
          enabled: true,
        },
      ],
    };

    await withDefaultEgressConfig(document, async () => {
      await withEnv({ BOB_EGRESS_DETECT_PROXY: ["http://", proxyAuthority, "@proxy.example:8080"].join("") }, async () => {
        let sawAgent = false;
        await withMockSafeFetch((url, requestOptions) => {
          sawAgent = sawAgent || !!requestOptions.agent;
          return { status: 404, statusText: "Not Found", body: "missing" };
        }, async () => {
          const result = await executeTool("bob_signup_detect", {
            target_domain: "example.com",
            target_url: "https://example.com",
            egress_profile: "detect-eu",
          });

          assert.equal(result.ok, true);
          assert.equal(result.data.egress_profile, "detect-eu");
          assert.equal(result.data.egress_region, "EU");
          assert.equal(result.data.proxy_configured, true);
          assert.match(result.data.egress_profile_identity_hash, /^[a-f0-9]{64}$/);
          assert.equal(sawAgent, true);
          assert.doesNotMatch(JSON.stringify(result), new RegExp(rawProxySecret));
        });

        const strict = await executeTool("bob_signup_detect", {
          target_domain: "example.com",
          target_url: "https://example.com",
          egress_profile: "detect-eu",
          block_internal_hosts: true,
        });
        assert.equal(strict.ok, false);
        assert.equal(strict.error.code, "SCOPE_BLOCKED");
        assert.match(strict.error.message, /block_internal_hosts cannot be enforced with proxy-backed egress_profile "detect-eu"/);
        assert.match(strict.error.details.egress_profile_identity_hash, /^[a-f0-9]{64}$/);
        assert.doesNotMatch(JSON.stringify(strict), new RegExp(rawProxySecret));
      });
    });
  });
});

test("bob_auto_signup blocks internal and off-target signup URLs before browser launch", async () => {
  await withTempHome(async () => {
    const domain = "example.com";
    seedSessionState(domain);

    const internalBlocked = await executeTool("bob_auto_signup", {
      target_domain: domain,
      signup_url: "http://127.0.0.1/signup",
      email: "a@example.test",
      password: "Password123!",
      block_internal_hosts: true,
    });
    assert.equal(internalBlocked.ok, false);
    assert.equal(internalBlocked.error.code, "SCOPE_BLOCKED");
    assert.equal(internalBlocked.error.details.scope_decision, "blocked");
    assert.equal(internalBlocked.error.details.host, "127.0.0.1");
    assert.match(internalBlocked.error.message, /outside target_domain example\.com/);

    const offTarget = await executeTool("bob_auto_signup", {
      target_domain: domain,
      signup_url: "https://third-party.example.net/signup",
      email: "a@example.test",
      password: "Password123!",
    });
    assert.equal(offTarget.ok, false);
    assert.equal(offTarget.error.code, "SCOPE_BLOCKED");
    assert.equal(offTarget.error.details.scope_decision, "blocked");
    assert.equal(offTarget.error.details.host, "third-party.example.net");
    assert.match(offTarget.error.message, /outside target_domain example\.com/);
  });
});

test("bob_auto_signup refuses strict internal-host mode before browser availability checks", async () => {
  await withTempHome(async () => {
    const domain = "example.com";
    seedSessionState(domain);

    const originalResolve = Module._resolveFilename;
    let patchrightResolveCalls = 0;
    Module._resolveFilename = function patchedResolve(request, parent, isMain, options) {
      if (request === "patchright") {
        patchrightResolveCalls += 1;
        throw new Error("Patchright resolution should not run after a strict browser policy block");
      }
      return originalResolve.call(this, request, parent, isMain, options);
    };

    try {
      await withMockSafeFetch({}, async (requestedUrls) => {
        const result = await executeTool("bob_auto_signup", {
          target_domain: domain,
          signup_url: "https://signup.example.com/register",
          email: "a@example.test",
          password: "Password123!",
          block_internal_hosts: true,
        });

        assert.equal(result.ok, false);
        assert.equal(result.error.code, "SCOPE_BLOCKED");
        assert.match(result.error.message, /block_internal_hosts cannot be enforced for browser auto-signup/);
        assert.equal(result.error.details.scope_decision, "blocked");
        assert.equal(result.error.details.fallback, "manual");
        assert.equal(result.error.details.reason, "strict_internal_hosts_unsupported_browser");
        assert.deepEqual(requestedUrls, []);
        assert.equal(patchrightResolveCalls, 0);
      }, { dnsRecords: { "signup.example.com": [{ address: "10.0.0.5", family: 4 }] } });
    } finally {
      Module._resolveFilename = originalResolve;
    }
  });
});

test("bob_auto_signup uses persisted paranoid policy for manual fallback before browser availability checks", async () => {
  await withTempHome(async () => {
    const domain = "paranoid-signup.example.com";
    const init = await executeTool("bob_init_session", {
      target_domain: domain,
      target_url: `https://${domain}`,
      checkpoint_mode: "paranoid",
    });
    assert.equal(init.ok, true);

    const originalResolve = Module._resolveFilename;
    let patchrightResolveCalls = 0;
    Module._resolveFilename = function patchedResolve(request, parent, isMain, options) {
      if (request === "patchright") {
        patchrightResolveCalls += 1;
        throw new Error("Patchright resolution should not run after an effective strict browser policy block");
      }
      return originalResolve.call(this, request, parent, isMain, options);
    };

    try {
      await withMockSafeFetch({}, async (requestedUrls) => {
        const result = await executeTool("bob_auto_signup", {
          target_domain: domain,
          signup_url: `https://signup.${domain}/register`,
          email: "a@example.test",
          password: "Password123!",
        });

        assert.equal(result.ok, false);
        assert.equal(result.error.code, "SCOPE_BLOCKED");
        assert.match(result.error.message, /block_internal_hosts cannot be enforced for browser auto-signup/);
        assert.equal(result.error.details.block_internal_hosts, true);
        assert.equal(result.error.details.block_internal_hosts_source, "paranoid_default");
        assert.equal(result.error.details.reason, "strict_internal_hosts_unsupported_browser");
        assert.deepEqual(requestedUrls, []);
        assert.equal(patchrightResolveCalls, 0);
      });
    } finally {
      Module._resolveFilename = originalResolve;
    }
  });
});

test("bob_auto_signup treats non-policy egress profile failures as manual fallback", async () => {
  await withTempHome(async () => {
    seedSessionState("example.com");
    const result = await executeTool("bob_auto_signup", {
      target_domain: "example.com",
      signup_url: "https://signup.example.com/register",
      email: "a@example.test",
      password: "Password123!",
      egress_profile: "missing-profile",
    });

    assert.equal(result.ok, true);
    assert.equal(result.data.success, false);
    assert.equal(result.data.fallback, "manual");
    assert.equal(result.data.reason, "egress_profile_unavailable");
    assert.match(result.data.message, /egress profile "missing-profile" was not found/);
    assert.notEqual(result.data.scope_decision, "blocked");
  });
});

// ── migrateAuthJson unit tests ──

test("migrateAuthJson wraps legacy flat object as attacker profile", () => {
  const legacy = { Authorization: "Bearer old", Cookie: "s=1" };
  const result = migrateAuthJson(legacy);
  assert.equal(result.version, 2);
  assert.deepStrictEqual(result.profiles.attacker, legacy);
});

test("migrateAuthJson returns v2 unchanged", () => {
  const v2 = { version: 2, profiles: { attacker: { Authorization: "Bearer a" } } };
  const result = migrateAuthJson(v2);
  assert.equal(result, v2);
});

test("migrateAuthJson handles null/undefined", () => {
  assert.deepStrictEqual(migrateAuthJson(null), { version: 2, profiles: {} });
  assert.deepStrictEqual(migrateAuthJson(undefined), { version: 2, profiles: {} });
});

// ── HTTP audit, imported traffic, public intel, and ranking tests ──

test("bob_http_scan writes audit entries for success, HTTP error, timeout, and scope-blocked requests", async () => {
  await withTempHome(async () => {
    const domain = "example.com";
    seedSessionState(domain);
    const timeoutError = new Error("The operation was aborted");
    timeoutError.name = "AbortError";

    await withMockSafeFetch({
      "https://example.com/ok": { status: 200, statusText: "OK", body: "ok" },
      "https://example.com/forbidden": { status: 403, statusText: "Forbidden", body: "no" },
      "https://example.com/timeout": { error: timeoutError },
    }, async () => {
      const okResult = await executeTool("bob_http_scan", {
        target_domain: domain,
        wave: "w1",
        agent: "a1",
        surface_id: "surface-a",
        method: "GET",
        url: "https://example.com/ok",
        response_mode: "status_only",
      });
      assert.equal(okResult.ok, true);
      assert.equal(okResult.data.status, 200);

      const forbiddenResult = await executeTool("bob_http_scan", {
        target_domain: domain,
        method: "GET",
        url: "https://example.com/forbidden",
        response_mode: "status_only",
      });
      assert.equal(forbiddenResult.ok, true);
      assert.equal(forbiddenResult.data.status, 403);

      const timeoutResult = await executeTool("bob_http_scan", {
        target_domain: domain,
        method: "GET",
        url: "https://example.com/timeout",
      });
      assert.equal(timeoutResult.ok, false);
      assert.equal(timeoutResult.error.code, "INTERNAL_ERROR");
      assert.match(timeoutResult.error.message, /timeout/i);

      const privateHostResult = await executeTool("bob_http_scan", {
        target_domain: domain,
        method: "GET",
        url: "http://127.0.0.1/admin",
        block_internal_hosts: true,
      });
      assert.equal(privateHostResult.ok, false);
      assert.equal(privateHostResult.error.code, "SCOPE_BLOCKED");
      assert.match(privateHostResult.error.message, /Blocked internal\/private host/);

      const records = readHttpAuditRecordsFromJsonl(domain);
      assert.equal(records.length, 4);
      assert.deepEqual(records.map((record) => record.status), [200, 403, null, null]);
      assert.deepEqual(records.map((record) => record.scope_decision), ["allowed", "allowed", "network_unreachable_target", "blocked"]);
      assert.deepEqual(records.map((record) => record.egress_profile), ["default", "default", "default", "default"]);
      assert.equal(records[0].wave, "w1");
      assert.equal(records[0].agent, "a1");
      assert.equal(records[0].surface_id, "surface-a");

      const audit = JSON.parse(readHttpAudit({ target_domain: domain, limit: 2 }));
      assert.equal(audit.summary.total, 4);
      assert.equal(audit.summary.shown, 2);
      assert.equal(audit.summary.by_status_class["4xx"], 1);
      assert.equal(audit.summary.scope_blocked, 1);
      assert.equal(audit.summary.network_unreachable_target, 1);
      assert.equal(audit.summary.egress.by_profile.default, 4);
      const clampedAudit = JSON.parse(readHttpAudit({ target_domain: domain, limit: 9999 }));
      assert.equal(clampedAudit.summary.cap, 40);
      assert.equal(clampedAudit.summary.shown, 4);
      const clampedEnvelope = await executeTool("bob_read_http_audit", { target_domain: domain, limit: 9999 });
      assert.equal(clampedEnvelope.ok, true);
      assert.equal(clampedEnvelope.data.summary.cap, 40);
      assert.ok(fs.existsSync(httpAuditJsonlPath(domain)));
    });
  });
});

test("bob_http_scan records selected egress profile and passes a proxy agent without storing proxy URLs", async () => {
  await withTempHome(async () => {
    const domain = "example.com";
    seedSessionState(domain);
    const rawProxySecret = ["raw", "proxy", "secret"].join("-");
    const proxyAuthority = ["user", rawProxySecret].join(":");
    const document = {
      version: 1,
      profiles: [
        egressProfiles.defaultEgressProfile(),
        {
          name: "gr-residential",
          proxy_url: "${BOB_EGRESS_GR_RESIDENTIAL_PROXY}",
          region: "GR",
          description: "Greece operator profile",
          enabled: true,
        },
      ],
    };

    await withDefaultEgressConfig(document, async () => {
      await withEnv({ BOB_EGRESS_GR_RESIDENTIAL_PROXY: ["http://", proxyAuthority, "@127.0.0.1:8080"].join("") }, async () => {
        let sawAgent = false;
        await withMockSafeFetch((url, requestOptions) => {
          sawAgent = !!requestOptions.agent;
          return { status: 200, statusText: "OK", body: "ok" };
        }, async () => {
          const result = await executeTool("bob_http_scan", {
            target_domain: domain,
            method: "GET",
            url: "https://example.com/ok",
            egress_profile: "gr-residential",
            response_mode: "status_only",
          });

          assert.equal(result.ok, true);
          assert.equal(result.data.egress_profile, "gr-residential");
          assert.equal(result.data.egress_region, "GR");
          assert.equal(sawAgent, true);

          const records = readHttpAuditRecordsFromJsonl(domain);
          assert.equal(records.length, 1);
          assert.equal(records[0].egress_profile, "gr-residential");
          assert.equal(records[0].egress_region, "GR");
          const audit = JSON.parse(readHttpAudit({ target_domain: domain }));
          assert.equal(audit.summary.egress.by_profile["gr-residential"], 1);
          assert.equal(audit.summary.egress.by_region.GR, 1);
          assert.doesNotMatch(JSON.stringify(result), new RegExp(rawProxySecret));
          assert.doesNotMatch(JSON.stringify(records), new RegExp(rawProxySecret));
          assert.doesNotMatch(JSON.stringify(audit), new RegExp(rawProxySecret));
        });
      });
    });
  });
});

test("bob_init_session binds egress profile identity without storing proxy secrets", async () => {
  await withTempHome(async () => {
    const domain = "egress-init.example.com";
    const rawProxySecret = ["init", "proxy", "secret"].join("-");
    const proxyAuthority = ["user", rawProxySecret].join(":");
    const document = {
      version: 1,
      profiles: [
        egressProfiles.defaultEgressProfile(),
        {
          name: "operator-eu",
          proxy_url: "${BOB_EGRESS_OPERATOR_PROXY}",
          region: "EU",
          description: "Operator egress profile",
          enabled: true,
        },
      ],
    };

    await withDefaultEgressConfig(document, async () => {
      await withEnv({ BOB_EGRESS_OPERATOR_PROXY: ["http://", proxyAuthority, "@proxy.example:8080"].join("") }, async () => {
        const result = await executeTool("bob_init_session", {
          target_domain: domain,
          target_url: `https://${domain}`,
          egress_profile: "operator-eu",
        });

        assert.equal(result.ok, true);
        assert.equal(result.data.state.egress_profile, "operator-eu");
        assert.equal(result.data.state.egress_region, "EU");
        assert.equal(result.data.state.proxy_configured, true);
        assert.match(result.data.state.egress_profile_identity_hash, /^[a-f0-9]{64}$/);
        assert.equal(result.data.state.egress_profile_identity_version, 1);
        assert.equal(result.data.state.egress_profile_identity_source.proxy_env_var, "BOB_EGRESS_OPERATOR_PROXY");
        assert.doesNotMatch(JSON.stringify(result), new RegExp(rawProxySecret));

        const rawState = fs.readFileSync(statePath(domain), "utf8");
        assert.doesNotMatch(rawState, new RegExp(rawProxySecret));
        const events = readJsonl(pipelineEventsJsonlPath(domain));
        assert.equal(events[0].type, "session_started");
        assert.equal(events[0].egress_profile_identity_hash, result.data.state.egress_profile_identity_hash);
        assert.doesNotMatch(JSON.stringify(events), new RegExp(rawProxySecret));
      });
    });
  });
});

test("default egress identity hash is stable unless identity version changes", () => {
  withTempHome(() => {
    const profile = egressProfiles.resolveEgressProfile("default");
    assert.equal(egressProfiles.EGRESS_PROFILE_IDENTITY_VERSION, 1);
    assert.equal(
      profile.egress_profile_identity_hash,
      "791de81d33f4f1d790cd2d1f9f800ba238072914b6f37aaa4739c7b34a398acc",
    );
  });
});

test("egress-bound HTTP scans require initialized session state", async () => {
  await withTempHome(async () => {
    const domain = "egress-no-session.example.com";
    await withMockSafeFetch(() => {
      throw new Error("network should not be reached without egress binding");
    }, async (requestedUrls) => {
      const result = await executeTool("bob_http_scan", {
        target_domain: domain,
        method: "GET",
        url: `https://${domain}/ok`,
      });
      assert.equal(result.ok, false);
      assert.equal(result.error.code, "STATE_CONFLICT");
      assert.match(result.error.message, /Session authority is missing/);
      assert.deepEqual(requestedUrls, []);
    });
  });
});

test("scope-blocked HTTP scans keep the bound egress identity in audit and telemetry", async () => {
  await withTempHome(async () => {
    const domain = "egress-scope-block.example.com";
    const init = await executeTool("bob_init_session", {
      target_domain: domain,
      target_url: `https://${domain}`,
    });
    assert.equal(init.ok, true);
    const boundHash = init.data.state.egress_profile_identity_hash;

    await withMockSafeFetch(() => {
      throw new Error("network should not be reached for scope-blocked requests");
    }, async (requestedUrls) => {
      const result = await executeTool("bob_http_scan", {
        target_domain: domain,
        method: "GET",
        url: "http://127.0.0.1/admin",
        block_internal_hosts: true,
      });
      assert.equal(result.ok, false);
      assert.equal(result.error.code, "SCOPE_BLOCKED");
      assert.equal(result.error.details.egress_profile_identity_hash, boundHash);
      assert.deepEqual(requestedUrls, []);
    });

    const records = readHttpAuditRecordsFromJsonl(domain);
    assert.equal(records.length, 1);
    assert.equal(records[0].scope_decision, "blocked");
    assert.equal(records[0].egress_profile_identity_hash, boundHash);

    const telemetryRows = readJsonl(toolTelemetryPath())
      .filter((row) => row.tool === "bob_http_scan");
    assert.equal(telemetryRows.length, 1);
    assert.equal(telemetryRows[0].egress_profile_identity_hash, boundHash);
  });
});

test("scope-blocked HTTP scans still reject initialized-session egress drift", async () => {
  await withTempHome(async () => {
    const domain = "egress-scope-drift.example.com";
    const document = {
      version: 1,
      profiles: [
        egressProfiles.defaultEgressProfile(),
        {
          name: "operator-eu",
          proxy_url: null,
          region: "EU",
          description: "Operator direct EU profile",
          enabled: true,
        },
      ],
    };

    await withDefaultEgressConfig(document, async () => {
      const init = await executeTool("bob_init_session", {
        target_domain: domain,
        target_url: `https://${domain}`,
      });
      assert.equal(init.ok, true);

      await withMockSafeFetch(() => {
        throw new Error("network should not be reached for scope-blocked drift");
      }, async (requestedUrls) => {
        const result = await executeTool("bob_http_scan", {
          target_domain: domain,
          method: "GET",
          url: "http://127.0.0.1/admin",
          egress_profile: "operator-eu",
          block_internal_hosts: true,
        });
        assert.equal(result.ok, false);
        assert.equal(result.error.code, "STATE_CONFLICT");
        assert.match(result.error.message, /egress profile drift/);
        assert.deepEqual(requestedUrls, []);
      });
    });

    assert.deepEqual(readHttpAuditRecordsFromJsonl(domain), []);
  });
});

test("scope-blocked HTTP scans migrate legacy egress identity before audit", async () => {
  await withTempHome(async () => {
    const domain = "legacy-scope-block.example.com";
    seedSessionState(domain, {
      phase: "EVALUATE",
      ...legacyEgressStateFields(),
    });

    await withMockSafeFetch(() => {
      throw new Error("network should not be reached for legacy scope block");
    }, async (requestedUrls) => {
      const result = await executeTool("bob_http_scan", {
        target_domain: domain,
        method: "GET",
        url: "http://127.0.0.1/admin",
        block_internal_hosts: true,
      });
      assert.equal(result.ok, false);
      assert.equal(result.error.code, "SCOPE_BLOCKED");
      assert.match(result.error.details.egress_profile_identity_hash, /^[a-f0-9]{64}$/);
      assert.deepEqual(requestedUrls, []);
    });

    const state = JSON.parse(fs.readFileSync(statePath(domain), "utf8"));
    assert.match(state.egress_profile_identity_hash, /^[a-f0-9]{64}$/);
    assert.equal(state.egress_profile_identity_bind_source, "legacy_migration");
    assert.equal(state.egress_profile_legacy_migration.source, "bob_http_scan_scope_blocked");
    const records = readHttpAuditRecordsFromJsonl(domain);
    assert.equal(records.length, 1);
    assert.equal(records[0].scope_decision, "blocked");
    assert.equal(records[0].egress_profile_identity_hash, state.egress_profile_identity_hash);
  });
});

test("session egress identity permits credential rotation but rejects route drift", async () => {
  await withTempHome(async () => {
    const domain = "egress-drift.example.com";
    const firstSecret = ["first", "proxy", "secret"].join("-");
    const secondSecret = ["second", "proxy", "secret"].join("-");
    const document = {
      version: 1,
      profiles: [
        egressProfiles.defaultEgressProfile(),
        {
          name: "operator-eu",
          proxy_url: "${BOB_EGRESS_OPERATOR_PROXY}",
          region: "EU",
          description: "Operator egress profile",
          enabled: true,
        },
      ],
    };

    await withDefaultEgressConfig(document, async () => {
      await withEnv({ BOB_EGRESS_OPERATOR_PROXY: `http://user:${firstSecret}@proxy.example:8080` }, async () => {
        const init = await executeTool("bob_init_session", {
          target_domain: domain,
          target_url: `https://${domain}`,
          egress_profile: "operator-eu",
        });
        assert.equal(init.ok, true);
      });

      const boundHash = JSON.parse(fs.readFileSync(statePath(domain), "utf8")).egress_profile_identity_hash;

      await withEnv({ BOB_EGRESS_OPERATOR_PROXY: `http://user:${secondSecret}@proxy.example:8080` }, async () => {
        await withMockSafeFetch({
          [`https://${domain}/ok`]: { status: 200, statusText: "OK", body: "ok" },
        }, async () => {
          const rotated = await executeTool("bob_http_scan", {
            target_domain: domain,
            method: "GET",
            url: `https://${domain}/ok`,
            egress_profile: "operator-eu",
            response_mode: "status_only",
          });
          assert.equal(rotated.ok, true);
          assert.equal(rotated.data.egress_profile_identity_hash, boundHash);
          assert.doesNotMatch(JSON.stringify(rotated), new RegExp(secondSecret));
          assert.doesNotMatch(fs.readFileSync(statePath(domain), "utf8"), new RegExp(secondSecret));
          assert.doesNotMatch(
            JSON.stringify(readJsonl(pipelineEventsJsonlPath(domain))),
            new RegExp(secondSecret),
          );
          assert.doesNotMatch(
            JSON.stringify(readHttpAuditRecordsFromJsonl(domain)),
            new RegExp(secondSecret),
          );
        });
      });

      await withEnv({ BOB_EGRESS_OPERATOR_PROXY: `http://user:${secondSecret}@other-proxy.example:8080` }, async () => {
        await withMockSafeFetch(() => {
          throw new Error("network should not be reached after egress drift");
        }, async (requestedUrls) => {
          const drifted = await executeTool("bob_http_scan", {
            target_domain: domain,
            method: "GET",
            url: `https://${domain}/ok`,
            egress_profile: "operator-eu",
          });
          assert.equal(drifted.ok, false);
          assert.equal(drifted.error.code, "STATE_CONFLICT");
          assert.match(drifted.error.message, /egress profile drift/);
          assert.equal(drifted.error.details.expected.egress_profile_identity_hash, boundHash);
          assert.deepEqual(requestedUrls, []);
          assert.doesNotMatch(JSON.stringify(drifted), new RegExp(secondSecret));
        });
      });

      const telemetryRows = readJsonl(toolTelemetryPath())
        .filter((row) => row.tool === "bob_http_scan");
      assert.ok(telemetryRows.some((row) => row.egress_profile_identity_hash === boundHash));
      const driftTelemetry = telemetryRows.find((row) => row.error_code === "STATE_CONFLICT");
      assert.ok(driftTelemetry);
      assert.equal(driftTelemetry.egress_profile_identity_hash, boundHash);
      assert.doesNotMatch(JSON.stringify(telemetryRows), new RegExp(secondSecret));
    });
  });
});

test("legacy sessions snapshot egress identity on first egress-bound request", async () => {
  await withTempHome(async () => {
    const domain = "legacy-egress.example.com";
    seedSessionState(domain, { phase: "EVALUATE" });
    appendJsonlLine(pipelineEventsJsonlPath(domain), {
      version: 1,
      bob_version: PACKAGE_VERSION,
      ts: "2026-05-15T00:00:00.000Z",
      target_domain: domain,
      type: "coverage_logged",
      counts: { coverage: 1 },
      source: "legacy_fixture",
    });

    await withMockSafeFetch({
      [`https://${domain}/ok`]: { status: 200, statusText: "OK", body: "ok" },
    }, async () => {
      const result = await executeTool("bob_http_scan", {
        target_domain: domain,
        method: "GET",
        url: `https://${domain}/ok`,
        response_mode: "status_only",
      });
      assert.equal(result.ok, true);
      assert.match(result.data.egress_profile_identity_hash, /^[a-f0-9]{64}$/);
    });

    const state = JSON.parse(fs.readFileSync(statePath(domain), "utf8"));
    assert.equal(state.egress_profile, "default");
    assert.match(state.egress_profile_identity_hash, /^[a-f0-9]{64}$/);
    assert.match(state.egress_profile_identity_bound_at, /^\d{4}-\d{2}-\d{2}T/);
    assert.equal(state.egress_profile_identity_bind_source, "legacy_migration");
    assert.deepEqual(state.egress_profile_legacy_migration.previous, {
      egress_profile: "default",
      egress_region: null,
      proxy_configured: false,
      egress_profile_identity_hash: null,
      egress_profile_identity_version: null,
    });
    const records = readHttpAuditRecordsFromJsonl(domain);
    assert.equal(records[0].egress_profile_identity_hash, state.egress_profile_identity_hash);
    const analytics = JSON.parse(readPipelineAnalytics({ target_domain: domain }));
    assert.equal(
      analytics.sessions[0].egress_profile_identity.egress_profile_identity_hash,
      state.egress_profile_identity_hash,
    );
    assert.equal(
      analytics.sessions[0].egress.by_identity_hash[state.egress_profile_identity_hash],
      1,
    );
    const events = readJsonl(pipelineEventsJsonlPath(domain));
    assert.ok(events.some((event) => (
      event.type === "egress_identity_bound" &&
      event.legacy_migration === true &&
      event.egress_profile_identity_hash === state.egress_profile_identity_hash
    )));
    const normalizedEvents = readPipelineEvents(domain).events;
    const legacyEvent = normalizedEvents.find((event) => event.source === "legacy_fixture");
    assert.ok(legacyEvent);
    assert.equal(legacyEvent.egress_profile_identity_hash, state.egress_profile_identity_hash);
  });
});

test("bob_http_scan rejects env-resolved proxy query secrets", async () => {
  await withTempHome(async () => {
    seedSessionState("example.com");
    const rawProxySecret = ["env", "query", "proxy", "secret"].join("-");
    const document = {
      version: 1,
      profiles: [
        egressProfiles.defaultEgressProfile(),
        {
          name: "env-query-secret",
          proxy_url: "${BOB_EGRESS_QUERY_PROXY}",
          region: "EU",
          description: null,
          enabled: true,
        },
      ],
    };

    await withDefaultEgressConfig(document, async () => {
      await withEnv({ BOB_EGRESS_QUERY_PROXY: `http://proxy.example:8080/?token=${rawProxySecret}` }, async () => {
        await withMockSafeFetch(() => {
          throw new Error("network should not be reached");
        }, async (requestedUrls) => {
          const result = await executeTool("bob_http_scan", {
            target_domain: "example.com",
            method: "GET",
            url: "https://example.com/ok",
            egress_profile: "env-query-secret",
          });
          assert.equal(result.ok, false);
          assert.equal(result.error.code, "INTERNAL_ERROR");
          assert.match(result.error.message, /query strings or fragments are not supported/);
          assert.doesNotMatch(JSON.stringify(result), new RegExp(rawProxySecret));
          assert.deepEqual(requestedUrls, []);
        });
      });
    });
  });
});

test("bob_http_scan rejects invalid egress profiles before sending network requests and redacts proxy credentials", async () => {
  await withTempHome(async () => {
    seedSessionState("example.com");
    const rawProxySecret = ["do", "not", "leak", "proxy", "secret"].join("-");
    const proxyAuthority = ["user", rawProxySecret].join(":");
    const document = {
      version: 1,
      profiles: [
        egressProfiles.defaultEgressProfile(),
        { name: "disabled", proxy_url: "${BOB_EGRESS_DISABLED_PROXY}", region: "EU", description: null, enabled: false },
        { name: "missing-env", proxy_url: "${BOB_EGRESS_MISSING_PROXY}", region: "EU", description: null, enabled: true },
        { name: "unsupported", proxy_url: "ftp://proxy.example:21", region: "EU", description: null, enabled: true },
        { name: "malformed", proxy_url: "http://", region: "EU", description: null, enabled: true },
      ],
    };

    await withDefaultEgressConfig(document, async () => {
      await withMockSafeFetch(() => {
        throw new Error("network should not be reached");
      }, async (requestedUrls) => {
        for (const [profileName, pattern] of [
          ["missing", /not found/],
          ["disabled", /disabled/],
          ["missing-env", /env var BOB_EGRESS_MISSING_PROXY is not set/],
          ["unsupported", /unsupported egress proxy protocol: ftp:/],
          ["malformed", /malformed/],
        ]) {
          const result = await executeTool("bob_http_scan", {
            target_domain: "example.com",
            method: "GET",
            url: "https://example.com/ok",
            egress_profile: profileName,
          });
          assert.equal(result.ok, false, `${profileName} should fail`);
          assert.equal(result.error.code, "INTERNAL_ERROR");
          assert.match(result.error.message, pattern);
          assert.doesNotMatch(JSON.stringify(result), new RegExp(rawProxySecret));
        }
        assert.deepEqual(requestedUrls, []);
      });
    });
  });
});

test("bob_http_scan rejects inline proxy credentials in egress profile config", async () => {
  await withTempHome(async () => {
    seedSessionState("example.com");
    const rawProxySecret = ["inline", "proxy", "secret"].join("-");
    const proxyAuthority = ["user", rawProxySecret].join(":");
    const document = {
      version: 1,
      profiles: [
        egressProfiles.defaultEgressProfile(),
        {
          name: "inline-secret",
          proxy_url: ["http://", proxyAuthority, "@proxy.example:8080"].join(""),
          region: "EU",
          description: null,
          enabled: true,
        },
      ],
    };

    await withDefaultEgressConfig(document, async () => {
      await withMockSafeFetch(() => {
        throw new Error("network should not be reached");
      }, async (requestedUrls) => {
        const result = await executeTool("bob_http_scan", {
          target_domain: "example.com",
          method: "GET",
          url: "https://example.com/ok",
          egress_profile: "inline-secret",
        });
        assert.equal(result.ok, false);
        assert.equal(result.error.code, "INTERNAL_ERROR");
        assert.match(result.error.message, /proxy_url credentials must use an environment reference/);
        assert.doesNotMatch(JSON.stringify(result), new RegExp(rawProxySecret));
        assert.deepEqual(requestedUrls, []);
      });
    });
  });
});

test("bob_http_scan rejects inline proxy query secrets in egress profile config", async () => {
  await withTempHome(async () => {
    seedSessionState("example.com");
    const rawProxySecret = ["query", "proxy", "secret"].join("-");
    const document = {
      version: 1,
      profiles: [
        egressProfiles.defaultEgressProfile(),
        {
          name: "query-secret",
          proxy_url: `http://proxy.example:8080/?token=${rawProxySecret}`,
          region: "EU",
          description: null,
          enabled: true,
        },
      ],
    };

    await withDefaultEgressConfig(document, async () => {
      await withMockSafeFetch(() => {
        throw new Error("network should not be reached");
      }, async (requestedUrls) => {
        const result = await executeTool("bob_http_scan", {
          target_domain: "example.com",
          method: "GET",
          url: "https://example.com/ok",
          egress_profile: "query-secret",
        });
        assert.equal(result.ok, false);
        assert.equal(result.error.code, "INTERNAL_ERROR");
        assert.match(result.error.message, /proxy_url query strings or fragments must use an environment reference/);
        assert.doesNotMatch(JSON.stringify(result), new RegExp(rawProxySecret));
        assert.deepEqual(requestedUrls, []);
      });
    });
  });
});

test("bob_http_scan rejects proxy egress when strict internal-host blocking is requested", async () => {
  await withTempHome(async () => {
    const domain = "example.com";
    seedSessionState(domain);
    const rawProxySecret = ["strict", "proxy", "secret"].join("-");
    const proxyAuthority = ["user", rawProxySecret].join(":");
    const document = {
      version: 1,
      profiles: [
        egressProfiles.defaultEgressProfile(),
        {
          name: "operator-eu",
          proxy_url: "${BOB_EGRESS_OPERATOR_EU_PROXY}",
          region: "EU",
          description: "Operator egress profile",
          enabled: true,
        },
      ],
    };

    await withDefaultEgressConfig(document, async () => {
      await withEnv({ BOB_EGRESS_OPERATOR_EU_PROXY: ["http://", proxyAuthority, "@proxy.example:8080"].join("") }, async () => {
        await withMockSafeFetch(() => {
          throw new Error("network should not be reached");
        }, async (requestedUrls) => {
          const result = await executeTool("bob_http_scan", {
            target_domain: domain,
            method: "GET",
            url: "https://example.com/ok",
            egress_profile: "operator-eu",
            block_internal_hosts: true,
          });

          assert.equal(result.ok, false);
          assert.equal(result.error.code, "SCOPE_BLOCKED");
          assert.match(result.error.message, /block_internal_hosts cannot be enforced with proxy-backed egress_profile "operator-eu"/);
          assert.equal(result.error.details.egress_profile, "operator-eu");
          assert.equal(result.error.details.egress_region, "EU");
          assert.deepEqual(requestedUrls, []);
          assert.doesNotMatch(JSON.stringify(result), new RegExp(rawProxySecret));

          const records = readHttpAuditRecordsFromJsonl(domain);
          assert.equal(records.length, 1);
          assert.equal(records[0].scope_decision, "blocked");
          assert.equal(records[0].egress_profile, "operator-eu");
          assert.equal(records[0].egress_region, "EU");
          assert.match(records[0].error, /block_internal_hosts cannot be enforced/);
          assert.doesNotMatch(JSON.stringify(records), new RegExp(rawProxySecret));
        });
      });
    });
  });
});

test("bob_http_scan redacts persisted audit URLs while sending the original request", async () => {
  await withTempHome(async () => {
    const domain = "example.com";
    seedSessionState(domain);
    await withMockSafeFetch({
      "https://example.com/callback?token=secret-token&code=oauth-code&id=123": {
        status: 200,
        statusText: "OK",
        body: "ok",
      },
    }, async (requestedUrls) => {
      await executeTool("bob_http_scan", {
        target_domain: domain,
        method: "GET",
        url: "https://example.com/callback?token=secret-token&code=oauth-code&id=123#client-fragment",
        response_mode: "status_only",
      });

      assert.equal(requestedUrls[0], "https://example.com/callback?token=secret-token&code=oauth-code&id=123");
      const records = readHttpAuditRecordsFromJsonl(domain);
      assert.equal(records.length, 1);
      assert.equal(records[0].url, "https://example.com/callback?token=REDACTED&code=REDACTED&id=REDACTED");
      assert.equal(records[0].path, "/callback?token=REDACTED&code=REDACTED&id=REDACTED");
      assert.doesNotMatch(JSON.stringify(records), /secret-token|oauth-code|client-fragment|id=123/);

      const audit = JSON.parse(readHttpAudit({ target_domain: domain }));
      assert.doesNotMatch(JSON.stringify(audit), /secret-token|oauth-code|client-fragment|id=123/);
    });
  });
});

test("bob_http_scan permits first-party hosts and blocks off-target hosts before network requests", async () => {
  await withTempHome(async () => {
    const domain = "example.com";
    seedSessionState(domain);
    seedAttackSurfaces(domain, [
      { id: "surface-api", hosts: [`https://api.partner-service.com`] },
    ]);
    // A leftover deny-list.txt from older sessions must no longer matter.
    fs.writeFileSync(path.join(sessionDir(domain), "deny-list.txt"), "blocked.example.com\n");

    await withMockSafeFetch({
      "https://app.example.com/ok": { status: 200, statusText: "OK", body: "ok" },
      "https://blocked.example.com/admin": { status: 200, statusText: "OK", body: "ok" },
    }, async (requestedUrls) => {
      const allowedTargets = [
        "https://app.example.com/ok",
        "https://blocked.example.com/admin",
      ];
      for (const url of allowedTargets) {
        const result = await executeTool("bob_http_scan", {
          target_domain: domain,
          method: "GET",
          url,
          response_mode: "status_only",
        });
        assert.equal(result.ok, true, `expected ${url} to be permitted`);
        assert.equal(result.data.status, 200);
      }

      const blockedTargets = [
        "https://api.partner-service.com/v1/users",
        "https://crt.sh/?q=example.com",
        "https://crt.sh/?q=other.com",
        "https://third-party.example.net/api",
        "http://127.0.0.1/admin",
        "http://metadata/latest/meta-data/",
        "http://service.internal/debug",
      ];
      for (const url of blockedTargets) {
        const result = await executeTool("bob_http_scan", {
          target_domain: domain,
          method: "GET",
          url,
          response_mode: "status_only",
        });
        assert.equal(result.ok, false, `expected ${url} to be blocked`);
        assert.equal(result.error.code, "SCOPE_BLOCKED");
        assert.match(result.error.message, /outside target_domain example\.com/);
      }

      assert.deepEqual(requestedUrls, allowedTargets);

      const records = readHttpAuditRecordsFromJsonl(domain);
      assert.equal(records.length, allowedTargets.length + blockedTargets.length);
      assert.deepEqual(
        records.map((record) => record.scope_decision),
        [...allowedTargets.map(() => "allowed"), ...blockedTargets.map(() => "blocked")],
      );
    });
  });
});

test("bob_http_scan requires target_domain instead of inferring scope from other sessions", async () => {
  await withTempHome(async () => {
    const domain = "example.com";
    seedSessionState(domain);

    const blocked = await executeTool("bob_http_scan", {
      method: "GET",
      url: "https://app.example.com/ok",
      response_mode: "status_only",
    });
    assert.equal(blocked.ok, false);
    assert.equal(blocked.error.code, "INVALID_ARGUMENTS");
    assert.match(blocked.error.message, /target_domain is required/);
  });
});

test("bob_http_scan optionally blocks internal redirect targets before fetching them", async () => {
  await withTempHome(async () => {
    const domain = "example.com";
    seedSessionState(domain);
    await withMockSafeFetch({
      "https://example.com/redirect": {
        status: 302,
        statusText: "Found",
        headers: { location: "http://127.0.0.1/admin" },
      },
    }, async (requestedUrls) => {
      const result = await executeTool("bob_http_scan", {
        target_domain: domain,
        method: "GET",
        url: "https://example.com/redirect",
        follow_redirects: true,
        block_internal_hosts: true,
      });

      assert.equal(result.ok, false);
      assert.equal(result.error.code, "SCOPE_BLOCKED");
      assert.match(result.error.message, /Blocked internal\/private host/);
      assert.equal(result.error.details.scope_decision, "blocked");
      assert.deepEqual(requestedUrls, ["https://example.com/redirect"]);

      const records = readHttpAuditRecordsFromJsonl(domain);
      assert.equal(records.length, 1);
      assert.equal(records[0].scope_decision, "blocked");
      assert.match(records[0].error, /Blocked internal\/private host/);
    });
  });
});

test("bob_http_scan blocks off-target redirects even when internal-host blocking is disabled", async () => {
  await withTempHome(async () => {
    const domain = "example.com";
    seedSessionState(domain);
    await withMockSafeFetch({
      "https://example.com/redirect": {
        status: 302,
        statusText: "Found",
        headers: { location: "http://127.0.0.1/admin" },
      },
      "http://127.0.0.1/admin": { status: 200, statusText: "OK", body: "local ok" },
    }, async (requestedUrls) => {
      const result = await executeTool("bob_http_scan", {
        target_domain: domain,
        method: "GET",
        url: "https://example.com/redirect",
        follow_redirects: true,
        response_mode: "status_only",
      });

      assert.equal(result.ok, false);
      assert.equal(result.error.code, "SCOPE_BLOCKED");
      assert.match(result.error.message, /outside target_domain example\.com/);
      assert.deepEqual(requestedUrls, ["https://example.com/redirect"]);
    });
  });
});

test("bob_http_scan optionally blocks public hostnames that resolve to private IPs before connecting", async () => {
  await withTempHome(async () => {
    const domain = "example.com";
    seedSessionState(domain);
    await withMockSafeFetch({
      "https://example.com/private-dns": { status: 200, body: "should not connect" },
    }, async (requestedUrls) => {
      const result = await executeTool("bob_http_scan", {
        target_domain: domain,
        method: "GET",
        url: "https://example.com/private-dns",
        block_internal_hosts: true,
      });
      assert.equal(result.ok, false);
      assert.equal(result.error.code, "SCOPE_BLOCKED");
      assert.match(result.error.message, /Blocked internal\/private DNS address/);
      assert.equal(result.error.details.scope_decision, "blocked");
      assert.deepEqual(requestedUrls, []);
    }, { dnsRecords: { "example.com": [{ address: "10.0.0.5", family: 4 }] } });
  });
});

test("bob_http_scan applies persisted paranoid internal-host blocking when call omits the flag", async () => {
  await withTempHome(async () => {
    const domain = "paranoid-http.example.com";
    const init = await executeTool("bob_init_session", {
      target_domain: domain,
      target_url: `https://${domain}`,
      checkpoint_mode: "paranoid",
    });
    assert.equal(init.ok, true);

    await withMockSafeFetch({
      [`https://${domain}/private-dns`]: { status: 200, body: "should not connect" },
    }, async (requestedUrls) => {
      for (const args of [
        {},
        { block_internal_hosts: false },
      ]) {
        const result = await executeTool("bob_http_scan", {
          target_domain: domain,
          method: "GET",
          url: `https://${domain}/private-dns`,
          ...args,
        });
        assert.equal(result.ok, false);
        assert.equal(result.error.code, "SCOPE_BLOCKED");
        assert.match(result.error.message, /Blocked internal\/private DNS address/);
      }
      assert.deepEqual(requestedUrls, []);
    }, { dnsRecords: { [domain]: [{ address: "10.0.0.5", family: 4 }] } });

    const records = readHttpAuditRecordsFromJsonl(domain);
    assert.equal(records.length, 2);
    assert.deepEqual(records.map((record) => record.block_internal_hosts), [true, true]);
    assert.deepEqual(records.map((record) => record.block_internal_hosts_source), [
      "paranoid_default",
      "paranoid_default",
    ]);
    const audit = JSON.parse(readHttpAudit({ target_domain: domain }));
    assert.equal(audit.summary.block_internal_hosts.true, 2);
    assert.equal(audit.summary.recent[0].block_internal_hosts, true);
    const analytics = JSON.parse(readPipelineAnalytics({ target_domain: domain }));
    assert.equal(analytics.sessions[0].block_internal_hosts, true);
    assert.equal(analytics.sessions[0].block_internal_hosts_source, "paranoid_default");
    assert.equal(analytics.sessions[0].http_audit.block_internal_hosts.true, 2);
    assert.equal(analytics.sessions[0].http_audit.block_internal_hosts.by_source.paranoid_default, 2);
  });
});

test("bob_http_scan blocks IPv4-embedded IPv6 DNS answers in dotted notation", async () => {
  await withTempHome(async () => {
    const dnsCases = [
      "::ffff:127.0.0.1",
      "::127.0.0.1",
      "::ffff:169.254.169.254",
    ];

    for (const address of dnsCases) {
      await withMockSafeFetch({
        "https://example.com/private-dns": { status: 200, body: "should not connect" },
      }, async (requestedUrls) => {
        seedSessionState("example.com");
        const result = await executeTool("bob_http_scan", {
          target_domain: "example.com",
          method: "GET",
          url: "https://example.com/private-dns",
          block_internal_hosts: true,
        });
        assert.equal(result.ok, false, address);
        assert.equal(result.error.code, "SCOPE_BLOCKED", address);
        assert.match(result.error.message, /Blocked internal\/private DNS address/, address);
        assert.deepEqual(requestedUrls, [], address);
      }, { dnsRecords: { "example.com": [{ address, family: 6 }] } });
    }
  });
});

test("bob_http_scan allows public hostnames that resolve to private IPs by default", async () => {
  await withTempHome(async () => {
    const domain = "example.com";
    seedSessionState(domain);
    await withMockSafeFetch({
      "https://example.com/private-dns": { status: 200, statusText: "OK", body: "connected" },
    }, async (requestedUrls) => {
      const result = await executeTool("bob_http_scan", {
        target_domain: domain,
        method: "GET",
        url: "https://example.com/private-dns",
        response_mode: "status_only",
      });
      assert.equal(result.ok, true);
      assert.equal(result.data.status, 200);
      assert.deepEqual(requestedUrls, ["https://example.com/private-dns"]);
    }, { dnsRecords: { "example.com": [{ address: "10.0.0.5", family: 4 }] } });
  });
});

test("safeFetch supports IPv6 literals by default and still blocks them when requested", async () => {
  await withTempHome(async () => {
    await withMockSafeFetch({
      "http://[::1]/admin": { status: 200, statusText: "OK", body: "ipv6 ok" },
    }, async (requestedUrls) => {
      const response = await safeFetch("http://[::1]/admin");

      assert.equal(response.status, 200);
      assert.equal(await response.text(), "ipv6 ok");
      assert.deepEqual(requestedUrls, ["http://[::1]/admin"]);
    });
  });

  await assert.rejects(
    () => safeFetch("http://[::1]/admin", { blockInternalHosts: true }),
    (error) => {
      assert.equal(error.scope_decision, "blocked");
      assert.match(error.message, /Blocked internal\/private host/);
      return true;
    },
  );
});

test("safeFetch enforces response byte caps without buffering the full body", async () => {
  await withTempHome(async () => {
    const domain = "example.com";
    await withMockSafeFetch({
      "https://example.com/large": { status: 200, body: "abcdef" },
    }, async () => {
      const response = await safeFetch("https://example.com/large", {
        targetDomain: domain,
        maxResponseBytes: 4,
      });
      assert.equal(response.bodyTruncated, true);
      assert.equal(response.bodyByteLength, 6);
      assert.equal(await response.text(), "abcd");
    });
  });
});

test("bob_import_http_traffic validates, dedupes, stores session-local traffic, and briefs only relevant surface traffic", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "EVALUATE", evaluation_wave: 1, pending_wave: 1 });
    seedAttackSurfaces(domain, [
      {
        id: "surface-api",
        hosts: [`https://app.${domain}`],
        tech_stack: ["JSON API"],
        endpoints: ["/api/me"],
        interesting_params: ["id"],
        nuclei_hits: [],
        priority: "LOW",
      },
      {
        id: "surface-admin",
        hosts: [`https://admin.${domain}`],
        tech_stack: ["Custom"],
        endpoints: ["/admin"],
        interesting_params: [],
        nuclei_hits: [],
        priority: "LOW",
      },
    ]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-api" }]);
    const attackSurfaceBeforeImport = fs.readFileSync(attackSurfacePath(domain), "utf8");

    const result = JSON.parse(importHttpTraffic({
      target_domain: domain,
      source: "burp",
      entries: [
        {
          request: {
            method: "GET",
            url: `https://app.${domain}/api/me?id=123`,
            headers: [{ name: "Cookie", value: "sid=redacted" }],
          },
          response: { status: 200 },
          startedDateTime: "2026-04-24T00:00:00.000Z",
        },
        {
          request: {
            method: "GET",
            url: `https://app.${domain}/api/me?id=123#frag`,
            headers: [{ name: "Cookie", value: "sid=redacted" }],
          },
          response: { status: 200 },
        },
        {
          method: "GET",
          url: "https://evil.example.net/api/me",
          status: 200,
        },
        {
          method: "GET",
          status: 200,
        },
      ],
    }));

    assert.equal(result.imported, 1);
    assert.equal(result.duplicates, 1);
    assert.equal(result.rejected, 2);
    assert.ok(fs.existsSync(trafficJsonlPath(domain)));
    assert.equal(readTrafficRecordsFromJsonl(domain).length, 1);
    assert.equal(fs.readFileSync(attackSurfacePath(domain), "utf8"), attackSurfaceBeforeImport);

    const brief = JSON.parse(readAssignmentBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
    assert.equal(brief.traffic_summary.total, 1);
    assert.equal(brief.traffic_summary.authenticated_count, 1);
    assert.match(brief.traffic_summary.recent[0].url, /\/api\/me/);
    assert.equal(brief.surface.priority, "HIGH");
    assert.ok(brief.ranking_summary.reasons.includes("imported_traffic"));
    assert.ok(brief.ranking_summary.reasons.includes("authenticated_observed_traffic"));
    assert.doesNotMatch(JSON.stringify(brief.traffic_summary), /evil\.example\.net/);
    assert.equal(fs.readFileSync(attackSurfacePath(domain), "utf8"), attackSurfaceBeforeImport);
  });
});

test("bob_import_http_traffic redacts persisted URLs and rejected reasons", () => {
  withTempHome(() => {
    const domain = "example.com";
    const result = JSON.parse(importHttpTraffic({
      target_domain: domain,
      source: "burp",
      entries: [
        {
          method: "GET",
          url: "https://app.example.com/api/me?token=secret-token&email=user@example.com&id=123#frag",
          status: 200,
          headers: { Cookie: "sid=secret" },
        },
        {
          method: "GET",
          url: "not a url with token=secret-token",
          status: 200,
        },
      ],
    }));

    assert.equal(result.imported, 1);
    assert.equal(result.rejected, 1);
    assert.doesNotMatch(JSON.stringify(result.rejected_reasons), /secret-token/);

    const records = readTrafficRecordsFromJsonl(domain);
    assert.equal(records.length, 1);
    assert.equal(records[0].url, "https://app.example.com/api/me?token=REDACTED&email=REDACTED&id=REDACTED");
    assert.equal(records[0].path, "/api/me?token=REDACTED&email=REDACTED&id=REDACTED");
    assert.deepEqual(records[0].query_keys, ["email", "id", "token"]);
    assert.doesNotMatch(JSON.stringify(records), /secret-token|user@example\.com|id=123|frag/);
  });
});

test("redactUrlSensitiveValues redacts query values, credentials, and fragments", () => {
  const inputUrl = ["https://", ["alice", "secret"].join(":"), "@example.com/path?token=abc&id=123#frag"].join("");
  const expectedUrl = ["https://", ["REDACTED", "REDACTED"].join(":"), "@example.com/path?token=REDACTED&id=REDACTED"].join("");
  assert.equal(
    redactUrlSensitiveValues(inputUrl),
    expectedUrl,
  );
  assert.equal(redactUrlSensitiveValues("not a url token=abc"), "not a url token=REDACTED");
});

test("legacy raw audit and traffic records are redacted on read", () => {
  withTempHome(() => {
    const domain = "example.com";
    appendJsonlLine(httpAuditJsonlPath(domain), {
      version: 1,
      ts: new Date().toISOString(),
      target_domain: domain,
      method: "GET",
      url: "https://example.com/callback?token=old-secret&id=123#frag",
      host: "example.com",
      path: "/callback?token=old-secret&id=123",
      status: 200,
      error: null,
      scope_decision: "allowed",
      final_url: "https://example.com/done?code=final-secret",
    });
    appendJsonlLine(trafficJsonlPath(domain), {
      version: 1,
      ts: new Date().toISOString(),
      target_domain: domain,
      source: "legacy",
      method: "GET",
      url: "https://app.example.com/api/me?session=old-secret&id=123#frag",
      host: "app.example.com",
      path: "/api/me?session=old-secret&id=123",
      status: 200,
      has_auth: true,
      header_names: ["cookie"],
      query_keys: ["id", "session"],
    });

    const auditRecords = readHttpAuditRecordsFromJsonl(domain);
    const trafficRecords = readTrafficRecordsFromJsonl(domain);
    assert.doesNotMatch(JSON.stringify({ auditRecords, trafficRecords }), /old-secret|final-secret|id=123|frag/);
    assert.equal(auditRecords[0].final_url, "https://example.com/done?code=REDACTED");
    assert.equal(trafficRecords[0].path, "/api/me?session=REDACTED&id=REDACTED");
  });
});

test("bob_import_static_artifact stores redacted session-owned content and rejects unsafe imports", () => {
  withTempHome(() => {
    const domain = "example.com";
    const source = `
      contract RugToken {
        string public apiKey = "super-secret-token-value";
        mapping(address => bool) private _isBlacklisted;
      }
    `;

    assert.throws(
      () => importStaticArtifact({
        target_domain: domain,
        artifact_type: "evm_token_contract",
        path: "/tmp/RugToken.sol",
        content: source,
      }),
      /Path imports are not supported/,
    );
    assert.throws(
      () => importStaticArtifact({
        target_domain: domain,
        artifact_type: "evm_token_contract",
        content: "x".repeat(STATIC_ARTIFACT_MAX_CHARS + 1),
      }),
      /content exceeds static artifact cap/,
    );
    assert.throws(
      () => importStaticArtifact({
        target_domain: domain,
        artifact_type: "evm_token_contract",
        content: source,
      }),
      /Missing session state:/,
    );
    assert.throws(
      () => staticScan({ target_domain: domain, artifact_id: "SA-1" }),
      /Missing session state:/,
    );
    assert.equal(fs.existsSync(sessionDir(domain)), false);
    assert.equal(JSON.parse(initSession({ target_domain: domain, target_url: `https://${domain}` })).created, true);

    const imported = JSON.parse(importStaticArtifact({
      target_domain: domain,
      artifact_type: "evm_token_contract",
      source_name: "/tmp/RugToken.sol",
      label: "Rug token",
      surface_id: "surface-api",
      content: source,
    }));

    assert.equal(imported.artifact_id, "SA-1");
    assert.equal(imported.source_name, "RugToken.sol");
    assert.ok(imported.artifact_path.startsWith(staticArtifactImportDir(domain)));
    assert.equal(imported.artifact_path, staticArtifactPath(domain, "SA-1"));
    assert.ok(fs.existsSync(staticArtifactsJsonlPath(domain)));
    assert.ok(fs.existsSync(staticArtifactPath(domain, "SA-1")));
    assert.equal(readStaticArtifactRecordsFromJsonl(domain).length, 1);

    const stored = fs.readFileSync(staticArtifactPath(domain, "SA-1"), "utf8");
    assert.match(stored, /REDACTED/);
    assert.doesNotMatch(stored, /super-secret-token-value|\/tmp\/RugToken/);
  });
});

test("bob_static_scan reports deduped findings separately from capped returned findings", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "EVALUATE", evaluation_wave: 1, pending_wave: 1 });
    const imported = JSON.parse(importStaticArtifact({
      target_domain: domain,
      artifact_type: "evm_token_contract",
      label: "Duplicate honeypot",
      content: `
        contract DuplicateHoneypot {
          function block(address account) external {
            _isBlacklisted[account] = true;
            _isBlacklisted[account] = true;
            _isBlacklisted[account] = true;
          }
        }
      `,
    }));

    const scan = JSON.parse(staticScan({
      target_domain: domain,
      artifact_id: imported.artifact_id,
      limit: 1,
    }));

    assert.equal(scan.findings_count, 1);
    assert.equal(scan.findings_returned, 1);
    assert.equal(scan.findings_capped, false);
    assert.equal(scan.findings_shown, 1);
    assert.equal(scan.findings_omitted, 0);
    assert.equal(scan.risk_score, 25);
  });
});

test("bob_static_scan scans only imported artifacts and feeds bounded evaluator brief hints", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "EVALUATE", evaluation_wave: 1, pending_wave: 1 });
    seedAttackSurfaces(domain, [
      {
        id: "surface-token",
        hosts: [`https://app.${domain}`],
        tech_stack: ["EVM token"],
        endpoints: ["/token"],
        interesting_params: [],
        nuclei_hits: [],
        priority: "LOW",
      },
    ]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-token" }]);

    const imported = JSON.parse(importStaticArtifact({
      target_domain: domain,
      artifact_type: "evm_token_contract",
      label: "Classic rug",
      source_name: "ClassicRug.sol",
      surface_id: "surface-token",
      content: `
        contract ClassicRug {
          mapping(address => bool) private _isBlacklisted;
          uint256 private _sellFee = 1;
          function blacklist(address account) external onlyOwner {
            _isBlacklisted[account] = true;
          }
          function setFees(uint256 fee) external onlyOwner {
            _sellFee = fee;
          }
          function emergencyWithdraw(address token) external onlyOwner {}
          function renounceOwnership() public override {}
          string private token = "secret-static-token";
        }
      `,
    }));

    assert.throws(
      () => staticScan({ target_domain: domain, artifact_id: "../SA-1" }),
      /artifact_id must match SA-N/,
    );
    assert.throws(
      () => staticScan({ target_domain: domain, artifact_id: "SA-999" }),
      /Static artifact SA-999 not found/,
    );

    const scan = JSON.parse(staticScan({
      target_domain: domain,
      artifact_id: imported.artifact_id,
      scan_type: "token_contract",
      limit: 10,
    }));
    assert.equal(scan.artifact_id, "SA-1");
    assert.equal(scan.chain, "evm");
    assert.ok(scan.risk_score >= 25);
    assert.match(scan.verdict, /RISK/);
    assert.ok(scan.findings.some((finding) => finding.category === "honeypot"));
    assert.ok(scan.findings.some((finding) => finding.category === "lp_drain"));
    assert.ok(fs.existsSync(staticScanResultsJsonlPath(domain)));
    assert.equal(readStaticScanResultsFromJsonl(domain).length, 1);
    assert.doesNotMatch(JSON.stringify(scan), /secret-static-token/);

    const brief = JSON.parse(readAssignmentBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
    assert.equal(brief.static_scan_hints.available, true);
    assert.equal(brief.static_scan_hints.total_results, 1);
    assert.ok(brief.static_scan_hints.findings.length > 0);
    assert.ok(brief.static_scan_hints.findings.length <= 10);
    assert.equal(brief.static_scan_hints.artifacts[0].artifact_id, "SA-1");
    assert.doesNotMatch(JSON.stringify(brief.static_scan_hints), /secret-static-token|_isBlacklisted|evidence/);
  });
});

test("circuit breaker summary marks repeated failures per host without blocking unrelated hosts", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "EVALUATE", evaluation_wave: 1, pending_wave: 1 });
    seedAttackSurfaces(domain, [
      {
        id: "surface-api",
        hosts: [`https://api.${domain}`],
        tech_stack: ["Custom"],
        endpoints: ["/api"],
        interesting_params: [],
        nuclei_hits: [],
        priority: "HIGH",
      },
      {
        id: "surface-app",
        hosts: [`https://app.${domain}`],
        tech_stack: ["Custom"],
        endpoints: ["/home"],
        interesting_params: [],
        nuclei_hits: [],
        priority: "HIGH",
      },
    ]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-api" }]);

    for (const [host, status, error] of [
      [`api.${domain}`, 403, null],
      [`api.${domain}`, 429, null],
      [`api.${domain}`, null, "timeout after 1000ms"],
      [`app.${domain}`, 403, null],
    ]) {
      appendJsonlLine(httpAuditJsonlPath(domain), {
        version: 1,
        ts: new Date().toISOString(),
        target_domain: domain,
        method: "GET",
        url: `https://${host}/api`,
        host,
        path: "/api",
        status,
        error,
        scope_decision: error ? "request_error" : "allowed",
      });
    }

    const brief = JSON.parse(readAssignmentBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
    assert.equal(brief.circuit_breaker_summary.tripped_count, 1);
    assert.equal(brief.circuit_breaker_summary.tripped_hosts[0].host, `api.${domain}`);
    assert.doesNotMatch(JSON.stringify(brief.circuit_breaker_summary), new RegExp(`app\\.${domain}`));
  });
});

test("buildCircuitBreakerSummary surfaces below-threshold per-host failures in below_threshold_hosts", () => {
  // The veda.tech regression: 2 internal errors + 2 network-unreachable
  // events on the same host produced no tripped breaker (below the
  // ≥3-per-host threshold) and no near-threshold visibility either.
  // Operators looking at a session with errors but no warnings could not
  // tell whether the threshold was reached and suppressed or never crossed.
  // below_threshold_hosts surfaces that data without false escalation.
  const records = [
    {
      version: 1,
      ts: "2026-05-02T00:00:00.000Z",
      target_domain: "example.com",
      method: "GET",
      url: "https://api.example.com/x",
      host: "api.example.com",
      status: 200,
      error: null,
      scope_decision: "allowed",
    },
    {
      version: 1,
      ts: "2026-05-02T00:00:01.000Z",
      target_domain: "example.com",
      method: "GET",
      url: "https://api.example.com/x",
      host: "api.example.com",
      status: 403,
      error: null,
      scope_decision: "allowed",
    },
    {
      version: 1,
      ts: "2026-05-02T00:00:02.000Z",
      target_domain: "example.com",
      method: "GET",
      url: "https://api.example.com/y",
      host: "api.example.com",
      status: null,
      error: "timeout after 5000ms",
      scope_decision: "request_error",
    },
    // A host with 3 failures — crosses the threshold and should appear in
    // tripped_hosts, NOT in below_threshold_hosts.
    {
      version: 1,
      ts: "2026-05-02T00:00:03.000Z",
      target_domain: "example.com",
      method: "GET",
      url: "https://hot.example.com/z",
      host: "hot.example.com",
      status: 429,
      error: null,
      scope_decision: "allowed",
    },
    {
      version: 1,
      ts: "2026-05-02T00:00:04.000Z",
      target_domain: "example.com",
      method: "GET",
      url: "https://hot.example.com/z",
      host: "hot.example.com",
      status: 429,
      error: null,
      scope_decision: "allowed",
    },
    {
      version: 1,
      ts: "2026-05-02T00:00:05.000Z",
      target_domain: "example.com",
      method: "GET",
      url: "https://hot.example.com/z",
      host: "hot.example.com",
      status: 403,
      error: null,
      scope_decision: "allowed",
    },
  ];

  const summary = buildCircuitBreakerSummary(records);
  assert.equal(summary.tripped_count, 1);
  assert.equal(summary.tripped_hosts[0].host, "hot.example.com");
  assert.equal(summary.below_threshold_count, 1);
  assert.equal(summary.below_threshold_hosts[0].host, "api.example.com");
  assert.equal(summary.below_threshold_hosts[0].failures, 2);
  // No host appears in both lists.
  assert.equal(
    summary.below_threshold_hosts.some((item) => item.host === "hot.example.com"),
    false,
  );
});

test("pipeline analytics surfaces egress and geofence warnings from HTTP audit", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "EVALUATE", evaluation_wave: 1, pending_wave: null });

    for (let index = 0; index < 3; index += 1) {
      appendHttpAuditRecord({
        version: 1,
        ts: new Date(Date.now() + index).toISOString(),
        target_domain: domain,
        method: "GET",
        url: `https://api.${domain}/blocked-${index}`,
        host: `api.${domain}`,
        path: `/blocked-${index}`,
        status: null,
        error: "timeout after 1000ms",
        scope_decision: "network_unreachable_target",
        egress_profile: "default",
        egress_region: null,
        block_internal_hosts: index === 0,
        block_internal_hosts_source: index === 0 ? "request_override" : "mode_default",
      });
    }

    const analytics = JSON.parse(readPipelineAnalytics({ target_domain: domain }));
    assert.equal(analytics.sessions[0].egress.by_profile.default, 3);
    assert.equal(analytics.sessions[0].http_audit.block_internal_hosts.true, 1);
    assert.equal(analytics.sessions[0].http_audit.block_internal_hosts.false, 2);
    assert.equal(analytics.sessions[0].http_audit.block_internal_hosts.by_source.request_override, 1);
    assert.equal(analytics.sessions[0].geofence_warnings.warning, true);
    assert.equal(analytics.sessions[0].geofence_warnings.code, "network_unreachable_target");
    assert.ok(analytics.bottlenecks.some((item) => item.code === "network_unreachable_target"));
    assert.doesNotMatch(JSON.stringify(analytics), /proxy_url|https?:\/\/|socks5/i);
  });
});

test("bob_public_intel caps output, persists optional intel, handles API failures, and feeds evaluator brief hints", async () => {
  await withTempHome(async () => {
    const domain = "example.com";
    const previousFetch = global.fetch;
    try {
      global.fetch = async (url) => {
        const textUrl = String(url);
        if (textUrl.includes("/example-program.json")) {
          return new Response(JSON.stringify({
            handle: "example-program",
            name: "Example Program",
            policy: "Only test owned assets. Report IDOR and auth bypass with proof.",
            offers_bounties: true,
            resolved_report_count: 42,
            structured_scopes: [
              { asset_identifier: `*.${domain}`, asset_type: "URL", eligible_for_bounty: true, instruction: "Main app and API." },
            ],
          }), { status: 200, headers: { "content-type": "application/json" } });
        }
        if (textUrl.includes("hacktivity")) {
          return new Response('<a href="/reports/123">IDOR in team export</a><a href="/reports/456">GraphQL auth bypass</a>', {
            status: 200,
            headers: { "content-type": "text/html" },
          });
        }
        return new Response("no", { status: 500 });
      };

      seedSessionState(domain, { phase: "EVALUATE", evaluation_wave: 1, pending_wave: 1 });
      seedAttackSurfaces(domain, [{
        id: "surface-api",
        hosts: [`https://app.${domain}`],
        tech_stack: ["GraphQL"],
        endpoints: ["/graphql", "/api/team/export"],
        interesting_params: ["team_id"],
        nuclei_hits: [],
        priority: "LOW",
      }]);
      seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-api" }]);
      const attackSurfaceBeforeIntel = fs.readFileSync(attackSurfacePath(domain), "utf8");

      const result = JSON.parse(await bountyPublicIntel({
        target_domain: domain,
        program: "https://hackerone.com/example-program",
        keywords: ["team export", "graphql"],
        limit: 1,
      }));
      assert.equal(result.disclosed_reports.length, 1);
      assert.equal(result.structured_scopes.length, 1);
      assert.equal(result.program_stats.resolved_report_count, 42);
      assert.match(result.policy_summary, /Only test owned assets/);
      assert.ok(fs.existsSync(publicIntelPath(domain)));
      assert.equal(fs.readFileSync(attackSurfacePath(domain), "utf8"), attackSurfaceBeforeIntel);

      const brief = JSON.parse(readAssignmentBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
      assert.equal(brief.intel_hints.available, true);
      assert.equal(brief.intel_hints.reports.length, 1);
      assert.ok(brief.ranking_summary.reasons.includes("disclosed_report_hints"));
      assert.equal(fs.readFileSync(attackSurfacePath(domain), "utf8"), attackSurfaceBeforeIntel);

      global.fetch = async () => { throw new Error("network down"); };
      const failed = JSON.parse(await bountyPublicIntel({ target_domain: "empty.example", keywords: ["none"], limit: 2 }));
      assert.equal(failed.disclosed_reports.length, 0);
      assert.ok(failed.errors.some((error) => /network down/.test(error)));
    } finally {
      global.fetch = previousFetch;
    }
  });
});

test("public intel fetch helper enforces HackerOne allowlist and response cap", async () => {
  const previousFetch = global.fetch;
  let called = false;
  try {
    global.fetch = async () => {
      called = true;
      return new Response("abcdef", { status: 200, headers: { "content-type": "text/html" } });
    };

    await assert.rejects(
      () => fetchTextWithTimeout("https://example.com/hacktivity"),
      /not allowlisted/,
    );
    assert.equal(called, false);

    const fetched = await fetchTextWithTimeout("https://hackerone.com/hacktivity?querystring=example", {
      maxBytes: 4,
    });
    assert.equal(fetched.ok, true);
    assert.equal(fetched.text, "abcd");
    assert.equal(fetched.truncated, true);
  } finally {
    global.fetch = previousFetch;
  }
});

test("rankAttackSurfaces returns ranking fields without mutating attack_surface.json", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedAttackSurfaces(domain, [{
      id: "surface-api",
      hosts: [`https://api.${domain}`],
      tech_stack: ["REST"],
      endpoints: ["/api/v1/users/{id}", "/billing/refund"],
      interesting_params: ["user_id", "account_id"],
      nuclei_hits: ["swagger exposed"],
      priority: "LOW",
    }]);

    const before = fs.readFileSync(attackSurfacePath(domain), "utf8");
    const ranked = rankAttackSurfaces(domain);
    assert.equal(ranked.surfaces.length, 1);
    const surface = ranked.surfaces[0];
    for (const field of ["id", "hosts", "tech_stack", "endpoints", "interesting_params", "nuclei_hits", "priority"]) {
      assert.ok(Object.prototype.hasOwnProperty.call(surface, field), `missing ${field}`);
    }
    assert.ok(surface.ranking.score > 0);
    assert.ok(surface.ranking.reasons.includes("api_or_mobile_surface"));
    assert.ok(priorityRankForTest(surface.priority) >= priorityRankForTest("HIGH"));
    assert.equal(fs.readFileSync(attackSurfacePath(domain), "utf8"), before);
  });
});

test("read-style status and evaluator brief compute ranking without mutating attack_surface.json", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "EVALUATE", evaluation_wave: 1, pending_wave: 1 });
    seedAttackSurfaces(domain, [{
      id: "surface-api",
      hosts: [`https://api.${domain}`],
      tech_stack: ["REST"],
      endpoints: ["/api/v1/users/{id}"],
      interesting_params: ["user_id"],
      nuclei_hits: ["swagger exposed"],
      priority: "LOW",
    }]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-api" }]);

    const before = fs.readFileSync(attackSurfacePath(domain), "utf8");
    const brief = JSON.parse(readAssignmentBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
    const status = JSON.parse(waveStatus({ target_domain: domain }));
    const after = fs.readFileSync(attackSurfacePath(domain), "utf8");

    assert.equal(after, before);
    assert.equal(brief.surface.priority, "HIGH");
    assert.ok(brief.ranking_summary.reasons.includes("api_or_mobile_surface"));
    assert.equal(status.coverage.unexplored_high, 1);
  });
});

function priorityRankForTest(priority) {
  return { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 }[String(priority || "").toUpperCase()] || 0;
}

// ── bob_read_assignment_brief tests ──

test("bob_read_assignment_brief returns surface, exclusions, and valid IDs", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, {
      phase: "EVALUATE",
      evaluation_wave: 1,
      pending_wave: 1,
      dead_ends: ["/api/old"],
      waf_blocked_endpoints: ["/admin"],
      scope_exclusions: ["third-party.com"],
    });
    seedAttackSurface(domain, ["surface-a", "surface-b"]);
    seedAssignments(domain, 1, [
      { agent: "a1", surface_id: "surface-a" },
      { agent: "a2", surface_id: "surface-b" },
    ]);

    const document = {
      version: 1,
      profiles: [
        egressProfiles.defaultEgressProfile(),
        {
          name: "operator-eu",
          proxy_url: null,
          region: "EU",
          description: "Operator direct EU profile",
          enabled: true,
        },
      ],
    };

    withDefaultEgressConfig(document, () => {
    const expectedEgress = egressProfiles.egressProfileIdentityFields(
      egressProfiles.resolveEgressProfile("operator-eu"),
    );
    const brief = JSON.parse(readAssignmentBrief({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      egress_profile: "operator-eu",
      block_internal_hosts: true,
    }));

    assert.deepEqual(brief.run_context, {
      target_domain: domain,
      lifecycle_state: "OPEN_FRONTIER",
      phase: "EVALUATE",
      auth_status: "pending",
      egress_profile: "operator-eu",
      egress_region: "EU",
      proxy_configured: false,
      egress_profile_identity_hash: expectedEgress.egress_profile_identity_hash,
      egress_profile_identity_version: expectedEgress.egress_profile_identity_version,
      checkpoint_mode: "normal",
      block_internal_hosts: true,
      block_internal_hosts_source: "request_override",
      capability_pack: "web",
      capability_pack_version: 1,
      evaluator_agent: "evaluator-agent",
      brief_profile: "web",
      context_budget: expectedWebContextBudget(),
    });
    assert.equal(brief.wave, "w1");
    assert.equal(brief.agent, "a1");
    assert.equal(brief.surface.id, "surface-a");
    assert.deepEqual(brief.valid_surface_ids, ["surface-a", "surface-b"]);
    assert.deepEqual(brief.dead_ends, ["/api/old"]);
    assert.deepEqual(brief.waf_blocked_endpoints, ["/admin"]);
    assert.strictEqual(brief.scope_exclusions, undefined);
    assert.ok(brief.exclusions_summary);
    assert.equal(brief.exclusions_summary.dead_ends_total, 1);
    assert.equal(brief.exclusions_summary.waf_blocked_total, 1);
    assert.equal(brief.auth_hint, undefined);
    assert.match(brief.auth_profiles_hint, /bob_list_auth_profiles/);
    assert.doesNotMatch(JSON.stringify(brief), /auth\.json/i);
    // Web brief shape: include the HTTP-flavored intel fields, omit SC-only fields.
    assert.ok(Object.prototype.hasOwnProperty.call(brief, "bypass_table"), "web brief must expose bypass_table");
    assert.ok(Object.prototype.hasOwnProperty.call(brief, "techniques"), "web brief must expose techniques");
    assert.ok(Object.prototype.hasOwnProperty.call(brief, "payload_hints"), "web brief must expose payload_hints");
    assert.ok(Object.prototype.hasOwnProperty.call(brief, "knowledge_summary"), "web brief must expose knowledge_summary");
    assert.ok(Object.prototype.hasOwnProperty.call(brief, "technique_packs"), "web brief must expose canonical technique_packs");
    assert.equal(brief.technique_packs.selection_budget.attempt_log_required, true);
    assert.deepEqual(brief.technique_packs.registry_warnings, []);
    assert.ok(brief.techniques.length <= 2);
    assert.ok(brief.payload_hints.length <= 2);
    assert.ok(Object.prototype.hasOwnProperty.call(brief, "traffic_summary"), "web brief must expose traffic_summary");
    assert.ok(Object.prototype.hasOwnProperty.call(brief, "audit_summary"), "web brief must expose audit_summary");
    assert.ok(Object.prototype.hasOwnProperty.call(brief, "circuit_breaker_summary"), "web brief must expose circuit_breaker_summary");
    assert.ok(Object.prototype.hasOwnProperty.call(brief, "intel_hints"), "web brief must expose intel_hints");
    assert.ok(Object.prototype.hasOwnProperty.call(brief, "static_scan_hints"), "web brief must expose static_scan_hints");
    assert.strictEqual(brief.bob_spec_status, undefined);
    assert.strictEqual(brief.rpc_pool, undefined);
    });
  });
});

test("bob_read_assignment_brief reports persisted internal-host policy when omitted", () => {
  withTempHome(() => {
    const domain = "paranoid-brief.example.com";
    seedSessionState(domain, {
      phase: "EVALUATE",
      evaluation_wave: 1,
      pending_wave: 1,
      checkpoint_mode: "paranoid",
      block_internal_hosts: true,
      block_internal_hosts_source: "paranoid_default",
    });
    seedAttackSurface(domain, ["surface-a"]);
    seedAssignments(domain, 1, [
      { agent: "a1", surface_id: "surface-a" },
    ]);

    const brief = JSON.parse(readAssignmentBrief({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
    }));
    assert.equal(brief.run_context.checkpoint_mode, "paranoid");
    assert.equal(brief.run_context.block_internal_hosts, true);
    assert.equal(brief.run_context.block_internal_hosts_source, "paranoid_default");
  });
});

test("bob_read_assignment_brief uses smart_contract_evm shape when the assignment routes to that pack", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, {
      phase: "EVALUATE",
      evaluation_wave: 1,
      pending_wave: 1,
      dead_ends: [],
      waf_blocked_endpoints: [],
    });
    seedAttackSurfaces(domain, [{
      id: "surface-evm-1",
      surface_type: "smart_contract",
      chain_family: "evm",
      chain_id: "1",
      hosts: [`https://${domain}`],
      foundry_harness_path: "/tmp/harness/evm",
    }]);
    seedAssignments(domain, 1, [{
      agent: "a1",
      surface_id: "surface-evm-1",
      capability_pack: "smart_contract_evm",
      evaluator_agent: "evaluator-evm-agent",
      brief_profile: "smart_contract_evm",
    }]);

    const brief = JSON.parse(readAssignmentBrief({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
    }));

    assert.equal(brief.run_context.capability_pack, "smart_contract_evm");
    assert.equal(brief.run_context.brief_profile, "smart_contract_evm");
    assert.equal(brief.run_context.evaluator_agent, "evaluator-evm-agent");
    assert.deepEqual(brief.run_context.context_budget, expectedSmartContractContextBudget());

    // SC profile must expose typed bob_spec_status and rpc_pool, not just
    // a present-but-undefined slot. hasOwnProperty + null-guard catches
    // the regression where dispatch returns the wrong shape.
    assert.ok(brief.bob_spec_status, "smart-contract brief must expose bob_spec_status");
    assert.equal(typeof brief.bob_spec_status, "object");
    assert.equal(typeof brief.bob_spec_status.present, "boolean");
    assert.ok(Object.prototype.hasOwnProperty.call(brief, "rpc_pool"), "smart-contract brief must expose rpc_pool");
    assert.equal(typeof brief.rpc_pool, "object");
    assert.ok(Array.isArray(brief.rpc_pool.endpoints) || brief.rpc_pool.endpoints == null);
    assert.equal(brief.surface.foundry_harness_path, "/tmp/harness/evm",
      "EVM evaluator must receive its foundry_harness_path scalar");

    // SC profile: omit the web-flavored fields the SC evaluator doesn't have tools for.
    for (const webField of [
      "bypass_table",
      "techniques",
      "payload_hints",
      "knowledge_summary",
      "traffic_summary",
      "audit_summary",
      "circuit_breaker_summary",
      "intel_hints",
      "static_scan_hints",
      "auth_profiles_hint",
    ]) {
      assert.ok(
        !Object.prototype.hasOwnProperty.call(brief, webField),
        `smart-contract brief must omit ${webField} (web-flavored)`,
      );
    }

    // Cross-cutting fields stay in both profiles.
    for (const sharedField of [
      "run_context",
      "target_url",
      "wave",
      "agent",
      "surface",
      "surface_limits",
      "valid_surface_ids",
      "dead_ends",
      "waf_blocked_endpoints",
      "exclusions_summary",
      "coverage_summary",
      "ranking_summary",
    ]) {
      assert.ok(
        Object.prototype.hasOwnProperty.call(brief, sharedField),
        `smart-contract brief must keep cross-cutting ${sharedField}`,
      );
    }
  });
});

test("bob_read_assignment_brief preserves per-chain harness paths for every smart-contract pack", () => {
  // slimSurfaceForBrief whitelists each chain's harness_path scalar.
  // SVM/Move/Substrate/CosmWasm evaluator prompts read anchor_harness_path /
  // move_harness_path / ink_harness_path / cargo_harness_path /
  // cosmwasm_harness_path; if those get stripped, evaluators falsely report
  // missing harnesses and write partial handoffs.
  const cases = [
    { pack: "smart_contract_svm",       chain_family: "svm",       agent: "evaluator-svm-agent",       field: "anchor_harness_path",   value: "/tmp/harness/svm" },
    { pack: "smart_contract_aptos",     chain_family: "aptos",     agent: "evaluator-move-agent",      field: "move_harness_path",     value: "/tmp/harness/aptos" },
    { pack: "smart_contract_sui",       chain_family: "sui",       agent: "evaluator-move-agent",      field: "move_harness_path",     value: "/tmp/harness/sui" },
    { pack: "smart_contract_substrate", chain_family: "substrate", agent: "evaluator-substrate-agent", field: "ink_harness_path",      value: "/tmp/harness/ink" },
    { pack: "smart_contract_substrate", chain_family: "substrate", agent: "evaluator-substrate-agent", field: "cargo_harness_path",    value: "/tmp/harness/cargo" },
    { pack: "smart_contract_cosmwasm",  chain_family: "cosmwasm",  agent: "evaluator-cosmwasm-agent",  field: "cosmwasm_harness_path", value: "/tmp/harness/cw" },
  ];
  for (const { pack, chain_family, agent, field, value } of cases) {
    withTempHome(() => {
      const domain = "example.com";
      seedSessionState(domain, { phase: "EVALUATE", evaluation_wave: 1, pending_wave: 1 });
      seedAttackSurfaces(domain, [{
        id: "sc-1",
        surface_type: "smart_contract",
        chain_family,
        chain_id: "1",
        hosts: [`https://${domain}`],
        [field]: value,
      }]);
      seedAssignments(domain, 1, [{
        agent: "a1",
        surface_id: "sc-1",
        capability_pack: pack,
        evaluator_agent: agent,
        brief_profile: pack,
      }]);
      const brief = JSON.parse(readAssignmentBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
      assert.equal(brief.surface[field], value, `${pack} evaluator must receive ${field}`);
    });
  }
});

test("bob_read_assignment_brief throws on an unsupported brief_profile rather than fail-open to smart-contract", () => {
  // Regression guard for fail-open: the dispatch must reject profiles the
  // capability-pack registry never declared, even if route metadata is
  // forged on disk.
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "EVALUATE", evaluation_wave: 1, pending_wave: 1 });
    seedAttackSurface(domain, ["surface-a"]);
    // We can't get an unsupported profile through normalizeAssignmentRouteMetadata
    // because that itself validates against the pack registry. So we forge the
    // assignment file directly to reach the dispatch.
    const dir = sessionDir(domain);
    const assignmentsPath = path.join(dir, "wave-1-assignments.json");
    fs.writeFileSync(assignmentsPath, JSON.stringify({
      wave_number: 1,
      assignments: [{
        agent: "a1",
        surface_id: "surface-a",
        capability_pack: "smart_contract_evm",
        evaluator_agent: "evaluator-evm-agent",
        brief_profile: "smart_contract_evm",
      }],
    }));
    // Sanity: this assignment is valid and produces an SC brief.
    JSON.parse(readAssignmentBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
    // Mutate the on-disk assignment to a profile no pack declares. The
    // route-metadata validator rejects it before dispatch, which is the
    // correct fail-loud behavior.
    fs.writeFileSync(assignmentsPath, JSON.stringify({
      wave_number: 1,
      assignments: [{
        agent: "a1",
        surface_id: "surface-a",
        capability_pack: "experimental_mobile",
        evaluator_agent: "mobile-evaluator-agent",
        brief_profile: "mobile_api",
      }],
    }));
    assert.throws(
      () => readAssignmentBrief({ target_domain: domain, wave: "w1", agent: "a1" }),
      /unknown capability_pack|Unsupported brief profile/,
    );
  });
});

test("bob_read_assignment_brief caps assigned surface arrays and reports surface_limits", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "EVALUATE", evaluation_wave: 1, pending_wave: 1 });
    seedAttackSurfaces(domain, [{
      id: "surface-rich",
      priority: "HIGH",
      hosts: Array.from({ length: 25 }, (_, index) => `https://h${index}.${domain}`),
      tech_stack: Array.from({ length: 25 }, (_, index) => `tech-${index}`),
      endpoints: Array.from({ length: 90 }, (_, index) => `/api/${index}`),
      interesting_params: Array.from({ length: 45 }, (_, index) => `param_${index}`),
      nuclei_hits: Array.from({ length: 35 }, (_, index) => `hit-${index}`),
      bug_class_hints: Array.from({ length: 25 }, (_, index) => `bug-${index}`),
      high_value_flows: Array.from({ length: 25 }, (_, index) => `flow-${index}`),
      evidence: Array.from({ length: 30 }, (_, index) => `evidence-${index}`),
      js_hints: Array.from({ length: 200 }, (_, index) => `js-${index}`),
      ranking: { version: 1, score: 77, priority: "HIGH", reasons: ["api_or_mobile_surface"] },
    }]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-rich" }]);

    const brief = JSON.parse(readAssignmentBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
    assert.equal(brief.surface.id, "surface-rich");
    assert.equal(brief.surface.priority, "HIGH");
    assert.equal(brief.surface.ranking.version, 1);
    assert.ok(Array.isArray(brief.surface.ranking.reasons));
    assert.equal(brief.surface.hosts.length, 20);
    assert.equal(brief.surface.endpoints.length, 80);
    assert.equal(brief.surface.interesting_params.length, 40);
    assert.equal(brief.surface.nuclei_hits.length, 30);
    assert.equal(brief.surface.bug_class_hints.length, 20);
    assert.equal(brief.surface.high_value_flows.length, 20);
    assert.equal(brief.surface.evidence.length, 25);
    assert.equal(brief.surface.js_hints, undefined);
    assert.deepEqual(brief.surface_limits.hosts, { shown: 20, total: 25, omitted: 5 });
    assert.deepEqual(brief.surface_limits.endpoints, { shown: 80, total: 90, omitted: 10 });
  });
});

test("bob_read_assignment_brief caps scalar strings and omits unknown scalar fields", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "EVALUATE", evaluation_wave: 1, pending_wave: 1 });
    const huge = "x".repeat(5000);
    seedAttackSurfaces(domain, [{
      id: "surface-scalar",
      hosts: [`https://${domain}`],
      tech_stack: ["Custom"],
      endpoints: [`/${huge}`],
      interesting_params: ["id"],
      priority: "HIGH",
      surface_type: huge,
      description: huge,
      surface_discovery_blob: huge,
    }]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-scalar" }]);

    const brief = JSON.parse(readAssignmentBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
    assert.equal(brief.surface.surface_type.length, 80);
    assert.equal(brief.surface.description.length, 500);
    assert.equal(brief.surface.endpoints[0].length, 500);
    assert.equal(brief.surface.surface_discovery_blob, undefined);
    assert.deepEqual(brief.surface_limits.surface_type, {
      shown_chars: 80,
      total_chars: 5000,
      omitted_chars: 4920,
    });
    assert.deepEqual(brief.surface_limits.description, {
      shown_chars: 500,
      total_chars: 5000,
      omitted_chars: 4500,
    });
    assert.equal(brief.surface_limits.endpoints.truncated_values, 1);
    assert.equal(brief.surface_limits.endpoints.max_value_chars, 500);
    assert.doesNotMatch(JSON.stringify(brief), new RegExp("x{1000}"));
  });
});

test("bob_read_assignment_brief includes assigned-surface coverage summary with latest-per-key dedupe", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "EVALUATE", evaluation_wave: 1, pending_wave: 1 });
    seedAttackSurface(domain, ["surface-a", "surface-b"]);
    seedAssignments(domain, 1, [
      { agent: "a1", surface_id: "surface-a" },
      { agent: "a2", surface_id: "surface-b" },
    ]);

    logCoverage({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      entries: [
        {
          endpoint: "/api/v1/users/123",
          method: "get",
          bug_class: "IDOR",
          auth_profile: "attacker-victim",
          status: "tested",
          evidence_summary: "first replay returned 403",
        },
        {
          endpoint: "/api/v1/users/123",
          method: "GET",
          bug_class: "idor",
          auth_profile: "attacker-victim",
          status: "promising",
          evidence_summary: "legacy query param still returns profile metadata",
          next_step: "try export route",
        },
        {
          endpoint: "/search",
          method: "POST",
          bug_class: "xss",
          status: "blocked",
          evidence_summary: "WAF blocks reflected payloads",
        },
      ],
    });
    logCoverage({
      target_domain: domain,
      wave: "w1",
      agent: "a2",
      surface_id: "surface-b",
      entries: [{
        endpoint: "/admin",
        bug_class: "authz",
        status: "promising",
        evidence_summary: "admin path reveals feature flags",
      }],
    });

    const brief = JSON.parse(readAssignmentBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
    assert.equal(brief.coverage_summary.surface_id, "surface-a");
    assert.equal(brief.coverage_summary.total, 2);
    assert.equal(brief.coverage_summary.shown, 2);
    assert.equal(brief.coverage_summary.omitted, 0);
    assert.deepEqual(brief.coverage_summary.tested, []);
    assert.equal(brief.coverage_summary.promising.length, 1);
    assert.equal(brief.coverage_summary.promising[0].endpoint, "/api/v1/users/123");
    assert.equal(brief.coverage_summary.promising[0].method, "GET");
    assert.equal(brief.coverage_summary.promising[0].bug_class, "idor");
    assert.equal(brief.coverage_summary.promising[0].next_step, "try export route");
    assert.equal(brief.coverage_summary.blocked.length, 1);
    assert.equal(brief.coverage_summary.blocked[0].endpoint, "/search");
    assert.doesNotMatch(JSON.stringify(brief.coverage_summary), /\/admin/);
  });
});

test("bob_read_assignment_brief caps coverage summary output", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "EVALUATE", evaluation_wave: 1, pending_wave: 1 });
    seedAttackSurface(domain, ["surface-a"]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);

    logCoverage({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      entries: Array.from({ length: 45 }, (_, index) => ({
        endpoint: `/api/v1/items/${index}`,
        method: "GET",
        bug_class: "idor",
        status: "tested",
        evidence_summary: `item ${index} returned 403`,
      })),
    });

    const brief = JSON.parse(readAssignmentBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
    assert.equal(brief.coverage_summary.total, 45);
    assert.equal(brief.coverage_summary.shown, 40);
    assert.equal(brief.coverage_summary.omitted, 5);
    assert.equal(brief.coverage_summary.tested.length, 40);

    const directSummary = buildCoverageSummaryForSurface(readCoverageRecordsFromJsonl(domain), "surface-a", 3);
    assert.equal(directSummary.total, 45);
    assert.equal(directSummary.shown, 3);
    assert.equal(directSummary.omitted, 42);
  });
});

test("bob_read_assignment_brief rejects unassigned agent", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "EVALUATE", evaluation_wave: 1, pending_wave: 1 });
    seedAttackSurface(domain, ["surface-a"]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);

    assert.throws(
      () => readAssignmentBrief({ target_domain: domain, wave: "w1", agent: "a9" }),
      /Agent a9 is not assigned/,
    );
  });
});

test("runtime resource resolution prefers neutral env paths and preserves Claude fallback", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-resources-"));
  try {
    const neutralResources = path.join(root, "neutral-resources");
    const claudeProject = path.join(root, "claude-project");
    fs.mkdirSync(path.join(neutralResources, "knowledge"), { recursive: true });
    fs.mkdirSync(path.join(root, "bob-project", ".hacker-bob"), { recursive: true });
    fs.mkdirSync(path.join(claudeProject, ".claude", "knowledge"), { recursive: true });
    fs.writeFileSync(path.join(neutralResources, "knowledge", "source.txt"), "neutral\n", "utf8");
    fs.writeFileSync(path.join(root, "bob-project", ".hacker-bob", "VERSION"), "9.8.7\n", "utf8");
    fs.writeFileSync(path.join(claudeProject, ".claude", "knowledge", "source.txt"), "claude\n", "utf8");

    assert.equal(bobVersion({ BOB_PROJECT_DIR: path.join(root, "bob-project") }), "9.8.7");
    assert.equal(runtimeClient({ BOB_CLIENT: "codex" }), "codex");

    withEnv({
      BOB_CLIENT: "codex",
      BOB_PROJECT_DIR: path.join(root, "bob-project"),
      BOB_RESOURCE_DIR: neutralResources,
      CLAUDE_PROJECT_DIR: claudeProject,
    }, () => {
      assert.equal(runtimeClient(), "codex");
      assert.equal(bobVersion(), "9.8.7");
      assert.equal(readResourceText("knowledge", "source.txt"), "neutral\n");
      assert.equal(resolveResourcePath("knowledge", "source.txt"), path.join(neutralResources, "knowledge", "source.txt"));
    });

    withEnv({
      BOB_VERSION: "8.8.8",
      BOB_CLIENT: undefined,
      BOB_PROJECT_DIR: undefined,
      BOB_RESOURCE_DIR: undefined,
      CLAUDE_PROJECT_DIR: claudeProject,
    }, () => {
      assert.equal(runtimeClient(), "claude");
      assert.equal(bobVersion(), "8.8.8");
      assert.equal(readResourceText("knowledge", "source.txt"), "claude\n");
      assert.equal(resolveResourcePath("knowledge", "source.txt"), path.join(claudeProject, ".claude", "knowledge", "source.txt"));
    });
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("bob_read_assignment_brief loads knowledge and bypass tables from BOB_RESOURCE_DIR", () => {
  const resources = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-resource-dir-"));
  try {
    fs.mkdirSync(path.join(resources, "knowledge"), { recursive: true });
    fs.mkdirSync(path.join(resources, "bypass-tables"), { recursive: true });
    fs.writeFileSync(path.join(resources, "bypass-tables", "rest-api.txt"), "CUSTOM REST BYPASS TABLE\n", "utf8");
    fs.writeFileSync(path.join(resources, "knowledge", "evaluator-techniques.json"), `${JSON.stringify({
      version: 1,
      entries: [{
        id: "acmecms",
        title: "AcmeCMS custom guidance",
        match: { tech: ["acmecms"] },
        techniques: ["Use the adapter-provided knowledge directory for AcmeCMS checks."],
        payload_hints: ["/acme/admin/export"],
      }],
    }, null, 2)}\n`, "utf8");

    withTempHome(() => withEnv({
      BOB_RESOURCE_DIR: resources,
      BOB_PROJECT_DIR: undefined,
      CLAUDE_PROJECT_DIR: undefined,
    }, () => {
      const domain = "example.com";
      seedSessionState(domain, { phase: "EVALUATE", evaluation_wave: 1, pending_wave: 1 });
      seedAttackSurfaces(domain, [{
        id: "surface-custom",
        hosts: [`https://${domain}`],
        tech_stack: ["AcmeCMS"],
        endpoints: ["/acme"],
        interesting_params: ["id"],
      }]);
      seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-custom" }]);

      const brief = JSON.parse(readAssignmentBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
      assert.equal(brief.bypass_table, "CUSTOM REST BYPASS TABLE");
      assert.deepEqual(brief.techniques.map((entry) => entry.id), ["acmecms"]);
      assert.match(JSON.stringify(brief.payload_hints), /\/acme\/admin\/export/);
    }));
  } finally {
    fs.rmSync(resources, { recursive: true, force: true });
  }
});

test("bob_read_assignment_brief includes WordPress-specific curated guidance", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "EVALUATE", evaluation_wave: 1, pending_wave: 1 });
    seedAttackSurfaces(domain, [{
      id: "surface-wp",
      hosts: [`https://${domain}`],
      tech_stack: ["WordPress", "PHP"],
      endpoints: ["/wp-json/wp/v2/users", "/wp-admin/admin-ajax.php"],
      interesting_params: ["author", "action", "nonce"],
    }]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-wp" }]);

    const brief = JSON.parse(readAssignmentBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
    assert.ok(brief.techniques.some((entry) => entry.id === "wordpress"));
    assert.ok(brief.payload_hints.some((entry) => entry.id === "wordpress"));
    assert.match(JSON.stringify(brief.techniques), /WordPress/);
  });
});

test("bob_read_assignment_brief includes GraphQL-specific curated guidance", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "EVALUATE", evaluation_wave: 1, pending_wave: 1 });
    seedAttackSurfaces(domain, [{
      id: "surface-graphql",
      hosts: [`https://${domain}`],
      tech_stack: ["GraphQL", "Apollo"],
      endpoints: ["/graphql"],
      interesting_params: ["query", "variables", "operationName"],
    }]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-graphql" }]);

    const brief = JSON.parse(readAssignmentBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
    assert.ok(brief.techniques.some((entry) => entry.id === "graphql"));
    assert.match(JSON.stringify(brief.payload_hints), /alias|updateUserRole|__schema/i);
  });
});

test("bob_read_assignment_brief includes generic REST/API guidance for API surfaces", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "EVALUATE", evaluation_wave: 1, pending_wave: 1 });
    seedAttackSurfaces(domain, [{
      id: "surface-api",
      hosts: [`https://api.${domain}`],
      tech_stack: ["Express", "JSON API"],
      endpoints: ["/api/v1/users/123", "/api/v2/admin/export"],
      interesting_params: ["id", "user_id", "role", "limit"],
    }]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-api" }]);

    const brief = JSON.parse(readAssignmentBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
    assert.ok(brief.techniques.some((entry) => entry.id === "generic-rest-api"));
    assert.match(JSON.stringify(brief.techniques), /object access|parser differentials|old API versions/i);
  });
});

test("bob_read_assignment_brief matches IDOR and authz bug_class_hints to REST/API authorization guidance", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "EVALUATE", evaluation_wave: 1, pending_wave: 1 });
    seedAttackSurfaces(domain, [{
      id: "surface-object-access",
      hosts: [`https://app.${domain}`],
      tech_stack: ["Custom"],
      endpoints: ["/dashboard"],
      interesting_params: ["q"],
      bug_class_hints: ["idor", "authz"],
      evidence: ["archived export URL exposed account_id and org_id"],
    }]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-object-access" }]);

    const brief = JSON.parse(readAssignmentBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
    const restEntry = brief.techniques.find((entry) => entry.id === "generic-rest-api");
    assert.ok(restEntry);
    assert.ok(restEntry.matched.some((match) => /hint:(idor|authz)/.test(match)));
    assert.match(JSON.stringify(restEntry.guidance), /object access|authorization/i);
  });
});

test("bob_read_assignment_brief matches billing metadata and high-value flows to business-logic guidance", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "EVALUATE", evaluation_wave: 1, pending_wave: 1 });
    seedAttackSurfaces(domain, [{
      id: "surface-billing",
      hosts: [`https://app.${domain}`],
      tech_stack: ["Custom"],
      endpoints: ["/account"],
      interesting_params: ["q"],
      surface_type: "billing",
      high_value_flows: ["checkout", "refund"],
      bug_class_hints: ["business_logic"],
      evidence: ["JS route references refund and subscription flows"],
    }]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-billing" }]);

    const brief = JSON.parse(readAssignmentBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
    assert.ok(brief.techniques.some((entry) => entry.id === "business-logic-race"));
    assert.match(JSON.stringify(brief.techniques), /checkout|refund|business logic/i);
  });
});

test("bob_read_assignment_brief matches upload surface_type to upload guidance", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "EVALUATE", evaluation_wave: 1, pending_wave: 1 });
    seedAttackSurfaces(domain, [{
      id: "surface-upload",
      hosts: [`https://assets.${domain}`],
      tech_stack: ["Custom"],
      endpoints: ["/profile"],
      interesting_params: ["q"],
      surface_type: "upload",
      high_value_flows: ["uploads"],
      bug_class_hints: ["upload"],
      evidence: ["live page contains avatar upload form"],
    }]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-upload" }]);

    const brief = JSON.parse(readAssignmentBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
    assert.ok(brief.techniques.some((entry) => entry.id === "upload-xss-file"));
    assert.match(JSON.stringify(brief.payload_hints), /file\.php\.jpg|Content-Type/i);
  });
});

test("bob_read_assignment_brief falls back to generic guidance for unknown tech", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "EVALUATE", evaluation_wave: 1, pending_wave: 1 });
    seedAttackSurfaces(domain, [{
      id: "surface-unknown",
      hosts: [`https://unknown.${domain}`],
      tech_stack: ["Custom"],
      endpoints: ["/home"],
      interesting_params: ["q"],
    }]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-unknown" }]);

    const brief = JSON.parse(readAssignmentBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
    assert.deepEqual(brief.techniques.map((entry) => entry.id), ["generic-rest-api"]);
    assert.deepEqual(brief.techniques[0].matched, ["fallback:generic-rest-api"]);
  });
});

test("bob_read_assignment_brief knowledge remains bounded and excludes full source docs", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "EVALUATE", evaluation_wave: 1, pending_wave: 1 });
    seedAttackSurfaces(domain, [{
      id: "surface-rich",
      hosts: [`https://${domain}`],
      tech_stack: ["WordPress", "GraphQL", "Next.js", "JWT", "OAuth", "SSRF", "storage"],
      endpoints: [
        "/wp-json/wp/v2/users",
        "/graphql",
        "/_next/image",
        "/oauth/authorize",
        "/api/v1/users",
        "/upload",
        "/billing/checkout",
      ],
      interesting_params: ["query", "variables", "url", "redirect_uri", "user_id", "file", "amount"],
      nuclei_hits: ["swagger exposed", "graphql endpoint", "wp-json exposed"],
      js_hints: ["__NEXT_DATA__", "Bearer token handling"],
    }]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-rich" }]);

    const brief = JSON.parse(readAssignmentBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
    assert.ok(brief.knowledge_summary.entries_returned <= 4);
    assert.equal(brief.knowledge_summary.max_entries, 2);
    assert.equal(brief.knowledge_summary.legacy_compatibility, true);
    assert.ok(brief.knowledge_summary.char_count <= brief.knowledge_summary.max_chars);
    assert.doesNotMatch(JSON.stringify(brief), /Complete reference library|Advanced Bug Bounty Evaluation Techniques|scripts\/|tools\//);
  });
});

test("bob_read_assignment_brief includes bounded candidate technique packs and context budget", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "EVALUATE", evaluation_wave: 1, pending_wave: 1 });
    seedAttackSurfaces(domain, [{
      id: "surface-graphql",
      hosts: [`https://${domain}`],
      tech_stack: ["GraphQL", "Apollo"],
      endpoints: ["/graphql"],
      interesting_params: ["query", "variables"],
    }]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-graphql" }]);

    const brief = JSON.parse(readAssignmentBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
    assert.deepEqual(brief.run_context.context_budget, expectedWebContextBudget());
    assert.equal(brief.run_context.capability_pack_version, 1);
    assert.equal(brief.technique_packs.selection_budget.candidate_pack_limit, 5);
    assert.equal(brief.technique_packs.selection_budget.full_pack_read_limit, 2);
    assert.equal(brief.technique_packs.selection_budget.attempt_log_required, true);
    assert.deepEqual(brief.technique_packs.registry_warnings, []);
    assert.ok(brief.technique_packs.selected.length <= 5);
    assert.ok(brief.techniques.length <= 2);
    assert.ok(brief.payload_hints.length <= 2);
    const graphql = brief.technique_packs.selected.find((entry) => entry.id === "graphql");
    assert.ok(graphql);
    assert.equal(graphql.version, 1);
    assert.ok(graphql.score > 0);
    assert.ok(graphql.summary.guidance.length > 0);
    assert.ok(graphql.summary.payload_hints.length > 0);
    assert.equal(graphql.summary_limits.guidance.item_limit, TECHNIQUE_SUMMARY_ITEMS_PER_KIND);
    assert.equal(graphql.summary_limits.guidance.item_max_chars, TECHNIQUE_SUMMARY_ITEM_MAX_CHARS);
    assert.ok(brief.technique_packs.selection_limits);
    assert.equal(graphql.full, undefined);
  });
});

test("technique pack summary and full reads truncate oversized content with limit metadata", () => {
  withTempTechniqueKnowledge(oversizedTechniqueKnowledge(), () => {
    const summary = readTechniquePack("oversized-0", { mode: "summary" });
    assert.equal(summary.technique_pack.id, "oversized-0");
    assert.equal(summary.technique_pack.summary.guidance.length, TECHNIQUE_SUMMARY_ITEMS_PER_KIND);
    assert.equal(summary.technique_pack.summary.payload_hints.length, TECHNIQUE_SUMMARY_ITEMS_PER_KIND);
    assert.equal(summary.technique_pack.summary.guidance.every((entry) => entry.length <= TECHNIQUE_SUMMARY_ITEM_MAX_CHARS), true);
    assert.equal(summary.technique_pack.summary.payload_hints.every((entry) => entry.length <= TECHNIQUE_SUMMARY_ITEM_MAX_CHARS), true);
    assert.equal(summary.technique_pack.summary_limits.guidance.total, 20);
    assert.equal(summary.technique_pack.summary_limits.guidance.omitted, 16);
    assert.equal(summary.technique_pack.summary_limits.guidance.truncated_values, TECHNIQUE_SUMMARY_ITEMS_PER_KIND);
    assert.deepEqual(summary.summary_limits, summary.technique_pack.summary_limits);

    const full = readTechniquePack("oversized-0", { mode: "full" });
    assert.equal(full.technique_pack.full.techniques.length, TECHNIQUE_FULL_ITEMS_PER_KIND);
    assert.equal(full.technique_pack.full.payload_hints.length, TECHNIQUE_FULL_ITEMS_PER_KIND);
    assert.equal(full.technique_pack.full.techniques.every((entry) => entry.length <= TECHNIQUE_FULL_ITEM_MAX_CHARS), true);
    assert.equal(full.technique_pack.full.payload_hints.every((entry) => entry.length <= TECHNIQUE_FULL_ITEM_MAX_CHARS), true);
    assert.equal(full.technique_pack.full_limits.techniques.total, 20);
    assert.equal(full.technique_pack.full_limits.techniques.omitted, 8);
    assert.equal(full.technique_pack.full_limits.techniques.truncated_values, TECHNIQUE_FULL_ITEMS_PER_KIND);
    assert.deepEqual(full.full_limits, full.technique_pack.full_limits);
  });
});

test("bob_select_technique_packs keeps oversized selected summaries within the selection limit", () => {
  withTempHome(() => {
    withTempTechniqueKnowledge(oversizedTechniqueKnowledge(), () => {
      const domain = "example.com";
      seedAttackSurfaces(domain, [{
        id: "surface-oversized",
        hosts: [`https://${domain}`],
        tech_stack: ["OversizedStack"],
        endpoints: ["/oversized"],
        interesting_params: ["oversized_id"],
        evidence: ["oversized-hint"],
      }]);

      const selected = JSON.parse(selectTechniquePacks({
        target_domain: domain,
        surface_id: "surface-oversized",
        capability_pack: "web",
        max_packs: 50,
      }));

      assert.equal(selected.selection_limits.max_chars, TECHNIQUE_SELECTION_MAX_CHARS);
      assert.equal(JSON.stringify(selected.technique_packs).length, selected.selection_limits.selected_chars);
      assert.ok(JSON.stringify(selected.technique_packs).length <= TECHNIQUE_SELECTION_MAX_CHARS);
      assert.ok(selected.selection_limits.omitted_due_to_char_limit > 0);
      assert.ok(selected.technique_packs.length < selected.max_packs);
      assert.equal(selected.technique_packs.every((pack) => pack.summary.guidance.length <= TECHNIQUE_SUMMARY_ITEMS_PER_KIND), true);
      assert.equal(
        selected.technique_packs.every((pack) => pack.summary.guidance.every((entry) => entry.length <= TECHNIQUE_SUMMARY_ITEM_MAX_CHARS)),
        true,
      );
    });
  });
});

test("bob_read_assignment_brief returns bounded oversized selected technique packs and selection limits", () => {
  withTempHome(() => {
    withTempTechniqueKnowledge(oversizedTechniqueKnowledge(), () => {
      const domain = "example.com";
      seedSessionState(domain, { phase: "EVALUATE", evaluation_wave: 1, pending_wave: 1 });
      seedAttackSurfaces(domain, [{
        id: "surface-oversized",
        hosts: [`https://${domain}`],
        tech_stack: ["OversizedStack"],
        endpoints: ["/oversized"],
        interesting_params: ["oversized_id"],
        evidence: ["oversized-hint"],
      }]);
      seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-oversized" }]);

      const brief = JSON.parse(readAssignmentBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
      assert.ok(Array.isArray(brief.techniques));
      assert.ok(Array.isArray(brief.payload_hints));
      assert.ok(brief.knowledge_summary);
      assert.equal(brief.knowledge_summary.max_entries, 2);
      assert.equal(brief.techniques.length <= 2, true);
      assert.equal(brief.payload_hints.length <= 2, true);
      assert.equal(brief.technique_packs.selection_limits.max_chars, TECHNIQUE_SELECTION_MAX_CHARS);
      assert.equal(JSON.stringify(brief.technique_packs.selected).length, brief.technique_packs.selection_limits.selected_chars);
      assert.ok(JSON.stringify(brief.technique_packs.selected).length <= TECHNIQUE_SELECTION_MAX_CHARS);
      assert.ok(brief.technique_packs.selection_limits.omitted_due_to_char_limit > 0);
      assert.equal(brief.technique_packs.selected.every((pack) => pack.summary_limits), true);
      assert.equal(
        brief.technique_packs.selected.every((pack) => pack.summary.guidance.every((entry) => entry.length <= TECHNIQUE_SUMMARY_ITEM_MAX_CHARS)),
        true,
      );
    });
  });
});

test("technique registry skips malformed entries and surfaces registry warnings", () => {
  withTempHome(() => {
    withTempTechniqueKnowledge({
      version: 4,
      entries: [
        {
          id: "valid-api",
          title: "Valid API pack",
          capability_packs: ["web"],
          match: { tech: ["customapi"], endpoints: ["/custom"] },
          techniques: ["Use the valid registry entry only."],
          payload_hints: ["/custom/export"],
        },
        "bad entry",
        {
          id: "bad-capability",
          title: "Bad capability",
          capability_packs: ["missing_pack"],
          techniques: ["This entry should be skipped."],
        },
        {
          id: "valid-api",
          title: "Duplicate API pack",
          capability_packs: ["web"],
          techniques: ["Duplicate should be skipped."],
        },
      ],
    }, () => {
      const domain = "example.com";
      seedSessionState(domain, { phase: "EVALUATE", evaluation_wave: 1, pending_wave: 1 });
      seedAttackSurfaces(domain, [{
        id: "surface-custom",
        hosts: [`https://${domain}`],
        tech_stack: ["CustomAPI"],
        endpoints: ["/custom"],
      }]);
      seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-custom" }]);

      const registry = loadTechniqueRegistry();
      assert.deepEqual(registry.packs.map((pack) => pack.id), ["valid-api"]);
      assert.equal(registry.warnings.length, 3);
      assert.match(JSON.stringify(registry.warnings), /technique pack entry must be an object/);
      assert.match(JSON.stringify(registry.warnings), /Unknown capability_pack/);
      assert.match(JSON.stringify(registry.warnings), /Duplicate technique pack id/);

      const selected = JSON.parse(selectTechniquePacks({
        target_domain: domain,
        surface_id: "surface-custom",
        capability_pack: "web",
      }));
      assert.equal(selected.technique_packs[0].id, "valid-api");
      assert.equal(selected.registry_warnings.length, 3);

      const summary = readTechniquePack("valid-api", { mode: "summary" });
      assert.equal(summary.registry_warnings.length, 3);

      const brief = JSON.parse(readAssignmentBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
      assert.equal(brief.technique_packs.selected[0].id, "valid-api");
      assert.equal(brief.technique_packs.registry_warnings.length, 3);
      assert.equal(brief.knowledge_summary.registry_warnings.length, 3);
    });
  });
});

test("malformed technique registry file warns instead of failing evaluator brief generation", () => {
  withTempHome(() => {
    withTempTechniqueKnowledgeText("{bad json", () => {
      const domain = "example.com";
      seedSessionState(domain, { phase: "EVALUATE", evaluation_wave: 1, pending_wave: 1 });
      seedAttackSurfaces(domain, [{
        id: "surface-api",
        hosts: [`https://${domain}`],
        tech_stack: ["JSON API"],
        endpoints: ["/api"],
      }]);
      seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-api" }]);

      const registry = loadTechniqueRegistry();
      assert.deepEqual(registry.packs, []);
      assert.equal(registry.warnings.length, 1);
      assert.match(registry.warnings[0].reason, /Malformed evaluator-techniques\.json/);

      const brief = JSON.parse(readAssignmentBrief({ target_domain: domain, wave: "w1", agent: "a1" }));
      assert.deepEqual(brief.technique_packs.selected, []);
      assert.deepEqual(brief.techniques, []);
      assert.deepEqual(brief.payload_hints, []);
      assert.equal(brief.technique_packs.registry_warnings.length, 1);
      assert.equal(brief.knowledge_summary.registry_warnings.length, 1);
    });
  });
});

test("temporary technique knowledge ignores and restores ambient Bob resource env", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-ambient-resources-"));
  try {
    const resources = path.join(root, "resources");
    const project = path.join(root, "project");
    fs.mkdirSync(path.join(resources, "knowledge"), { recursive: true });
    fs.mkdirSync(project, { recursive: true });
    fs.writeFileSync(path.join(resources, "knowledge", "evaluator-techniques.json"), `${JSON.stringify({
      version: 1,
      entries: [{
        id: "ambient-only",
        title: "Ambient only",
        capability_packs: ["web"],
        techniques: ["This ambient resource must not leak into scoped tests."],
      }],
    }, null, 2)}\n`, "utf8");

    withEnv({
      BOB_RESOURCE_DIR: resources,
      BOB_PROJECT_DIR: project,
      CLAUDE_PROJECT_DIR: undefined,
    }, () => {
      withTempTechniqueKnowledge({
        version: 1,
        entries: [{
          id: "scoped-only",
          title: "Scoped only",
          capability_packs: ["web"],
          techniques: ["Use only the scoped test registry."],
        }],
      }, () => {
        assert.equal(process.env.BOB_RESOURCE_DIR, undefined);
        assert.equal(process.env.BOB_PROJECT_DIR, undefined);
        assert.deepEqual(loadTechniqueRegistry().packs.map((pack) => pack.id), ["scoped-only"]);
      });
      assert.equal(process.env.BOB_RESOURCE_DIR, resources);
      assert.equal(process.env.BOB_PROJECT_DIR, project);
    });
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("context budget and technique-pack MCP tools are deterministic and bounded", async () => {
  await withTempHome(async () => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "EVALUATE", evaluation_wave: 1, pending_wave: 1 });
    seedAttackSurfaces(domain, [
      {
        id: "surface-graphql",
        surface_type: "graphql",
        hosts: [`https://${domain}`],
        tech_stack: ["GraphQL", "Apollo"],
        endpoints: ["/graphql"],
        interesting_params: ["query", "variables"],
      },
      {
        id: "surface-api",
        surface_type: "api",
        hosts: [`https://api.${domain}`],
        tech_stack: ["JSON API"],
        endpoints: ["/api/v1/users/123", "/api/v2/admin/export"],
        interesting_params: ["id", "user_id", "role"],
        bug_class_hints: ["idor"],
      },
      {
        id: "surface-wp",
        surface_type: "cms",
        hosts: [`https://${domain}`],
        tech_stack: ["WordPress"],
        endpoints: ["/wp-json/wp/v2/users", "/wp-admin/admin-ajax.php"],
        interesting_params: ["author", "action"],
      },
    ]);
    JSON.parse(routeSurfaces({ target_domain: domain }));

    const packOnlyBudget = JSON.parse(getContextBudget({ capability_pack: "web" }));
    assert.deepEqual(packOnlyBudget.context_budget, expectedWebContextBudget());

    assert.throws(
      () => getContextBudget({ capability_pack: "web", surface_id: "surface-graphql" }),
      /target_domain is required when surface_id is provided/,
    );
    const missingTargetDomain = await executeTool("bob_get_context_budget", {
      capability_pack: "web",
      surface_id: "surface-graphql",
    });
    assert.equal(missingTargetDomain.ok, false);
    assert.equal(missingTargetDomain.error.code, "INVALID_ARGUMENTS");

    const budget = JSON.parse(getContextBudget({
      target_domain: domain,
      surface_id: "surface-graphql",
      capability_pack: "web",
      brief_profile: "web",
    }));
    assert.equal(budget.version, 1);
    assert.equal(budget.capability_pack_version, 1);
    assert.deepEqual(budget.context_budget, expectedWebContextBudget());

    const routeSpecificBudget = {
      candidate_pack_limit: 3,
      full_pack_read_limit: 1,
      attempt_log_required: false,
    };
    writeFileAtomic(surfaceRoutesPath(domain), `${JSON.stringify({
      version: 1,
      route_version: 1,
      routes: [{
        surface_id: "surface-graphql",
        surface_type: "graphql",
        capability_pack: "web",
        capability_pack_version: 7,
        evaluator_agent: "evaluator-agent",
        brief_profile: "web",
        context_budget: routeSpecificBudget,
        confidence: "high",
        reasons: ["test:custom-route-budget"],
      }],
    }, null, 2)}\n`);
    const routeBudget = JSON.parse(getContextBudget({
      target_domain: domain,
      surface_id: "surface-graphql",
      capability_pack: "web",
    }));
    assert.equal(routeBudget.capability_pack_version, 7);
    assert.deepEqual(routeBudget.context_budget, routeSpecificBudget);

    writeFileAtomic(surfaceRoutesPath(domain), `${JSON.stringify({
      version: 1,
      route_version: 1,
      routes: [{
        surface_id: "surface-graphql",
        surface_type: "graphql",
        capability_pack: "web",
        capability_pack_version: 7,
        evaluator_agent: "evaluator-agent",
        brief_profile: "web",
        context_budget: {
          ...routeSpecificBudget,
          brief_max_tokens: 1234,
        },
        confidence: "high",
        reasons: ["test:unsupported-route-budget"],
      }],
    }, null, 2)}\n`);
    assert.throws(
      () => getContextBudget({
        target_domain: domain,
        surface_id: "surface-graphql",
        capability_pack: "web",
      }),
      /unsupported context_budget\.brief_max_tokens/,
    );

    writeFileAtomic(surfaceRoutesPath(domain), `${JSON.stringify({
      version: 1,
      route_version: 1,
      routes: [{
        surface_id: "surface-graphql",
        surface_type: "graphql",
        capability_pack: "web",
        capability_pack_version: 7,
        evaluator_agent: "evaluator-agent",
        brief_profile: "smart_contract_evm",
        context_budget: routeSpecificBudget,
        confidence: "high",
        reasons: ["test:mismatched-route-profile"],
      }],
    }, null, 2)}\n`);
    assert.throws(
      () => getContextBudget({
        target_domain: domain,
        surface_id: "surface-graphql",
        capability_pack: "web",
      }),
      /brief_profile smart_contract_evm does not match pack web/,
    );
    JSON.parse(routeSurfaces({ target_domain: domain }));

    const graphql = JSON.parse(selectTechniquePacks({
      target_domain: domain,
      surface_id: "surface-graphql",
      capability_pack: "web",
      max_packs: 50,
    }));
    assert.equal(graphql.max_packs, 5);
    assert.ok(graphql.technique_packs.length <= 5);
    assert.equal(graphql.technique_packs[0].id, "graphql");
    assert.equal(graphql.technique_packs[0].full, undefined);
    assert.match(JSON.stringify(graphql.technique_packs[0].matched), /tech:graphql|endpoint:\/graphql/);

    const api = JSON.parse(selectTechniquePacks({ target_domain: domain, surface_id: "surface-api", max_packs: 5 }));
    assert.ok(api.technique_packs.some((entry) => entry.id === "generic-rest-api"));

    const wordpress = JSON.parse(selectTechniquePacks({ target_domain: domain, surface_id: "surface-wp", max_packs: 5 }));
    assert.equal(wordpress.technique_packs[0].id, "wordpress");

    const summary = readTechniquePack("graphql", { mode: "summary" });
    assert.equal(summary.registry_version, 1);
    assert.equal(summary.technique_pack.id, "graphql");
    assert.equal(summary.technique_pack.full, undefined);

    const full = readTechniquePack("graphql", { mode: "full" });
    assert.equal(full.registry_version, 1);
    assert.equal(full.technique_pack.id, "graphql");
    assert.ok(full.technique_pack.full.techniques.length > 0);
    assert.ok(full.technique_pack.full.techniques.length <= TECHNIQUE_FULL_ITEMS_PER_KIND);
    assert.equal(full.technique_pack.full.techniques.every((entry) => entry.length <= TECHNIQUE_FULL_ITEM_MAX_CHARS), true);
    assert.equal(full.technique_pack.full.payload_hints.every((entry) => entry.length <= TECHNIQUE_FULL_ITEM_MAX_CHARS), true);
    assert.ok(full.technique_pack.full_limits);
    assert.doesNotMatch(JSON.stringify(full), /WordPress REST/);

    assert.throws(
      () => readTechniquePack("unknown-pack", { mode: "summary" }),
      /Unknown technique pack id/,
    );

    const envelope = await executeTool("bob_read_technique_pack", { pack_id: "unknown-pack", mode: "summary" });
    assert.equal(envelope.ok, false);
    assert.equal(envelope.error.code, "NOT_FOUND");
  });
});

test("bob_read_technique_pack full mode enforces per-assignment read budget", async () => {
  await withTempHome(async () => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "EVALUATE", evaluation_wave: 1, pending_wave: 1 });
    seedAttackSurfaces(domain, [{
      id: "surface-graphql",
      surface_type: "graphql",
      hosts: [`https://${domain}`],
      tech_stack: ["GraphQL", "REST API", "WordPress"],
      endpoints: ["/graphql", "/api/v1/users", "/wp-json/wp/v2/users"],
      interesting_params: ["query", "id", "author"],
    }]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-graphql" }]);

    const summary = await executeTool("bob_read_technique_pack", { pack_id: "graphql", mode: "summary" });
    assert.equal(summary.ok, true);
    assert.equal(fs.existsSync(techniquePackReadsJsonlPath(domain)), false);

    const missingContext = await executeTool("bob_read_technique_pack", { pack_id: "graphql", mode: "full" });
    assert.equal(missingContext.ok, false);
    assert.equal(missingContext.error.code, "INVALID_ARGUMENTS");
    assert.match(missingContext.error.message, /target_domain is required for session authority/);

    const context = {
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-graphql",
      mode: "full",
    };

    const first = await executeTool("bob_read_technique_pack", { ...context, pack_id: "graphql" });
    assert.equal(first.ok, true);
    assert.equal(first.data.registry_version, 1);
    assert.equal(first.data.full_read_budget.full_pack_read_limit, 2);
    assert.equal(first.data.full_read_budget.full_packs_read, 1);
    assert.equal(first.data.full_read_budget.remaining_full_pack_reads, 1);
    assert.equal(first.data.full_read_budget.already_read, false);
    assert.equal(first.data.full_read_budget.log_path, techniquePackReadsJsonlPath(domain));

    const second = await executeTool("bob_read_technique_pack", { ...context, pack_id: "generic-rest-api" });
    assert.equal(second.ok, true);
    assert.equal(second.data.full_read_budget.full_packs_read, 2);
    assert.equal(second.data.full_read_budget.remaining_full_pack_reads, 0);

    const reread = await executeTool("bob_read_technique_pack", { ...context, pack_id: "graphql" });
    assert.equal(reread.ok, true);
    assert.equal(reread.data.full_read_budget.already_read, true);
    assert.equal(reread.data.full_read_budget.full_packs_read, 2);

    const records = readTechniquePackReadRecordsFromJsonl(domain);
    assert.deepEqual(records.map((record) => record.pack_id), ["graphql", "generic-rest-api"]);
    assert.deepEqual(records.map((record) => ({
      pack_id: record.pack_id,
      pack_version: record.pack_version,
      registry_version: record.registry_version,
      capability_pack: record.capability_pack,
      capability_pack_version: record.capability_pack_version,
    })), [
      {
        pack_id: "graphql",
        pack_version: 1,
        registry_version: 1,
        capability_pack: "web",
        capability_pack_version: 1,
      },
      {
        pack_id: "generic-rest-api",
        pack_version: 1,
        registry_version: 1,
        capability_pack: "web",
        capability_pack_version: 1,
      },
    ]);

    const third = await executeTool("bob_read_technique_pack", { ...context, pack_id: "wordpress" });
    assert.equal(third.ok, false);
    assert.equal(third.error.code, "INVALID_ARGUMENTS");
    assert.match(third.error.message, /full_pack_read_limit/);
    assert.equal(readTechniquePackReadRecordsFromJsonl(domain).length, 2);
  });
});

test("bob_log_technique_attempt appends valid JSONL and rejects invalid inputs", async () => {
  await withTempHome(async () => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "EVALUATE", evaluation_wave: 1, pending_wave: 1 });
    seedAttackSurfaces(domain, [{
      id: "surface-graphql",
      hosts: [`https://${domain}`],
      tech_stack: ["GraphQL"],
      endpoints: ["/graphql"],
    }]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-graphql" }]);

    const logged = JSON.parse(logTechniqueAttempt({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-graphql",
      pack_id: "graphql",
      status: "attempted",
      outcome: "not_applicable",
      evidence: "GraphQL endpoint returned 404 for this assigned surface.",
    }));
    assert.equal(logged.appended, 1);
    assert.equal(logged.log_path, techniqueAttemptsJsonlPath(domain));
    assert.equal(logged.record.pack_version, 1);
    assert.equal(logged.record.registry_version, 1);
    assert.equal(logged.record.capability_pack, "web");
    assert.equal(logged.record.capability_pack_version, 1);

    const records = readTechniqueAttemptRecordsFromJsonl(domain);
    assert.equal(records.length, 1);
    assert.equal(records[0].pack_id, "graphql");
    assert.equal(records[0].pack_version, 1);
    assert.equal(records[0].registry_version, 1);
    assert.equal(records[0].capability_pack, "web");
    assert.equal(records[0].capability_pack_version, 1);
    assert.equal(records[0].status, "attempted");
    assert.equal(records[0].outcome, "not_applicable");
    assert.match(records[0].ts, /^\d{4}-\d{2}-\d{2}T/);

    const pipelineEvents = readJsonl(pipelineEventsJsonlPath(domain));
    const attemptEvent = pipelineEvents.find((event) => event.type === "technique_attempt_logged");
    assert.ok(attemptEvent);
    assert.equal(attemptEvent.wave_number, 1);
    assert.equal(attemptEvent.agent, "a1");
    assert.equal(attemptEvent.surface_id, "surface-graphql");
    assert.equal(attemptEvent.status, "attempted");
    assert.equal(attemptEvent.source, "bob_log_technique_attempt");
    assert.deepEqual(attemptEvent.counts, { records: 1 });
    for (const field of ["evidence", "outcome", "pack_id", "technique_pack", "payload_hints"]) {
      assert.equal(Object.prototype.hasOwnProperty.call(attemptEvent, field), false);
    }

    const selectedAfterAttempt = JSON.parse(selectTechniquePacks({
      target_domain: domain,
      surface_id: "surface-graphql",
      capability_pack: "web",
      include_attempted: false,
    }));
    assert.ok(selectedAfterAttempt.attempts_summary.omitted_attempted.some((entry) => entry.pack_id === "graphql"));

    assert.throws(
      () => logTechniqueAttempt({
        target_domain: domain,
        surface_id: "missing-surface",
        pack_id: "graphql",
        status: "selected",
        evidence: "Trying to log an invalid surface.",
      }),
      /Unknown surface_id/,
    );
    const invalidStatus = await executeTool("bob_log_technique_attempt", {
      target_domain: domain,
      surface_id: "surface-graphql",
      pack_id: "graphql",
      status: "invalid",
      evidence: "Bad status.",
    });
    assert.equal(invalidStatus.ok, false);
    assert.equal(invalidStatus.error.code, "INVALID_ARGUMENTS");
  });
});

test("bob_log_technique_attempt rejects packs incompatible with assigned capability pack", async () => {
  await withTempHome(async () => {
    await withTempTechniqueKnowledge({
      version: 1,
      entries: [
        {
          id: "web-pack",
          title: "Web pack",
          capability_packs: ["web"],
          match: { tech: ["json api"] },
          techniques: ["Exercise the web API route."],
          payload_hints: ["/api/export"],
        },
        {
          id: "evm-only-pack",
          title: "EVM-only pack",
          capability_packs: ["smart_contract_evm"],
          match: { tech: ["solidity"] },
          techniques: ["Exercise the EVM contract invariant."],
          payload_hints: ["forge test"],
        },
      ],
    }, async () => {
      const domain = "example.com";
      seedSessionState(domain, { phase: "EVALUATE", evaluation_wave: 1, pending_wave: 1 });
      seedAttackSurfaces(domain, [{
        id: "surface-api",
        hosts: [`https://${domain}`],
        tech_stack: ["JSON API"],
        endpoints: ["/api"],
      }]);
      seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-api" }]);

      const rejected = await executeTool("bob_log_technique_attempt", {
        target_domain: domain,
        wave: "w1",
        agent: "a1",
        surface_id: "surface-api",
        pack_id: "evm-only-pack",
        status: "attempted",
        evidence: "Trying to log an EVM-only technique against a web assignment.",
      });
      assert.equal(rejected.ok, false);
      assert.equal(rejected.error.code, "INVALID_ARGUMENTS");
      assert.match(rejected.error.message, /not compatible with capability_pack web/);
      assert.equal(readTechniqueAttemptRecordsFromJsonl(domain).length, 0);

      const accepted = await executeTool("bob_log_technique_attempt", {
        target_domain: domain,
        wave: "w1",
        agent: "a1",
        surface_id: "surface-api",
        pack_id: "web-pack",
        status: "attempted",
        evidence: "Logged the compatible web technique pack.",
      });
      assert.equal(accepted.ok, true);
      assert.equal(readTechniqueAttemptRecordsFromJsonl(domain).length, 1);
    });
  });
});

// ── filterExclusionsByHosts tests ──

test("filterExclusionsByHosts filters dead ends by surface hosts", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, {
      phase: "EVALUATE",
      evaluation_wave: 1,
      pending_wave: 1,
      dead_ends: [
        "api.example.com - /v1/users returns 404",
        "admin.example.com - /panel gives 403",
        "All /api/* endpoints return 401",
      ],
      waf_blocked_endpoints: [
        "api.example.com - /v1/debug blocked by WAF",
        "admin.example.com - /admin/config blocked",
        "Generic WAF rule on POST",
      ],
    });

    // Create surfaces with distinct hosts
    const surfaces = [
      { id: "surface-api", hosts: ["https://api.example.com"] },
      { id: "surface-admin", hosts: ["https://admin.example.com"] },
    ];
    writeFileAtomic(
      attackSurfacePath(domain),
      `${JSON.stringify({ surfaces }, null, 2)}\n`,
    );
    seedAssignments(domain, 1, [
      { agent: "a1", surface_id: "surface-api" },
      { agent: "a2", surface_id: "surface-admin" },
    ]);

    // Agent a1 should see api.example.com dead ends + generic
    const brief1 = JSON.parse(readAssignmentBrief({
      target_domain: domain, wave: "w1", agent: "a1",
    }));
    assert.deepEqual(brief1.dead_ends, [
      "api.example.com - /v1/users returns 404",
      "All /api/* endpoints return 401",
    ]);
    assert.deepEqual(brief1.waf_blocked_endpoints, [
      "api.example.com - /v1/debug blocked by WAF",
      "Generic WAF rule on POST",
    ]);

    // Agent a2 should see admin.example.com dead ends + generic
    const brief2 = JSON.parse(readAssignmentBrief({
      target_domain: domain, wave: "w1", agent: "a2",
    }));
    assert.deepEqual(brief2.dead_ends, [
      "admin.example.com - /panel gives 403",
      "All /api/* endpoints return 401",
    ]);
    assert.deepEqual(brief2.waf_blocked_endpoints, [
      "admin.example.com - /admin/config blocked",
      "Generic WAF rule on POST",
    ]);
  });
});

test("filterExclusionsByHosts caps at limit and reports omitted count", () => {
  const entries = Array.from({ length: 150 }, (_, i) => `generic entry ${i}`);
  const result = filterExclusionsByHosts(entries, ["https://example.com"], 100);
  assert.equal(result.filtered.length, 100);
  assert.equal(result.total, 150);
  assert.equal(result.omitted, 50);
});

test("filterExclusionsByHosts handles empty and null input", () => {
  assert.deepStrictEqual(filterExclusionsByHosts([], []), { filtered: [], total: 0, omitted: 0 });
  assert.deepStrictEqual(filterExclusionsByHosts(null, []), { filtered: [], total: 0, omitted: 0 });
  assert.deepStrictEqual(filterExclusionsByHosts(undefined, []), { filtered: [], total: 0, omitted: 0 });
});

// ── Bug 1: Path traversal via target_domain ──

test("assertSafeDomain rejects path traversal sequences", () => {
  assert.throws(() => assertSafeDomain("../../etc"), /invalid path characters/);
  assert.throws(() => assertSafeDomain("foo/../bar"), /invalid path characters/);
  assert.throws(() => assertSafeDomain(".."), /invalid path characters/);
  assert.throws(() => assertSafeDomain("foo/bar"), /invalid path characters/);
  assert.throws(() => assertSafeDomain("foo\\bar"), /invalid path characters/);
});

test("assertSafeDomain accepts valid domain names", () => {
  assert.equal(assertSafeDomain("example.com"), "example.com");
  assert.equal(assertSafeDomain("sub.example.com"), "sub.example.com");
  assert.equal(assertSafeDomain("my-target.io"), "my-target.io");
});

test("sessionDir rejects path traversal in target_domain", () => {
  assert.throws(() => sessionDir("../../.ssh"), /invalid path characters/);
  assert.throws(() => sessionDir("../secrets"), /invalid path characters/);
});

test("initSession rejects path traversal domain", () => {
  withTempHome(() => {
    assert.throws(
      () => initSession({ target_domain: "../../etc", target_url: "https://evil.com" }),
      /invalid path characters/,
    );
  });
});

// ── Bug 2: writeHandoff validates domain and uses atomic writes ──

test("writeHandoff rejects missing target_domain", () => {
  withTempHome(() => {
    assert.throws(
      () => writeHandoff({ target_url: "https://example.com", session_number: 1 }),
      /target_domain/,
    );
  });
});

test("writeHandoff rejects path traversal domain", () => {
  withTempHome(() => {
    assert.throws(
      () => writeHandoff({ target_domain: "../evil", target_url: "https://example.com", session_number: 1 }),
      /invalid path characters/,
    );
  });
});

test("writeHandoff writes file atomically", () => {
  withTempHome(() => {
    const domain = "example.com";
    const dir = sessionDir(domain);
    fs.mkdirSync(dir, { recursive: true });

    writeHandoff({
      target_domain: domain,
      target_url: "https://example.com",
      session_number: 1,
      findings_summary: [{ id: "F-1", severity: "high", title: "Test" }],
    });

    const handoffPath = path.join(dir, "SESSION_HANDOFF.md");
    assert.ok(fs.existsSync(handoffPath));
    const content = fs.readFileSync(handoffPath, "utf8");
    assert.ok(content.includes("F-1"));
  });
});

// ── Bug 3: auth path resolution requires explicit target domain ──

test("resolveAuthJsonPath requires an explicit domain by default and keeps fallback legacy-only", () => {
  withTempHome((tempHome) => {
    const sessionsDir = path.join(tempHome, "hacker-bob-sessions");

    // Create two session dirs: aaa-old.com (older) and zzz-new.com (newer alphabetically but older mtime)
    const oldDir = path.join(sessionsDir, "zzz-alphabetically-last.com");
    const newDir = path.join(sessionsDir, "aaa-alphabetically-first.com");
    fs.mkdirSync(oldDir, { recursive: true });
    fs.mkdirSync(newDir, { recursive: true });

    // Touch the "aaa" dir to make it most recent
    const now = new Date();
    fs.utimesSync(oldDir, new Date(now - 60000), new Date(now - 60000));
    fs.utimesSync(newDir, now, now);

    assert.equal(resolveAuthJsonPath(null), null);
    const legacyResult = resolveAuthJsonPath(null, { allowLegacyFallback: true });
    assert.ok(legacyResult.includes("aaa-alphabetically-first.com"));
  });
});

test("auth storage rejects path traversal target domains", () => {
  withTempHome(() => {
    assert.throws(
      () => resolveAuthJsonPath("../evil"),
      /invalid path characters/,
    );
    assert.throws(
      () => authStore({ target_domain: "../evil", profile_name: "attacker", headers: { Authorization: "Bearer token" } }),
      /invalid path characters/,
    );
  });
});

// ── Bug 4: httpScan URL validation ──

const INTERNAL_SCAN_URLS = [
  "http://localhost/admin",
  "http://%6c%6f%63%61%6c%68%6f%73%74/admin",
  "http://127.0.0.1/admin",
  "http://127.1/admin",
  "http://0177.0.0.1/admin",
  "http://2130706433/admin",
  "http://0x7f000001/admin",
  "http://0.0.0.0/",
  "http://10.0.0.1/secret",
  "http://192.168.1.1/admin",
  "http://172.16.0.1/internal",
  "http://[::1]/admin",
  "http://[::7f00:1]/admin",
  "http://[::127.0.0.1]/admin",
  "http://[::a9fe:a9fe]/latest/meta-data/",
  "http://[fc00::1]/admin",
  "http://[fd12:3456::1]/admin",
  "http://[fe80::1]/admin",
  "http://[::ffff:127.0.0.1]/admin",
  "http://[::ffff:7f00:1]/admin",
  "http://169.254.169.254/latest/meta-data/",
  "http://metadata.google.internal/computeMetadata/v1/",
  "http://metadata/latest/meta-data/",
  "http://service.internal/api",
  "http://printer.local/status",
];

test("validateScanUrl permits localhost, private, metadata, and internal hosts by default", () => {
  for (const url of INTERNAL_SCAN_URLS) {
    assert.doesNotThrow(() => validateScanUrl(url), url);
  }
});

test("validateScanUrl rejects localhost, private, metadata, and internal hosts when requested", () => {
  for (const url of INTERNAL_SCAN_URLS) {
    assert.throws(() => validateScanUrl(url, { blockInternalHosts: true }), /Blocked internal/, url);
  }
  assert.throws(() => validateScanUrl("http://127.0.0.1/admin", { block_internal_hosts: true }), /Blocked internal/);
});

test("validateScanUrl rejects unsupported protocols", () => {
  assert.throws(() => validateScanUrl("ftp://example.com/file"), /Unsupported protocol/);
  assert.throws(() => validateScanUrl("file:///etc/passwd"), /Unsupported protocol/);
});

test("validateScanUrl accepts valid external URLs", () => {
  assert.doesNotThrow(() => validateScanUrl("https://example.com/api/v1/users"));
  assert.doesNotThrow(() => validateScanUrl("http://target.io/login"));
});

test("validateScanUrl rejects malformed URLs", () => {
  assert.throws(() => validateScanUrl("not-a-url"), /Invalid URL/);
});

test("Claude settings register only artifact guards; scoped HTTP policy is enforced by MCP runtime", () => {
  const { defaultClaudeSettings } = require("../adapters/claude/config.js");
  const { mergeSettings } = require("../scripts/merge-claude-config.js");
  const generated = defaultClaudeSettings();
  const installed = JSON.parse(fs.readFileSync(path.join(ROOT, ".claude", "settings.json"), "utf8"));

  for (const settings of [generated, installed]) {
    const hooksText = JSON.stringify(settings.hooks.PreToolUse || []);
    assert.doesNotMatch(hooksText, /scope-guard/);
    const bash = settings.hooks.PreToolUse.find((entry) => entry.matcher === "Bash");
    assert.ok(bash, "Bash hook entry should remain for session artifact guards");
    assert.ok(bash.hooks.some((hook) => /session-write-guard\.sh/.test(hook.command)));
    assert.ok(bash.hooks.some((hook) => /session-read-guard\.sh/.test(hook.command)));
    assert.equal(
      settings.hooks.PreToolUse.some((entry) => /^mcp__(hacker-bob|bountyagent)__/.test(entry.matcher || "")),
      false,
      "MCP tool hooks should not imply an external scope guard",
    );
  }

  for (const [toolName, metadata] of Object.entries(TOOL_MANIFEST)) {
    assert.equal(
      Object.prototype.hasOwnProperty.call(metadata, REMOVED_HOOK_AUTHORITY_FIELD),
      false,
      `${toolName} must not advertise a hook authority`,
    );
  }

  const merged = mergeSettings({
    hooks: {
      PreToolUse: [
        {
          matcher: "Bash",
          hooks: [
            { type: "command", command: "echo existing", timeout: 1 },
            { type: "command", command: "bash \"$CLAUDE_PROJECT_DIR/.claude/hooks/scope-guard.sh\"", timeout: 5 },
          ],
        },
        {
          matcher: "mcp__hacker-bob__bob_http_scan",
          hooks: [
            { type: "command", command: "bash \"$CLAUDE_PROJECT_DIR/.claude/hooks/scope-guard-mcp.sh\"", timeout: 5 },
          ],
        },
      ],
    },
  }, generated);
  const mergedHooksText = JSON.stringify(merged.hooks.PreToolUse || []);
  assert.doesNotMatch(mergedHooksText, /scope-guard/);
  assert.match(mergedHooksText, /session-write-guard\.sh/);
  assert.match(mergedHooksText, /session-read-guard\.sh/);
  assert.match(mergedHooksText, /echo existing/);
  assert.equal(
    merged.hooks.PreToolUse.some((entry) => /^mcp__(hacker-bob|bountyagent)__/.test(entry.matcher || "")),
    false,
    "stale MCP scope hook matchers should be removed when their only hook is stale",
  );
});

// ── Bug 5: Session lock uses owner metadata for ownership verification ──

test("session lock creates an atomic metadata lock file", () => {
  withTempHome(() => {
    const domain = "locktest.com";
    const dir = sessionDir(domain);
    fs.mkdirSync(dir, { recursive: true });
    const lockPath = sessionLockPath(domain);
    const originalOpenSync = fs.openSync;
    const openWxCalls = [];

    try {
      fs.openSync = function patchedOpenSync(target, flags, mode) {
        if (target === lockPath && flags === "wx") {
          openWxCalls.push({ target, flags });
        }
        return originalOpenSync.call(fs, target, flags, mode);
      };
      const release = acquireSessionLock(domain);
      try {
        assert.deepEqual(openWxCalls, []);
        assert.ok(fs.statSync(lockPath).isFile());
        const metadata = JSON.parse(fs.readFileSync(lockPath, "utf8"));
        assert.equal(metadata.pid, process.pid);
        assert.ok(metadata.hostname);
        assert.ok(metadata.timestamp);
        assert.ok(metadata.token);
      } finally {
        release();
      }
    } finally {
      fs.openSync = originalOpenSync;
    }
    assert.ok(!fs.existsSync(sessionLockPath(domain)));
  });
});

test("writeFileExclusiveAtomic preserves existing files on EEXIST", () => {
  withTempHome((tempHome) => {
    const filePath = path.join(tempHome, "exclusive.txt");
    fs.writeFileSync(filePath, "original", "utf8");

    assert.equal(writeFileExclusiveAtomic(filePath, "replacement"), false);
    assert.equal(fs.readFileSync(filePath, "utf8"), "original");
  });
});

test("withSessionLock is reentrant for synchronous same-domain callbacks", () => {
  withTempHome(() => {
    const domain = "reentrant-lock.example";
    const lockPath = sessionLockPath(domain);
    let innerSawLock = false;

    withSessionLock(domain, () => {
      assert.ok(fs.existsSync(lockPath));
      withSessionLock(domain, () => {
        innerSawLock = fs.existsSync(lockPath);
      });
      assert.ok(fs.existsSync(lockPath));
    });

    assert.equal(innerSawLock, true);
    assert.ok(!fs.existsSync(lockPath));
  });
});

test("withSessionLock rejects async callbacks without leaking the lock", () => {
  withTempHome(() => {
    const domain = "async-lock.example";
    assert.throws(
      () => withSessionLock(domain, async () => true),
      /withSessionLock callback must be synchronous/,
    );
    assert.ok(!fs.existsSync(sessionLockPath(domain)));
  });
});

test("session lock release removes an owned lock even if metadata is truncated", () => {
  withTempHome(() => {
    const domain = "truncated-lock.example";
    const lockPath = sessionLockPath(domain);
    const release = acquireSessionLock(domain);

    fs.writeFileSync(lockPath, "", "utf8");
    release();

    assert.ok(!fs.existsSync(lockPath));
  });
});

test("session lock stale override uses JSON timestamp and does not remove replacement locks", () => {
  withTempHome(() => {
    const domain = "locktest.com";
    const lockPath = sessionLockPath(domain);
    fs.mkdirSync(sessionDir(domain), { recursive: true });

    fs.writeFileSync(lockPath, `${JSON.stringify({
      pid: 1,
      hostname: "old-host",
      timestamp: new Date(Date.now() - SESSION_LOCK_STALE_MS - 1_000).toISOString(),
      token: "old",
    })}\n`);
    const freshDate = new Date();
    fs.utimesSync(lockPath, freshDate, freshDate);

    const release = acquireSessionLock(domain);
    try {
      const metadata = JSON.parse(fs.readFileSync(lockPath, "utf8"));
      assert.equal(metadata.pid, process.pid);
      assert.notEqual(metadata.token, "old");
    } finally {
      release();
    }

    fs.writeFileSync(lockPath, `${JSON.stringify({
      pid: 1,
      hostname: "old-host",
      timestamp: new Date(Date.now() - SESSION_LOCK_STALE_MS - 1_000).toISOString(),
      token: "stale",
    })}\n`);
    const snapshot = readSessionLockSnapshot(lockPath);
    assert.equal(snapshot.isStale, true);

    fs.rmSync(lockPath, { force: true });
    fs.writeFileSync(lockPath, `${JSON.stringify({
      pid: process.pid,
      hostname: "new-host",
      timestamp: new Date().toISOString(),
      token: "replacement",
    })}\n`);

    assert.equal(removeStaleSessionLock(lockPath, snapshot), false);
    assert.equal(JSON.parse(fs.readFileSync(lockPath, "utf8")).token, "replacement");
  });
});

test("session lock stale detection bounds future metadata timestamps by file mtime", () => {
  withTempHome(() => {
    const domain = "future-lock.example";
    const lockPath = sessionLockPath(domain);
    fs.mkdirSync(sessionDir(domain), { recursive: true });

    fs.writeFileSync(lockPath, `${JSON.stringify({
      pid: 1,
      hostname: "future-host",
      timestamp: new Date(Date.now() + SESSION_LOCK_STALE_MS + 60_000).toISOString(),
      token: "future",
    })}\n`);
    const staleDate = new Date(Date.now() - SESSION_LOCK_STALE_MS - 1_000);
    fs.utimesSync(lockPath, staleDate, staleDate);

    assert.equal(readSessionLockSnapshot(lockPath).isStale, true);
  });
});

// ── Fix 1: Verification round filename mapping ──

test("verificationRoundPaths returns balanced.json for balanced round (not brutalist-final.json)", () => {
  withTempHome(() => {
    const paths = verificationRoundPaths("example.com", "balanced");
    assert.ok(paths.json.endsWith("balanced.json"), `Expected balanced.json, got ${paths.json}`);
    assert.ok(paths.markdown.endsWith("balanced.md"), `Expected balanced.md, got ${paths.markdown}`);
    assert.ok(!paths.json.includes("brutalist-final"), "Should not contain brutalist-final");
  });
});

// ── Fix 2: Finding counter race condition (sequential IDs under lock) ──

test("recordFinding produces sequential IDs without gaps when called rapidly", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "EVALUATE", evaluation_wave: 1, pending_wave: 1 });
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);

    const ids = [];
    for (let i = 0; i < 5; i++) {
      const result = JSON.parse(recordFinding({
        target_domain: domain,
        wave: "w1",
        agent: "a1",
        surface_id: "surface-a",
        title: `Finding ${i}`,
        severity: "medium",
        endpoint: `/api/test${i}`,
        description: "Test",
        proof_of_concept: "curl test",
        response_evidence: "200 OK",
        impact: "Test impact",
        validated: true,
      }));
      ids.push(result.finding_id);
    }

    assert.deepEqual(ids, ["F-1", "F-2", "F-3", "F-4", "F-5"]);
  });
});

// ── Fix 3: Session lock stale timeout ──

test("SESSION_LOCK_STALE_MS is 300 seconds", () => {
  assert.equal(SESSION_LOCK_STALE_MS, 300_000);
});

// ── Fix 6: waveStatus returns coverage data ──

test("bob_wave_status returns coverage_pct when attack surface and state exist", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, {
      phase: "EVALUATE",
      evaluation_wave: 1,
      pending_wave: null,
      explored: ["surface-a"],
    });

    // Seed attack surface with priorities
    const surfaces = [
      { id: "surface-a", hosts: ["https://example.com"], priority: "CRITICAL" },
      { id: "surface-b", hosts: ["https://api.example.com"], priority: "HIGH" },
      { id: "surface-c", hosts: ["https://cdn.example.com"], priority: "LOW" },
    ];
    writeFileAtomic(attackSurfacePath(domain), JSON.stringify({ surfaces }) + "\n");

    const result = JSON.parse(waveStatus({ target_domain: domain }));
    assert.ok(result.coverage != null, "coverage should not be null");
    assert.equal(result.coverage.total_surfaces, 3);
    assert.equal(result.coverage.non_low_total, 2);     // CRITICAL + HIGH
    assert.equal(result.coverage.non_low_explored, 1);   // only surface-a explored
    assert.equal(result.coverage.coverage_pct, 50);       // 1/2 = 50%
    assert.equal(result.coverage.unexplored_high, 1);     // surface-b is HIGH and unexplored
    assert.deepEqual(result.coverage.unexplored_high_surface_ids, ["surface-b"]);
    assert.deepEqual(result.coverage.open_requeue_surface_ids, []);
    assert.equal(result.transition_blockers.some((item) => item.code === "unexplored_high_surfaces"), true);
  });
});

test("bob_wave_status coverage_pct is 100 when all surfaces are LOW", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "EVALUATE", evaluation_wave: 0, pending_wave: null });

    const surfaces = [
      { id: "surface-a", hosts: ["https://cdn.example.com"], priority: "LOW" },
      { id: "surface-b", hosts: ["https://static.example.com"], priority: "LOW" },
    ];
    writeFileAtomic(attackSurfacePath(domain), JSON.stringify({ surfaces }) + "\n");

    const result = JSON.parse(waveStatus({ target_domain: domain }));
    assert.equal(result.coverage.non_low_total, 0);
    assert.equal(result.coverage.coverage_pct, 100);  // 0/0 → 100% (no non-LOW to explore)
  });
});

test("bob_wave_status returns open requeue coverage surface ids and transition blockers", () => {
  withTempHome(() => {
    const domain = "example.com";
    // surface-a has unfinished coverage and is NOT in `explored`, so the
    // surface is genuinely still open and the gate must block.
    seedSessionState(domain, {
      phase: "EVALUATE",
      evaluation_wave: 1,
      pending_wave: null,
      explored: [],
    });
    seedAttackSurfaces(domain, [
      { id: "surface-a", hosts: [`https://${domain}`], priority: "MEDIUM" },
    ]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    logCoverage({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      entries: [{
        endpoint: "/api/export",
        method: "GET",
        bug_class: "idor",
        status: "requeue",
        evidence_summary: "late discovered export route",
      }],
    });

    const result = JSON.parse(waveStatus({ target_domain: domain }));
    assert.deepEqual(result.coverage.open_requeue_surface_ids, ["surface-a"]);
    assert.deepEqual(result.coverage.unexplored_high_surface_ids, []);
    assert.equal(result.transition_blockers.some((item) => item.code === "open_requeue_coverage"), true);
  });
});

test("bob_wave_status excludes explored surfaces from open_requeue_surface_ids", () => {
  // The veda.tech regression: a surface had a `requeue` coverage row from
  // an earlier wave, then was closed by a `surface_status: complete`
  // handoff in a later wave (which populated state.explored). wave_status
  // used to keep the surface in open_requeue_surface_ids forever because
  // no later coverage row was written for the same (endpoint, bug_class)
  // tuple. The complete handoff is the authoritative "surface is closed"
  // signal — coverage rows are endpoint-level history, not surface state.
  withTempHome(() => {
    const domain = "explored-stale-coverage.example.com";
    seedSessionState(domain, {
      phase: "EVALUATE",
      evaluation_wave: 2,
      pending_wave: null,
      explored: ["surface-a"],
    });
    seedAttackSurfaces(domain, [
      { id: "surface-a", hosts: [`https://${domain}`], priority: "MEDIUM" },
    ]);
    seedAssignments(domain, 1, [{ agent: "a1", surface_id: "surface-a" }]);
    seedAssignments(domain, 2, [{ agent: "a1", surface_id: "surface-a" }]);
    logCoverage({
      target_domain: domain,
      wave: "w1",
      agent: "a1",
      surface_id: "surface-a",
      entries: [{
        endpoint: "/api/legacy",
        method: "GET",
        bug_class: "idor",
        status: "requeue",
        evidence_summary: "endpoint-level requeue from earlier wave",
      }],
    });

    const result = JSON.parse(waveStatus({ target_domain: domain }));
    assert.deepEqual(result.coverage.open_requeue_surface_ids, []);
    assert.equal(
      result.transition_blockers.some((item) => item.code === "open_requeue_coverage"),
      false,
    );
  });
});

// ── Auth silent fallback: httpScan returns error when auth_profile not found ──

test("httpScan returns error when auth_profile is requested but not found", async () => {
  const previousHome = process.env.HOME;
  const tempHome = fs.mkdtempSync(path.join(os.tmpdir(), "hacker-bob-authtest-"));
  process.env.HOME = tempHome;
  try {
    seedSessionState("example.com");
    const result = await executeTool("bob_http_scan", {
      target_domain: "example.com",
      method: "GET",
      url: "https://example.com/",
      auth_profile: "nonexistent_test_profile_xyz",
    });
    assert.equal(result.ok, false);
    assert.equal(result.error.code, "AUTH_MISSING");
    assert.ok(result.error.message.includes("not found"), `Error should mention profile not found: ${result.error.message}`);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(tempHome, { recursive: true, force: true });
  }
});

// ── Verification completeness: malformed prior round is a hard error, not skipped ──

test("writeVerificationRound rejects balanced round when brutalist JSON is malformed", () => {
  withTempHome(() => {
    const domain = "example.com";
    seedSessionState(domain, { phase: "VERIFY" });
    seedFinding(domain, { severity: "high" });

    // Write valid brutalist round first
    writeVerificationRound({
      target_domain: domain,
      round: "brutalist",
      results: [{ finding_id: "F-1", disposition: "confirmed", severity: "high", reportable: true, reasoning: "Valid" }],
    });

    // Corrupt the brutalist JSON
    const brutalistPath = verificationRoundPaths(domain, "brutalist").json;
    fs.writeFileSync(brutalistPath, "NOT VALID JSON{{{");

    // Balanced round should fail because prior round is malformed (not silently skip)
    assert.throws(
      () => writeVerificationRound({
        target_domain: domain,
        round: "balanced",
        results: [{ finding_id: "F-1", disposition: "confirmed", severity: "high", reportable: true, reasoning: "Valid" }],
      }),
      /Unexpected token/,  // JSON.parse error
    );
  });
});
