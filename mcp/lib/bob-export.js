"use strict";

const fs = require("fs");
const path = require("path");
const {
  VERIFICATION_ROUND_VALUES,
} = require("./constants.js");
const {
  toolInvocationTelemetryPath,
  readToolInvocationTelemetryEvents,
  readToolTelemetryEvents,
  telemetryDir,
  toolTelemetryPath,
} = require("./tool-telemetry.js");
const {
  listSessionDomains,
  readPipelineAnalytics,
  readPipelineEvents,
  readSessionArtifactSummary,
} = require("./pipeline-analytics.js");
const {
  replayExecutionPolicy,
} = require("./verification-replay-safety.js");
const {
  attackSurfacePath,
  chainAttemptsJsonlPath,
  claimsJsonlPath,
  coverageJsonlPath,
  evidencePackPaths,
  gradeArtifactPaths,
  httpAuditJsonlPath,
  pipelineEventsJsonlPath,
  reportMarkdownPath,
  sessionDir,
  sessionsRoot,
  statePath,
  techniqueAttemptsJsonlPath,
  techniquePackReadsJsonlPath,
  verificationAdjudicationPath,
  verificationAttemptsDir,
  verificationManifestPath,
  verificationRoundPaths,
  verificationSnapshotPath,
} = require("./paths.js");
const {
  bobVersion,
} = require("./runtime-resources.js");

const EXPORT_BUNDLE_VERSION = 1;
const BUNDLE_FILES = Object.freeze([
  "AGENT_PROMPT.md",
  "manifest.json",
  "summary.md",
  "problem-clusters.json",
  "sessions.json",
  "tool-events.filtered.jsonl",
  "tool-invocations.filtered.jsonl",
  "source-paths.txt",
]);

function capString(value, maxChars = 1000) {
  if (value == null) return null;
  const text = String(value).replace(/[\r\n\t]+/g, " ").trim();
  if (!text) return null;
  return text.length > maxChars ? text.slice(0, maxChars) : text;
}

function timestampMs(value) {
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

function sortedStrings(values) {
  return Array.from(new Set(values.filter(Boolean).map(String))).sort();
}

function eventSortKey(event) {
  return [
    event && event.ts ? event.ts : "",
    event && event.target_domain ? event.target_domain : "",
    event && event.tool ? event.tool : "",
    event && event.run_id ? event.run_id : "",
    JSON.stringify(event),
  ].join("\0");
}

function sortEvents(events) {
  return events.slice().sort((a, b) => eventSortKey(a).localeCompare(eventSortKey(b)));
}

function versionKey(value) {
  return capString(value, 80) || "<unknown>";
}

function versionMatches(event, currentVersion) {
  return versionKey(event && event.bob_version) === currentVersion;
}

function countByVersion(events, currentVersion) {
  const counts = {};
  for (const event of events) {
    const key = versionKey(event && event.bob_version);
    if (key === currentVersion) continue;
    counts[key] = (counts[key] || 0) + 1;
  }
  return Object.keys(counts).sort().map((bob_version) => ({
    bob_version,
    count: counts[bob_version],
  }));
}

function releaseDirectoryName(version) {
  const stripped = String(version || "0.0.0").replace(/^v/i, "");
  const safe = stripped.replace(/[^A-Za-z0-9._-]+/g, "_") || "0.0.0";
  return `v${safe}`;
}

function timestampDirectoryName(now) {
  return now.toISOString().replace(/[:.]/g, "-");
}

function createUniqueBundleDir(root, timestamp) {
  fs.mkdirSync(root, { recursive: true });
  for (let index = 0; index < 1000; index += 1) {
    const suffix = index === 0 ? "" : `-${String(index).padStart(3, "0")}`;
    const candidate = path.join(root, `${timestamp}${suffix}`);
    try {
      fs.mkdirSync(candidate);
      return candidate;
    } catch (error) {
      if (!error || error.code !== "EEXIST") throw error;
    }
  }
  throw new Error(`Unable to create a unique Bob export bundle directory under ${root}`);
}

function writeJson(filePath, value) {
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function writeJsonl(filePath, events) {
  const body = events.map((event) => JSON.stringify(event)).join("\n");
  fs.writeFileSync(filePath, body ? `${body}\n` : "", "utf8");
}

function readTelemetry(currentVersion, env) {
  const toolRead = readToolTelemetryEvents({ env });
  const toolInvocationRead = readToolInvocationTelemetryEvents({ env });
  const toolEvents = sortEvents(toolRead.events.filter((event) => versionMatches(event, currentVersion)));
  const agentRuns = sortEvents(toolInvocationRead.events.filter((event) => versionMatches(event, currentVersion)));
  return {
    toolRead,
    toolInvocationRead,
    toolEvents,
    agentRuns,
    exclusions: {
      tool_events: countByVersion(toolRead.events, currentVersion),
      agent_runs: countByVersion(toolInvocationRead.events, currentVersion),
    },
  };
}

function sessionVersions(eventRead) {
  const versions = sortedStrings(eventRead.events.map((event) => capString(event.bob_version, 80)));
  const unknown_events = eventRead.events.filter((event) => !capString(event.bob_version, 80)).length;
  return { versions, unknown_events };
}

function classifySession(targetDomain, currentVersion) {
  const eventRead = readPipelineEvents(targetDomain, { allowBackfill: false, validateAuthority: true });
  const { versions, unknown_events: unknownEvents } = sessionVersions(eventRead);
  const base = {
    target_domain: targetDomain,
    session_dir: sessionDir(targetDomain),
    event_log_path: eventRead.events_path,
    observed_bob_versions: versions,
    malformed_event_lines: eventRead.malformed_lines,
  };

  if (!eventRead.exists || eventRead.events.length === 0) {
    return {
      included: false,
      eventRead,
      exclusion: {
        ...base,
        reason: "unknown_version",
        detail: eventRead.exists
          ? "Pipeline event log has no readable versioned events"
          : "Pipeline event log is missing",
      },
    };
  }
  if (unknownEvents > 0 || versions.length > 1) {
    return {
      included: false,
      eventRead,
      exclusion: {
        ...base,
        reason: "mixed_version",
        detail: unknownEvents > 0
          ? "Pipeline event log contains events without bob_version"
          : "Pipeline event log contains multiple Bob versions",
      },
    };
  }
  if (versions[0] !== currentVersion) {
    return {
      included: false,
      eventRead,
      exclusion: {
        ...base,
        reason: "version_mismatch",
        detail: `Session version ${versions[0]} does not match current Bob version ${currentVersion}`,
      },
    };
  }
  return { included: true, eventRead };
}

function parsePipelineAnalytics(targetDomain, env) {
  try {
    const parsed = JSON.parse(readPipelineAnalytics({
      target_domain: targetDomain,
      include_events: true,
      limit: 100,
    }, { env, validateAuthority: true }));
    return {
      sessions: Array.isArray(parsed.sessions) ? parsed.sessions : [],
      funnel: parsed.funnel || null,
      bottlenecks: Array.isArray(parsed.bottlenecks) ? parsed.bottlenecks : [],
      next_actions: Array.isArray(parsed.next_actions) ? parsed.next_actions : [],
      event_log: parsed.event_log || null,
    };
  } catch (error) {
    return {
      error: error && error.message ? error.message : String(error),
    };
  }
}

function existingSourcePathEntries(targetDomain) {
  const entries = [
    ["session_dir", sessionDir(targetDomain)],
    ["state", statePath(targetDomain)],
    ["attack_surface", attackSurfacePath(targetDomain)],
    ["pipeline_events", pipelineEventsJsonlPath(targetDomain)],
    ["claims", claimsJsonlPath(targetDomain)],
    ["coverage", coverageJsonlPath(targetDomain)],
    ["technique_attempts", techniqueAttemptsJsonlPath(targetDomain)],
    ["technique_pack_reads", techniquePackReadsJsonlPath(targetDomain)],
    ["chain_attempts", chainAttemptsJsonlPath(targetDomain)],
    ["http_audit", httpAuditJsonlPath(targetDomain)],
    ["report", reportMarkdownPath(targetDomain)],
  ];
  const evidence = evidencePackPaths(targetDomain);
  entries.push(["evidence_json", evidence.json], ["evidence_markdown", evidence.markdown]);
  entries.push(
    ["verification_snapshot", verificationSnapshotPath(targetDomain)],
    ["verification_adjudication", verificationAdjudicationPath(targetDomain)],
    ["verification_manifest", verificationManifestPath(targetDomain)],
  );
  const grade = gradeArtifactPaths(targetDomain);
  entries.push(["grade_json", grade.json], ["grade_markdown", grade.markdown]);
  for (const round of VERIFICATION_ROUND_VALUES) {
    const roundPaths = verificationRoundPaths(targetDomain, round);
    entries.push([`verification_${round}_json`, roundPaths.json]);
    entries.push([`verification_${round}_markdown`, roundPaths.markdown]);
  }
  const attemptsDir = verificationAttemptsDir(targetDomain);
  if (fs.existsSync(attemptsDir)) {
    for (const filePath of listFilesRecursive(attemptsDir)) {
      entries.push(["verification_archive", filePath]);
    }
  }
  return entries
    .filter(([, filePath]) => fs.existsSync(filePath))
    .map(([kind, filePath]) => ({ kind, path: filePath }));
}

function listFilesRecursive(root) {
  const files = [];
  for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
    const filePath = path.join(root, entry.name);
    if (entry.isDirectory()) {
      files.push(...listFilesRecursive(filePath));
    } else if (entry.isFile()) {
      files.push(filePath);
    }
  }
  return files.sort();
}

function readSessions(currentVersion, env) {
  const sessions = [];
  const exclusions = [];
  const sourcePaths = [];
  for (const targetDomain of listSessionDomains()) {
    const classified = classifySession(targetDomain, currentVersion);
    if (!classified.included) {
      exclusions.push(classified.exclusion);
      continue;
    }
    const artifacts = readSessionArtifactSummary(targetDomain, { validateAuthority: true });
    const analytics = parsePipelineAnalytics(targetDomain, env);
    const pipelineEvents = sortEvents(
      classified.eventRead.events.filter((event) => versionMatches(event, currentVersion)),
    );
    sessions.push({
      target_domain: targetDomain,
      session_dir: artifacts.session_dir,
      observed_bob_versions: [currentVersion],
      latest_artifact_ts: artifacts.latest_artifact_ts,
      event_log: {
        path: classified.eventRead.events_path,
        exists: classified.eventRead.exists,
        malformed_lines: classified.eventRead.malformed_lines,
        events: pipelineEvents,
      },
      artifact_summary: artifacts,
      pipeline_analytics: analytics,
    });
    sourcePaths.push(...existingSourcePathEntries(targetDomain));
  }
  sessions.sort((a, b) => (
    (timestampMs(b.latest_artifact_ts) - timestampMs(a.latest_artifact_ts)) ||
    a.target_domain.localeCompare(b.target_domain)
  ));
  exclusions.sort((a, b) => a.target_domain.localeCompare(b.target_domain));
  return { sessions, exclusions, sourcePaths };
}

function addGroup(map, key, seed = {}) {
  if (!map.has(key)) {
    map.set(key, {
      key,
      count: 0,
      targets: new Set(),
      examples: [],
      ...seed,
    });
  }
  return map.get(key);
}

function pushExample(group, example, limit = 5) {
  if (group.examples.length < limit) group.examples.push(example);
}

function groupsToArray(map, mapper) {
  return Array.from(map.values())
    .map((group) => mapper ? mapper(group) : group)
    .sort((a, b) => b.count - a.count || String(a.code || a.key).localeCompare(String(b.code || b.key)));
}

function buildPipelineBottleneckClusters(sessions) {
  const groups = new Map();
  for (const session of sessions) {
    const bottlenecks = Array.isArray(session.pipeline_analytics && session.pipeline_analytics.bottlenecks)
      ? session.pipeline_analytics.bottlenecks
      : [];
    for (const bottleneck of bottlenecks) {
      const code = capString(bottleneck.code, 120) || "unknown_bottleneck";
      const group = addGroup(groups, code, { code });
      const count = Number.isFinite(bottleneck.affected_count)
        ? Math.max(1, Math.trunc(bottleneck.affected_count))
        : 1;
      group.count += count;
      const affectedTargets = Array.isArray(bottleneck.affected_targets) && bottleneck.affected_targets.length
        ? bottleneck.affected_targets
        : [session.target_domain];
      for (const target of affectedTargets) group.targets.add(target);
      pushExample(group, {
        target_domain: session.target_domain,
        evidence: bottleneck.evidence || null,
      });
    }
  }
  return groupsToArray(groups, (group) => ({
    code: group.code,
    count: group.count,
    repeated: group.count > 1,
    targets: sortedStrings(Array.from(group.targets)),
    examples: group.examples,
  }));
}

function buildMcpToolErrorClusters(toolEvents) {
  const groups = new Map();
  for (const event of toolEvents) {
    if (event.ok) continue;
    const tool = capString(event.tool, 120) || "<unknown>";
    const errorCode = capString(event.error_code, 120) || "<unknown>";
    const group = addGroup(groups, `${tool}\0${errorCode}`, {
      tool,
      error_code: errorCode,
      latest_ts: null,
    });
    group.count += 1;
    if (event.target_domain) group.targets.add(event.target_domain);
    if (!group.latest_ts || timestampMs(event.ts) > timestampMs(group.latest_ts)) group.latest_ts = event.ts;
    pushExample(group, {
      ts: event.ts,
      target_domain: event.target_domain,
      wave: event.wave,
      agent: event.agent,
      surface_id: event.surface_id,
      error_message: event.error_message || null,
    });
  }
  return groupsToArray(groups, (group) => ({
    tool: group.tool,
    error_code: group.error_code,
    count: group.count,
    targets: sortedStrings(Array.from(group.targets)),
    latest_ts: group.latest_ts,
    examples: group.examples,
  }));
}

function buildEvaluatorBlockClusters(agentRuns) {
  const groups = new Map();
  for (const event of agentRuns) {
    if (event.status !== "blocked") continue;
    const blockCode = capString(event.block_code, 120) || "<unknown>";
    const group = addGroup(groups, blockCode, {
      block_code: blockCode,
      waves: new Set(),
      agents: new Set(),
      latest_ts: null,
    });
    group.count += 1;
    if (event.target_domain) group.targets.add(event.target_domain);
    if (event.wave) group.waves.add(event.wave);
    if (event.agent) group.agents.add(event.agent);
    if (!group.latest_ts || timestampMs(event.ts) > timestampMs(group.latest_ts)) group.latest_ts = event.ts;
    pushExample(group, {
      ts: event.ts,
      target_domain: event.target_domain,
      wave: event.wave,
      agent: event.agent,
      surface_id: event.surface_id,
      handoff: event.handoff || null,
      coverage: event.coverage || null,
      findings: event.findings || null,
    });
  }
  return groupsToArray(groups, (group) => ({
    block_code: group.block_code,
    count: group.count,
    targets: sortedStrings(Array.from(group.targets)),
    waves: sortedStrings(Array.from(group.waves)),
    agents: sortedStrings(Array.from(group.agents)),
    latest_ts: group.latest_ts,
    examples: group.examples,
  }));
}

function malformedLineCount(artifact) {
  return Number.isFinite(artifact && artifact.malformed_lines)
    ? Math.max(0, Math.trunc(artifact.malformed_lines))
    : 0;
}

function buildMalformedArtifactClusters(sessions, telemetry) {
  const clusters = [];
  if (telemetry.toolRead.malformed_lines > 0) {
    clusters.push({
      source: "tool-events",
      path: telemetry.toolRead.telemetry_path,
      count: telemetry.toolRead.malformed_lines,
      errors: [`Malformed tool-events.jsonl lines: ${telemetry.toolRead.malformed_lines}`],
    });
  }
  if (telemetry.toolInvocationRead.malformed_lines > 0) {
    clusters.push({
      source: "tool-invocations",
      path: telemetry.toolInvocationRead.telemetry_path,
      count: telemetry.toolInvocationRead.malformed_lines,
      errors: [`Malformed tool-invocations.jsonl lines: ${telemetry.toolInvocationRead.malformed_lines}`],
    });
  }
  for (const session of sessions) {
    const artifacts = session.artifact_summary;
    const errors = Array.isArray(artifacts.artifact_errors) ? artifacts.artifact_errors.slice() : [];
    const count = errors.length
      + malformedLineCount(artifacts.findings)
      + malformedLineCount(artifacts.coverage)
      + malformedLineCount(artifacts.technique_attempts)
      + malformedLineCount(artifacts.technique_pack_reads)
      + malformedLineCount(artifacts.chain_attempts)
      + (session.event_log && Number.isFinite(session.event_log.malformed_lines) ? session.event_log.malformed_lines : 0);
    if (count <= 0) continue;
    clusters.push({
      source: "session",
      target_domain: session.target_domain,
      session_dir: session.session_dir,
      count,
      malformed_counts: {
        pipeline_events: session.event_log.malformed_lines,
        findings: malformedLineCount(artifacts.findings),
        coverage: malformedLineCount(artifacts.coverage),
        technique_attempts: malformedLineCount(artifacts.technique_attempts),
        technique_pack_reads: malformedLineCount(artifacts.technique_pack_reads),
        chain_attempts: malformedLineCount(artifacts.chain_attempts),
      },
      errors,
    });
  }
  return clusters.sort((a, b) => b.count - a.count || String(a.target_domain || a.source).localeCompare(String(b.target_domain || b.source)));
}

function addBlocker(groups, code, session, detail) {
  const group = addGroup(groups, code, { code });
  group.count += 1;
  group.targets.add(session.target_domain);
  pushExample(group, {
    target_domain: session.target_domain,
    ...detail,
  });
}

function buildEvidenceReportCoverageBlockers(sessions) {
  const groups = new Map();
  for (const session of sessions) {
    const artifacts = session.artifact_summary;
    const coverage = artifacts.attack_surface_coverage || {};
    if (coverage.exists && Number.isFinite(coverage.closed_pct) && coverage.closed_pct < 100) {
      addBlocker(groups, "coverage_incomplete", session, {
        closed_pct: coverage.closed_pct,
        coverage_pct: coverage.coverage_pct,
        non_low_total: coverage.non_low_total,
        non_low_explored: coverage.non_low_explored,
        non_low_terminally_blocked: coverage.non_low_terminally_blocked,
      });
    }
    if (coverage.exists && Number.isFinite(coverage.unexplored_high) && coverage.unexplored_high > 0) {
      addBlocker(groups, "high_surfaces_unexplored", session, {
        unexplored_high: coverage.unexplored_high,
        blocked_high: coverage.blocked_high,
      });
    }
    if (coverage.exists && coverage.total_surfaces > 0 && artifacts.coverage && artifacts.coverage.total_records === 0) {
      addBlocker(groups, "coverage_records_missing", session, {
        total_surfaces: coverage.total_surfaces,
      });
    }

    const verification = artifacts.verification || {};
    const evidence = artifacts.evidence || {};
    const finalRound = verification.rounds && verification.rounds.final ? verification.rounds.final : null;
    if (artifacts.findings && artifacts.findings.total > 0 && finalRound && !finalRound.exists) {
      addBlocker(groups, "missing_final_verification", session, {
        findings_total: artifacts.findings.total,
      });
    }
    if (evidence.final_reportable_count > 0 && !evidence.valid) {
      addBlocker(groups, "evidence_invalid_or_missing", session, {
        final_reportable_count: evidence.final_reportable_count,
        reportable_findings_covered: evidence.reportable_findings_covered,
        missing_finding_ids: Array.isArray(evidence.missing_finding_ids) ? evidence.missing_finding_ids.slice(0, 10) : [],
        error: evidence.error || null,
      });
    }
    if (artifacts.state && artifacts.state.lifecycle_state === "REPORT" && artifacts.report && !artifacts.report.present) {
      addBlocker(groups, "report_missing", session, {
        lifecycle_state: artifacts.state.lifecycle_state,
        findings_total: artifacts.findings ? artifacts.findings.total : 0,
        final_reportable_count: evidence.final_reportable_count || 0,
      });
    }
    if (artifacts.grade && artifacts.grade.verdict === "HOLD") {
      addBlocker(groups, "grade_hold", session, {
        hold_reasons: artifacts.grade.hold_reasons || [],
        total_score: artifacts.grade.total_score,
      });
    }
  }
  return groupsToArray(groups, (group) => ({
    code: group.code,
    count: group.count,
    targets: sortedStrings(Array.from(group.targets)),
    examples: group.examples,
  }));
}

function buildVersionExclusionClusters(manifestExclusions) {
  const groups = new Map();
  for (const session of manifestExclusions.sessions) {
    const group = addGroup(groups, `session\0${session.reason}`, {
      kind: "session",
      reason: session.reason,
      bob_versions: new Set(),
    });
    group.count += 1;
    group.targets.add(session.target_domain);
    for (const version of session.observed_bob_versions || []) group.bob_versions.add(version);
    pushExample(group, {
      target_domain: session.target_domain,
      session_dir: session.session_dir,
      detail: session.detail,
    });
  }
  for (const [kind, rows] of Object.entries(manifestExclusions.telemetry)) {
    for (const row of rows) {
      const group = addGroup(groups, `telemetry\0${kind}\0${row.bob_version}`, {
        kind,
        reason: row.bob_version === "<unknown>" ? "unknown_version" : "version_mismatch",
        bob_versions: new Set(),
      });
      group.count += row.count;
      group.bob_versions.add(row.bob_version);
    }
  }
  return groupsToArray(groups, (group) => ({
    kind: group.kind,
    reason: group.reason,
    count: group.count,
    bob_versions: sortedStrings(Array.from(group.bob_versions)),
    targets: sortedStrings(Array.from(group.targets)),
    examples: group.examples,
  }));
}

function uniqueSourcePaths(entries) {
  const seen = new Set();
  const result = [];
  for (const entry of entries) {
    const kind = capString(entry.kind, 120) || "source";
    const filePath = capString(entry.path, 2000);
    if (!filePath) continue;
    const key = `${kind}\0${filePath}`;
    if (seen.has(key)) continue;
    seen.add(key);
    result.push({ kind, path: filePath });
  }
  return result.sort((a, b) => a.kind.localeCompare(b.kind) || a.path.localeCompare(b.path));
}

function buildProblemClusters({ bob_version: currentVersion, generated_at: generatedAt, sessions, telemetry, manifestExclusions, sources }) {
  return {
    version: EXPORT_BUNDLE_VERSION,
    bob_version: currentVersion,
    generated_at: generatedAt,
    counts: {
      included_sessions: sessions.length,
      tool_events: telemetry.toolEvents.length,
      agent_runs: telemetry.agentRuns.length,
      excluded_sessions: manifestExclusions.sessions.length,
      source_paths: sources.length,
    },
    clusters: {
      pipeline_bottlenecks: buildPipelineBottleneckClusters(sessions),
      mcp_tool_errors: buildMcpToolErrorClusters(telemetry.toolEvents),
      evaluator_blocks: buildEvaluatorBlockClusters(telemetry.agentRuns),
      malformed_artifacts: buildMalformedArtifactClusters(sessions, telemetry),
      evidence_report_coverage_blockers: buildEvidenceReportCoverageBlockers(sessions),
      version_exclusions: buildVersionExclusionClusters(manifestExclusions),
      source_paths: sources,
    },
  };
}

function renderClusterLines(title, clusters, labelFn) {
  const lines = [`## ${title}`];
  if (!clusters.length) {
    lines.push("No matching facts were observed.");
    return lines;
  }
  for (const cluster of clusters.slice(0, 10)) {
    lines.push(`- ${labelFn(cluster)}`);
  }
  return lines;
}

function summarizeReplayBudget(snapshot) {
  if (!Array.isArray(snapshot) || snapshot.length === 0) return null;
  const totals = {
    pack_count: snapshot.length,
    serialized_count: 0,
    parallel_safe_count: 0,
    active_leases_total: 0,
  };
  for (const pack of snapshot) {
    if (pack.mode === "serialized") totals.serialized_count += 1;
    else if (pack.mode === "parallel_safe") totals.parallel_safe_count += 1;
    if (Array.isArray(pack.active_leases)) totals.active_leases_total += pack.active_leases.length;
  }
  return totals;
}

function renderReplayBudgetSection(snapshot) {
  if (!Array.isArray(snapshot) || snapshot.length === 0) return [];
  const totals = summarizeReplayBudget(snapshot);
  const lines = [
    "## Replay Budget",
    `- Capability packs: ${totals.pack_count} (${totals.serialized_count} serialized, ${totals.parallel_safe_count} parallel-safe)`,
    `- Active leases at export time: ${totals.active_leases_total}`,
    "",
    "Per-pack replay policy:",
  ];
  for (const pack of snapshot) {
    const concurrency = pack.can_run_rounds_concurrently ? "concurrent rounds OK" : "rounds must serialize";
    lines.push(`- \`${pack.capability_pack}\` · mode \`${pack.mode}\` · scope \`${pack.lease_scope}\` · ${concurrency} · active leases ${pack.active_leases ? pack.active_leases.length : 0}`);
  }
  lines.push("");
  return lines;
}

function renderSummary({ manifest, problemClusters, replaySnapshot }) {
  const clusters = problemClusters.clusters;
  const lines = [
    "# Hacker Bob Release Improvement Bundle",
    "",
    `Bob version: ${manifest.bob_version}`,
    `Generated at: ${manifest.generated_at}`,
    `Bundle directory: ${manifest.bundle_dir}`,
    "",
    "## Counts",
    `- Included sessions: ${manifest.counts.included_sessions}`,
    `- Current-version tool events: ${manifest.counts.tool_events}`,
    `- Current-version agent runs: ${manifest.counts.agent_runs}`,
    `- Excluded sessions: ${manifest.counts.excluded_sessions}`,
    `- Malformed telemetry lines: ${manifest.counts.malformed_tool_event_lines + manifest.counts.malformed_agent_run_lines}`,
    "",
    ...renderClusterLines(
      "Pipeline Bottlenecks",
      clusters.pipeline_bottlenecks,
      (cluster) => `${cluster.code}: ${cluster.count} affected session${cluster.count === 1 ? "" : "s"} (${cluster.targets.join(", ") || "no target"})`,
    ),
    "",
    ...renderClusterLines(
      "MCP Tool Errors",
      clusters.mcp_tool_errors,
      (cluster) => `${cluster.tool} / ${cluster.error_code}: ${cluster.count} failure${cluster.count === 1 ? "" : "s"}`,
    ),
    "",
    ...renderClusterLines(
      "Evaluator Blocks",
      clusters.evaluator_blocks,
      (cluster) => `${cluster.block_code}: ${cluster.count} blocked run${cluster.count === 1 ? "" : "s"}`,
    ),
    "",
    ...renderClusterLines(
      "Evidence, Report, And Coverage Blockers",
      clusters.evidence_report_coverage_blockers,
      (cluster) => `${cluster.code}: ${cluster.count} session${cluster.count === 1 ? "" : "s"} (${cluster.targets.join(", ")})`,
    ),
    "",
    ...renderReplayBudgetSection(replaySnapshot),
    "This summary is deterministic telemetry clustering. It is not an assessment of target validity or impact viability.",
    "",
  ];
  return lines.join("\n");
}

function renderAgentPrompt({ manifest }) {
  return [
    "# Fresh Agent Prompt: Improve Hacker Bob From This Release Bundle",
    "",
    `This bundle was generated for Hacker Bob version ${manifest.bob_version}. It is for improving Hacker Bob itself, not for evaluating, resuming sessions, interacting with targets, or contacting third-party systems.`,
    "",
    "Start here, in order:",
    "1. Read `summary.md`.",
    "2. Read `problem-clusters.json`.",
    "3. Read `manifest.json`.",
    "",
    "Then inspect the current Hacker Bob repo before patching. Treat this bundle as evidence of recurring release behavior, not as a replacement for live source inspection.",
    "",
    "Use `source-paths.txt` only when you need raw local session evidence. Target names, paths, logs, reports, and transcript-derived metadata are sensitive; preserve user privacy and avoid copying raw target data into public docs, commits, or issue text.",
    "",
    "Storage roots used by this release:",
    "- `~/hacker-bob-sessions` (canonical session root)",
    "- `~/bounty-agent-sessions` (legacy session root, read-fallback preserved until v2.1.0 `--purge-legacy-session-root`)",
    "- `~/bounty-agent-telemetry`",
    "",
    "Do not rename those storage roots as part of a routine improvement patch unless the operator explicitly asks for a storage migration.",
    "",
    "Recommended verification commands before handing work back:",
    "```bash",
    "npm run test:mcp",
    "npm run test:prompts",
    "npm run test:install",
    "git diff --check",
    "npm test",
    "npm run release:check",
    "```",
    "",
  ].join("\n");
}

function renderSourcePaths(sources) {
  if (!sources.length) return "";
  return `${sources.map((entry) => `${entry.kind}\t${entry.path}`).join("\n")}\n`;
}

function buildManifest({
  currentVersion,
  generatedAt,
  bundleDir,
  env,
  telemetry,
  sessions,
  sessionExclusions,
  sources,
}) {
  const exclusions = {
    sessions: sessionExclusions,
    telemetry: telemetry.exclusions,
  };
  return {
    version: EXPORT_BUNDLE_VERSION,
    bob_version: currentVersion,
    generated_at: generatedAt,
    bundle_dir: bundleDir,
    telemetry_dir: telemetryDir(env),
    sessions_root: sessionsRoot(),
    output_files: BUNDLE_FILES.slice(),
    inputs: {
      tool_telemetry_path: toolTelemetryPath(env),
      tool_invocation_telemetry_path: toolInvocationTelemetryPath(env),
    },
    counts: {
      included_sessions: sessions.length,
      excluded_sessions: sessionExclusions.length,
      tool_events: telemetry.toolEvents.length,
      agent_runs: telemetry.agentRuns.length,
      malformed_tool_event_lines: telemetry.toolRead.malformed_lines,
      malformed_tool_invocation_lines: telemetry.toolInvocationRead.malformed_lines,
      source_paths: sources.length,
      version_excluded_tool_events: telemetry.exclusions.tool_events.reduce((sum, row) => sum + row.count, 0),
      version_excluded_agent_runs: telemetry.exclusions.agent_runs.reduce((sum, row) => sum + row.count, 0),
    },
    exclusions,
  };
}

function exportBobReleaseBundle(options = {}) {
  const projectDir = options.projectDir ? path.resolve(options.projectDir) : process.cwd();
  const env = {
    ...process.env,
    ...(options.env || {}),
    BOB_PROJECT_DIR: projectDir,
  };
  const now = options.now instanceof Date ? options.now : new Date();
  const generatedAt = now.toISOString();
  const currentVersion = versionKey(bobVersion(env));
  const releaseRoot = path.join(telemetryDir(env), "release-bundles", releaseDirectoryName(currentVersion));
  const bundleDir = createUniqueBundleDir(releaseRoot, timestampDirectoryName(now));

  const telemetry = readTelemetry(currentVersion, env);
  const sessionRead = readSessions(currentVersion, env);
  const sources = uniqueSourcePaths([
    { kind: "telemetry_tool_events", path: toolTelemetryPath(env) },
    { kind: "telemetry_tool_invocations", path: toolInvocationTelemetryPath(env) },
    ...sessionRead.sourcePaths,
  ]);
  const manifest = buildManifest({
    currentVersion,
    generatedAt,
    bundleDir,
    env,
    telemetry,
    sessions: sessionRead.sessions,
    sessionExclusions: sessionRead.exclusions,
    sources,
  });
  const problemClusters = buildProblemClusters({
    bob_version: currentVersion,
    generated_at: generatedAt,
    sessions: sessionRead.sessions,
    telemetry,
    manifestExclusions: manifest.exclusions,
    sources,
  });
  const sessionsDocument = {
    version: EXPORT_BUNDLE_VERSION,
    bob_version: currentVersion,
    generated_at: generatedAt,
    sessions: sessionRead.sessions,
  };

  const files = {
    AGENT_PROMPT: path.join(bundleDir, "AGENT_PROMPT.md"),
    manifest: path.join(bundleDir, "manifest.json"),
    summary: path.join(bundleDir, "summary.md"),
    problem_clusters: path.join(bundleDir, "problem-clusters.json"),
    sessions: path.join(bundleDir, "sessions.json"),
    tool_events: path.join(bundleDir, "tool-events.filtered.jsonl"),
    agent_runs: path.join(bundleDir, "tool-invocations.filtered.jsonl"),
    source_paths: path.join(bundleDir, "source-paths.txt"),
  };

  const replaySnapshot = replayExecutionPolicy();
  manifest.replay_budget = {
    snapshot: replaySnapshot,
    totals: summarizeReplayBudget(replaySnapshot),
  };
  writeJson(files.manifest, manifest);
  writeJson(files.problem_clusters, problemClusters);
  writeJson(files.sessions, sessionsDocument);
  writeJsonl(files.tool_events, telemetry.toolEvents);
  writeJsonl(files.agent_runs, telemetry.agentRuns);
  fs.writeFileSync(files.summary, renderSummary({ manifest, problemClusters, replaySnapshot }), "utf8");
  fs.writeFileSync(files.AGENT_PROMPT, renderAgentPrompt({ manifest }), "utf8");
  fs.writeFileSync(files.source_paths, renderSourcePaths(sources), "utf8");

  return {
    ok: true,
    bob_version: currentVersion,
    generated_at: generatedAt,
    bundle_dir: bundleDir,
    files,
    counts: manifest.counts,
  };
}

function renderExportResult(result) {
  return [
    `AGENT_PROMPT.md: ${result.files.AGENT_PROMPT}`,
    `Summary: ${result.counts.included_sessions} session${result.counts.included_sessions === 1 ? "" : "s"}, ${result.counts.tool_events} tool event${result.counts.tool_events === 1 ? "" : "s"}, ${result.counts.agent_runs} agent run${result.counts.agent_runs === 1 ? "" : "s"}, ${result.counts.excluded_sessions} excluded session${result.counts.excluded_sessions === 1 ? "" : "s"}.`,
    "",
  ].join("\n");
}

module.exports = {
  BUNDLE_FILES,
  EXPORT_BUNDLE_VERSION,
  buildProblemClusters,
  exportBobReleaseBundle,
  renderExportResult,
};
