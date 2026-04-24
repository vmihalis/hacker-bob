#!/usr/bin/env node
// Bounty Agent MCP Server — stdio transport, zero dependencies
// Provides: bounty_http_scan, bounty_record_finding, bounty_read_findings,
//           bounty_list_findings, bounty_write_verification_round,
//           bounty_read_verification_round, bounty_write_grade_verdict,
//           bounty_read_grade_verdict, bounty_init_session,
//           bounty_read_session_state, bounty_read_state_summary,
//           bounty_transition_phase,
//           bounty_start_wave, bounty_apply_wave_merge,
//           bounty_write_handoff, bounty_write_wave_handoff,
//           bounty_wave_handoff_status, bounty_merge_wave_handoffs,
//           bounty_read_handoff, bounty_log_dead_ends, bounty_log_coverage,
//           bounty_auth_manual, bounty_wave_status,
//           bounty_temp_email, bounty_signup_detect, bounty_auth_store,
//           bounty_auto_signup, bounty_import_http_traffic,
//           bounty_read_http_audit, bounty_public_intel

const { redactUrlSensitiveValues } = require("./redaction.js");
const {
  AUTH_STATUS_VALUES,
  COVERAGE_STATUS_VALUES,
  GRADE_VERDICT_VALUES,
  PHASE_VALUES,
  SESSION_LOCK_STALE_MS,
  SEVERITY_VALUES,
  VERIFICATION_DISPOSITION_VALUES,
  VERIFICATION_ROUND_VALUES,
} = require("./lib/constants.js");
const { normalizeStringArray } = require("./lib/validation.js");
const {
  assertSafeDomain,
  attackSurfacePath,
  coverageJsonlPath,
  findingsJsonlPath,
  findingsMarkdownPath,
  gradeArtifactPaths,
  httpAuditJsonlPath,
  publicIntelPath,
  sessionDir,
  sessionLockPath,
  statePath,
  trafficJsonlPath,
  verificationRoundPaths,
} = require("./lib/paths.js");
const {
  appendJsonlLine,
  writeFileAtomic,
} = require("./lib/storage.js");
const {
  compactSessionState,
  initSession,
  normalizeSessionStateDocument,
  readSessionState,
  readStateSummary,
  transitionPhase,
} = require("./lib/session-state.js");
const {
  buildCoverageSummaryForSurface,
  computeCoverageRequeueSurfaceIds,
  logCoverage,
  normalizeCoverageRecord,
  readCoverageRecordsFromJsonl,
} = require("./lib/coverage.js");
const {
  buildCircuitBreakerSummary,
  importHttpTraffic: importHttpTrafficRecords,
  normalizeHttpAuditRecord,
  normalizeTrafficRecord,
  readHttpAudit: readHttpAuditRecordsTool,
  readHttpAuditRecordsFromJsonl,
  readTrafficRecordsFromJsonl,
} = require("./lib/http-records.js");
const { validateScanUrl } = require("./lib/url-surface.js");
const {
  bountyPublicIntel: bountyPublicIntelTool,
} = require("./lib/public-intel.js");
const {
  listFindings,
  normalizeFindingRecord,
  normalizeGradeVerdictDocument,
  normalizeVerificationRoundDocument,
  readFindings,
  readFindingsFromJsonl,
  readGradeVerdict,
  readVerificationRound,
  recordFinding,
  renderFindingMarkdownEntry,
  renderGradeVerdictMarkdown,
  renderVerificationRoundMarkdown,
  summarizeFindings,
  writeGradeVerdict,
  writeVerificationRound,
} = require("./lib/findings.js");
const {
  readAttackSurfaceStrict,
} = require("./lib/attack-surface.js");
const {
  rankAttackSurfaces,
} = require("./lib/ranking.js");
const {
  filterExclusionsByHosts,
  readScopeExclusions,
} = require("./lib/scope.js");
const {
  readHunterBrief,
  resolveHunterKnowledge,
} = require("./lib/hunter-brief.js");
const {
  authManual,
  authStore,
  buildHeaderProfile,
  migrateAuthJson,
  readAuthJson,
  resolveAuthJsonPath,
} = require("./lib/auth.js");
const { httpScan } = require("./lib/http-scan.js");
const { tempEmail } = require("./lib/temp-email.js");
const {
  autoSignup,
  signupDetect,
} = require("./lib/signup.js");
const {
  applyWaveMerge,
  logDeadEnds,
  mergeWaveHandoffs,
  readHandoff,
  startWave,
  waveHandoffStatus,
  waveStatus,
  writeHandoff,
  writeWaveHandoff,
} = require("./lib/waves.js");

// ── Tool definitions ──
const TOOLS = [
  {
    name: "bounty_http_scan",
    description:
      "Make an HTTP request and auto-analyze for security issues. Returns status, headers, body, plus detected tech stack, leaked secrets, misconfigs, and endpoints.",
    inputSchema: {
      type: "object",
      properties: {
        method: { type: "string", enum: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"] },
        url: { type: "string" },
        headers: { type: "object", additionalProperties: { type: "string" } },
        body: { type: "string" },
        follow_redirects: { type: "boolean" },
        timeout_ms: { type: "number" },
        auth_profile: { type: "string" },
        target_domain: { type: "string", description: "Session domain for scope resolution when scanning cross-domain URLs (e.g. third-party APIs discovered on the target)." },
        wave: { type: "string", pattern: "^w[0-9]+$", description: "Optional wave ID for request audit correlation." },
        agent: { type: "string", pattern: "^a[0-9]+$", description: "Optional agent ID for request audit correlation." },
        surface_id: { type: "string", description: "Optional assigned surface ID for request audit correlation." },
        response_mode: {
          type: "string",
          enum: ["full", "status_only", "headers_only", "body_truncate"],
          description: "Control response size. 'full' (default): complete response. 'status_only': status code + redirect info only (~100 tokens). 'headers_only': status + headers, no body. 'body_truncate': status + headers + first body_limit chars of body.",
        },
        body_limit: { type: "number", description: "Max body chars when response_mode is 'body_truncate'. Default 2000." },
      },
      required: ["method", "url"],
    },
  },
  {
    name: "bounty_import_http_traffic",
    description:
      "Import Burp/HAR-style request history into session-owned traffic.jsonl. Entries are validated, capped, deduped, and limited to the target's first-party hosts.",
    inputSchema: {
      type: "object",
      properties: {
        target_domain: { type: "string" },
        source: { type: "string", description: "Traffic source label such as burp, har, browser, proxy, or manual." },
        entries: {
          oneOf: [
            { type: "array", items: { type: "object" } },
            { type: "object" },
            { type: "string" },
          ],
          description: "Array of HAR log.entries items, a HAR object with log.entries, a JSON string containing either shape, or simplified {method,url,status,headers,ts} records.",
        },
      },
      required: ["target_domain", "source"],
    },
  },
  {
    name: "bounty_read_http_audit",
    description:
      "Read a capped HTTP request audit summary from session-owned http-audit.jsonl, optionally filtered to one attack surface.",
    inputSchema: {
      type: "object",
      properties: {
        target_domain: { type: "string" },
        surface_id: { type: "string" },
        limit: { type: "number" },
      },
      required: ["target_domain"],
    },
  },
  {
    name: "bounty_public_intel",
    description:
      "Fetch optional public bug bounty intel: HackerOne-style program policy summary, stats, structured scopes, and disclosed report hints. Network/API failures degrade to empty results with errors.",
    inputSchema: {
      type: "object",
      properties: {
        target_domain: { type: "string" },
        program: { type: "string", description: "Optional HackerOne handle or program URL." },
        keywords: {
          oneOf: [
            { type: "array", items: { type: "string" } },
            { type: "string" },
          ],
          description: "Optional disclosed-report search keywords. Defaults to the target domain.",
        },
        limit: { type: "number" },
      },
      required: ["target_domain"],
    },
  },
  {
    name: "bounty_record_finding",
    description: "Record a validated security finding to structured disk artifacts. Survives context rotation.",
    inputSchema: {
      type: "object",
      properties: {
        target_domain: { type: "string" },
        title: { type: "string" },
        severity: { type: "string", enum: ["critical", "high", "medium", "low", "info"] },
        cwe: { type: "string" },
        endpoint: { type: "string" },
        description: { type: "string" },
        proof_of_concept: { type: "string" },
        response_evidence: { type: "string" },
        impact: { type: "string" },
        validated: { type: "boolean" },
        wave: { type: "string" },
        agent: { type: "string" },
      },
      required: ["target_domain", "title", "severity", "endpoint", "description", "proof_of_concept", "validated"],
    },
  },
  {
    name: "bounty_read_findings",
    description: "Read all recorded findings for a target from authoritative structured storage.",
    inputSchema: {
      type: "object",
      properties: { target_domain: { type: "string" } },
      required: ["target_domain"],
    },
  },
  {
    name: "bounty_list_findings",
    description: "List all recorded findings for a target.",
    inputSchema: {
      type: "object",
      properties: { target_domain: { type: "string" } },
      required: ["target_domain"],
    },
  },
  {
    name: "bounty_write_verification_round",
    description: "Write one verifier round to authoritative JSON plus a markdown mirror.",
    inputSchema: {
      type: "object",
      properties: {
        target_domain: { type: "string" },
        round: { type: "string", enum: VERIFICATION_ROUND_VALUES },
        notes: { type: ["string", "null"] },
        results: {
          type: "array",
          items: {
            type: "object",
            properties: {
              finding_id: { type: "string" },
              disposition: { type: "string", enum: VERIFICATION_DISPOSITION_VALUES },
              severity: { enum: [...SEVERITY_VALUES, null] },
              reportable: { type: "boolean" },
              reasoning: { type: "string" },
            },
            required: ["finding_id", "disposition", "severity", "reportable", "reasoning"],
          },
        },
      },
      required: ["target_domain", "round", "notes", "results"],
    },
  },
  {
    name: "bounty_read_verification_round",
    description: "Read one verification round JSON document.",
    inputSchema: {
      type: "object",
      properties: {
        target_domain: { type: "string" },
        round: { type: "string", enum: VERIFICATION_ROUND_VALUES },
      },
      required: ["target_domain", "round"],
    },
  },
  {
    name: "bounty_write_grade_verdict",
    description: "Write the authoritative grading verdict JSON plus a markdown mirror.",
    inputSchema: {
      type: "object",
      properties: {
        target_domain: { type: "string" },
        verdict: { type: "string", enum: GRADE_VERDICT_VALUES },
        total_score: { type: "number" },
        findings: {
          type: "array",
          items: {
            type: "object",
            properties: {
              finding_id: { type: "string" },
              impact: { type: "number" },
              proof_quality: { type: "number" },
              severity_accuracy: { type: "number" },
              chain_potential: { type: "number" },
              report_quality: { type: "number" },
              total_score: { type: "number" },
              feedback: { type: ["string", "null"] },
            },
            required: [
              "finding_id",
              "impact",
              "proof_quality",
              "severity_accuracy",
              "chain_potential",
              "report_quality",
              "total_score",
              "feedback",
            ],
          },
        },
        feedback: { type: ["string", "null"] },
      },
      required: ["target_domain", "verdict", "total_score", "findings", "feedback"],
    },
  },
  {
    name: "bounty_read_grade_verdict",
    description: "Read the authoritative grade verdict JSON document.",
    inputSchema: {
      type: "object",
      properties: { target_domain: { type: "string" } },
      required: ["target_domain"],
    },
  },
  {
    name: "bounty_init_session",
    description: "Initialize a new session state.json for a target domain.",
    inputSchema: {
      type: "object",
      properties: {
        target_domain: { type: "string" },
        target_url: { type: "string" },
      },
      required: ["target_domain", "target_url"],
    },
  },
  {
    name: "bounty_read_session_state",
    description: "Read normalized orchestrator session state from authoritative storage.",
    inputSchema: {
      type: "object",
      properties: { target_domain: { type: "string" } },
      required: ["target_domain"],
    },
  },
  {
    name: "bounty_transition_phase",
    description: "Apply one validated FSM phase transition to the persisted session state.",
    inputSchema: {
      type: "object",
      properties: {
        target_domain: { type: "string" },
        to_phase: { type: "string", enum: PHASE_VALUES },
        auth_status: { type: "string", enum: AUTH_STATUS_VALUES.filter((value) => value !== "pending") },
      },
      required: ["target_domain", "to_phase"],
    },
  },
  {
    name: "bounty_start_wave",
    description: "Persist a new wave assignment file and set pending_wave in session state.",
    inputSchema: {
      type: "object",
      properties: {
        target_domain: { type: "string" },
        wave_number: { type: "number" },
        assignments: {
          type: "array",
          items: {
            type: "object",
            properties: {
              agent: { type: "string", pattern: "^a[0-9]+$" },
              surface_id: { type: "string" },
            },
            required: ["agent", "surface_id"],
          },
        },
      },
      required: ["target_domain", "wave_number", "assignments"],
    },
  },
  {
    name: "bounty_apply_wave_merge",
    description: "Apply one wave merge to session state from authoritative structured handoff JSON, including exclusions, leads, and findings summary.",
    inputSchema: {
      type: "object",
      properties: {
        target_domain: { type: "string" },
        wave_number: { type: "number" },
        force_merge: { type: "boolean" },
      },
      required: ["target_domain", "wave_number", "force_merge"],
    },
  },
  {
    name: "bounty_write_handoff",
    description: "Write session handoff for context rotation.",
    inputSchema: {
      type: "object",
      properties: {
        target_domain: { type: "string" },
        session_number: { type: "number" },
        target_url: { type: "string" },
        program_url: { type: "string" },
        findings_summary: { type: "array", items: { type: "object", properties: { id: { type: "string" }, severity: { type: "string" }, title: { type: "string" } } } },
        attack_surface_map: { type: "array", items: { type: "string" } },
        explored_with_results: { type: "array", items: { type: "string" } },
        dead_ends: { type: "array", items: { type: "string" } },
        blockers: { type: "array", items: { type: "string" } },
        unexplored: { type: "array", items: { type: "string" } },
        must_do_next: { type: "array", items: { type: "object", properties: { priority: { type: "string" }, description: { type: "string" } } } },
        promising_leads: { type: "array", items: { type: "string" } },
      },
      required: ["target_domain", "session_number", "target_url", "explored_with_results", "must_do_next"],
    },
  },
  {
    name: "bounty_write_wave_handoff",
    description: "Hunter-final writer for one structured wave handoff as markdown plus authoritative JSON.",
    inputSchema: {
      type: "object",
      properties: {
        target_domain: { type: "string" },
        wave: { type: "string", pattern: "^w[0-9]+$" },
        agent: { type: "string", pattern: "^a[0-9]+$" },
        surface_id: { type: "string" },
        surface_status: { type: "string", enum: ["complete", "partial"] },
        content: { type: "string" },
        dead_ends: { type: "array", items: { type: "string" } },
        waf_blocked_endpoints: { type: "array", items: { type: "string" } },
        lead_surface_ids: { type: "array", items: { type: "string" } },
      },
      required: ["target_domain", "wave", "agent", "surface_id", "surface_status", "content"],
    },
  },
  {
    name: "bounty_wave_handoff_status",
    description: "Read-only readiness check for one wave. Compares expected assignments to present handoff JSON files without validating payload contents.",
    inputSchema: {
      type: "object",
      properties: {
        target_domain: { type: "string" },
        wave_number: { type: "number" },
      },
      required: ["target_domain", "wave_number"],
    },
  },
  {
    name: "bounty_merge_wave_handoffs",
    description: "Merge structured wave handoffs for one wave using the persisted assignment file.",
    inputSchema: {
      type: "object",
      properties: {
        target_domain: { type: "string" },
        wave_number: { type: "number" },
      },
      required: ["target_domain", "wave_number"],
    },
  },
  {
    name: "bounty_read_handoff",
    description: "Read previous session handoff to resume hunting.",
    inputSchema: {
      type: "object",
      properties: { target_domain: { type: "string" } },
      required: ["target_domain"],
    },
  },
  {
    name: "bounty_auth_manual",
    description: "Store auth tokens as a profile for use with bounty_http_scan.",
    inputSchema: {
      type: "object",
      properties: {
        target_domain: { type: "string" },
        profile_name: { type: "string" },
        cookies: { type: "object", additionalProperties: { type: "string" } },
        headers: { type: "object", additionalProperties: { type: "string" } },
        local_storage: { type: "object", additionalProperties: { type: "string" } },
      },
      required: ["profile_name"],
    },
  },
  {
    name: "bounty_log_dead_ends",
    description:
      "Append dead ends and WAF-blocked endpoints discovered so far. Call periodically (~every 30 turns) so terrain survives if the hunter hits maxTurns. Validated against wave assignments.",
    inputSchema: {
      type: "object",
      properties: {
        target_domain: { type: "string" },
        wave: { type: "string", pattern: "^w[0-9]+$" },
        agent: { type: "string", pattern: "^a[0-9]+$" },
        surface_id: { type: "string" },
        dead_ends: { type: "array", items: { type: "string" } },
        waf_blocked_endpoints: { type: "array", items: { type: "string" } },
      },
      required: ["target_domain", "wave", "agent", "surface_id"],
    },
  },
  {
    name: "bounty_log_coverage",
    description:
      "Append concise endpoint/bug-class/auth-profile coverage records for the assigned surface. Call after meaningful tests and before long pivots so coverage survives maxTurns. Validated against wave assignments.",
    inputSchema: {
      type: "object",
      properties: {
        target_domain: { type: "string" },
        wave: { type: "string", pattern: "^w[0-9]+$" },
        agent: { type: "string", pattern: "^a[0-9]+$" },
        surface_id: { type: "string" },
        entries: {
          type: "array",
          items: {
            type: "object",
            properties: {
              endpoint: { type: "string" },
              method: { type: "string" },
              bug_class: { type: "string" },
              auth_profile: { type: "string" },
              status: { type: "string", enum: COVERAGE_STATUS_VALUES },
              evidence_summary: { type: "string" },
              next_step: { type: "string" },
            },
            required: ["endpoint", "bug_class", "status", "evidence_summary"],
          },
        },
      },
      required: ["target_domain", "wave", "agent", "surface_id", "entries"],
    },
  },
  {
    name: "bounty_wave_status",
    description: "Read-only hunt status summary for wave decisions. Returns finding counts, severity breakdown, and per-finding metadata.",
    inputSchema: {
      type: "object",
      properties: { target_domain: { type: "string" } },
      required: ["target_domain"],
    },
  },
  {
    name: "bounty_temp_email",
    description:
      "Manage temporary email addresses for automated account registration. Operations: create (new mailbox), poll (check inbox), extract (parse verification code/link from message).",
    inputSchema: {
      type: "object",
      properties: {
        operation: { type: "string", enum: ["create", "poll", "extract"] },
        provider: { type: "string", enum: ["mail.tm", "guerrillamail"] },
        email_address: { type: "string" },
        message_id: { type: "string" },
        from_filter: { type: "string" },
      },
      required: ["operation"],
    },
  },
  {
    name: "bounty_signup_detect",
    description:
      "Probe a target for registration/signup endpoints and analyze form requirements. Returns detected endpoints, form fields, CAPTCHA presence, and signup feasibility.",
    inputSchema: {
      type: "object",
      properties: {
        target_domain: { type: "string" },
        target_url: { type: "string" },
      },
      required: ["target_domain", "target_url"],
    },
  },
  {
    name: "bounty_auth_store",
    description:
      "Store authentication profile for a specific role (attacker/victim). Supports multi-profile auth.json v2 format. Use instead of bounty_auth_manual for new sessions.",
    inputSchema: {
      type: "object",
      properties: {
        target_domain: { type: "string" },
        role: { type: "string", enum: ["attacker", "victim"] },
        cookies: { type: "object", additionalProperties: { type: "string" } },
        headers: { type: "object", additionalProperties: { type: "string" } },
        local_storage: { type: "object", additionalProperties: { type: "string" } },
        credentials: {
          type: "object",
          properties: {
            email: { type: "string" },
            password: { type: "string" },
          },
        },
      },
      required: ["target_domain", "role"],
    },
  },
  {
    name: "bounty_auto_signup",
    description:
      "Automated browser-based account registration using Patchright (stealth Playwright fork) with CAPTCHA solving. Fills signup forms with human-like interaction, solves reCAPTCHA/hCaptcha/Turnstile via CapSolver, and returns extracted auth tokens. Requires patchright to be installed (optional dep). Set CAPSOLVER_API_KEY env var for CAPTCHA solving.",
    inputSchema: {
      type: "object",
      properties: {
        target_domain: { type: "string" },
        signup_url: { type: "string" },
        email: { type: "string" },
        password: { type: "string" },
        name: { type: "string" },
        role: { type: "string", enum: ["attacker", "victim"], default: "attacker" },
        proxy: { type: "string" },
        headless: { type: "boolean" },
        timeout_ms: { type: "number" },
      },
      required: ["target_domain", "signup_url", "email", "password"],
    },
  },
  {
    name: "bounty_read_state_summary",
    description: "Lightweight session state view (~500 tokens). Returns phase, wave, finding count, coverage, and array sizes without the full dead_ends/waf arrays. Use this instead of bounty_read_session_state when you only need to check progress.",
    inputSchema: {
      type: "object",
      properties: { target_domain: { type: "string" } },
      required: ["target_domain"],
    },
  },
  {
    name: "bounty_read_hunter_brief",
    description:
      "Return everything a hunter needs to start testing: assigned surface, exclusions, valid surface IDs, bypass table, and bounded curated technique guidance. Hunters call this once on startup instead of receiving everything via spawn prompt.",
    inputSchema: {
      type: "object",
      properties: {
        target_domain: { type: "string" },
        wave: { type: "string", pattern: "^w[0-9]+$" },
        agent: { type: "string", pattern: "^a[0-9]+$" },
      },
      required: ["target_domain", "wave", "agent"],
    },
  },
];

function importHttpTraffic(args) {
  return importHttpTrafficRecords(args, { rankAttackSurfaces });
}

function readHttpAudit(args) {
  return readHttpAuditRecordsTool(args, { readAttackSurfaceStrict });
}

async function bountyPublicIntel(args) {
  return bountyPublicIntelTool(args, { rankAttackSurfaces });
}

// ── Tool dispatch ──
async function executeTool(name, args) {
  switch (name) {
    case "bounty_http_scan": return httpScan(args);
    case "bounty_record_finding": return recordFinding(args);
    case "bounty_read_findings": return readFindings(args);
    case "bounty_list_findings": return listFindings(args);
    case "bounty_write_verification_round": return writeVerificationRound(args);
    case "bounty_read_verification_round": return readVerificationRound(args);
    case "bounty_write_grade_verdict": return writeGradeVerdict(args);
    case "bounty_read_grade_verdict": return readGradeVerdict(args);
    case "bounty_init_session": return initSession(args);
    case "bounty_read_session_state": return readSessionState(args);
    case "bounty_read_state_summary": return readStateSummary(args);
    case "bounty_transition_phase": return transitionPhase(args);
    case "bounty_start_wave": return startWave(args);
    case "bounty_apply_wave_merge": return applyWaveMerge(args);
    case "bounty_write_handoff": return writeHandoff(args);
    case "bounty_log_dead_ends": return logDeadEnds(args);
    case "bounty_log_coverage": return logCoverage(args);
    case "bounty_write_wave_handoff": return writeWaveHandoff(args);
    case "bounty_wave_handoff_status": return waveHandoffStatus(args);
    case "bounty_merge_wave_handoffs": return mergeWaveHandoffs(args);
    case "bounty_read_handoff": return readHandoff(args);
    case "bounty_auth_manual": return authManual(args);
    case "bounty_wave_status": return waveStatus(args);
    case "bounty_import_http_traffic": return importHttpTraffic(args);
    case "bounty_read_http_audit": return readHttpAudit(args);
    case "bounty_public_intel": return bountyPublicIntel(args);
    case "bounty_temp_email": return tempEmail(args);
    case "bounty_signup_detect": return signupDetect(args);
    case "bounty_auth_store": return authStore(args);
    case "bounty_auto_signup": return autoSignup(args);
    case "bounty_read_hunter_brief": return readHunterBrief(args);
    default: return JSON.stringify({ error: `Unknown tool: ${name}` });
  }
}

// ── MCP stdio transport ──
let transportMode = "framed";
let buffer = "";

function send(msg) {
  const json = JSON.stringify(msg);
  if (transportMode === "raw") {
    process.stdout.write(`${json}\n`);
    return;
  }
  process.stdout.write(`Content-Length: ${Buffer.byteLength(json)}\r\n\r\n${json}`);
}

async function handleMessage(rpc) {
  switch (rpc.method) {
    case "initialize":
      send({
        jsonrpc: "2.0",
        id: rpc.id,
        result: {
          protocolVersion: rpc.params?.protocolVersion || "2025-11-25",
          capabilities: { tools: {} },
          serverInfo: { name: "bountyagent", version: "1.0.0" },
        },
      });
      break;

    case "ping":
      send({
        jsonrpc: "2.0",
        id: rpc.id,
        result: {},
      });
      break;

    case "notifications/initialized":
      // No response needed for notifications
      break;

    case "tools/list":
      send({
        jsonrpc: "2.0",
        id: rpc.id,
        result: { tools: TOOLS },
      });
      break;

    case "tools/call": {
      const { name, arguments: args } = rpc.params;
      try {
        const result = await executeTool(name, args || {});
        send({
          jsonrpc: "2.0",
          id: rpc.id,
          result: {
            content: [{ type: "text", text: typeof result === "string" ? result : JSON.stringify(result, null, 2) }],
          },
        });
      } catch (e) {
        send({
          jsonrpc: "2.0",
          id: rpc.id,
          result: {
            content: [{ type: "text", text: JSON.stringify({ error: e.message || String(e) }) }],
          },
        });
      }
      break;
    }

    default:
      if (rpc.id) {
        send({
          jsonrpc: "2.0",
          id: rpc.id,
          error: { code: -32601, message: `Method not found: ${rpc.method}` },
        });
      }
      break;
  }
}

function startServer() {
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", (chunk) => {
    buffer += chunk;
    while (true) {
      const headerEnd = buffer.indexOf("\r\n\r\n");
      if (headerEnd === -1) {
        const trimmed = buffer.trim();
        if (!trimmed) break;

        // Claude Code health checks may send a single raw JSON-RPC message
        // without Content-Length framing. Accept that shape too.
        try {
          const msg = JSON.parse(trimmed);
          transportMode = "raw";
          buffer = "";
          handleMessage(msg);
          continue;
        } catch {
          if (buffer.includes("\n")) {
            const lines = buffer.split("\n");
            buffer = lines.pop() ?? "";
            let parsedAny = false;
            for (const line of lines.map((l) => l.trim()).filter(Boolean)) {
              try {
                transportMode = "raw";
                handleMessage(JSON.parse(line));
                parsedAny = true;
              } catch {
                buffer = `${line}\n${buffer}`;
              }
            }
            if (parsedAny) continue;
          }
        }
        break;
      }

      const headerPart = buffer.slice(0, headerEnd);
      const match = headerPart.match(/Content-Length:\s*(\d+)/i);
      if (!match) {
        // Try parsing as raw JSON (some clients skip Content-Length)
        try {
          const lines = buffer.split("\n").filter((l) => l.trim());
          for (const line of lines) {
            const msg = JSON.parse(line);
            handleMessage(msg);
          }
          buffer = "";
          return;
        } catch {
          buffer = buffer.slice(headerEnd + 4);
          continue;
        }
      }

      const contentLength = parseInt(match[1], 10);
      transportMode = "framed";
      const bodyStart = headerEnd + 4;
      if (buffer.length < bodyStart + contentLength) break;

      const body = buffer.slice(bodyStart, bodyStart + contentLength);
      buffer = buffer.slice(bodyStart + contentLength);

      try {
        const msg = JSON.parse(body);
        handleMessage(msg);
      } catch {
        send({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } });
      }
    }
  });

  process.stderr.write("bountyagent MCP server running (stdio)\n");
}

module.exports = {
  TOOLS,
  SESSION_LOCK_STALE_MS,
  assertSafeDomain,
  validateScanUrl,
  attackSurfacePath,
  appendJsonlLine,
  applyWaveMerge,
  autoSignup,
  authStore,
  buildHeaderProfile,
  buildCoverageSummaryForSurface,
  buildCircuitBreakerSummary,
  computeCoverageRequeueSurfaceIds,
  coverageJsonlPath,
  gradeArtifactPaths,
  httpAuditJsonlPath,
  importHttpTraffic,
  initSession,
  listFindings,
  logCoverage,
  mergeWaveHandoffs,
  migrateAuthJson,
  normalizeCoverageRecord,
  normalizeFindingRecord,
  normalizeGradeVerdictDocument,
  normalizeHttpAuditRecord,
  normalizeSessionStateDocument,
  normalizeTrafficRecord,
  publicIntelPath,
  bountyPublicIntel,
  readAuthJson,
  resolveAuthJsonPath,
  sessionDir,
  sessionLockPath,
  statePath,
  startWave,
  findingsJsonlPath,
  findingsMarkdownPath,
  trafficJsonlPath,
  readFindings,
  readCoverageRecordsFromJsonl,
  readHttpAudit,
  readHttpAuditRecordsFromJsonl,
  readTrafficRecordsFromJsonl,
  readFindingsFromJsonl,
  redactUrlSensitiveValues,
  filterExclusionsByHosts,
  readHunterBrief,
  rankAttackSurfaces,
  resolveHunterKnowledge,
  readGradeVerdict,
  readScopeExclusions,
  readSessionState,
  readStateSummary,
  compactSessionState,
  readVerificationRound,
  recordFinding,
  renderFindingMarkdownEntry,
  renderGradeVerdictMarkdown,
  renderVerificationRoundMarkdown,
  signupDetect,
  summarizeFindings,
  tempEmail,
  transitionPhase,
  verificationRoundPaths,
  waveHandoffStatus,
  waveStatus,
  writeGradeVerdict,
  writeHandoff,
  writeVerificationRound,
  writeWaveHandoff,
  normalizeStringArray,
  writeFileAtomic,
  executeTool,
  startServer,
};

if (require.main === module) {
  startServer();
}
