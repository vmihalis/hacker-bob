#!/usr/bin/env node
// Bounty Agent MCP Server — stdio transport, zero dependencies
// Provides: bounty_http_scan, bounty_record_finding, bounty_read_findings,
//           bounty_list_findings, bounty_write_verification_round,
//           bounty_read_verification_round, bounty_write_grade_verdict,
//           bounty_read_grade_verdict, bounty_init_session,
//           bounty_read_session_state, bounty_transition_phase,
//           bounty_start_wave, bounty_apply_wave_merge,
//           bounty_write_handoff, bounty_write_wave_handoff,
//           bounty_wave_handoff_status, bounty_merge_wave_handoffs,
//           bounty_read_handoff, bounty_log_dead_ends,
//           bounty_auth_manual, bounty_wave_status,
//           bounty_temp_email, bounty_signup_detect, bounty_auth_store,
//           bounty_auto_signup

const fs = require("fs");
const path = require("path");
const os = require("os");

// ── In-memory state ──
const authProfiles = new Map();
const tempMailboxes = new Map(); // email_address → { provider, address, password, token, domain, login }

const FINDING_ID_RE = /^F-([1-9]\d*)$/;
const SEVERITY_VALUES = ["critical", "high", "medium", "low", "info"];
const PHASE_VALUES = ["RECON", "AUTH", "HUNT", "CHAIN", "VERIFY", "GRADE", "REPORT"];
const AUTH_STATUS_VALUES = ["pending", "authenticated", "unauthenticated"];
const VERIFICATION_ROUND_VALUES = ["brutalist", "balanced", "final"];
const VERIFICATION_DISPOSITION_VALUES = ["confirmed", "denied", "downgraded"];
const GRADE_VERDICT_VALUES = ["SUBMIT", "HOLD", "SKIP"];
const SESSION_LOCK_NAME = ".session.lock";
const SESSION_LOCK_STALE_MS = 300_000;
const SESSION_PUBLIC_STATE_FIELDS = [
  "target",
  "target_url",
  "phase",
  "hunt_wave",
  "pending_wave",
  "total_findings",
  "explored",
  "dead_ends",
  "waf_blocked_endpoints",
  "lead_surface_ids",
  "scope_exclusions",
  "hold_count",
  "auth_status",
];
const VERIFICATION_ROUND_FILE_MAP = {
  brutalist: { json: "brutalist.json", markdown: "brutalist.md" },
  balanced: { json: "balanced.json", markdown: "balanced.md" },
  final: { json: "verified-final.json", markdown: "verified-final.md" },
};

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
      },
      required: ["method", "url"],
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
    name: "bounty_read_hunter_brief",
    description:
      "Return everything a hunter needs to start testing: assigned surface, exclusions, valid surface IDs, and bypass table. Hunters call this once on startup instead of receiving everything via spawn prompt.",
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

// ── Session path helper ──
function assertSafeDomain(domain) {
  const trimmed = assertNonEmptyString(domain, "target_domain");
  if (/[\/\\]/.test(trimmed) || /(?:^|\.)\.\.(?:\.|$)/.test(trimmed)) {
    throw new Error(`target_domain contains invalid path characters: ${trimmed}`);
  }
  return trimmed;
}

function sessionDir(domain) {
  const safe = assertSafeDomain(domain);
  return path.join(os.homedir(), "bounty-agent-sessions", safe);
}

function statePath(domain) {
  return path.join(sessionDir(domain), "state.json");
}

function attackSurfacePath(domain) {
  return path.join(sessionDir(domain), "attack_surface.json");
}

function sessionLockPath(domain) {
  return path.join(sessionDir(domain), SESSION_LOCK_NAME);
}

function waveAssignmentsPath(domain, waveNumber) {
  return path.join(sessionDir(domain), `wave-${waveNumber}-assignments.json`);
}

function scopeWarningsPath(domain) {
  return path.join(sessionDir(domain), "scope-warnings.log");
}

function buildInitialSessionState(domain, targetUrl) {
  return {
    target: domain,
    target_url: targetUrl,
    phase: "RECON",
    hunt_wave: 0,
    pending_wave: null,
    total_findings: 0,
    explored: [],
    dead_ends: [],
    waf_blocked_endpoints: [],
    lead_surface_ids: [],
    scope_exclusions: [],
    hold_count: 0,
    auth_status: "pending",
  };
}

function publicSessionState(state) {
  return SESSION_PUBLIC_STATE_FIELDS.reduce((result, field) => {
    result[field] = state[field];
    return result;
  }, {});
}

const WAVE_ID_RE = /^w([1-9]\d*)$/;
const AGENT_ID_RE = /^a([1-9]\d*)$/;

function assertNonEmptyString(value, fieldName) {
  if (typeof value !== "string" || !value.trim()) {
    throw new Error(`${fieldName} must be a non-empty string`);
  }
  return value.trim();
}

function parseWaveId(value, fieldName = "wave") {
  const wave = assertNonEmptyString(value, fieldName);
  if (!WAVE_ID_RE.test(wave)) {
    throw new Error(`${fieldName} must match wN`);
  }
  return wave;
}

function parseAgentId(value, fieldName = "agent") {
  const agent = assertNonEmptyString(value, fieldName);
  if (!AGENT_ID_RE.test(agent)) {
    throw new Error(`${fieldName} must match aN`);
  }
  return agent;
}

function parseWaveNumber(value, fieldName = "wave_number") {
  if (!Number.isInteger(value) || value < 1) {
    throw new Error(`${fieldName} must be a positive integer`);
  }
  return value;
}

function parseSurfaceStatus(value) {
  if (value !== "complete" && value !== "partial") {
    throw new Error(`surface_status must be "complete" or "partial"`);
  }
  return value;
}

function normalizeStringArray(value, fieldName) {
  if (value == null) return [];
  if (!Array.isArray(value)) {
    throw new Error(`${fieldName} must be an array of strings`);
  }

  const normalized = [];
  const seen = new Set();
  for (const item of value) {
    if (typeof item !== "string") {
      throw new Error(`${fieldName} must contain only strings`);
    }
    const trimmed = item.trim();
    if (!trimmed || seen.has(trimmed)) continue;
    seen.add(trimmed);
    normalized.push(trimmed);
  }
  return normalized;
}

function pushUnique(target, seen, values) {
  for (const value of values) {
    if (seen.has(value)) continue;
    seen.add(value);
    target.push(value);
  }
}

function compareAgentLabels(a, b) {
  const aMatch = typeof a === "string" && a.match(AGENT_ID_RE);
  const bMatch = typeof b === "string" && b.match(AGENT_ID_RE);

  if (aMatch && bMatch) {
    return Number(aMatch[1]) - Number(bMatch[1]);
  }
  if (aMatch) return -1;
  if (bMatch) return 1;
  return String(a).localeCompare(String(b));
}

function readJsonFile(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function writeFileAtomic(filePath, content) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const tempPath = path.join(
    path.dirname(filePath),
    `.${path.basename(filePath)}.${process.pid}.${Date.now()}.${Math.random().toString(16).slice(2)}.tmp`,
  );
  fs.writeFileSync(tempPath, content);
  fs.renameSync(tempPath, filePath);
}

function normalizeSessionStateDocument(document, requestedDomain) {
  if (document == null || typeof document !== "object" || Array.isArray(document)) {
    throw new Error("expected object");
  }

  if (document.target != null) {
    assertNonEmptyString(document.target, "target");
  }

  return {
    target: requestedDomain,
    target_url: assertNonEmptyString(document.target_url, "target_url"),
    phase: assertEnumValue(document.phase, PHASE_VALUES, "phase"),
    hunt_wave: document.hunt_wave == null
      ? 0
      : assertInteger(document.hunt_wave, "hunt_wave", { min: 0 }),
    pending_wave: document.pending_wave == null
      ? null
      : assertInteger(document.pending_wave, "pending_wave", { min: 1 }),
    total_findings: document.total_findings == null
      ? 0
      : assertInteger(document.total_findings, "total_findings", { min: 0 }),
    explored: normalizeStringArray(document.explored, "explored"),
    dead_ends: normalizeStringArray(document.dead_ends, "dead_ends"),
    waf_blocked_endpoints: normalizeStringArray(document.waf_blocked_endpoints, "waf_blocked_endpoints"),
    lead_surface_ids: normalizeStringArray(document.lead_surface_ids, "lead_surface_ids"),
    scope_exclusions: normalizeStringArray(document.scope_exclusions, "scope_exclusions"),
    hold_count: document.hold_count == null
      ? 0
      : assertInteger(document.hold_count, "hold_count", { min: 0 }),
    auth_status: document.auth_status == null
      ? "pending"
      : assertEnumValue(document.auth_status, AUTH_STATUS_VALUES, "auth_status"),
  };
}

function readSessionStateStrict(domain) {
  const normalizedDomain = assertNonEmptyString(domain, "target_domain");
  const filePath = statePath(normalizedDomain);

  if (!fs.existsSync(filePath)) {
    throw new Error(`Missing session state: ${filePath}`);
  }

  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch (error) {
    throw new Error(`Malformed session state: ${filePath} (${error.message || String(error)})`);
  }

  try {
    return {
      dir: sessionDir(normalizedDomain),
      path: filePath,
      raw: parsed,
      state: normalizeSessionStateDocument(parsed, normalizedDomain),
    };
  } catch (error) {
    throw new Error(`Malformed session state: ${filePath} (${error.message || String(error)})`);
  }
}

function composeSessionStateDocument(rawDocument, state) {
  return {
    ...rawDocument,
    ...publicSessionState(state),
  };
}

function writeSessionStateDocument(domain, rawDocument, state) {
  const filePath = statePath(domain);
  const nextDocument = composeSessionStateDocument(rawDocument, state);
  writeFileAtomic(filePath, `${JSON.stringify(nextDocument, null, 2)}\n`);
  return nextDocument;
}

function isSessionDirEffectivelyEmpty(dirPath) {
  if (!fs.existsSync(dirPath)) {
    return true;
  }

  const entries = fs.readdirSync(dirPath).filter((entry) => entry !== SESSION_LOCK_NAME);
  return entries.length === 0;
}

function tryAcquireSessionLock(lockPathValue) {
  try {
    fs.mkdirSync(lockPathValue);
    return true;
  } catch (error) {
    if (error && error.code === "EEXIST") {
      return false;
    }
    throw error;
  }
}

function acquireSessionLock(domain) {
  const dir = sessionDir(domain);
  fs.mkdirSync(dir, { recursive: true });

  const lockPathValue = sessionLockPath(domain);
  for (let attempt = 0; attempt < 2; attempt += 1) {
    if (tryAcquireSessionLock(lockPathValue)) {
      // Write a marker file so we can verify lock ownership
      const markerPath = path.join(lockPathValue, `owner-${process.pid}-${Date.now()}`);
      try { fs.writeFileSync(markerPath, ""); } catch {}
      return () => {
        try {
          fs.rmSync(lockPathValue, { recursive: true, force: true });
        } catch {}
      };
    }

    let isStale = false;
    try {
      const stats = fs.statSync(lockPathValue);
      isStale = Date.now() - stats.mtimeMs > SESSION_LOCK_STALE_MS;
    } catch {}

    if (attempt === 0 && isStale) {
      try {
        fs.rmSync(lockPathValue, { recursive: true, force: true });
      } catch {}
      // Re-check: if another process grabbed it between rmSync and our next mkdirSync,
      // tryAcquireSessionLock will return false and we'll throw "lock busy" on attempt 1
      continue;
    }

    throw new Error(`Session lock busy: ${dir}`);
  }

  throw new Error(`Session lock busy: ${dir}`);
}

function withSessionLock(domain, callback) {
  const release = acquireSessionLock(domain);
  try {
    return callback();
  } finally {
    release();
  }
}

function loadWaveAssignments(domain, waveNumber) {
  const dir = sessionDir(domain);
  const assignmentsPath = waveAssignmentsPath(domain, waveNumber);

  if (!fs.existsSync(assignmentsPath)) {
    throw new Error(`Missing assignment file: ${assignmentsPath}`);
  }

  const assignmentsDoc = readJsonFile(assignmentsPath);
  if (assignmentsDoc == null || typeof assignmentsDoc !== "object" || Array.isArray(assignmentsDoc)) {
    throw new Error(`Invalid assignment file: ${assignmentsPath}`);
  }
  if (assignmentsDoc.wave_number !== waveNumber) {
    throw new Error(`Assignment file wave_number mismatch in ${assignmentsPath}`);
  }
  if (!Array.isArray(assignmentsDoc.assignments)) {
    throw new Error(`Assignment file assignments must be an array in ${assignmentsPath}`);
  }

  const assignments = [];
  const assignmentByAgent = new Map();
  for (const assignment of assignmentsDoc.assignments) {
    if (assignment == null || typeof assignment !== "object" || Array.isArray(assignment)) {
      throw new Error(`Invalid assignment entry in ${assignmentsPath}`);
    }
    const agent = parseAgentId(assignment.agent);
    const surfaceId = assertNonEmptyString(assignment.surface_id, "surface_id");
    if (assignmentByAgent.has(agent)) {
      throw new Error(`Duplicate assignment for ${agent} in ${assignmentsPath}`);
    }
    const normalizedAssignment = { agent, surface_id: surfaceId };
    assignments.push(normalizedAssignment);
    assignmentByAgent.set(agent, normalizedAssignment);
  }

  return { dir, wave: `w${waveNumber}`, assignmentsPath, assignments, assignmentByAgent };
}

function listWaveHandoffFiles(dir, wave) {
  const handoffPrefix = `handoff-${wave}-`;
  // Readiness intentionally indexes only structured handoff JSON. Markdown handoffs are for humans/debugging.
  return fs.existsSync(dir)
    ? fs.readdirSync(dir)
        .filter((name) => name.startsWith(handoffPrefix) && name.endsWith(".json"))
        .sort()
    : [];
}

function buildWaveHandoffFileIndex(dir, wave, assignmentByAgent) {
  const handoffFiles = listWaveHandoffFiles(dir, wave);
  const handoffPathByAgent = new Map();
  const unexpectedAgentSet = new Set();

  for (const fileName of handoffFiles) {
    const rawAgent = fileName.slice(`handoff-${wave}-`.length, -".json".length);
    if (!assignmentByAgent.has(rawAgent)) {
      unexpectedAgentSet.add(rawAgent);
      continue;
    }
    handoffPathByAgent.set(rawAgent, path.join(dir, fileName));
  }

  return {
    handoffFiles,
    handoffPathByAgent,
    unexpectedAgents: Array.from(unexpectedAgentSet).sort(compareAgentLabels),
  };
}

function normalizeWaveAssignmentsInput(assignments) {
  if (!Array.isArray(assignments) || assignments.length === 0) {
    throw new Error("assignments must be a non-empty array");
  }

  const normalizedAssignments = [];
  const seenAgents = new Set();
  const seenSurfaceIds = new Set();

  for (const assignment of assignments) {
    if (assignment == null || typeof assignment !== "object" || Array.isArray(assignment)) {
      throw new Error("assignments entries must be objects");
    }

    const agent = parseAgentId(assignment.agent);
    const surfaceId = assertNonEmptyString(assignment.surface_id, "surface_id");

    if (seenAgents.has(agent)) {
      throw new Error(`Duplicate assignment for ${agent}`);
    }
    if (seenSurfaceIds.has(surfaceId)) {
      throw new Error(`Duplicate surface_id in assignments: ${surfaceId}`);
    }

    seenAgents.add(agent);
    seenSurfaceIds.add(surfaceId);
    normalizedAssignments.push({ agent, surface_id: surfaceId });
  }

  return normalizedAssignments;
}

function validateAssignedWaveAgentSurface(domain, wave, agent, surfaceId) {
  const waveNumber = Number(wave.slice(1));
  const { assignmentByAgent } = loadWaveAssignments(domain, waveNumber);
  const assignment = assignmentByAgent.get(agent);
  if (!assignment) {
    throw new Error(`Agent ${agent} is not assigned in wave ${wave}`);
  }
  if (assignment.surface_id !== surfaceId) {
    throw new Error(`Agent ${agent} is assigned surface ${assignment.surface_id}, not ${surfaceId}`);
  }
  return assignment;
}

function loadWaveArtifacts(domain, waveNumber) {
  const assignmentsInfo = loadWaveAssignments(domain, waveNumber);
  const handoffInfo = buildWaveHandoffFileIndex(
    assignmentsInfo.dir,
    assignmentsInfo.wave,
    assignmentsInfo.assignmentByAgent,
  );

  return {
    ...assignmentsInfo,
    ...handoffInfo,
  };
}

function buildWaveReadiness(artifacts) {
  const receivedAgents = [];
  const missingAgents = [];

  for (const assignment of artifacts.assignments) {
    if (artifacts.handoffPathByAgent.has(assignment.agent)) {
      receivedAgents.push(assignment.agent);
    } else {
      missingAgents.push(assignment.agent);
    }
  }

  return {
    assignments_total: artifacts.assignments.length,
    handoffs_total: artifacts.handoffFiles.length,
    received_agents: receivedAgents,
    missing_agents: missingAgents,
    unexpected_agents: artifacts.unexpectedAgents,
    is_complete: missingAgents.length === 0,
  };
}

function mergeWaveHandoffsInternal(domain, waveNumber) {
  const artifacts = loadWaveArtifacts(domain, waveNumber);
  const readiness = buildWaveReadiness(artifacts);

  const receivedAgents = [];
  const invalidAgents = [];
  const completedSurfaceIds = [];
  const partialSurfaceIds = [];
  const missingSurfaceIds = [];
  const deadEnds = [];
  const wafBlockedEndpoints = [];
  const leadSurfaceIds = [];

  const deadEndSet = new Set();
  const wafSet = new Set();
  const leadSet = new Set();

  for (const assignment of artifacts.assignments) {
    const filePath = artifacts.handoffPathByAgent.get(assignment.agent);
    if (!filePath) {
      missingSurfaceIds.push(assignment.surface_id);
      continue;
    }

    try {
      const payload = validateWaveHandoffPayload(readJsonFile(filePath), {
        targetDomain: domain,
        wave: artifacts.wave,
        agent: assignment.agent,
        surfaceId: assignment.surface_id,
      });

      receivedAgents.push(assignment.agent);
      if (payload.surface_status === "complete") {
        completedSurfaceIds.push(assignment.surface_id);
      } else {
        partialSurfaceIds.push(assignment.surface_id);
      }
      pushUnique(deadEnds, deadEndSet, payload.dead_ends);
      pushUnique(wafBlockedEndpoints, wafSet, payload.waf_blocked_endpoints);
      pushUnique(leadSurfaceIds, leadSet, payload.lead_surface_ids);
    } catch {
      invalidAgents.push(assignment.agent);
    }
  }

  for (const assignment of artifacts.assignments) {
    const logPath = path.join(artifacts.dir, `live-dead-ends-${artifacts.wave}-${assignment.agent}.jsonl`);
    if (!fs.existsSync(logPath)) continue;
    let raw;
    try {
      raw = fs.readFileSync(logPath, "utf8");
    } catch {
      continue;
    }
    const lines = raw.trim().split("\n");
    for (const line of lines) {
      if (!line) continue;
      try {
        const record = JSON.parse(line);
        if (record.surface_id !== assignment.surface_id) continue;
        pushUnique(deadEnds, deadEndSet, normalizeStringArray(record.dead_ends, "live_dead_ends"));
        pushUnique(wafBlockedEndpoints, wafSet, normalizeStringArray(record.waf_blocked_endpoints, "live_waf_blocked"));
      } catch {
        // Skip malformed line, keep processing remaining records
      }
    }
  }

  return {
    artifacts,
    readiness,
    merge: {
      received_agents: receivedAgents,
      invalid_agents: invalidAgents,
      unexpected_agents: readiness.unexpected_agents,
      completed_surface_ids: completedSurfaceIds,
      partial_surface_ids: partialSurfaceIds,
      missing_surface_ids: missingSurfaceIds,
      dead_ends: deadEnds,
      waf_blocked_endpoints: wafBlockedEndpoints,
      lead_surface_ids: leadSurfaceIds,
    },
  };
}

function computeRequeueSurfaceIds(artifacts, merge) {
  const requeueSurfaceIds = [];
  const seen = new Set();
  pushUnique(requeueSurfaceIds, seen, merge.partial_surface_ids);
  pushUnique(requeueSurfaceIds, seen, merge.missing_surface_ids);

  for (const agent of merge.invalid_agents) {
    const assignment = artifacts.assignmentByAgent.get(agent);
    if (!assignment) continue;
    pushUnique(requeueSurfaceIds, seen, [assignment.surface_id]);
  }

  return requeueSurfaceIds;
}

function readAttackSurfaceStrict(domain) {
  const filePath = attackSurfacePath(domain);
  if (!fs.existsSync(filePath)) {
    throw new Error(`Missing attack surface JSON: ${filePath}`);
  }

  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch (error) {
    throw new Error(`Malformed attack surface JSON: ${filePath} (${error.message || String(error)})`);
  }

  if (parsed == null || typeof parsed !== "object" || Array.isArray(parsed) || !Array.isArray(parsed.surfaces)) {
    throw new Error(`Malformed attack surface JSON: ${filePath} (expected object with surfaces array)`);
  }

  const surfaceIds = [];
  const surfaceIdSet = new Set();
  for (const surface of parsed.surfaces) {
    let surfaceId;
    try {
      if (surface == null || typeof surface !== "object" || Array.isArray(surface)) {
        throw new Error("invalid surface entry");
      }
      surfaceId = assertNonEmptyString(surface.id, "surface.id");
    } catch (error) {
      throw new Error(`Malformed attack surface JSON: ${filePath} (${error.message || String(error)})`);
    }
    if (surfaceIdSet.has(surfaceId)) continue;
    surfaceIdSet.add(surfaceId);
    surfaceIds.push(surfaceId);
  }

  return {
    path: filePath,
    document: parsed,
    surface_ids: surfaceIds,
    surface_id_set: surfaceIdSet,
  };
}

function summarizeFindings(findings) {
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };

  for (const finding of findings) {
    bySeverity[finding.severity] += 1;
  }

  return {
    total: findings.length,
    by_severity: bySeverity,
    has_high_or_critical: bySeverity.critical + bySeverity.high > 0,
  };
}

function normalizeScopeExclusionToken(token) {
  if (typeof token !== "string") {
    return null;
  }

  const trimmed = token.trim().replace(/^["']+|["']+$/g, "");
  if (!trimmed) {
    return null;
  }

  try {
    const parsed = new URL(trimmed);
    if (parsed.hostname) {
      return parsed.hostname.trim().toLowerCase();
    }
  } catch {}

  const hostCandidate = trimmed
    .split(/[/?#]/, 1)[0]
    .split(":", 1)[0]
    .trim()
    .replace(/\.+$/, "");
  if (/^[A-Za-z0-9][A-Za-z0-9._-]*\.[A-Za-z]{2,63}$/.test(hostCandidate)) {
    return hostCandidate.toLowerCase();
  }

  return trimmed;
}

function readScopeExclusions(domain) {
  const logPath = scopeWarningsPath(domain);
  if (!fs.existsSync(logPath)) {
    return [];
  }

  let raw;
  try {
    raw = fs.readFileSync(logPath, "utf8");
  } catch {
    return [];
  }

  const exclusions = [];
  const seen = new Set();
  for (const line of raw.split("\n")) {
    const match = line.match(/OUT-OF-SCOPE(?: \(http_scan\))?:\s*(.+?)\s*\((?:command|url):/);
    if (!match) continue;
    const normalized = normalizeScopeExclusionToken(match[1]);
    if (!normalized || seen.has(normalized)) continue;
    seen.add(normalized);
    exclusions.push(normalized);
  }

  return exclusions;
}

function assertRequiredText(value, fieldName) {
  if (typeof value !== "string" || !value.trim()) {
    throw new Error(`${fieldName} must be a non-empty string`);
  }
  return value.trim();
}

function normalizeOptionalText(value, fieldName) {
  if (value == null) return null;
  if (typeof value !== "string") {
    throw new Error(`${fieldName} must be a string or null`);
  }
  const normalized = value.trim();
  return normalized ? normalized : null;
}

function assertBoolean(value, fieldName) {
  if (typeof value !== "boolean") {
    throw new Error(`${fieldName} must be a boolean`);
  }
  return value;
}

function assertInteger(value, fieldName, { min = undefined, max = undefined } = {}) {
  if (!Number.isInteger(value)) {
    throw new Error(`${fieldName} must be an integer`);
  }
  if (min != null && value < min) {
    throw new Error(`${fieldName} must be >= ${min}`);
  }
  if (max != null && value > max) {
    throw new Error(`${fieldName} must be <= ${max}`);
  }
  return value;
}

function assertEnumValue(value, allowedValues, fieldName) {
  if (!allowedValues.includes(value)) {
    throw new Error(`${fieldName} must be one of ${allowedValues.join(", ")}`);
  }
  return value;
}

function parseFindingId(value, fieldName = "finding_id") {
  const findingId = assertNonEmptyString(value, fieldName);
  if (!FINDING_ID_RE.test(findingId)) {
    throw new Error(`${fieldName} must match F-N`);
  }
  return findingId;
}

function findingsJsonlPath(domain) {
  return path.join(sessionDir(domain), "findings.jsonl");
}

function findingsMarkdownPath(domain) {
  return path.join(sessionDir(domain), "findings.md");
}

function verificationRoundPaths(domain, round) {
  const normalizedRound = assertEnumValue(round, VERIFICATION_ROUND_VALUES, "round");
  const fileNames = VERIFICATION_ROUND_FILE_MAP[normalizedRound];
  const dir = sessionDir(domain);
  return {
    round: normalizedRound,
    json: path.join(dir, fileNames.json),
    markdown: path.join(dir, fileNames.markdown),
  };
}

function gradeArtifactPaths(domain) {
  const dir = sessionDir(domain);
  return {
    json: path.join(dir, "grade.json"),
    markdown: path.join(dir, "grade.md"),
  };
}

function appendJsonlLine(filePath, document) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.appendFileSync(filePath, `${JSON.stringify(document)}\n`, "utf8");
}

function writeMarkdownMirror(markdownPath, content, response) {
  try {
    writeFileAtomic(markdownPath, content);
    response.written_md = markdownPath;
  } catch (error) {
    response.markdown_sync_error = error.message || String(error);
  }
}

function appendMarkdownMirror(markdownPath, content, response) {
  try {
    fs.mkdirSync(path.dirname(markdownPath), { recursive: true });
    fs.appendFileSync(markdownPath, content, "utf8");
    response.written_md = markdownPath;
  } catch (error) {
    response.markdown_sync_error = error.message || String(error);
  }
}

function loadJsonDocumentStrict(filePath, label) {
  if (!fs.existsSync(filePath)) {
    throw new Error(`Missing ${label}: ${filePath}`);
  }

  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch (error) {
    throw new Error(`Malformed ${label}: ${filePath} (${error.message || String(error)})`);
  }

  if (parsed == null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`Malformed ${label}: ${filePath} (expected object)`);
  }

  return parsed;
}

function normalizeFindingRecord(record, { expectedDomain = null, lineNumber = null } = {}) {
  if (record == null || typeof record !== "object" || Array.isArray(record)) {
    throw new Error(lineNumber == null
      ? "finding record must be an object"
      : `Malformed findings.jsonl at line ${lineNumber}: expected object`);
  }

  try {
    const finding = {
      id: parseFindingId(record.id, "id"),
      target_domain: assertNonEmptyString(record.target_domain, "target_domain"),
      title: assertRequiredText(record.title, "title"),
      severity: assertEnumValue(record.severity, SEVERITY_VALUES, "severity"),
      cwe: normalizeOptionalText(record.cwe, "cwe"),
      endpoint: assertRequiredText(record.endpoint, "endpoint"),
      description: assertRequiredText(record.description, "description"),
      proof_of_concept: assertRequiredText(record.proof_of_concept, "proof_of_concept"),
      response_evidence: normalizeOptionalText(record.response_evidence, "response_evidence"),
      impact: normalizeOptionalText(record.impact, "impact"),
      validated: assertBoolean(record.validated, "validated"),
      wave: record.wave == null ? null : parseWaveId(record.wave),
      agent: record.agent == null ? null : parseAgentId(record.agent),
    };

    if (expectedDomain != null && finding.target_domain !== expectedDomain) {
      throw new Error("target_domain mismatch");
    }

    return finding;
  } catch (error) {
    if (lineNumber == null) {
      throw error;
    }
    throw new Error(`Malformed findings.jsonl at line ${lineNumber}: ${error.message || String(error)}`);
  }
}

function readFindingsFromJsonl(domain) {
  const filePath = findingsJsonlPath(domain);
  if (!fs.existsSync(filePath)) {
    return [];
  }

  const content = fs.readFileSync(filePath, "utf8");
  if (!content.trim()) {
    return [];
  }

  const findings = [];
  const lines = content.split("\n");
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (!line.trim()) continue;

    let parsed;
    try {
      parsed = JSON.parse(line);
    } catch (error) {
      throw new Error(`Malformed findings.jsonl at line ${index + 1}: ${error.message || String(error)}`);
    }

    findings.push(normalizeFindingRecord(parsed, {
      expectedDomain: domain,
      lineNumber: index + 1,
    }));
  }

  return findings;
}

function renderFindingMarkdownEntry(finding) {
  const waveAgent = finding.wave || finding.agent
    ? `\n- **Wave/Agent:** ${finding.wave || "?"}/${finding.agent || "?"}`
    : "";

  return [
    `## FINDING ${finding.id.slice(2)} (${finding.severity.toUpperCase()}): ${finding.title}`,
    `- **ID:** ${finding.id}`,
    `- **CWE:** ${finding.cwe || "N/A"}`,
    `- **Endpoint:** ${finding.endpoint}`,
    `- **Validated:** ${finding.validated ? "YES" : "NO"}`,
    `- **Description:** ${finding.description}`,
    `- **PoC:**`,
    "```",
    finding.proof_of_concept,
    "```",
    `- **Evidence:** ${finding.response_evidence || "See PoC"}`,
    `- **Impact:** ${finding.impact || "N/A"}`,
    waveAgent,
    "---\n\n",
  ].join("\n");
}

function normalizeVerificationResult(result, findingIdSet) {
  if (result == null || typeof result !== "object" || Array.isArray(result)) {
    throw new Error("results entries must be objects");
  }

  const findingId = parseFindingId(result.finding_id);
  if (!findingIdSet.has(findingId)) {
    throw new Error(`Unknown finding_id: ${findingId}`);
  }

  return {
    finding_id: findingId,
    disposition: assertEnumValue(result.disposition, VERIFICATION_DISPOSITION_VALUES, "disposition"),
    severity: result.severity == null ? null : assertEnumValue(result.severity, SEVERITY_VALUES, "severity"),
    reportable: assertBoolean(result.reportable, "reportable"),
    reasoning: assertRequiredText(result.reasoning, "reasoning"),
  };
}

function normalizeVerificationRoundDocument(document, { expectedDomain, expectedRound, findingIdSet = null } = {}) {
  if (document == null || typeof document !== "object" || Array.isArray(document)) {
    throw new Error("verification round document must be an object");
  }

  const round = assertEnumValue(document.round, VERIFICATION_ROUND_VALUES, "round");
  const normalized = {
    version: assertInteger(document.version, "version", { min: 1, max: 1 }),
    target_domain: assertNonEmptyString(document.target_domain, "target_domain"),
    round,
    notes: normalizeOptionalText(document.notes, "notes"),
    results: [],
  };

  if (!Array.isArray(document.results)) {
    throw new Error("results must be an array");
  }

  const seenIds = new Set();
  for (const result of document.results) {
    const normalizedResult = normalizeVerificationResult(
      result,
      findingIdSet ?? new Set([parseFindingId(result.finding_id)]),
    );
    if (seenIds.has(normalizedResult.finding_id)) {
      throw new Error(`Duplicate finding_id in results: ${normalizedResult.finding_id}`);
    }
    seenIds.add(normalizedResult.finding_id);
    normalized.results.push(normalizedResult);
  }

  if (expectedDomain != null && normalized.target_domain !== expectedDomain) {
    throw new Error(`verification round target_domain mismatch: expected ${expectedDomain}`);
  }
  if (expectedRound != null && normalized.round !== expectedRound) {
    throw new Error(`verification round mismatch: expected ${expectedRound}`);
  }

  return normalized;
}

function renderVerificationRoundMarkdown(document) {
  const lines = [
    `# Verification Round: ${document.round}`,
    `- Target: ${document.target_domain}`,
    `- Notes: ${document.notes || "N/A"}`,
    `- Results: ${document.results.length}`,
    "",
  ];

  if (document.results.length === 0) {
    lines.push("No verification results recorded.");
    lines.push("");
    return `${lines.join("\n")}\n`;
  }

  for (const result of document.results) {
    lines.push(`## ${result.finding_id}`);
    lines.push(`- Disposition: ${result.disposition}`);
    lines.push(`- Severity: ${result.severity || "none"}`);
    lines.push(`- Reportable: ${result.reportable ? "YES" : "NO"}`);
    lines.push(`- Reasoning: ${result.reasoning}`);
    lines.push("");
  }

  return `${lines.join("\n")}\n`;
}

function normalizeGradeFinding(result, findingIdSet) {
  if (result == null || typeof result !== "object" || Array.isArray(result)) {
    throw new Error("findings entries must be objects");
  }

  const findingId = parseFindingId(result.finding_id);
  if (!findingIdSet.has(findingId)) {
    throw new Error(`Unknown finding_id: ${findingId}`);
  }

  const normalized = {
    finding_id: findingId,
    impact: assertInteger(result.impact, "impact", { min: 0, max: 30 }),
    proof_quality: assertInteger(result.proof_quality, "proof_quality", { min: 0, max: 25 }),
    severity_accuracy: assertInteger(result.severity_accuracy, "severity_accuracy", { min: 0, max: 15 }),
    chain_potential: assertInteger(result.chain_potential, "chain_potential", { min: 0, max: 15 }),
    report_quality: assertInteger(result.report_quality, "report_quality", { min: 0, max: 15 }),
    total_score: assertInteger(result.total_score, "total_score", { min: 0 }),
    feedback: normalizeOptionalText(result.feedback, "feedback"),
  };

  const expectedTotal = normalized.impact
    + normalized.proof_quality
    + normalized.severity_accuracy
    + normalized.chain_potential
    + normalized.report_quality;
  if (normalized.total_score !== expectedTotal) {
    throw new Error(`finding ${findingId} total_score must equal the sum of rubric scores`);
  }

  return normalized;
}

function normalizeGradeVerdictDocument(document, { expectedDomain = null, findingIdSet = null } = {}) {
  if (document == null || typeof document !== "object" || Array.isArray(document)) {
    throw new Error("grade verdict document must be an object");
  }

  const normalized = {
    version: assertInteger(document.version, "version", { min: 1, max: 1 }),
    target_domain: assertNonEmptyString(document.target_domain, "target_domain"),
    verdict: assertEnumValue(document.verdict, GRADE_VERDICT_VALUES, "verdict"),
    total_score: assertInteger(document.total_score, "total_score", { min: 0 }),
    findings: [],
    feedback: normalizeOptionalText(document.feedback, "feedback"),
  };

  if (!Array.isArray(document.findings)) {
    throw new Error("findings must be an array");
  }

  const seenIds = new Set();
  for (const finding of document.findings) {
    const normalizedFinding = normalizeGradeFinding(
      finding,
      findingIdSet ?? new Set([parseFindingId(finding.finding_id)]),
    );
    if (seenIds.has(normalizedFinding.finding_id)) {
      throw new Error(`Duplicate finding_id in findings: ${normalizedFinding.finding_id}`);
    }
    seenIds.add(normalizedFinding.finding_id);
    normalized.findings.push(normalizedFinding);
  }

  if (expectedDomain != null && normalized.target_domain !== expectedDomain) {
    throw new Error(`grade verdict target_domain mismatch: expected ${expectedDomain}`);
  }

  return normalized;
}

function renderGradeVerdictMarkdown(document) {
  const lines = [
    "# Grade Verdict",
    `- Target: ${document.target_domain}`,
    `- Verdict: ${document.verdict}`,
    `- Total Score: ${document.total_score}`,
    `- Feedback: ${document.feedback || "N/A"}`,
    "",
  ];

  if (document.findings.length === 0) {
    lines.push("No graded findings.");
    lines.push("");
    return `${lines.join("\n")}\n`;
  }

  for (const finding of document.findings) {
    lines.push(`## ${finding.finding_id}`);
    lines.push(`- Impact: ${finding.impact}`);
    lines.push(`- Proof Quality: ${finding.proof_quality}`);
    lines.push(`- Severity Accuracy: ${finding.severity_accuracy}`);
    lines.push(`- Chain Potential: ${finding.chain_potential}`);
    lines.push(`- Report Quality: ${finding.report_quality}`);
    lines.push(`- Total Score: ${finding.total_score}`);
    lines.push(`- Feedback: ${finding.feedback || "N/A"}`);
    lines.push("");
  }

  return `${lines.join("\n")}\n`;
}

// ── Tool implementations ──

function validateScanUrl(url) {
  let parsed;
  try { parsed = new URL(url); } catch { throw new Error(`Invalid URL: ${url}`); }
  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error(`Unsupported protocol: ${parsed.protocol}`);
  }
  const host = parsed.hostname.toLowerCase();
  if (
    host === "localhost" ||
    host === "127.0.0.1" ||
    host === "[::1]" || host === "::1" ||
    host === "0.0.0.0" ||
    host.startsWith("10.") ||
    host.startsWith("192.168.") ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(host) ||
    host === "169.254.169.254" ||
    host.endsWith(".internal") ||
    host.endsWith(".local")
  ) {
    throw new Error(`Blocked internal/private host: ${host}`);
  }
}

async function httpScan(args) {
  const method = args.method;
  const url = args.url;
  validateScanUrl(url);
  const headers = args.headers || {};
  const body = args.body || undefined;
  const followRedirects = args.follow_redirects ?? false;
  const timeoutMs = args.timeout_ms || 10000;
  const authProfile = args.auth_profile;

  if (authProfile) {
    let auth = null;

    // 1. Exact match in memory (legacy profile_name or domain:role)
    if (authProfiles.has(authProfile)) {
      auth = authProfiles.get(authProfile);
    }

    // 2. Try domain-qualified key from URL (e.g. "attacker" → "target.com:attacker")
    if (!auth) {
      try {
        const urlHost = new URL(url).hostname;
        const domainKey = `${urlHost}:${authProfile}`;
        if (authProfiles.has(domainKey)) auth = authProfiles.get(domainKey);
      } catch {}
    }

    // 3. Fallback: load from auth.json on disk (v2 format)
    if (!auth) {
      try {
        const urlHost = new URL(url).hostname;
        const authPath = resolveAuthJsonPath(urlHost);
        if (authPath) {
          const doc = readAuthJson(authPath);
          if (doc && doc.version === 2 && doc.profiles && doc.profiles[authProfile]) {
            auth = doc.profiles[authProfile];
          } else if (doc && !doc.version) {
            // Legacy flat format — use as-is
            auth = doc;
          }
        }
      } catch {}
    }

    if (auth) {
      for (const [k, v] of Object.entries(auth)) {
        if (k !== "credentials" && !headers[k]) headers[k] = v;
      }
    } else {
      return JSON.stringify({
        error: `auth_profile "${authProfile}" requested but not found — request was NOT sent. Store auth first via bounty_auth_store or bounty_auth_manual.`,
      });
    }
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);

    const resp = await fetch(url, {
      method,
      headers,
      body,
      redirect: followRedirects ? "follow" : "manual",
      signal: controller.signal,
    });
    clearTimeout(timeout);

    const respHeaders = {};
    resp.headers.forEach((v, k) => { respHeaders[k] = v; });

    const ct = resp.headers.get("content-type") || "";
    let respBody;
    let analysisBody;
    if (ct.includes("text") || ct.includes("json") || ct.includes("xml") || ct.includes("javascript") || ct.includes("html")) {
      const text = await resp.text();
      analysisBody = text;
      respBody = text.slice(0, 12000);
      if (text.length > 12000) respBody += `\n[TRUNCATED — ${text.length} chars]`;
    } else {
      const buf = await resp.arrayBuffer();
      respBody = `[Binary: ${buf.byteLength} bytes, type: ${ct}]`;
      analysisBody = respBody;
    }

    const analysis = analyzeResponse(url, resp.status, respHeaders, analysisBody);

    return JSON.stringify({
      status: resp.status,
      status_text: resp.statusText,
      headers: respHeaders,
      body: respBody,
      redirected: resp.redirected,
      final_url: resp.url,
      analysis,
    }, null, 2);
  } catch (err) {
    return JSON.stringify({ error: err.message || String(err) });
  }
}

function analyzeResponse(url, status, headers, body) {
  const tech = [];
  const issues = [];
  const secrets = [];
  const endpoints = [];
  const authInfo = [];

  // Tech fingerprinting
  if (headers["x-powered-by"]) tech.push(`X-Powered-By: ${headers["x-powered-by"]}`);
  if (headers["server"]) tech.push(`Server: ${headers["server"]}`);
  if (body.includes("__NEXT_DATA__")) tech.push("Next.js");
  if (body.includes("__nuxt")) tech.push("Nuxt.js");
  if (body.includes("ng-version")) tech.push("Angular");
  if (body.includes("__vue__")) tech.push("Vue.js");
  if (body.includes("firebase")) tech.push("Firebase");
  if (body.includes("graphql")) tech.push("GraphQL");
  if (body.includes("wp-content")) tech.push("WordPress");
  if (body.includes("laravel") || body.includes("XSRF-TOKEN")) tech.push("Laravel");
  if (body.includes("django") || body.includes("csrfmiddlewaretoken")) tech.push("Django");
  if (headers["cf-ray"]) tech.push("Cloudflare");
  if (headers["x-vercel-id"]) tech.push("Vercel");
  if (headers["x-amzn-requestid"]) tech.push("AWS");

  // Security headers
  if (!headers["strict-transport-security"]) issues.push("Missing HSTS");
  if (!headers["x-content-type-options"]) issues.push("Missing X-Content-Type-Options");
  if (!headers["x-frame-options"] && !(headers["content-security-policy"] || "").includes("frame-ancestors"))
    issues.push("No clickjacking protection");
  if (headers["access-control-allow-origin"] === "*") issues.push("CORS: wildcard origin (*)");
  if (headers["access-control-allow-credentials"] === "true")
    issues.push(`CORS: credentials + origin ${headers["access-control-allow-origin"] || "?"} — test reflection`);

  // Cookie analysis
  const sc = headers["set-cookie"] || "";
  if (sc) {
    if (!sc.includes("HttpOnly")) authInfo.push("Cookie missing HttpOnly");
    if (!sc.includes("Secure")) authInfo.push("Cookie missing Secure flag");
    if (!sc.includes("SameSite")) authInfo.push("Cookie missing SameSite");
  }

  // Secret detection
  const patterns = [
    { re: /AKIA[A-Z0-9]{16}/, label: "AWS Access Key" },
    { re: /ghp_[a-zA-Z0-9]{36}/, label: "GitHub PAT" },
    { re: /gho_[a-zA-Z0-9]{36}/, label: "GitHub OAuth" },
    { re: /sk-[a-zA-Z0-9]{32,}/, label: "Secret key (sk-)" },
    { re: /sk_live_[a-zA-Z0-9]{24,}/, label: "Stripe Live" },
    { re: /pk_live_[a-zA-Z0-9]{24,}/, label: "Stripe Publishable" },
    { re: /eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+/, label: "JWT" },
    { re: /xox[bpas]-[a-zA-Z0-9-]+/, label: "Slack token" },
    { re: /AIza[a-zA-Z0-9_-]{35}/, label: "Google API key" },
    { re: /GOCSPX-[a-zA-Z0-9_-]+/, label: "Google OAuth secret" },
    { re: /-----BEGIN (?:RSA )?PRIVATE KEY-----/, label: "Private key" },
    { re: /(?:api[_-]?key|apikey)\s*[:=]\s*["']?([a-zA-Z0-9_\-]{20,})/i, label: "API key" },
    { re: /(?:secret|password|passwd|pwd)\s*[:=]\s*["']?([^\s"']{8,})/i, label: "Secret/password" },
    { re: /mongodb(\+srv)?:\/\/[^\s"']+/, label: "MongoDB URI" },
    { re: /postgres(ql)?:\/\/[^\s"']+/, label: "PostgreSQL URI" },
    { re: /redis:\/\/[^\s"']+/, label: "Redis URI" },
    { re: /smtp:\/\/[^\s"']+/, label: "SMTP URI" },
  ];
  for (const { re, label } of patterns) {
    const m = body.match(re);
    if (m) secrets.push(`${label}: ${m[0].slice(0, 50)}...`);
  }

  // Endpoint extraction
  const urls = body.match(/(?:https?:\/\/[^\s"'<>{}]+|\/api\/[^\s"'<>{}]+|\/v[0-9]+\/[^\s"'<>{}]+)/g) || [];
  endpoints.push(...[...new Set(urls)].slice(0, 30));

  // Status hints
  if (status === 403) issues.push("403 — try different auth/methods");
  if (status === 405) issues.push("405 — try other HTTP methods");
  if (status === 500) issues.push("500 — possible injection vector");

  return { tech_stack: tech, security_issues: issues, leaked_secrets: secrets, discovered_endpoints: endpoints, auth_info: authInfo };
}

function recordFinding(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const hasWave = args.wave != null;
  const hasAgent = args.agent != null;
  if (hasWave !== hasAgent) {
    throw new Error("wave and agent must either both be provided or both be omitted");
  }

  let wave = null;
  let agent = null;
  if (hasWave) {
    wave = parseWaveId(args.wave);
    agent = parseAgentId(args.agent);

    const waveNumber = Number(wave.slice(1));
    const { assignmentByAgent } = loadWaveAssignments(domain, waveNumber);
    if (!assignmentByAgent.has(agent)) {
      throw new Error(`Agent ${agent} is not assigned in wave ${wave}`);
    }
  }

  return withSessionLock(domain, () => {
    const structuredPath = findingsJsonlPath(domain);
    const counter = readFindingsFromJsonl(domain).length + 1;

    const finding = normalizeFindingRecord({
      id: `F-${counter}`,
      target_domain: domain,
      title: args.title,
      severity: args.severity,
      cwe: args.cwe,
      endpoint: args.endpoint,
      description: args.description,
      proof_of_concept: args.proof_of_concept,
      response_evidence: args.response_evidence,
      impact: args.impact,
      validated: args.validated,
      wave,
      agent,
    }, { expectedDomain: domain });

    appendJsonlLine(structuredPath, finding);

    const response = {
      recorded: true,
      finding_id: finding.id,
      total: counter,
      written_jsonl: structuredPath,
    };

    appendMarkdownMirror(findingsMarkdownPath(domain), renderFindingMarkdownEntry(finding), response);
    return JSON.stringify(response);
  });
}

function readFindings(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  return JSON.stringify({
    version: 1,
    target_domain: domain,
    findings: readFindingsFromJsonl(domain),
  });
}

function listFindings(args) {
  const findings = readFindingsFromJsonl(assertNonEmptyString(args.target_domain, "target_domain"));
  return JSON.stringify({
    count: findings.length,
    findings: findings.map((finding) => ({
      id: finding.id,
      severity: finding.severity,
      title: finding.title,
      endpoint: finding.endpoint,
    })),
  });
}

function waveStatus(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const findings = readFindingsFromJsonl(domain);
  const summary = summarizeFindings(findings);

  // Compute surface coverage for deterministic wave decisions
  let coverage = null;
  try {
    const { state } = readSessionStateStrict(domain);
    const attackSurface = readAttackSurfaceStrict(domain);
    const exploredSet = new Set(state.explored);
    const nonLowSurfaces = attackSurface.document.surfaces.filter(
      (s) => s.priority && s.priority.toUpperCase() !== "LOW",
    );
    const totalNonLow = nonLowSurfaces.length;
    const exploredNonLow = nonLowSurfaces.filter((s) => exploredSet.has(s.id)).length;
    coverage = {
      total_surfaces: attackSurface.document.surfaces.length,
      non_low_total: totalNonLow,
      non_low_explored: exploredNonLow,
      coverage_pct: totalNonLow > 0 ? Math.round((exploredNonLow / totalNonLow) * 100) : 100,
      unexplored_high: attackSurface.document.surfaces.filter(
        (s) => ["CRITICAL", "HIGH"].includes((s.priority || "").toUpperCase()) && !exploredSet.has(s.id),
      ).length,
    };
  } catch {}

  return JSON.stringify({
    ...summary,
    coverage,
    findings_summary: findings.map((finding) => ({
      id: finding.id,
      severity: finding.severity,
      title: finding.title,
      endpoint: finding.endpoint,
      wave_agent: finding.wave || finding.agent ? `${finding.wave || "?"}/${finding.agent || "?"}` : null,
    })),
  });
}

// Bypass table tech-to-file map (matches .claude/commands/bountyagent.md BYPASS TABLES section)
const BYPASS_TABLE_MAP = {
  wordpress: "wordpress.txt",
  graphql: "graphql.txt",
  ssrf: "ssrf.txt",
  jwt: "jwt.txt",
  firebase: "firebase.txt",
  "next.js": "nextjs.txt",
  nextjs: "nextjs.txt",
  oauth: "oauth-oidc.txt",
  oidc: "oauth-oidc.txt",
};
const BYPASS_TABLE_DEFAULT = "rest-api.txt";

function resolveBypassTable(techStack) {
  if (!Array.isArray(techStack)) return BYPASS_TABLE_DEFAULT;
  for (const tech of techStack) {
    const key = String(tech).toLowerCase();
    for (const [pattern, file] of Object.entries(BYPASS_TABLE_MAP)) {
      if (key.includes(pattern)) return file;
    }
  }
  return BYPASS_TABLE_DEFAULT;
}

function readHunterBrief(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const wave = parseWaveId(args.wave);
  const agent = parseAgentId(args.agent);
  const waveNumber = Number(wave.slice(1));

  // 1. Load and validate assignment
  const { assignmentByAgent } = loadWaveAssignments(domain, waveNumber);
  const assignment = assignmentByAgent.get(agent);
  if (!assignment) {
    throw new Error(`Agent ${agent} is not assigned in wave ${wave}`);
  }

  // 2. Load attack surface and find assigned surface
  const attackSurface = readAttackSurfaceStrict(domain);
  const surfaceObj = attackSurface.document.surfaces.find(
    (s) => s.id === assignment.surface_id,
  );
  if (!surfaceObj) {
    throw new Error(`Surface ${assignment.surface_id} not found in attack_surface.json`);
  }

  // 3. Read session state for exclusions
  const { state } = readSessionStateStrict(domain);

  // 4. Resolve bypass table
  const bypassFile = resolveBypassTable(surfaceObj.tech_stack);
  let bypassTable = "";
  try {
    // Look for bypass tables relative to project dir, install location, or global install
    const candidates = [
      path.join(process.env.CLAUDE_PROJECT_DIR || "", ".claude", "bypass-tables", bypassFile),
      path.join(__dirname, "..", ".claude", "bypass-tables", bypassFile),
      path.join(os.homedir(), ".claude", "bypass-tables", bypassFile),
    ];
    for (const candidate of candidates) {
      if (fs.existsSync(candidate)) {
        bypassTable = fs.readFileSync(candidate, "utf8").trim();
        break;
      }
    }
  } catch {}

  return JSON.stringify({
    target_url: state.target_url,
    wave,
    agent,
    surface: surfaceObj,
    valid_surface_ids: attackSurface.surface_ids,
    dead_ends: state.dead_ends,
    waf_blocked_endpoints: state.waf_blocked_endpoints,
    scope_exclusions: state.scope_exclusions,
    bypass_table: bypassTable || null,
    auth_hint: "Read ~/bounty-agent-sessions/" + domain + "/auth.json if it exists.",
  }, null, 2);
}

function writeVerificationRound(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const round = assertEnumValue(args.round, VERIFICATION_ROUND_VALUES, "round");
  const notes = normalizeOptionalText(args.notes, "notes");
  if (!Array.isArray(args.results)) {
    throw new Error("results must be an array");
  }

  const findingIdSet = new Set(readFindingsFromJsonl(domain).map((finding) => finding.id));
  const seenIds = new Set();
  const results = args.results.map((result) => {
    const normalizedResult = normalizeVerificationResult(result, findingIdSet);
    if (seenIds.has(normalizedResult.finding_id)) {
      throw new Error(`Duplicate finding_id in results: ${normalizedResult.finding_id}`);
    }
    seenIds.add(normalizedResult.finding_id);
    return normalizedResult;
  });

  // Completeness guard: balanced/final rounds must cover every finding from the prior round
  const PRIOR_ROUND = { balanced: "brutalist", final: "balanced" };
  if (PRIOR_ROUND[round]) {
    const priorPaths = verificationRoundPaths(domain, PRIOR_ROUND[round]);
    if (!fs.existsSync(priorPaths.json)) {
      // Prior round file doesn't exist yet (e.g., brutalist hasn't run) — skip check
    } else {
      // File exists — parse it; malformed JSON is a hard error, not a skip
      const priorDoc = JSON.parse(fs.readFileSync(priorPaths.json, "utf8"));
      const priorIds = new Set((priorDoc.results || []).map((r) => r.finding_id));
      const currentIds = new Set(results.map((r) => r.finding_id));
      const missing = [...priorIds].filter((id) => !currentIds.has(id));
      if (missing.length > 0) {
        throw new Error(
          `${round} round is missing ${missing.length} finding(s) from ${PRIOR_ROUND[round]} round: ${missing.join(", ")}. ` +
          `Include ALL findings from the prior round — pass through unchanged findings you did not re-test.`
        );
      }
    }
  }

  const document = {
    version: 1,
    target_domain: domain,
    round,
    notes,
    results,
  };

  const paths = verificationRoundPaths(domain, round);
  writeFileAtomic(paths.json, JSON.stringify(document, null, 2) + "\n");

  const response = {
    round,
    results_count: results.length,
    written_json: paths.json,
  };
  writeMarkdownMirror(paths.markdown, renderVerificationRoundMarkdown(document), response);
  return JSON.stringify(response);
}

function readVerificationRound(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const paths = verificationRoundPaths(domain, args.round);
  const document = loadJsonDocumentStrict(paths.json, `${paths.round} verification round JSON`);
  const findingIdSet = new Set(readFindingsFromJsonl(domain).map((finding) => finding.id));
  return JSON.stringify(normalizeVerificationRoundDocument(document, {
    expectedDomain: domain,
    expectedRound: paths.round,
    findingIdSet,
  }));
}

function writeGradeVerdict(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const verdict = assertEnumValue(args.verdict, GRADE_VERDICT_VALUES, "verdict");
  const totalScore = assertInteger(args.total_score, "total_score", { min: 0 });
  const feedback = normalizeOptionalText(args.feedback, "feedback");
  if (!Array.isArray(args.findings)) {
    throw new Error("findings must be an array");
  }

  const findingIdSet = new Set(readFindingsFromJsonl(domain).map((finding) => finding.id));
  const seenIds = new Set();
  const findings = args.findings.map((finding) => {
    const normalizedFinding = normalizeGradeFinding(finding, findingIdSet);
    if (seenIds.has(normalizedFinding.finding_id)) {
      throw new Error(`Duplicate finding_id in findings: ${normalizedFinding.finding_id}`);
    }
    seenIds.add(normalizedFinding.finding_id);
    return normalizedFinding;
  });

  const document = {
    version: 1,
    target_domain: domain,
    verdict,
    total_score: totalScore,
    findings,
    feedback,
  };

  const paths = gradeArtifactPaths(domain);
  writeFileAtomic(paths.json, JSON.stringify(document, null, 2) + "\n");

  const response = {
    verdict,
    findings_count: findings.length,
    written_json: paths.json,
  };
  writeMarkdownMirror(paths.markdown, renderGradeVerdictMarkdown(document), response);
  return JSON.stringify(response);
}

function readGradeVerdict(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const paths = gradeArtifactPaths(domain);
  const document = loadJsonDocumentStrict(paths.json, "grade verdict JSON");
  const findingIdSet = new Set(readFindingsFromJsonl(domain).map((finding) => finding.id));
  return JSON.stringify(normalizeGradeVerdictDocument(document, {
    expectedDomain: domain,
    findingIdSet,
  }));
}

function initSession(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const targetUrl = assertNonEmptyString(args.target_url, "target_url");

  return withSessionLock(domain, () => {
    const dir = sessionDir(domain);
    const filePath = statePath(domain);

    if (fs.existsSync(filePath)) {
      throw new Error(`Session already initialized: ${filePath}`);
    }
    if (!isSessionDirEffectivelyEmpty(dir)) {
      throw new Error(`Session directory is not empty: ${dir}`);
    }

    const state = buildInitialSessionState(domain, targetUrl);
    writeFileAtomic(filePath, `${JSON.stringify(state, null, 2)}\n`);

    return JSON.stringify({
      version: 1,
      created: true,
      session_dir: dir,
      state: publicSessionState(state),
    });
  });
}

function readSessionState(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const { state } = readSessionStateStrict(domain);
  return JSON.stringify({
    version: 1,
    state: publicSessionState(state),
  });
}

function transitionPhase(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const toPhase = assertEnumValue(args.to_phase, PHASE_VALUES, "to_phase");

  return withSessionLock(domain, () => {
    const { raw, state } = readSessionStateStrict(domain);
    const fromPhase = state.phase;
    const allowedTransitions = {
      RECON: ["AUTH"],
      AUTH: ["HUNT"],
      HUNT: ["CHAIN"],
      CHAIN: ["VERIFY"],
      VERIFY: ["GRADE"],
      GRADE: ["REPORT", "HUNT"],
    };

    if (!(allowedTransitions[fromPhase] || []).includes(toPhase)) {
      throw new Error(`Invalid phase transition: ${fromPhase} -> ${toPhase}`);
    }

    let nextAuthStatus = state.auth_status;
    if (fromPhase === "AUTH" && toPhase === "HUNT") {
      if (args.auth_status == null) {
        throw new Error("auth_status is required for AUTH -> HUNT");
      }
      nextAuthStatus = assertEnumValue(
        args.auth_status,
        AUTH_STATUS_VALUES.filter((value) => value !== "pending"),
        "auth_status",
      );
    } else if (args.auth_status != null) {
      throw new Error("auth_status is only allowed for AUTH -> HUNT");
    }

    const nextState = {
      ...state,
      phase: toPhase,
      auth_status: nextAuthStatus,
      hold_count: fromPhase === "GRADE" && toPhase === "HUNT"
        ? state.hold_count + 1
        : state.hold_count,
    };

    writeSessionStateDocument(domain, raw, nextState);
    return JSON.stringify({
      version: 1,
      transitioned: true,
      from_phase: fromPhase,
      to_phase: toPhase,
      state: publicSessionState(nextState),
    });
  });
}

function startWave(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const waveNumber = parseWaveNumber(args.wave_number);
  const assignments = normalizeWaveAssignmentsInput(args.assignments);

  return withSessionLock(domain, () => {
    const { raw, state } = readSessionStateStrict(domain);
    if (state.phase !== "HUNT") {
      throw new Error(`Wave start requires phase HUNT, found ${state.phase}`);
    }
    if (state.pending_wave != null) {
      throw new Error(`Wave start requires pending_wave null, found ${state.pending_wave}`);
    }
    if (waveNumber !== state.hunt_wave + 1) {
      throw new Error(`wave_number must equal hunt_wave + 1 (${state.hunt_wave + 1})`);
    }

    const assignmentsPath = waveAssignmentsPath(domain, waveNumber);
    if (fs.existsSync(assignmentsPath)) {
      throw new Error(`Assignment file already exists: ${assignmentsPath}`);
    }

    writeFileAtomic(assignmentsPath, `${JSON.stringify({
      wave_number: waveNumber,
      assignments,
    }, null, 2)}\n`);

    const nextState = {
      ...state,
      pending_wave: waveNumber,
    };

    try {
      writeSessionStateDocument(domain, raw, nextState);
    } catch (error) {
      let rollbackSucceeded = false;
      try {
        fs.rmSync(assignmentsPath, { force: true });
        rollbackSucceeded = true;
      } catch {}

      const rollbackStatus = rollbackSucceeded ? "rollback succeeded" : "rollback failed";
      throw new Error(
        `State write failed after writing assignments; ${rollbackStatus}: ${assignmentsPath} (${error.message || String(error)})`,
      );
    }

    return JSON.stringify({
      version: 1,
      started: true,
      wave_number: waveNumber,
      assignments,
      assignments_path: assignmentsPath,
      state: publicSessionState(nextState),
    });
  });
}

function applyWaveMerge(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const waveNumber = parseWaveNumber(args.wave_number);
  const forceMerge = assertBoolean(args.force_merge, "force_merge");

  return withSessionLock(domain, () => {
    const { raw, state } = readSessionStateStrict(domain);
    if (state.phase !== "HUNT") {
      throw new Error(`Wave merge requires phase HUNT, found ${state.phase}`);
    }
    if (state.pending_wave == null) {
      throw new Error("Wave merge requires pending_wave to be set");
    }
    if (state.pending_wave !== waveNumber) {
      throw new Error(`Wave merge requires pending_wave ${waveNumber}, found ${state.pending_wave}`);
    }

    const readiness = buildWaveReadiness(loadWaveArtifacts(domain, waveNumber));
    if (!readiness.is_complete && !forceMerge) {
      return JSON.stringify({
        version: 1,
        status: "pending",
        wave_number: waveNumber,
        force_merge: false,
        readiness,
        state: publicSessionState(state),
      });
    }

    const attackSurface = readAttackSurfaceStrict(domain);
    const { artifacts, merge } = mergeWaveHandoffsInternal(domain, waveNumber);
    const requeueSurfaceIds = computeRequeueSurfaceIds(artifacts, merge);
    const findings = summarizeFindings(readFindingsFromJsonl(domain));
    const scopeExclusions = [...state.scope_exclusions];
    pushUnique(scopeExclusions, new Set(scopeExclusions), readScopeExclusions(domain));

    const explored = [...state.explored];
    const deadEnds = [...state.dead_ends];
    const wafBlockedEndpoints = [...state.waf_blocked_endpoints];
    const leadSurfaceIds = [...state.lead_surface_ids];

    pushUnique(explored, new Set(explored), merge.completed_surface_ids);
    pushUnique(deadEnds, new Set(deadEnds), merge.dead_ends);
    pushUnique(wafBlockedEndpoints, new Set(wafBlockedEndpoints), merge.waf_blocked_endpoints);
    pushUnique(leadSurfaceIds, new Set(leadSurfaceIds), merge.lead_surface_ids);

    const filteredLeadSurfaceIds = leadSurfaceIds.filter(
      (surfaceId) => attackSurface.surface_id_set.has(surfaceId) && !explored.includes(surfaceId),
    );

    const nextState = {
      ...state,
      explored,
      dead_ends: deadEnds,
      waf_blocked_endpoints: wafBlockedEndpoints,
      lead_surface_ids: filteredLeadSurfaceIds,
      scope_exclusions: scopeExclusions,
      pending_wave: null,
      hunt_wave: waveNumber,
      total_findings: findings.total,
    };

    writeSessionStateDocument(domain, raw, nextState);
    return JSON.stringify({
      version: 1,
      status: "merged",
      wave_number: waveNumber,
      force_merge: forceMerge,
      readiness,
      merge: {
        ...merge,
        requeue_surface_ids: requeueSurfaceIds,
      },
      findings,
      state: publicSessionState(nextState),
    });
  });
}

function writeHandoff(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const dir = sessionDir(domain);
  fs.mkdirSync(dir, { recursive: true });

  const lines = [];
  lines.push(`# Handoff — Session ${args.session_number}`);
  lines.push(`## Target: ${args.target_url}`);
  if (args.program_url) lines.push(`## Program: ${args.program_url}`);
  const findings = args.findings_summary || [];
  lines.push(`\n## Findings (${findings.length})`);
  for (const f of findings) lines.push(`- ${f.id} [${(f.severity || "").toUpperCase()}]: ${f.title}`);
  lines.push("\n## Explored");
  for (const e of args.explored_with_results || []) lines.push(`- ${e}`);
  lines.push("\n## Dead Ends");
  for (const d of args.dead_ends || []) lines.push(`- ${d}`);
  lines.push("\n## Unexplored");
  for (const u of args.unexplored || []) lines.push(`- ${u}`);
  lines.push("\n## Must Do Next");
  for (const m of args.must_do_next || []) lines.push(`- [${m.priority}] ${m.description}`);
  lines.push("\n## Promising Leads");
  for (const p of args.promising_leads || []) lines.push(`- ${p}`);

  const handoffPath = path.join(dir, `SESSION_HANDOFF.md`);
  writeFileAtomic(handoffPath, lines.join("\n") + "\n");
  return JSON.stringify({ written: handoffPath });
}

function logDeadEnds(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const wave = parseWaveId(args.wave);
  const agent = parseAgentId(args.agent);
  const surfaceId = assertNonEmptyString(args.surface_id, "surface_id");

  validateAssignedWaveAgentSurface(domain, wave, agent, surfaceId);

  const deadEnds = normalizeStringArray(args.dead_ends, "dead_ends");
  const wafBlocked = normalizeStringArray(args.waf_blocked_endpoints, "waf_blocked_endpoints");

  if (deadEnds.length === 0 && wafBlocked.length === 0) {
    return JSON.stringify({ appended: 0, message: "Nothing to log" });
  }

  const dir = sessionDir(domain);
  const logPath = path.join(dir, `live-dead-ends-${wave}-${agent}.jsonl`);
  const record = {
    ts: new Date().toISOString(),
    surface_id: surfaceId,
    dead_ends: deadEnds,
    waf_blocked_endpoints: wafBlocked,
  };
  appendJsonlLine(logPath, record);

  return JSON.stringify({
    appended: deadEnds.length + wafBlocked.length,
    dead_ends: deadEnds.length,
    waf_blocked_endpoints: wafBlocked.length,
    log_path: logPath,
  });
}

function writeWaveHandoff(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const wave = parseWaveId(args.wave);
  const agent = parseAgentId(args.agent);
  const surfaceId = assertNonEmptyString(args.surface_id, "surface_id");
  const surfaceStatus = parseSurfaceStatus(args.surface_status);

  if (typeof args.content !== "string") {
    throw new Error("content must be a string");
  }

  const handoff = {
    target_domain: domain,
    wave,
    agent,
    surface_id: surfaceId,
    surface_status: surfaceStatus,
    dead_ends: normalizeStringArray(args.dead_ends, "dead_ends"),
    waf_blocked_endpoints: normalizeStringArray(args.waf_blocked_endpoints, "waf_blocked_endpoints"),
    lead_surface_ids: normalizeStringArray(args.lead_surface_ids, "lead_surface_ids"),
  };

  const dir = sessionDir(domain);
  const markdownPath = path.join(dir, `handoff-${wave}-${agent}.md`);
  const jsonPath = path.join(dir, `handoff-${wave}-${agent}.json`);

  validateAssignedWaveAgentSurface(domain, wave, agent, surfaceId);
  writeFileAtomic(markdownPath, args.content);
  writeFileAtomic(jsonPath, JSON.stringify(handoff, null, 2) + "\n");

  return JSON.stringify({
    written_md: markdownPath,
    written_json: jsonPath,
  });
}

function validateWaveHandoffPayload(payload, { targetDomain, wave, agent, surfaceId }) {
  if (payload == null || typeof payload !== "object" || Array.isArray(payload)) {
    throw new Error("handoff payload must be an object");
  }

  if (payload.target_domain != null && assertNonEmptyString(payload.target_domain, "target_domain") !== targetDomain) {
    throw new Error("handoff target_domain does not match merge target");
  }

  const payloadWave = parseWaveId(payload.wave);
  const payloadAgent = parseAgentId(payload.agent);
  const payloadSurfaceId = assertNonEmptyString(payload.surface_id, "surface_id");
  const surfaceStatus = parseSurfaceStatus(payload.surface_status);

  if (payloadWave !== wave) throw new Error("handoff wave does not match assignment wave");
  if (payloadAgent !== agent) throw new Error("handoff agent does not match assignment");
  if (payloadSurfaceId !== surfaceId) throw new Error("handoff surface_id does not match assignment");

  return {
    dead_ends: normalizeStringArray(payload.dead_ends, "dead_ends"),
    waf_blocked_endpoints: normalizeStringArray(payload.waf_blocked_endpoints, "waf_blocked_endpoints"),
    lead_surface_ids: normalizeStringArray(payload.lead_surface_ids, "lead_surface_ids"),
    surface_status: surfaceStatus,
  };
}

function waveHandoffStatus(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const waveNumber = parseWaveNumber(args.wave_number);
  return JSON.stringify(buildWaveReadiness(loadWaveArtifacts(domain, waveNumber)));
}

function mergeWaveHandoffs(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const waveNumber = parseWaveNumber(args.wave_number);
  const { readiness, merge } = mergeWaveHandoffsInternal(domain, waveNumber);

  return JSON.stringify({
    assignments_total: readiness.assignments_total,
    handoffs_total: readiness.handoffs_total,
    received_agents: merge.received_agents,
    invalid_agents: merge.invalid_agents,
    unexpected_agents: merge.unexpected_agents,
    completed_surface_ids: merge.completed_surface_ids,
    partial_surface_ids: merge.partial_surface_ids,
    missing_surface_ids: merge.missing_surface_ids,
    dead_ends: merge.dead_ends,
    waf_blocked_endpoints: merge.waf_blocked_endpoints,
    lead_surface_ids: merge.lead_surface_ids,
  });
}

function readHandoff(args) {
  const dir = sessionDir(args.target_domain);
  const handoffPath = path.join(dir, "SESSION_HANDOFF.md");
  try {
    const content = fs.readFileSync(handoffPath, "utf8");
    return JSON.stringify({ handoff: content });
  } catch {
    return JSON.stringify({ handoff: null, message: "No handoff found" });
  }
}

// ── Auth store (v2 multi-profile) ──

function buildHeaderProfile(headers, cookies, storage) {
  const profile = {};
  Object.assign(profile, headers);
  if (Object.keys(cookies).length) {
    profile["Cookie"] = Object.entries(cookies).map(([k, v]) => `${k}=${v}`).join("; ");
  }
  for (const [k, v] of Object.entries(storage)) {
    if (typeof v === "string" && v.startsWith("eyJ") && !profile["Authorization"]) {
      profile["Authorization"] = `Bearer ${v}`;
    }
  }
  return profile;
}

function resolveAuthJsonPath(targetDomain) {
  const sessionsDir = path.join(os.homedir(), "bounty-agent-sessions");
  if (targetDomain) {
    const targetDir = path.join(sessionsDir, targetDomain.trim());
    if (fs.existsSync(targetDir)) return path.join(targetDir, "auth.json");
  }
  try {
    const entries = fs.readdirSync(sessionsDir)
      .map((d) => {
        const full = path.join(sessionsDir, d);
        try {
          const stat = fs.statSync(full);
          return stat.isDirectory() ? { name: d, mtimeMs: stat.mtimeMs } : null;
        } catch { return null; }
      })
      .filter(Boolean)
      .sort((a, b) => b.mtimeMs - a.mtimeMs);
    if (entries.length > 0) return path.join(sessionsDir, entries[0].name, "auth.json");
  } catch {}
  return null;
}

function readAuthJson(filePath) {
  try {
    return JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch {
    return null;
  }
}

function migrateAuthJson(existing) {
  if (!existing || typeof existing !== "object") return { version: 2, profiles: {} };
  if (existing.version === 2) return existing;
  // Legacy format: flat header object → wrap as attacker profile
  return { version: 2, profiles: { attacker: existing } };
}

function authStore(args) {
  const domain = args.target_domain;
  const role = args.role;
  const headers = args.headers || {};
  const cookies = args.cookies || {};
  const storage = args.local_storage || {};
  const credentials = args.credentials || null;

  const profile = buildHeaderProfile(headers, cookies, storage);
  if (credentials) profile.credentials = credentials;

  // Update in-memory cache with domain-qualified key
  const cacheKey = domain ? `${domain}:${role}` : role;
  authProfiles.set(cacheKey, profile);

  // Write to disk
  const authPath = resolveAuthJsonPath(domain);
  if (authPath) {
    try {
      const existing = readAuthJson(authPath);
      const doc = migrateAuthJson(existing);
      const profileForDisk = Object.assign({}, profile);
      doc.profiles[role] = profileForDisk;
      writeFileAtomic(authPath, JSON.stringify(doc, null, 2) + "\n");
    } catch {}
  }

  // Check which profiles exist
  let hasAttacker = false;
  let hasVictim = false;
  if (authPath) {
    try {
      const saved = readAuthJson(authPath);
      if (saved && saved.version === 2 && saved.profiles) {
        hasAttacker = !!saved.profiles.attacker;
        hasVictim = !!saved.profiles.victim;
      }
    } catch {}
  }

  return JSON.stringify({
    success: true,
    role,
    keys: Object.keys(profile).filter((k) => k !== "credentials"),
    has_attacker: hasAttacker,
    has_victim: hasVictim,
  });
}

// Backward-compat wrapper for bounty_auth_manual
function authManual(args) {
  const result = authStore({
    target_domain: args.target_domain,
    role: "attacker",
    cookies: args.cookies,
    headers: args.headers,
    local_storage: args.local_storage,
  });
  // Also set the old profile_name key for backward compat with existing httpScan callers
  if (args.profile_name) {
    const headers = args.headers || {};
    const cookies = args.cookies || {};
    const storage = args.local_storage || {};
    const profile = buildHeaderProfile(headers, cookies, storage);
    authProfiles.set(args.profile_name, profile);
  }
  return result;
}

// ── Temp email ──

const TEMP_EMAIL_PROVIDERS = ["mail.tm", "guerrillamail"];

const BROWSER_HEADERS = {
  "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
  "Accept": "application/json, text/plain, */*",
  "Accept-Language": "en-US,en;q=0.9",
};

function generatePassword(len = 16) {
  const chars = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%";
  let pw = "";
  for (let i = 0; i < len; i++) pw += chars[Math.floor(Math.random() * chars.length)];
  return pw;
}

function generateUsername(len = 10) {
  const chars = "abcdefghijkmnpqrstuvwxyz23456789";
  let name = "hunt_";
  for (let i = 0; i < len; i++) name += chars[Math.floor(Math.random() * chars.length)];
  return name;
}

async function failDetail(resp, prefix) {
  let body = "";
  try { body = (await resp.text()).slice(0, 200); } catch { /* ignore */ }
  return `${prefix}: HTTP ${resp.status}${body ? ` — ${body}` : ""}`;
}

async function tempEmailCreate(preferredProvider) {
  const providers = preferredProvider
    ? [preferredProvider, ...TEMP_EMAIL_PROVIDERS.filter((p) => p !== preferredProvider)]
    : [...TEMP_EMAIL_PROVIDERS];
  const tried = [];

  for (const provider of providers) {
    try {
      if (provider === "mail.tm") {
        // Get available domain
        const domainResp = await fetch("https://api.mail.tm/domains", {
          headers: { ...BROWSER_HEADERS, Accept: "application/json" },
        });
        if (!domainResp.ok) throw new Error(await failDetail(domainResp, "mail.tm domains"));
        const domainData = await domainResp.json();
        const domains = domainData["hydra:member"] || domainData.member || [];
        if (!domains.length) throw new Error("mail.tm: no domains available");
        const emailDomain = domains[0].domain;
        const login = generateUsername();
        const password = generatePassword();
        const address = `${login}@${emailDomain}`;

        // Create account
        const createResp = await fetch("https://api.mail.tm/accounts", {
          method: "POST",
          headers: { ...BROWSER_HEADERS, "Content-Type": "application/json" },
          body: JSON.stringify({ address, password }),
        });
        if (!createResp.ok) throw new Error(await failDetail(createResp, "mail.tm create"));

        // Get auth token
        const tokenResp = await fetch("https://api.mail.tm/token", {
          method: "POST",
          headers: { ...BROWSER_HEADERS, "Content-Type": "application/json" },
          body: JSON.stringify({ address, password }),
        });
        if (!tokenResp.ok) throw new Error(await failDetail(tokenResp, "mail.tm token"));
        const tokenData = await tokenResp.json();

        const mailbox = { provider: "mail.tm", address, password, token: tokenData.token, domain: emailDomain, login };
        tempMailboxes.set(address, mailbox);
        return JSON.stringify({ success: true, email_address: address, password, provider: "mail.tm" });
      }

      if (provider === "guerrillamail") {
        const resp = await fetch("https://api.guerrillamail.com/ajax.php?f=get_email_address", {
          headers: BROWSER_HEADERS,
        });
        if (!resp.ok) throw new Error(await failDetail(resp, "guerrillamail get_email_address"));
        const data = await resp.json();
        const address = data.email_addr;
        if (!address) throw new Error("guerrillamail: no email_addr in response");
        const sidToken = data.sid_token;
        if (!sidToken) throw new Error("guerrillamail: no sid_token in response");
        const [login, emailDomain] = address.split("@");
        const password = generatePassword();

        const mailbox = { provider: "guerrillamail", address, password, token: sidToken, domain: emailDomain, login };
        tempMailboxes.set(address, mailbox);
        return JSON.stringify({ success: true, email_address: address, password, provider: "guerrillamail" });
      }
    } catch (err) {
      tried.push({ provider, error: err.message || String(err) });
    }
  }

  return JSON.stringify({ success: false, error: "All temp email providers failed", providers_tried: tried });
}

async function tempEmailPoll(emailAddress, fromFilter) {
  const mailbox = tempMailboxes.get(emailAddress);
  if (!mailbox) return JSON.stringify({ error: `Unknown email address: ${emailAddress}. Call create first.` });

  try {
    let messages = [];

    if (mailbox.provider === "mail.tm") {
      const resp = await fetch("https://api.mail.tm/messages", {
        headers: { ...BROWSER_HEADERS, Authorization: `Bearer ${mailbox.token}`, Accept: "application/json" },
      });
      if (!resp.ok) return JSON.stringify({ error: await failDetail(resp, "mail.tm poll") });
      const data = await resp.json();
      messages = (data["hydra:member"] || data.member || []).map((m) => ({
        id: m.id || m["@id"],
        from: m.from?.address || "",
        subject: m.subject || "",
        date: m.createdAt || "",
      }));
    }

    if (mailbox.provider === "guerrillamail") {
      const resp = await fetch(
        `https://api.guerrillamail.com/ajax.php?f=check_email&seq=0&sid_token=${encodeURIComponent(mailbox.token)}`,
        { headers: BROWSER_HEADERS }
      );
      if (!resp.ok) return JSON.stringify({ error: await failDetail(resp, "guerrillamail poll") });
      const data = await resp.json();
      messages = (data.list || []).map((m) => ({
        id: String(m.mail_id),
        from: m.mail_from || "",
        subject: m.mail_subject || "",
        date: m.mail_date || "",
      }));
    }

    if (fromFilter) {
      const filter = fromFilter.toLowerCase();
      messages = messages.filter((m) => m.from.toLowerCase().includes(filter));
    }

    return JSON.stringify({ success: true, messages });
  } catch (err) {
    return JSON.stringify({ error: err.message || String(err) });
  }
}

async function tempEmailExtract(emailAddress, messageId) {
  const mailbox = tempMailboxes.get(emailAddress);
  if (!mailbox) return JSON.stringify({ error: `Unknown email address: ${emailAddress}. Call create first.` });

  try {
    let bodyText = "";

    if (mailbox.provider === "mail.tm") {
      const resp = await fetch(`https://api.mail.tm/messages/${encodeURIComponent(messageId)}`, {
        headers: { ...BROWSER_HEADERS, Authorization: `Bearer ${mailbox.token}`, Accept: "application/json" },
      });
      if (!resp.ok) return JSON.stringify({ error: await failDetail(resp, "mail.tm read") });
      const data = await resp.json();
      bodyText = data.text || data.html || "";
    }

    if (mailbox.provider === "guerrillamail") {
      const resp = await fetch(
        `https://api.guerrillamail.com/ajax.php?f=fetch_email&email_id=${encodeURIComponent(messageId)}&sid_token=${encodeURIComponent(mailbox.token)}`,
        { headers: BROWSER_HEADERS }
      );
      if (!resp.ok) return JSON.stringify({ error: await failDetail(resp, "guerrillamail read") });
      const data = await resp.json();
      bodyText = data.mail_body || "";
    }

    // Strip HTML tags for code extraction
    const plainText = bodyText.replace(/<[^>]+>/g, " ").replace(/&nbsp;/g, " ");

    // Extract verification codes (4-8 digit numbers)
    const codeMatches = plainText.match(/\b(\d{4,8})\b/g) || [];
    const verificationCodes = [...new Set(codeMatches)];

    // Extract verification links
    const linkPattern = /https?:\/\/[^\s"'<>]+(?:verify|confirm|activate|token|code|validate|email)[^\s"'<>]*/gi;
    const linkMatches = bodyText.match(linkPattern) || [];
    const verificationLinks = [...new Set(linkMatches)];

    return JSON.stringify({
      success: true,
      verification_codes: verificationCodes,
      verification_links: verificationLinks,
      raw_text_preview: plainText.slice(0, 500),
    });
  } catch (err) {
    return JSON.stringify({ error: err.message || String(err) });
  }
}

async function tempEmail(args) {
  const op = args.operation;
  if (op === "create") return tempEmailCreate(args.provider);
  if (op === "poll") return tempEmailPoll(args.email_address, args.from_filter);
  if (op === "extract") return tempEmailExtract(args.email_address, args.message_id);
  return JSON.stringify({ error: `Unknown operation: ${op}` });
}

// ── Signup detect ──

const SIGNUP_PATHS = [
  "/register", "/signup", "/sign-up", "/join", "/create-account",
  "/api/register", "/api/signup", "/api/auth/register", "/api/auth/signup",
  "/api/v1/register", "/api/v1/signup", "/api/v1/auth/register",
  "/auth/register", "/auth/signup", "/account/create",
  "/free-trial", "/try", "/get-started", "/start", "/onboarding",
  "/pricing", "/plans", "/account/signup", "/users/sign_up",
];

const CAPTCHA_INDICATORS = ["recaptcha", "hcaptcha", "turnstile", "captcha", "g-recaptcha", "cf-turnstile", "h-captcha"];

const FORM_FIELD_PATTERNS = [
  { name: "email", pattern: /name=["']?(?:email|e-mail|user_email|userEmail)["'\s>]/i },
  { name: "password", pattern: /name=["']?(?:password|passwd|pass|user_password)["'\s>]/i },
  { name: "username", pattern: /name=["']?(?:username|user_name|login|handle)["'\s>]/i },
  { name: "name", pattern: /name=["']?(?:name|full_name|fullName|first_name|firstName)["'\s>]/i },
  { name: "phone", pattern: /name=["']?(?:phone|telephone|mobile|tel)["'\s>]/i },
];

async function signupDetect(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const targetUrl = assertNonEmptyString(args.target_url, "target_url").replace(/\/+$/, "");

  const endpointsFound = [];
  const formFieldsSet = new Set();
  let hasCaptcha = false;
  let captchaType = null;
  let oauthOnly = false;
  let emailRestrictions = false;

  for (const signupPath of SIGNUP_PATHS) {
    try {
      const url = `${targetUrl}${signupPath}`;
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 5000);
      const resp = await fetch(url, {
        method: "GET",
        headers: { "User-Agent": "Mozilla/5.0 (compatible; security-testing)", Accept: "text/html,application/json" },
        redirect: "follow",
        signal: controller.signal,
      });
      clearTimeout(timeout);

      if (resp.status >= 200 && resp.status < 400) {
        const ct = resp.headers.get("content-type") || "";
        let body = "";
        if (ct.includes("text") || ct.includes("json") || ct.includes("html")) {
          body = (await resp.text()).slice(0, 20000);
        }

        endpointsFound.push({ path: signupPath, method: "GET", status: resp.status });

        // Detect form fields
        for (const { name, pattern } of FORM_FIELD_PATTERNS) {
          if (pattern.test(body)) formFieldsSet.add(name);
        }

        // Detect CAPTCHA
        const bodyLower = body.toLowerCase();
        for (const indicator of CAPTCHA_INDICATORS) {
          if (bodyLower.includes(indicator)) {
            hasCaptcha = true;
            captchaType = captchaType || indicator;
          }
        }

        // Detect email restrictions
        if (/disposable|temporary email|business email only|corporate email/i.test(body)) {
          emailRestrictions = true;
        }

        // Detect OAuth-only
        if (!formFieldsSet.has("email") && !formFieldsSet.has("password")) {
          const hasOAuth = /oauth|google.*sign|facebook.*sign|github.*sign|sign.*with.*google|sign.*with.*github/i.test(body);
          if (hasOAuth && endpointsFound.length === 1) oauthOnly = true;
        }
      }
    } catch {
      // Timeout or connection error — skip this path
    }
  }

  // Determine feasibility
  let feasibility = "manual";
  if (endpointsFound.length > 0) {
    if (oauthOnly) {
      feasibility = "manual";
    } else if (hasCaptcha) {
      feasibility = "assisted";
    } else {
      feasibility = "automated";
    }
  }

  // Override: if OAuth-only was a premature guess and we found email fields later, correct it
  if (formFieldsSet.has("email") && formFieldsSet.has("password")) {
    oauthOnly = false;
  }

  return JSON.stringify({
    endpoints_found: endpointsFound,
    form_fields: [...formFieldsSet],
    has_captcha: hasCaptcha,
    captcha_type: captchaType,
    oauth_only: oauthOnly,
    email_restrictions_detected: emailRestrictions,
    signup_feasibility: feasibility,
  });
}

// ── Auto signup (browser-based) ──

const { execFile } = require("child_process");

async function autoSignup(args) {
  const domain = assertNonEmptyString(args.target_domain, "target_domain");
  const signupUrl = assertNonEmptyString(args.signup_url, "signup_url");
  const email = assertNonEmptyString(args.email, "email");
  const password = assertNonEmptyString(args.password, "password");
  const role = args.role || "attacker";
  const name = args.name || "Hunter Test";

  // Check if patchright is available before spawning the script
  let patchrightAvailable = false;
  try {
    require.resolve("patchright");
    patchrightAvailable = true;
  } catch {}

  if (!patchrightAvailable) {
    return JSON.stringify({
      success: false,
      error: "patchright not installed. Run: npm install && npx patchright install chromium",
      fallback: "manual",
    });
  }

  const scriptPath = path.join(__dirname, "auto-signup.js");
  if (!fs.existsSync(scriptPath)) {
    return JSON.stringify({ success: false, error: "auto-signup.js not found", fallback: "manual" });
  }

  const config = {
    signup_url: signupUrl,
    email,
    password,
    name,
    capsolver_api_key: process.env.CAPSOLVER_API_KEY || null,
    proxy: args.proxy || process.env.BOUNTY_PROXY || null,
    timeout_ms: args.timeout_ms || 45000,
    headless: args.headless !== undefined ? args.headless : false,
  };

  return new Promise((resolve) => {
    const timeout = (config.timeout_ms || 45000) + 10000; // script timeout + buffer
    const child = execFile(
      process.execPath,
      [scriptPath, JSON.stringify(config)],
      { timeout, maxBuffer: 5 * 1024 * 1024, env: { ...process.env } },
      async (err, stdout, stderr) => {
        if (err && !stdout) {
          resolve(JSON.stringify({
            success: false,
            error: err.message || String(err),
            stderr: (stderr || "").slice(0, 500),
            fallback: "manual",
          }));
          return;
        }

        let result;
        try {
          result = JSON.parse(stdout);
        } catch {
          resolve(JSON.stringify({
            success: false,
            error: "auto-signup returned invalid JSON",
            raw_output: (stdout || "").slice(0, 500),
            fallback: "manual",
          }));
          return;
        }

        // If signup succeeded, auto-store auth
        if (result.success && (Object.keys(result.cookies || {}).length > 0 || Object.keys(result.headers || {}).length > 0)) {
          try {
            await authStore({
              target_domain: domain,
              role,
              cookies: result.cookies || {},
              headers: result.headers || {},
              local_storage: result.local_storage || {},
              credentials: { email, password },
            });
            result.auth_stored = true;
            result.auth_role = role;
          } catch (storeErr) {
            result.auth_stored = false;
            result.auth_store_error = storeErr.message;
          }
        }

        resolve(JSON.stringify(result));
      }
    );
  });
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
    case "bounty_transition_phase": return transitionPhase(args);
    case "bounty_start_wave": return startWave(args);
    case "bounty_apply_wave_merge": return applyWaveMerge(args);
    case "bounty_write_handoff": return writeHandoff(args);
    case "bounty_log_dead_ends": return logDeadEnds(args);
    case "bounty_write_wave_handoff": return writeWaveHandoff(args);
    case "bounty_wave_handoff_status": return waveHandoffStatus(args);
    case "bounty_merge_wave_handoffs": return mergeWaveHandoffs(args);
    case "bounty_read_handoff": return readHandoff(args);
    case "bounty_auth_manual": return authManual(args);
    case "bounty_wave_status": return waveStatus(args);
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
  gradeArtifactPaths,
  initSession,
  listFindings,
  mergeWaveHandoffs,
  migrateAuthJson,
  normalizeFindingRecord,
  normalizeGradeVerdictDocument,
  normalizeSessionStateDocument,
  readAuthJson,
  resolveAuthJsonPath,
  sessionDir,
  sessionLockPath,
  statePath,
  startWave,
  findingsJsonlPath,
  findingsMarkdownPath,
  readFindings,
  readFindingsFromJsonl,
  readHunterBrief,
  readGradeVerdict,
  readScopeExclusions,
  readSessionState,
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
