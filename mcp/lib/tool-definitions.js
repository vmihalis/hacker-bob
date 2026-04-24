const {
  AUTH_STATUS_VALUES,
  COVERAGE_STATUS_VALUES,
  GRADE_VERDICT_VALUES,
  PHASE_VALUES,
  SEVERITY_VALUES,
  VERIFICATION_DISPOSITION_VALUES,
  VERIFICATION_ROUND_VALUES,
} = require("./constants.js");

const TOOLS = [
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
            { type: "array", items: { type: "object", additionalProperties: true } },
            { type: "object", additionalProperties: true },
            { type: "string" },
          ],
          description: "Array of HAR log.entries items, a HAR object with log.entries, a JSON string containing either shape, or simplified {method,url,status,headers,ts} records.",
        },
      },
      required: ["target_domain", "source"],
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
    name: "bounty_import_static_artifact",
    description:
      "Import a token contract source artifact into session-owned static-imports for later safe static scanning. Accepts content only; filesystem path imports are rejected. Stored content is redacted and capped.",
    inputSchema: {
      type: "object",
      properties: {
        target_domain: { type: "string" },
        artifact_type: { type: "string", enum: ["evm_token_contract", "solana_token_contract"] },
        content: { type: "string", maxLength: 200000 },
        label: { type: "string", description: "Optional short display label for the artifact." },
        source_name: { type: "string", description: "Optional source filename/display name. Used as a label only; no file is read." },
        surface_id: { type: "string", description: "Optional attack_surface.json surface ID to scope hunter brief hints." },
      },
      required: ["target_domain", "artifact_type", "content"],
    },
  },
  {
    name: "bounty_static_scan",
    description:
      "Run a deterministic token-contract static scan on a previously imported session-owned artifact. Results are stored as redacted structured JSON in static-scan-results.jsonl and summarized in hunter briefs.",
    inputSchema: {
      type: "object",
      properties: {
        target_domain: { type: "string" },
        artifact_id: { type: "string", pattern: "^SA-[1-9][0-9]*$" },
        scan_type: { type: "string", enum: ["token_contract"], description: "Defaults to token_contract." },
        limit: { type: "number", description: "Max findings to return in the immediate response. Stored results remain capped by Bob." },
      },
      required: ["target_domain", "artifact_id"],
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
        auth_profile: { type: "string" },
        surface_id: { type: "string" },
        validated: { type: "boolean" },
        wave: { type: "string" },
        agent: { type: "string" },
        force_record: { type: "boolean", description: "Intentionally record a duplicate finding instead of returning the existing finding ID." },
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
        handoff_token: { type: "string", minLength: 16 },
        summary: { type: "string", minLength: 1, maxLength: 2000 },
        chain_notes: { type: "array", maxItems: 20, items: { type: "string", minLength: 1, maxLength: 300 } },
        content: { type: "string" },
        dead_ends: { type: "array", items: { type: "string" } },
        waf_blocked_endpoints: { type: "array", items: { type: "string" } },
        lead_surface_ids: { type: "array", items: { type: "string" } },
      },
      required: ["target_domain", "wave", "agent", "surface_id", "surface_status", "summary", "content"],
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
    name: "bounty_read_wave_handoffs",
    description:
      "Read validated structured wave handoff summaries from handoff-wN-aN.json files only. Markdown handoffs are ignored.",
    inputSchema: {
      type: "object",
      properties: {
        target_domain: { type: "string" },
        wave_number: { type: "number", description: "Optional wave number. When omitted, all assignment files are scanned." },
      },
      required: ["target_domain"],
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
      "Store an authentication profile by profile_name. Names such as attacker, victim, admin, and tenant_b are caller-defined auth profiles.",
    inputSchema: {
      type: "object",
      properties: {
        target_domain: { type: "string" },
        profile_name: { type: "string" },
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
      required: ["target_domain", "profile_name"],
    },
  },
  {
    name: "bounty_list_auth_profiles",
    description:
      "Return redacted auth profile status for a target. Shows profile names, header/cookie key names, credential presence, and expiry/staleness hints without token, cookie, localStorage, or password values.",
    inputSchema: {
      type: "object",
      properties: {
        target_domain: { type: "string" },
      },
      required: ["target_domain"],
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
        profile_name: { type: "string", default: "attacker" },
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
      "Return everything a hunter needs to start testing: assigned surface, exclusions, valid surface IDs, bypass table, bounded curated technique guidance, and capped traffic/audit/intel/static-scan hints. Hunters call this once on startup instead of receiving everything via spawn prompt.",
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

module.exports = { TOOLS };
