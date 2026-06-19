---
title: "Hacker Bob Offline Code Walkthrough"
subtitle: "v1.3.5 snapshot — How the project, agent pipeline, MCP memory, context management, and JSON state fit together"
author: "Generated for local code review"
date: "2026-05-01"
lang: en
---

> **v1.3.5 snapshot.** This walkthrough was generated against the v1.x codebase prior to the v2.0.0 frontier-topology rewrite. It uses the legacy vocabulary throughout (`bountyagent` MCP server, `bounty_*` tool prefix, eight-phase FSM, `~/bounty-agent-sessions/` session root, `findings.jsonl` claim ledger). Treat every named tool, namespace, and session path here as a v1.x identifier. For target-state vocabulary see [CHANGELOG.md v2.0.0](../CHANGELOG.md), [docs/releases/v2.0.0.md](releases/v2.0.0.md), and the rewritten [docs/FIRST_RUN.md](FIRST_RUN.md) / [docs/SMART_CONTRACTS_SPEC.md](SMART_CONTRACTS_SPEC.md) / [docs/capability-hypergraph.md](capability-hypergraph.md).

# How To Use This Guide

This guide is meant for a flight or any offline reading session. It assumes you
have the repository checkout open locally and no internet connection.

Read it in two passes:

1. First pass: understand the system shape. Focus on the diagrams, the phase
   flow, and the artifact tables.
2. Second pass: keep the repo open and follow the file-by-file reading plan.
   When a section references a file, open it and skim the exact functions named
   there.

All paths in this guide are relative to the repository root:

```text
<repo-root>
```

The most important idea is this:

```text
Claude chat coordinates.
Agents do bounded jobs.
The MCP server owns memory and validation.
JSON/JSONL artifacts are the durable source of truth.
Markdown is mostly for humans.
```

\newpage

# One-Page Mental Model

Hacker Bob is not one monolithic script. It is a local Claude Code framework
installed into a Claude Code project.

The source repo contains:

```text
.claude/        Claude-facing commands, skills, agents, hooks, rules, knowledge
mcp/            Local MCP server and all runtime tool implementations
scripts/        Installer, config merge, release, prompt generation utilities
bin/            CLI entry point: hacker-bob
test/           Contract tests for MCP, prompts, installer, CLI, hooks
testing/        Policy replay harness for prompt/refusal diagnostics
docs/           Human docs and release notes
```

At runtime, a Bob evaluate creates a local session directory:

```text
~/bounty-agent-sessions/[target_domain]/
```

That session directory stores structured artifacts:

```text
state.json
attack_surface.json
wave-1-assignments.json
handoff-w1-a1.json
coverage.jsonl
findings.jsonl
chain-attempts.jsonl
brutalist.json
balanced.json
verified-final.json
evidence-packs.json
grade.json
report.md
pipeline-events.jsonl
http-audit.jsonl
```

The slash command `/bob-evaluate` is the orchestrator. It does not directly evaluate.
It coordinates the finite-state machine:

```text
SURFACE_DISCOVERY -> AUTH -> EVALUATE -> CHAIN -> VERIFY -> GRADE -> REPORT
```

The heavy work is delegated to specialist agents:

```text
surface-discovery-agent
evaluator-agent
chain-builder
brutalist-verifier
balanced-verifier
final-verifier
evidence-agent
grader
report-writer
```

The MCP server exposes 39 `bounty_*` tools. Those tools validate inputs, write
state atomically, enforce phase gates, redact sensitive data, summarize context,
and return standard envelopes:

```json
{
  "ok": true,
  "data": {},
  "meta": {
    "tool": "bounty_read_state_summary",
    "version": 1
  }
}
```

\newpage

# Why This Architecture Exists

The design is a response to four hard problems in agentic security work.

## Problem 1: Chat Context Is Too Small

A full bounty run can include:

- surface-discovery output
- live hosts
- archived URLs
- JavaScript endpoints
- imported HTTP traffic
- auth profiles
- hundreds of HTTP scan records
- evaluator notes
- coverage records
- findings
- chain attempts
- verification rounds
- evidence samples
- grading
- report drafts

Pasting all of that into every agent would overwhelm the context window and
make agents repeat work. Bob solves this by storing durable state in MCP-owned
JSON and JSONL files, then giving each agent a small slice.

The most important context-reduction tool is:

```text
mcp/lib/assignment-brief.js
```

That file builds a curated evaluator brief from:

- assigned surface
- coverage summary
- imported traffic summary
- HTTP audit summary
- circuit-breaker summary
- ranking summary
- public intel hints
- static scan hints
- auth hint
- bypass table
- curated evaluator techniques

Evaluators receive one assigned surface, not the entire session.

## Problem 2: Many Agents Need One Shared Memory

The root orchestrator and subagents are separate Claude Code contexts. A
background evaluator might finish after the root chat has moved on or after context
compaction. Shared state cannot live only in a message transcript.

Bob therefore uses:

```text
~/bounty-agent-sessions/[domain]/
```

as the durable memory store, with MCP tools as the only trusted writers for
critical artifacts.

## Problem 3: Agents Drift Unless Outputs Are Structured

Without strict structure, an agent might say "I found something" in prose but
forget to write the machine-readable artifact. Bob makes each phase write a
specific artifact:

- evaluators write `handoff-wN-aN.json`
- evaluators record findings in `findings.jsonl`
- chain builder writes `chain-attempts.jsonl`
- verifiers write `brutalist.json`, `balanced.json`, `verified-final.json`
- evidence agent writes `evidence-packs.json`
- grader writes `grade.json`
- reporter writes `report.md`

Phase gates inspect those structured artifacts. Prose alone does not count.

## Problem 4: Security Automation Needs Guardrails

Bob can send real HTTP requests and store sensitive test data. The repo has
guardrails in several layers:

- MCP input validation in `mcp/lib/tool-validation.js`
- path safety in `mcp/lib/paths.js`
- atomic writes and session locks in `mcp/lib/storage.js`
- redaction in `mcp/redaction.js`, `mcp/lib/http-records.js`, and evidence
  validation
- write guard hook in `.claude/hooks/session-write-guard.sh`
- evaluator stop validation in `.claude/hooks/agent-run-stop.js`
- phase gates in `mcp/lib/phase-gates.js`
- egress profile handling in `mcp/lib/egress-profiles.js`

\newpage

# Source Checkout Versus Installed Workspace

This repo is usually the source package. It installs Bob into another Claude
Code project directory.

## Source Repo

The source repo is where you develop Bob:

```text
<repo-root>
```

Here you run:

```bash
npm test
node scripts/generate-agent-tools.js --check
node scripts/generate-bountyagent-skill.js --check
```

## Installed Project

An installed project is where a user actually runs Claude Code and `/bob-evaluate`:

```text
/path/to/user/project
```

The installer copies these into that target:

```text
.claude/
mcp/
.mcp.json
testing/policy-replay/
```

Important installer files:

```text
bin/hacker-bob.js
install.sh
scripts/install.js
scripts/merge-claude-config.js
scripts/lifecycle.js
mcp/lib/claude-config.js
```

The CLI has these main commands:

```text
hacker-bob install <project-dir>
hacker-bob update <project-dir>
hacker-bob check-update <project-dir>
hacker-bob doctor <project-dir>
hacker-bob uninstall <project-dir>
```

`hacker-bob` is the canonical npm package. `hacker-bob-cc` and
`hacker-bob-codex` are small adapter wrapper packages that depend on the
matching canonical version.

\newpage

# The Three Control Surfaces

Bob has three main control surfaces.

## 1. Slash Commands And Skills

Files:

```text
.claude/skills/bob-evaluate/SKILL.md
.claude/skills/bob-status/SKILL.md
.claude/skills/bob-debug/SKILL.md
.claude/commands/bob-update.md
.claude/commands/bob-egress.md
```

Claude Code turns these into user-facing commands:

```text
/bob-evaluate
/bob-status
/bob-debug
/bob-update
/bob-egress
```

The most important file is `bob-evaluate/SKILL.md`. It is the orchestrator prompt.
It defines:

- accepted arguments
- flags such as `--no-auth` and `--egress`
- the finite-state machine
- which MCP tools are authoritative
- how to spawn each specialist agent
- when to wait
- when to stop
- when to merge a wave
- which artifacts to validate before moving forward

## 2. Agent Definitions

Files:

```text
.claude/agents/surface-discovery-agent.md
.claude/agents/evaluator-agent.md
.claude/agents/chain-builder.md
.claude/agents/brutalist-verifier.md
.claude/agents/balanced-verifier.md
.claude/agents/final-verifier.md
.claude/agents/evidence-agent.md
.claude/agents/grader.md
.claude/agents/report-writer.md
```

Each agent has:

- a role
- allowed tools
- model preference
- MCP server metadata when needed
- a final-output contract

Example: evaluators do not get the `Write` tool. They can write durable evaluate
artifacts only through MCP tools such as:

```text
bounty_record_finding
bounty_log_coverage
bounty_write_wave_handoff
```

## 3. MCP Runtime

Files:

```text
mcp/server.js
mcp/lib/transport.js
mcp/lib/tool-registry.js
mcp/lib/dispatch.js
mcp/lib/tools/index.js
mcp/lib/tools/*.js
mcp/lib/*.js
```

Claude Code talks to `mcp/server.js` over stdio. The server exposes `bounty_*`
tools. It validates, dispatches, records telemetry, and returns standard
envelopes.

\newpage

# The Full Runtime Flow

This is the simplified execution path when the user runs:

```text
/bob-evaluate example.com
```

```text
User
  |
  v
/bob-evaluate skill
  |
  v
Root orchestrator prompt
  |
  +--> MCP: bounty_init_session
  |
  +--> Task: surface-discovery-agent
  |       |
  |       +--> writes attack_surface.json
  |
  +--> MCP: bounty_transition_phase AUTH
  |
  +--> AUTH tools: signup detect, temp email, auth store
  |
  +--> MCP: bounty_transition_phase EVALUATE
  |
  +--> MCP: bounty_start_wave
  |       |
  |       +--> writes wave-N-assignments.json
  |       +--> sets state.pending_wave = N
  |
  +--> background evaluator agents
  |       |
  |       +--> MCP: bounty_read_assignment_brief
  |       +--> MCP: bounty_http_scan
  |       +--> MCP: bounty_log_coverage
  |       +--> MCP: bounty_record_finding
  |       +--> MCP: bounty_write_wave_handoff
  |       +--> final marker: BOB_AGENT_RUN_DONE {...}
  |
  +--> evaluator SubagentStop hook validates marker + handoff
  |
  +--> MCP: bounty_apply_wave_merge
  |       |
  |       +--> validates handoffs
  |       +--> updates explored/dead_ends/leads/findings count
  |       +--> clears pending_wave
  |
  +--> more waves or CHAIN
  |
  +--> chain-builder
  |       |
  |       +--> writes chain-attempts.jsonl
  |
  +--> brutalist verifier
  +--> balanced verifier
  +--> final verifier
  |
  +--> evidence-agent
  |       |
  |       +--> writes evidence-packs.json
  |
  +--> grader
  |       |
  |       +--> writes grade.json
  |
  +--> report-writer
          |
          +--> writes report.md
```

The orchestration principle:

```text
The root orchestrator coordinates state and agents.
It does not do ad-hoc target testing outside the AUTH path.
```

\newpage

# The Finite-State Machine

The state machine is implemented in:

```text
mcp/lib/session-state.js
mcp/lib/phase-gates.js
```

Valid phases:

```text
SURFACE_DISCOVERY
AUTH
EVALUATE
CHAIN
VERIFY
GRADE
REPORT
EXPLORE
```

Allowed transitions:

```text
SURFACE_DISCOVERY   -> AUTH
AUTH    -> EVALUATE
EVALUATE    -> CHAIN
CHAIN   -> VERIFY
VERIFY  -> GRADE
GRADE   -> REPORT
GRADE   -> EVALUATE      # on HOLD
REPORT  -> EXPLORE   # user asks for more evaluating
EXPLORE -> CHAIN
```

Important transition gates:

## EVALUATE -> CHAIN

Blocked when:

- `pending_wave` is still set
- attack surface cannot be read
- high or critical surfaces remain unexplored
- latest coverage contains unfinished `promising`, `needs_auth`, or `requeue`
  entries

Code:

```text
mcp/lib/phase-gates.js
computeEvaluationToChainGate()
```

## CHAIN -> VERIFY

Blocked when chain work is required but no terminal chain attempt exists.

Chain work is required when:

- there are multiple findings, or
- structured wave handoffs contain `chain_notes`

Terminal outcomes:

```text
confirmed
denied
blocked
not_applicable
```

Code:

```text
mcp/lib/phase-gates.js
computeChainToVerifyGate()
```

## VERIFY -> GRADE

Blocked when final reportable findings exist but valid evidence packs are
missing.

Code:

```text
mcp/lib/phase-gates.js
computeVerifyToGradeGate()
mcp/lib/evidence.js
requireValidEvidencePacksForFinalReportableFindings()
```

## GRADE -> REPORT

Also checks evidence validity. The report should only be trusted after final
verification, evidence, and grade artifacts exist and validate.

\newpage

# Session State

The initial state is created by:

```text
mcp/lib/session-state.js
buildInitialSessionState()
initSession()
```

Example simplified `state.json`:

```json
{
  "target": "example.com",
  "target_url": "https://example.com",
  "checkpoint_mode": "paranoid",
  "block_internal_hosts": true,
  "block_internal_hosts_source": "paranoid_default",
  "phase": "EVALUATE",
  "evaluation_wave": 2,
  "pending_wave": null,
  "total_findings": 1,
  "explored": ["api-main", "auth-flow"],
  "dead_ends": ["cdn.example.com static-only"],
  "waf_blocked_endpoints": ["/admin/export"],
  "lead_surface_ids": ["billing-api"],
  "scope_exclusions": [],
  "hold_count": 0,
  "auth_status": "authenticated"
}
```

Key fields:

```text
phase
  Current FSM phase.

evaluation_wave
  Last merged wave number.

pending_wave
  Wave started but not settled yet. If this is not null, the correct path is
  usually /bob-evaluate resume <domain>.

explored
  Surface IDs completed by merged wave handoffs.

dead_ends
  Durable endpoint/host notes that should not be retried blindly.

waf_blocked_endpoints
  Endpoint classes where evaluators hit hard blocking.

lead_surface_ids
  Existing attack surface IDs that later waves should prioritize.

total_findings
  Updated during wave merge from findings.jsonl summary.

hold_count
  Incremented when GRADE sends the workflow back to EVALUATE.

auth_status
  pending, authenticated, or unauthenticated.

checkpoint_mode / block_internal_hosts
  The selected checkpoint mode and effective direct-egress internal-host
  blocking policy. `normal`, `yolo`, and pre-policy legacy sessions default to
  false; `paranoid` defaults to true unless initialized with
  `allow_internal_hosts`.
```

There are two read styles:

```text
bounty_read_session_state
  Full public state arrays.

bounty_read_state_summary
  Compact counts for routine orchestration.
```

This is one context-management pattern used throughout Bob: prefer summaries
unless the full arrays are needed.

\newpage

# JSON, JSONL, And Markdown

Bob uses three artifact styles.

## JSON

Use JSON for current authoritative documents:

```text
state.json
attack_surface.json
wave-1-assignments.json
handoff-w1-a1.json
brutalist.json
balanced.json
verified-final.json
evidence-packs.json
grade.json
public-intel.json
```

JSON files are best when there is one current document to read and validate.

## JSONL

Use JSONL for append-only event streams:

```text
findings.jsonl
coverage.jsonl
http-audit.jsonl
traffic.jsonl
chain-attempts.jsonl
pipeline-events.jsonl
static-artifacts.jsonl
static-scan-results.jsonl
```

Each line is a complete JSON object. This is useful when agents keep appending
records over time without rewriting a whole file.

## Markdown

Use Markdown for human-readable mirrors:

```text
findings.md
brutalist.md
balanced.md
verified-final.md
evidence-packs.md
grade.md
SESSION_HANDOFF.md
report.md
handoff-w1-a1.md
```

Important distinction:

```text
Machine-readable orchestration should use JSON and JSONL.
Markdown is for humans and debugging.
```

The exception is `report.md`, which is the final human-facing output written by
the report writer.

\newpage

# Core Artifact Table

| Artifact | Format | Owner | Purpose |
|---|---:|---|---|
| `state.json` | JSON | MCP | FSM phase, waves, explored surfaces, auth status |
| `attack_surface.json` | JSON | surface-discovery-agent | Surface-discovery output and evaluator surface list |
| `traffic.jsonl` | JSONL | MCP | Imported HAR/Burp-style traffic |
| `http-audit.jsonl` | JSONL | MCP | Redacted record of Bob HTTP scan calls |
| `wave-N-assignments.json` | JSON | MCP | Which evaluator owns which surface |
| `.handoff-signing-key.json` | JSON | MCP | Session-local private key for tokenized handoff signatures |
| `handoff-wN-aN.json` | JSON | MCP | Authoritative evaluator final handoff |
| `handoff-wN-aN.md` | Markdown | MCP | Human mirror of evaluator handoff |
| `coverage.jsonl` | JSONL | MCP | Endpoint/class/auth coverage records |
| `findings.jsonl` | JSONL | MCP | Proven findings recorded by evaluators |
| `chain-attempts.jsonl` | JSONL | MCP | Tested chain hypotheses and outcomes |
| `brutalist.json` | JSON | MCP | Verification round 1 |
| `balanced.json` | JSON | MCP | Verification round 2 |
| `verified-final.json` | JSON | MCP | Final verification round |
| `evidence-packs.json` | JSON | MCP | Bounded evidence for final reportables |
| `grade.json` | JSON | MCP | SUBMIT/HOLD/SKIP verdict |
| `report.md` | Markdown | report-writer | Final output for the operator |
| `pipeline-events.jsonl` | JSONL | MCP | Phase/wave/finding/verification/grade events |
| tool telemetry | JSONL | MCP | Safe metadata for MCP tool health |

\newpage

# MCP Server Architecture

Start here:

```text
mcp/server.js
```

This file is a facade. It imports most runtime helpers and exports them for
runtime entrypoints only:

- `TOOLS`
- `TOOL_MANIFEST`
- `executeTool`
- `startServer`

Tests and helper scripts should import lower-level behavior from the module that
owns it instead of expanding this facade. When run as a process, it starts the
stdio MCP server:

```text
startServer()
  -> startStdioServer({ tools: TOOLS, executeTool })
```

## Transport

File:

```text
mcp/lib/transport.js
```

Responsibilities:

- handle MCP `initialize`
- answer `ping`
- return `tools/list`
- execute `tools/call`
- support both framed `Content-Length` messages and raw JSON lines
- serialize tool envelopes back into MCP text content

## Registry

File:

```text
mcp/lib/tool-registry.js
```

The registry imports:

```text
mcp/lib/tools/index.js
```

Each tool entry must define:

```text
name
description
inputSchema
handler
role_bundles
mutating
global_preapproval
network_access
browser_access
scope_required
sensitive_output
session_artifacts_written
```

This metadata drives:

- MCP tool exposure
- Claude settings permissions
- agent allowed tools
- prompt contract tests
- installed session-artifact hooks; central session authority is enforced by the dispatcher/policy layer, with HTTP scope URL checks layered on tools that set `scope_required`
- docs and generated surfaces

## Dispatch

File:

```text
mcp/lib/dispatch.js
```

Flow:

```text
executeTool(name, args)
  -> look up tool
  -> validate input schema
  -> resolve session authority
  -> apply scoped URL policy
  -> call handler
  -> parse handler result
  -> classify data errors
  -> wrap in ok/error envelope
  -> record safe telemetry
```

## Envelopes

File:

```text
mcp/lib/envelope.js
```

Success:

```json
{
  "ok": true,
  "data": {
    "version": 1
  },
  "meta": {
    "tool": "bounty_example",
    "version": 1
  }
}
```

Failure:

```json
{
  "ok": false,
  "error": {
    "code": "STATE_CONFLICT",
    "message": "Wave merge requires pending_wave to be set"
  },
  "meta": {
    "tool": "bounty_apply_wave_merge",
    "version": 1
  }
}
```

The orchestrator prompt explicitly says: use `.data` on success and `.error`
on failure. Do not infer success from random top-level fields.

\newpage

# The 39 MCP Tools By Role

The tools are registered in `mcp/lib/tools/index.js` and metadata is enforced
by `mcp/lib/tool-registry.js`.

## Orchestrator Tools

```text
bounty_init_session
bounty_read_session_state
bounty_read_state_summary
bounty_transition_phase
bounty_start_wave
bounty_apply_wave_merge
bounty_wave_status
bounty_wave_handoff_status
bounty_merge_wave_handoffs
bounty_read_wave_handoffs
bounty_write_handoff
bounty_import_http_traffic
bounty_public_intel
bounty_list_findings
bounty_read_chain_attempts
bounty_read_verification_round
bounty_read_evidence_packs
bounty_read_grade_verdict
bounty_list_auth_profiles
bounty_read_tool_telemetry
bounty_read_pipeline_analytics
```

## Evaluator Tools

```text
bounty_read_assignment_brief
bounty_http_scan
bounty_read_http_audit
bounty_import_static_artifact
bounty_static_scan
bounty_record_finding
bounty_list_findings
bounty_log_coverage
bounty_log_dead_ends
bounty_write_wave_handoff
bounty_list_auth_profiles
```

## Auth Tools

```text
bounty_signup_detect
bounty_temp_email
bounty_auto_signup
bounty_auth_store
bounty_list_auth_profiles
bounty_http_scan
```

## Chain Tools

```text
bounty_read_findings
bounty_read_wave_handoffs
bounty_read_chain_attempts
bounty_write_chain_attempt
bounty_read_http_audit
bounty_list_auth_profiles
bounty_http_scan
```

## Verification Tools

```text
bounty_read_findings
bounty_read_chain_attempts
bounty_read_verification_round
bounty_write_verification_round
bounty_read_http_audit
bounty_list_auth_profiles
bounty_http_scan
```

## Evidence, Grade, Report Tools

Evidence:

```text
bounty_read_findings
bounty_read_verification_round
bounty_read_http_audit
bounty_list_auth_profiles
bounty_http_scan
bounty_write_evidence_packs
bounty_read_evidence_packs
```

Grade:

```text
bounty_read_findings
bounty_read_chain_attempts
bounty_read_verification_round
bounty_read_evidence_packs
bounty_write_grade_verdict
bounty_read_grade_verdict
```

Report:

```text
bounty_read_findings
bounty_read_chain_attempts
bounty_read_verification_round
bounty_read_evidence_packs
bounty_read_grade_verdict
```

\newpage

# Context Management In Detail

This is the central design idea in the repo.

## Context Is Not Shared By Default

The root orchestrator, evaluators, verifiers, chain builder, grader, and reporter
are separate agent runs. They do not automatically share all chat history.

Bob treats the chat transcript as unreliable for durable coordination. The
shared memory is MCP-owned artifacts.

## The Root Orchestrator Gets Summaries

The root orchestrator usually calls:

```text
bounty_read_state_summary
bounty_wave_status
bounty_read_pipeline_analytics
```

These are compact. They avoid loading full arrays unless needed.

## Evaluators Get One Curated Brief

Evaluator first action:

```text
bounty_read_assignment_brief({
  target_domain: "...",
  wave: "w1",
  agent: "a1"
})
```

The returned brief includes one assigned surface and bounded summaries.

File:

```text
mcp/lib/assignment-brief.js
```

Key context controls in that file:

- caps scalar strings
- caps arrays
- reports omitted counts
- includes only the assigned surface
- filters dead ends by relevant hosts
- summarizes coverage by latest endpoint/method/bug/auth key
- summarizes traffic relevant to the surface
- summarizes HTTP audit and circuit breaker state
- adds public intel and static scan hints when available
- gives auth guidance without exposing secrets
- includes curated technique hints from `.claude/knowledge/evaluator-techniques.json`

This is how Bob avoids pasting the whole session into every evaluator.

## Verification Reads Structured Artifacts

Verifiers do not trust `findings.md`. They read:

```text
bounty_read_findings
bounty_read_chain_attempts
bounty_read_verification_round
bounty_read_http_audit
```

Each verification round writes a full JSON result set. Balanced and final
rounds must include every finding from the prior round so findings are not
silently dropped.

Code:

```text
mcp/lib/findings.js
writeVerificationRound()
requirePriorVerificationRound()
```

## Evidence Is Separate From Findings

Evaluators record claims in `findings.jsonl`. Final verification decides which
claims are reportable. The evidence agent then collects bounded, redacted
samples in `evidence-packs.json`.

This separation matters because raw PoC text is not enough for a trustworthy
report. The evidence pack is the structured proof layer used by grading and
report writing.

## Analytics Summarizes The Whole Pipeline

File:

```text
mcp/lib/pipeline-analytics.js
```

It reads artifacts and telemetry to answer:

- what phase is this session in?
- is a wave pending?
- are handoffs missing?
- did evaluators get blocked?
- did tools fail often?
- did final verification drop all findings?
- are evidence packs missing?
- is grade/report present?
- did network reachability or egress look bad?

This powers `/bob-status` and `/bob-debug`.

\newpage

# Agent Architecture

Each agent is narrow on purpose.

## Root Orchestrator

File:

```text
.claude/skills/bob-evaluate/SKILL.md
```

Responsibilities:

- parse command arguments and flags
- initialize or resume session
- transition phases
- spawn agents
- start and merge waves
- validate artifacts before proceeding
- choose next command or stop point

Not responsible for:

- ad-hoc target testing
- writing MCP-owned files directly
- synthesizing evaluator handoff JSON
- repairing missing structured artifacts from Markdown

## Surface-discovery Agent

File:

```text
.claude/agents/surface-discovery-agent.md
```

It uses Bash only. It is intentionally MCP-free.

It has exactly seven collection Bash steps:

1. tool check
2. subdomain enum
3. live hosts
4. family discovery
5. CDX archived URLs
6. nuclei
7. JavaScript extraction

Then it writes:

```text
attack_surface.json
```

This is one of the few agent-owned direct writes allowed in the session dir.

## Evaluator Agent

File:

```text
.claude/agents/evaluator-agent.md
```

Responsibilities:

- read assigned brief
- test one surface only
- use auth profiles when available
- prefer traffic-derived endpoints
- call `bounty_http_scan` for audited requests
- log meaningful coverage
- record only proven findings
- write exactly one wave handoff
- emit exactly one final marker

Important constraints:

- no `Write` tool
- do not directly write MCP-owned files
- do not scan arbitrary local static paths
- do not record weak standalone non-findings
- stop and request egress rotation after repeated first-party network failures

## Chain Builder

File:

```text
.claude/agents/chain-builder.md
```

It reads structured findings, handoffs, audit records, auth profiles, and prior
chain attempts. It writes every tested hypothesis to:

```text
chain-attempts.jsonl
```

It must not use Markdown handoffs as machine input.

## Three Verifiers

Files:

```text
.claude/agents/brutalist-verifier.md
.claude/agents/balanced-verifier.md
.claude/agents/final-verifier.md
```

Round 1: brutalist

- skeptical replay
- deny weak claims
- downgrade inflated severity

Round 2: balanced

- catch false negatives
- review brutalist decisions
- include every prior finding

Round 3: final

- re-run only reportable survivors with fresh requests
- include every prior finding
- final `reportable: true` results drive evidence collection

## Evidence Agent

File:

```text
.claude/agents/evidence-agent.md
```

Collects bounded, redacted evidence packs for final reportable findings only.
It writes:

```text
evidence-packs.json
```

## Grader

File:

```text
.claude/agents/grader.md
```

Scores final survivors on:

- impact
- proof quality
- severity accuracy
- chain potential
- report quality

Verdicts:

```text
SUBMIT
HOLD
SKIP
```

## Report Writer

File:

```text
.claude/agents/report-writer.md
```

Writes:

```text
report.md
```

It reads final verification, evidence packs, chain attempts, and grade. It
should include only verified, evidenced, graded findings.

\newpage

# Wave Lifecycle

Waves are the core EVALUATE-phase coordination mechanism.

## Start A Wave

The orchestrator computes assignments and calls:

```text
bounty_start_wave({
  target_domain: "example.com",
  wave_number: 1,
  assignments: [
    { "agent": "a1", "surface_id": "api-main" },
    { "agent": "a2", "surface_id": "auth-flow" }
  ]
})
```

Code:

```text
mcp/lib/waves.js
startWave()
```

Effects:

- validates phase is `EVALUATE` or `EXPLORE`
- validates no `pending_wave`
- validates wave number is `evaluation_wave + 1`
- validates surface IDs exist in `attack_surface.json`
- generates a secret handoff token for each assignment
- writes `wave-N-assignments.json` with token hashes
- creates the session-local `.handoff-signing-key.json` with `0600` permissions
- returns plain handoff tokens to the orchestrator
- sets `state.pending_wave = N`

The token is given only to the assigned evaluator. The token prevents another
agent from writing through `bounty_write_wave_handoff` for a different
assignment. After token validation, Bob signs the persisted JSON with the
session-local `.handoff-signing-key.json` key so read and merge paths can reject
later hand-edited JSON for tokenized assignments.

## Spawn Background Evaluators

The orchestrator spawns one `evaluator-agent` per assignment with:

```text
run_in_background: true
```

Each evaluator prompt includes:

- domain
- wave
- agent ID
- assigned handoff token
- egress profile
- first action: call `bounty_read_assignment_brief`
- final action: call `bounty_write_wave_handoff`
- final marker: `BOB_AGENT_RUN_DONE {...}`

## Evaluator Writes Handoff

Example simplified handoff:

```json
{
  "target_domain": "example.com",
  "wave": "w1",
  "agent": "a2",
  "surface_id": "auth-flow",
  "surface_status": "partial",
  "provenance": "verified",
  "provenance_model": "session_file_hmac_v1",
  "provenance_assignment_hash": "...",
  "provenance_signature": {
    "version": 1,
    "algorithm": "hmac-sha256",
    "digest": "..."
  },
  "summary": "Tested signup, reset, invite, and OAuth callback flows.",
  "chain_notes": [
    "Password reset token leak may combine with weak session rotation."
  ],
  "dead_ends": [
    "/logout is static redirect only"
  ],
  "waf_blocked_endpoints": [],
  "lead_surface_ids": [
    "billing-api"
  ]
}
```

Code:

```text
mcp/lib/waves.js
writeWaveHandoff()
```

## SubagentStop Hook Validates Completion

File:

```text
.claude/hooks/agent-run-stop.js
```

When a evaluator stops, the hook checks:

- did the final assistant message include `BOB_AGENT_RUN_DONE`?
- is the marker valid JSON?
- does the marker include target, wave, agent, surface?
- does a structured handoff JSON exist?
- does the handoff match the marker?
- is the handoff provenance verified?

If validation fails, the hook blocks the subagent stop.

Important: the hook does not merge waves. It only validates completion and
records telemetry.

## Merge A Wave

After background evaluators finish, the orchestrator calls:

```text
bounty_apply_wave_merge({
  target_domain: "example.com",
  wave_number: 1,
  force_merge: false
})
```

Code:

```text
mcp/lib/waves.js
applyWaveMerge()
```

Effects:

- reads assignments
- checks handoff readiness
- validates handoff payloads
- computes completed and partial surfaces
- includes live dead-end logs
- computes requeue surface IDs
- updates `explored`
- updates `dead_ends`
- updates `waf_blocked_endpoints`
- updates `lead_surface_ids`
- clears `pending_wave`
- sets `evaluation_wave`
- updates `total_findings`
- appends a pipeline event

If not all handoffs are present and `force_merge` is false, it returns:

```json
{
  "status": "pending"
}
```

and does not mutate session state.

\newpage

# How Findings Flow Through The Pipeline

## 1. Evaluator Records A Finding

Tool:

```text
bounty_record_finding
```

Code:

```text
mcp/lib/findings.js
recordFinding()
```

Simplified record:

```json
{
  "id": "F-1",
  "target_domain": "example.com",
  "title": "IDOR in invoice export exposes victim invoices",
  "severity": "high",
  "cwe": "CWE-639",
  "endpoint": "https://app.example.com/api/invoices/export?id=123",
  "description": "The endpoint accepts arbitrary invoice IDs.",
  "proof_of_concept": "curl ...",
  "response_evidence": "200 response includes victim invoice metadata",
  "impact": "Attacker can read billing data for other accounts.",
  "validated": true,
  "wave": "w1",
  "agent": "a2",
  "surface_id": "billing-api",
  "auth_profile": "attacker",
  "dedupe_key": "..."
}
```

`recordFinding()` also computes a dedupe key from endpoint, title/classification,
auth context, and evidence fingerprint. Exact duplicates are not recorded unless
`force_record` is true.

## 2. Chain Builder Tests Combinations

Tool:

```text
bounty_write_chain_attempt
```

Code:

```text
mcp/lib/chain-attempts.js
```

Simplified record:

```json
{
  "version": 1,
  "ts": "2026-05-01T00:00:00.000Z",
  "attempt_id": "C-1",
  "target_domain": "example.com",
  "finding_ids": ["F-1", "F-2"],
  "surface_ids": ["billing-api", "auth-flow"],
  "hypothesis": "Invite leak plus IDOR could expose invoices without victim action.",
  "steps": [
    "Used attacker profile to replay leaked invite context.",
    "Requested victim invoice ID through export endpoint."
  ],
  "outcome": "denied",
  "evidence_summary": "Export endpoint still required invoice ownership.",
  "request_refs": ["http-audit:42"],
  "auth_profiles": ["attacker", "victim"]
}
```

## 3. Verification Rounds Decide Survivors

Each verification result has:

```json
{
  "finding_id": "F-1",
  "disposition": "confirmed",
  "severity": "high",
  "reportable": true,
  "reasoning": "Fresh replay returned victim invoice metadata."
}
```

The final round decides which findings require evidence.

## 4. Evidence Agent Collects Bounded Proof

Tool:

```text
bounty_write_evidence_packs
```

Simplified pack:

```json
{
  "finding_id": "F-1",
  "sample_type": "cross-account invoice access",
  "sample_count": 3,
  "aggregate_counts": {
    "affected_accounts_sampled": 3,
    "private_fields_observed": 5
  },
  "representative_samples": [
    {
      "request_ref": "http-audit:42",
      "endpoint": "/api/invoices/export",
      "auth_profile": "attacker",
      "status": 200,
      "observed_fields": ["account_id", "email", "invoice_total"],
      "redacted_object_id": "inv_...789"
    }
  ],
  "sensitive_clusters": ["invoice metadata"],
  "replay_summary": "Attacker replay returned private invoice metadata.",
  "redaction_notes": "IDs and personal values redacted.",
  "report_snippet": "An attacker can enumerate invoice exports and receive private billing metadata."
}
```

Evidence validation rejects secrets, auth headers, cookies, tokens, huge raw
responses, duplicate packs, packs for non-reportable findings, and missing
packs for final reportable findings.

## 5. Grader Produces A Verdict

Simplified grade:

```json
{
  "version": 1,
  "target_domain": "example.com",
  "verdict": "SUBMIT",
  "total_score": 72,
  "findings": [
    {
      "finding_id": "F-1",
      "impact": 25,
      "proof_quality": 20,
      "severity_accuracy": 12,
      "chain_potential": 5,
      "report_quality": 10,
      "total_score": 72,
      "feedback": null
    }
  ],
  "feedback": null
}
```

Code enforces:

- per-finding total equals sum of rubric scores
- grade `total_score` equals the max per-finding score
- verdict matches thresholds and final reportability
- evidence packs are valid before grade write/read succeeds

\newpage

# HTTP, Auth, Egress, And Audit

## HTTP Scan

Tool:

```text
bounty_http_scan
```

Code:

```text
mcp/lib/http-scan.js
mcp/lib/safe-fetch.js
mcp/lib/url-surface.js
mcp/lib/http-records.js
```

Responsibilities:

- require `target_domain`
- resolve egress profile
- optionally attach auth profile headers
- apply the session's effective internal-host policy, optionally blocking internal/private hosts on direct egress
- send request through safe fetch
- cap response bytes
- analyze response for tech, endpoints, secrets, security hints
- append redacted audit record to `http-audit.jsonl`

Important design choice:

For session-bound tools, caller `target_domain` is only a session lookup key.
The dispatcher authorizes against initialized session state, validates the raw
stored `target` and `target_url`, and rejects drift before the handler runs.
Legacy sessions may default progress or presentation fields, but missing or
drifted authority fields fail closed for tools that rely on them.

Bob's MCP-scoped HTTP tools require a public `target_domain` and only send
first-party target-host requests after session authority passes. That policy
blocks direct off-target URLs before the request is sent, rejects
public-suffix-only scope tokens with the packaged Public Suffix List via `psl`,
and isolates registrable tenant domains.
If that packaged list is stale, set `BOB_PSL_OVERLAY_FILE` to a local suffix
file before running Bob; overlay matches are recorded in HTTP audit rows with
`public_suffix_source` and `psl_overlay_file`, and the overlay is not a
per-request bypass.
It still does not make first-party host scope into DNS-rebinding protection or
SSRF protection. `normal`, `yolo`, and pre-policy legacy sessions allow a public
first-party hostname that resolves to private infrastructure. `paranoid`
sessions default to local DNS/private-address blocking on direct/default egress
unless the operator starts an explicitly authorized internal/lab program with
`--allow-internal-hosts`. A caller can force blocking outside paranoid mode with:

```json
{
  "block_internal_hosts": true
}
```

Strict internal-host blocking is a direct-egress policy. Bob refuses
effective `block_internal_hosts: true` with proxy-backed egress profiles because
target DNS and routing may be resolved by the proxy outside Bob's process. The
effective value is persisted in session state, evaluator briefs, HTTP audit rows,
pipeline events, and analytics.

## Auth Storage

Tool:

```text
bounty_auth_store
```

Code:

```text
mcp/lib/auth.js
```

Auth profiles are stored in:

```text
~/bounty-agent-sessions/[domain]/auth.json
```

The file is written with mode `0600`. Profiles can be named:

```text
attacker
victim
legacy
custom names
```

Agents do not read `auth.json` directly. They call:

```text
bounty_list_auth_profiles
```

for redacted summaries and use:

```text
auth_profile: "attacker"
```

in `bounty_http_scan` calls.

## Egress Profiles

Code:

```text
mcp/lib/egress-profiles.js
.claude/hooks/bob-egress.js
.claude/commands/bob-egress.md
```

Config:

```text
.claude/bob/egress-profiles.json
```

Default profile:

```json
{
  "name": "default",
  "proxy_url": null,
  "region": null,
  "description": "Direct connection from this machine.",
  "enabled": true
}
```

Non-default profiles can use environment variable references:

```json
{
  "name": "gr-residential",
  "proxy_url": "${BOB_EGRESS_GR_RESIDENTIAL_PROXY}",
  "region": "GR",
  "enabled": false
}
```

Proxy URLs are redacted and should not be printed into chat.

## Geofence Warnings

HTTP audit summaries detect repeated first-party timeouts or connection errors.
When a host repeatedly fails, Bob treats it as a reachability warning. The
orchestrator should ask the operator before switching egress profiles.

\newpage

# Hooks And Guardrails

## Session Write Guard

File:

```text
.claude/hooks/session-write-guard.sh
```

Registered for:

```text
Bash
Write
```

It blocks direct writes to MCP-owned files under:

```text
~/bounty-agent-sessions/
```

Examples of blocked files:

```text
state.json
findings.jsonl
coverage.jsonl
http-audit.jsonl
traffic.jsonl
chain-attempts.jsonl
brutalist.json
balanced.json
verified-final.json
evidence-packs.json
grade.json
pipeline-events.jsonl
handoff-w1-a1.json
```

Examples of allowed agent-owned files:

```text
attack_surface.json
report.md
chains.md
*.txt
```

The hook catches:

- Write tool writes
- Bash redirects
- `tee`
- inline Python `open(..., "w")`
- `Path(...).write_text(...)`
- common inline script write patterns

## Evaluator Stop Hook

File:

```text
.claude/hooks/agent-run-stop.js
```

Registered for:

```text
SubagentStop: evaluator-agent
```

It blocks evaluators from finishing unless their final marker and structured
handoff are valid.

It also records metadata-only evaluator run telemetry.

## No Shell Scope Guard

Bob no longer installs a shell or MCP scope-guard hook. The previous hook files
were intentionally permissive compatibility shims, so keeping them registered
overstated the enforcement model.

MCP-scoped HTTP tool policy is enforced in the runtime dispatcher and handlers.
Those tools require first-party target-host URLs, and they can add local
DNS/private-address blocking only when the caller passes
effective `block_internal_hosts: true` on direct egress. Browser-based auto-signup routes
page HTTP requests through a target-host guard, blocks service workers, and
blocks WebSockets when the host browser API supports it, but it refuses
effective `block_internal_hosts: true` because Chromium resolves destinations outside
Bob's safeFetch transport. Raw shell surface-discovery commands such as `curl`, `httpx`,
`katana`, `nuclei`, and passive intel collection are bounded by generated
prompts, host permissions, and operator authorization, not by Bob-enforced
network containment.

This boundary is documented and tested, not accidental.

\newpage

# Pipeline Analytics And Debugging

Bob records two major diagnostic streams.

## Pipeline Events

File:

```text
~/bounty-agent-sessions/[domain]/pipeline-events.jsonl
```

Event types:

```text
session_started
phase_transitioned
wave_started
evaluator_stopped
wave_merge_pending
wave_merged
coverage_logged
finding_recorded
verification_written
evidence_written
grade_written
```

Example:

```json
{
  "version": 1,
  "ts": "2026-05-01T00:00:00.000Z",
  "target_domain": "example.com",
  "type": "wave_merged",
  "phase": "EVALUATE",
  "wave_number": 1,
  "status": "merged",
  "source": "bounty_apply_wave_merge",
  "counts": {
    "assignments": 2,
    "handoffs": 2,
    "findings": 1
  }
}
```

## Tool Telemetry

File:

```text
~/bounty-agent-telemetry/tool-events.jsonl
~/bounty-agent-telemetry/agent-runs.jsonl
```

Code:

```text
mcp/lib/tool-telemetry.js
```

Telemetry is intentionally metadata-only:

- tool name
- ok/failure
- elapsed time
- error code
- target domain
- wave/agent/surface context
- registry metadata
- authority decision metadata: version, class, mode, source, result, symbolic
  error code, and shadow status

It avoids storing raw secret-bearing payloads, raw tool arguments, raw session
state, session paths, scoped URLs, target URLs, and egress credentials.
Read summaries redact local telemetry and transcript paths to stable labels.
`bounty_read_tool_telemetry` aggregates authority status by version, class,
result, and symbolic error code so blocked authority paths are visible without
exposing the state document.

## Pipeline Analytics Reader

Tool:

```text
bounty_read_pipeline_analytics
```

Code:

```text
mcp/lib/pipeline-analytics.js
```

It can read one session or recent sessions and summarize:

- phase
- waves
- pending handoffs
- findings
- chain attempts
- final verification count
- evidence status
- egress/geofence warnings
- grade
- report presence
- health status
- bottlenecks
- next actions
- tool health
- evaluator health

This is the core behind `/bob-status` and `/bob-debug`.

\newpage

# How To Read The Repo Step By Step

This is the recommended offline reading order.

## Step 1: Read The Product Contract

Open:

```text
README.md
CLAUDE.md
CONTRIBUTING.md
docs/FIRST_RUN.md
docs/TROUBLESHOOTING.md
```

Questions to answer:

- What does Bob install?
- What does the user run?
- Where does run state live?
- What is `bountyagent`?
- What is the difference between `hacker-bob-cc` and `hacker-bob`?

## Step 2: Understand Install And Lifecycle

Open:

```text
bin/hacker-bob.js
install.sh
scripts/install.js
scripts/merge-claude-config.js
scripts/lifecycle.js
mcp/lib/claude-config.js
```

Trace:

```text
hacker-bob install /target
  -> scripts/install.js installProject()
  -> copy .claude agents/skills/hooks/rules/knowledge
  -> copy mcp runtime
  -> merge .mcp.json
  -> merge .claude/settings.json
  -> write .claude/bob/VERSION and install.json
```

Questions to answer:

- Which files are copied?
- Which config is merged instead of overwritten?
- How are hooks registered?
- How does uninstall know what is Bob-managed?

## Step 3: Read The Orchestrator Prompt

Open:

```text
.claude/skills/bob-evaluate/SKILL.md
```

Do not skim too quickly. This file is the operational spec.

Mark these sections:

- Flags
- Hard Rules
- FSM
- Resume
- SURFACE_DISCOVERY
- AUTH
- EVALUATE
- CHAIN
- VERIFY
- GRADE
- REPORT
- EXPLORE

Questions to answer:

- Why does the root orchestrator avoid target testing?
- Why are evaluator waves backgrounded?
- Why is same-turn wave merge forbidden after spawn?
- What artifacts are validated before moving phases?
- What happens after `HOLD`?

## Step 4: Read The Agent Prompts

Open in this order:

```text
.claude/agents/surface-discovery-agent.md
.claude/agents/evaluator-agent.md
.claude/agents/chain-builder.md
.claude/agents/brutalist-verifier.md
.claude/agents/balanced-verifier.md
.claude/agents/final-verifier.md
.claude/agents/evidence-agent.md
.claude/agents/grader.md
.claude/agents/report-writer.md
```

For each agent, write down:

- What can it read?
- What can it write?
- Which MCP tools does it use?
- What must its final action be?
- Which artifact does it own?

## Step 5: Read MCP From Entry Point To Tool Handler

Open:

```text
mcp/server.js
mcp/lib/transport.js
mcp/lib/tool-registry.js
mcp/lib/dispatch.js
mcp/lib/envelope.js
mcp/lib/tool-validation.js
mcp/lib/tools/index.js
```

Trace one tool call:

```text
MCP tools/call
  -> transport handleMessage()
  -> executeTool(name, args)
  -> validateToolArguments()
  -> tool.handler(args)
  -> parseHandlerResult()
  -> okEnvelope() or errorEnvelope()
  -> safeRecordToolTelemetry()
```

Questions to answer:

- Where are tool schemas defined?
- Where are unknown arguments rejected?
- Where are errors classified?
- How does telemetry avoid changing tool behavior?

## Step 6: Read Session State And Storage

Open:

```text
mcp/lib/paths.js
mcp/lib/storage.js
mcp/lib/session-state.js
mcp/lib/phase-gates.js
```

Questions to answer:

- How does `target_domain` become a safe path?
- What is the session lock?
- Which transitions are allowed?
- Which transitions have gates?
- What happens when a lock is stale?

## Step 7: Read Waves And Evaluator Context

Open:

```text
mcp/lib/assignments.js
mcp/lib/waves.js
mcp/lib/assignment-brief.js
mcp/lib/coverage.js
mcp/lib/ranking.js
```

Trace:

```text
bounty_start_wave
  -> write wave assignment with token hash
  -> return plain token to orchestrator

evaluator
  -> bounty_read_assignment_brief
  -> bounty_log_coverage
  -> bounty_write_wave_handoff

bounty_apply_wave_merge
  -> validate handoffs
  -> update state
```

Questions to answer:

- Why are handoff tokens hashed on disk?
- What makes a handoff valid?
- How does a partial handoff get requeued?
- How does coverage create requeue surface IDs?
- How is evaluator context capped?

## Step 8: Read Findings, Chain, Verification, Evidence, Grade

Open:

```text
mcp/lib/findings.js
mcp/lib/chain-attempts.js
mcp/lib/evidence.js
```

Questions to answer:

- How are duplicate findings suppressed?
- Why must balanced/final rounds include all prior findings?
- What makes evidence valid?
- How does grade consistency get enforced?
- Why can no-finding sessions still continue to SKIP and report?

## Step 9: Read HTTP, Auth, Egress, Redaction

Open:

```text
mcp/lib/http-scan.js
mcp/lib/safe-fetch.js
mcp/lib/url-surface.js
mcp/lib/http-records.js
mcp/lib/auth.js
mcp/lib/signup.js
mcp/lib/temp-email.js
mcp/lib/egress-profiles.js
mcp/redaction.js
```

Questions to answer:

- Why does `bounty_http_scan` require `target_domain`?
- What gets written to `http-audit.jsonl`?
- Where are proxy URLs redacted?
- How are auth profiles resolved?
- When are internal hosts blocked?

## Step 10: Read Hooks And Tests

Open:

```text
.claude/hooks/session-write-guard.sh
.claude/hooks/agent-run-stop.js
test/test-write-guard.py
test/prompt-contracts.test.js
test/mcp-server.test.js
test/install-smoke.test.js
test/cli.test.js
```

Questions to answer:

- Which behaviors are contractual?
- Which prompt phrases are tests protecting?
- Which state machine gates have test coverage?
- Which security boundaries are tested?

\newpage

# Useful Offline Commands

Run from the repo root.

## List Files

```bash
rg --files
```

## Find Tool Definitions

```bash
rg "name: \"bounty_" mcp/lib/tools
```

## See Tool Registry Summary

```bash
node - <<'NODE'
const { TOOL_REGISTRY } = require('./mcp/lib/tool-registry.js');
for (const t of TOOL_REGISTRY) {
  console.log(`${t.name} roles=${t.role_bundles.join(',')} writes=${t.session_artifacts_written.join(',') || '-'}`);
}
NODE
```

## Run Focused Tests

```bash
npm run test:mcp
npm run test:prompts
npm run test:install
npm run test:cli
npm run test:hooks
```

## Run Full Test Suite

```bash
npm test
```

## Check Generated Prompt Surfaces

```bash
node scripts/generate-agent-tools.js --check
node scripts/generate-bountyagent-skill.js --check
```

## Inspect Installed-Style MCP Server

```bash
node -e "const s=require('./mcp/server.js'); console.log(s.TOOLS.length)"
```

## Search For Artifact Ownership Rules

```bash
rg "MCP-owned|handoff|evidence-packs|pending_wave|phase" .claude mcp test
```

\newpage

# Suggested Flight Reading Plan

## 30 Minutes: Product Shape

Read:

```text
README.md
CLAUDE.md
docs/FIRST_RUN.md
```

Goal: understand what Bob is from the user's point of view.

## 45 Minutes: Orchestrator And Agents

Read:

```text
.claude/skills/bob-evaluate/SKILL.md
.claude/agents/*.md
```

Goal: understand the role contract for each agent.

## 60 Minutes: MCP Core

Read:

```text
mcp/server.js
mcp/lib/transport.js
mcp/lib/tool-registry.js
mcp/lib/dispatch.js
mcp/lib/envelope.js
mcp/lib/tools/index.js
```

Goal: understand how Claude Code calls become validated local functions.

## 90 Minutes: State, Waves, Context

Read:

```text
mcp/lib/session-state.js
mcp/lib/phase-gates.js
mcp/lib/waves.js
mcp/lib/assignment-brief.js
mcp/lib/coverage.js
```

Goal: understand how Bob manages many agents without relying on chat memory.

## 60 Minutes: Findings To Report

Read:

```text
mcp/lib/findings.js
mcp/lib/chain-attempts.js
mcp/lib/evidence.js
```

Goal: understand how a raw evaluator claim becomes a trusted final report.

## 45 Minutes: Safety And Diagnostics

Read:

```text
.claude/hooks/*.js
.claude/hooks/*.sh
mcp/lib/pipeline-analytics.js
mcp/lib/tool-telemetry.js
```

Goal: understand how Bob catches drift, missing artifacts, and stuck sessions.

## 45 Minutes: Tests As Documentation

Read test names first:

```bash
rg "^(test|describe)\\(" test testing -n
```

Then inspect the tests that match the parts you still find confusing.

\newpage

# Annotated Golden Run

This chapter follows one fictional run for `example.test`. It is not a live
target transcript. It is a deliberately clean path through the system so you can
keep the moving parts in your head while reading the code.

Use this as the reference story:

```text
/bob-evaluate https://example.test --normal --egress default
```

The whole run is an artifact pipeline:

```text
skill prompt
  -> MCP session state
  -> surface-discovery artifact
  -> auth artifact
  -> wave assignments
  -> evaluator briefs
  -> HTTP audit, coverage, findings, handoffs
  -> wave merge
  -> chain attempts
  -> three verification rounds
  -> evidence packs
  -> grade
  -> report
```

If you only remember one thing, remember this: the chat is not the database.
The session directory is the database, and MCP tools are the write API.

## Step 0: Claude Code Loads The Control Surface

The operator types `/bob-evaluate`. Claude Code loads:

```text
.claude/skills/bob-evaluate/SKILL.md
```

That skill is the root orchestrator contract. It says:

- which MCP tools the root may call
- which agents the root may spawn
- which phases are legal
- when waves can start and merge
- which artifacts are authoritative
- what the root must never do itself

Important detail: the root orchestrator has `Task`, `Read`, and selected MCP
tools. It is intentionally not a evaluator. It coordinates the state machine.

## Step 1: Session Initialization

First meaningful write:

```text
bounty_init_session({
  target_domain: "example.test",
  target_url: "https://example.test",
  egress_profile: "default"
})
```

Session initialization binds the selected egress profile identity in `state.json`.
Bob records `egress_profile_identity_hash` and redacted source metadata, not raw
proxy credentials. Later egress-bound requests compare against that hash; changing
the profile or proxy route fails closed, while credential rotation on the same
route does not. Egress-bound HTTP and signup calls require initialized session
state. Pre-identity legacy sessions are bound on their first egress-bound resume
and record `egress_profile_identity_bind_source: "legacy_migration"` plus the
previous unbound egress fields.

Code path:

```text
mcp/lib/tools/init-session.js
  -> mcp/lib/session-state.js
  -> mcp/lib/storage.js
  -> mcp/lib/pipeline-analytics.js
```

Artifact written:

```text
~/bounty-agent-sessions/example.test/state.json
```

Simplified state:

```json
{
  "target": "example.test",
  "target_url": "https://example.test",
  "phase": "SURFACE_DISCOVERY",
  "evaluation_wave": 0,
  "pending_wave": null,
  "total_findings": 0,
  "explored": [],
  "dead_ends": [],
  "waf_blocked_endpoints": [],
  "lead_surface_ids": [],
  "scope_exclusions": [],
  "hold_count": 0,
  "auth_status": "pending"
}
```

Pipeline event appended:

```text
pipeline-events.jsonl
event_type = session_started
source = bounty_init_session
```

The event log is not the state itself. It is the audit trail that explains how
the state changed over time.

## Step 2: Surface-discovery Agent Produces The Attack Surface

The root spawns:

```text
Agent(subagent_type: "surface-discovery-agent", name: "surface-discovery", prompt: "DOMAIN=example.test SESSION=...")
```

Agent contract:

```text
.claude/agents/surface-discovery-agent.md
```

The surface-discovery agent is unusual because it uses Bash and writes one authoritative
agent-owned artifact directly:

```text
attack_surface.json
```

It also creates surface-discovery scratch files such as:

```text
subdomains.txt
live_hosts.txt
family_live.txt
all_urls.txt
nuclei_results.txt
js_endpoints.txt
js_secrets.txt
```

Those scratch files help build the final attack surface, but later orchestration
mostly cares about `attack_surface.json`.

After surface-discovery, the root reads `attack_surface.json`. If it is missing or empty,
the run stops. If it contains surfaces, the root transitions:

```text
bounty_transition_phase({
  target_domain: "example.test",
  to_phase: "AUTH"
})
```

State change:

```text
SURFACE_DISCOVERY -> AUTH
```

## Step 3: Auth Either Stores Profiles Or Marks The Run Unauthenticated

In normal mode, AUTH attempts signup/login capture. The root may use:

```text
bounty_signup_detect
bounty_temp_email
bounty_http_scan
bounty_auto_signup
bounty_auth_store
bounty_list_auth_profiles
```

The durable output is:

```text
auth.json
```

Typical profiles:

```text
attacker
victim
legacy
```

The important design point is that agents should not need raw secrets in their
prompt context. They ask MCP for profile summaries and pass `auth_profile` into
`bounty_http_scan`. The HTTP layer applies stored auth material.

If the operator used `--no-auth`, the root does not try signup. It transitions:

```text
bounty_transition_phase({
  target_domain: "example.test",
  to_phase: "EVALUATE",
  auth_status: "unauthenticated"
})
```

Otherwise successful auth transitions with:

```text
auth_status: "authenticated"
```

## Step 4: The Root Starts A Evaluation Wave

Before every wave, the root reads compact state and attack surface context:

```text
bounty_read_state_summary
bounty_wave_status
Read attack_surface.json
```

It computes assignments. A simple wave 1 might be:

```json
[
  { "agent": "a1", "surface_id": "api-main" },
  { "agent": "a2", "surface_id": "auth-flow" },
  { "agent": "a3", "surface_id": "billing-api" }
]
```

Then the root calls:

```text
bounty_start_wave({
  target_domain: "example.test",
  wave_number: 1,
  assignments: [...]
})
```

Code path:

```text
mcp/lib/tools/start-wave.js
  -> mcp/lib/waves.js
```

Artifacts written:

```text
wave-1-assignments.json
state.json
pipeline-events.jsonl
```

Important `state.json` mutation:

```json
{
  "evaluation_wave": 0,
  "pending_wave": 1
}
```

Important `wave-1-assignments.json` detail:

```json
{
  "wave_number": 1,
  "assignments": [
    {
      "agent": "a1",
      "surface_id": "api-main",
      "handoff_token_required": true,
      "handoff_token_sha256": "..."
    }
  ]
}
```

The plaintext handoff token is returned only in the MCP response to
`bounty_start_wave`. It is not written to disk. The root injects each token into
only the matching evaluator prompt.

Why this matters:

- an agent cannot write another agent's authoritative handoff without the token
- read and merge paths can distinguish signed MCP-written handoffs from
  unsigned or tampered JSON for tokenized assignments
- the orchestrator does not have to trust Markdown claims

This is a session-file trust model, not remote cryptographic nonrepudiation. A
local actor with direct read access to `.handoff-signing-key.json` can forge a
signature; Bob's guarantee is that the key is not returned through MCP and raw
tokens are not persisted in assignment or handoff JSON.

## Step 5: Evaluators Run In Parallel

The root spawns one background `evaluator-agent` per assignment:

```text
evaluator-w1-a1 -> api-main
evaluator-w1-a2 -> auth-flow
evaluator-w1-a3 -> billing-api
```

The root must use background tasks for evaluator waves. It must also respect the
launch-turn barrier:

```text
start wave
spawn evaluators
report assignments
stop this turn
```

It must not start and merge the same wave in one turn. This prevents the root
from merging before background agents have had a fair chance to write handoffs.

## Step 6: Each Evaluator Loads One Curated Context Packet

The first action for a normal evaluator is:

```text
bounty_read_assignment_brief({
  target_domain: "example.test",
  wave: "w1",
  agent: "a2"
})
```

Code path:

```text
mcp/lib/tools/read-assignment-brief.js
  -> mcp/lib/assignment-brief.js
```

The brief contains only what that evaluator needs:

- its assigned surface
- valid surface IDs
- relevant traffic summary
- relevant HTTP audit summary
- coverage summary
- dead-end and WAF exclusions
- auth guidance
- ranking hints
- public intel hints
- static scan hints
- curated technique hints

This is the practical core of context management. The evaluator does not receive
the whole session. It receives one bounded packet.

## Step 7: Evaluator Activity Creates Structured Evidence Trails

During testing, the evaluator uses MCP tools instead of writing files:

```text
bounty_http_scan          -> http-audit.jsonl
bounty_log_coverage      -> coverage.jsonl
bounty_log_dead_ends     -> live-dead-ends-w1-a2.jsonl
bounty_record_finding    -> findings.jsonl and findings.md
```

If a evaluator proves a finding, it records it immediately:

```text
bounty_record_finding({
  target_domain: "example.test",
  wave: "w1",
  agent: "a2",
  surface_id: "billing-api",
  title: "IDOR in invoice export exposes victim invoice metadata",
  severity: "high",
  endpoint: "https://app.example.test/api/invoices/export?id=123",
  validated: true,
  ...
})
```

Code path:

```text
mcp/lib/tools/record-finding.js
  -> mcp/lib/findings.js
```

Artifacts:

```text
findings.jsonl
findings.md
pipeline-events.jsonl
```

`findings.jsonl` is authoritative. `findings.md` is a human/debug mirror.

## Step 8: Evaluator Completion Uses Two Signals

At the end of its assigned surface, each evaluator must call:

```text
bounty_write_wave_handoff({
  target_domain: "example.test",
  wave: "w1",
  agent: "a2",
  surface_id: "billing-api",
  surface_status: "complete",
  handoff_token: "...",
  summary: "...",
  chain_notes: [...],
  dead_ends: [...],
  lead_surface_ids: [...]
})
```

Artifacts:

```text
handoff-w1-a2.json
handoff-w1-a2.md
```

Then the final assistant message must include:

```text
BOB_AGENT_RUN_DONE {"target_domain":"example.test","wave":"w1","agent":"a2","surface_id":"billing-api"}
```

The hook checks the marker and the structured handoff:

```text
.claude/hooks/agent-run-stop.js
```

Why two signals exist:

- the MCP handoff is the durable state input
- the final marker helps Claude Code/hook lifecycle know the subagent ended
  correctly
- the hook prevents "I am done" prose from replacing structured completion

## Step 9: Resume Or Completion Merges The Wave

When all evaluators complete, or when the operator later runs resume, the root
settles the pending wave:

```text
bounty_read_state_summary({ target_domain: "example.test" })
```

If `pending_wave` is `1`, the root calls:

```text
bounty_apply_wave_merge({
  target_domain: "example.test",
  wave_number: 1,
  force_merge: false
})
```

Code path:

```text
mcp/lib/tools/apply-wave-merge.js
  -> mcp/lib/waves.js
```

If not all handoffs are present, MCP returns:

```json
{
  "status": "pending",
  "readiness": {
    "assignments_total": 3,
    "handoffs_total": 2,
    "missing_agents": ["a3"],
    "is_complete": false
  }
}
```

No state mutation happens in that case.

If ready, the merge updates:

```text
state.explored
state.dead_ends
state.waf_blocked_endpoints
state.lead_surface_ids
state.pending_wave
state.evaluation_wave
state.total_findings
```

Typical mutation:

```json
{
  "evaluation_wave": 1,
  "pending_wave": null,
  "total_findings": 1,
  "explored": ["api-main", "auth-flow", "billing-api"]
}
```

The merge also computes requeues from:

- partial handoffs
- missing handoffs
- invalid handoffs
- coverage entries with unfinished statuses

## Step 10: The Root Decides Another Wave Or CHAIN

The root calls:

```text
bounty_wave_status({ target_domain: "example.test" })
```

That status includes:

- finding counts
- coverage percentage
- unexplored high/critical surfaces
- open requeue surfaces
- HTTP audit health
- traffic import summary
- circuit breaker summary
- transition blockers

The EVALUATE -> CHAIN gate is enforced in:

```text
mcp/lib/phase-gates.js
```

The transition blocks if:

- `pending_wave` is still set
- `attack_surface.json` cannot be read
- coverage cannot be read
- high or critical surfaces remain unexplored
- latest coverage still has open promising, needs-auth, or requeue entries

If the gate passes:

```text
bounty_transition_phase({
  target_domain: "example.test",
  to_phase: "CHAIN"
})
```

## Step 11: Chain Builder Tests Combinations

The root spawns:

```text
Agent(subagent_type: "chain-builder", name: "chain", ...)
```

The chain builder reads:

```text
bounty_read_findings
bounty_read_wave_handoffs
bounty_read_http_audit
bounty_list_auth_profiles
bounty_read_chain_attempts
```

It writes:

```text
bounty_write_chain_attempt -> chain-attempts.jsonl
```

The CHAIN -> VERIFY gate blocks when a chain is required but no terminal chain
attempt exists. A chain is required when there are multiple findings or any
structured handoff includes `chain_notes`.

Terminal outcomes:

```text
confirmed
denied
blocked
not_applicable
```

Non-terminal:

```text
inconclusive
```

The point of this phase is not to make every finding worse. It is to eliminate
speculative chains and record whether a plausible chain actually worked.

## Step 12: Three Verifiers Protect Against Agent Overclaiming

After CHAIN, the root transitions:

```text
CHAIN -> VERIFY
```

Then it runs three verifier agents:

```text
brutalist-verifier -> brutalist.json
balanced-verifier  -> balanced.json
final-verifier     -> verified-final.json
```

Round behavior:

```text
brutalist: attack the claims hard
balanced: catch brutalist false negatives or over-downgrades
final: re-run only reportable survivors with fresh requests
```

Important invariant:

```text
balanced must include every brutalist finding
final must include every balanced finding
```

If a finding is omitted from a verifier result array, it is effectively lost.
That is why the prompts repeat the "include every prior finding" rule.

## Step 13: Evidence Packs Are Written After Final Verification

If final verification has reportable findings, the root spawns:

```text
Agent(subagent_type: "evidence-agent", name: "evidence", ...)
```

The evidence agent reads:

```text
bounty_read_findings
bounty_read_verification_round(round="final")
bounty_read_http_audit
bounty_list_auth_profiles
```

It writes:

```text
bounty_write_evidence_packs -> evidence-packs.json and evidence-packs.md
```

Evidence is intentionally late in the pipeline. This prevents agents from
collecting polished evidence for claims that did not survive verification.

The VERIFY -> GRADE gate validates evidence packs for final reportable
findings. If a reportable finding is missing evidence, the transition blocks.

If no final finding is reportable, evidence can be skipped in a structured way,
and the run still proceeds to GRADE and REPORT.

## Step 14: Grader Produces A Submit/Hold/Skip Decision

The root transitions:

```text
VERIFY -> GRADE
```

Then it spawns:

```text
Agent(subagent_type: "grader", name: "grader", ...)
```

The grader reads:

```text
bounty_read_findings
bounty_read_chain_attempts
bounty_read_verification_round(round="final")
bounty_read_evidence_packs
```

It writes:

```text
bounty_write_grade_verdict -> grade.json and grade.md
```

Verdicts:

```text
SUBMIT: score >= 40 and at least one medium-or-higher final reportable
HOLD:   score 20-39
SKIP:   score < 20 or no medium-or-higher final reportable
```

On `HOLD`, the FSM can go:

```text
GRADE -> EVALUATE
```

`state.hold_count` increments so Bob does not loop forever without escalation.

## Step 15: Report Writer Produces The Human Output

For `SUBMIT` or `SKIP`, the root transitions:

```text
GRADE -> REPORT
```

Then it spawns:

```text
Agent(subagent_type: "report-writer", name: "reporter", ...)
```

The report writer reads:

```text
bounty_read_findings
bounty_read_chain_attempts
bounty_read_verification_round(round="final")
bounty_read_evidence_packs
bounty_read_grade_verdict
```

It writes:

```text
report.md
```

`report.md` is the thing a human reads or adapts. It should be explainable from
the structured artifacts behind it. If `report.md` says something that
`verified-final.json`, `evidence-packs.json`, and `grade.json` do not support,
trust the JSON and debug the report writer.

## Golden Run Reading Checklist

When following this run in the code, read in this order:

```text
.claude/skills/bob-evaluate/SKILL.md
mcp/lib/session-state.js
.claude/agents/surface-discovery-agent.md
mcp/lib/waves.js
.claude/agents/evaluator-agent.md
mcp/lib/assignment-brief.js
mcp/lib/findings.js
mcp/lib/phase-gates.js
.claude/agents/chain-builder.md
.claude/agents/*verifier.md
mcp/lib/evidence.js
.claude/agents/grader.md
.claude/agents/report-writer.md
```

The goal is not to memorize every helper function. The goal is to see where
each state mutation is allowed to happen.

\newpage

# Deep Artifact Catalog

This is the map of "what file means what" in a session directory.

The default session root is:

```text
~/bounty-agent-sessions/[domain]/
```

Path construction lives in:

```text
mcp/lib/paths.js
```

## `state.json`

Owner:

```text
MCP only
```

Written by:

```text
bounty_init_session
bounty_transition_phase
bounty_start_wave
bounty_apply_wave_merge
```

Read by:

```text
bounty_read_session_state
bounty_read_state_summary
bounty_wave_status
bounty_read_pipeline_analytics
phase gates
```

Use it to answer:

- what phase is the session in?
- is a wave pending?
- how many waves were merged?
- what surfaces are explored?
- how many findings does the state think exist?
- did grading hold once or more?
- is auth pending, authenticated, or unauthenticated?

Trust level:

```text
authoritative for phase and coarse progress
```

Important caution:

`total_findings` is a summary copied into state during merges. The authoritative
finding records are still in `findings.jsonl`.

## `attack_surface.json`

Owner:

```text
surface-discovery-agent
```

Written by:

```text
.claude/agents/surface-discovery-agent.md
```

Read by:

```text
root orchestrator
bounty_start_wave
bounty_wave_status
bounty_read_assignment_brief
ranking and phase gate code
```

Use it to answer:

- what surfaces exist?
- what surface IDs can be assigned?
- which surfaces are high or critical?
- what evidence led surface-discovery to classify each surface?
- what high-value flows and bug-class hints should evaluators consider?

Trust level:

```text
authoritative for surface inventory
```

Important caution:

Runtime ranking should not rewrite this file. Ranking is computed from current
state, traffic, coverage, audit, public intel, and static hints.

## Surface-discovery Scratch Files

Examples:

```text
surface-discovery-tools.txt
subdomains.txt
live_hosts.txt
family_candidates.txt
family_live.txt
all_urls.txt
nuclei_results.txt
js_urls.txt
js_endpoints.txt
js_secrets.txt
```

Owner:

```text
surface-discovery-agent
```

Use them to answer:

- where did `attack_surface.json` come from?
- did a surface-discovery tool fail or return nothing?
- did JavaScript extraction produce useful endpoint hints?

Trust level:

```text
supporting evidence for surface-discovery, not the main orchestration API
```

## `auth.json`

Owner:

```text
MCP auth tools
```

Written by:

```text
bounty_auth_store
bounty_auto_signup
```

Read by:

```text
bounty_list_auth_profiles
bounty_http_scan
agents that need profile summaries
```

Use it to answer:

- which profiles exist?
- was signup automated, assisted, or manually stored?
- are attacker and victim profiles both available?

Trust level:

```text
authoritative for stored auth profiles
```

Important caution:

Do not paste raw auth material into prompts or reports. Agents should pass
`auth_profile` into `bounty_http_scan`.

## `traffic.jsonl`

Owner:

```text
MCP import tool
```

Written by:

```text
bounty_import_http_traffic
```

Read by:

```text
bounty_read_assignment_brief
bounty_wave_status
bounty_read_pipeline_analytics
```

Use it to answer:

- what real application routes were imported from Burp/HAR-style history?
- what authenticated routes should evaluators prioritize?
- did imported traffic cover the assigned surface?

Trust level:

```text
authoritative imported traffic summary source
```

Important caution:

It is JSONL because imported request histories can be large and append-like.

## `http-audit.jsonl`

Owner:

```text
bounty_http_scan
```

Read by:

```text
evaluators
chain builder
verifiers
evidence agent
analytics
wave status
```

Use it to answer:

- what did Bob actually request?
- which egress profile was used?
- which `egress_profile_identity_hash` was bound to the request?
- did target-owned hosts repeatedly timeout or fail?
- what request refs support evidence?
- did geofence warnings appear?

Trust level:

```text
authoritative metadata trail for Bob HTTP requests
```

Important caution:

It should be redacted and bounded. It is not a raw packet capture.
It records profile names, regions, proxy-configured status, and identity hashes,
but not proxy URLs or credentials.

## `wave-N-assignments.json`

Owner:

```text
bounty_start_wave
```

Read by:

```text
bounty_read_assignment_brief
bounty_write_wave_handoff
bounty_wave_handoff_status
bounty_apply_wave_merge
```

Use it to answer:

- which agent owned which surface?
- what wave number was active?
- were handoff tokens required?

Trust level:

```text
authoritative wave assignment record
```

Important caution:

It stores token hashes and `handoff_token_required: true`, not plaintext tokens.
The separate `.handoff-signing-key.json` file stores the session-local signing
key and is created with `0600` permissions when the wave is started.

## `handoff-wN-aN.json`

Owner:

```text
bounty_write_wave_handoff
```

Read by:

```text
bounty_read_wave_handoffs
bounty_wave_handoff_status (presence only)
bounty_apply_wave_merge
chain builder
phase gates for chain-note detection
SubagentStop hook validation
```

Use it to answer:

- did the evaluator finish?
- was the surface complete or partial?
- what should be requeued?
- what dead ends and WAF blocks were discovered?
- what chain notes should the chain builder consider?
- was the handoff token verified?
- does tokenized provenance have a valid session-file signature?

Use `bounty_read_wave_handoffs` or merge output for provenance validation.
`bounty_wave_handoff_status` answers only whether structured JSON files are
present for assigned agents.

Trust level:

```text
authoritative evaluator completion record
```

Important caution:

`provenance: "verified"` is accepted only when the handoff carries
`provenance_model: "session_file_hmac_v1"` and a valid HMAC signature over the
JSON payload. Assignments without token hashes are rejected; unsigned verified
claims are invalid for every wave handoff.

Markdown handoffs are ignored for machine merge. A Markdown-only handoff is not
a completed wave handoff.

## `handoff-wN-aN.md`

Owner:

```text
bounty_write_wave_handoff
```

Use it to answer:

- what did the evaluator say in human-friendly prose?

Trust level:

```text
human/debug mirror only
```

Important caution:

Do not build automation on it.

## `live-dead-ends-wN-aN.jsonl`

Owner:

```text
bounty_log_dead_ends
```

Read by:

```text
bounty_apply_wave_merge
bounty_read_assignment_brief
analytics
```

Use it to answer:

- did a evaluator log dead ends before reaching final handoff?
- should later evaluators avoid a path even if a handoff was partial?

Trust level:

```text
authoritative live exclusion log
```

## `coverage.jsonl`

Owner:

```text
bounty_log_coverage
```

Read by:

```text
bounty_read_assignment_brief
bounty_wave_status
phase gates
wave merge requeue logic
analytics
```

Use it to answer:

- which endpoint, bug class, and auth-profile combinations were tested?
- what is still promising?
- what needs auth?
- what should be requeued?

Trust level:

```text
authoritative coverage trail
```

Important caution:

Coverage is not a finding. It is a work ledger.

## `findings.jsonl`

Owner:

```text
bounty_record_finding
```

Read by:

```text
root status tools
chain builder
verifiers
evidence agent
grader
report writer
analytics
```

Use it to answer:

- what claims did evaluators prove live?
- which wave, agent, and surface produced each claim?
- what endpoint and auth profile were involved?
- what evidence did the evaluator provide before verification?

Trust level:

```text
authoritative evaluator finding ledger
```

Important caution:

A finding here is not automatically reportable. It must survive verification,
evidence, and grading.

## `findings.md`

Owner:

```text
bounty_record_finding
```

Use it to answer:

- what is the readable finding summary?

Trust level:

```text
human/debug mirror only
```

## `chain-attempts.jsonl`

Owner:

```text
bounty_write_chain_attempt
```

Read by:

```text
chain builder
verifiers
grader
report writer
phase gates
analytics
```

Use it to answer:

- were chain hypotheses tested?
- which findings were linked?
- did the chain work, fail, get blocked, or not apply?
- should chain impact be included in the final report?

Trust level:

```text
authoritative chain test ledger
```

Important caution:

Only confirmed chain attempts should be used as impact evidence in reports.

## `brutalist.json`, `balanced.json`, `verified-final.json`

Owner:

```text
bounty_write_verification_round
```

Read by:

```text
root orchestrator
later verifiers
evidence agent
grader
report writer
analytics
```

Use them to answer:

- did the finding survive skeptical replay?
- was severity changed?
- is the finding reportable?
- why was the finding denied or downgraded?

Trust level:

```text
authoritative verification records
```

Important caution:

`verified-final.json` is the final reportability source. Earlier rounds explain
the debate, but final drives evidence and grade.

## `brutalist.md`, `balanced.md`, `verified-final.md`

Owner:

```text
bounty_write_verification_round
```

Trust level:

```text
human/debug mirrors only
```

## `evidence-packs.json`

Owner:

```text
bounty_write_evidence_packs
```

Read by:

```text
bounty_read_evidence_packs
grader
report writer
phase gates
analytics
```

Use it to answer:

- is every final reportable finding covered by bounded evidence?
- what representative samples support the report?
- what aggregate counts prove impact without dumping raw sensitive data?
- what redaction decisions were made?

Trust level:

```text
authoritative pre-grade evidence layer
```

Important caution:

This is where proof becomes report-safe. It must not contain secrets, cookies,
tokens, passwords, raw large responses, or unbounded PII.

## `evidence-packs.md`

Owner:

```text
bounty_write_evidence_packs
```

Trust level:

```text
human/debug mirror only
```

## `grade.json`

Owner:

```text
bounty_write_grade_verdict
```

Read by:

```text
bounty_read_grade_verdict
report writer
analytics
```

Use it to answer:

- should the result be submitted, held, or skipped?
- what score did each final survivor receive?
- what feedback should drive a HOLD loop?

Trust level:

```text
authoritative verdict
```

Important caution:

The code validates scoring arithmetic and verdict thresholds. If the grade is
malformed, `bounty_read_grade_verdict` should fail instead of silently trusting
it.

## `grade.md`

Owner:

```text
bounty_write_grade_verdict
```

Trust level:

```text
human/debug mirror only
```

## `report.md`

Owner:

```text
report-writer agent
```

Read by:

```text
human operator
status/debug tools
```

Use it to answer:

- what should be submitted or retained as the final closeout?

Trust level:

```text
human output, but not the source of truth for orchestration
```

Important caution:

For a disputed claim, trace backward to `grade.json`,
`evidence-packs.json`, `verified-final.json`, and `findings.jsonl`.

## `pipeline-events.jsonl`

Owner:

```text
MCP state-changing operations
```

Read by:

```text
bounty_read_pipeline_analytics
/bob-status
/bob-debug
```

Use it to answer:

- what happened when?
- did a wave start or merge?
- did a phase transition happen?
- were there pending merges or failures?
- how did this session reach its current state?

Trust level:

```text
authoritative event timeline, not authoritative current state
```

## Tool Telemetry

Owner:

```text
mcp/lib/tool-telemetry.js
```

Read by:

```text
bounty_read_tool_telemetry
bounty_read_pipeline_analytics
```

Use it to answer:

- which MCP tools fail often?
- which agents hit stop-hook failures?
- are failures concentrated around auth, HTTP, handoff, evidence, or phase gates?

Trust level:

```text
metadata-only diagnostic source
```

## Static Artifact Files

Artifacts:

```text
static-imports/SA-N.txt
static-artifacts.jsonl
static-scan-results.jsonl
```

Owner:

```text
bounty_import_static_artifact
bounty_static_scan
```

Use them to answer:

- what token-contract or static source was imported?
- what bounded static scan hints should evaluator briefs include?

Trust level:

```text
authoritative for imported static-analysis leads
```

Important caution:

Evaluators must import pasted content through MCP. They must not scan arbitrary
local paths.

## `public-intel.json`

Owner:

```text
bounty_public_intel
```

Read by:

```text
bounty_read_assignment_brief
ranking
analytics
```

Use it to answer:

- what public program or disclosure hints were collected?
- which bug classes or flows may be worth prioritizing?

Trust level:

```text
prioritization hint, not evidence
```

\newpage

# Agent Responsibility Matrix

This section describes each agent as an operating contract: what it receives,
what it may write, and what it must not decide.

## Root Orchestrator

File:

```text
.claude/skills/bob-evaluate/SKILL.md
```

Phase:

```text
all phases
```

Primary context:

- command arguments
- compact MCP state
- wave status
- pipeline analytics
- artifact existence and validation results

May write through MCP:

- session state
- wave assignments
- phase transitions
- session handoff notes

May spawn:

- surface-discovery agent
- evaluator agents
- chain builder
- verifiers
- evidence agent
- grader
- report writer

Must not:

- evaluate directly
- send target HTTP requests except AUTH signup/login calls
- synthesize handoff JSON
- manually edit MCP-owned artifacts
- merge a wave in the same turn it launched evaluators

Best file to read:

```text
.claude/skills/bob-evaluate/SKILL.md
```

Failure signals:

- invalid phase transition
- pending wave not settled
- phase gate blockers
- missing attack surface
- missing verification/evidence/grade artifacts

## Surface-discovery Agent

File:

```text
.claude/agents/surface-discovery-agent.md
```

Phase:

```text
SURFACE_DISCOVERY
```

Primary context:

- domain
- session directory

May write:

```text
attack_surface.json
surface-discovery scratch files
```

Must not:

- use MCP tools
- keep probing beyond the seven Bash collection steps
- create multiple competing attack-surface artifacts

Best code/doc pair:

```text
.claude/agents/surface-discovery-agent.md
mcp/lib/attack-surface.js
```

Failure signals:

- missing tools in `surface-discovery-tools.txt`
- empty `live_hosts.txt`
- missing or malformed `attack_surface.json`
- attack surface contains no surfaces

## Evaluator Agent

File:

```text
.claude/agents/evaluator-agent.md
```

Phase:

```text
EVALUATE or EXPLORE
```

Primary context:

- spawn prompt with target, wave, agent, handoff token, egress profile
- one `bounty_read_assignment_brief` result

May write through MCP:

```text
http-audit.jsonl
coverage.jsonl
live-dead-ends-wN-aN.jsonl
findings.jsonl
findings.md
handoff-wN-aN.json
handoff-wN-aN.md
static artifacts and scan results
```

Must not:

- test unassigned first-party surfaces as primary scope
- manually write handoff, findings, coverage, traffic, audit, or static files
- record weak standalone non-findings
- continue hammering unreachable or WAF-blocked hosts
- finish without a structured handoff in normal wave mode

Best code/doc pair:

```text
.claude/agents/evaluator-agent.md
mcp/lib/assignment-brief.js
mcp/lib/waves.js
mcp/lib/findings.js
```

Failure signals:

- no `BOB_AGENT_RUN_DONE` marker
- marker does not match handoff
- handoff token invalid
- handoff missing or malformed
- `surface_status` is partial and should requeue
- coverage shows promising work left open

## Chain Builder

File:

```text
.claude/agents/chain-builder.md
```

Phase:

```text
CHAIN
```

Primary context:

- findings
- structured handoffs
- HTTP audit
- auth profile summaries
- prior chain attempts

May write through MCP:

```text
chain-attempts.jsonl
```

Must not:

- invent chains from prose alone
- read Markdown handoffs or `findings.md` as machine input
- leave required chains as only `inconclusive`

Best code/doc pair:

```text
.claude/agents/chain-builder.md
mcp/lib/chain-attempts.js
mcp/lib/phase-gates.js
```

Failure signals:

- CHAIN -> VERIFY blocked by missing terminal chain attempt
- chain evidence says "could" but no `confirmed`, `denied`, `blocked`, or
  `not_applicable` outcome exists

## Brutalist Verifier

File:

```text
.claude/agents/brutalist-verifier.md
```

Phase:

```text
VERIFY round 1
```

Primary context:

- findings
- chain attempts
- HTTP audit
- auth profile summaries

May write through MCP:

```text
brutalist.json
brutalist.md
```

Must not:

- accept claims without replay or reasoning
- write verifier Markdown directly
- deny solely because auth expired

Failure signals:

- missing `brutalist.json`
- empty results when findings exist
- malformed disposition/severity/reportable fields

## Balanced Verifier

File:

```text
.claude/agents/balanced-verifier.md
```

Phase:

```text
VERIFY round 2
```

Primary context:

- findings
- brutalist round
- chain attempts
- HTTP audit
- auth profile summaries

May write through MCP:

```text
balanced.json
balanced.md
```

Must not:

- drop findings from the brutalist round
- blindly pass through denied/downgraded results if there is a clear false
  negative

Failure signals:

- result count is less than brutalist result count
- a brutalist finding ID is absent from balanced results

## Final Verifier

File:

```text
.claude/agents/final-verifier.md
```

Phase:

```text
VERIFY round 3
```

Primary context:

- findings
- balanced round
- chain attempts
- HTTP audit
- auth profile summaries

May write through MCP:

```text
verified-final.json
verified-final.md
```

Must not:

- drop findings from the balanced round
- use stale results for reportable survivors without fresh replay

Failure signals:

- reportable finding lacks fresh replay reasoning
- final results omit a balanced finding
- evidence phase has nothing to cover because final incorrectly dropped all
  reportables

## Evidence Agent

File:

```text
.claude/agents/evidence-agent.md
```

Phase:

```text
after final verification, before GRADE
```

Primary context:

- findings
- final verification
- HTTP audit
- auth profile summaries

May write through MCP:

```text
evidence-packs.json
evidence-packs.md
```

Must not:

- create, modify, or remove findings
- grade
- write reports
- store raw secrets, cookies, tokens, or unbounded sensitive data

Failure signals:

- missing pack for a final reportable finding
- unsafe evidence content
- sample count too high
- evidence pack references a non-reportable finding

## Grader

File:

```text
.claude/agents/grader.md
```

Phase:

```text
GRADE
```

Primary context:

- findings
- chain attempts
- final verification
- evidence packs

May write through MCP:

```text
grade.json
grade.md
```

Must not:

- submit automatically
- score speculative chain impact
- issue `SUBMIT` without a medium-or-higher final reportable finding

Failure signals:

- arithmetic does not add up
- verdict contradicts thresholds
- `SUBMIT` without evidence or final reportable medium-or-higher finding

## Report Writer

File:

```text
.claude/agents/report-writer.md
```

Phase:

```text
REPORT
```

Primary context:

- findings
- chain attempts
- final verification
- evidence packs
- grade verdict

May write directly:

```text
report.md
```

Must not:

- report denied, blocked, inconclusive, or not-applicable chains as impact
- use evaluator severity if verification changed it
- invent vulnerability sections in no-findings reports
- include methodology filler

Failure signals:

- report contains a claim absent from final verification
- report includes evidence absent from evidence packs
- report severity differs from final verification without explanation

\newpage

# State Machine And Phase Gates

The FSM is simple on paper:

```text
SURFACE_DISCOVERY -> AUTH -> EVALUATE -> CHAIN -> VERIFY -> GRADE -> REPORT
                                                 |
                                                 v
                                   REPORT -> EXPLORE -> CHAIN
```

But the important logic is not the arrow. The important logic is what must be
true before an arrow is allowed.

Code:

```text
mcp/lib/session-state.js
mcp/lib/phase-gates.js
```

## Transition Contract

Every transition goes through:

```text
bounty_transition_phase
```

That tool:

1. reads `state.json`
2. checks the current phase
3. checks the requested next phase is legal
4. runs any phase-specific gate
5. writes `state.json`
6. appends a `phase_transitioned` event

If the gate blocks, the tool returns a `STATE_CONFLICT` style failure. The root
should use the blocker message to decide what to do next.

## Gate Table

```text
SURFACE_DISCOVERY -> AUTH
  Legal after surface-discovery if attack_surface.json exists and root decides surface-discovery found surfaces.
  The MCP transition itself does not create attack_surface.json.

AUTH -> EVALUATE
  Requires auth_status.
  Allowed values: authenticated or unauthenticated.

EVALUATE -> CHAIN
  Requires no pending_wave.
  Requires readable attack_surface.json.
  Requires readable coverage.
  Blocks if high/critical surfaces remain unexplored.
  Blocks if latest coverage contains promising, needs_auth, or requeue work.
  Can be overridden only with an explicit override_reason.

CHAIN -> VERIFY
  Computes whether chain testing is required.
  Chain testing is required when there are multiple findings or structured
  handoff chain_notes.
  If required, at least one terminal chain attempt must exist.
  Can be overridden only with an explicit override_reason.

VERIFY -> GRADE
  Requires valid evidence packs for all final reportable findings.
  If there are no final reportable findings, structured evidence skip is allowed.

GRADE -> REPORT
  Reuses the evidence-pack validity gate.

GRADE -> EVALUATE
  Allowed on HOLD.
  Increments hold_count.

REPORT -> EXPLORE
  Allowed only when the user asks to continue evaluating after a report.

EXPLORE -> CHAIN
  Uses the same wave system as EVALUATE, then returns to CHAIN.
```

## Phase Gate Debugging Question

When a phase transition fails, ask:

```text
Is this blocked by state, artifact validity, missing work, or operator intent?
```

Examples:

```text
pending_wave is not null
  -> state says a wave is open
  -> inspect wave assignments and handoff status

unexplored_high_surfaces
  -> attack_surface.json has HIGH/CRITICAL surfaces not in state.explored
  -> run another wave or explicitly override with a reason

open_requeue_coverage
  -> latest coverage has promising, needs_auth, or requeue entries
  -> run another wave focused on those surfaces

chain_attempts_missing
  -> chain context says a chain should be tested
  -> rerun chain builder or override only with operator acceptance

evidence_packs_invalid
  -> final reportable findings are not all covered by valid evidence
  -> rerun evidence agent
```

## State Machine Reading Exercise

Open:

```text
mcp/lib/session-state.js
```

Find:

```text
allowedTransitions
```

Then open:

```text
mcp/lib/phase-gates.js
```

Trace these functions:

```text
computeEvaluationToChainGate
computeChainToVerifyGate
computeVerifyToGradeGate
formatTransitionBlockers
```

That is the complete "why can or cannot we move forward" core.

\newpage

# Trace One Finding End To End

This chapter traces a fictional finding `F-1` forward and backward.

Finding:

```text
F-1: IDOR in invoice export exposes victim invoice metadata
```

## Forward Trace

### 1. Evaluator Discovers The Issue

The evaluator is assigned:

```text
wave = w1
agent = a2
surface_id = billing-api
```

It reads:

```text
bounty_read_assignment_brief
```

It sees imported traffic for:

```text
GET /api/invoices/export?id=123
```

It tests with:

```text
bounty_http_scan({
  target_domain: "example.test",
  method: "GET",
  url: "https://app.example.test/api/invoices/export?id=123",
  auth_profile: "attacker",
  wave: "w1",
  agent: "a2",
  surface_id: "billing-api",
  egress_profile: "default",
  block_internal_hosts: false
})
```

The request is audited in:

```text
http-audit.jsonl
```

### 2. Evaluator Logs Coverage

The evaluator records that this endpoint and bug class were tested:

```text
bounty_log_coverage({
  target_domain: "example.test",
  wave: "w1",
  agent: "a2",
  surface_id: "billing-api",
  entries: [
    {
      "endpoint": "/api/invoices/export",
      "method": "GET",
      "bug_class": "IDOR",
      "auth_profile": "attacker",
      "status": "tested",
      "evidence_summary": "Export accepted arbitrary invoice id"
    }
  ]
})
```

Artifact:

```text
coverage.jsonl
```

### 3. Evaluator Records The Finding

Tool:

```text
bounty_record_finding
```

Artifact:

```text
findings.jsonl
```

Simplified line:

```json
{
  "id": "F-1",
  "target_domain": "example.test",
  "wave": "w1",
  "agent": "a2",
  "surface_id": "billing-api",
  "title": "IDOR in invoice export exposes victim invoice metadata",
  "severity": "high",
  "endpoint": "https://app.example.test/api/invoices/export?id=123",
  "auth_profile": "attacker",
  "validated": true
}
```

MCP also updates the human mirror:

```text
findings.md
```

### 4. Evaluator Writes Handoff

Tool:

```text
bounty_write_wave_handoff
```

Artifact:

```text
handoff-w1-a2.json
```

Important fields:

```json
{
  "wave": "w1",
  "agent": "a2",
  "surface_id": "billing-api",
  "surface_status": "complete",
  "provenance": "verified",
  "provenance_model": "session_file_hmac_v1",
  "provenance_assignment_hash": "...",
  "provenance_signature": {
    "version": 1,
    "algorithm": "hmac-sha256",
    "digest": "..."
  },
  "summary": "Tested invoice export and related billing endpoints.",
  "chain_notes": [
    "Invoice IDOR may combine with account enumeration from auth-flow."
  ]
}
```

Then the final marker appears:

```text
BOB_AGENT_RUN_DONE {"target_domain":"example.test","wave":"w1","agent":"a2","surface_id":"billing-api"}
```

The hook checks marker-to-handoff consistency.

### 5. Wave Merge Updates State

Tool:

```text
bounty_apply_wave_merge
```

State after merge:

```json
{
  "pending_wave": null,
  "evaluation_wave": 1,
  "total_findings": 1,
  "explored": ["billing-api"]
}
```

Pipeline event:

```text
wave_merged
```

### 6. Chain Builder Tests The Chain Note

Because the handoff includes `chain_notes`, CHAIN likely requires a terminal
attempt.

Tool:

```text
bounty_write_chain_attempt
```

Artifact:

```text
chain-attempts.jsonl
```

Possible record:

```json
{
  "attempt_id": "C-1",
  "finding_ids": ["F-1"],
  "surface_ids": ["billing-api", "auth-flow"],
  "hypothesis": "Account enumeration can help target invoice IDs for export.",
  "outcome": "denied",
  "evidence_summary": "Enumeration did not reveal invoice IDs.",
  "auth_profiles": ["attacker", "victim"]
}
```

Even a denied attempt is useful. It prevents speculative chain language in the
report.

### 7. Verification Rounds Debate The Finding

Round 1:

```text
brutalist.json
```

Maybe:

```json
{
  "finding_id": "F-1",
  "disposition": "confirmed",
  "severity": "high",
  "reportable": true,
  "reasoning": "Fresh replay with attacker profile returned victim invoice metadata."
}
```

Round 2:

```text
balanced.json
```

Passes through or adjusts.

Round 3:

```text
verified-final.json
```

Final source for whether evidence must be collected:

```json
{
  "finding_id": "F-1",
  "disposition": "confirmed",
  "severity": "high",
  "reportable": true,
  "reasoning": "Fresh final replay confirms cross-account invoice metadata exposure."
}
```

### 8. Evidence Agent Creates A Safe Proof Pack

Tool:

```text
bounty_write_evidence_packs
```

Artifact:

```text
evidence-packs.json
```

Simplified pack:

```json
{
  "finding_id": "F-1",
  "sample_type": "cross-account invoice export",
  "sample_count": 3,
  "representative_samples": [
    {
      "request_ref": "http-audit:42",
      "endpoint": "/api/invoices/export",
      "auth_profile": "attacker",
      "status": 200,
      "observed_fields": ["account_id", "email", "invoice_total"],
      "redacted_object_id": "inv_...789"
    }
  ],
  "sensitive_clusters": ["invoice metadata"],
  "replay_summary": "Attacker profile returned victim invoice metadata.",
  "redaction_notes": "Identifiers and personal values redacted.",
  "report_snippet": "An attacker can export invoice metadata for other accounts by changing the invoice id."
}
```

### 9. Grader Scores It

Tool:

```text
bounty_write_grade_verdict
```

Artifact:

```text
grade.json
```

Possible verdict:

```json
{
  "verdict": "SUBMIT",
  "total_score": 72,
  "findings": [
    {
      "finding_id": "F-1",
      "impact": 25,
      "proof_quality": 20,
      "severity_accuracy": 12,
      "chain_potential": 5,
      "report_quality": 10,
      "total_score": 72
    }
  ]
}
```

### 10. Report Writer Uses Only Survivors

Artifact:

```text
report.md
```

The report should cite:

- final severity from `verified-final.json`
- bounded samples from `evidence-packs.json`
- only confirmed chain attempts from `chain-attempts.jsonl`
- grade verdict from `grade.json`

## Backward Trace

If you are reading `report.md` and want to verify a claim, walk backward:

```text
report.md
  -> grade.json
  -> evidence-packs.json
  -> verified-final.json
  -> balanced.json
  -> brutalist.json
  -> findings.jsonl
  -> http-audit.jsonl
  -> handoff-w1-a2.json
  -> wave-1-assignments.json
  -> attack_surface.json
  -> state.json
```

Ask these questions:

1. Does `grade.json` include the finding?
2. Does `verified-final.json` mark it `reportable: true`?
3. Does `evidence-packs.json` include a pack for it?
4. Does the evidence pack reference request audit entries?
5. Does `findings.jsonl` show which evaluator recorded it?
6. Does the evaluator handoff match the assigned surface?
7. Does state show the wave was actually merged?

That backward trace is the fastest way to find hallucinated report content.

\newpage

# Debugging Playbook

This section is written for offline use. Start with the symptom, then inspect
the listed artifacts or files.

## The Run Says A Wave Is Pending

Inspect:

```text
state.json
wave-N-assignments.json
handoff-wN-aN.json files
bounty_wave_handoff_status
bounty_read_pipeline_analytics
```

Likely causes:

- one background evaluator has not finished
- a evaluator ended without the final marker
- handoff JSON is missing
- handoff JSON is malformed
- marker and handoff disagree
- an unexpected agent wrote a handoff

Code to read:

```text
mcp/lib/waves.js
.claude/hooks/agent-run-stop.js
```

What to do:

- wait for evaluators if they are still running
- resume the session after completion
- use force-merge only when the missing/invalid handoff is understood and the
  reason is explicit

## EVALUATE Will Not Transition To CHAIN

Inspect:

```text
bounty_wave_status
state.json
attack_surface.json
coverage.jsonl
```

Likely blockers:

```text
pending_wave
attack_surface_unavailable
coverage_unavailable
unexplored_high_surfaces
open_requeue_coverage
```

Code to read:

```text
mcp/lib/phase-gates.js
computeEvaluationToChainGate
```

What to do:

- merge the pending wave
- run another wave for high/critical unexplored surfaces
- run another wave for promising or requeue coverage
- override only if the operator intentionally accepts the gap

## CHAIN Will Not Transition To VERIFY

Inspect:

```text
findings.jsonl
handoff-wN-aN.json
chain-attempts.jsonl
```

Likely blocker:

```text
chain_attempts_missing
```

This means the repo detected reason to test chainability, usually multiple
findings or handoff `chain_notes`, but no terminal chain attempt was recorded.

Code to read:

```text
mcp/lib/phase-gates.js
computeChainRequirement
computeChainToVerifyGate
mcp/lib/chain-attempts.js
```

What to do:

- rerun the chain builder with the blocker text
- make sure it records `confirmed`, `denied`, `blocked`, or `not_applicable`
- do not treat `inconclusive` as satisfying the gate

## VERIFY Will Not Transition To GRADE

Inspect:

```text
verified-final.json
evidence-packs.json
bounty_read_evidence_packs
```

Likely blocker:

```text
evidence_packs_invalid
```

Common causes:

- final reportable finding has no pack
- evidence pack references a non-reportable finding
- evidence contains unsafe token-like or secret-like content
- representative samples are missing or unbounded

Code to read:

```text
mcp/lib/evidence.js
mcp/lib/phase-gates.js
```

What to do:

- rerun evidence agent
- remove unsafe fields
- ensure every final reportable finding has exactly the needed bounded proof

## The Report Mentions A Finding That Is Not In Final Verification

Inspect:

```text
report.md
verified-final.json
evidence-packs.json
grade.json
```

Likely causes:

- report writer used stale evaluator findings instead of final verification
- report writer included a denied or downgraded non-reportable finding
- report writer included chain impact from a denied or blocked chain attempt

Code/doc to read:

```text
.claude/agents/report-writer.md
```

What to do:

- regenerate the report writer output
- instruct it to use only final reportable findings and evidence packs

## A Evaluator Keeps Repeating Work

Inspect:

```text
coverage.jsonl
bounty_read_assignment_brief
dead_ends in state.json
waf_blocked_endpoints in state.json
```

Likely causes:

- coverage was not logged before pivots
- dead ends were not merged yet
- evaluator brief caps hid some older context
- assigned surface is too broad

Code to read:

```text
mcp/lib/assignment-brief.js
mcp/lib/coverage.js
```

What to do:

- make evaluators log coverage after meaningful tests
- split broad surfaces in surface-discovery if needed
- tune evaluator brief summaries if context caps are too aggressive

## A Finding Is Missing From The Report

Trace:

```text
findings.jsonl
brutalist.json
balanced.json
verified-final.json
evidence-packs.json
grade.json
report.md
```

Possible disappearance points:

- evaluator never recorded it
- brutalist denied it
- balanced failed to pass it through
- final failed to pass it through
- final marked it non-reportable
- evidence pack missing
- grade skipped it
- report writer omitted it

Most important invariant:

```text
balanced includes every brutalist result
final includes every balanced result
```

If that invariant breaks, inspect:

```text
mcp/lib/findings.js
.claude/agents/balanced-verifier.md
.claude/agents/final-verifier.md
test/mcp-server.test.js
```

## Auth Does Not Seem To Work

Inspect:

```text
auth.json
bounty_list_auth_profiles
http-audit.jsonl
```

Likely causes:

- profile was never stored
- profile expired
- profile name mismatch
- request did not pass `auth_profile`
- target changed auth requirements

What to do:

- use `bounty_list_auth_profiles` before replay
- store a fresh profile with `bounty_auth_store`
- make sure evaluators/verifiers use `auth_profile: "attacker"` and `"victim"`
  where appropriate

## HTTP Requests Fail Repeatedly

Inspect:

```text
http-audit.jsonl
bounty_wave_status
bounty_read_pipeline_analytics
circuit_breaker_summary in evaluator brief
```

Likely causes:

- target unavailable
- WAF or rate limit
- egress profile blocked
- geofence or regional behavior
- internal host reachability issue

What to do:

- do not silently rotate egress
- log blocked coverage and dead ends
- ask the operator to resume with a specific `--egress` profile if appropriate

## JSON And Markdown Disagree

Rule:

```text
JSON and JSONL win for orchestration.
Markdown is human/debug output unless explicitly documented otherwise.
```

Examples:

```text
findings.jsonl wins over findings.md
handoff-wN-aN.json wins over handoff-wN-aN.md
verified-final.json wins over verified-final.md
evidence-packs.json wins over evidence-packs.md
grade.json wins over grade.md
```

Exception:

```text
report.md is the final human-facing report.
```

Even then, report trust comes from the structured artifacts behind it.

\newpage

# Context Budget Cheat Sheet

Bob's architecture is mostly about preventing context collapse.

The naive version of this project would paste everything into every agent:

```text
all surface-discovery
all traffic
all requests
all findings
all handoffs
all previous discussion
all reports
```

That would fail because agents would lose the important part, repeat work, and
silently drift away from the state machine.

Bob uses three context patterns instead.

## Pattern 1: Compact State For The Root

The root usually reads:

```text
bounty_read_state_summary
bounty_wave_status
bounty_read_pipeline_analytics
```

It does not need every request or every endpoint. It needs to know:

- what phase is active
- whether a wave is pending
- whether gates are blocked
- whether another agent must run
- whether an artifact is missing

This is why `readStateSummary()` exists next to full `readSessionState()`.

## Pattern 2: One Assigned Brief For Each Evaluator

Each evaluator reads:

```text
bounty_read_assignment_brief
```

That brief is a lossy but purposeful packet. It should answer:

- what am I assigned?
- what should I prioritize?
- what has already been tested?
- what should I avoid?
- what auth can I use?
- what request history is relevant?
- what static or public hints matter?

The evaluator should not read the whole session directory. It should not decide
its own surface. It should not consume all other evaluators' context.

## Pattern 3: Structured Artifacts For Later Agents

Later agents read JSON/JSONL:

```text
chain builder -> findings, handoffs, audit, auth summaries
verifiers     -> findings, chain attempts, audit, auth summaries
evidence      -> final verification, findings, audit, auth summaries
grader        -> final verification, evidence packs, chain attempts
reporter      -> final verification, evidence packs, grade
```

This prevents the final report from depending on the root chat transcript.

## What Gets Summarized

Good candidates for summary:

- old HTTP audit entries
- imported traffic
- coverage history
- dead ends
- public intel
- static scan hints
- telemetry

Bad candidates for lossy summary:

- final verification dispositions
- grade verdict
- evidence pack validation
- phase
- pending wave
- handoff token verification result

The rule of thumb:

```text
Summarize prioritization context.
Preserve decision state.
```

## What Must Stay Structured

These should remain structured and machine-validated:

```text
state
wave assignments
handoffs
coverage records
findings
chain attempts
verification rounds
evidence packs
grade
pipeline events
tool telemetry
```

If these become prose-only, many-agent coordination breaks.

## Context Loss Recovery

If the root chat loses context, the recovery path is:

```text
/bob-evaluate resume example.test
```

The root does not need the old chat. It reads:

```text
bounty_read_state_summary
```

Then:

```text
if pending_wave:
  try bounty_apply_wave_merge
else:
  continue from state.phase
```

That is why the durable state model matters. Resume is possible because the
chat is disposable.

\newpage

# Offline Exercises

These are designed for a flight. Do the "Task" first, then check the answer.

## Exercise 1: Find The Main Orchestrator Contract

Task:

```bash
sed -n '1,260p' .claude/skills/bob-evaluate/SKILL.md
```

Questions:

- what tools can the root call?
- what are the hard rules?
- where is the FSM defined?
- what does the launch-turn barrier forbid?

Answer:

The root orchestrator contract is the `bob-evaluate` skill. It owns phase
coordination, agent spawning, wave start/merge decisions, and resume behavior.
It must not evaluate directly, synthesize handoffs, or write MCP-owned artifacts.
The launch-turn barrier forbids merging or checking handoff status in the same
turn that spawned evaluators.

## Exercise 2: Find Who Writes `state.json`

Task:

```bash
rg -n "state.json|writeSessionStateDocument|session_artifacts_written" mcp/lib
```

Answer:

`state.json` is written by MCP state/wave tools:

```text
bounty_init_session
bounty_transition_phase
bounty_start_wave
bounty_apply_wave_merge
```

The core implementation is in:

```text
mcp/lib/session-state.js
mcp/lib/waves.js
```

Agents should not write it directly.

## Exercise 3: Find The Wave Token Logic

Task:

```bash
rg -n "handoff_token|sha256|provenance" mcp/lib/waves.js
```

Answer:

`bounty_start_wave` generates a plaintext token per assignment and writes only
its SHA-256 hash to `wave-N-assignments.json`. `bounty_write_wave_handoff`
validates the supplied token, then signs the JSON handoff with the session-local
`.handoff-signing-key.json` key. Verified handoffs carry
`provenance: "verified"` plus `provenance_model: "session_file_hmac_v1"` and a
signature.

This prevents unauthenticated handoff writes through the MCP tool and lets read
and merge paths reject hand-edited tokenized handoff JSON unless the local
session signing key is available.

## Exercise 4: Find The Evaluator's First Required Action

Task:

```bash
rg -n "first action|bounty_read_assignment_brief|Call `bounty_read_assignment_brief`" .claude/agents/evaluator-agent.md .claude/skills/bob-evaluate/SKILL.md
```

Answer:

The evaluator must call `bounty_read_assignment_brief` first in normal wave mode. The
orchestrator prompt injects wave, agent, target, token, and egress profile, but
the brief is where the assigned context packet comes from.

## Exercise 5: Find Where EVALUATE -> CHAIN Can Block

Task:

```bash
sed -n '1,180p' mcp/lib/phase-gates.js
```

Answer:

`computeEvaluationToChainGate()` blocks on:

```text
pending_wave
attack_surface_unavailable
coverage_unavailable
unexplored_high_surfaces
open_requeue_coverage
```

This is why Bob cannot simply decide "enough evaluating" based on chat vibes.

## Exercise 6: Find The "Include Every Finding" Rule

Task:

```bash
rg -n "EVERY finding|silently dropped|missing from your results" .claude/agents
```

Answer:

Balanced verifier must include every brutalist result. Final verifier must
include every balanced result. If a verifier omits a finding, it can disappear
from the pipeline.

## Exercise 7: Find Evidence Validation

Task:

```bash
rg -n "requireValidEvidence|representative_samples|secret|token|final reportable" mcp/lib/evidence.js
```

Answer:

Evidence validation ensures final reportable findings are covered and evidence
is bounded/redacted. This is the gate before grade/report work.

## Exercise 8: Find The Tool Registry Contract

Task:

```bash
sed -n '1,180p' mcp/lib/tool-registry.js
```

Answer:

Every tool entry must declare metadata such as:

```text
role_bundles
mutating
network_access
browser_access
scope_required
sensitive_output
session_artifacts_written
```

This supports tool governance, prompt generation, and contract tests.

## Exercise 9: Find Write Guard Rules

Task:

```bash
sed -n '1,180p' .claude/hooks/session-write-guard.sh
sed -n '1,180p' test/test-write-guard.py
```

Answer:

The write guard blocks direct writes to MCP-owned artifacts such as state,
findings, handoffs, evidence packs, traffic, audit, coverage, and pipeline
events. It allows surface-discovery-owned `attack_surface.json`.

## Exercise 10: Trace One Tool End To End

Task:

Trace `bounty_write_wave_handoff`.

Read:

```text
mcp/lib/tools/write-wave-handoff.js
mcp/lib/tool-registry.js
mcp/lib/dispatch.js
mcp/lib/waves.js
.claude/agents/evaluator-agent.md
.claude/hooks/agent-run-stop.js
test/mcp-server.test.js
```

Answer:

The agent prompt requires the handoff. The tool module defines the schema and
metadata. The registry validates tool shape. Dispatch wraps execution in the
standard envelope. `waves.js` validates assignment, token, payload, and writes
JSON/Markdown. The stop hook checks that the final marker matches the structured
handoff. Tests cover missing, malformed, and mismatched cases.

\newpage

# Code Map By Question

Use this section when you know the question but not the file.

## Where Does A Run Start?

```text
.claude/skills/bob-evaluate/SKILL.md
mcp/lib/tools/init-session.js
mcp/lib/session-state.js
```

## Where Are Phases Defined?

```text
mcp/lib/constants.js
mcp/lib/session-state.js
mcp/lib/phase-gates.js
```

## Where Are MCP Tools Registered?

```text
mcp/lib/tools/index.js
mcp/lib/tool-registry.js
mcp/lib/dispatch.js
mcp/server.js
```

## Where Is The Standard MCP Response Shape?

```text
mcp/lib/envelope.js
mcp/lib/dispatch.js
```

Look for:

```text
{ ok, data, meta }
{ ok: false, error, meta }
```

## Where Are Session Paths Defined?

```text
mcp/lib/paths.js
```

## Where Is State Persisted And Normalized?

```text
mcp/lib/session-state.js
mcp/lib/storage.js
```

## Where Are Waves Implemented?

```text
mcp/lib/waves.js
mcp/lib/assignments.js
mcp/lib/tools/start-wave.js
mcp/lib/tools/apply-wave-merge.js
mcp/lib/tools/write-wave-handoff.js
```

## Where Are Evaluator Briefs Built?

```text
mcp/lib/assignment-brief.js
mcp/lib/ranking.js
mcp/lib/http-records.js
mcp/lib/coverage.js
```

## Where Are Findings Implemented?

```text
mcp/lib/findings.js
mcp/lib/tools/record-finding.js
mcp/lib/tools/read-findings.js
mcp/lib/tools/list-findings.js
```

## Where Are Chain Attempts Implemented?

```text
mcp/lib/chain-attempts.js
mcp/lib/tools/write-chain-attempt.js
mcp/lib/tools/read-chain-attempts.js
```

## Where Are Verification Rounds Implemented?

```text
mcp/lib/findings.js
mcp/lib/tools/write-verification-round.js
mcp/lib/tools/read-verification-round.js
```

## Where Are Evidence Packs Implemented?

```text
mcp/lib/evidence.js
mcp/lib/tools/write-evidence-packs.js
mcp/lib/tools/read-evidence-packs.js
```

## Where Is Grading Implemented?

```text
mcp/lib/tools/write-grade-verdict.js
mcp/lib/tools/read-grade-verdict.js
.claude/agents/grader.md
```

## Where Is HTTP Scanning And Audit Implemented?

```text
mcp/lib/http-scan.js
mcp/lib/safe-fetch.js
mcp/lib/http-records.js
mcp/lib/tools/http-scan.js
mcp/redaction.js
```

## Where Is Auth Stored And Applied?

```text
mcp/lib/auth.js
mcp/lib/signup.js
mcp/auto-signup.js
mcp/lib/tools/auth-store.js
mcp/lib/tools/auto-signup.js
mcp/lib/tools/list-auth-profiles.js
```

## Where Are Egress Profiles Implemented?

```text
mcp/lib/egress-profiles.js
.claude/commands/bob-egress.md
.claude/hooks/bob-egress.js
.claude/bob/egress-profiles.json
```

## Where Are Analytics Implemented?

```text
mcp/lib/pipeline-analytics.js
mcp/lib/tool-telemetry.js
.claude/skills/bob-status/SKILL.md
.claude/skills/bob-debug/SKILL.md
```

## Where Are Safety Hooks?

```text
.claude/hooks/session-write-guard.sh
.claude/hooks/agent-run-stop.js
```

## Where Are Prompt Contracts Tested?

```text
test/prompt-contracts.test.js
scripts/generate-agent-tools.js
scripts/generate-bountyagent-skill.js
```

## Where Are End-To-End Runtime Behaviors Tested?

```text
test/mcp-server.test.js
test/cli.test.js
test/install-smoke.test.js
test/policy-replay.test.js
```

\newpage

# Improvement Roadmap At A Glance

The detailed improvement notes below explain each suggestion. This roadmap
groups them by likely payoff and implementation shape.

## Quick Wins

Add a question-based code map to the repo docs.

Why:

New readers search by question, not by module name. This guide now includes
that map, but a shorter checked-in docs page would help contributors.

Add an artifact ownership table to `README.md` or `docs/developer`.

Why:

The JSON/JSONL/Markdown split is central. A single table reduces accidental
direct writes and prompt drift.

Add report provenance comments to `report.md`.

Why:

A local-only footer or HTML comment can make reports traceable back to
`verified-final.json`, `evidence-packs.json`, and `grade.json`.

## Medium Refactors

Add `bounty_explain_phase_gate`.

Why:

The gate logic already exists. A read-only explainer would make blocked
transitions understandable without first attempting a transition that fails.

Add fixture sessions.

Why:

Small synthetic sessions would make tests, documentation, and offline learning
much easier. They would also support future static session explanation tools.

Add an "explain this session" script.

Why:

`bounty_read_pipeline_analytics` already computes much of the needed summary.
A static Markdown/HTML report could turn raw artifacts into a readable
postmortem.

Expose context budget metadata in evaluator briefs.

Why:

When a brief is heavily compressed, the evaluator and operator should know. Numeric
budget metadata would make missed context easier to diagnose.

## Larger Architecture Improvements

Generate artifact schemas or schema docs from runtime validators.

Why:

The validators are the real contract today. Generated docs or JSON Schemas
would make that contract visible without duplicating it by hand.

Generate lifecycle diagrams from tool metadata.

Why:

The tool registry already knows role bundles and written artifacts. A generated
graph would show phase -> agent -> tool -> artifact -> gate.

Build a local dashboard.

Why:

Multi-agent state is hard to inspect from raw JSON. A local HTML/TUI dashboard
could show waves, handoffs, coverage, findings, verification, evidence, and
telemetry in one place.

## Design Principles To Preserve

Keep egress rotation operator-controlled.

Why:

Egress affects authorization boundaries, geofencing, rate limits, and program
rules. Agents should surface reachability problems, not silently route around
them.

Keep Markdown non-authoritative for machine decisions.

Why:

Markdown is easy for agents to overfit or hallucinate. JSON/JSONL gives the
pipeline validation, dedupe, phase gates, and deterministic recovery.

Keep context bounded by role.

Why:

The main value of the architecture is not just parallel agents. It is parallel
agents with durable shared state and small, role-specific context packets.

\newpage

# Improvement Suggestions

This section is intentionally written as engineering notes, not as a criticism
of the current design. The project already has a coherent architecture: narrow
agents, MCP-owned state, structured artifacts, write guards, phase gates, and
contract tests. The suggestions below are the places where the system could
become easier to understand, easier to debug, or harder for agents to misuse.

## 1. Add A Machine-Readable Artifact Schema Reference

Suggestion:

Create a checked-in schema reference for the major session artifacts:

```text
docs/artifact-schemas.md
docs/schemas/state.schema.json
docs/schemas/attack-surface.schema.json
docs/schemas/wave-handoff.schema.json
docs/schemas/finding.schema.json
docs/schemas/verification-round.schema.json
docs/schemas/evidence-packs.schema.json
docs/schemas/grade.schema.json
```

Why it makes sense:

Right now, artifact schemas are mostly encoded in normalizer functions:

```text
mcp/lib/session-state.js
mcp/lib/waves.js
mcp/lib/findings.js
mcp/lib/evidence.js
mcp/lib/chain-attempts.js
```

That is good for enforcement, but harder for a new reader to inspect offline.
JSON Schemas or a generated docs page would make the state model easier to
learn and reduce accidental prompt/code drift.

Tradeoff:

Schemas can become stale unless generated from or tested against the same
normalizers. The right approach would be to add tests that compare sample
fixtures against both the schema and runtime validators.

Priority:

High for maintainability and onboarding.

## 2. Generate An Artifact Lifecycle Diagram From Tests Or Metadata

Suggestion:

Add a small script that emits a Mermaid or DOT graph showing:

```text
phase -> agent -> MCP tool -> artifact -> next phase gate
```

Example output:

```text
EVALUATE -> evaluator-agent -> bounty_record_finding -> findings.jsonl
EVALUATE -> evaluator-agent -> bounty_write_wave_handoff -> handoff-wN-aN.json
EVALUATE -> bounty_apply_wave_merge -> state.json
CHAIN -> chain-builder -> bounty_write_chain_attempt -> chain-attempts.jsonl
VERIFY -> final-verifier -> bounty_write_verification_round -> verified-final.json
VERIFY -> evidence-agent -> bounty_write_evidence_packs -> evidence-packs.json
GRADE -> grader -> bounty_write_grade_verdict -> grade.json
REPORT -> report-writer -> report.md
```

Why it makes sense:

Bob's architecture is easy to understand once you see the artifact chain, but
the chain is currently spread across prompts, tool metadata, and tests. A graph
would make the workflow explainable at a glance and would help contributors see
where a new tool or artifact belongs.

Tradeoff:

If hand-maintained, it will drift. Prefer generating it from `TOOL_MANIFEST`,
agent frontmatter, and a small curated phase map.

Priority:

High for documentation value; medium implementation effort.

## 3. Add A Local "Explain This Session" Static Report

Suggestion:

Add a command or script that reads one session directory and writes a static
HTML or Markdown explanation:

```bash
node scripts/explain-session.js example.com > session-explained.md
```

It should explain:

- current phase
- why Bob is or is not allowed to transition
- wave history
- missing or invalid handoffs
- findings flow
- verification outcomes
- evidence readiness
- grade/report trust
- relevant telemetry bottlenecks

Why it makes sense:

`/bob-status` is intentionally compact and `/bob-debug` is interactive. A
static explanation would be useful offline, in PR reviews, and when handing a
session to another operator. It would also make the JSON state easier to learn
because it could link every conclusion back to the artifact that produced it.

Tradeoff:

It overlaps with `bounty_read_pipeline_analytics`. The implementation should
reuse `mcp/lib/pipeline-analytics.js` rather than inventing a second analyzer.

Priority:

Medium-high, especially for teaching and postmortems.

## 4. Make Context Budgets Visible In Evaluator Briefs

Suggestion:

Expand `bounty_read_assignment_brief` output with a small `context_budget` object:

```json
{
  "context_budget": {
    "surface_chars": 3210,
    "coverage_items": 18,
    "traffic_items": 22,
    "audit_items": 12,
    "knowledge_chars": 2400,
    "truncated": true
  }
}
```

Why it makes sense:

The repo already caps surface arrays and reports `surface_limits`. A broader
budget summary would make it obvious when a evaluator is receiving a heavily
compressed view. That helps explain missed context and helps tune caps without
guesswork.

Tradeoff:

More metadata in the brief consumes a little context. Keep it compact and
numeric.

Priority:

Medium. It directly supports the project's context-management model.

## 5. Add A "Why This Phase Is Blocked" MCP Tool

Suggestion:

Add a read-only tool:

```text
bounty_explain_phase_gate
```

Inputs:

```json
{
  "target_domain": "example.com",
  "from_phase": "EVALUATE",
  "to_phase": "CHAIN"
}
```

Output:

```json
{
  "allowed": false,
  "blockers": [
    {
      "code": "unexplored_high_surfaces",
      "message": "HIGH or CRITICAL attack surfaces remain unexplored",
      "surface_ids": ["billing-api"]
    }
  ],
  "next_actions": [
    "Run another wave for billing-api or transition with an explicit override reason."
  ]
}
```

Why it makes sense:

The gate logic already exists in `mcp/lib/phase-gates.js`. Today, blocked
transitions surface as `STATE_CONFLICT` errors from `bounty_transition_phase`.
A dedicated read-only explainer would make orchestration and `/bob-status`
clearer without requiring a failed transition attempt.

Tradeoff:

It adds another MCP tool and must be reflected in registry metadata, prompt
contracts, and generated allowed tools.

Priority:

Medium-high for operator experience.

## 6. Add Small Fixture Sessions For Offline Learning

Suggestion:

Create sanitized fixture sessions under a test/docs path:

```text
docs/fixtures/sessions/clean-submit/
docs/fixtures/sessions/no-findings-skip/
docs/fixtures/sessions/pending-wave/
docs/fixtures/sessions/missing-evidence/
```

Each fixture should include realistic but fake artifacts:

```text
state.json
attack_surface.json
coverage.jsonl
findings.jsonl
handoff-w1-a1.json
verified-final.json
evidence-packs.json
grade.json
pipeline-events.jsonl
```

Why it makes sense:

Reading artifact examples is the fastest way to understand the system. Tests
construct many synthetic sessions already, but they are embedded in test code.
Curated fixtures would make the artifact model concrete without exposing real
target data.

Tradeoff:

Fixtures can create maintenance overhead. Keep them minimal and validate them
in tests.

Priority:

High for offline understanding; medium for production runtime.

## 7. Consider A Human-Friendly Session Index

Suggestion:

Maintain or generate an index file per session:

```text
session-index.json
```

Possible contents:

```json
{
  "target_domain": "example.com",
  "session_dir": "...",
  "current_phase": "VERIFY",
  "artifacts": {
    "state": "state.json",
    "attack_surface": "attack_surface.json",
    "findings": "findings.jsonl",
    "final_verification": "verified-final.json"
  },
  "latest_events": ["wave_merged", "phase_transitioned", "verification_written"]
}
```

Why it makes sense:

The session directory contains many files. An index would help humans and tools
navigate without guessing which artifact is current.

Tradeoff:

If written as another authoritative artifact, it could create consistency
problems. Safer version: generate it on demand from existing artifacts.

Priority:

Medium.

## 8. Tighten Prompt-To-Tool Traceability

Suggestion:

For each agent prompt, include a short "artifact contract" block in a consistent
format:

```text
Reads:
  - bounty_read_findings -> findings.jsonl
Writes:
  - bounty_write_verification_round -> verified-final.json
Must not:
  - write verifier markdown directly
```

Why it makes sense:

The information already exists, but it is written in prose and frontmatter.
A consistent block would help future prompt edits and make prompt-contract tests
simpler to maintain.

Tradeoff:

Prompts are already carefully size-limited. The block should be compact or
generated.

Priority:

Medium.

## 9. Add A Developer "Trace One Tool" Walkthrough

Suggestion:

Add a doc page that traces a single tool end to end, for example
`bounty_write_wave_handoff`:

```text
agent prompt
  -> MCP tool schema
  -> tool registry metadata
  -> executeTool validation
  -> waves.js writeWaveHandoff
  -> assignment token validation
  -> JSON and Markdown writes
  -> SubagentStop validation
  -> wave merge consumption
  -> tests
```

Why it makes sense:

This project is easiest to understand through one complete vertical slice.
`bounty_write_wave_handoff` is a good candidate because it touches prompts,
MCP, token provenance, files, hooks, and tests.

Tradeoff:

Documentation maintenance. Keep it focused on one representative path.

Priority:

High for new maintainers.

## 10. Make Report Trust Explicit In `report.md`

Suggestion:

Have the report writer include a small internal footer or comment with source
artifact references:

```text
Generated from:
- verified-final.json
- evidence-packs.json
- chain-attempts.jsonl
- grade.json
```

For no-findings reports, include:

```text
Final verification: 0 reportable findings
Grade: SKIP
Evidence: skipped
```

Why it makes sense:

The system already treats report trust as dependent on final verification,
evidence, and grade. Making that visible in the report helps another human
understand why the report can or cannot be trusted.

Tradeoff:

Bug bounty submissions should stay clean. This could be included as an HTML
comment or a local-only appendix, not necessarily in the final pasted report.

Priority:

Medium.

## 11. Add More Negative Fixtures For Agent Drift

Suggestion:

Add tests and fixtures for common bad behaviors:

- evaluator writes Markdown handoff only
- evaluator marker does not match structured handoff
- balanced verifier drops a finding
- evidence pack includes a token-like string
- grade says `SUBMIT` with no medium-or-higher final reportable
- report exists but grade is missing

Why it makes sense:

Many of these are already tested in `test/mcp-server.test.js`. Curated negative
fixtures would make the failure modes more discoverable and could feed the
future static session explainer.

Tradeoff:

More fixtures mean more files. Keep them short and synthetic.

Priority:

Medium.

## 12. Separate "Runtime Docs" From "Contributor Docs"

Suggestion:

Split documentation into two mental tracks:

```text
docs/operator/
  first-run.md
  status-debug.md
  egress.md

docs/developer/
  architecture.md
  artifact-schemas.md
  adding-a-tool.md
  prompt-contracts.md
  release.md
```

Why it makes sense:

The repo serves two audiences:

- operators running Bob against authorized targets
- contributors changing Bob itself

Mixing those can make onboarding harder. A clearer split would reduce cognitive
load.

Tradeoff:

Docs navigation must stay simple. Too many docs can be worse than too few.

Priority:

Low-medium.

## 13. Add A Lightweight Local TUI Or HTML Dashboard

Suggestion:

Generate a local dashboard from `bounty_read_pipeline_analytics`:

```bash
hacker-bob doctor-session example.com --html
```

The dashboard could show:

- phase timeline
- waves and handoff readiness
- surface coverage
- findings flow
- verification disposition table
- evidence coverage
- tool failures
- egress/geofence warnings

Why it makes sense:

The data already exists. A dashboard would make multi-agent state easier to
inspect without reading raw JSON. It would also be useful during demos and
debugging.

Tradeoff:

This is polish, not core correctness. It should not replace JSON artifacts or
MCP analytics.

Priority:

Low-medium unless operator debugging becomes a major bottleneck.

## 14. Keep Strong Boundaries Around Automatic Egress Rotation

Suggestion:

Keep the current operator-controlled egress model. If adding future automation,
make it recommendation-only by default:

```text
"default egress has repeated first-party failures; operator may resume with --egress gr-residential"
```

Why it makes sense:

Egress changes can affect authorization, rate limits, geofencing, program rules,
and legal/ethical boundaries. The current design is conservative: agents detect
reachability problems and ask the operator rather than silently rotating.

Tradeoff:

Manual intervention slows autonomous runs, but it preserves operator control.

Priority:

High as a design principle.

## 15. Make "Context Is A Product Feature" A First-Class Doc Theme

Suggestion:

Add a short architecture doc specifically about context management:

```text
docs/developer/context-management.md
```

It should explain:

- why the root orchestrator uses summaries
- why evaluators get one assigned brief
- why arrays are capped
- why Markdown is not authoritative
- how telemetry stays metadata-only
- how resume works after context loss

Why it makes sense:

The central technical achievement of this repo is not just "many agents." It is
many agents coordinated through bounded context and structured durable state.
Making that explicit will help future AI-generated changes preserve the
architecture instead of accidentally expanding prompts or stuffing too much data
into agent context.

Tradeoff:

Documentation does not enforce behavior by itself. Pair this with prompt
contract tests around context caps and brief shape.

Priority:

High for long-term agent quality.

\newpage

# FAQ

## Where is the main entry point?

There are several, depending on what you mean:

- CLI entry: `bin/hacker-bob.js`
- installer: `scripts/install.js`
- MCP server: `mcp/server.js`
- `/bob-evaluate` orchestration prompt: `.claude/skills/bob-evaluate/SKILL.md`
- MCP tool registry: `mcp/lib/tool-registry.js`

For runtime behavior, start with `/bob-evaluate` and `mcp/server.js`.

## Why use MCP at all?

Because separate agents need shared memory, validation, and durable state.
Without MCP, everything would depend on chat history and fragile prose. MCP
turns key actions into typed tool calls that write structured local artifacts.

## Why not just let agents write files directly?

Direct file writes create drift. An agent might write malformed JSON, skip a
required field, overwrite someone else's data, or invent state. MCP tools
validate and normalize writes. The write guard blocks direct writes to
MCP-owned artifacts.

## Why JSONL for findings instead of one JSON file?

Append-only logs are safer for multi-step agent work. Each record is one JSON
line. Appending a finding or coverage record does not require rewriting a whole
array and does not risk losing older records if a later write fails.

## Why are Markdown files still present?

They are human/debug mirrors. For example, `findings.md` is easier to read than
`findings.jsonl`, but orchestration should trust `findings.jsonl`.

## What happens if the root chat loses context?

The user can run:

```text
/bob-evaluate resume <domain>
```

The orchestrator reads MCP state and artifacts, sees the current phase and
pending wave, and continues from there.

## What is `pending_wave`?

It means a wave was started but not merged. Evaluators may still be running, or
some handoffs may be missing. Bob should not start another wave or move to
CHAIN while `pending_wave` is set.

## Why forbid same-turn merge after spawning evaluators?

Evaluators run in the background. The root turn that spawns them should not
immediately assume their handoffs exist. The launch-turn barrier prevents the
orchestrator from racing ahead before background work finishes.

## What is a handoff token?

When `bounty_start_wave` creates assignments, it generates a token for each
assigned evaluator. The token hash is stored in `wave-N-assignments.json`; the
plain token is returned only to the orchestrator so it can put it in that
evaluator's prompt. `bounty_write_wave_handoff` verifies the token before accepting
the handoff.

## Why does the evaluator also emit `BOB_AGENT_RUN_DONE`?

The marker lets the SubagentStop hook confirm that the final message is a
proper evaluator completion. The hook then checks that the structured handoff
exists and matches the marker. The marker alone is not enough.

## Who owns `attack_surface.json`?

The surface-discovery agent writes it directly. This is one of the explicitly allowed
agent-owned session files. After that, MCP reads it and validates surface IDs.

## How does Bob avoid repeating work?

Several mechanisms:

- `state.explored`
- `coverage.jsonl`
- dead-end and WAF-blocked endpoint lists
- evaluator brief coverage summaries
- wave merge requeue logic
- finding dedupe keys
- HTTP audit summaries and circuit breaker summaries

## How does Bob decide which surfaces to evaluate?

The surface-discovery agent gives each surface a priority. MCP ranking can compute runtime
ranking from attack surface data, imported traffic, and public intel hints. The
README says ranking is runtime prioritization, not a durable rewrite in normal
status/brief reads.

## What is the difference between coverage and findings?

Coverage records what was tested and what remains promising, blocked, or worth
requeueing. Findings are proven vulnerability claims. Coverage can exist
without findings.

## Why have three verification rounds?

To reduce false positives:

- Brutalist verifier tries to kill weak findings.
- Balanced verifier catches false negatives or over-corrections.
- Final verifier freshly replays reportable survivors.

The final round is the gate for evidence collection.

## Why does evidence come after final verification?

Evidence collection can touch the target again. Bob should collect formal
evidence only for findings that survived final verification, not for every weak
evaluator claim.

## What makes evidence valid?

`evidence-packs.json` must cover every final reportable finding, avoid secrets
and raw sensitive values, stay bounded, avoid duplicate finding IDs, and contain
representative samples plus summaries.

## What determines SUBMIT, HOLD, or SKIP?

The grader scores final survivors on five axes. Code enforces score math and
verdict thresholds:

- `SUBMIT`: score at least 40 and at least one medium-or-higher reportable
  finding
- `HOLD`: score 20-39 when reportability exists
- `SKIP`: score below 20 or no medium-or-higher reportable finding

## Can a no-finding session still reach REPORT?

Yes. If final verification has no reportables, evidence can be skipped, the
grader writes a terminal `SKIP`, and the reporter writes a no-findings closeout.

## Where is auth stored?

In:

```text
~/bounty-agent-sessions/[domain]/auth.json
```

The file is mode `0600`. Agents should not read it directly. They use
`bounty_list_auth_profiles` and `auth_profile` on `bounty_http_scan`.

## Does Bob block private IPs and localhost?

Bob's MCP-scoped HTTP tools require both passing session authority and a public
`target_domain`, so direct localhost/private-IP URLs are not valid first-party
targets for normal HTTP scans. `normal`, `yolo`, and compatible legacy sessions
still permit public
first-party hostnames that resolve to private IPs, which keeps authorized labs,
VPN scopes, and internal programs usable. `paranoid` sessions block those DNS
results by default on direct/default egress unless initialized with
`--allow-internal-hosts`; `--block-internal-hosts` forces the same policy in
other modes. First-party host scope does not protect against DNS rebinding or
proxy-side DNS/routing.

Smart-contract RPC/REST tools use a separate direct-only policy. EVM, SVM,
Aptos, Sui, Substrate, and CosmWasm reads/runners accept only public HTTPS
endpoints from shipped ladders, explicit `endpoints` / `fork_urls`, or
`BOB_<FAMILY>_RPCS_<NETWORK>` env overrides. Bob rejects HTTP, private/internal
host literals, and public hostnames whose DNS answers resolve to private or
link-local addresses during bounded preflight. Bob-owned Node SC reads and EVM
source fetches then pin the HTTPS socket lookup to one of those preflighted
public DNS answers. Fork runners are preflight-only handoff: Bob strips
inherited proxy/RPC/secret env before spawning downstream CLIs, then restores
only runner-created fork URL env or CLI args from preflighted public endpoints;
it does not control or DNS-pin the CLI socket. SC RPC does not use `egress_profile` proxy routing.
Private/localnet RPC remains unsupported by default; Sui/Substrate/CosmWasm
`localnet` may run local-only harness tests, but no localnet RPC endpoint is
accepted without a future per-family opt-in policy. DNS preflight is bounded
before the SC read or runner timeout budget applies. Endpoint evidence and
policy rejections redact credentials and query values.

## What is an egress profile?

A named route for Bob network tools that support managed egress, including HTTP
scan, signup detection, and browser signup. The default profile is direct local
connection. Non-default profiles can point to operator-managed proxies via
environment variable references.

## Why is there no shell scope guard?

The current design puts enforceable target-host policy into MCP HTTP calls and
does not claim Bob-enforced containment for raw Bash surface-discovery. The removed hook
files were permissive compatibility shims, so deleting them makes the installed
surface match the enforcement model. This is tested behavior, not missing code.

## What is `/bob-status`?

A compact, read-only status command. It reads analytics, state summary, wave
status, and key artifacts to tell the operator where the latest or selected
session stands.

## What is `/bob-debug`?

A deeper read-only debugger. It starts with telemetry and analytics, then can
inspect artifacts and narrow transcript windows. With `--deep`, it identifies
policy/refusal failure windows that a developer can replay with the local
policy replay harness.

## What is policy replay?

The `testing/policy-replay/` harness can replay minimized transcript cases
against agent prompts to diagnose false refusals, policy stalls, or unsafe
compliance risks. It is not part of normal evaluating.

## How are generated prompt surfaces kept in sync?

Scripts:

```text
scripts/generate-agent-tools.js
scripts/generate-bountyagent-skill.js
```

Prompt contract tests ensure generated files and registry metadata agree.

## Which tests should I read first?

Start with:

```text
test/prompt-contracts.test.js
test/mcp-server.test.js
test/install-smoke.test.js
test/test-write-guard.py
```

The test names are a good architecture outline.

## What should I trust if Markdown and JSON disagree?

Trust the MCP-owned structured JSON/JSONL artifact. Markdown mirrors are for
humans and debugging.

\newpage

# Glossary

## Agent

A Claude Code subagent with a narrow prompt and tool list.

## Orchestrator

The root `/bob-evaluate` flow. It coordinates agents and state transitions.

## MCP

Model Context Protocol. In Bob, it is the local server that owns structured
state and exposes `bounty_*` tools.

## Surface

An attackable unit from `attack_surface.json`, such as an API, auth flow,
admin panel, upload feature, CMS, GraphQL endpoint, static property, or token
contract artifact.

## Wave

A batch of evaluator assignments. Each assignment maps one agent ID to one surface
ID.

## Handoff

A structured end-of-wave summary written by a evaluator through MCP.

## Coverage

Durable records of endpoint/bug-class/auth-profile tests and whether each was
tested, blocked, promising, needs auth, or should be requeued.

## Finding

A proven vulnerability claim recorded by a evaluator.

## Chain Attempt

A tested hypothesis that findings or handoff notes combine into stronger
impact.

## Verification Round

One of brutalist, balanced, or final. Each round records dispositions for
findings.

## Evidence Pack

Bounded redacted proof for a final reportable finding.

## Grade

The structured SUBMIT/HOLD/SKIP verdict.

## Pipeline Analytics

Metadata-only summary of session health, bottlenecks, and next actions.

\newpage

# File Map Cheat Sheet

## User-Facing Docs

```text
README.md
docs/FIRST_RUN.md
docs/TROUBLESHOOTING.md
docs/ROADMAP.md
CHANGELOG.md
docs/releases/
```

## Claude-Facing Runtime

```text
.claude/skills/
.claude/agents/
.claude/commands/
.claude/hooks/
.claude/rules/
.claude/knowledge/
.claude/bypass-tables/
```

## MCP Core

```text
mcp/server.js
mcp/lib/transport.js
mcp/lib/tool-registry.js
mcp/lib/dispatch.js
mcp/lib/envelope.js
mcp/lib/tool-validation.js
mcp/lib/tools/index.js
```

## MCP State And Pipeline

```text
mcp/lib/paths.js
mcp/lib/storage.js
mcp/lib/session-state.js
mcp/lib/phase-gates.js
mcp/lib/waves.js
mcp/lib/assignments.js
mcp/lib/coverage.js
mcp/lib/findings.js
mcp/lib/chain-attempts.js
mcp/lib/evidence.js
mcp/lib/pipeline-analytics.js
mcp/lib/tool-telemetry.js
```

## HTTP, Auth, Surface-discovery Enrichment

```text
mcp/lib/http-scan.js
mcp/lib/safe-fetch.js
mcp/lib/url-surface.js
mcp/lib/http-records.js
mcp/lib/auth.js
mcp/lib/signup.js
mcp/lib/temp-email.js
mcp/lib/egress-profiles.js
mcp/lib/public-intel.js
mcp/lib/static-artifacts.js
mcp/lib/ranking.js
mcp/lib/assignment-brief.js
mcp/redaction.js
```

## Installer And Lifecycle

```text
bin/hacker-bob.js
install.sh
scripts/install.js
scripts/lifecycle.js
scripts/merge-claude-config.js
scripts/release-check.js
scripts/generate-agent-tools.js
scripts/generate-bountyagent-skill.js
```

## Tests

```text
test/mcp-server.test.js
test/prompt-contracts.test.js
test/install-smoke.test.js
test/cli.test.js
test/package.test.js
test/update-check.test.js
test/policy-replay.test.js
test/test-write-guard.py
```

\newpage

# Final Reading Advice

When reading this repo, do not start by trying to understand every helper
function. Follow the data:

```text
/bob-evaluate
  -> state.json
  -> attack_surface.json
  -> wave assignments
  -> evaluator brief
  -> coverage/findings/handoff
  -> wave merge
  -> chain attempts
  -> verification rounds
  -> evidence packs
  -> grade
  -> report
```

Then follow the enforcement:

```text
tool registry
  -> tool validation
  -> session locks
  -> phase gates
  -> write guard
  -> evaluator stop hook
  -> prompt contract tests
```

If you understand those two paths, the rest of the repo becomes much easier:
install scripts move the framework into place, docs explain the user flow,
telemetry explains failures, and tests keep the contract from drifting.
