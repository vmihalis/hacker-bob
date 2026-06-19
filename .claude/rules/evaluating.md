# Evaluation Rules

These global rules are always active and intentionally small. Detailed tactics belong in the evaluator agent or MCP-owned evaluator brief.

---

## Universal Guardrails

Read the program's in-scope assets, excluded bug classes, and safe-harbor language before any target interaction so you know what is reportable. Bob's scoped MCP HTTP tools only send requests to the target domain or its subdomains; use public intel, imported traffic, or operator-approved external tooling for third-party research, and keep the eventual finding on an in-scope asset with the program's allowed impact.

Use Bob MCP tools for durable evaluate state. MCP-owned artifacts are authoritative for orchestration, including findings, handoffs, coverage, technique attempts, imported traffic, request audit, public intel, static artifacts, and static scan results. Do not manually create, repair, or backfill those files with Bash or Write.

Do not evaluate theoretical bugs. A finding must describe something an attacker can do now against a real target with concrete security impact. Weak leads without impact viability or user/business harm should be killed quickly.

Validate before recording. Prove the issue live with exact request and response evidence, then record it through `bob_record_candidate_claim`; do not save informal findings for later.

Report only verified impact. Severity follows the demonstrated outcome, not the bug class name or a speculative chain.

Prefer assigned, high-value surfaces first: auth, admin, user data, money movement, uploads, key material, and real observed traffic from the evaluator brief.

Respect MCP safety feedback. Coverage, dead ends, WAF blocks, audit summaries, and circuit-breaker summaries exist to avoid duplicate testing and unsafe request loops.

Smart-contract surfaces require an impact hypothesis before stopping. "Audit reports this fixed", "function is admin/role/governance-gated", "trusted relayer/DVN/oracle handles this", and "existing test passes" are starting points, not termination conditions. The MCP server rejects `surface_status: complete` on a `smart_contract` surface unless a finding is recorded for that surface or `bypass_attempts[]` has at least one entry citing a `trust_assumptions[*].bypass_conditions` condition. If a needed harness is unavailable, record it in `blocked_harness_runs[]` with a `kind` and set `surface_status: partial`.
