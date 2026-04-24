# Hunting Rules

These global rules are always active and intentionally small. Detailed tactics belong in the hunter agent or MCP-owned hunter brief.

---

## Universal Guardrails

Stay inside the program scope. Read the in-scope assets, out-of-scope assets, excluded bug classes, and safe-harbor language before any target interaction. Treat third-party services as out of scope unless the program explicitly includes them.

Use Bob MCP tools for durable hunt state. MCP-owned artifacts are authoritative for orchestration, including findings, handoffs, coverage, imported traffic, request audit, public intel, static artifacts, and static scan results. Do not manually create, repair, or backfill those files with Bash or Write.

Do not hunt theoretical bugs. A finding must describe something an attacker can do now against a real target with concrete security impact. Weak leads without exploitability or user/business harm should be killed quickly.

Validate before recording. Prove the issue live with exact request and response evidence, then record it through `bounty_record_finding`; do not save informal findings for later.

Report only verified impact. Severity follows the demonstrated outcome, not the bug class name or a speculative chain.

Prefer assigned, high-value surfaces first: auth, admin, user data, money movement, uploads, key material, and real observed traffic from the hunter brief.

Respect MCP safety feedback. Coverage, dead ends, WAF blocks, audit summaries, and circuit-breaker summaries exist to avoid duplicate testing and unsafe request loops.
