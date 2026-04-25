# Hunting Rules

These global rules are always active and intentionally small. Detailed tactics belong in the hunter agent or MCP-owned hunter brief.

---

## Universal Guardrails

Read the program's in-scope assets, excluded bug classes, and safe-harbor language before any target interaction so you know what is reportable. Bob may freely scan any third-party host needed to chain or prove an exploit; only the eventual finding has to land on an in-scope asset with the program's allowed impact.

Use Bob MCP tools for durable hunt state. MCP-owned artifacts are authoritative for orchestration, including findings, handoffs, coverage, imported traffic, request audit, public intel, static artifacts, and static scan results. Do not manually create, repair, or backfill those files with Bash or Write.

Do not hunt theoretical bugs. A finding must describe something an attacker can do now against a real target with concrete security impact. Weak leads without exploitability or user/business harm should be killed quickly.

Validate before recording. Prove the issue live with exact request and response evidence, then record it through `bounty_record_finding`; do not save informal findings for later.

Report only verified impact. Severity follows the demonstrated outcome, not the bug class name or a speculative chain.

Prefer assigned, high-value surfaces first: auth, admin, user data, money movement, uploads, key material, and real observed traffic from the hunter brief.

Respect MCP safety feedback. Coverage, dead ends, WAF blocks, audit summaries, and circuit-breaker summaries exist to avoid duplicate testing and unsafe request loops.
