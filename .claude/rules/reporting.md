# Reporting Rules

These global rules keep reports concise. Detailed report structure belongs in `report-writer`.

---

## Universal Guardrails

Report only in-scope behavior. The affected asset, endpoint, account role, and data type must be inside the program scope and allowed by the policy.

Use MCP-owned artifacts as the source of truth. Findings, verification rounds, grade verdicts, handoffs, coverage, imported traffic, request audit, public intel, static artifacts, and static scan results must be read through Bob MCP tools or their approved agent prompts, not manually rewritten.

Do not write theoretical impact. Use concrete language: "An attacker can [action] by [method]." Avoid "could", "may", "might", and speculative chain language unless the chain was verified.

Every reportable finding needs exact proof. Include the request, response evidence, auth profile or account role used, and the observed impact.

Severity must match verified impact. Use the final verification and grading output rather than the hunter's original claim.

Do not manually edit Bob session artifacts. Report prose can be written by `report-writer`, but authoritative JSON/JSONL state must remain MCP-owned.

Keep the final report short and triage-friendly: impact first, reproduction steps next, then evidence, severity rationale, and remediation.
