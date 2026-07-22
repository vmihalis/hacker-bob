"use strict";

const {
  runNucleiScan,
  NUCLEI_SEVERITIES,
} = require("../offensive-nuclei-producer.js");

module.exports = Object.freeze({
  name: "bob_nuclei_scan",
  description:
    "Nuclei template scan (PR7) — DETECTION-ONLY, the FIRST tool to run inside the hardened wide-open offensive container. Runs nuclei against ONE in-scope target_url and returns a bounded LEAD summary (findings_count, counts by severity, and capped lists of matched template-ids + matched-at endpoints). " +
    "LEADS, NOT PROOF: a nuclei template match is a heuristic, so this tool CANNOT mint a signed offensive-runs row (its oracle never returns positive AND it is deliberately absent from the demonstrated-severity ceiling registry). Triage a lead and re-prove it through a real signing producer: an OOB-suspect lead via bob_oob_mint + bob_oob_poll (MEDIUM), a reflected-XSS lead via bob_http_xss_reflect / bob_http_xss_confirm, an IDOR lead via bob_http_idor_confirm. " +
    "OAST FORCED OFF: nuclei's interactsh/OAST is hard-disabled (-no-interactsh) because nuclei's interactsh correlation scheme is incompatible with Bob's OOB sink; OOB must be proven via the Bob mint/poll path, never via nuclei's interactsh. " +
    "SAFETY: the URL is scope-validated at dispatch AND re-checked inside the runner before any spawn; output is secret-scanned before any lead reaches you; the run consumes the shared per-session offensive-run budget and is recorded as a CONTAINER_RUN row in http-audit. " +
    "INERT-UNTIL-PROVISIONED: returns blocked_by_infra:offensive_image_unavailable until the operator re-mints the digest-pinned arsenal image to include the nuclei binary (scripts/build-offensive-image.sh) — it ships dormant and runs only after provisioning.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string", description: "The session scope domain (audit + scope ownership)." },
      target_url: {
        type: "string",
        description: "The single in-scope URL to scan. Scope-validated at dispatch and re-checked in the runner; an out-of-scope URL is rejected before any container spawn.",
      },
      severity: {
        type: "array",
        items: { type: "string", enum: [...NUCLEI_SEVERITIES] },
        maxItems: 6,
        description: "Optional nuclei severities to include (maps to -severity). Default: nuclei's own default set.",
      },
      tags: {
        type: "array",
        items: { type: "string", pattern: "^[a-z0-9][a-z0-9_-]{0,39}$" },
        maxItems: 20,
        description: "Optional nuclei template tags to include (maps to -tags), e.g. cve, ssrf, exposure.",
      },
    },
    required: ["target_domain", "target_url"],
    additionalProperties: false,
  },
  handler: runNucleiScan,
  // Narrow on purpose: granted ONLY to the web evaluator, never to read-only/verifier/
  // evidence roles (mirrors the other offensive tools). check:authority-inventory
  // asserts the narrow grant.
  role_bundles: ["evaluator-web"],
  // Runs a container that issues real target traffic + consumes the offensive-run budget,
  // and writes a CONTAINER_RUN audit row — a session-state mutation, so mutating:true.
  mutating: true,
  global_preapproval: false,
  network_access: true,
  browser_access: false,
  scope_required: true,
  // target_url is scope-validated at dispatch (in addition to the runner's internal
  // AIM-check) — declared here so an out-of-scope URL is rejected before the handler runs.
  scope_url_fields: ["target_url"],
  sensitive_output: true,
  // DETECTION-only: never signs an offensive-runs row. The runner's reservation records a
  // CONTAINER_RUN row in http-audit.jsonl (nuclei egress IS target traffic, unlike the OOB
  // sink) so the circuit breaker accounts for it.
 session_artifacts_written: ["http-audit.jsonl"],
  required_session_axes: ["url"],
});
