"use strict";

const fs = require("fs");
const { repoDockerRun } = require("../repo-env.js");
const { verifyOracleDifferential } = require("../repro-replay-verifier.js");

// Bounded read of a captured run stream (repo-runs/<run_id>.{stdout,stderr}, ≤16 MB
// per the O-P3 cap). The verifier parses these bytes itself; we never trust a
// self-reported crash field.
function readCapture(filePath) {
  try {
    return filePath ? fs.readFileSync(filePath, "utf8") : "";
  } catch {
    return "";
  }
}

async function verifyOracleDifferentialToolHandler(args) {
  // The verifier owns both executions; this wrapper turns the real repoDockerRun's
  // captured-to-disk streams into the {stdout_text, stderr_text} the verifier parses.
  // repoDockerRun honors the OE1 checkout_patch the verifier supplies on each run.
  const repoDockerRunFn = async (runArgs) => {
    const r = await repoDockerRun(runArgs);
    return {
      run_id: r.run_id,
      exit_code: r.exit_code,
      timed_out: r.timed_out === true,
      error: typeof r.error === "string" ? r.error : undefined,
      stdout_text: readCapture(r.stdout_path),
      stderr_text: readCapture(r.stderr_path),
    };
  };
  return verifyOracleDifferential(
    {
      target_domain: args.target_domain,
      finding_id: args.finding_id,
      command: args.command,
      vuln_patch: args.vuln_patch,
      fix_ref: args.fix_ref,
      fix_patch: args.fix_patch,
      vuln_ref: args.vuln_ref,
      vuln_kind: args.vuln_kind,
      fix_kind: args.fix_kind,
      image_tag: args.image_tag,
      allow_network: args.allow_network,
    },
    { repoDockerRunFn },
  );
}

module.exports = Object.freeze({
  name: "bob_verify_oracle_differential",
  description:
    "Execution-graded SOUND oracle differential for ASAN-INVISIBLE value-state findings — the invariant-from-diff " +
    "sibling of bob_verify_repro_reproduction. For a known-fix target, the agent derives the invariant the fix " +
    "enforces and crafts two unified diffs that insert the SAME repo-rooted invariant probe (a heap OOB on a " +
    "detected violation) at the result site of each tree. This tool re-runs the SAME command in two fresh " +
    "sandboxed containers — the vulnerable tree (vuln_patch via self_patch) and the upstream-fix tree (fix_patch " +
    "via upstream_fix) — and parses the sanitizer bytes it captured itself. Mints a verified_pass (value_state_" +
    "confirmed) ONLY on a genuine flip: the probe faults with a repo-attributable /src frame on the vulnerable " +
    "tree and is QUIET on the fix tree (the invariant FAILS on the vuln, HOLDS on the fix). A probe that faults " +
    "on both, or roots only in libc/system frames, is refuted; a degraded fix build is inconclusive. verified_pass " +
    "is written only to the MCP-write-only, audit-graded repro-verified.jsonl the O-P4 claim gate requires.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string", description: "The repo session domain (repo-<name>-<hash>)." },
      finding_id: { type: "string", description: "The finding the differential attests (e.g. F-3)." },
      command: {
        type: "array",
        items: { type: "string" },
        minItems: 1,
        maxItems: 64,
        description:
          "The build+run command as a token array (e.g. [\"sh\",\"-lc\",\"build the ASAN harness && run the value-state input\"]). " +
          "Re-run verbatim against both the vuln-patched and the fix-patched tree.",
      },
      vuln_patch: {
        type: "string",
        description:
          "Unified diff inserting the invariant probe (a repo-rooted heap OOB on violation) at the vuln tree's result site; " +
          "applied via self_patch over the base ref (defaults to fix_ref so the vuln tree is the inverse of the fix tree).",
      },
      fix_ref: {
        type: "string",
        description: "The upstream-fix commit ref; the fix control tree is materialized at this checkout.",
      },
      fix_patch: {
        type: "string",
        description:
          "Unified diff inserting the SAME invariant probe at the fix tree's result site; the fix's own guard upholds the " +
          "invariant so the probe stays quiet, producing the differential flip.",
      },
      vuln_ref: {
        type: "string",
        description: "Optional base ref the vuln_patch applies onto (default: fix_ref).",
      },
      vuln_kind: {
        type: "string",
        description: "Differential checkout kind for the vuln tree (default self_patch).",
      },
      fix_kind: {
        type: "string",
        description: "Differential checkout kind for the fix tree (default upstream_fix).",
      },
      image_tag: {
        type: "string",
        description: "Optional session-derived image tag override (must match the O-D6 session tag).",
      },
      allow_network: {
        type: "boolean",
        description: "Allow build-time network for the re-runs (default false; toolchain is in the image).",
      },
    },
    required: ["target_domain", "finding_id", "command", "vuln_patch", "fix_ref", "fix_patch"],
  },
  handler: verifyOracleDifferentialToolHandler,
  // Same placement + classification as bob_verify_repro_reproduction: a VERIFICATION
  // activity (independent two-tree re-execution to confirm a flip), outside
  // evaluator-shared. Minting the audit-graded repro-verified.jsonl is an MCP-owned
  // write; the audit-grade blocks only the agent Write tool.
  role_bundles: ["verifier", "evidence"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: true,
  required_session_axes: ["repo"],
  session_artifacts_written: ["repro-verified.jsonl", "repo-command-runs.jsonl", "repo-runs/", "repo-checkouts/"],
});
