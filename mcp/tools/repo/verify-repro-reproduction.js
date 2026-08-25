"use strict";

const fs = require("fs");
const { repoDockerRun } = require("../../domains/repo/repo-env.js");
const { verifyReproReproduction } = require("../../domains/repo/repro-replay-verifier.js");

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

async function verifyReproReproductionToolHandler(args) {
  // The verifier owns both executions; this wrapper turns the real repoDockerRun's
  // captured-to-disk streams into the {stdout_text, stderr_text} the verifier parses.
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
  return verifyReproReproduction(
    {
      target_domain: args.target_domain,
      finding_id: args.finding_id,
      command: args.command,
      control_ref: args.control_ref,
      control_kind: args.control_kind,
      image_tag: args.image_tag,
      allow_network: args.allow_network,
    },
    { repoDockerRunFn },
  );
}

module.exports = Object.freeze({
  name: "bob_verify_repro_reproduction",
  description:
    "Execution-graded DIFFERENTIAL reproduction gate for OSS native-code memory-safety findings. " +
    "Re-runs the SAME PoC command in two fresh sandboxed containers — the vulnerable tree and the " +
    "upstream-fix tree (via the O-P3 differential checkout) — and parses the sanitizer bytes it " +
    "captured itself (never a self-reported crash field). Mints a verified_pass ONLY on a genuine " +
    "flip: a sanitizer crash with a /src root-cause frame on the vulnerable tree that is QUIET on the " +
    "fix tree. A printf-forged banner fires identically on both trees and is refuted; so is an " +
    "over-broad or unattributable crash. verified_pass is written only to the MCP-write-only, " +
    "audit-graded repro-verified.jsonl that the O-P4 claim gate requires. Object-auth's sibling: this " +
    "is bob_verify_composition_path's pattern applied to native-code reproduction.",
  inputSchema: {
    type: "object",
    properties: {
      target_domain: { type: "string", description: "The repo session domain (repo-<name>-<hash>)." },
      finding_id: { type: "string", description: "The finding the reproduction attests (e.g. F-3)." },
      command: {
        type: "array",
        items: { type: "string" },
        minItems: 1,
        maxItems: 64,
        description:
          "The PoC build+run command as a token array (e.g. [\"sh\",\"-lc\",\"build the ASAN harness && run the crashing input\"]). " +
          "Re-run verbatim on both the vulnerable and the upstream-fix tree.",
      },
      control_ref: {
        type: "string",
        description: "The upstream-fix commit ref; the differential control tree is materialized at this checkout.",
      },
      control_kind: {
        type: "string",
        description: "Differential checkout kind (default upstream_fix).",
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
    required: ["target_domain", "finding_id", "command", "control_ref"],
  },
  handler: verifyReproReproductionToolHandler,
  // Differential reproduction is a VERIFICATION activity (independent re-execution
  // to confirm a flip), not an evaluator one — so this mirrors verify-composition-path's
  // placement, NOT repo-docker-run's. Deliberately OUTSIDE evaluator-shared: the
  // evaluator records the finding + repro_command_argv recipe + its single docker-run
  // evidence ref; the verifier re-runs the differential here to mint the verified_pass
  // (and the web evaluator never carries an OSS-only tool). Writing the audit-graded
  // ledger is an MCP-owned write; the audit-grade blocks only the agent Write tool.
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
