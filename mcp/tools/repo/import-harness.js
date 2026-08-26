"use strict";

const { importHarness } = require("../../core/harness-store.js");

module.exports = Object.freeze({
  name: "bob_import_harness",
  description:
    "Import a libFuzzer harness (a source file defining LLVMFuzzerTestOneInput) into " +
    "session-owned harnesses/ so the OSS native-fuzz lane can build + fuzz a target whose " +
    "repo ships no harness of its own (harnesses commonly live in OSS-Fuzz, not the project). " +
    "Content only; filesystem path imports are rejected. Stored content is redacted and capped. " +
    "Once imported, bob_repo_inventory reports native_fuzz_shape and bob_repo_prepare_env emits " +
    "the fuzz commands; bob_repo_docker_run stages the harness into the build.",
  inputSchema: {
    "type": "object",
    "properties": {
      "target_domain": {
        "type": "string",
        "description": "Repo session target_domain derived by bob_init_repo_session.",
      },
      "language": {
        "type": "string",
        "enum": ["c", "cpp"],
        "description": "Harness source language. Defaults to cpp.",
      },
      "content": {
        "type": "string",
        "maxLength": 200000,
        "description": "The harness source defining LLVMFuzzerTestOneInput. No file is read.",
      },
      "source": {
        "type": "string",
        "enum": ["operator", "oss_fuzz_ingest", "llm_synth"],
        "description": "Provenance of the harness. Defaults to operator.",
      },
      "source_url": {
        "type": "string",
        "description": "Optional provenance URL (e.g. the OSS-Fuzz path). Stored only; never fetched.",
      },
      "target_includes": {
        "type": "array",
        "items": { "type": "string" },
        "description": "Optional headers the harness includes (provenance only).",
      },
    },
    "required": ["target_domain", "content"],
  },
  handler: importHarness,
  role_bundles: ["orchestrator"],
  mutating: true,
  // Orchestrator-only mutator: NOT globally pre-approved (matches its sibling repo
  // tools bob_repo_prepare_env / bob_repo_inventory / bob_init_repo_session). The
  // operator approves it per-call; the prompt-contracts invariant forbids an
  // orchestrator-only mutator from sitting in the global pre-approved set.
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["harnesses", "harnesses.jsonl"],
  importHarness,
});
