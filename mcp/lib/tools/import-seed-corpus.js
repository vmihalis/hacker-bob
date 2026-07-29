"use strict";

const { importSeedCorpus } = require("../seed-corpus-store.js");

module.exports = Object.freeze({
  name: "bob_import_seed_corpus",
  description:
    "Import a batch of generated fuzz seed inputs into a session-owned seed corpus for the OSS " +
    "native-fuzz lane (the grammar-aware arm). The evaluator perceives the target's harness input " +
    "contract, generates diverse VALID grammar-spanning inputs that byte-mutation cannot synthesize " +
    "from cold (string literals, comma-lists, nested calls, structured frames matching the harness), " +
    "and imports them here; bob_repo_docker_run then mounts the newest corpus at /seeds and the fuzz " +
    "recipes stage it into the libFuzzer/afl corpus. Content only; path imports rejected. Each seed " +
    "is redacted and capped. Generate inputs that match the HARNESS contract for THIS target — do not " +
    "encode knowledge of a specific bug or trigger.",
  inputSchema: {
    "type": "object",
    "properties": {
      "target_domain": {
        "type": "string",
        "description": "Repo session target_domain derived by bob_init_repo_session.",
      },
      "seeds": {
        "type": "array",
        "description": "The generated seed inputs (1-512). Each item is a string, or {content, name?}. No file is read.",
        "items": {
          "anyOf": [
            { "type": "string" },
            { "type": "object", "properties": { "content": { "type": "string" }, "name": { "type": "string" } }, "required": ["content"] },
          ],
        },
        "minItems": 1,
        "maxItems": 512,
      },
      "source": {
        "type": "string",
        "enum": ["grammar_gen", "operator", "llm_synth"],
        "description": "Provenance of the seeds. Defaults to grammar_gen.",
      },
      "label": {
        "type": "string",
        "description": "Optional short label (e.g. the perceived target class / harness contract).",
      },
    },
    "required": ["target_domain", "seeds"],
  },
  handler: importSeedCorpus,
  // Orchestrator-only, mirroring bob_import_harness: grammar-seed generation is a
  // per-target SETUP activity (perceive the harness contract once -> generate -> import);
  // evaluators then fuzz with the /seeds mount automatically. global_preapproval:false
  // because the orchestrator-only-mutator invariant forbids it from the global set.
  role_bundles: ["orchestrator"],
  mutating: true,
  global_preapproval: false,
  network_access: false,
  browser_access: false,
  scope_required: false,
  sensitive_output: false,
  session_artifacts_written: ["seed-corpus", "seed-corpus.jsonl"],
  importSeedCorpus,
});
