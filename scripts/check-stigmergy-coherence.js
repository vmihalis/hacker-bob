#!/usr/bin/env node
"use strict";

// Cycle Y.9 (rev 4.1) — `check:stigmergy-coherence` CI gate (Y-P14c).
//
// Walks the two manifest registries that anchor the Y-P14 coordination
// discipline:
//
//   * `mcp/lib/stigmergic-producers.js` — landed in Y.6 (rev 4.1 defect
//     4: moved forward so ROLE_TRACE_EXPECTATIONS cross-references
//     resolve mechanically).
//   * `mcp/lib/stigmergic-consumers.js` — landed in Y.9 (this cycle).
//
// Mechanical assertions per pair:
//
//   (A) Every manifested producer has at least one manifested consumer
//       reference. Producer's `registered_consumers[]` MUST overlap the
//       consumers manifest by at least one consumer_id.
//
//   (B) Every manifested consumer references its manifested producer at
//       a citable source location. `source_location.file` MUST exist on
//       disk relative to repo root, AND the consumer's `token_or_regex`
//       MUST resolve at that file (string token → substring match;
//       RegExp → regex test).
//
//   (C) No consumer references a non-manifested producer. Every
//       consumer's `producer_id` MUST match an entry in
//       STIGMERGIC_PRODUCERS.
//
// Optional `--fixtures-only <dir>` mode: scans manifests synthesized in a
// fixture corpus instead of the real tree, for FP-rate measurement.
// `--root <dir>` overrides repo root.

const fs = require("fs");
const path = require("path");
const {
  STIGMERGIC_PRODUCERS,
  isKnownProducerId,
} = require("../mcp/lib/stigmergic-producers.js");
const {
  STIGMERGIC_CONSUMERS,
} = require("../mcp/lib/stigmergic-consumers.js");

const ROOT = path.join(__dirname, "..");

function parseArgs(argv) {
  const args = { root: ROOT, fixtures: null, verbose: false };
  for (let i = 2; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === "--root" && argv[i + 1]) {
      args.root = path.resolve(argv[++i]);
    } else if (a === "--fixtures" && argv[i + 1]) {
      args.fixtures = path.resolve(argv[++i]);
    } else if (a === "--verbose" || a === "-v") {
      args.verbose = true;
    }
  }
  return args;
}

function tokenMatches(content, tokenOrRegex) {
  if (tokenOrRegex instanceof RegExp) return tokenOrRegex.test(content);
  if (typeof tokenOrRegex === "string") return content.includes(tokenOrRegex);
  return false;
}

function checkAssertionA(producers, consumers) {
  const violations = [];
  const consumerIds = new Set(consumers.map((c) => c.consumer_id));
  for (const producer of producers) {
    const registered = producer.registered_consumers || [];
    if (registered.length === 0) {
      violations.push({
        kind: "producer_has_no_consumers",
        producer_id: producer.producer_id,
        detail: "registered_consumers[] is empty",
      });
      continue;
    }
    const overlap = registered.filter((id) => consumerIds.has(id));
    if (overlap.length === 0) {
      violations.push({
        kind: "producer_consumers_not_manifested",
        producer_id: producer.producer_id,
        detail: `registered_consumers ${JSON.stringify(registered)} have no entry in STIGMERGIC_CONSUMERS`,
      });
    }
  }
  return violations;
}

function checkAssertionB(consumers, root) {
  const violations = [];
  for (const consumer of consumers) {
    const sourceLoc = consumer.source_location || {};
    const file = sourceLoc.file;
    const tokenOrRegex = sourceLoc.token_or_regex;
    if (typeof file !== "string" || !file) {
      violations.push({
        kind: "consumer_missing_source_file",
        consumer_id: consumer.consumer_id,
        detail: "source_location.file MUST be a non-empty string",
      });
      continue;
    }
    const absPath = path.join(root, file);
    let content;
    try {
      content = fs.readFileSync(absPath, "utf8");
    } catch (err) {
      violations.push({
        kind: "consumer_source_file_missing",
        consumer_id: consumer.consumer_id,
        file,
        detail: `cannot read ${file}: ${err.code || err.message}`,
      });
      continue;
    }
    if (!tokenMatches(content, tokenOrRegex)) {
      violations.push({
        kind: "consumer_token_unresolved",
        consumer_id: consumer.consumer_id,
        file,
        detail: `token_or_regex ${tokenOrRegex instanceof RegExp ? tokenOrRegex.toString() : JSON.stringify(tokenOrRegex)} did not match content`,
      });
    }
  }
  return violations;
}

function checkAssertionC(consumers) {
  const violations = [];
  for (const consumer of consumers) {
    if (!isKnownProducerId(consumer.producer_id)) {
      violations.push({
        kind: "consumer_references_unknown_producer",
        consumer_id: consumer.consumer_id,
        producer_id: consumer.producer_id,
        detail: `producer_id ${JSON.stringify(consumer.producer_id)} is not in STIGMERGIC_PRODUCERS`,
      });
    }
  }
  return violations;
}

function runCoherenceCheck({ producers, consumers, root }) {
  const violations = [
    ...checkAssertionA(producers, consumers),
    ...checkAssertionB(consumers, root),
    ...checkAssertionC(consumers),
  ];
  return violations;
}

function main() {
  const args = parseArgs(process.argv);
  const violations = runCoherenceCheck({
    producers: STIGMERGIC_PRODUCERS,
    consumers: STIGMERGIC_CONSUMERS,
    root: args.root,
  });
  if (violations.length === 0) {
    if (args.verbose) {
      console.log(
        `stigmergy-coherence OK (${STIGMERGIC_PRODUCERS.length} producers × ${STIGMERGIC_CONSUMERS.length} consumers)`,
      );
    }
    process.exit(0);
  }
  console.error(
    `stigmergy-coherence FAIL (${violations.length} violation${violations.length === 1 ? "" : "s"}):`,
  );
  for (const v of violations) {
    console.error(`  - [${v.kind}] ${JSON.stringify(v)}`);
  }
  process.exit(1);
}

if (require.main === module) {
  try {
    main();
  } catch (err) {
    console.error(err && err.stack ? err.stack : String(err));
    process.exit(2);
  }
}

module.exports = {
  runCoherenceCheck,
  checkAssertionA,
  checkAssertionB,
  checkAssertionC,
};
