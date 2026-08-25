#!/usr/bin/env node
"use strict";

// runner-wiring: projection CLI.
//
// usage: node scripts/project-findings.js <payload.json>
// env: BOB_PROJECTION_URL (required), RUNNER_SECRET (required)
//
// Prints one JSON summary line on the final attempt and exits:
//   0  projected (2xx)
//   2  definitive rejection (4xx — payload or capability invalid)
//   3  retries exhausted (5xx / network)
//   64 usage error
//
// Called synchronously from bob_finalize_report via execFileSync; also the
// dispatch service's redrive path.

const fs = require("fs");
const {
  postProjection,
} = require("../mcp/lib/projection-client.js");

function main() {
  const payloadFile = process.argv[2];
  const url = process.env.BOB_PROJECTION_URL;
  const secret = process.env.RUNNER_SECRET;
  if (!payloadFile || !url || !secret) {
    console.error("usage: node scripts/project-findings.js <payload.json> (BOB_PROJECTION_URL and RUNNER_SECRET required)");
    process.exit(64);
  }
  let payload;
  try {
    payload = JSON.parse(fs.readFileSync(payloadFile, "utf8"));
  } catch (error) {
    console.error(JSON.stringify({ error: `payload file unreadable: ${error.message}` }));
    process.exit(64);
  }
  postProjection({ url, secret, payload })
    .then((summary) => {
      console.log(JSON.stringify(summary));
      process.exit(summary.ok ? 0 : 2);
    })
    .catch((error) => {
      console.log(JSON.stringify({ ok: false, error: error.message || String(error) }));
      process.exit(3);
    });
}

main();
