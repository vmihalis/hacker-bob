"use strict";

const crypto = require("node:crypto");
const path = require("node:path");

const binding = require(path.join(
  __dirname,
  "..",
  "..",
  "build",
  "Release",
  "native_dispatch_custodian.node",
));

const mode = process.argv[2] || "normal";

async function run() {
  if (mode === "queue") {
    for (let index = 0; index < 4; index += 1) {
      crypto.pbkdf2("fixture", "fixture", 5000000, 32, "sha256", () => {});
    }
  }
  const completion = binding.dispatchFixtureExact();
  if (mode === "busy") {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 500);
  }
  await completion;
  if (mode === "replay") {
    let rejected = false;
    try {
      binding.dispatchFixtureExact();
    } catch {
      rejected = true;
    }
    if (!rejected) process.exitCode = 71;
  }
}

run().catch(() => {
  process.exitCode = 70;
});
