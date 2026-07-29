"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const ROOT = path.resolve(__dirname, "..");

test("source-only package excludes its compiled test fixture", () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8"));
  assert.ok(!manifest.files.some((entry) => entry === "dist" || entry.startsWith("dist/")));
  const source = fs.readFileSync(path.join(ROOT, "native", "lifecycle_custodian.c"), "utf8");
  assert.match(source, /define exactly one lifecycle custodian build gate/u);
  assert.match(source, /--test-only-lifecycle-custodian-v1/u);
  assert.doesNotMatch(source, /\/dev\/fd/u);
});
