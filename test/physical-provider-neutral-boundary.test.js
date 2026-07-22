"use strict";

// PH-X3 boundary lock. The provider-neutral broker and artifact-vault packages
// must not physically host, require, or export any provider-specific (Chameleon)
// code. Provider adapters live in the provider package and are selected at the
// MCP composition root through the data-only provider-profile catalog (scalar
// ids/digests), never through a cross-package require or a provider-named export.
// This is the mechanical earn-criterion for the frozen
// provider_neutral_runtime_store_package_boundary_missing blocker: it fails red
// while the coupling exists and passes only once the boundary is real.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");

// Generic, provider-neutral package source roots (non-recursive top-level .js +
// their lib/). A provider name must never appear in these as a filename, a
// require specifier, or a package export.
const GENERIC_SOURCE_DIRS = [
  "packages/bob-instrument-broker/lib",
  "packages/bob-artifact-vault/lib",
  "packages/bob-artifact-vault",
];
const GENERIC_PACKAGE_JSON = [
  "packages/bob-instrument-broker/package.json",
  "packages/bob-artifact-vault/package.json",
];

const PROVIDER_TOKEN = /chameleon/i;
const PROVIDER_REQUIRE = /require\(\s*["'][^"']*chameleon[^"']*["']\s*\)/i;

function jsFilesIn(dir) {
  const abs = path.join(ROOT, dir);
  if (!fs.existsSync(abs)) return [];
  return fs.readdirSync(abs)
    .filter((name) => name.endsWith(".js"))
    .map((name) => ({ rel: path.relative(ROOT, path.join(abs, name)), abs: path.join(abs, name), name }));
}

test("provider-neutral packages host no provider-specific source file", () => {
  const offenders = [];
  for (const dir of GENERIC_SOURCE_DIRS) {
    for (const file of jsFilesIn(dir)) {
      if (PROVIDER_TOKEN.test(file.name)) offenders.push(file.rel);
    }
  }
  assert.deepEqual(offenders, [],
    `provider-neutral packages must not contain a provider-named module: ${offenders.join(", ")}`);
});

test("provider-neutral packages do not require a provider-specific package", () => {
  const offenders = [];
  for (const dir of GENERIC_SOURCE_DIRS) {
    for (const file of jsFilesIn(dir)) {
      const src = fs.readFileSync(file.abs, "utf8");
      if (PROVIDER_REQUIRE.test(src)) offenders.push(file.rel);
    }
  }
  assert.deepEqual(offenders, [],
    `provider-neutral packages must not require a Chameleon package; offenders: ${offenders.join(", ")}`);
});

test("provider-neutral package manifests export no provider-specific module", () => {
  const offenders = [];
  for (const manifest of GENERIC_PACKAGE_JSON) {
    const abs = path.join(ROOT, manifest);
    if (!fs.existsSync(abs)) continue;
    const exportsBlock = JSON.stringify(JSON.parse(fs.readFileSync(abs, "utf8")).exports ?? {});
    if (PROVIDER_TOKEN.test(exportsBlock)) offenders.push(manifest);
  }
  assert.deepEqual(offenders, [],
    `provider-neutral package manifests must not export a Chameleon module: ${offenders.join(", ")}`);
});
