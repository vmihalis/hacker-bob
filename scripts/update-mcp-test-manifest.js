#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");

const ROOT = path.join(__dirname, "..");
const MANIFEST_PATH = path.join(ROOT, "test", "mcp-test-manifest.json");
const PACKAGE_PATH = path.join(ROOT, "package.json");

function main() {
  const manifest = JSON.parse(fs.readFileSync(MANIFEST_PATH, "utf8"));
  if (!Array.isArray(manifest)) {
    throw new Error("test/mcp-test-manifest.json must contain an array");
  }

  const pkg = JSON.parse(fs.readFileSync(PACKAGE_PATH, "utf8"));
  const packageScriptText = Object.values(pkg.scripts || {}).join("\n");
  const packageTests = new Set(
    Array.from(packageScriptText.matchAll(/test\/[\w.-]+\.test\.js/g), (match) => match[0]),
  );
  const onDiskTests = fs.readdirSync(path.join(ROOT, "test"))
    .filter((name) => /\.test\.js$/.test(name))
    .map((name) => `test/${name}`)
    .sort();

  const updated = Array.from(new Set(manifest));
  const included = new Set([...updated, ...packageTests]);
  for (const file of onDiskTests) {
    if (!included.has(file)) {
      updated.push(file);
      included.add(file);
    }
  }

  fs.writeFileSync(MANIFEST_PATH, `${JSON.stringify(updated, null, 2)}\n`);
  process.stdout.write(`Updated ${path.relative(ROOT, MANIFEST_PATH)} (${updated.length} entries).\n`);
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    console.error(error.message || String(error));
    process.exit(1);
  }
}
