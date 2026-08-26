#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { buildToolCompositionSnapshot } = require("./lib/tool-composition-contract.js");

const fixture = path.join(__dirname, "..", "test", "fixtures", "tool-composition-contract.json");
fs.writeFileSync(fixture, `${JSON.stringify(buildToolCompositionSnapshot(), null, 2)}\n`);
process.stdout.write(`updated ${path.relative(process.cwd(), fixture)}\n`);
