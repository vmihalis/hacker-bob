#!/usr/bin/env node
"use strict";

const KIMI_ADAPTER = require("../adapters/kimi");

KIMI_ADAPTER.render({ check: process.argv.includes("--check") });
