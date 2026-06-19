"use strict";

const fs = require("fs");
const {
  sessionNucleusFromState,
} = require("./governance-contracts.js");
const {
  sessionNucleusPath,
} = require("./paths.js");
const {
  readSessionStateStrict,
} = require("./session-state-store.js");
const {
  readFileUtf8,
} = require("./storage.js");

function readSessionNucleus(domain) {
  const filePath = sessionNucleusPath(domain);
  if (fs.existsSync(filePath)) {
    const raw = readFileUtf8(filePath, { label: "session-nucleus.json" });
    return JSON.parse(raw);
  }
  return sessionNucleusFromState(readSessionStateStrict(domain).state);
}

module.exports = {
  readSessionNucleus,
};
