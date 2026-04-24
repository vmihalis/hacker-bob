"use strict";

const TOOL_MODULES = Object.freeze([
  require("./http-scan.js"),
  require("./read-http-audit.js"),
  require("./start-wave.js"),
]);

module.exports = {
  TOOL_MODULES,
};
