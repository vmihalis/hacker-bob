"use strict";

const NATIVE_SOURCE_EXTENSIONS = Object.freeze(new Set([
  ".c",
  ".cc",
  ".cpp",
  ".cxx",
  ".h",
  ".hh",
  ".hpp",
]));

module.exports = {
  NATIVE_SOURCE_EXTENSIONS,
};
