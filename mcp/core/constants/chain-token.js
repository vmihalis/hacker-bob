"use strict";

function normalizeChainToken(value) {
  if (value == null) return null;
  const normalized = String(value).trim().toLowerCase().replace(/[\s-]+/g, "_");
  return normalized || null;
}

module.exports = Object.freeze({ normalizeChainToken });
