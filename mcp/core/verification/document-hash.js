"use strict";

const {
  cloneJson,
  hashCanonicalJson,
} = require("./verification-contracts.js");

function hashDocumentExcluding(document, fields) {
  const copy = cloneJson(document);
  for (const field of fields) {
    delete copy[field];
  }
  return hashCanonicalJson(copy);
}

function withDocumentHash(document, fieldName) {
  const copy = cloneJson(document);
  copy[fieldName] = hashDocumentExcluding(copy, [fieldName]);
  return copy;
}

module.exports = {
  hashDocumentExcluding,
  withDocumentHash,
};
