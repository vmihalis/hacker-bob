"use strict";

const {
  createTransformRegistry,
  runTransform,
} = require("./lib/transform-worker.js");
const {
  PROVIDER_RESPONSE_VAULT_ASSURANCE,
  PROVIDER_RESPONSE_VAULT_VERSION,
  assertProviderResponseIngestReceipt,
  assertProviderResponseIngestReceiptPort,
  assertProviderResponseRawCustodyReceipt,
  assertProviderResponseRawCustodyReceiptPort,
  assertProviderResponseSemanticValidationPort,
  assertProviderResponseSink,
  assertProviderResponseSinkCommit,
  commitProviderResponseIngestReceipt,
  commitProviderResponseRawCustody,
  commitProviderResponseSink,
  createProviderResponseIngestReceiptPort,
  createProviderResponseRawCustodyReceiptPort,
  createProviderResponseSink,
  readProviderResponseIngestReceipt,
  readProviderResponseRawCustodyReceipt,
  readProviderResponseSinkCommit,
} = require("./lib/provider-response-vault.js");
const {
  NATIVE_PROVIDER_RESPONSE_RECORD_HEADER_BYTES,
  NATIVE_PROVIDER_RESPONSE_VAULT_ASSURANCE,
  NATIVE_PROVIDER_RESPONSE_VAULT_VERSION,
  assertNativeProviderResponseSink,
  cancelNativeProviderResponseSink,
  consumeNativeProviderResponseRecord,
  nativeProviderResponseSinkWriteDescriptor,
  prepareNativeProviderResponseSink,
  revokeNativeProviderResponseSinkWriteDescriptor,
} = require("./lib/native-provider-response-vault.js");

// This worker barrel is provider-neutral: it exposes only raw-custody, sink,
// ingest, and the provider-neutral semantic-validation-PORT interface. Provider
// semantic validators (e.g. Chameleon get_app_version) live in their provider
// package and are wired to this vault at the composition root.
module.exports = {
  NATIVE_PROVIDER_RESPONSE_RECORD_HEADER_BYTES,
  NATIVE_PROVIDER_RESPONSE_VAULT_ASSURANCE,
  NATIVE_PROVIDER_RESPONSE_VAULT_VERSION,
  PROVIDER_RESPONSE_VAULT_ASSURANCE,
  PROVIDER_RESPONSE_VAULT_VERSION,
  assertProviderResponseIngestReceipt,
  assertProviderResponseIngestReceiptPort,
  assertProviderResponseRawCustodyReceipt,
  assertProviderResponseRawCustodyReceiptPort,
  assertProviderResponseSemanticValidationPort,
  assertProviderResponseSink,
  assertProviderResponseSinkCommit,
  assertNativeProviderResponseSink,
  cancelNativeProviderResponseSink,
  commitProviderResponseIngestReceipt,
  commitProviderResponseRawCustody,
  commitProviderResponseSink,
  consumeNativeProviderResponseRecord,
  createProviderResponseIngestReceiptPort,
  createProviderResponseRawCustodyReceiptPort,
  createProviderResponseSink,
  createTransformRegistry,
  nativeProviderResponseSinkWriteDescriptor,
  prepareNativeProviderResponseSink,
  readProviderResponseIngestReceipt,
  readProviderResponseRawCustodyReceipt,
  readProviderResponseSinkCommit,
  revokeNativeProviderResponseSinkWriteDescriptor,
  runTransform,
};
