"use strict";

const {
  TECHNIQUE_SUMMARY_ITEM_MAX_CHARS,
} = require("./technique-packs.js");

/**
 * OSS root-cause family record.
 *
 * Mirrors the I5 invariant-template corpus shape, but for repo-bound OSS
 * source/sink patterns:
 *   {
 *     id,
 *     family,
 *     name,
 *     description,
 *     lens_affinity[],
 *     source_sink_signature[],
 *     witness: { project, cve_or_commit, file_symbol, controlling_fields, impact }
 *   }
 *
 * The two families absent from the shipped oss_native_code prose blob are:
 *   - crypto_ordering: decrypt / parse before MAC or signature verification.
 *   - validate_vs_consume: length/size/index consumed before validation.
 *
 * Witness rows intentionally carry public technical facts only: project,
 * public id or "disclosed", file/symbol, controlling fields, and impact.
 */
const FAMILIES = Object.freeze([
  Object.freeze({
    id: "OSS-FAM-ALLOCATION-SIZE-MATH-001",
    family: "allocation_size_math",
    name: "Allocation-size math crosses untrusted length",
    description: "Allocation or resize math derives from an attacker-controlled count, width, or element size before overflow and maximum-size checks prove the allocation matches the later write.",
    lens_affinity: Object.freeze(["code_surface_scout", "taint_trace", "fuzz_run"]),
    source_sink_signature: Object.freeze(["count_field", "element_size", "allocation_call", "write_site"]),
    witness: Object.freeze({
      project: "libtirpc",
      cve_or_commit: "disclosed",
      file_symbol: "__xdrrec_getrec",
      controlling_fields: Object.freeze(["record_length", "fragment_length", "heap_record_buffer"]),
      impact: "heap out-of-bounds write from record-size consumption before the allocation/write boundary is proven safe",
    }),
  }),
  Object.freeze({
    id: "OSS-FAM-BOUNDS-CHECK-001",
    family: "bounds_check",
    name: "Unchecked length or index crosses a fixed buffer",
    description: "A length, index, or element count from network, file, or API input reaches a fixed buffer or array access before an adjacent bounds check constrains it.",
    lens_affinity: Object.freeze(["code_surface_scout", "taint_trace", "fuzz_run"]),
    source_sink_signature: Object.freeze(["length_field", "fixed_buffer", "copy_or_index_op", "bounds_check_site"]),
    witness: Object.freeze({
      project: "rpcbind",
      cve_or_commit: "disclosed",
      file_symbol: "rpcbaddrlist",
      controlling_fields: Object.freeze(["unbounded_xdr_string", "buf[128]", "copy_length"]),
      impact: "stack overflow when an unbounded XDR string is copied into buf[128]",
    }),
  }),
  Object.freeze({
    id: "OSS-FAM-CRYPTO-ORDERING-001",
    family: "crypto_ordering",
    name: "Decrypt-before-authenticate ordering",
    description: "Ciphertext or attacker-controlled plaintext bytes are decrypted, padded, or parsed before the MAC or signature is verified.",
    lens_affinity: Object.freeze(["code_surface_scout", "taint_trace", "fuzz_run"]),
    source_sink_signature: Object.freeze(["decrypt_call", "mac_verify_call", "ordering_between_them"]),
    fixture_only: true,
    portfolio_status: "fixture-only; Bob's portfolio has zero crypto-ordering findings",
    witness: Object.freeze({
      project: "OpenSSL SSLv3 CBC record processing",
      cve_or_commit: "CVE-2014-3566",
      file_symbol: "ssl/s3_pkt.c:ssl3_get_record",
      controlling_fields: Object.freeze(["CBC_padding", "MAC_check", "decrypt_then_verify_order"]),
      impact: "padding-oracle plaintext recovery in the classic MAC-then-encrypt ordering class",
    }),
  }),
  Object.freeze({
    id: "OSS-FAM-DOUBLE-FREE-UAF-001",
    family: "double_free_use_after_free",
    name: "Cleanup path reuses or frees stale ownership",
    description: "An object, buffer, or context changes owner across error, callback, or reconnect paths, then a stale pointer is freed or dereferenced again.",
    lens_affinity: Object.freeze(["code_surface_scout", "taint_trace", "fuzz_run"]),
    source_sink_signature: Object.freeze(["owner_transfer_site", "cleanup_path", "stale_pointer_use", "second_free_or_deref"]),
    witness: Object.freeze({
      project: "OSS native-code protocol-memory fixture",
      cve_or_commit: "disclosed",
      file_symbol: "async callback / queued PDU cleanup",
      controlling_fields: Object.freeze(["context_owner", "queued_pdu_reference", "cleanup_branch"]),
      impact: "use-after-free or double-free when lifetime ownership is not reset consistently across cleanup paths",
    }),
  }),
  Object.freeze({
    id: "OSS-FAM-INTEGER-TRUNCATION-001",
    family: "integer_truncation",
    name: "Sentinel or length truncation changes loop bounds",
    description: "A sentinel, declared length, or computed size narrows or wraps across integer widths before it controls a loop, allocation, or copy.",
    lens_affinity: Object.freeze(["code_surface_scout", "taint_trace", "fuzz_run"]),
    source_sink_signature: Object.freeze(["declared_length", "narrowing_cast", "loop_bound", "size_check_site"]),
    witness: Object.freeze({
      project: "LibreDWG",
      cve_or_commit: "disclosed",
      file_symbol: "read_literal_length",
      controlling_fields: Object.freeze(["0xFFFF_literal_length", "loop_bound", "termination_check"]),
      impact: "unbounded loop when the literal-length sentinel is consumed as a loop-control value",
    }),
  }),
  Object.freeze({
    id: "OSS-FAM-LIFETIME-OWNERSHIP-001",
    family: "lifetime_ownership",
    name: "Ownership handoff leaves stale aliases",
    description: "A queue, callback, cache, or refcount path keeps an alias after ownership moves, so later cleanup or dispatch observes a stale object lifetime.",
    lens_affinity: Object.freeze(["code_surface_scout", "taint_trace", "fuzz_run"]),
    source_sink_signature: Object.freeze(["ownership_handoff", "alias_storage", "refcount_or_queue", "later_cleanup_or_dispatch"]),
    witness: Object.freeze({
      project: "OSS native-code protocol-memory fixture",
      cve_or_commit: "disclosed",
      file_symbol: "callback context / reconnect queue",
      controlling_fields: Object.freeze(["context_lifetime", "queue_reference", "refcount_or_owner_flag"]),
      impact: "stale alias survives an ownership handoff and can become a use-after-free or cleanup-path corruption",
    }),
  }),
  Object.freeze({
    id: "OSS-FAM-NUL-PATH-HANDLING-001",
    family: "nul_path_handling",
    name: "Path or NUL normalization mismatch",
    description: "A path, string, or NUL-bearing byte sequence is validated under one representation and consumed under another.",
    lens_affinity: Object.freeze(["code_surface_scout", "taint_trace", "fuzz_run"]),
    source_sink_signature: Object.freeze(["path_bytes", "normalization_site", "validation_site", "filesystem_or_parser_consumer"]),
    witness: Object.freeze({
      project: "OSS native-code path-handling fixture",
      cve_or_commit: "disclosed",
      file_symbol: "path normalization / consumer boundary",
      controlling_fields: Object.freeze(["raw_path_bytes", "nul_or_separator", "normalized_path"]),
      impact: "validation bypass or unintended file effect when the consumed path differs from the checked path",
    }),
  }),
  Object.freeze({
    id: "OSS-FAM-SIGNEDNESS-CONVERSION-001",
    family: "signedness_conversion",
    name: "Signed/unsigned boundary changes safety checks",
    description: "A signed value is checked in one domain, converted to an unsigned size or index, and then used by a copy, loop, allocation, or parser sink.",
    lens_affinity: Object.freeze(["code_surface_scout", "taint_trace", "fuzz_run"]),
    source_sink_signature: Object.freeze(["signed_source_field", "unsigned_sink_size", "conversion_site", "range_check_site"]),
    witness: Object.freeze({
      project: "LibreDWG",
      cve_or_commit: "disclosed",
      file_symbol: "read_literal_length",
      controlling_fields: Object.freeze(["literal_length", "0xFFFF_sentinel", "loop_counter_width"]),
      impact: "malformed literal length crosses integer-domain handling and can drive excessive loop work",
    }),
  }),
  Object.freeze({
    id: "OSS-FAM-STATE-MACHINE-CONFUSION-001",
    family: "state_machine_confusion",
    name: "Parser state transition consumes stale fields",
    description: "A parser or protocol state machine advances after a malformed field, early return, or partial reset, then consumes stale state in the next transition.",
    lens_affinity: Object.freeze(["code_surface_scout", "taint_trace", "fuzz_run"]),
    source_sink_signature: Object.freeze(["state_field", "transition_site", "early_return_or_partial_reset", "next_consumer"]),
    witness: Object.freeze({
      project: "netatalk afpd Spotlight RPC",
      cve_or_commit: "disclosed",
      file_symbol: "Spotlight RPC length handling",
      controlling_fields: Object.freeze(["rpc_length", "spotlight_request_state", "consumer_transition"]),
      impact: "heap out-of-bounds access when RPC length/state is consumed before validation completes",
    }),
  }),
  Object.freeze({
    id: "OSS-FAM-VALIDATE-VS-CONSUME-001",
    family: "validate_vs_consume",
    name: "Consume-before-bound length ordering",
    description: "An untrusted length, size, or index is consumed by allocation, copy, loop, or parser state before the bounds check proves the value safe.",
    lens_affinity: Object.freeze(["code_surface_scout", "taint_trace", "fuzz_run"]),
    source_sink_signature: Object.freeze(["length_field", "consuming_op", "bound_check_site", "entry_to_consumer_path"]),
    witness: Object.freeze({
      project: "rpcbind",
      cve_or_commit: "disclosed",
      file_symbol: "rpcbaddrlist",
      controlling_fields: Object.freeze(["unbounded_xdr_string", "buf[128]", "bound_check_site"]),
      impact: "stack overflow when an XDR string is consumed before the fixed buffer bound is enforced",
    }),
    additional_witnesses: Object.freeze([
      Object.freeze({
        project: "netatalk afpd",
        cve_or_commit: "disclosed",
        file_symbol: "Spotlight RPC length handling",
        controlling_fields: Object.freeze(["rpc_length", "heap_buffer", "validation_site"]),
        impact: "heap out-of-bounds access when the Spotlight RPC length is consumed before validation",
      }),
      Object.freeze({
        project: "libtirpc",
        cve_or_commit: "disclosed",
        file_symbol: "__xdrrec_getrec",
        controlling_fields: Object.freeze(["record_length", "heap_record_buffer", "fragment_validation"]),
        impact: "heap out-of-bounds write when the record length reaches the consumer before validation",
      }),
      Object.freeze({
        project: "LibreDWG",
        cve_or_commit: "disclosed",
        file_symbol: "read_literal_length",
        controlling_fields: Object.freeze(["0xFFFF_literal_length", "loop_bound", "validation_site"]),
        impact: "unbounded loop from consuming the literal-length sentinel before the bound is enforced",
      }),
    ]),
  }),
]);

const OSS_ROOTCAUSE_FAMILIES = FAMILIES;

const FAMILIES_BY_LENS = (() => {
  const map = new Map();
  for (const family of FAMILIES) {
    for (const lens of family.lens_affinity) {
      if (!map.has(lens)) map.set(lens, []);
      map.get(lens).push(family);
    }
  }
  return map;
})();

const SUPPORTED_FAMILIES = Object.freeze(Array.from(new Set(FAMILIES.map((family) => family.family))).sort());

function isPlainObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

function getFamiliesForLens(lens) {
  if (typeof lens !== "string") return [];
  return (FAMILIES_BY_LENS.get(lens) || []).slice();
}

function stringValues(value) {
  if (value == null) return [];
  const values = Array.isArray(value) ? value : [value];
  return values
    .filter((item) => item != null)
    .map((item) => String(item));
}

function surfaceSignalText(surface) {
  if (!isPlainObject(surface)) return "";
  const fields = [
    "id",
    "title",
    "description",
    "surface_type",
    "language",
    "file_path",
    "symbol",
    "sink_kind",
    "task_lens",
    "capability_pack",
    "endpoints",
    "interesting_params",
    "bug_class_hints",
    "high_value_flows",
    "evidence",
    "source_sink_signature",
  ];
  const values = [];
  for (const field of fields) {
    values.push(...stringValues(surface[field]));
  }
  return values.join("\n").toLowerCase();
}

function signatureNeedles(signature) {
  const value = String(signature).toLowerCase();
  return Object.freeze([
    value,
    value.replace(/_/g, " "),
    value.replace(/_/g, "-"),
  ]);
}

function matchedSignatureTerms(family, surfaceText) {
  if (!surfaceText) return [];
  return family.source_sink_signature.filter((signature) => (
    signatureNeedles(signature).some((needle) => needle && surfaceText.includes(needle))
  ));
}

function capBriefString(value, maxChars = TECHNIQUE_SUMMARY_ITEM_MAX_CHARS) {
  const text = String(value);
  if (text.length <= maxChars) return text;
  if (maxChars <= 3) return text.slice(0, maxChars);
  return `${text.slice(0, maxChars - 3)}...`;
}

function witnessBrief(witness, additionalCount = 0) {
  const suffix = additionalCount > 0 ? ` (+${additionalCount} public witnesses)` : "";
  return capBriefString(
    `${witness.project} ${witness.cve_or_commit} ${witness.file_symbol}: ${witness.impact}${suffix}`,
  );
}

function familyBrief(family) {
  return capBriefString(
    `${family.family}: ${family.name}. Witness: ${witnessBrief(family.witness, (family.additional_witnesses || []).length)}`,
  );
}

function effectiveLens(surface, options) {
  if (options && typeof options.lens === "string") return options.lens;
  if (surface && typeof surface.task_lens === "string") return surface.task_lens;
  if (surface && typeof surface.taskLens === "string") return surface.taskLens;
  return "unknown";
}

function suggestFamiliesForSurface(surface, options) {
  if (!isPlainObject(surface)) {
    throw new TypeError("surface must be an object");
  }
  const lens = effectiveLens(surface, options);
  const families = getFamiliesForLens(lens);
  if (families.length === 0) {
    return {
      lens,
      family_count: 0,
      suggestions: [],
      unmatched_lens: true,
      summary_limits: {
        item_max_chars: TECHNIQUE_SUMMARY_ITEM_MAX_CHARS,
        limit: 0,
        returned: 0,
      },
    };
  }
  const limit = options && Number.isInteger(options.limit) && options.limit > 0
    ? Math.min(options.limit, 25)
    : families.length;
  const surfaceText = surfaceSignalText(surface);
  const suggestions = families
    .map((family, index) => ({
      family,
      index,
      matchedSignature: matchedSignatureTerms(family, surfaceText),
    }))
    .sort((left, right) => (
      right.matchedSignature.length - left.matchedSignature.length
        || left.index - right.index
    ))
    .slice(0, limit)
    .map(({ family, matchedSignature }) => {
      return {
        family_id: family.id,
        family: family.family,
        name: family.name,
        matched_signature: matchedSignature,
        witness: witnessBrief(family.witness, (family.additional_witnesses || []).length),
        brief: familyBrief(family),
        ...(family.fixture_only === true ? { fixture_only: true } : {}),
      };
    });
  return {
    lens,
    family_count: families.length,
    suggestions,
    unmatched_lens: false,
    summary_limits: {
      item_max_chars: TECHNIQUE_SUMMARY_ITEM_MAX_CHARS,
      limit,
      returned: suggestions.length,
    },
  };
}

module.exports = {
  OSS_ROOTCAUSE_FAMILIES,
  SUPPORTED_FAMILIES,
  getFamiliesForLens,
  suggestFamiliesForSurface,
};
