"use strict";

const { hashCanonicalJson } = require("./verification/verification-contracts.js");
const { parseGraphqlSdl, looksLikeGraphqlSdl } = require("./graphql-sdl-parser.js");
const { parsePostmanCollection, looksLikePostmanCollection } = require("./postman-parser.js");

const HTTP_METHODS = Object.freeze([
  "get",
  "put",
  "post",
  "delete",
  "options",
  "head",
  "patch",
  "trace",
]);

const PREFERRED_REQUEST_CONTENT_TYPES = Object.freeze([
  "application/json",
  "application/x-www-form-urlencoded",
  "multipart/form-data",
]);

const PREFERRED_RESPONSE_CONTENT_TYPES = Object.freeze([
  "application/json",
]);

function isPlainObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

function resolveLocalRef(refString, doc) {
  if (typeof refString !== "string" || !refString.startsWith("#/")) return null;
  const segments = refString.slice(2).split("/").map((segment) =>
    segment.replace(/~1/g, "/").replace(/~0/g, "~"),
  );
  let node = doc;
  for (const segment of segments) {
    if (node == null) return null;
    node = node[segment];
  }
  return node === undefined ? null : node;
}

function resolveRefsDeep(node, doc, visited) {
  if (Array.isArray(node)) {
    return node.map((item) => resolveRefsDeep(item, doc, visited));
  }
  if (!isPlainObject(node)) return node;
  if (typeof node.$ref === "string" && node.$ref.startsWith("#/")) {
    if (visited.has(node.$ref)) {
      return { $ref_cycle: node.$ref };
    }
    const resolved = resolveLocalRef(node.$ref, doc);
    if (resolved == null) {
      return { $ref_unresolved: node.$ref };
    }
    const nextVisited = new Set(visited);
    nextVisited.add(node.$ref);
    return resolveRefsDeep(resolved, doc, nextVisited);
  }
  const result = {};
  for (const key of Object.keys(node)) {
    result[key] = resolveRefsDeep(node[key], doc, visited);
  }
  return result;
}

function pickPreferredContentType(contentObject, preferred) {
  if (!isPlainObject(contentObject)) return null;
  const types = Object.keys(contentObject).sort();
  if (types.length === 0) return null;
  for (const candidate of preferred) {
    if (types.includes(candidate)) return candidate;
  }
  return types[0];
}

function normalizeSchemaShape(schema, doc) {
  if (!isPlainObject(schema)) return null;
  const resolved = resolveRefsDeep(schema, doc, new Set());
  if (!isPlainObject(resolved)) return null;
  const shape = {};
  if (typeof resolved.type === "string") {
    shape.type = resolved.type;
  }
  if (Array.isArray(resolved.required)) {
    shape.required = [...resolved.required].sort();
  }
  if (isPlainObject(resolved.properties)) {
    const properties = {};
    for (const key of Object.keys(resolved.properties).sort()) {
      const propValue = resolved.properties[key];
      properties[key] = isPlainObject(propValue) && typeof propValue.type === "string"
        ? { type: propValue.type }
        : {};
    }
    shape.properties = properties;
  }
  if (isPlainObject(resolved.items) && typeof resolved.items.type === "string") {
    shape.items = { type: resolved.items.type };
  }
  if (Array.isArray(resolved.enum)) {
    shape.enum_count = resolved.enum.length;
  }
  return Object.keys(shape).length === 0 ? null : shape;
}

function normalizeSecurity(securityArray) {
  if (!Array.isArray(securityArray)) {
    return { schemes: [], none_allowed: false };
  }
  const schemeSet = new Set();
  let noneAllowed = false;
  for (const requirement of securityArray) {
    if (!isPlainObject(requirement)) continue;
    const keys = Object.keys(requirement);
    if (keys.length === 0) {
      noneAllowed = true;
      continue;
    }
    for (const key of keys) {
      schemeSet.add(key);
    }
  }
  return {
    schemes: Array.from(schemeSet).sort(),
    none_allowed: noneAllowed,
  };
}

function dereferenceParameter(rawParam, doc) {
  if (!isPlainObject(rawParam)) return null;
  if (typeof rawParam.$ref === "string" && rawParam.$ref.startsWith("#/")) {
    const resolved = resolveLocalRef(rawParam.$ref, doc);
    return isPlainObject(resolved) ? resolved : null;
  }
  return rawParam;
}

function normalizeParameters(rawParams, doc) {
  if (!Array.isArray(rawParams)) return [];
  const result = [];
  for (const rawParam of rawParams) {
    const param = dereferenceParameter(rawParam, doc);
    if (!isPlainObject(param)) continue;
    if (typeof param.name !== "string" || typeof param.in !== "string") continue;
    result.push({
      name: param.name,
      in: param.in,
      required: param.required === true,
      schema_type: isPlainObject(param.schema) && typeof param.schema.type === "string"
        ? param.schema.type
        : "any",
      schema_shape: normalizeSchemaShape(param.schema, doc),
    });
  }
  return result;
}

function normalizeRequestBody(requestBody, doc) {
  if (!isPlainObject(requestBody)) return null;
  const resolved = (typeof requestBody.$ref === "string" && requestBody.$ref.startsWith("#/"))
    ? resolveLocalRef(requestBody.$ref, doc)
    : requestBody;
  if (!isPlainObject(resolved)) return null;
  const chosenType = pickPreferredContentType(resolved.content, PREFERRED_REQUEST_CONTENT_TYPES);
  if (!chosenType) return null;
  const mediaSchema = isPlainObject(resolved.content[chosenType])
    ? resolved.content[chosenType].schema
    : null;
  return {
    name: "body",
    in: "body",
    required: resolved.required === true,
    schema_type: isPlainObject(mediaSchema) && typeof mediaSchema.type === "string"
      ? mediaSchema.type
      : "any",
    schema_shape: normalizeSchemaShape(mediaSchema, doc),
    content_type: chosenType,
  };
}

function normalizeResponses(responses, doc) {
  if (!isPlainObject(responses)) return {};
  const result = {};
  for (const status of Object.keys(responses).sort()) {
    const response = responses[status];
    const resolved = isPlainObject(response)
      && typeof response.$ref === "string"
      && response.$ref.startsWith("#/")
      ? resolveLocalRef(response.$ref, doc)
      : response;
    if (!isPlainObject(resolved)) continue;
    if (!isPlainObject(resolved.content)) {
      result[status] = { content_type: null, shape: null };
      continue;
    }
    const chosenType = pickPreferredContentType(resolved.content, PREFERRED_RESPONSE_CONTENT_TYPES);
    if (!chosenType) {
      result[status] = { content_type: null, shape: null };
      continue;
    }
    const mediaSchema = isPlainObject(resolved.content[chosenType])
      ? resolved.content[chosenType].schema
      : null;
    result[status] = {
      content_type: chosenType,
      shape: normalizeSchemaShape(mediaSchema, doc),
    };
  }
  return result;
}

function sortParams(params) {
  return params.slice().sort((a, b) => {
    const byIn = a.in.localeCompare(b.in);
    if (byIn !== 0) return byIn;
    return a.name.localeCompare(b.name);
  });
}

function buildContract(doc, pathKey, method, operation, pathLevelParams, globalSecurity) {
  const operationParams = Array.isArray(operation.parameters) ? operation.parameters : [];
  const combinedParams = [...(pathLevelParams || []), ...operationParams];
  const params = normalizeParameters(combinedParams, doc);
  const bodyContract = normalizeRequestBody(operation.requestBody, doc);
  if (bodyContract) {
    params.push(bodyContract);
  }
  const sortedParams = sortParams(params);
  const security = Array.isArray(operation.security) ? operation.security : globalSecurity;
  const claimedAuth = normalizeSecurity(security);
  const contract = {
    endpoint: pathKey,
    method: method.toUpperCase(),
    claimed_auth: claimedAuth,
    claimed_params: sortedParams,
    claimed_response_shape: normalizeResponses(operation.responses, doc),
  };
  contract.contract_hash = hashCanonicalJson(contract);
  return contract;
}

function parseOpenApi3(parsedDoc) {
  const warnings = [];
  if (!isPlainObject(parsedDoc)) {
    return {
      schema_format: "openapi-3",
      contracts: [],
      source_doc_hash: null,
      parser_warnings: ["root_not_object"],
    };
  }
  if (typeof parsedDoc.openapi !== "string" || !parsedDoc.openapi.startsWith("3.")) {
    warnings.push(`unexpected_openapi_version:${parsedDoc.openapi || "missing"}`);
  }
  const paths = isPlainObject(parsedDoc.paths) ? parsedDoc.paths : {};
  const globalSecurity = Array.isArray(parsedDoc.security) ? parsedDoc.security : null;
  const contracts = [];
  for (const pathKey of Object.keys(paths).sort()) {
    const pathItem = paths[pathKey];
    if (!isPlainObject(pathItem)) continue;
    const pathLevelParams = Array.isArray(pathItem.parameters) ? pathItem.parameters : [];
    for (const method of HTTP_METHODS) {
      const operation = pathItem[method];
      if (!isPlainObject(operation)) continue;
      try {
        const contract = buildContract(
          parsedDoc,
          pathKey,
          method,
          operation,
          pathLevelParams,
          globalSecurity,
        );
        contracts.push(contract);
      } catch (err) {
        warnings.push(`contract_build_failed:${method.toUpperCase()}:${pathKey}:${err.message}`);
      }
    }
  }
  contracts.sort((a, b) => {
    const byEndpoint = a.endpoint.localeCompare(b.endpoint);
    if (byEndpoint !== 0) return byEndpoint;
    return a.method.localeCompare(b.method);
  });
  return {
    schema_format: "openapi-3",
    contracts,
    source_doc_hash: hashCanonicalJson(parsedDoc),
    parser_warnings: warnings,
  };
}

function parseSchemaDoc(rawDoc) {
  if (typeof rawDoc !== "string") {
    throw new TypeError("rawDoc must be a string");
  }
  let parsedJson = null;
  let jsonError = null;
  try {
    parsedJson = JSON.parse(rawDoc);
  } catch (err) {
    jsonError = err;
  }
  if (parsedJson != null) {
    if (
      isPlainObject(parsedJson)
      && typeof parsedJson.openapi === "string"
      && parsedJson.openapi.startsWith("3.")
    ) {
      return parseOpenApi3(parsedJson);
    }
    if (looksLikePostmanCollection(parsedJson)) {
      return parsePostmanCollection(parsedJson);
    }
    return {
      schema_format: null,
      contracts: [],
      source_doc_hash: null,
      parser_warnings: ["unsupported_format"],
    };
  }
  if (looksLikeGraphqlSdl(rawDoc)) {
    return parseGraphqlSdl(rawDoc);
  }
  return {
    schema_format: null,
    contracts: [],
    source_doc_hash: null,
    parser_warnings: [`json_parse_failed:${jsonError ? jsonError.message : "unknown"}`],
  };
}

module.exports = {
  parseSchemaDoc,
  parseOpenApi3,
  parseGraphqlSdl,
  parsePostmanCollection,
};
