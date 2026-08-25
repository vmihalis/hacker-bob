"use strict";

const { hashCanonicalJson } = require("./verification/verification-contracts.js");

const POSTMAN_AUTH_SCHEME_PREFIX = "postman_auth";
const PATH_VARIABLE_PATTERN = /^:(\w+)$/;

function isPlainObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

function looksLikePostmanCollection(value) {
  if (!isPlainObject(value)) return false;
  if (!Array.isArray(value.item)) return false;
  if (!isPlainObject(value.info)) return false;
  if (typeof value.info.schema === "string"
    && /postman.*collection.*v?2/i.test(value.info.schema)) {
    return true;
  }
  return typeof value.info.name === "string";
}

function flattenItems(items, accumulator) {
  if (!Array.isArray(items)) return;
  for (const item of items) {
    if (!isPlainObject(item)) continue;
    if (Array.isArray(item.item)) {
      flattenItems(item.item, accumulator);
      continue;
    }
    if (isPlainObject(item.request)) {
      accumulator.push(item);
    }
  }
}

function normalizePath(rawSegments) {
  if (!Array.isArray(rawSegments) || rawSegments.length === 0) return null;
  const normalized = rawSegments.map((segment) => {
    if (typeof segment !== "string") return null;
    const variableMatch = segment.match(PATH_VARIABLE_PATTERN);
    if (variableMatch) return `{${variableMatch[1]}}`;
    return segment;
  }).filter((segment) => segment != null);
  if (normalized.length === 0) return null;
  return `/${normalized.join("/")}`;
}

function pathFromRaw(rawUrl) {
  if (typeof rawUrl !== "string" || rawUrl.length === 0) return null;
  try {
    const parsed = new URL(rawUrl);
    const path = parsed.pathname || "";
    if (path.length === 0) return null;
    return path.replace(/:(\w+)/g, "{$1}");
  } catch (_err) {
    if (rawUrl.startsWith("/")) {
      const queryIndex = rawUrl.indexOf("?");
      const path = queryIndex >= 0 ? rawUrl.slice(0, queryIndex) : rawUrl;
      return path.replace(/:(\w+)/g, "{$1}");
    }
    return null;
  }
}

function extractEndpoint(url) {
  if (typeof url === "string") return pathFromRaw(url);
  if (!isPlainObject(url)) return null;
  const fromArray = normalizePath(url.path);
  if (fromArray) return fromArray;
  return pathFromRaw(url.raw);
}

function paramsFromUrl(url) {
  const params = [];
  if (!isPlainObject(url)) return params;
  if (Array.isArray(url.variable)) {
    for (const variable of url.variable) {
      if (!isPlainObject(variable) || typeof variable.key !== "string") continue;
      params.push({
        name: variable.key,
        in: "path",
        required: true,
        schema_type: "string",
        schema_shape: null,
      });
    }
  }
  if (Array.isArray(url.query)) {
    for (const query of url.query) {
      if (!isPlainObject(query) || typeof query.key !== "string") continue;
      params.push({
        name: query.key,
        in: "query",
        required: query.disabled !== true,
        schema_type: "string",
        schema_shape: null,
      });
    }
  }
  return params;
}

function paramsFromHeaders(headers) {
  const params = [];
  if (!Array.isArray(headers)) return params;
  for (const header of headers) {
    if (!isPlainObject(header) || typeof header.key !== "string") continue;
    if (header.disabled === true) continue;
    if (/^content-type$/i.test(header.key)) continue;
    if (/^authorization$/i.test(header.key)) continue;
    params.push({
      name: header.key,
      in: "header",
      required: false,
      schema_type: "string",
      schema_shape: null,
    });
  }
  return params;
}

function inferJsonShape(body) {
  if (Array.isArray(body)) {
    return {
      type: "array",
      items: body.length > 0 ? inferJsonShape(body[0]) : null,
    };
  }
  if (!isPlainObject(body)) {
    if (typeof body === "string") return { type: "string" };
    if (typeof body === "number") return { type: "number" };
    if (typeof body === "boolean") return { type: "boolean" };
    if (body === null) return { type: "null" };
    return null;
  }
  const properties = {};
  for (const key of Object.keys(body).sort()) {
    const value = body[key];
    if (value == null) {
      properties[key] = { type: "null" };
    } else if (typeof value === "string") {
      properties[key] = { type: "string" };
    } else if (typeof value === "number") {
      properties[key] = { type: "number" };
    } else if (typeof value === "boolean") {
      properties[key] = { type: "boolean" };
    } else if (Array.isArray(value)) {
      properties[key] = { type: "array" };
    } else if (isPlainObject(value)) {
      properties[key] = { type: "object" };
    }
  }
  return { type: "object", properties };
}

function bodyParamFromRequest(body) {
  if (!isPlainObject(body)) return null;
  const mode = typeof body.mode === "string" ? body.mode : null;
  if (mode == null) return null;
  if (mode === "raw" && typeof body.raw === "string" && body.raw.length > 0) {
    let parsed = null;
    try {
      parsed = JSON.parse(body.raw);
    } catch (_err) {
      // Not JSON — body is opaque text
    }
    return {
      name: "body",
      in: "body",
      required: true,
      schema_type: parsed !== null ? "object" : "string",
      schema_shape: parsed !== null ? inferJsonShape(parsed) : null,
      content_type: isPlainObject(body.options) && isPlainObject(body.options.raw)
        && typeof body.options.raw.language === "string"
        ? `application/${body.options.raw.language}`
        : (parsed !== null ? "application/json" : "text/plain"),
    };
  }
  if (mode === "urlencoded" || mode === "formdata") {
    return {
      name: "body",
      in: "body",
      required: true,
      schema_type: "object",
      schema_shape: null,
      content_type: mode === "urlencoded"
        ? "application/x-www-form-urlencoded"
        : "multipart/form-data",
    };
  }
  if (mode === "graphql") {
    return {
      name: "body",
      in: "body",
      required: true,
      schema_type: "object",
      schema_shape: null,
      content_type: "application/json",
    };
  }
  return null;
}

function deriveAuth(itemAuth, collectionAuth) {
  const auth = isPlainObject(itemAuth) ? itemAuth : (isPlainObject(collectionAuth) ? collectionAuth : null);
  if (auth == null) return { schemes: [], none_allowed: false };
  if (typeof auth.type !== "string" || auth.type.length === 0) {
    return { schemes: [], none_allowed: false };
  }
  if (auth.type === "noauth") return { schemes: [], none_allowed: true };
  return {
    schemes: [`${POSTMAN_AUTH_SCHEME_PREFIX}:${auth.type}`],
    none_allowed: false,
  };
}

function responseShapeFromExamples(responses) {
  if (!Array.isArray(responses) || responses.length === 0) return {};
  const result = {};
  for (const response of responses) {
    if (!isPlainObject(response)) continue;
    if (typeof response.code !== "number") continue;
    const statusKey = String(response.code);
    if (result[statusKey]) continue;
    let contentType = null;
    if (Array.isArray(response.header)) {
      for (const header of response.header) {
        if (!isPlainObject(header) || typeof header.key !== "string") continue;
        if (/^content-type$/i.test(header.key)
          && typeof header.value === "string") {
          contentType = header.value.split(";")[0].trim();
          break;
        }
      }
    }
    let shape = null;
    if (typeof response.body === "string" && response.body.length > 0) {
      try {
        const parsed = JSON.parse(response.body);
        shape = inferJsonShape(parsed);
      } catch (_err) {
        shape = null;
      }
    }
    result[statusKey] = {
      content_type: contentType,
      shape,
    };
  }
  return result;
}

function buildContract(item, collectionAuth) {
  const request = item.request;
  if (!isPlainObject(request)) return null;
  const method = typeof request.method === "string" ? request.method.toUpperCase() : "GET";
  const endpoint = extractEndpoint(request.url);
  if (endpoint == null) return null;
  const params = [
    ...paramsFromUrl(request.url),
    ...paramsFromHeaders(request.header),
  ];
  const bodyParam = bodyParamFromRequest(request.body);
  if (bodyParam) params.push(bodyParam);
  params.sort((a, b) => {
    const byIn = a.in.localeCompare(b.in);
    if (byIn !== 0) return byIn;
    return a.name.localeCompare(b.name);
  });
  const contract = {
    endpoint,
    method,
    claimed_auth: deriveAuth(request.auth, collectionAuth),
    claimed_params: params,
    claimed_response_shape: responseShapeFromExamples(item.response),
  };
  contract.contract_hash = hashCanonicalJson(contract);
  return contract;
}

function parsePostmanCollection(parsedJson) {
  const warnings = [];
  if (!looksLikePostmanCollection(parsedJson)) {
    return {
      schema_format: "postman",
      contracts: [],
      source_doc_hash: null,
      parser_warnings: ["not_a_postman_collection"],
    };
  }
  const items = [];
  flattenItems(parsedJson.item, items);
  const collectionAuth = isPlainObject(parsedJson.auth) ? parsedJson.auth : null;
  const contracts = [];
  for (const item of items) {
    try {
      const contract = buildContract(item, collectionAuth);
      if (contract) contracts.push(contract);
    } catch (err) {
      warnings.push(`contract_build_failed:${item.name || "<unnamed>"}:${err.message}`);
    }
  }
  contracts.sort((a, b) => {
    const byEndpoint = a.endpoint.localeCompare(b.endpoint);
    if (byEndpoint !== 0) return byEndpoint;
    return a.method.localeCompare(b.method);
  });
  return {
    schema_format: "postman",
    contracts,
    source_doc_hash: hashCanonicalJson(parsedJson),
    parser_warnings: warnings,
  };
}

module.exports = {
  parsePostmanCollection,
  looksLikePostmanCollection,
};
