"use strict";

const { hashCanonicalJson } = require("./verification/verification-contracts.js");

const PUNCT = new Set(["{", "}", "(", ")", "[", "]", ":", "!", "=", ",", "@", "&", "|"]);

const SCALAR_MAP = Object.freeze({
  ID: "string",
  String: "string",
  Int: "integer",
  Float: "number",
  Boolean: "boolean",
});

const AUTH_DIRECTIVE_NAMES = new Set([
  "auth",
  "authenticated",
  "isAuthenticated",
  "requireAuth",
  "requiresAuth",
  "requireRole",
  "hasRole",
  "hasScope",
  "guard",
]);

function tokenize(source) {
  const tokens = [];
  let i = 0;
  const len = source.length;
  while (i < len) {
    const c = source[i];
    if (c === " " || c === "\t" || c === "\n" || c === "\r" || c === ",") {
      i++;
      continue;
    }
    if (c === "#") {
      while (i < len && source[i] !== "\n") i++;
      continue;
    }
    if (source.slice(i, i + 3) === '"""') {
      const start = i + 3;
      const end = source.indexOf('"""', start);
      if (end === -1) {
        throw new Error("unterminated block string");
      }
      tokens.push({ type: "STRING", value: source.slice(start, end) });
      i = end + 3;
      continue;
    }
    if (c === '"') {
      const start = i + 1;
      let j = start;
      let value = "";
      while (j < len && source[j] !== '"') {
        if (source[j] === "\\" && j + 1 < len) {
          value += source[j + 1];
          j += 2;
        } else {
          value += source[j];
          j++;
        }
      }
      if (j >= len) throw new Error("unterminated string");
      tokens.push({ type: "STRING", value });
      i = j + 1;
      continue;
    }
    if (PUNCT.has(c)) {
      tokens.push({ type: "PUNCT", value: c });
      i++;
      continue;
    }
    if (/[_A-Za-z]/.test(c)) {
      let j = i + 1;
      while (j < len && /[_A-Za-z0-9]/.test(source[j])) j++;
      tokens.push({ type: "IDENT", value: source.slice(i, j) });
      i = j;
      continue;
    }
    if (/[0-9.\-]/.test(c)) {
      let j = i + 1;
      while (j < len && /[0-9.\-eE+]/.test(source[j])) j++;
      tokens.push({ type: "NUMBER", value: source.slice(i, j) });
      i = j;
      continue;
    }
    throw new Error(`unexpected character ${JSON.stringify(c)} at offset ${i}`);
  }
  return tokens;
}

class Parser {
  constructor(tokens) {
    this.tokens = tokens;
    this.pos = 0;
  }
  peek(offset = 0) { return this.tokens[this.pos + offset]; }
  consume() { return this.tokens[this.pos++]; }
  expect(type, value) {
    const t = this.consume();
    if (!t) throw new Error(`expected ${type}${value ? ":" + value : ""}, got EOF`);
    if (t.type !== type) throw new Error(`expected ${type}, got ${t.type}:${t.value}`);
    if (value != null && t.value !== value) throw new Error(`expected ${value}, got ${t.value}`);
    return t;
  }
  isPunct(value) {
    const t = this.peek();
    return t != null && t.type === "PUNCT" && t.value === value;
  }
  isIdent(value) {
    const t = this.peek();
    if (t == null || t.type !== "IDENT") return false;
    return value === undefined || t.value === value;
  }
  skipDescription() {
    while (this.peek() && this.peek().type === "STRING") this.consume();
  }
  parseDocument() {
    const document = {
      types: {},
      inputs: {},
      schemaDef: null,
      warnings: [],
    };
    while (this.peek()) {
      this.skipDescription();
      const t = this.peek();
      if (!t) break;
      if (t.type === "IDENT") {
        if (t.value === "type" || t.value === "extend") {
          this.parseTypeDef(document);
          continue;
        }
        if (t.value === "input") {
          this.parseInputDef(document);
          continue;
        }
        if (t.value === "schema") {
          this.parseSchemaDef(document);
          continue;
        }
        if (
          t.value === "interface"
          || t.value === "enum"
          || t.value === "union"
          || t.value === "scalar"
          || t.value === "directive"
        ) {
          this.skipUnsupportedDef();
          continue;
        }
      }
      document.warnings.push(`unexpected_token:${t.type}:${t.value}`);
      this.consume();
    }
    return document;
  }
  parseTypeDef(document) {
    let isExtend = false;
    if (this.isIdent("extend")) {
      this.consume();
      isExtend = true;
    }
    this.expect("IDENT", "type");
    const name = this.expect("IDENT").value;
    if (this.isIdent("implements")) {
      this.consume();
      while (this.peek() && this.peek().type === "IDENT") {
        this.consume();
        if (this.isPunct("&")) this.consume();
        else break;
      }
    }
    this.parseDirectives();
    if (!this.isPunct("{")) return;
    this.expect("PUNCT", "{");
    const existing = isExtend && document.types[name] ? document.types[name].fields : [];
    const fields = existing;
    while (!this.isPunct("}")) {
      const field = this.parseFieldDef();
      if (!field) break;
      fields.push(field);
    }
    this.expect("PUNCT", "}");
    if (isExtend && document.types[name]) {
      document.types[name].fields = fields;
    } else {
      document.types[name] = { kind: "type", name, fields };
    }
  }
  parseInputDef(document) {
    this.expect("IDENT", "input");
    const name = this.expect("IDENT").value;
    this.parseDirectives();
    if (!this.isPunct("{")) return;
    this.expect("PUNCT", "{");
    const fields = [];
    while (!this.isPunct("}")) {
      const field = this.parseFieldDef();
      if (!field) break;
      fields.push(field);
    }
    this.expect("PUNCT", "}");
    document.inputs[name] = { kind: "input", name, fields };
  }
  parseSchemaDef(document) {
    this.expect("IDENT", "schema");
    this.parseDirectives();
    if (!this.isPunct("{")) return;
    this.expect("PUNCT", "{");
    const mapping = {};
    while (!this.isPunct("}")) {
      this.skipDescription();
      const op = this.expect("IDENT").value;
      this.expect("PUNCT", ":");
      const typeName = this.expect("IDENT").value;
      mapping[op] = typeName;
    }
    this.expect("PUNCT", "}");
    document.schemaDef = mapping;
  }
  skipUnsupportedDef() {
    this.consume();
    while (this.peek() && !this.isPunct("{") && !this.isIdent("type") && !this.isIdent("input")
      && !this.isIdent("schema") && !this.isIdent("interface") && !this.isIdent("enum")
      && !this.isIdent("union") && !this.isIdent("scalar") && !this.isIdent("directive")
      && !this.isIdent("extend")) {
      this.consume();
    }
    if (this.isPunct("{")) {
      this.consume();
      let depth = 1;
      while (depth > 0 && this.peek()) {
        const t = this.consume();
        if (t.type === "PUNCT" && t.value === "{") depth++;
        else if (t.type === "PUNCT" && t.value === "}") depth--;
      }
    }
  }
  parseFieldDef() {
    this.skipDescription();
    if (this.isPunct("}")) return null;
    if (!this.peek() || this.peek().type !== "IDENT") return null;
    const name = this.expect("IDENT").value;
    let args = [];
    if (this.isPunct("(")) args = this.parseArgList();
    this.expect("PUNCT", ":");
    const type = this.parseType();
    const directives = this.parseDirectives();
    return { name, args, type, directives };
  }
  parseArgList() {
    this.expect("PUNCT", "(");
    const args = [];
    while (!this.isPunct(")")) {
      this.skipDescription();
      const name = this.expect("IDENT").value;
      this.expect("PUNCT", ":");
      const type = this.parseType();
      let defaultValue = null;
      if (this.isPunct("=")) {
        this.consume();
        defaultValue = this.parseValue();
      }
      const directives = this.parseDirectives();
      args.push({ name, type, default_value: defaultValue, directives });
    }
    this.expect("PUNCT", ")");
    return args;
  }
  parseType() {
    let typeNode;
    if (this.isPunct("[")) {
      this.consume();
      const inner = this.parseType();
      this.expect("PUNCT", "]");
      typeNode = { kind: "list", of: inner, nonNull: false };
    } else {
      const t = this.expect("IDENT");
      typeNode = { kind: "named", name: t.value, nonNull: false };
    }
    if (this.isPunct("!")) {
      this.consume();
      typeNode.nonNull = true;
    }
    return typeNode;
  }
  parseDirectives() {
    const directives = [];
    while (this.isPunct("@")) {
      this.consume();
      const name = this.expect("IDENT").value;
      const args = this.isPunct("(") ? this.parseDirectiveArgs() : {};
      directives.push({ name, args });
    }
    return directives;
  }
  parseDirectiveArgs() {
    this.expect("PUNCT", "(");
    const args = {};
    while (!this.isPunct(")")) {
      const name = this.expect("IDENT").value;
      this.expect("PUNCT", ":");
      args[name] = this.parseValue();
    }
    this.expect("PUNCT", ")");
    return args;
  }
  parseValue() {
    const t = this.peek();
    if (!t) throw new Error("expected value, got EOF");
    if (t.type === "STRING") return this.consume().value;
    if (t.type === "NUMBER") return Number(this.consume().value);
    if (t.type === "IDENT") {
      const ident = this.consume().value;
      if (ident === "true") return true;
      if (ident === "false") return false;
      if (ident === "null") return null;
      return ident;
    }
    if (this.isPunct("[")) {
      this.consume();
      const items = [];
      while (!this.isPunct("]")) items.push(this.parseValue());
      this.consume();
      return items;
    }
    if (this.isPunct("{")) {
      this.consume();
      const obj = {};
      while (!this.isPunct("}")) {
        const k = this.expect("IDENT").value;
        this.expect("PUNCT", ":");
        obj[k] = this.parseValue();
      }
      this.consume();
      return obj;
    }
    throw new Error(`unexpected value token: ${t.type}:${t.value}`);
  }
}

function typeRefToString(typeNode) {
  if (typeNode.kind === "list") {
    return `[${typeRefToString(typeNode.of)}]${typeNode.nonNull ? "!" : ""}`;
  }
  return `${typeNode.name}${typeNode.nonNull ? "!" : ""}`;
}

function resolveTypeShape(typeNode, document, visited) {
  const seen = visited || new Set();
  if (typeNode.kind === "list") {
    return { type: "array", items: resolveTypeShape(typeNode.of, document, seen) };
  }
  const name = typeNode.name;
  if (SCALAR_MAP[name]) return { type: SCALAR_MAP[name] };
  if (seen.has(name)) return { type: "object", $ref_cycle: name };
  const typeDef = document.types[name] || document.inputs[name];
  if (!typeDef) return { type: "object", $ref_unresolved: name };
  const next = new Set(seen);
  next.add(name);
  const properties = {};
  const required = [];
  for (const field of typeDef.fields || []) {
    properties[field.name] = resolveTypeShape(field.type, document, next);
    if (typeDef.kind === "input" && field.type.nonNull && field.default_value == null) {
      required.push(field.name);
    }
  }
  const shape = { type: "object", properties };
  if (required.length > 0) shape.required = required.sort();
  return shape;
}

function deriveClaimedAuth(directives) {
  const schemes = new Set();
  for (const directive of directives || []) {
    if (AUTH_DIRECTIVE_NAMES.has(directive.name)) {
      schemes.add(`graphql_directive:${directive.name}`);
    }
  }
  return {
    schemes: Array.from(schemes).sort(),
    none_allowed: schemes.size === 0,
  };
}

function buildGraphqlContracts(document) {
  const schema = document.schemaDef || {};
  const opTypeNames = [
    ["query", schema.query || "Query"],
    ["mutation", schema.mutation || "Mutation"],
  ];
  const contracts = [];
  for (const [opKind, typeName] of opTypeNames) {
    const typeDef = document.types[typeName];
    if (!typeDef) continue;
    for (const field of typeDef.fields) {
      const responseShape = resolveTypeShape(field.type, document);
      const params = field.args.map((arg) => ({
        name: arg.name,
        in: "graphql_arg",
        required: arg.type.nonNull === true && arg.default_value == null,
        schema_type: arg.type.kind === "named" && SCALAR_MAP[arg.type.name]
          ? SCALAR_MAP[arg.type.name]
          : (arg.type.kind === "list" ? "array" : "object"),
        schema_shape: resolveTypeShape(arg.type, document),
      })).sort((a, b) => a.name.localeCompare(b.name));
      const contract = {
        endpoint: `/graphql:${opKind}.${field.name}`,
        method: "POST",
        operation_kind: opKind,
        operation_name: field.name,
        return_type_signature: typeRefToString(field.type),
        claimed_auth: deriveClaimedAuth(field.directives),
        claimed_params: params,
        claimed_response_shape: {
          "200": {
            content_type: "application/json",
            shape: {
              type: "object",
              properties: { data: responseShape },
            },
          },
        },
      };
      contract.contract_hash = hashCanonicalJson(contract);
      contracts.push(contract);
    }
  }
  contracts.sort((a, b) => a.endpoint.localeCompare(b.endpoint));
  return contracts;
}

function parseGraphqlSdl(rawSdl) {
  const warnings = [];
  let tokens;
  try {
    tokens = tokenize(rawSdl);
  } catch (err) {
    return {
      schema_format: "graphql",
      contracts: [],
      source_doc_hash: null,
      parser_warnings: [`tokenize_failed:${err.message || String(err)}`],
    };
  }
  let document;
  try {
    document = new Parser(tokens).parseDocument();
  } catch (err) {
    return {
      schema_format: "graphql",
      contracts: [],
      source_doc_hash: null,
      parser_warnings: [`parse_failed:${err.message || String(err)}`],
    };
  }
  warnings.push(...document.warnings);
  const contracts = buildGraphqlContracts(document);
  const canonicalAst = {
    types: document.types,
    inputs: document.inputs,
    schemaDef: document.schemaDef,
  };
  return {
    schema_format: "graphql",
    contracts,
    source_doc_hash: hashCanonicalJson(canonicalAst),
    parser_warnings: warnings,
  };
}

function looksLikeGraphqlSdl(text) {
  if (typeof text !== "string") return false;
  return /\btype\s+\w+\s*[\{\@]/.test(text)
    || /\bschema\s*[\{\@]/.test(text)
    || /\binput\s+\w+\s*[\{\@]/.test(text);
}

module.exports = {
  parseGraphqlSdl,
  looksLikeGraphqlSdl,
};
