"use strict";

// A signed closure still needs a loader whose authority is the signed graph,
// not Node's ambient resolver. The analyzer below operates on an AST (never on
// comments or token-shaped text) and admits `require` only as a direct call
// with one string literal. The loader then resolves that call exclusively
// through the already-verified edge table and in-memory file set.

const babelParser = require("@babel/parser");
const path = require("node:path");
const vm = require("node:vm");

const babelParse = babelParser.parse;
const objectFreeze = Object.freeze;
const objectKeys = Object.keys;
const reflectApply = Reflect.apply;
const vmCreateContext = vm.createContext;
const VmScript = vm.Script;

const FORBIDDEN_IDENTIFIERS = objectFreeze(new Set([
  "Function",
  "WebAssembly",
  "__non_webpack_require__",
  "eval",
  "exports",
  "global",
  "globalThis",
]));
const FORBIDDEN_MEMBER_NAMES = objectFreeze(new Set([
  "__proto__",
  "constructor",
]));

function closedLoaderError(reasonCode) {
  const error = new Error("Closed CommonJS worker policy rejected the source");
  Object.defineProperty(error, "code", {
    value: "closed_commonjs_loader_rejected",
    enumerable: false,
  });
  Object.defineProperty(error, "reason_code", {
    value: reasonCode,
    enumerable: false,
  });
  return error;
}

function reject(reasonCode) {
  throw closedLoaderError(reasonCode);
}

function parseCommonjs(source, sourcePath) {
  if (typeof source !== "string" || typeof sourcePath !== "string"
      || sourcePath.length === 0) reject("source_invalid");
  try {
    return reflectApply(babelParse, babelParser, [source, {
      sourceType: "script",
      sourceFilename: sourcePath,
      allowReturnOutsideFunction: true,
      allowAwaitOutsideFunction: false,
      errorRecovery: false,
      createParenthesizedExpressions: true,
    }]);
  } catch {
    reject("javascript_syntax_rejected");
  }
}

function walkAst(node, ancestors, visitor) {
  if (node == null || typeof node !== "object") return;
  if (typeof node.type === "string") visitor(node, ancestors);
  const nextAncestors = typeof node.type === "string" ? [...ancestors, node] : ancestors;
  for (const key of objectKeys(node)) {
    if (key === "loc" || key === "start" || key === "end" || key === "extra"
        || key === "comments" || key === "tokens" || key === "errors") continue;
    const child = node[key];
    if (Array.isArray(child)) {
      for (const item of child) walkAst(item, nextAncestors, visitor);
    } else {
      walkAst(child, nextAncestors, visitor);
    }
  }
}

function parentOf(ancestors) {
  return ancestors.length === 0 ? null : ancestors[ancestors.length - 1];
}

function outerMemberChain(identifier, ancestors) {
  const parts = [];
  let current = identifier;
  let ancestorIndex = ancestors.length - 1;
  while (ancestorIndex >= 0) {
    const parent = ancestors[ancestorIndex];
    if ((parent.type !== "MemberExpression" && parent.type !== "OptionalMemberExpression")
        || parent.object !== current) break;
    if (parent.type === "OptionalMemberExpression" || parent.optional === true
        || parent.computed === true || !parent.property
        || parent.property.type !== "Identifier") {
      return { valid: false, parts, outer: parent, outerParent: null };
    }
    parts.push(parent.property.name);
    current = parent;
    ancestorIndex -= 1;
  }
  return {
    valid: true,
    parts,
    outer: current,
    outerParent: ancestorIndex >= 0 ? ancestors[ancestorIndex] : null,
  };
}

function assertProcessReference(identifier, ancestors) {
  const chain = outerMemberChain(identifier, ancestors);
  if (!chain.valid) reject("process_capability_rejected");
  const identity = chain.parts.join(".");
  if (identity === "platform") return;
  if (identity === "getuid") {
    const parent = chain.outerParent;
    const directCall = parent && parent.type === "CallExpression"
      && parent.callee === chain.outer && parent.optional !== true
      && parent.arguments.length === 0;
    const typeProbe = parent && parent.type === "UnaryExpression"
      && parent.operator === "typeof" && parent.argument === chain.outer;
    if (directCall || typeProbe) return;
  }
  if (identity === "hrtime.bigint") {
    const parent = chain.outerParent;
    if (parent && parent.type === "CallExpression" && parent.callee === chain.outer
        && parent.optional !== true && parent.arguments.length === 0) return;
  }
  reject("process_capability_rejected");
}

function assertModuleReference(identifier, ancestors) {
  const parent = parentOf(ancestors);
  if (!parent || parent.type !== "MemberExpression" || parent.object !== identifier
      || parent.optional === true || parent.computed === true
      || parent.property.type !== "Identifier" || parent.property.name !== "exports") {
    reject("module_capability_rejected");
  }
}

function dangerousMemberName(node) {
  if (node.type !== "MemberExpression" && node.type !== "OptionalMemberExpression") return null;
  if (!node.computed && node.property && node.property.type === "Identifier") {
    return node.property.name;
  }
  if (node.computed && node.property
      && (node.property.type === "StringLiteral" || node.property.type === "Literal")) {
    return typeof node.property.value === "string" ? node.property.value : null;
  }
  return null;
}

function isNonReferencePropertyIdentifier(node, ancestors) {
  const parent = parentOf(ancestors);
  if (!parent) return false;
  if ((parent.type === "MemberExpression" || parent.type === "OptionalMemberExpression")
      && parent.property === node && parent.computed !== true) return true;
  if ((parent.type === "ObjectProperty" || parent.type === "ObjectMethod"
      || parent.type === "ClassMethod" || parent.type === "ClassProperty")
      && parent.key === node && parent.computed !== true && parent.shorthand !== true) return true;
  return parent.type === "LabeledStatement" || parent.type === "BreakStatement"
    || parent.type === "ContinueStatement";
}

function analyzeClosedCommonjsSource(source, sourcePath) {
  const ast = parseCommonjs(source, sourcePath);
  const specifiers = [];
  walkAst(ast, [], (node, ancestors) => {
    if (node.type === "ImportExpression" || node.type === "ImportDeclaration"
        || node.type === "ExportNamedDeclaration" || node.type === "ExportDefaultDeclaration"
        || node.type === "ExportAllDeclaration"
        || (node.type === "CallExpression" && node.callee && node.callee.type === "Import")) {
      reject("dynamic_loader_rejected");
    }
    const memberName = dangerousMemberName(node);
    if (memberName != null && FORBIDDEN_MEMBER_NAMES.has(memberName)) {
      reject("reflective_code_generation_rejected");
    }
    if (node.type !== "Identifier") return;
    if (node.name === "require") {
      const parent = parentOf(ancestors);
      if (!parent || parent.type !== "CallExpression" || parent.callee !== node
          || parent.optional === true || parent.arguments.length !== 1
          || parent.arguments[0].type !== "StringLiteral"
          || typeof parent.arguments[0].value !== "string"
          || parent.arguments[0].value.length === 0) {
        reject("dynamic_loader_rejected");
      }
      specifiers.push(parent.arguments[0].value);
      return;
    }
    if (node.name === "module") {
      assertModuleReference(node, ancestors);
      return;
    }
    if (node.name === "process") {
      assertProcessReference(node, ancestors);
      return;
    }
    if (FORBIDDEN_IDENTIFIERS.has(node.name)
        && !isNonReferencePropertyIdentifier(node, ancestors)) {
      reject("dynamic_loader_rejected");
    }
  });
  const unique = [...new Set(specifiers)];
  if (unique.length !== specifiers.length) reject("duplicate_module_edge_rejected");
  return objectFreeze(unique.sort());
}

function createDefaultProcessProjection(hostProcess = process) {
  const getuid = typeof hostProcess.getuid === "function"
    ? objectFreeze(() => hostProcess.getuid())
    : undefined;
  return objectFreeze({
    platform: String(hostProcess.platform),
    getuid,
    hrtime: objectFreeze({
      bigint: objectFreeze(() => hostProcess.hrtime.bigint()),
    }),
  });
}

function createClosedCommonjsLoader(input) {
  if (input == null || typeof input !== "object" || !(input.sources instanceof Map)
      || !Array.isArray(input.module_edges) || !(input.builtin_modules instanceof Map)) {
    reject("loader_input_invalid");
  }
  const sources = new Map();
  for (const [sourcePath, source] of input.sources) {
    if (typeof sourcePath !== "string" || sourcePath.length === 0
        || (typeof source !== "string" && !Buffer.isBuffer(source))) {
      reject("loader_input_invalid");
    }
    const text = Buffer.isBuffer(source) ? source.toString("utf8") : source;
    if (sourcePath.endsWith(".js")) analyzeClosedCommonjsSource(text, sourcePath);
    sources.set(sourcePath, text);
  }
  const edges = new Map();
  for (const edge of input.module_edges) {
    if (edge == null || typeof edge !== "object" || typeof edge.source_path !== "string"
        || typeof edge.specifier !== "string" || typeof edge.resolved_path !== "string") {
      reject("loader_input_invalid");
    }
    const identity = `${edge.source_path}\0${edge.specifier}`;
    if (edges.has(identity)) reject("loader_input_invalid");
    edges.set(identity, edge.resolved_path);
  }
  const context = reflectApply(vmCreateContext, vm, [Object.create(null), {
    name: "hacker-bob-closed-worker",
    codeGeneration: { strings: false, wasm: false },
  }]);
  context.Buffer = Buffer;
  context.process = input.process_projection || createDefaultProcessProjection();
  const cache = new Map();

  function load(sourcePath) {
    if (cache.has(sourcePath)) return cache.get(sourcePath).exports;
    if (!sources.has(sourcePath)) reject("runtime_edge_target_missing");
    if (sourcePath.endsWith(".json")) {
      let parsed;
      try {
        parsed = JSON.parse(sources.get(sourcePath));
      } catch {
        reject("runtime_json_rejected");
      }
      const jsonRecord = { exports: parsed };
      cache.set(sourcePath, jsonRecord);
      return parsed;
    }
    if (!sourcePath.endsWith(".js")) reject("runtime_media_type_rejected");
    const moduleRecord = { exports: {} };
    cache.set(sourcePath, moduleRecord);
    const closedRequire = (specifier) => {
      const resolved = edges.get(`${sourcePath}\0${specifier}`);
      if (resolved == null) reject("runtime_undeclared_edge_rejected");
      if (resolved.startsWith("node:")) {
        if (!input.builtin_modules.has(resolved)) reject("runtime_builtin_rejected");
        return input.builtin_modules.get(resolved);
      }
      return load(resolved);
    };
    const wrapperSource = `(function (exports, require, module, __filename, __dirname) {\n`
      + `${sources.get(sourcePath)}\n})`;
    let wrapper;
    try {
      const script = new VmScript(wrapperSource, { filename: sourcePath, displayErrors: false });
      wrapper = script.runInContext(context, { displayErrors: false });
      wrapper(
        moduleRecord.exports,
        closedRequire,
        moduleRecord,
        sourcePath,
        path.posix.dirname(sourcePath),
      );
    } catch (error) {
      cache.delete(sourcePath);
      if (error && error.code === "closed_commonjs_loader_rejected") throw error;
      reject("runtime_evaluation_rejected");
    }
    return moduleRecord.exports;
  }

  return objectFreeze({
    loadEntrypoint(entrypoint) {
      if (typeof entrypoint !== "string" || !sources.has(entrypoint)) {
        reject("runtime_entrypoint_rejected");
      }
      return load(entrypoint);
    },
  });
}

module.exports = {
  analyzeClosedCommonjsSource,
  createClosedCommonjsLoader,
  createDefaultProcessProjection,
};
