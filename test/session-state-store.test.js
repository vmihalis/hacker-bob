const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const {
  sessionDir,
  statePath,
} = require("../mcp/lib/paths.js");
const {
  withSessionLock,
  writeFileAtomic,
} = require("../mcp/lib/storage.js");
const {
  blockInternalHostsRequestPolicy,
  readSessionStateStrict,
  writeSessionStateDocument,
} = require("../mcp/lib/session-state-store.js");

const ROOT = path.resolve(__dirname, "..");

function readSource(relativePath) {
  return fs.readFileSync(path.join(ROOT, relativePath), "utf8");
}

function listRuntimeJsFiles(relativeDir = "mcp") {
  const dir = path.join(ROOT, relativeDir);
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const relativePath = path.join(relativeDir, entry.name);
    if (entry.isDirectory()) return listRuntimeJsFiles(relativePath);
    return entry.isFile() && entry.name.endsWith(".js") ? [relativePath] : [];
  });
}

function requireCalls(source) {
  const semanticCode = sourceWithoutCommentsAndStrings(source);
  const code = sourceWithoutComments(source);
  return [...semanticCode.matchAll(/\brequire\s*\(/g)].map((match) => {
    const parenStart = semanticCode.indexOf("(", match.index);
    const parenEnd = findMatchingParen(code, parenStart);
    return {
      index: match.index,
      end: parenEnd + 1,
      argsText: code.slice(parenStart + 1, parenEnd).trim(),
    };
  });
}

function staticRequireSpec(call) {
  const match = call.argsText.match(/^["']([^"']+)["']$/);
  return match ? match[1] : null;
}

function requireSpecs(source) {
  return requireCalls(source)
    .map(staticRequireSpec)
    .filter((spec) => spec !== null);
}

function normalizeRelativePath(relativePath) {
  return relativePath.split(path.sep).join("/");
}

function resolveRuntimeRequire(fromRelativePath, spec) {
  if (!spec.startsWith(".")) return null;
  const withExtension = spec.endsWith(".js") ? spec : `${spec}.js`;
  return normalizeRelativePath(path.normalize(path.join(path.dirname(fromRelativePath), withExtension)));
}

function sourceWithoutComments(source) {
  return stripJavaScriptSource(source, { stripStrings: false });
}

function sourceWithoutCommentsAndStrings(source) {
  return stripJavaScriptSource(source, { stripStrings: true });
}

function stripJavaScriptSource(source, { stripStrings }) {
  let output = "";
  const stack = [{ type: "normal" }];
  const current = () => stack[stack.length - 1];
  const appendStringChar = (char) => {
    output += stripStrings && char !== "\n" ? " " : char;
  };
  for (let index = 0; index < source.length; index += 1) {
    const char = source[index];
    const next = source[index + 1];
    const context = current();
    if (context.type === "lineComment") {
      if (char === "\n") {
        output += "\n";
        stack.pop();
      } else {
        output += " ";
      }
      continue;
    }
    if (context.type === "blockComment") {
      if (char === "*" && next === "/") {
        output += "  ";
        index += 1;
        stack.pop();
      } else {
        output += char === "\n" ? "\n" : " ";
      }
      continue;
    }
    if (context.type === "string") {
      appendStringChar(char);
      if (char === "\n") {
        context.escaped = false;
        stack.pop();
        continue;
      }
      if (context.escaped) {
        context.escaped = false;
      } else if (char === "\\") {
        context.escaped = true;
      } else if (char === context.quote) {
        stack.pop();
      }
      continue;
    }
    if (context.type === "template") {
      if (context.escaped) {
        appendStringChar(char);
        context.escaped = false;
        continue;
      }
      if (char === "\\") {
        appendStringChar(char);
        context.escaped = true;
        continue;
      }
      if (char === "`") {
        appendStringChar(char);
        stack.pop();
        continue;
      }
      if (char === "$" && next === "{") {
        output += stripStrings ? "  " : "${";
        index += 1;
        stack.push({ type: "templateExpr", braceDepth: 1 });
        continue;
      }
      appendStringChar(char);
      continue;
    }
    if (char === "/" && next === "/") {
      output += "  ";
      index += 1;
      stack.push({ type: "lineComment" });
      continue;
    }
    if (char === "/" && next === "*") {
      output += "  ";
      index += 1;
      stack.push({ type: "blockComment" });
      continue;
    }
    if (char === "\"" || char === "'") {
      appendStringChar(char);
      stack.push({ type: "string", quote: char, escaped: false });
      continue;
    }
    if (char === "`") {
      appendStringChar(char);
      stack.push({ type: "template", escaped: false });
      continue;
    }
    if (context.type === "templateExpr") {
      if (char === "{") {
        context.braceDepth += 1;
        output += char;
        continue;
      }
      if (char === "}") {
        context.braceDepth -= 1;
        output += context.braceDepth === 0 && stripStrings ? " " : char;
        if (context.braceDepth === 0) stack.pop();
        continue;
      }
    }
    output += char;
  }
  return output;
}

function assertNoDynamicRequire(source, label) {
  const semanticCode = sourceWithoutCommentsAndStrings(source);
  assert.doesNotMatch(
    semanticCode,
    /\bimport\s*\(/,
    `${label} must not use dynamic import`,
  );
  const dynamicCalls = requireCalls(source).filter((call) => staticRequireSpec(call) === null);
  assert.deepEqual(dynamicCalls, [], `${label} must not use dynamic require`);
  const code = sourceWithoutComments(source).split("");
  for (const call of requireCalls(source)) {
    code.fill(" ", call.index, call.end);
  }
  assert.doesNotMatch(
    sourceWithoutCommentsAndStrings(code.join("")),
    /\brequire\b/,
    `${label} must not alias require`,
  );
}

function functionRange(source, functionName) {
  const declarationPattern = new RegExp(`\\bfunction\\s+${functionName}\\s*\\(`);
  const declarationMatch = source.match(declarationPattern);
  if (declarationMatch) {
    const paramsStart = source.indexOf("(", declarationMatch.index);
    assert.notEqual(paramsStart, -1, `${functionName} parameter list must start with a paren`);
    const paramsEnd = findMatchingParen(source, paramsStart);
    const bodyStart = source.indexOf("{", paramsEnd);
    assert.notEqual(bodyStart, -1, `${functionName} body must start with a brace`);
    return blockBodyRange(source, bodyStart, functionName);
  }

  const assignmentPattern = new RegExp(`\\b(?:const|let|var)\\s+${functionName}\\s*=\\s*(?:async\\s+)?(?:function\\s*)?`);
  const assignmentMatch = source.match(assignmentPattern);
  assert.ok(assignmentMatch, `${functionName} declaration must exist`);
  let cursor = skipWhitespace(source, assignmentMatch.index + assignmentMatch[0].length);
  let paramsEnd;
  if (source[cursor] === "(") {
    paramsEnd = findMatchingParen(source, cursor);
  } else {
    const paramMatch = source.slice(cursor).match(/^[A-Za-z_$][A-Za-z0-9_$]*/);
    assert.ok(paramMatch, `${functionName} arrow parameter must be named or parenthesized`);
    paramsEnd = cursor + paramMatch[0].length;
  }
  cursor = skipWhitespace(source, paramsEnd + 1);
  if (source.slice(cursor, cursor + 2) === "=>") {
    const bodyStart = skipWhitespace(source, cursor + 2);
    if (source[bodyStart] === "{") return blockBodyRange(source, bodyStart, functionName);
    const bodyEnd = findArrowExpressionBodyEnd(source, bodyStart);
    return {
      body: source.slice(bodyStart, bodyEnd),
      bodyStart,
      bodyEnd,
    };
  }
  assert.equal(source[cursor], "{", `${functionName} body must start with a brace`);
  return blockBodyRange(source, cursor, functionName);
}

function blockBodyRange(source, bodyStart, functionName) {
  let depth = 0;
  for (let index = bodyStart; index < source.length; index += 1) {
    const char = source[index];
    if (char === "{") depth += 1;
    if (char === "}") {
      depth -= 1;
      if (depth === 0) {
        return {
          body: source.slice(bodyStart + 1, index),
          bodyStart,
          bodyEnd: index,
        };
      }
    }
  }
  assert.fail(`${functionName} body must end with a matching brace`);
}

function functionBody(source, functionName) {
  return functionRange(source, functionName).body;
}

function findArrowExpressionBodyEnd(source, bodyStart) {
  let depth = 0;
  for (let index = bodyStart; index < source.length; index += 1) {
    const char = source[index];
    if (char === "(" || char === "{" || char === "[") depth += 1;
    if (char === ")" || char === "}" || char === "]") depth -= 1;
    if (char === ";" && depth === 0) return index;
  }
  return source.length;
}

function findInlineArrowExpressionBodyEnd(source, bodyStart, limit = source.length) {
  const openingChar = source[bodyStart];
  const matchingClose = openingChar === "(" ? ")" : openingChar === "{" ? "}" : openingChar === "[" ? "]" : null;
  let depth = 0;
  for (let index = bodyStart; index < limit; index += 1) {
    const char = source[index];
    if (char === "(" || char === "{" || char === "[") {
      depth += 1;
      continue;
    }
    if (char === ")" || char === "}" || char === "]") {
      if (depth === 0) return index;
      depth -= 1;
      if (depth === 0 && char === matchingClose) return index + 1;
      continue;
    }
    if (depth === 0 && (char === "," || char === ";")) return index;
  }
  return limit;
}

function findMatchingBrace(source, openIndex) {
  assert.equal(source[openIndex], "{", "openIndex must point at an opening brace");
  let depth = 0;
  for (let index = openIndex; index < source.length; index += 1) {
    const char = source[index];
    if (char === "{") depth += 1;
    if (char === "}") {
      depth -= 1;
      if (depth === 0) return index;
    }
  }
  assert.fail("brace range must end with a matching brace");
}

function findMatchingParen(source, openIndex) {
  assert.equal(source[openIndex], "(", "openIndex must point at an opening paren");
  let depth = 0;
  let quote = null;
  let escaped = false;
  let lineComment = false;
  let blockComment = false;
  for (let index = openIndex; index < source.length; index += 1) {
    const char = source[index];
    const next = source[index + 1];
    if (lineComment) {
      if (char === "\n") lineComment = false;
      continue;
    }
    if (blockComment) {
      if (char === "*" && next === "/") {
        index += 1;
        blockComment = false;
      }
      continue;
    }
    if (quote) {
      if (char === "\n" && quote !== "`") {
        quote = null;
        escaped = false;
        continue;
      }
      if (escaped) {
        escaped = false;
      } else if (char === "\\") {
        escaped = true;
      } else if (char === quote) {
        quote = null;
      }
      continue;
    }
    if (char === "/" && next === "/") {
      index += 1;
      lineComment = true;
      continue;
    }
    if (char === "/" && next === "*") {
      index += 1;
      blockComment = true;
      continue;
    }
    if (char === "\"" || char === "'" || char === "`") {
      quote = char;
      continue;
    }
    if (char === "(") depth += 1;
    if (char === ")") {
      depth -= 1;
      if (depth === 0) return index;
    }
  }
  assert.fail("paren range must end with a matching paren");
}

function topLevelArguments(source, parenStart, parenEnd) {
  const args = [];
  let start = parenStart + 1;
  let depth = 0;
  for (let index = parenStart + 1; index < parenEnd; index += 1) {
    const char = source[index];
    if (char === "(" || char === "{" || char === "[") depth += 1;
    if (char === ")" || char === "}" || char === "]") depth -= 1;
    if (char === "," && depth === 0) {
      const text = source.slice(start, index).trim();
      if (text) args.push({ start, end: index, text });
      start = index + 1;
    }
  }
  const text = source.slice(start, parenEnd).trim();
  if (text) args.push({ start, end: parenEnd, text });
  return args;
}

function topLevelCommaSeparated(source) {
  const items = [];
  let start = 0;
  let depth = 0;
  for (let index = 0; index < source.length; index += 1) {
    const char = source[index];
    if (char === "(" || char === "{" || char === "[") depth += 1;
    if (char === ")" || char === "}" || char === "]") depth -= 1;
    if (char === "," && depth === 0) {
      const text = source.slice(start, index).trim();
      if (text) items.push(text);
      start = index + 1;
    }
  }
  const text = source.slice(start).trim();
  if (text) items.push(text);
  return items;
}

function normalizeExpression(expression) {
  return String(expression || "").replace(/\s+/g, "");
}

function callIndexes(source, calleeName) {
  const callPattern = new RegExp(`\\b${calleeName}\\s*\\(`, "g");
  const indexes = [];
  for (const match of source.matchAll(callPattern)) {
    const prefix = source.slice(Math.max(0, match.index - 20), match.index);
    if (/function\s+$/.test(prefix)) continue;
    indexes.push(match.index);
  }
  return indexes;
}

function callExpressions(source, calleeName) {
  return callIndexes(source, calleeName).map((callIndex) => {
    const parenStart = source.indexOf("(", callIndex);
    const parenEnd = findMatchingParen(source, parenStart);
    return {
      callIndex,
      args: topLevelArguments(source, parenStart, parenEnd),
    };
  });
}

function namedFunctionRanges(source) {
  const names = new Set();
  for (const match of source.matchAll(/\bfunction\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(/g)) {
    names.add(match[1]);
  }
  for (const match of source.matchAll(/\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:async\s+)?(?:function\s*\(|\([^)]*\)\s*=>|[A-Za-z_$][A-Za-z0-9_$]*\s*=>)/g)) {
    names.add(match[1]);
  }
  return [...names].map((name) => ({
    name,
    ...functionRange(source, name),
  }));
}

function runtimeCallSummaries(calleeName) {
  const summaries = [];
  for (const relativePath of listRuntimeJsFiles()) {
    const code = sourceWithoutCommentsAndStrings(readSource(relativePath));
    if (!code.includes(calleeName)) continue;
    const functions = namedFunctionRanges(code);
    for (const callIndex of callIndexes(code, calleeName)) {
      const owner = functions.find((fn) => fn.bodyStart < callIndex && callIndex < fn.bodyEnd);
      summaries.push(`${relativePath}:${owner ? owner.name : "<top-level>"}`);
    }
  }
  return summaries.sort();
}

function skipWhitespace(source, index, end = source.length) {
  let next = index;
  while (next < end && /\s/.test(source[next])) next += 1;
  return next;
}

function findTopLevelArrow(source, start, end) {
  let depth = 0;
  for (let index = start; index < end - 1; index += 1) {
    const char = source[index];
    if (char === "(" || char === "{" || char === "[") depth += 1;
    if (char === ")" || char === "}" || char === "]") depth -= 1;
    if (char === "=" && source[index + 1] === ">" && depth === 0) return index;
  }
  return -1;
}

function callbackBodyRange(source, arg) {
  let start = skipWhitespace(source, arg.start, arg.end);
  if (source.slice(start, start + 5) === "async" && !/[A-Za-z0-9_$]/.test(source[start + 5] || "")) {
    assert.fail("withSessionLock callback must not be async for this gate");
  }
  if (source.slice(start, start + 8) === "function") {
    const bodyStart = source.indexOf("{", start);
    assert.ok(bodyStart !== -1 && bodyStart < arg.end, "withSessionLock function callback must have a body");
    return {
      bodyStart,
      bodyEnd: findMatchingBrace(source, bodyStart),
    };
  }
  const arrowIndex = findTopLevelArrow(source, start, arg.end);
  assert.notEqual(arrowIndex, -1, "withSessionLock callback must be an inline function or arrow for this gate");
  const bodyStart = skipWhitespace(source, arrowIndex + 2, arg.end);
  if (source[bodyStart] === "{") {
    return {
      bodyStart,
      bodyEnd: findMatchingBrace(source, bodyStart),
    };
  }
  return {
    bodyStart,
    bodyEnd: arg.end,
  };
}

const DEFERRED_CALLBACK_CALLEES = [
  { name: "setImmediate", callbackArgIndex: 0 },
  { name: "setTimeout", callbackArgIndex: 0 },
  { name: "queueMicrotask", callbackArgIndex: 0 },
  { name: "nextTick", callbackArgIndex: 0 },
  { name: "then", callbackArgIndex: 0 },
  { name: "on", callbackArgIndex: 1 },
  { name: "once", callbackArgIndex: 1 },
  { name: "addListener", callbackArgIndex: 1 },
  { name: "prependListener", callbackArgIndex: 1 },
  { name: "addEventListener", callbackArgIndex: 1 },
  { name: "subscribe", callbackArgIndex: 0 },
  { name: "observe", callbackArgIndex: 0 },
];

function deferredCallbackRanges(source) {
  const ranges = [];
  for (const { name, callbackArgIndex } of DEFERRED_CALLBACK_CALLEES) {
    for (const call of callExpressions(source, name)) {
      if (!call.args[callbackArgIndex]) continue;
      try {
        ranges.push({
          callee: name,
          ...callbackBodyRange(source, call.args[callbackArgIndex]),
        });
      } catch {
        // A non-inline scheduled callback cannot contain the checked call token.
      }
    }
  }
  return ranges;
}

function assertNoDeferredSchedulingSyntax(semanticBody, rawBody, functionName, calleeName) {
  assert.doesNotMatch(
    semanticBody,
    /\b(?:setImmediate|setTimeout|setInterval|queueMicrotask|nextTick|on|once|addListener|prependListener|addEventListener|subscribe|observe)\b|\.\s*(?:then|catch|finally|on|once|addListener|prependListener|addEventListener|subscribe|observe)\s*\(/,
    `${functionName} must not schedule deferred callbacks while proving ${calleeName} lock containment`,
  );
  assert.doesNotMatch(
    rawBody,
    /\[\s*(?:"setImmediate"|'setImmediate'|`setImmediate`|"setTimeout"|'setTimeout'|`setTimeout`|"setInterval"|'setInterval'|`setInterval`|"queueMicrotask"|'queueMicrotask'|`queueMicrotask`|"nextTick"|'nextTick'|`nextTick`|"then"|'then'|`then`|"catch"|'catch'|`catch`|"finally"|'finally'|`finally`|"on"|'on'|`on`|"once"|'once'|`once`|"addListener"|'addListener'|`addListener`|"prependListener"|'prependListener'|`prependListener`|"addEventListener"|'addEventListener'|`addEventListener`|"subscribe"|'subscribe'|`subscribe`|"observe"|'observe'|`observe`)\s*\]\s*(?:\(|\.|\[)/,
    `${functionName} must not schedule deferred callbacks through computed properties while proving ${calleeName} lock containment`,
  );
}

function nestedCallbackRanges(source, lockRange) {
  const ranges = [];
  const lockBody = source.slice(lockRange.bodyStart, lockRange.bodyEnd);
  for (const match of lockBody.matchAll(/\b(?:async\s+)?function\b/g)) {
    const functionIndex = lockRange.bodyStart + match.index;
    const bodyStart = source.indexOf("{", functionIndex);
    if (bodyStart === -1 || bodyStart >= lockRange.bodyEnd) continue;
    ranges.push({
      bodyStart,
      bodyEnd: findMatchingBrace(source, bodyStart),
    });
  }
  for (const match of lockBody.matchAll(/=>/g)) {
    const arrowIndex = lockRange.bodyStart + match.index;
    const bodyStart = skipWhitespace(source, arrowIndex + 2, lockRange.bodyEnd);
    if (bodyStart >= lockRange.bodyEnd) continue;
    const bodyEnd = source[bodyStart] === "{"
      ? findMatchingBrace(source, bodyStart)
      : findInlineArrowExpressionBodyEnd(source, bodyStart, lockRange.bodyEnd);
    ranges.push({
      bodyStart,
      bodyEnd: Math.min(bodyEnd, lockRange.bodyEnd),
    });
  }
  return ranges;
}

function assertNoNestedCallbackSyntaxInLockCallbacks(source, locks, calls, functionName, calleeName) {
  for (const range of locks) {
    const nestedCallbacks = nestedCallbackRanges(source, range);
    for (const call of calls) {
      const nestedCallback = nestedCallbacks.find((nestedRange) => (
        nestedRange.bodyStart <= call.callIndex && call.callIndex < nestedRange.bodyEnd
      ));
      assert.equal(
        nestedCallback,
        undefined,
        `${functionName} must not call ${calleeName} from a nested callback while proving lock containment`,
      );
    }
  }
}

function lockCallbackRanges(source) {
  const ranges = [];
  for (const call of callExpressions(source, "withSessionLock")) {
    assert.ok(call.args.length >= 2, "withSessionLock calls must pass a lock target and callback");
    const bodyRange = callbackBodyRange(source, call.args[1]);
    ranges.push({
      lockDomainExpression: normalizeExpression(call.args[0].text),
      ...bodyRange,
    });
  }
  return ranges;
}

function assertCallsInsideSessionLock(source, functionName, calleeName, options = {}) {
  const requireMatchingDomain = options.requireMatchingDomain !== false;
  const body = functionBody(sourceWithoutCommentsAndStrings(source), functionName);
  const rawBody = functionBody(sourceWithoutComments(source), functionName);
  const calls = callExpressions(body, calleeName);
  assert.notEqual(calls.length, 0, `${functionName} must call ${calleeName}`);
  assertNoDeferredSchedulingSyntax(body, rawBody, functionName, calleeName);
  const locks = lockCallbackRanges(body);
  assertNoNestedCallbackSyntaxInLockCallbacks(body, locks, calls, functionName, calleeName);
  const deferredCallbacks = deferredCallbackRanges(body);
  for (const call of calls) {
    const deferredCallback = deferredCallbacks.find((range) => (
      range.bodyStart <= call.callIndex && call.callIndex < range.bodyEnd
    ));
    assert.equal(
      deferredCallback,
      undefined,
      `${functionName} must not call ${calleeName} from a deferred ${deferredCallback && deferredCallback.callee} callback`,
    );
    const matchingLock = locks.find((range) => (
        range.bodyStart <= call.callIndex &&
        call.callIndex < range.bodyEnd
    ));
    if (!requireMatchingDomain) {
      assert.ok(
        matchingLock,
        `${functionName} must call ${calleeName} inside a withSessionLock callback`,
      );
      continue;
    }
    const calleeDomainExpression = normalizeExpression(call.args[0] && call.args[0].text);
    assert.ok(calleeDomainExpression, `${functionName} ${calleeName} call must pass a lock domain as first argument`);
    assert.ok(
      matchingLock && matchingLock.lockDomainExpression === calleeDomainExpression,
      `${functionName} must call ${calleeName} inside a matching withSessionLock(${calleeDomainExpression}) callback`,
    );
  }
}

function assertNoForbiddenRequire(relativePath, forbiddenSpecs) {
  const source = readSource(relativePath);
  const specs = requireSpecs(source);
  for (const spec of forbiddenSpecs) {
    assert.equal(specs.includes(spec), false, `${relativePath} must not require ${spec}`);
  }
  assertNoDynamicRequire(source, relativePath);
}

function assertSourceDoesNotAliasStoreWriter(relativePath, source) {
  const code = sourceWithoutComments(source);
  assert.doesNotMatch(
    code,
    /\bwriteSessionStateDocument\s*:/,
    `${relativePath} must not alias writeSessionStateDocument at import`,
  );
  assert.doesNotMatch(
    code,
    /["']writeSessionStateDocument["']\s*\]\s*:/,
    `${relativePath} must not alias computed writeSessionStateDocument imports`,
  );
  assert.doesNotMatch(
    code,
    /\b(?:const|let|var)\s+[A-Za-z_$][A-Za-z0-9_$]*\s*=\s*writeSessionStateDocument\b/,
    `${relativePath} must not alias writeSessionStateDocument after import`,
  );
  assert.doesNotMatch(
    code,
    /=\s*writeSessionStateDocument\b/,
    `${relativePath} must not assign writeSessionStateDocument to aliases`,
  );
  assert.doesNotMatch(
    code,
    /:\s*writeSessionStateDocument\b/,
    `${relativePath} must not store writeSessionStateDocument behind object properties`,
  );
  assert.doesNotMatch(
    code,
    /\.\s*writeSessionStateDocument\b/,
    `${relativePath} must not access writeSessionStateDocument through namespace imports`,
  );
  assert.doesNotMatch(
    code,
    /\bwriteSessionStateDocument\s*\.\s*(?:call|apply|bind)\b/,
    `${relativePath} must not invoke writeSessionStateDocument through call/apply/bind`,
  );
  assert.doesNotMatch(
    code,
    /\b(?:const|let|var)\s+[A-Za-z_$][A-Za-z0-9_$]*\s*=\s*require\s*\(\s*["'][^"']*session-state-store(?:\.js)?["']\s*\)/,
    `${relativePath} must destructure session-state-store.js imports for writer scanning`,
  );
  assert.doesNotMatch(
    code,
    /\brequire\s*\(\s*["'][^"']*session-state-store(?:\.js)?["']\s*\)\s*(?:\.|\[)/,
    `${relativePath} must destructure session-state-store.js imports for writer scanning`,
  );
  assertOnlyCheckedStoreWriterReferences(relativePath, source);
}

function assertStoreWriterBindingIsNotAliased() {
  for (const relativePath of listRuntimeJsFiles()) {
    assertSourceDoesNotAliasStoreWriter(relativePath, readSource(relativePath));
  }
}

function assertOnlyCheckedStoreWriterReferences(relativePath, source) {
  const writerName = "writeSessionStateDocument";
  const importCode = sourceWithoutComments(source);
  const semanticCode = sourceWithoutCommentsAndStrings(source);
  const code = semanticCode.split("");
  if (relativePath === "mcp/lib/session-state-store.js") {
    const declarationMatch = semanticCode.match(/\bfunction\s+writeSessionStateDocument\s*\(/);
    assert.ok(declarationMatch, "session-state-store.js must keep the canonical writeSessionStateDocument declaration");
    const declarationIndex = declarationMatch.index + declarationMatch[0].indexOf(writerName);
    code.fill(" ", declarationIndex, declarationIndex + writerName.length);
    const exportStart = semanticCode.indexOf("module.exports = {");
    assert.notEqual(exportStart, -1, "session-state-store.js must keep an explicit export object");
    const exportBraceStart = semanticCode.indexOf("{", exportStart);
    const exportBraceEnd = findMatchingBrace(semanticCode, exportBraceStart);
    const exportBlock = semanticCode.slice(exportBraceStart, exportBraceEnd + 1);
    for (const token of exportBlock.matchAll(/(?:^|[,{]\s*)writeSessionStateDocument\s*(?=,|\})/g)) {
      const tokenIndex = exportBraceStart + token.index + token[0].indexOf(writerName);
      code.fill(" ", tokenIndex, tokenIndex + writerName.length);
    }
  }
  const importPattern = /\b(?:const|let|var)\s*{[\s\S]*?}\s*=\s*require\s*\(\s*["'][^"']*session-state-store(?:\.js)?["']\s*\)/g;
  for (const match of importCode.matchAll(importPattern)) {
    for (const token of match[0].matchAll(/\bwriteSessionStateDocument\b/g)) {
      const tokenIndex = match.index + token.index;
      code.fill(" ", tokenIndex, tokenIndex + writerName.length);
    }
  }
  for (const call of callExpressions(semanticCode, writerName)) {
    code.fill(" ", call.callIndex, call.callIndex + writerName.length);
  }
  assert.doesNotMatch(
    code.join(""),
    /\bwriteSessionStateDocument\b/,
    `${relativePath} must only reference writeSessionStateDocument as a destructured session-state-store import or checked direct call`,
  );
}

function assertOnlyCheckedInternalHelperReferences(source, helperName) {
  const semanticCode = sourceWithoutCommentsAndStrings(source);
  const code = semanticCode.split("");
  const declarationMatch = semanticCode.match(new RegExp(`\\bfunction\\s+${helperName}\\s*\\(`));
  assert.ok(declarationMatch, `${helperName} declaration must exist`);
  const declarationIndex = declarationMatch.index + declarationMatch[0].indexOf(helperName);
  code.fill(" ", declarationIndex, declarationIndex + helperName.length);
  for (const call of callExpressions(semanticCode, helperName)) {
    code.fill(" ", call.callIndex, call.callIndex + helperName.length);
  }
  assert.doesNotMatch(
    code.join(""),
    new RegExp(`\\b${helperName}\\b`),
    `${helperName} must only appear as its declaration or checked direct calls`,
  );
}

function assertOnlyCheckedSurfaceLeadInternalReferences(source) {
  assertOnlyCheckedInternalHelperReferences(source, "promoteSurfaceLeadsInternal");
}

function assertOnlyCheckedStartWaveLockedReferences(source) {
  const helperName = "startWaveLocked";
  const semanticCode = sourceWithoutCommentsAndStrings(source);
  const code = semanticCode.split("");
  const declarationMatch = semanticCode.match(/\bfunction\s+startWaveLocked\s*\(/);
  assert.ok(declarationMatch, `${helperName} declaration must exist`);
  const declarationIndex = declarationMatch.index + declarationMatch[0].indexOf(helperName);
  code.fill(" ", declarationIndex, declarationIndex + helperName.length);
  for (const call of callExpressions(semanticCode, helperName)) {
    code.fill(" ", call.callIndex, call.callIndex + helperName.length);
  }
  assert.doesNotMatch(
    code.join(""),
    /\bstartWaveLocked\b/,
    `${helperName} must only appear as its declaration or checked direct calls`,
  );
}

function delegatedRuntimeSummaries(check) {
  return [...new Set([
    ...(check.lockedCallers || []),
    ...(check.stateDisabledCallers || []).map(({ functionName }) => functionName),
  ])].map((functionName) => `${check.relativePath}:${functionName}`).sort();
}

function delegatedWriterSummary(check) {
  return `${check.relativePath}:${check.helperName}`;
}

function moduleExportsObjectInfo(source, label) {
  const semanticCode = sourceWithoutCommentsAndStrings(source);
  const exportMatch = semanticCode.match(/\bmodule\s*\.\s*exports\s*=\s*{/);
  assert.ok(exportMatch, `${label} export proof requires an explicit module.exports object`);
  const exportBraceStart = semanticCode.indexOf("{", exportMatch.index);
  const exportBraceEnd = findMatchingBrace(semanticCode, exportBraceStart);
  return {
    semanticCode,
    assignmentStart: exportMatch.index,
    blockStart: exportBraceStart,
    blockEnd: exportBraceEnd,
    block: semanticCode.slice(exportBraceStart, exportBraceEnd + 1),
  };
}

function moduleExportsObjectBlock(source, label) {
  return moduleExportsObjectInfo(source, label).block;
}

function moduleExportedIdentifiers(source, label) {
  const block = moduleExportsObjectBlock(source, label);
  return topLevelCommaSeparated(block.slice(1, -1))
    .map((entry) => entry.trim())
    .filter(Boolean)
    .flatMap((entry) => {
      const shorthand = entry.match(/^([A-Za-z_$][A-Za-z0-9_$]*)$/);
      if (shorthand) return [shorthand[1]];
      const property = entry.match(/^([A-Za-z_$][A-Za-z0-9_$]*)\s*:/);
      if (property) return [property[1]];
      return [];
    });
}

function parentExportMutationPattern() {
  const moduleExportTarget = String.raw`module\s*(?:\.\s*exports|\[\s*(?:["'\`]exports["'\`]|[A-Za-z_$][A-Za-z0-9_$]*)\s*\])`;
  return new RegExp(String.raw`\b(?:Object\s*\.\s*(?:assign|defineProperty|defineProperties)\s*\(\s*(?:exports\b|this\b|${moduleExportTarget})|Reflect\s*\.\s*(?:set|defineProperty)\s*\(\s*(?:exports\b|this\b|${moduleExportTarget})|${moduleExportTarget}|exports\s*(?:\.|\[)|this\s*(?:\.|\[))`);
}

const SURFACE_ARTIFACT_PATH_FUNCTIONS = new Set(["attackSurfacePath", "surfaceLeadsPath"]);
const SURFACE_ARTIFACT_WRITE_CALLEES = [
  "writeFileAtomic",
  "writeFileSync",
  "writeFile",
  "appendFileSync",
  "appendFile",
  "createWriteStream",
];

function surfaceArtifactPathAliases(source) {
  const aliases = new Map();
  const addAlias = (name, pathFunction) => {
    aliases.set(normalizeExpression(name), pathFunction);
  };
  for (const match of source.matchAll(/\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(attackSurfacePath|surfaceLeadsPath)\b(?!\s*\()/g)) {
    addAlias(match[1], match[2]);
  }
  for (const match of source.matchAll(/\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(attackSurfacePath|surfaceLeadsPath)\s*\(/g)) {
    addAlias(match[1], match[2]);
  }
  for (const match of source.matchAll(/\b((?:this|[A-Za-z_$][A-Za-z0-9_$]*)\s*\.\s*[A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(attackSurfacePath|surfaceLeadsPath)\s*\(/g)) {
    addAlias(match[1], match[2]);
  }
  for (const match of source.matchAll(/\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*\{[^}]*\b([A-Za-z_$][A-Za-z0-9_$]*)\s*:\s*(attackSurfacePath|surfaceLeadsPath)\s*\(/g)) {
    addAlias(`${match[1]}.${match[2]}`, match[3]);
  }
  for (const match of source.matchAll(/\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:async\s*)?(?:(?:function\s*)?\([^)]*\)|[A-Za-z_$][A-Za-z0-9_$]*)\s*=>\s*(?:\{\s*return\s+)?(attackSurfacePath|surfaceLeadsPath)\s*\(/g)) {
    addAlias(match[1], match[2]);
  }
  for (const match of source.matchAll(/\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:async\s*)?function\s*\([^)]*\)\s*\{[^{}]*\breturn\s+(attackSurfacePath|surfaceLeadsPath)\s*\(/g)) {
    addAlias(match[1], match[2]);
  }
  for (const match of source.matchAll(/\bfunction\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\([^)]*\)\s*\{[^{}]*\breturn\s+(attackSurfacePath|surfaceLeadsPath)\s*\(/g)) {
    addAlias(match[1], match[2]);
  }
  for (const match of source.matchAll(/\b(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*\{[\s\S]*?\b([A-Za-z_$][A-Za-z0-9_$]*)\s*\([^)]*\)\s*\{[^{}]*\breturn\s+(attackSurfacePath|surfaceLeadsPath)\s*\(/g)) {
    addAlias(`${match[1]}.${match[2]}`, match[3]);
  }
  return aliases;
}

function surfaceArtifactPathName(expression, aliases) {
  const normalized = normalizeExpression(expression);
  const direct = normalized.match(/\b(attackSurfacePath|surfaceLeadsPath)\(/);
  if (direct) return direct[1];
  const functionAlias = normalized.match(/^([A-Za-z_$][A-Za-z0-9_$]*)\(/);
  if (functionAlias && aliases.has(functionAlias[1])) return aliases.get(functionAlias[1]);
  const propertyFunctionAlias = normalized.match(/^((?:this|[A-Za-z_$][A-Za-z0-9_$]*)\.[A-Za-z_$][A-Za-z0-9_$]*)\(/);
  if (propertyFunctionAlias && aliases.has(propertyFunctionAlias[1])) return aliases.get(propertyFunctionAlias[1]);
  return aliases.get(normalized) || null;
}

function surfaceArtifactWriteSummaries(relativePath, source) {
  const semanticSource = sourceWithoutCommentsAndStrings(source);
  const candidates = [];
  const globalAliases = surfaceArtifactPathAliases(semanticSource);
  const hasSurfaceArtifactPath = /\b(?:attackSurfacePath|surfaceLeadsPath)\b/.test(semanticSource) || globalAliases.size > 0;
  for (const callee of SURFACE_ARTIFACT_WRITE_CALLEES) {
    for (const call of callExpressions(semanticSource, callee)) {
      const firstArg = normalizeExpression(call.args[0] && call.args[0].text);
      const directPath = firstArg.match(/\b(attackSurfacePath|surfaceLeadsPath)\(/);
      const maybePathAlias = hasSurfaceArtifactPath && (
        /^[A-Za-z_$][A-Za-z0-9_$]*$/.test(firstArg) ||
        /^(?:this|[A-Za-z_$][A-Za-z0-9_$]*)\.[A-Za-z_$][A-Za-z0-9_$]*$/.test(firstArg) ||
        /^[A-Za-z_$][A-Za-z0-9_$]*\(/.test(firstArg) ||
        /^(?:this|[A-Za-z_$][A-Za-z0-9_$]*)\.[A-Za-z_$][A-Za-z0-9_$]*\(/.test(firstArg)
      );
      if (!directPath && !maybePathAlias) continue;
      candidates.push({ call, callee, directPathName: directPath && directPath[1] });
    }
  }
  if (candidates.length === 0) return [];
  const functions = namedFunctionRanges(semanticSource);
  const summaries = [];
  for (const { call, callee, directPathName } of candidates) {
    const owner = functions.find((fn) => fn.bodyStart < call.callIndex && call.callIndex < fn.bodyEnd);
    const aliasSource = owner ? semanticSource.slice(owner.bodyStart, owner.bodyEnd) : semanticSource;
    const localAliases = surfaceArtifactPathAliases(aliasSource);
    const pathName = directPathName
      || surfaceArtifactPathName(call.args[0] && call.args[0].text, localAliases)
      || surfaceArtifactPathName(call.args[0] && call.args[0].text, globalAliases);
    if (!pathName || !SURFACE_ARTIFACT_PATH_FUNCTIONS.has(pathName)) continue;
    summaries.push(`${relativePath}:${owner ? owner.name : "<top-level>"}:${callee}:${pathName}`);
  }
  return summaries;
}

function assertSurfaceArtifactRollbackRestoreIsLocked(wavesSource) {
  const semanticSource = sourceWithoutCommentsAndStrings(wavesSource);
  const exportsBlock = moduleExportsObjectBlock(wavesSource, "wave-scheduler.js");
  assert.doesNotMatch(exportsBlock, /\bsnapshotFileForRollback\b/);
  assert.doesNotMatch(exportsBlock, /\brestoreFileSnapshot\b/);
  const startNextWaveBody = functionBody(semanticSource, "startNextWave");
  // Cycle D.3 deleted the attack_surface.json writer; the promotion path
  // no longer touches the legacy projection file, so the rollback list
  // contracts to surface-leads.json + surface-routes.json. attack_surface.json
  // is read-only after D.3.
  assert.doesNotMatch(
    startNextWaveBody,
    /\bsnapshotFileForRollback\s*\(\s*attackSurfacePath\s*\(\s*domain\s*\)\s*\)/,
    "startNextWave rollback must not snapshot attack_surface.json after D.3 (legacy writer removed)",
  );
  assert.match(
    startNextWaveBody,
    /\bsnapshotFileForRollback\s*\(\s*surfaceLeadsPath\s*\(\s*domain\s*\)\s*\)/,
    "startNextWave rollback must snapshot surface-leads.json through the explicit path helper",
  );
  const restoreBody = functionBody(semanticSource, "restoreFileSnapshot");
  assert.match(
    restoreBody,
    /\bwriteFileAtomic\s*\(\s*snapshot\s*\.\s*path\s*,\s*snapshot\s*\.\s*content\s*\)/,
    "restoreFileSnapshot must keep the snapshot.path write explicit",
  );
  assert.deepEqual(runtimeCallSummaries("restoreFileSnapshot"), [
    "mcp/lib/waves/wave-scheduler.js:startNextWave",
    "mcp/lib/waves/wave-scheduler.js:startNextWave",
  ]);
  assertCallsInsideSessionLock(wavesSource, "startNextWave", "restoreFileSnapshot", { requireMatchingDomain: false });
}

function assertStateDisabledOptionsArgument(argumentText, proof, label) {
  assert.ok(proof && typeof proof === "object", `${label} must define a structured state-disabled options proof`);
  assert.match(proof.requiredLeadingSpread, /^[A-Za-z_$][A-Za-z0-9_$]*$/, `${label} must name the required options spread`);
  assert.ok(proof.forcedBooleanLast && typeof proof.forcedBooleanLast === "object", `${label} must define a forced boolean option`);
  assert.match(proof.forcedBooleanLast.name, /^[A-Za-z_$][A-Za-z0-9_$]*$/, `${label} must name the forced boolean option`);
  assert.equal(typeof proof.forcedBooleanLast.value, "boolean", `${label} forced option value must be boolean`);

  const text = String(argumentText || "").trim();
  assert.match(text, /^\{[\s\S]*\}$/, `${label} must pass an object literal as the state-disabled options argument`);
  const entries = topLevelCommaSeparated(text.slice(1, -1)).map(normalizeExpression);
  assert.notEqual(entries.length, 0, `${label} must pass a non-empty options object`);
  assert.equal(
    entries.length,
    2,
    `${label} must contain only the leading options spread and final state-disabled option`,
  );
  assert.equal(
    entries[0],
    `...${proof.requiredLeadingSpread}`,
    `${label} must spread ${proof.requiredLeadingSpread} before forcing the state-disabled option`,
  );
  const forcedEntry = `${proof.forcedBooleanLast.name}:${String(proof.forcedBooleanLast.value)}`;
  assert.deepEqual(
    entries.flatMap((entry, index) => (entry === forcedEntry ? [index] : [])),
    [entries.length - 1],
    `${label} must force ${forcedEntry} exactly once as the final option`,
  );
}

function assertStateDisabledDelegatedCalls(source, helperName, safeCaller) {
  assert.ok(safeCaller && typeof safeCaller === "object", "state-disabled delegated callers must be structured objects");
  assert.equal(
    Object.hasOwn(safeCaller, "requiredPattern"),
    false,
    "state-disabled delegated checks must not use body-level requiredPattern regexes",
  );
  assert.match(safeCaller.functionName, /^[A-Za-z_$][A-Za-z0-9_$]*$/, "state-disabled delegated callers must name a function");
  assert.ok(Number.isInteger(safeCaller.callCount) && safeCaller.callCount > 0, "state-disabled delegated callers must define a positive callCount");
  assert.equal(typeof safeCaller.firstArg, "string", "state-disabled delegated callers must define the first argument");
  const optionsArg = safeCaller.stateDisabledOptionsArg;
  assert.ok(optionsArg && Number.isInteger(optionsArg.position) && optionsArg.position > 0, "state-disabled delegated callers must define the options argument position");

  const body = functionBody(sourceWithoutCommentsAndStrings(source), safeCaller.functionName);
  const calls = callExpressions(body, helperName);
  assert.equal(
    calls.length,
    safeCaller.callCount,
    `${safeCaller.functionName} must call ${helperName} exactly ${safeCaller.callCount} time(s) as a state-disabled delegation`,
  );
  calls.forEach((call, index) => {
    const label = `${safeCaller.functionName} ${helperName} call ${index + 1}`;
    assert.equal(
      normalizeExpression(call.args[0] && call.args[0].text),
      normalizeExpression(safeCaller.firstArg),
      `${label} must pass ${safeCaller.firstArg} as its first argument`,
    );
    assertStateDisabledOptionsArgument(
      call.args[optionsArg.position] && call.args[optionsArg.position].text,
      optionsArg,
      label,
    );
  });
}

function assertDelegatedStoreWriterCheck(check) {
  assert.ok(check && typeof check === "object", "delegated writer checks must be structured objects");
  assert.match(check.relativePath, /^mcp\/.+\.js$/, "delegated writer checks must name a runtime file");
  assert.match(check.helperName, /^[A-Za-z_$][A-Za-z0-9_$]*$/, "delegated writer checks must name a helper");
  assert.equal(typeof check.source, "string", "delegated writer checks must provide source");
  assert.ok(
    (check.lockedCallers || []).length > 0 || (check.stateDisabledCallers || []).length > 0,
    "delegated writer checks must define a lock or state-disabled proof channel",
  );
  assert.deepEqual(runtimeCallSummaries(check.helperName), delegatedRuntimeSummaries(check));
  for (const functionName of check.lockedCallers || []) {
    assertCallsInsideSessionLock(check.source, functionName, check.helperName);
  }
  for (const safeCaller of check.stateDisabledCallers || []) {
    assertStateDisabledDelegatedCalls(check.source, check.helperName, safeCaller);
  }
  if (check.referenceGate === "startWaveLocked") {
    assertOnlyCheckedStartWaveLockedReferences(check.source);
  } else if (check.referenceGate === "surfaceLeadInternal") {
    assertOnlyCheckedSurfaceLeadInternalReferences(check.source);
  } else {
    assert.fail(`Unknown delegated writer reference gate: ${check.referenceGate}`);
  }
  if (check.mustNotExport) {
    const exportBlock = moduleExportsObjectBlock(check.source, check.helperName);
    assert.doesNotMatch(exportBlock, new RegExp(`\\b${check.helperName}\\b`), `${check.helperName} must not be exported`);
  }
}

function runtimeRequireGraph() {
  const files = listRuntimeJsFiles();
  const fileSet = new Set(files);
  const graph = new Map();
  for (const file of files) {
    graph.set(file, requireSpecs(readSource(file))
      .map((spec) => resolveRuntimeRequire(file, spec))
      .filter((target) => target && fileSet.has(target)));
  }
  return graph;
}

function reachableRuntimeFiles(graph, roots) {
  const reachable = new Set();
  function visit(file) {
    if (reachable.has(file)) return;
    reachable.add(file);
    for (const next of graph.get(file) || []) visit(next);
  }
  for (const root of roots) visit(root);
  return [...reachable].sort();
}

function firstReachableCycle(graph, root) {
  const visiting = new Map();
  const visited = new Set();
  const stack = [];

  function visit(file) {
    if (visiting.has(file)) {
      return [...stack.slice(visiting.get(file)), file];
    }
    if (visited.has(file)) return null;
    visiting.set(file, stack.length);
    stack.push(file);
    for (const next of graph.get(file) || []) {
      const cycle = visit(next);
      if (cycle) return cycle;
    }
    stack.pop();
    visiting.delete(file);
    visited.add(file);
    return null;
  }

  return visit(root);
}

function withTempHome(fn) {
  const previousHome = process.env.HOME;
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "bob-session-state-store-"));
  process.env.HOME = home;
  try {
    return fn(home);
  } finally {
    process.env.HOME = previousHome;
    fs.rmSync(home, { recursive: true, force: true });
  }
}

function writeState(domain, overrides = {}) {
  const document = {
    target: domain,
    target_url: `https://${domain}`,
    phase: "EVALUATE",
    explored: [],
    terminally_blocked: [],
    ...overrides,
  };
  fs.mkdirSync(sessionDir(domain), { recursive: true });
  writeFileAtomic(statePath(domain), `${JSON.stringify(document, null, 2)}\n`);
  return document;
}

test("session-state contract and store keep forbidden import boundaries", () => {
  const contractSource = readSource("mcp/lib/session-state-contracts.js");
  // Cycle D.3 added lazy require("./frontier-projections.js") inside
  // compactSessionState and terminallyBlockedSurfaceIds so the deleted
  // state.json projection fields (explored / terminally_blocked /
  // lead_surface_ids) can be re-derived from frontier events without a
  // top-level circular import.
  assert.deepEqual(requireSpecs(contractSource).sort(), [
    "./constants.js",
    "./frontier-projections.js",
    "./frontier-projections.js",
    "./sensitive-material.js",
    "./validation.js",
  ].sort());
  assertNoForbiddenRequire("mcp/lib/session-state-contracts.js", [
    "fs",
    "./paths.js",
    "./storage.js",
    "./session-state.js",
    "./pipeline-events.js",
    "./verification.js",
    "./verification-snapshot-contracts.js",
    "./session-authority.js",
    "./egress-profiles.js",
    "./envelope.js",
  ]);

  const storeSource = readSource("mcp/lib/session-state-store.js");
  assert.deepEqual(requireSpecs(storeSource).sort(), [
    "fs",
    "./paths.js",
    "./session-state-contracts.js",
    "./storage.js",
    "./validation.js",
  ].sort());
  assertNoForbiddenRequire("mcp/lib/session-state-store.js", [
    "./session-state.js",
    "./pipeline-events.js",
    "./verification.js",
    "./verification-snapshot-contracts.js",
    "./session-authority.js",
  ]);
});

test("session-state store stays lock-free and parent barrel omits moved store helpers", () => {
  const storeSource = readSource("mcp/lib/session-state-store.js");
  const storeCode = sourceWithoutComments(storeSource);
  assert.doesNotMatch(storeCode, /\bwithSessionLock\s*\(/);
  assert.doesNotMatch(storeCode, /\bacquireSessionLock\s*\(/);
  assert.doesNotMatch(storeCode, /\bsessionLockPath\s*\(/);

  const parentSource = readSource("mcp/lib/session-state.js");
  const parentExportInfo = moduleExportsObjectInfo(parentSource, "session-state.js");
  const exportBlock = parentExportInfo.block;
  const movedHelpers = [...new Set([
    ...moduleExportedIdentifiers(storeSource, "session-state-store.js"),
    ...moduleExportedIdentifiers(readSource("mcp/lib/session-state-contracts.js"), "session-state-contracts.js"),
  ])].sort();
  for (const helper of movedHelpers) {
    assert.doesNotMatch(exportBlock, new RegExp(`\\b${helper}\\b`), `${helper} must not be exported from session-state.js`);
  }
  const parentOutsideExportBlock = [
    parentExportInfo.semanticCode.slice(0, parentExportInfo.assignmentStart),
    parentExportInfo.semanticCode.slice(parentExportInfo.blockEnd + 1),
  ].join("");
  assert.doesNotMatch(
    parentOutsideExportBlock,
    parentExportMutationPattern(),
    "session-state.js must not add parent barrel exports outside the explicit export object",
  );
  const rawParentExportStart = parentSource.indexOf("module.exports = {");
  assert.notEqual(rawParentExportStart, -1, "session-state.js must keep an explicit export object");
  const rawParentExportBraceStart = parentSource.indexOf("{", rawParentExportStart);
  const rawParentExportBraceEnd = findMatchingBrace(parentSource, rawParentExportBraceStart);
  const rawParentOutsideExportBlock = [
    parentSource.slice(0, rawParentExportStart),
    parentSource.slice(rawParentExportBraceEnd + 1),
  ].join("");
  assert.doesNotMatch(
    rawParentOutsideExportBlock,
    /\bmodule\s*\[\s*(?:["'`]exports["'`]|[A-Za-z_$][A-Za-z0-9_$]*)\s*\]|\bObject\s*\.\s*(?:assign|defineProperty|defineProperties)\s*\(\s*(?:exports\b|this\b|module\s*(?:\.\s*exports|\[\s*(?:["'`]exports["'`]|[A-Za-z_$][A-Za-z0-9_$]*)\s*\]))|\bReflect\s*\.\s*(?:set|defineProperty)\s*\(\s*(?:exports\b|this\b|module\s*(?:\.\s*exports|\[\s*(?:["'`]exports["'`]|[A-Za-z_$][A-Za-z0-9_$]*)\s*\]))|\bthis\s*(?:\.|\[)/,
    "session-state.js must not mutate module exports outside the explicit export object",
  );
  assert.match('Object.assign(module.exports, { readSessionStateStrict });', parentExportMutationPattern());
  assert.match('Object.assign(exports, { normalizeSessionStateDocument });', parentExportMutationPattern());
  assert.match('module["exports"].leak = readSessionStateStrict;', parentExportMutationPattern());
  assert.match("module[`exports`].leak2 = normalizeSessionStateDocument;", parentExportMutationPattern());
  assert.match('Object.defineProperty(exports, "readSessionStateStrict", { value: readSessionStateStrict });', parentExportMutationPattern());
  assert.match('Reflect.set(exports, "normalizeSessionStateDocument", normalizeSessionStateDocument);', parentExportMutationPattern());
  assert.match('Object.assign(this, { buildInitialSessionState });', parentExportMutationPattern());
  assert.match('this.leak = normalizeSessionStateDocument;', parentExportMutationPattern());
  assert.match('const slot = "exports"; module[slot].leak = readSessionStateStrict;', parentExportMutationPattern());
  assert.match('Object.assign(module[slot], { readSessionStateStrict });', parentExportMutationPattern());
});

test("session-state contraction cycle-return roots stay cycle-free", () => {
  const graph = runtimeRequireGraph();
  const closureRoots = [
    "mcp/lib/session-state-contracts.js",
    "mcp/lib/session-state-store.js",
    "mcp/lib/http-records.js",
    "mcp/lib/lead-intake.js",
    "mcp/lib/lead-scoring.js",
    "mcp/lib/lead-promotion.js",
    "mcp/lib/surface-leads.js",
  ];
  for (const file of reachableRuntimeFiles(graph, closureRoots)) {
    assertNoDynamicRequire(readSource(file), file);
  }
  for (const root of closureRoots) {
    assert.equal(firstReachableCycle(graph, root), null, `${root} must not reach a local require cycle`);
  }
});

test("state-writing surface lead helper is not exported unlocked", () => {
  // F.6 carved the legacy surface-leads.js into lead-intake (doc I/O +
  // normalization), lead-scoring (priority signals), and lead-promotion
  // (record + promote flow + session-lock wrappers). D.3 deleted the
  // surface-mutator.js shim: attack_surface.json is no longer written;
  // surface-index.json (materialized from frontier events) is the
  // authoritative surface source. The structural invariants are anchored to
  // the new files; surface-leads.js is now an aggregator shim.
  const promotionSource = readSource("mcp/lib/lead-promotion.js");
  const intakeSource = readSource("mcp/lib/lead-intake.js");
  const promotionExports = moduleExportsObjectBlock(promotionSource, "lead-promotion.js");
  const waveWrapperBody = functionBody(promotionSource, "promoteSurfaceLeadsForWave");
  const semanticWaveWrapperBody = sourceWithoutCommentsAndStrings(waveWrapperBody);
  assert.doesNotMatch(promotionExports, /\bpromoteSurfaceLeadsInternal\b/);
  assert.doesNotMatch(promotionExports, /\brecordSurfaceLeadsInternal\b/);
  assert.match(promotionExports, /\bpromoteSurfaceLeadsForWave\b/);
  assert.match(promotionExports, /\brecordSurfaceLeadsForWaveHandoff\b/);
  assertOnlyCheckedSurfaceLeadInternalReferences(promotionSource);
  assertOnlyCheckedInternalHelperReferences(promotionSource, "recordSurfaceLeadsInternal");
  assertCallsInsideSessionLock(promotionSource, "promoteSurfaceLeadsForWave", "promoteSurfaceLeadsInternal");
  const waveWrapperCalls = callExpressions(semanticWaveWrapperBody, "promoteSurfaceLeadsInternal");
  assert.equal(waveWrapperCalls.length, 1, "wave promotion wrapper must have exactly one internal promotion call");
  assert.equal(
    normalizeExpression(waveWrapperCalls[0].args[0] && waveWrapperCalls[0].args[0].text),
    "domain",
    "wave promotion wrapper must call the internal helper with domain",
  );
  assert.match(
    waveWrapperCalls[0].args[1] && waveWrapperCalls[0].args[1].text,
    /^\s*{\s*\.\.\.options\s*,\s*update_state:\s*false\s*,?\s*}\s*$/,
    "wave promotion wrapper must spread options before forcing update_state false",
  );
  assert.doesNotMatch(
    semanticWaveWrapperBody.replace(/\bpromoteSurfaceLeadsInternal\s*\(\s*domain\s*,\s*{\s*\.\.\.options\s*,\s*update_state:\s*false\s*,?\s*}\s*\)/, ""),
    /\bpromoteSurfaceLeadsInternal\b/,
    "wave promotion wrapper must not reference the internal helper outside the checked call",
  );
  assert.doesNotMatch(semanticWaveWrapperBody, /\bupdate_state:\s*true\b/);

  const waveSchedulerSource = readSource("mcp/lib/waves/wave-scheduler.js");
  const waveAssignmentStoreSource = readSource("mcp/lib/waves/wave-assignment-store.js");
  for (const source of [waveSchedulerSource, waveAssignmentStoreSource]) {
    assert.doesNotMatch(source, /\bpromoteSurfaceLeadsInternal\b/);
    assert.doesNotMatch(source, /\brecordSurfaceLeadsInternal\b/);
  }
  assert.match(waveSchedulerSource, /\bpromoteSurfaceLeadsForWave\b/);
  assert.match(waveAssignmentStoreSource, /\brecordSurfaceLeadsForWaveHandoff\b/);
  assertCallsInsideSessionLock(waveAssignmentStoreSource, "writeWaveHandoff", "recordSurfaceLeadsForWaveHandoff");
  assert.deepEqual(runtimeCallSummaries("writeSurfaceLeadsDocument"), [
    "mcp/lib/lead-promotion.js:promoteSurfaceLeadsInternal",
    "mcp/lib/lead-promotion.js:recordSurfaceLeadsInternal",
  ].sort());
  // writeSurfaceLeadsDocument lives in lead-intake (doc I/O) and is consumed
  // cross-module by lead-promotion's record/promote internals. The legacy
  // "no external references" invariant no longer applies; structural callers
  // are pinned by the runtimeCallSummaries check above.
  const intakeFunctions = namedFunctionRanges(sourceWithoutCommentsAndStrings(intakeSource));
  const intakeArtifactWrites = callExpressions(sourceWithoutCommentsAndStrings(intakeSource), "writeFileAtomic")
    .flatMap((call) => {
      const firstArg = normalizeExpression(call.args[0] && call.args[0].text);
      if (firstArg !== "filePath") return [];
      const owner = intakeFunctions.find((fn) => fn.bodyStart < call.callIndex && call.callIndex < fn.bodyEnd);
      return [`${owner ? owner.name : "<top-level>"}:${firstArg}`];
    })
    .sort();
  assert.deepEqual(intakeArtifactWrites, [
    "writeSurfaceLeadsDocument:filePath",
  ]);
  assert.match(
    functionBody(sourceWithoutCommentsAndStrings(intakeSource), "writeSurfaceLeadsDocument"),
    /\bconst\s+filePath\s*=\s*surfaceLeadsPath\s*\(\s*domain\s*\)/,
    "writeSurfaceLeadsDocument must derive filePath from surfaceLeadsPath(domain)",
  );
  const runtimeSurfaceArtifactPathWrites = [];
  for (const relativePath of listRuntimeJsFiles()) {
    runtimeSurfaceArtifactPathWrites.push(...surfaceArtifactWriteSummaries(relativePath, readSource(relativePath)));
  }
  // D.3 deleted the legacy attack_surface.json writer; the only runtime
  // surface-artifact write is surface-leads.json from lead-intake.
  assert.deepEqual(runtimeSurfaceArtifactPathWrites.sort(), [
    "mcp/lib/lead-intake.js:writeSurfaceLeadsDocument:writeFileAtomic:surfaceLeadsPath",
  ]);
  assertSurfaceArtifactRollbackRestoreIsLocked(waveSchedulerSource);
  assert.deepEqual(surfaceArtifactWriteSummaries("fixture.js", `
    const fs = require("fs");
    function direct(domain) { fs.writeFileSync(surfaceLeadsPath(domain), "{}"); }
    function aliased(domain) {
      const target = surfaceLeadsPath(domain);
      writeFileAtomic(target, "{}");
    }
    function propertyAlias(domain) {
      const cfg = { path: surfaceLeadsPath(domain) };
      writeFileAtomic(cfg.path, "{}");
    }
    function makePath(domain) { return surfaceLeadsPath(domain); }
    function functionAlias(domain) { writeFileAtomic(makePath(domain), "{}"); }
    const arrowPath = (domain) => surfaceLeadsPath(domain);
    function arrowAlias(domain) { writeFileAtomic(arrowPath(domain), "{}"); }
    const blockArrowPath = (domain) => { return surfaceLeadsPath(domain); };
    function blockArrowAlias(domain) { writeFileAtomic(blockArrowPath(domain), "{}"); }
    const functionExpressionPath = function(domain) { return surfaceLeadsPath(domain); };
    function functionExpressionAlias(domain) { writeFileAtomic(functionExpressionPath(domain), "{}"); }
    const pathBag = { make(domain) { return surfaceLeadsPath(domain); } };
    function methodAlias(domain) { writeFileAtomic(pathBag.make(domain), "{}"); }
    const directFunctionPath = surfaceLeadsPath;
    function directFunctionAlias(domain) { writeFileAtomic(directFunctionPath(domain), "{}"); }
    class LeadStore {
      constructor(domain) { this.path = surfaceLeadsPath(domain); }
      write() { writeFileAtomic(this.path, "{}"); }
    }
  `).sort(), [
    "fixture.js:<top-level>:writeFileAtomic:surfaceLeadsPath",
    "fixture.js:aliased:writeFileAtomic:surfaceLeadsPath",
    "fixture.js:arrowAlias:writeFileAtomic:surfaceLeadsPath",
    "fixture.js:blockArrowAlias:writeFileAtomic:surfaceLeadsPath",
    "fixture.js:direct:writeFileSync:surfaceLeadsPath",
    "fixture.js:directFunctionAlias:writeFileAtomic:surfaceLeadsPath",
    "fixture.js:functionAlias:writeFileAtomic:surfaceLeadsPath",
    "fixture.js:functionExpressionAlias:writeFileAtomic:surfaceLeadsPath",
    "fixture.js:methodAlias:writeFileAtomic:surfaceLeadsPath",
    "fixture.js:propertyAlias:writeFileAtomic:surfaceLeadsPath",
  ]);
  assert.throws(
    () => assertOnlyCheckedSurfaceLeadInternalReferences(`
      function promoteSurfaceLeadsInternal(domain, options = {}) {
        return { domain, options };
      }
      const unsafePromote = promoteSurfaceLeadsInternal;
      function promoteSurfaceLeadsForWave(domain, options = {}) {
        promoteSurfaceLeadsInternal(domain, { ...options, update_state: false });
        return unsafePromote(domain, options);
      }
    `),
    /must only appear/,
  );
});

test("session-state store write callers keep explicit lock boundaries", () => {
  assertStoreWriterBindingIsNotAliased();
  assert.deepEqual(requireSpecs('const fs = require ("fs");'), ["fs"]);
  assert.deepEqual(requireSpecs('const dependency = `${require("./session-state.js")}`;'), ["./session-state.js"]);
  assert.throws(
    () => assertNoDynamicRequire('const dependency = import("./session-state.js");', "fixture"),
    /must not use dynamic import/,
  );
  assert.throws(
    () => assertNoDynamicRequire("const dependency = require (moduleName);", "fixture"),
    /must not use dynamic require/,
  );
  assert.throws(
    () => assertNoDynamicRequire("const dependency = `${require(moduleName)}`;", "fixture"),
    /must not use dynamic require/,
  );
  assert.throws(
    () => assertNoDynamicRequire('const dependency = require("./session-state" + ".js");', "fixture"),
    /must not use dynamic require/,
  );
  assert.throws(
    () => assertNoDynamicRequire('const load = require; const dependency = load("./session-state.js");', "fixture"),
    /must not alias require/,
  );
  assert.throws(
    () => assertNoDynamicRequire('const marker = "/*"; const load = require; const done = "*/";', "fixture"),
    /must not alias require/,
  );
  assert.throws(
    () => assertSourceDoesNotAliasStoreWriter(
      "fixture.js",
      'const store = require("./session-state-store"); const writeState = store.writeSessionStateDocument; writeState(domain, raw, state);',
    ),
    /namespace imports|destructure session-state-store/,
  );
  assert.throws(
    () => assertSourceDoesNotAliasStoreWriter(
      "fixture.js",
      'require("./session-state-store")["writeSessionStateDocument"](domain, raw, state);',
    ),
    /destructure session-state-store/,
  );
  assert.throws(
    () => assertSourceDoesNotAliasStoreWriter(
      "fixture.js",
      "const writer = { write: writeSessionStateDocument }; writer.write(domain, raw, state);",
    ),
    /object properties/,
  );
  assert.throws(
    () => assertSourceDoesNotAliasStoreWriter(
      "fixture.js",
      "const writer = { writeSessionStateDocument }; Object.values(writer)[0](domain, raw, state);",
    ),
    /only reference/,
  );
  assert.throws(
    () => assertSourceDoesNotAliasStoreWriter(
      "fixture.js",
      "module.exports.writeState = writeSessionStateDocument; module.exports.writeState(domain, raw, state);",
    ),
    /assign/,
  );
  assert.throws(
    () => assertSourceDoesNotAliasStoreWriter(
      "mcp/lib/session-state-store.js",
      "function writeSessionStateDocument(domain, raw, state) { return { domain, raw, state }; } module.exports.writeState = writeSessionStateDocument;",
    ),
    /assign/,
  );
  assert.throws(
    () => assertSourceDoesNotAliasStoreWriter(
      "mcp/lib/session-state-store.js",
      'function writeSessionStateDocument(domain, raw, state) { return { domain, raw, state }; } module.exports = { writeSessionStateDocument, ...Object.fromEntries([["writeState", writeSessionStateDocument]]) };',
    ),
    /only reference/,
  );
  assert.throws(
    () => assertSourceDoesNotAliasStoreWriter(
      "fixture.js",
      "writeSessionStateDocument.call(null, domain, raw, state);",
    ),
    /call\/apply\/bind/,
  );
  assert.throws(
    () => assertSourceDoesNotAliasStoreWriter(
      "fixture.js",
      "(writeSessionStateDocument)(domain, raw, state);",
    ),
    /only reference/,
  );
  assert.throws(
    () => assertSourceDoesNotAliasStoreWriter(
      "fixture.js",
      "[writeSessionStateDocument][0](domain, raw, state);",
    ),
    /only reference/,
  );
  assert.throws(
    () => assertSourceDoesNotAliasStoreWriter(
      "fixture.js",
      'const marker = "/*"; const writer = writeSessionStateDocument; const done = "*/";',
    ),
    /after import/,
  );
  const directStoreWriterLockChecks = [
    // Cycle O.1: repo-target.initRepoSession is the bootstrap path for
    // OSS-axis sessions and writes state.json under its own withSessionLock,
    // mirroring the contract for session-state.initSession.
    { relativePath: "mcp/lib/repo-target.js", functionName: "initRepoSession", callCount: 1 },
    { relativePath: "mcp/lib/session-state.js", functionName: "advanceSession", callCount: 2 },
    { relativePath: "mcp/lib/session-state.js", functionName: "assertSessionEgressIdentity", callCount: 1 },
    { relativePath: "mcp/lib/session-state.js", functionName: "clearOperatorNote", callCount: 1 },
    { relativePath: "mcp/lib/session-state.js", functionName: "clearTerminalBlock", callCount: 1 },
    { relativePath: "mcp/lib/session-state.js", functionName: "initSession", callCount: 1 },
    { relativePath: "mcp/lib/session-state.js", functionName: "setOperatorNote", callCount: 1 },
    { relativePath: "mcp/lib/waves/wave-merge-settler.js", functionName: "applyWaveMerge", callCount: 1 },
  ];
  const storeWriterSummaries = runtimeCallSummaries("writeSessionStateDocument");
  assert.deepEqual(
    storeWriterSummaries.filter((summary) => summary.endsWith(":<top-level>")),
    [],
    "writeSessionStateDocument calls must be owned by named functions before they can be allowed",
  );
  for (const { relativePath, functionName } of directStoreWriterLockChecks) {
    assertCallsInsideSessionLock(readSource(relativePath), functionName, "writeSessionStateDocument");
  }

  const waveSchedulerSource = readSource("mcp/lib/waves/wave-scheduler.js");
  const waveAssignmentStoreSource = readSource("mcp/lib/waves/wave-assignment-store.js");
  const promotionSource = readSource("mcp/lib/lead-promotion.js");
  // Cycle D.3 removed state.lead_surface_ids from the session-state
  // contract; lead-promotion no longer writes state.json, so it is no
  // longer a delegated store writer. The startWaveLocked path remains the
  // sole locked delegated writer in the wave plane.
  const delegatedStoreWriterChecks = [
    {
      relativePath: "mcp/lib/waves/wave-scheduler.js",
      helperName: "startWaveLocked",
      source: waveSchedulerSource,
      lockedCallers: ["startWave", "startNextWave"],
      stateDisabledCallers: [],
      referenceGate: "startWaveLocked",
      mustNotExport: true,
    },
  ];
  for (const delegatedCheck of delegatedStoreWriterChecks) assertDelegatedStoreWriterCheck(delegatedCheck);
  const expectedStoreWriterSummaries = [
    ...directStoreWriterLockChecks.flatMap(({ relativePath, functionName, callCount }) => (
      Array.from({ length: callCount }, () => `${relativePath}:${functionName}`)
    )),
    ...delegatedStoreWriterChecks.map(delegatedWriterSummary),
  ].sort();
  assert.deepEqual(storeWriterSummaries, expectedStoreWriterSummaries);

  assert.deepEqual(runtimeCallSummaries("promoteSurfaceLeadsInternal"), [
    "mcp/lib/lead-promotion.js:promoteSurfaceLeads",
    "mcp/lib/lead-promotion.js:promoteSurfaceLeadsForWave",
  ].sort());
  assert.deepEqual(runtimeCallSummaries("recordSurfaceLeadsInternal"), [
    "mcp/lib/lead-promotion.js:recordStaticAnalysisLeads",
    "mcp/lib/lead-promotion.js:recordSurfaceLeads",
    "mcp/lib/lead-promotion.js:recordSurfaceLeadsForWaveHandoff",
  ].sort());
  assert.deepEqual(runtimeCallSummaries("recordSurfaceLeadsForWaveHandoff"), [
    "mcp/lib/waves/wave-assignment-store.js:writeWaveHandoff",
  ]);
  assertCallsInsideSessionLock(promotionSource, "recordSurfaceLeads", "recordSurfaceLeadsInternal");
  assertCallsInsideSessionLock(promotionSource, "recordStaticAnalysisLeads", "recordSurfaceLeadsInternal");
  assertCallsInsideSessionLock(promotionSource, "recordSurfaceLeadsForWaveHandoff", "recordSurfaceLeadsInternal");
  assertCallsInsideSessionLock(waveAssignmentStoreSource, "writeWaveHandoff", "recordSurfaceLeadsForWaveHandoff");
  // Cycle D.3 removed lead-promotion's runtime use of update_state; the
  // assertion-mechanism throw fixtures below still validate the
  // state-disabled invariant shape against a synthetic proof so the
  // test infrastructure stays exercised.
  const stateDisabledPromotionProof = {
    functionName: "promoteSurfaceLeadsForWave",
    callCount: 1,
    firstArg: "domain",
    stateDisabledOptionsArg: {
      position: 1,
      requiredLeadingSpread: "options",
      forcedBooleanLast: {
        name: "update_state",
        value: false,
      },
    },
  };
  assert.throws(
    () => assertStateDisabledDelegatedCalls(`
      function promoteSurfaceLeadsForWave(domain, options = {}) {
        return promoteSurfaceLeadsInternal(domain, { ...options, update_state: false });
      }
    `, "promoteSurfaceLeadsInternal", {
      ...stateDisabledPromotionProof,
      requiredPattern: /./,
    }),
    /body-level requiredPattern/,
  );
  assert.throws(
    () => assertStateDisabledDelegatedCalls(`
      function promoteSurfaceLeadsForWave(domain, options = {}) {
        return promoteSurfaceLeadsInternal(domain, { ...options, update_state: true });
      }
    `, "promoteSurfaceLeadsInternal", stateDisabledPromotionProof),
    /update_state:false/,
  );
  assert.throws(
    () => assertStateDisabledDelegatedCalls(`
      function promoteSurfaceLeadsForWave(domain, options = {}) {
        promoteSurfaceLeadsInternal(domain, { ...options, update_state: false });
        return promoteSurfaceLeadsInternal(domain, { ...options, update_state: true });
      }
    `, "promoteSurfaceLeadsInternal", stateDisabledPromotionProof),
    /exactly 1 time/,
  );
  assert.throws(
    () => assertStateDisabledDelegatedCalls(`
      function promoteSurfaceLeadsForWave(domain, options = {}) {
        return promoteSurfaceLeadsInternal(domain, { update_state: false, ...options });
      }
    `, "promoteSurfaceLeadsInternal", stateDisabledPromotionProof),
    /spread options before forcing/,
  );
  assert.throws(
    () => assertStateDisabledDelegatedCalls(`
      function promoteSurfaceLeadsForWave(domain, options = {}) {
        return promoteSurfaceLeadsInternal(domain, { ...options, limit: 50, update_state: false });
      }
    `, "promoteSurfaceLeadsInternal", stateDisabledPromotionProof),
    /only the leading options spread/,
  );
  assert.throws(
    () => moduleExportsObjectBlock("const exportsObject = {};", "surface-leads.js"),
    /explicit module\.exports object/,
  );
  assert.throws(
    () => assertCallsInsideSessionLock(`
      function badWrite(domain, otherDomain, raw, state) {
        return withSessionLock(otherDomain, () => {
          writeSessionStateDocument(domain, raw, state);
        });
      }
    `, "badWrite", "writeSessionStateDocument"),
    /matching withSessionLock\(domain\)/,
  );
  assert.throws(
    () => assertCallsInsideSessionLock(`
      function asyncWrite(domain, raw, state) {
        return withSessionLock(domain, async () => {
          await Promise.resolve();
          writeSessionStateDocument(domain, raw, state);
        });
      }
    `, "asyncWrite", "writeSessionStateDocument"),
    /must not be async/,
  );
  assert.throws(
    () => assertCallsInsideSessionLock(`
      function deferredWrite(domain, raw, state) {
        return withSessionLock(domain, () => {
          setImmediate(() => writeSessionStateDocument(domain, raw, state));
        });
      }
    `, "deferredWrite", "writeSessionStateDocument"),
    /must not schedule deferred callbacks/,
  );
  assert.throws(
    () => assertCallsInsideSessionLock(`
      function namedDeferredWrite(domain, raw, state) {
        return withSessionLock(domain, () => {
          function later() { writeSessionStateDocument(domain, raw, state); }
          setImmediate(later);
        });
      }
    `, "namedDeferredWrite", "writeSessionStateDocument"),
    /must not schedule deferred callbacks/,
  );
  assert.throws(
    () => assertCallsInsideSessionLock(`
      function promiseDeferredWrite(domain, raw, state) {
        return withSessionLock(domain, () => {
          Promise.resolve().finally(() => writeSessionStateDocument(domain, raw, state));
        });
      }
    `, "promiseDeferredWrite", "writeSessionStateDocument"),
    /must not schedule deferred callbacks/,
  );
  assert.throws(
    () => assertCallsInsideSessionLock(`
      function callDeferredWrite(domain, raw, state) {
        return withSessionLock(domain, () => {
          setTimeout.call(null, () => writeSessionStateDocument(domain, raw, state), 0);
        });
      }
    `, "callDeferredWrite", "writeSessionStateDocument"),
    /must not schedule deferred callbacks/,
  );
  assert.throws(
    () => assertCallsInsideSessionLock(`
      function reflectDeferredWrite(domain, raw, state) {
        return withSessionLock(domain, () => {
          Reflect.apply(setImmediate, null, [() => writeSessionStateDocument(domain, raw, state)]);
        });
      }
    `, "reflectDeferredWrite", "writeSessionStateDocument"),
    /must not schedule deferred callbacks/,
  );
  assert.throws(
    () => assertCallsInsideSessionLock(`
      function bracketPromiseDeferredWrite(domain, raw, state) {
        return withSessionLock(domain, () => {
          Promise.resolve()["then"](() => writeSessionStateDocument(domain, raw, state));
        });
      }
    `, "bracketPromiseDeferredWrite", "writeSessionStateDocument"),
    /computed properties/,
  );
  assert.throws(
    () => assertCallsInsideSessionLock(`
      function eventDeferredWrite(domain, raw, state) {
        return withSessionLock(domain, () => {
          process.once("beforeExit", () => writeSessionStateDocument(domain, raw, state));
        });
      }
    `, "eventDeferredWrite", "writeSessionStateDocument"),
    /must not schedule deferred callbacks/,
  );
  assert.throws(
    () => assertCallsInsideSessionLock(`
      function reflectEventDeferredWrite(domain, raw, state) {
        return withSessionLock(domain, () => {
          Reflect.apply(process.once, process, ["beforeExit", () => writeSessionStateDocument(domain, raw, state)]);
        });
      }
    `, "reflectEventDeferredWrite", "writeSessionStateDocument"),
    /must not schedule deferred callbacks/,
  );
  assert.throws(
    () => assertCallsInsideSessionLock(`
      function callbackDeferredWrite(domain, raw, state) {
        return withSessionLock(domain, () => {
          fs.readFile(statePath(domain), () => writeSessionStateDocument(domain, raw, state));
        });
      }
    `, "callbackDeferredWrite", "writeSessionStateDocument"),
    /must not call writeSessionStateDocument from a nested callback/,
  );
  assertCallsInsideSessionLock(`
    const arrowWrite = (domain, raw, state) => withSessionLock(domain, () => {
      writeSessionStateDocument(domain, raw, state);
    });
  `, "arrowWrite", "writeSessionStateDocument");
  assert.throws(
    () => assertCallsInsideSessionLock(`
      const arrowWrite = (domain, raw, state) => writeSessionStateDocument(domain, raw, state);
    `, "arrowWrite", "writeSessionStateDocument"),
    /matching withSessionLock\(domain\)/,
  );
  assert.throws(
    () => assertOnlyCheckedStartWaveLockedReferences(`
      function startWaveLocked(domain, options = {}) { return options; }
      const unsafeStartWave = startWaveLocked;
    `),
    /only appear/,
  );
});

test("same-domain session locks stay reentrant for nested surface-lead wrappers", () => {
  withTempHome(() => {
    const domain = "nested-surface-lead-lock.example";
    const events = [];
    const result = withSessionLock(domain, () => {
      events.push("outer");
      return withSessionLock(domain, () => {
        events.push("inner");
        return "nested-ok";
      });
    });

    assert.equal(result, "nested-ok");
    assert.deepEqual(events, ["outer", "inner"]);
  });
});

test("session-state-store reads normalized state while preserving raw authority fields", () => {
  withTempHome(() => {
    const domain = "store-read.example";
    writeState(domain, {
      target: "drifted.example",
      custom_legacy_field: "preserve-me",
      block_internal_hosts: true,
      block_internal_hosts_source: "explicit_block",
    });

    const read = readSessionStateStrict(domain);
    assert.equal(read.raw.target, "drifted.example");
    assert.equal(read.raw.custom_legacy_field, "preserve-me");
    assert.equal(read.state.target, domain);
    assert.equal(read.state.block_internal_hosts, true);
    assert.equal(read.state.block_internal_hosts_source, "explicit_block");
  });
});

test("session-state-store reports missing and malformed state consistently", () => {
  withTempHome(() => {
    assert.throws(
      () => readSessionStateStrict("missing.example"),
      /Missing session state:/,
    );

    const domain = "malformed.example";
    fs.mkdirSync(sessionDir(domain), { recursive: true });
    writeFileAtomic(statePath(domain), "{not json");

    assert.throws(
      () => readSessionStateStrict(domain),
      /Malformed session state:/,
    );
  });
});

test("session-state-store writes preserve unknown raw fields and rely on caller locks", () => {
  withTempHome(() => {
    const domain = "store-write.example";
    const raw = writeState(domain, {
      custom_legacy_field: "keep",
      operator_note: "old note",
    });
    const read = readSessionStateStrict(domain);

    withSessionLock(domain, () => {
      writeSessionStateDocument(domain, read.raw, {
        ...read.state,
        operator_note: "new note",
      });
    });

    const written = JSON.parse(fs.readFileSync(statePath(domain), "utf8"));
    assert.equal(written.custom_legacy_field, raw.custom_legacy_field);
    assert.equal(written.operator_note, "new note");
  });
});

test("session-state-store internal-host policy preserves session precedence and missing fallback", () => {
  withTempHome(() => {
    const domain = "policy.example";
    writeState(domain, {
      checkpoint_mode: "paranoid",
      block_internal_hosts: true,
      block_internal_hosts_source: "paranoid_default",
    });

    assert.deepEqual(blockInternalHostsRequestPolicy(domain, {}), {
      checkpoint_mode: "paranoid",
      block_internal_hosts: true,
      block_internal_hosts_source: "paranoid_default",
      block_internal_hosts_effective_source: "session",
    });
    assert.deepEqual(blockInternalHostsRequestPolicy("missing-policy.example", {}, {
      allowMissingSession: true,
    }), {
      checkpoint_mode: "normal",
      block_internal_hosts: false,
      block_internal_hosts_source: "legacy_default",
      block_internal_hosts_effective_source: "legacy_default",
    });
    assert.deepEqual(blockInternalHostsRequestPolicy("missing-policy.example", {
      block_internal_hosts: true,
    }, {
      allowMissingSession: true,
    }), {
      checkpoint_mode: "normal",
      block_internal_hosts: true,
      block_internal_hosts_source: "request_override",
      block_internal_hosts_effective_source: "request",
    });
    assert.throws(
      () => blockInternalHostsRequestPolicy("missing-policy.example", {}),
      /Missing session state:/,
    );
  });
});
