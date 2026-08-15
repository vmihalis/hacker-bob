"use strict";

// Facts about a JavaScript source that a gate may rely on, read from a PARSE
// rather than from token-shaped text. Sibling of scripts/lib/closed-commonjs-loader.js
// and held to the same principle its header states: operate on an AST, never on
// comments or token-shaped text.
//
// A hand-written mode machine that must tell `/` as division from `/` as the
// start of a literal is choosing a heuristic. The usual one — look at the
// previous significant token — is wrong on at least `return /re/`, `case /re/`,
// and the ASI boundary where a newline ends the previous statement, and getting
// it wrong is not a near miss: a regex literal holding a quote opens a string
// mode that swallows every comment until the next matching quote, so the gate
// silently reads prose as code over a window it never reports. The tokenizer
// already made that decision correctly. Do not make it again.
//
// Every entry point is read-only and hermetic: no clock, no randomness, no
// network, no writes. A source the parser cannot read raises a tagged error so
// the caller can fail closed on it instead of skipping it or mis-reading it.

const babelParser = require("@babel/parser");

const JS_PARSE_ERROR_CODE = "js_source_parse_failed";

function parseJsSource(source, label) {
  try {
    return babelParser.parse(source, {
      sourceType: "unambiguous",
      sourceFilename: label,
      allowReturnOutsideFunction: true,
      errorRecovery: false,
    });
  } catch (err) {
    const error = new Error(`${label}: ${err && err.message ? err.message : String(err)}`);
    error.code = JS_PARSE_ERROR_CODE;
    error.label = label;
    error.parse_message = err && err.message ? err.message : String(err);
    throw error;
  }
}

// Blank every comment to spaces, leaving newlines in place. Byte offsets and
// total length are preserved character-for-character, so a caller that indexes
// into the result — or diffs it line-by-line against the original — does not
// have to know this happened.
function blankComments(source, label) {
  const ast = parseJsSource(source, label);
  const comments = Array.isArray(ast.comments) ? ast.comments : [];
  if (comments.length === 0) return source;
  // Babel's offsets are UTF-16 code-unit indices, so split into code units
  // rather than code points and the length is preserved exactly.
  const units = source.split("");
  for (const comment of comments) {
    for (let i = comment.start; i < comment.end && i < units.length; i += 1) {
      if (units[i] !== "\n") units[i] = " ";
    }
  }
  return units.join("");
}

function staticStringValue(node) {
  if (!node) return null;
  if (node.type === "StringLiteral") return node.value;
  if (node.type === "TemplateLiteral" && node.expressions.length === 0 && node.quasis.length === 1) {
    const cooked = node.quasis[0].value.cooked;
    return typeof cooked === "string" ? cooked : null;
  }
  return null;
}

// The static name a key/property node denotes, or null when it is computed from
// something the gate cannot read.
function staticPropertyName(node, computed) {
  if (!node) return null;
  if (!computed && node.type === "Identifier") return node.name;
  if (node.type === "StringLiteral") return node.value;
  if (!computed && node.type === "NumericLiteral") return String(node.value);
  return null;
}

// The name an assignment target is anchored on: a bare binding, or the trailing
// property of a member chain (`a.b.field` anchors on `field`).
function targetAnchorName(node) {
  if (!node) return null;
  if (node.type === "Identifier") return node.name;
  if (node.type === "MemberExpression") return staticPropertyName(node.property, node.computed);
  return null;
}

function walk(node, visit) {
  if (node == null || typeof node !== "object") return;
  if (Array.isArray(node)) {
    for (const item of node) walk(item, visit);
    return;
  }
  if (typeof node.type !== "string") return;
  visit(node);
  for (const key of Object.keys(node)) {
    if (key === "loc" || key === "start" || key === "end" || key === "extra"
        || key === "comments" || key === "tokens" || key === "errors"
        || key === "leadingComments" || key === "trailingComments"
        || key === "innerComments") continue;
    walk(node[key], visit);
  }
}

// A NUL joins the two halves of a pair key: neither an identifier nor a
// string-literal key can hold one, so ("a\0b", "c") cannot collide with
// ("a", "b\0c").
const PAIR_SEPARATOR = "\u0000";

function pairKey(field, member) {
  return `${field}${PAIR_SEPARATOR}${member}`;
}

// Every KEY-ANCHORED EXECUTABLE WRITE in the source, as `field` → `member`
// pairs. Anchored on the field so an unrelated occurrence of the member string
// (a comparison, a log line, a different key) is not a write. Four shapes, one
// per emitter the gate recognises:
//
//   { field: "member" }            an object property whose value is a literal
//   field = "member"               an assignment or declaration of a binding
//   x.field = "member"             or of a statically named property
//   field.member += 1 / ++         a counter incremented on an accumulator
//   field["member"] += 1 / ++      the computed form of the same counter
function collectKeyedWrites(source, label) {
  const ast = parseJsSource(source, label);
  const writes = new Set();

  const recordCounter = (target) => {
    if (!target || target.type !== "MemberExpression") return;
    const member = staticPropertyName(target.property, target.computed);
    if (member === null) return;
    const field = targetAnchorName(target.object);
    if (field === null) return;
    writes.add(pairKey(field, member));
  };

  walk(ast.program, (node) => {
    if (node.type === "ObjectProperty" && !node.shorthand) {
      const field = staticPropertyName(node.key, node.computed);
      const member = staticStringValue(node.value);
      if (field !== null && member !== null) writes.add(pairKey(field, member));
      return;
    }
    if (node.type === "AssignmentExpression") {
      if (node.operator === "=") {
        const field = targetAnchorName(node.left);
        const member = staticStringValue(node.right);
        if (field !== null && member !== null) writes.add(pairKey(field, member));
      }
      recordCounter(node.left);
      return;
    }
    if (node.type === "UpdateExpression") {
      recordCounter(node.argument);
      return;
    }
    if (node.type === "VariableDeclarator" && node.id && node.id.type === "Identifier") {
      const member = staticStringValue(node.init);
      if (member !== null) writes.add(pairKey(node.id.name, member));
    }
  });

  return writes;
}

function hasKeyedWrite(writes, field, member) {
  return writes.has(pairKey(field, member));
}

// The shapes a module edge can be written in, one name per shape. ONE
// definition site: the reader stamps `callee_form` from here and every caller
// discriminates on the same strings rather than re-deriving the shape from the
// other fields.
const REQUIRE_CALLEE_FORMS = Object.freeze({
  REQUIRE: "require",
  DYNAMIC_IMPORT: "dynamic_import",
  MEMBER_REQUIRE: "member_require",
  REQUIRE_RESOLVE: "require_resolve",
  ALIAS_BINDING: "require_alias_binding",
});

// A module-scope `const` bound to `path.resolve(__dirname, ...)` or
// `path.join(__dirname, ...)` over string literals, as `name` -> the RELATIVE
// specifier it denotes. Deliberately hard-narrow: this is a constant fold, not
// a dataflow analysis, and its whole purpose is that `require(SOME_PATH)` — the
// one shape this tree actually writes — stops being an edge nobody can follow.
//
// The specifier is returned RELATIVE (`./x.js`) rather than as the absolute
// path the runtime computes: a caller resolves it against the importing file,
// which is exactly what `path.resolve(__dirname, ...)` means, and an absolute
// string would read to that caller as a package rather than a local edge.
//
// A name that is reassigned, updated, or bound more than once anywhere in the
// file is dropped: two bindings mean the fold would have to know which one is
// in scope at the call, and it does not.
//
// That once-only count is the WHOLE safety argument, because the fold is keyed
// by name and blind to scope — so it has to see every form a name can be bound
// in. Every name a binding target introduces, whatever pattern it is written
// in, comes from here: one derivation shared by the declarator arm, the
// parameter arm, the catch parameter, and the two hoisted declaration forms.
// An Identifier-only test saw `const X = …` but not `const { X } = …`, which
// left a destructured shadow uncounted and folded the call against the wrong
// file.
function collectBindingNames(node, out) {
  if (!node || typeof node.type !== "string") return out;
  switch (node.type) {
    case "Identifier":
      out.push(node.name);
      break;
    case "ObjectPattern":
      for (const property of node.properties) {
        if (property.type === "RestElement") collectBindingNames(property.argument, out);
        else if (property.type === "ObjectProperty") collectBindingNames(property.value, out);
      }
      break;
    case "ArrayPattern":
      // A hole in `[, x]` is a null element, which the guard above drops.
      for (const element of node.elements) collectBindingNames(element, out);
      break;
    case "AssignmentPattern":
      collectBindingNames(node.left, out);
      break;
    case "RestElement":
      collectBindingNames(node.argument, out);
      break;
    default:
      break;
  }
  return out;
}

function collectFoldableModulePaths(program) {
  const bindingCounts = new Map();
  const rebound = new Set();
  const bump = (name) => bindingCounts.set(name, (bindingCounts.get(name) || 0) + 1);
  const bumpBindings = (node) => { for (const name of collectBindingNames(node, [])) bump(name); };
  walk(program, (node) => {
    if (node.type === "AssignmentExpression" && node.left && node.left.type === "Identifier") {
      rebound.add(node.left.name);
      return;
    }
    if (node.type === "UpdateExpression" && node.argument && node.argument.type === "Identifier") {
      rebound.add(node.argument.name);
      return;
    }
    // Not exclusive: a FunctionDeclaration binds its own name AND its params.
    if (node.type === "VariableDeclarator") bumpBindings(node.id);
    if (node.type === "CatchClause") bumpBindings(node.param);
    if (node.type === "FunctionDeclaration" || node.type === "ClassDeclaration") bumpBindings(node.id);
    if (Array.isArray(node.params)) for (const param of node.params) bumpBindings(param);
  });
  const isStable = (name) => bindingCounts.get(name) === 1 && !rebound.has(name);

  const pathBindings = new Set();
  const foldable = new Map();
  for (const statement of program.body) {
    if (statement.type !== "VariableDeclaration" || statement.kind !== "const") continue;
    for (const declarator of statement.declarations) {
      if (!declarator.id || declarator.id.type !== "Identifier" || !declarator.init) continue;
      if (!isStable(declarator.id.name)) continue;
      const init = declarator.init;
      if (init.type === "CallExpression" && init.callee && init.callee.type === "Identifier"
          && init.callee.name === "require") {
        const required = staticStringValue(init.arguments[0]);
        if (required === "path" || required === "node:path") pathBindings.add(declarator.id.name);
        continue;
      }
      const folded = foldDirnameJoin(init, pathBindings);
      if (folded !== null) foldable.set(declarator.id.name, folded);
    }
  }
  return foldable;
}

function foldDirnameJoin(node, pathBindings) {
  if (!node || node.type !== "CallExpression") return null;
  const callee = node.callee;
  if (!callee || callee.type !== "MemberExpression" || callee.computed) return null;
  if (!callee.object || callee.object.type !== "Identifier" || !pathBindings.has(callee.object.name)) return null;
  if (!callee.property || callee.property.type !== "Identifier") return null;
  if (callee.property.name !== "resolve" && callee.property.name !== "join") return null;
  const args = node.arguments;
  if (args.length < 2) return null;
  if (!args[0] || args[0].type !== "Identifier" || args[0].name !== "__dirname") return null;
  const parts = [];
  for (let i = 1; i < args.length; i += 1) {
    const part = staticStringValue(args[i]);
    // An absolute segment would make `resolve` discard __dirname entirely and
    // `join` mean something else again; refuse rather than guess between them.
    if (part === null || part === "" || part.startsWith("/")) return null;
    parts.push(part);
  }
  return `./${parts.join("/")}`;
}

// The half-open source ranges of every FUNCTION BODY in a program. A site
// inside one of these is evaluated when the function RUNS, not when the module
// loads — which is the only difference between an edge a reader sees at the top
// of a file and one that is written where nobody looks for it.
//
// Read from the parse for the same reason everything else here is: "is this
// require indented?" is a text question with a wrong answer, and `if (x)
// require(y)` at column 2 of the module body is a LOAD-time edge while a
// `require` on column 4 inside an arrow function is not.
function collectFunctionBodyRanges(program) {
  const ranges = [];
  walk(program, (node) => {
    if (node.type !== "FunctionDeclaration" && node.type !== "FunctionExpression"
        && node.type !== "ArrowFunctionExpression" && node.type !== "ObjectMethod"
        && node.type !== "ClassMethod" && node.type !== "ClassPrivateMethod") {
      return;
    }
    // An expression-bodied arrow (`() => require("x")`) has no BlockStatement,
    // and its body is still deferred, so the range is the body node either way.
    const body = node.body;
    if (!body || typeof body.start !== "number" || typeof body.end !== "number") return;
    ranges.push([body.start, body.end]);
  });
  return ranges;
}

// Every MODULE-EDGE SITE in the source, in source order, as
// `{ specifier, line, argument_type, callee_form, deferred }`.
//
// `deferred` is TRUE when the site sits inside a function body, so the edge is
// created when that function is CALLED rather than when the module loads. A
// deferred require is still an edge and is reported as one: deferring is how a
// dependency cycle is hidden from a reader without being removed, so a caller
// that wants to say a cycle was BROKEN has to be able to see that it was only
// moved. Nothing here treats a deferred site as absent.
//
// `specifier` is the string a caller can resolve AGAINST THE IMPORTING FILE, or
// NULL when the site exists but its target cannot be read statically
// (`require(name)`, `require(`${dir}/x`)`, `require()`). The null is deliberate
// and load-bearing: a caller that only wants resolvable edges has to look
// straight at the case it cannot resolve, so an unreadable edge is a decision
// rather than an omission. `argument_type` names the node that made it
// unreadable, for the report.
//
// `callee_form` names the SHAPE the edge is written in, from
// REQUIRE_CALLEE_FORMS. A bare `require` identifier is `require` and keeps the
// meaning it always had; the other four exist so that no edge form is both
// unresolved and unmentioned:
//
//   dynamic_import         `import(x)`. Resolves against the importing file
//                          exactly as `require` does, so a string literal SETS
//                          the specifier; an expression leaves it null.
//   member_require         `x.require(y)`. `module.require(y)` resolves against
//                          the importing file, so that receiver sets the
//                          specifier. Any OTHER receiver is
//                          `Module.prototype.require`, which resolves against
//                          the RECEIVER's path — resolving it here would be a
//                          wrong-base answer worse than silence, so it stays
//                          null and the caller names it.
//   require_resolve        `require.resolve(x)`. Still not a module edge: it
//                          asks where a module WOULD be, and this tree uses it
//                          only to probe for an installed package. The
//                          specifier is always null so no caller can mistake it
//                          for an import; it is returned rather than dropped so
//                          the exclusion can be counted instead of assumed.
//   require_alias_binding  `const r = require` / `const { require: r } = x`.
//                          Not a call at all — it is the point where this
//                          reader's completeness guarantee for the file ends.
//                          Chasing the alias would be dataflow; naming the
//                          binding lets the caller fail closed on the file.
//
// The reader is a parse, so a specifier written inside a comment or inside a
// regex literal is not a site at all.
function collectStaticRequires(source, label) {
  const ast = parseJsSource(source, label);
  const foldable = collectFoldableModulePaths(ast.program);
  const functionBodies = collectFunctionBodyRanges(ast.program);
  const sites = [];

  const record = (node, calleeForm, argumentType, specifier) => {
    sites.push({
      specifier,
      line: node.loc ? node.loc.start.line : 0,
      argument_type: argumentType,
      callee_form: calleeForm,
      deferred: typeof node.start === "number"
        && functionBodies.some(([from, to]) => node.start >= from && node.start < to),
    });
  };

  walk(ast.program, (node) => {
    if (node.type === "VariableDeclarator") {
      if (node.init && node.init.type === "Identifier" && node.init.name === "require") {
        record(node, REQUIRE_CALLEE_FORMS.ALIAS_BINDING, "(not a call)", null);
      } else if (node.id && node.id.type === "ObjectPattern") {
        for (const property of node.id.properties) {
          if (property.type !== "ObjectProperty") continue;
          if (staticPropertyName(property.key, property.computed) === "require") {
            record(property, REQUIRE_CALLEE_FORMS.ALIAS_BINDING, "(not a call)", null);
          }
        }
      }
      return;
    }
    if (node.type !== "CallExpression") return;
    const callee = node.callee;
    const argument = node.arguments.length > 0 ? node.arguments[0] : null;
    const argumentType = argument ? argument.type : "(no argument)";
    const literal = argument && argument.type === "StringLiteral" ? argument.value : null;

    if (callee && callee.type === "Identifier" && callee.name === "require") {
      let specifier = literal;
      if (specifier === null && argument && argument.type === "Identifier") {
        const folded = foldable.get(argument.name);
        if (folded !== undefined) specifier = folded;
      }
      record(node, REQUIRE_CALLEE_FORMS.REQUIRE, argumentType, specifier);
      return;
    }
    if (callee && callee.type === "Import") {
      record(node, REQUIRE_CALLEE_FORMS.DYNAMIC_IMPORT, argumentType, literal);
      return;
    }
    if (!callee || callee.type !== "MemberExpression" || callee.computed) return;
    if (!callee.property || callee.property.type !== "Identifier") return;
    const receiverIsIdentifier = callee.object && callee.object.type === "Identifier";
    if (callee.property.name === "resolve" && receiverIsIdentifier && callee.object.name === "require") {
      record(node, REQUIRE_CALLEE_FORMS.REQUIRE_RESOLVE, argumentType, null);
      return;
    }
    if (callee.property.name === "require") {
      const resolvesAgainstCaller = receiverIsIdentifier && callee.object.name === "module";
      record(node, REQUIRE_CALLEE_FORMS.MEMBER_REQUIRE, argumentType, resolvesAgainstCaller ? literal : null);
    }
  });
  return sites;
}

module.exports = {
  JS_PARSE_ERROR_CODE,
  REQUIRE_CALLEE_FORMS,
  blankComments,
  collectKeyedWrites,
  collectStaticRequires,
  hasKeyedWrite,
  // The two primitives every reader above is built from, exported so a gate's
  // own suite can read that gate's source the same way — a fact about a
  // checker is a fact about a JavaScript source, and deriving it by grep is
  // the defect this module exists to remove.
  parseJsSource,
  walk,
  // The key-name rule the readers above share, exported for the same reason: a
  // gate that has to say what name a line DECLARES must ask the same question
  // this file already answers, not re-derive a second answer to it.
  staticPropertyName,
};
