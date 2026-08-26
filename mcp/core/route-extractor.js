"use strict";

const SUPPORTED_FRAMEWORKS = Object.freeze([
  "express",
  "koa",
  "fastify",
  "nestjs",
  "flask",
  "django",
  "spring",
]);

const SUPPORTED_LANGUAGES = Object.freeze({
  js: ["express", "koa", "fastify", "nestjs"],
  ts: ["express", "koa", "fastify", "nestjs"],
  py: ["flask", "django"],
  java: ["spring"],
  kt: ["spring"],
});

const HTTP_METHODS = Object.freeze([
  "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE",
]);

function isPlainObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

function lineFromOffset(source, offset) {
  if (typeof source !== "string" || offset == null) return null;
  let line = 1;
  for (let i = 0; i < offset && i < source.length; i++) {
    if (source.charCodeAt(i) === 10) line++;
  }
  return line;
}

function findMatchingBrace(source, openIndex) {
  if (typeof source !== "string" || source[openIndex] !== "{") return -1;
  let depth = 0;
  for (let i = openIndex; i < source.length; i++) {
    if (source[i] === "{") depth += 1;
    else if (source[i] === "}") {
      depth -= 1;
      if (depth === 0) return i;
    }
  }
  return -1;
}

function isOffsetInRanges(offset, ranges) {
  return ranges.some((range) => offset >= range.start && offset < range.end);
}

function extractExpressRoutes(source) {
  // app.METHOD('/path', ...) or router.METHOD('/path', ...) where METHOD is a
  // lowercase HTTP verb. Also matches app.use('/prefix', router) for surface
  // visibility (recorded with method ALL).
  const routes = [];
  const verbRegex = /\b(?:app|router|api|server|express\.Router\(\))\.(get|post|put|delete|patch|options|head|use|all)\s*\(\s*(['"`])([^'"`\\]+)\2/g;
  let match;
  while ((match = verbRegex.exec(source)) != null) {
    const methodToken = match[1].toUpperCase();
    if (methodToken === "USE") {
      routes.push({
        framework: "express",
        method: "ALL",
        path: match[3],
        line: lineFromOffset(source, match.index),
        handler_hint: extractHandlerHint(source, verbRegex.lastIndex),
        edge_kind: "mount",
      });
    } else if (HTTP_METHODS.includes(methodToken)) {
      routes.push({
        framework: "express",
        method: methodToken,
        path: match[3],
        line: lineFromOffset(source, match.index),
        handler_hint: extractHandlerHint(source, verbRegex.lastIndex),
        edge_kind: "route",
      });
    } else if (methodToken === "ALL") {
      routes.push({
        framework: "express",
        method: "ALL",
        path: match[3],
        line: lineFromOffset(source, match.index),
        handler_hint: extractHandlerHint(source, verbRegex.lastIndex),
        edge_kind: "route",
      });
    }
  }
  return routes;
}

function extractKoaFastifyRoutes(source, options = {}) {
  const routes = [];
  const includeKoa = options.includeKoa !== false;
  const includeFastify = options.includeFastify !== false;
  // Koa: app.use(router.routes()) is broad; Koa explicit handlers commonly
  // come via koa-router which mirrors Express patterns. Matched alongside
  // express; only add Koa-specific patterns here to avoid double-counting.
  if (includeKoa && /(?:koa-router|@koa\/router|new\s+Router\s*\(|require\s*\(\s*['"](?:@koa\/router|koa-router)['"]\s*\))/.test(source)) {
    const koaVerbRegex = /\b(?:router|apiRouter|routes)\.(get|post|put|delete|patch|options|head|all)\s*\(\s*(['"`])([^'"`\\]+)\2/g;
    let koaMatch;
    while ((koaMatch = koaVerbRegex.exec(source)) != null) {
      const method = koaMatch[1].toUpperCase();
      routes.push({
        framework: "koa",
        method: method === "ALL" ? "ALL" : method,
        path: koaMatch[3],
        line: lineFromOffset(source, koaMatch.index),
        handler_hint: extractHandlerHint(source, koaVerbRegex.lastIndex),
        edge_kind: "route",
      });
    }
  }
  // Fastify: fastify.get('/path', handler), fastify.route({ method: 'GET', url: '/path' })
  if (!includeFastify) return routes;
  const fastifyVerbRegex = /\bfastify\.(get|post|put|delete|patch|options|head|all)\s*\(\s*(['"`])([^'"`\\]+)\2/g;
  let match;
  while ((match = fastifyVerbRegex.exec(source)) != null) {
    const method = match[1].toUpperCase();
    routes.push({
      framework: "fastify",
      method: method === "ALL" ? "ALL" : method,
      path: match[3],
      line: lineFromOffset(source, match.index),
      handler_hint: extractHandlerHint(source, fastifyVerbRegex.lastIndex),
      edge_kind: "route",
    });
  }
  const fastifyRouteRegex = /\bfastify\.route\s*\(\s*\{[^}]*method\s*:\s*(['"`])([A-Z,\s'"`]+)\1[^}]*url\s*:\s*(['"`])([^'"`\\]+)\3/g;
  while ((match = fastifyRouteRegex.exec(source)) != null) {
    const methodList = match[2].replace(/['"`\s]/g, "").split(",");
    for (const method of methodList) {
      const upper = method.toUpperCase();
      if (HTTP_METHODS.includes(upper)) {
        routes.push({
          framework: "fastify",
          method: upper,
          path: match[4],
          line: lineFromOffset(source, match.index),
          handler_hint: null,
          edge_kind: "route",
        });
      }
    }
  }
  return routes;
}

function extractNestjsRoutes(source) {
  // NestJS @Get('/path'), @Post('/path'), etc. Class-level @Controller('/prefix')
  // captured to expose mount edges.
  const routes = [];
  const controllerRanges = [];
  const controllerClassRegex = /@Controller\s*\(\s*(['"`])([^'"`\\]+)\1\s*\)[\s\S]*?\b(?:export\s+)?class\s+[A-Za-z_$][\w$]*[^{]*\{/g;
  let match;
  while ((match = controllerClassRegex.exec(source)) != null) {
    const controllerPrefix = match[2];
    const openBraceIndex = controllerClassRegex.lastIndex - 1;
    const closeBraceIndex = findMatchingBrace(source, openBraceIndex);
    const bodyEnd = closeBraceIndex === -1 ? source.length : closeBraceIndex;
    controllerRanges.push({ start: openBraceIndex + 1, end: bodyEnd });
    routes.push({
      framework: "nestjs",
      method: "ALL",
      path: controllerPrefix.startsWith("/") ? controllerPrefix : `/${controllerPrefix}`,
      line: lineFromOffset(source, match.index),
      handler_hint: null,
      edge_kind: "mount",
    });
    extractNestjsDecorators(source, openBraceIndex + 1, bodyEnd, controllerPrefix, routes);
  }

  extractNestjsDecorators(source, 0, source.length, null, routes, controllerRanges);
  return routes;
}

function extractNestjsDecorators(source, start, end, controllerPrefix, routes, skipRanges = []) {
  const decoratorRegex = /@(Get|Post|Put|Delete|Patch|Options|Head|All)\s*\(\s*(?:(['"`])([^'"`\\]*)\2)?\s*\)/g;
  decoratorRegex.lastIndex = start;
  let match;
  while ((match = decoratorRegex.exec(source)) != null) {
    if (match.index >= end) break;
    if (skipRanges.length > 0 && isOffsetInRanges(match.index, skipRanges)) continue;
    const method = match[1].toUpperCase();
    const subPath = match[3] || "";
    const fullPath = controllerPrefix
      ? joinNestjsPaths(controllerPrefix, subPath)
      : (subPath ? (subPath.startsWith("/") ? subPath : `/${subPath}`) : "/");
    routes.push({
      framework: "nestjs",
      method: method === "ALL" ? "ALL" : method,
      path: fullPath,
      line: lineFromOffset(source, match.index),
      handler_hint: extractHandlerHintAfterDecorator(source, decoratorRegex.lastIndex),
      edge_kind: "route",
    });
  }
}

function joinNestjsPaths(prefix, sub) {
  const cleanPrefix = prefix.startsWith("/") ? prefix : `/${prefix}`;
  if (!sub) return cleanPrefix;
  const cleanSub = sub.startsWith("/") ? sub : `/${sub}`;
  return cleanPrefix.endsWith("/") ? `${cleanPrefix.slice(0, -1)}${cleanSub}` : `${cleanPrefix}${cleanSub}`;
}

function extractFlaskRoutes(source) {
  const routes = [];
  const routeRegex = /@(?:app|bp|blueprint|api|router)\.route\s*\(\s*(['"])([^'"]+)\1(?:\s*,\s*methods\s*=\s*\[([^\]]*)\])?/g;
  let match;
  while ((match = routeRegex.exec(source)) != null) {
    const path = match[2];
    const methods = match[3]
      ? match[3].split(",").map((m) => m.replace(/['"\s]/g, "").toUpperCase()).filter((m) => m.length > 0)
      : ["GET"];
    for (const method of methods) {
      if (HTTP_METHODS.includes(method)) {
        routes.push({
          framework: "flask",
          method,
          path,
          line: lineFromOffset(source, match.index),
          handler_hint: extractHandlerHintAfterDecorator(source, routeRegex.lastIndex),
          edge_kind: "route",
        });
      }
    }
  }
  // Flask shorthand decorators: @app.get('/x'), @app.post('/x')
  const verbRegex = /@(?:app|bp|blueprint|api|router)\.(get|post|put|delete|patch|options|head)\s*\(\s*(['"])([^'"]+)\2/g;
  while ((match = verbRegex.exec(source)) != null) {
    routes.push({
      framework: "flask",
      method: match[1].toUpperCase(),
      path: match[3],
      line: lineFromOffset(source, match.index),
      handler_hint: extractHandlerHintAfterDecorator(source, verbRegex.lastIndex),
      edge_kind: "route",
    });
  }
  return routes;
}

function extractDjangoRoutes(source) {
  // path('users/', views.list, name='users') and re_path / url variants.
  const routes = [];
  const pathRegex = /\b(?:path|re_path|url)\s*\(\s*(?:r?(['"])([^'"]*)\1|([^,]+))\s*,\s*([\w.]+)/g;
  let match;
  while ((match = pathRegex.exec(source)) != null) {
    const path = match[2] != null ? match[2] : match[3].trim();
    const handler = match[4];
    routes.push({
      framework: "django",
      method: "ALL",
      path: path.startsWith("/") ? path : `/${path}`,
      line: lineFromOffset(source, match.index),
      handler_hint: handler,
      edge_kind: "route",
    });
  }
  return routes;
}

function extractSpringRoutes(source) {
  const routes = [];
  const classRanges = [];
  const requestMappingClass = /@RequestMapping\s*\(\s*(?:value\s*=\s*)?\{?\s*(['"])([^'"]*)\1[\s\S]*?\b(?:public\s+)?(?:class|interface)\s+[A-Za-z_$][\w$]*[^{]*\{/g;
  let m;
  while ((m = requestMappingClass.exec(source)) != null) {
    const classPrefix = m[2];
    const openBraceIndex = requestMappingClass.lastIndex - 1;
    const closeBraceIndex = findMatchingBrace(source, openBraceIndex);
    const bodyEnd = closeBraceIndex === -1 ? source.length : closeBraceIndex;
    classRanges.push({ start: m.index, end: bodyEnd });
    extractSpringDecorators(source, openBraceIndex + 1, bodyEnd, classPrefix, routes);
  }

  extractSpringDecorators(source, 0, source.length, null, routes, classRanges);
  return routes;
}

function extractSpringDecorators(source, start, end, classPrefix, routes, skipRanges = []) {
  const verbDecoratorRegex = /@(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)\s*\(\s*(?:(?:value|path)\s*=\s*)?\{?\s*(['"])([^'"]*)\2(?:[^)]*method\s*=\s*RequestMethod\.([A-Z]+))?/g;
  verbDecoratorRegex.lastIndex = start;
  let match;
  while ((match = verbDecoratorRegex.exec(source)) != null) {
    if (match.index >= end) break;
    if (skipRanges.length > 0 && isOffsetInRanges(match.index, skipRanges)) continue;
    let method = "GET";
    if (match[1] === "PostMapping") method = "POST";
    else if (match[1] === "PutMapping") method = "PUT";
    else if (match[1] === "DeleteMapping") method = "DELETE";
    else if (match[1] === "PatchMapping") method = "PATCH";
    else if (match[1] === "RequestMapping" && match[4]) method = match[4].toUpperCase();
    else if (match[1] === "RequestMapping") method = "ALL";
    const subPath = match[3] || "";
    const fullPath = classPrefix
      ? joinNestjsPaths(classPrefix, subPath)
      : (subPath.startsWith("/") ? subPath : `/${subPath}`);
    routes.push({
      framework: "spring",
      method,
      path: fullPath,
      line: lineFromOffset(source, match.index),
      handler_hint: null,
      edge_kind: "route",
    });
  }
}

function extractHandlerHint(source, after) {
  if (typeof source !== "string" || after >= source.length) return null;
  // Skip whitespace, then look for identifier or arrow function
  let i = after;
  while (i < source.length && /[\s,]/.test(source[i])) i++;
  if (i >= source.length) return null;
  const identMatch = source.slice(i, i + 80).match(/^([A-Za-z_$][\w$]*)/);
  if (identMatch) return identMatch[1];
  return null;
}

function extractHandlerHintAfterDecorator(source, after) {
  if (typeof source !== "string" || after >= source.length) return null;
  // Look for the next "def name" or "function name" after the decorator
  const slice = source.slice(after, after + 400);
  const pyDef = slice.match(/\bdef\s+([A-Za-z_][\w]*)/);
  if (pyDef) return pyDef[1];
  const jsFunc = slice.match(/\b(?:function\s+|async\s+function\s+|const\s+|let\s+|var\s+)?([A-Za-z_$][\w$]*)\s*[(:]/);
  if (jsFunc) return jsFunc[1];
  return null;
}

function detectLanguage(filePath) {
  if (typeof filePath !== "string") return null;
  const lower = filePath.toLowerCase();
  if (lower.endsWith(".ts") || lower.endsWith(".tsx")) return "ts";
  if (lower.endsWith(".js") || lower.endsWith(".jsx") || lower.endsWith(".mjs") || lower.endsWith(".cjs")) return "js";
  if (lower.endsWith(".py")) return "py";
  if (lower.endsWith(".java")) return "java";
  if (lower.endsWith(".kt")) return "kt";
  return null;
}

function extractRoutesFromSource({ source, language, file }) {
  if (typeof source !== "string") {
    throw new TypeError("source must be a string");
  }
  const detectedLanguage = language || detectLanguage(file);
  const candidateFrameworks = detectedLanguage && SUPPORTED_LANGUAGES[detectedLanguage]
    ? SUPPORTED_LANGUAGES[detectedLanguage]
    : SUPPORTED_FRAMEWORKS;
  const all = [];
  if (candidateFrameworks.includes("express")) all.push(...extractExpressRoutes(source));
  if (candidateFrameworks.includes("koa") || candidateFrameworks.includes("fastify")) {
    all.push(...extractKoaFastifyRoutes(source, {
      includeKoa: candidateFrameworks.includes("koa"),
      includeFastify: candidateFrameworks.includes("fastify"),
    }));
  }
  if (candidateFrameworks.includes("nestjs")) all.push(...extractNestjsRoutes(source));
  if (candidateFrameworks.includes("flask")) all.push(...extractFlaskRoutes(source));
  if (candidateFrameworks.includes("django")) all.push(...extractDjangoRoutes(source));
  if (candidateFrameworks.includes("spring")) all.push(...extractSpringRoutes(source));
  for (const route of all) {
    route.file = typeof file === "string" ? file : null;
  }
  // Deduplicate identical (framework, method, path, line, file) tuples.
  const seen = new Set();
  const deduped = [];
  for (const route of all) {
    const key = `${route.framework}|${route.method}|${route.path}|${route.line}|${route.file || ""}`;
    if (seen.has(key)) continue;
    seen.add(key);
    deduped.push(route);
  }
  deduped.sort((a, b) => {
    const byFile = (a.file || "").localeCompare(b.file || "");
    if (byFile !== 0) return byFile;
    if (a.line !== b.line) return (a.line || 0) - (b.line || 0);
    const byPath = a.path.localeCompare(b.path);
    if (byPath !== 0) return byPath;
    return a.method.localeCompare(b.method);
  });
  return deduped;
}

function extractRoutesFromFiles(fileSpecs) {
  if (!Array.isArray(fileSpecs)) {
    throw new TypeError("fileSpecs must be an array of {file, source, language?}");
  }
  const all = [];
  for (const spec of fileSpecs) {
    if (!isPlainObject(spec)) continue;
    if (typeof spec.source !== "string") continue;
    all.push(...extractRoutesFromSource({
      file: spec.file,
      source: spec.source,
      language: spec.language,
    }));
  }
  return all;
}

module.exports = {
  extractRoutesFromSource,
  extractRoutesFromFiles,
  detectLanguage,
  SUPPORTED_FRAMEWORKS,
  SUPPORTED_LANGUAGES,
  HTTP_METHODS,
};
