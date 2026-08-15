"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  extractRoutesFromSource,
  extractRoutesFromFiles,
  detectLanguage,
  SUPPORTED_FRAMEWORKS,
} = require("../mcp/core/route-extractor.js");

test("detectLanguage maps file extensions to language tags", () => {
  assert.equal(detectLanguage("app.js"), "js");
  assert.equal(detectLanguage("controllers/user.controller.ts"), "ts");
  assert.equal(detectLanguage("views.py"), "py");
  assert.equal(detectLanguage("UserController.java"), "java");
  assert.equal(detectLanguage("UserController.kt"), "kt");
  assert.equal(detectLanguage("README.md"), null);
  assert.equal(detectLanguage(null), null);
});

test("Express: app.get/post/put/delete/patch route declarations are extracted", () => {
  const source = `
    const app = express();
    app.get('/users', getUsers);
    app.post('/users', createUser);
    app.put('/users/:id', updateUser);
    app.delete('/users/:id', deleteUser);
    app.patch('/users/:id', patchUser);
  `;
  const routes = extractRoutesFromSource({ source, language: "js", file: "routes.js" });
  const summaries = routes.map((r) => `${r.method} ${r.path}`).sort();
  assert.deepEqual(summaries, [
    "DELETE /users/:id",
    "GET /users",
    "PATCH /users/:id",
    "POST /users",
    "PUT /users/:id",
  ]);
  assert.ok(routes.every((r) => r.framework === "express"));
});

test("Express: app.use mounts surface as ALL with edge_kind: mount", () => {
  const source = "app.use('/api', apiRouter);";
  const routes = extractRoutesFromSource({ source, language: "js" });
  assert.equal(routes.length, 1);
  assert.equal(routes[0].method, "ALL");
  assert.equal(routes[0].path, "/api");
  assert.equal(routes[0].edge_kind, "mount");
});

test("Express: handler_hint captures the next identifier after the path argument", () => {
  const source = "app.get('/users', getUsers);";
  const routes = extractRoutesFromSource({ source, language: "js" });
  assert.equal(routes[0].handler_hint, "getUsers");
});

test("Fastify: explicit verb form and fastify.route({ method, url }) shape", () => {
  const source = `
    fastify.get('/health', healthHandler);
    fastify.route({
      method: 'POST',
      url: '/login',
      handler: loginHandler,
    });
  `;
  const routes = extractRoutesFromSource({ source, language: "js" });
  const summaries = routes.map((r) => `${r.framework}/${r.method} ${r.path}`).sort();
  assert.ok(summaries.includes("fastify/GET /health"));
  assert.ok(summaries.includes("fastify/POST /login"));
});

test("Koa: koa-router verb declarations emit koa routes", () => {
  const source = `
    const Router = require('koa-router');
    const router = new Router();
    router.get('/users', listUsers);
    router.post('/users', createUser);
  `;
  const routes = extractRoutesFromSource({ source, language: "js" });
  const summaries = routes
    .filter((r) => r.framework === "koa")
    .map((r) => `${r.method} ${r.path}`)
    .sort();
  assert.deepEqual(summaries, [
    "GET /users",
    "POST /users",
  ]);
});

test("NestJS: @Controller prefix joins with @Get/@Post path arguments", () => {
  const source = `
    @Controller('/users')
    export class UsersController {
      @Get('/')
      list() {}

      @Post('/')
      create() {}

      @Get('/:id')
      one() {}
    }
  `;
  const routes = extractRoutesFromSource({ source, language: "ts" });
  const summaries = routes.filter((r) => r.edge_kind === "route").map((r) => `${r.method} ${r.path}`).sort();
  assert.deepEqual(summaries, [
    "GET /users/",
    "GET /users/:id",
    "POST /users/",
  ]);
  // Mount edge for the controller prefix is also recorded.
  const mountEdges = routes.filter((r) => r.edge_kind === "mount");
  assert.equal(mountEdges.length, 1);
  assert.equal(mountEdges[0].path, "/users");
});

test("NestJS: multiple controllers in one file keep separate prefixes", () => {
  const source = `
    @Controller('/users')
    export class UsersController {
      @Get('/:id')
      one() {}
    }

    @Controller('/admin')
    export class AdminController {
      @Post('/audit')
      audit() {}
    }
  `;
  const routes = extractRoutesFromSource({ source, language: "ts" });
  const summaries = routes.filter((r) => r.edge_kind === "route").map((r) => `${r.method} ${r.path}`).sort();
  assert.deepEqual(summaries, [
    "GET /users/:id",
    "POST /admin/audit",
  ]);
});

test("Flask: @app.route with methods=[] expands one entry per method", () => {
  const source = `
    @app.route('/users', methods=['GET', 'POST'])
    def users():
      pass

    @bp.route('/health')
    def health():
      pass

    @app.get('/ping')
    def ping():
      pass
  `;
  const routes = extractRoutesFromSource({ source, language: "py" });
  const summaries = routes.map((r) => `${r.method} ${r.path}`).sort();
  assert.deepEqual(summaries, [
    "GET /health",
    "GET /ping",
    "GET /users",
    "POST /users",
  ]);
});

test("Flask: handler_hint captures the def name following the decorator", () => {
  const source = `
    @app.route('/users')
    def list_users():
      return []
  `;
  const routes = extractRoutesFromSource({ source, language: "py" });
  assert.equal(routes[0].handler_hint, "list_users");
});

test("Django: path() and re_path() extract the URL pattern + view callable", () => {
  const source = `
    urlpatterns = [
      path('users/', views.list_users, name='user_list'),
      path('users/<int:pk>/', views.user_detail, name='user_detail'),
      re_path(r'^login/$', views.login_view),
    ]
  `;
  const routes = extractRoutesFromSource({ source, language: "py" });
  assert.ok(routes.length >= 3);
  const handlerHints = routes.map((r) => r.handler_hint).sort();
  assert.ok(handlerHints.includes("views.list_users"));
  assert.ok(handlerHints.includes("views.user_detail"));
  assert.ok(handlerHints.includes("views.login_view"));
});

test("Spring: @RequestMapping class prefix + @GetMapping / @PostMapping methods", () => {
  const source = `
    @RestController
    @RequestMapping("/api")
    public class UserController {
      @GetMapping("/users")
      public List<User> list() {}

      @PostMapping("/users")
      public User create() {}

      @RequestMapping(value = "/admin", method = RequestMethod.DELETE)
      public void admin() {}
    }
  `;
  const routes = extractRoutesFromSource({ source, language: "java" });
  const summaries = routes.map((r) => `${r.method} ${r.path}`).sort();
  assert.deepEqual(summaries, [
    "DELETE /api/admin",
    "GET /api/users",
    "POST /api/users",
  ]);
});

test("Spring: multiple classes in one file keep separate request prefixes", () => {
  const source = `
    @RestController
    @RequestMapping("/api")
    public class ApiController {
      @GetMapping("/users")
      public List<User> list() {}
    }

    @RestController
    @RequestMapping("/admin")
    public class AdminController {
      @PostMapping("/audit")
      public void audit() {}
    }
  `;
  const routes = extractRoutesFromSource({ source, language: "java" });
  const summaries = routes.map((r) => `${r.method} ${r.path}`).sort();
  assert.deepEqual(summaries, [
    "GET /api/users",
    "POST /admin/audit",
  ]);
});

test("language filter narrows which framework parsers run", () => {
  const flaskOnly = extractRoutesFromSource({
    source: `app.get('/users', handler); @app.route('/users')`,
    language: "py",
  });
  const expressOnly = extractRoutesFromSource({
    source: `app.get('/users', handler); @app.route('/users')`,
    language: "js",
  });
  // Python parser misses Express patterns; Express parser misses Python decorators.
  assert.ok(flaskOnly.every((r) => r.framework !== "express"));
  assert.ok(expressOnly.every((r) => r.framework !== "flask"));
});

test("extractRoutesFromFiles concatenates routes across multiple files", () => {
  const routes = extractRoutesFromFiles([
    { file: "a.js", source: "app.get('/a', h);" },
    { file: "b.py", source: "@app.route('/b')\ndef b(): pass" },
    { file: "C.java", source: "@GetMapping(\"/c\") public void c() {}" },
  ]);
  const summaries = routes.map((r) => `${r.framework}/${r.method} ${r.path} (${r.file})`).sort();
  assert.deepEqual(summaries, [
    "express/GET /a (a.js)",
    "flask/GET /b (b.py)",
    "spring/GET /c (C.java)",
  ]);
});

test("output sorts deterministically by (file, line, path, method)", () => {
  const source = `
    app.post('/z', h);
    app.get('/a', h);
    app.get('/m', h);
  `;
  const routes = extractRoutesFromSource({ source, language: "js", file: "deterministic.js" });
  const lines = routes.map((r) => r.line);
  for (let i = 1; i < lines.length; i++) {
    assert.ok(lines[i - 1] <= lines[i]);
  }
});

test("duplicate (framework, method, path, line, file) tuples are deduplicated", () => {
  const source = "app.get('/users', h);";
  const routes = extractRoutesFromSource({ source, language: "js", file: "x.js" });
  // Run twice over same source-as-file shouldn't duplicate within one extraction call.
  assert.equal(routes.length, 1);
});

test("SUPPORTED_FRAMEWORKS includes the full first-slice framework set", () => {
  for (const fw of ["express", "koa", "fastify", "nestjs", "flask", "django", "spring"]) {
    assert.ok(SUPPORTED_FRAMEWORKS.includes(fw), `${fw} present`);
  }
});

test("non-string source rejected", () => {
  assert.throws(() => extractRoutesFromSource({ source: null }), /source must be/);
});

test("file array input rejected when not array", () => {
  assert.throws(() => extractRoutesFromFiles(null), /fileSpecs/);
});
