"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  parseGraphqlSdl,
  looksLikeGraphqlSdl,
} = require("../mcp/core/graphql-sdl-parser.js");

const MINIMAL_SDL = `
type Query {
  user(id: ID!): User
  users(limit: Int = 10): [User!]!
}

type Mutation {
  createUser(input: CreateUserInput!): User
  deleteUser(id: ID!): Boolean
}

type User {
  id: ID!
  name: String
  email: String
}

input CreateUserInput {
  name: String!
  email: String!
}
`;

test("looksLikeGraphqlSdl recognizes type / schema / input definitions", () => {
  assert.equal(looksLikeGraphqlSdl("type Query { id: ID }"), true);
  assert.equal(looksLikeGraphqlSdl("schema { query: Q }"), true);
  assert.equal(looksLikeGraphqlSdl("input X { id: ID }"), true);
  assert.equal(looksLikeGraphqlSdl(""), false);
  assert.equal(looksLikeGraphqlSdl(null), false);
  assert.equal(looksLikeGraphqlSdl('{"openapi":"3.0"}'), false);
});

test("parseGraphqlSdl emits one contract per Query / Mutation field", () => {
  const result = parseGraphqlSdl(MINIMAL_SDL);
  assert.equal(result.schema_format, "graphql");
  assert.equal(result.contracts.length, 4);
  const endpoints = result.contracts.map((c) => c.endpoint).sort();
  assert.deepEqual(endpoints, [
    "/graphql:mutation.createUser",
    "/graphql:mutation.deleteUser",
    "/graphql:query.user",
    "/graphql:query.users",
  ]);
});

test("contract.method is POST for every GraphQL contract", () => {
  const result = parseGraphqlSdl(MINIMAL_SDL);
  for (const contract of result.contracts) {
    assert.equal(contract.method, "POST");
  }
});

test("non-null required arg emits required: true; nullable arg emits required: false", () => {
  const result = parseGraphqlSdl(MINIMAL_SDL);
  const userOp = result.contracts.find((c) => c.operation_name === "user");
  const idArg = userOp.claimed_params.find((p) => p.name === "id");
  assert.equal(idArg.required, true);
  assert.equal(idArg.schema_type, "string");

  const usersOp = result.contracts.find((c) => c.operation_name === "users");
  const limitArg = usersOp.claimed_params.find((p) => p.name === "limit");
  assert.equal(limitArg.required, false);
  assert.equal(limitArg.schema_type, "integer");
});

test("input type is resolved into the request arg shape with required fields", () => {
  const result = parseGraphqlSdl(MINIMAL_SDL);
  const create = result.contracts.find((c) => c.operation_name === "createUser");
  const inputArg = create.claimed_params.find((p) => p.name === "input");
  assert.ok(inputArg);
  assert.equal(inputArg.schema_type, "object");
  assert.deepEqual(inputArg.schema_shape.required, ["email", "name"]);
});

test("response shape places the resolved return type under data:", () => {
  const result = parseGraphqlSdl(MINIMAL_SDL);
  const userOp = result.contracts.find((c) => c.operation_name === "user");
  const ok = userOp.claimed_response_shape["200"];
  assert.equal(ok.content_type, "application/json");
  assert.equal(ok.shape.type, "object");
  assert.ok(ok.shape.properties.data, "data property present");
  assert.equal(ok.shape.properties.data.type, "object");
  assert.ok(ok.shape.properties.data.properties.id, "User.id resolved");
});

test("auth directives populate claimed_auth.schemes", () => {
  const sdl = `
    type Query {
      adminPanel: String @auth(role: "admin")
      publicHealth: String
    }
  `;
  const result = parseGraphqlSdl(sdl);
  const admin = result.contracts.find((c) => c.operation_name === "adminPanel");
  assert.deepEqual(admin.claimed_auth, {
    schemes: ["graphql_directive:auth"],
    none_allowed: false,
  });
  const pub = result.contracts.find((c) => c.operation_name === "publicHealth");
  assert.deepEqual(pub.claimed_auth, { schemes: [], none_allowed: true });
});

test("multiple auth directive aliases map to graphql_directive:* schemes", () => {
  const sdl = `
    type Query {
      one: String @authenticated
      two: String @requireAuth
      three: String @hasRole(role: "admin")
    }
  `;
  const result = parseGraphqlSdl(sdl);
  const schemes = result.contracts.map((c) => c.claimed_auth.schemes).flat().sort();
  assert.deepEqual(schemes, [
    "graphql_directive:authenticated",
    "graphql_directive:hasRole",
    "graphql_directive:requireAuth",
  ]);
});

test("unresolved type names produce $ref_unresolved markers, not throws", () => {
  const sdl = `
    type Query {
      something: UnknownType
    }
  `;
  const result = parseGraphqlSdl(sdl);
  assert.equal(result.contracts.length, 1);
  const dataShape = result.contracts[0].claimed_response_shape["200"].shape.properties.data;
  assert.equal(dataShape.$ref_unresolved, "UnknownType");
});

test("recursive types produce $ref_cycle markers", () => {
  const sdl = `
    type Query {
      tree: Node
    }
    type Node {
      id: ID!
      children: [Node!]
    }
  `;
  const result = parseGraphqlSdl(sdl);
  const data = result.contracts[0].claimed_response_shape["200"].shape.properties.data;
  // children is array of Node — that array's items hits the cycle
  assert.equal(data.properties.children.type, "array");
  assert.equal(data.properties.children.items.$ref_cycle, "Node");
});

test("contract_hash is stable across whitespace and comment differences", () => {
  const noisy = `
    # leading comment
    type Query {
      # field comment
      user(id: ID!): User
    }
    type User {
      id: ID!
    }
  `;
  const tight = `type Query{user(id:ID!):User}type User{id:ID!}`;
  const a = parseGraphqlSdl(noisy);
  const b = parseGraphqlSdl(tight);
  assert.equal(a.contracts[0].contract_hash, b.contracts[0].contract_hash);
  assert.equal(a.source_doc_hash, b.source_doc_hash);
});

test("schema definition with custom Query/Mutation type names is honored", () => {
  const sdl = `
    schema {
      query: RootQuery
      mutation: RootMutation
    }
    type RootQuery {
      ping: String
    }
    type RootMutation {
      pong: String
    }
  `;
  const result = parseGraphqlSdl(sdl);
  assert.equal(result.contracts.length, 2);
  assert.deepEqual(result.contracts.map((c) => c.endpoint).sort(), [
    "/graphql:mutation.pong",
    "/graphql:query.ping",
  ]);
});

test("extend type Query merges fields", () => {
  const sdl = `
    type Query {
      one: String
    }
    extend type Query {
      two: String
    }
  `;
  const result = parseGraphqlSdl(sdl);
  assert.equal(result.contracts.length, 2);
});

test("descriptions and block strings are tolerated", () => {
  const sdl = `
    """The root query type."""
    type Query {
      """Returns the user."""
      user(
        """The id."""
        id: ID!
      ): User
    }
    type User {
      id: ID!
    }
  `;
  const result = parseGraphqlSdl(sdl);
  assert.equal(result.contracts.length, 1);
  assert.equal(result.contracts[0].operation_name, "user");
});

test("malformed SDL emits parse_failed warning instead of throwing", () => {
  const result = parseGraphqlSdl("type Query { x:");
  assert.equal(result.contracts.length, 0);
  assert.match(result.parser_warnings[0], /parse_failed/);
});

test("subscription types are skipped in this slice", () => {
  const sdl = `
    type Query {
      x: String
    }
    type Subscription {
      events: String
    }
  `;
  const result = parseGraphqlSdl(sdl);
  assert.equal(result.contracts.length, 1);
  assert.equal(result.contracts[0].operation_kind, "query");
});

test("interface, enum, union, scalar, directive defs do not break parsing", () => {
  const sdl = `
    scalar DateTime
    enum Role { ADMIN MEMBER GUEST }
    interface Node { id: ID! }
    union Result = User | Error
    directive @auth(role: String) on FIELD_DEFINITION

    type Query {
      ping: String
    }
    type User { id: ID! }
    type Error { message: String }
  `;
  const result = parseGraphqlSdl(sdl);
  assert.equal(result.contracts.length, 1);
  assert.equal(result.contracts[0].operation_name, "ping");
});
