"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const { ERROR_CODES } = require("../mcp/lib/envelope.js");
const { assertSignupEmailAllowed } = require("../mcp/lib/signup.js");
const { tempEmailCreate, tempMailboxIsKnown } = require("../mcp/lib/temp-email.js");

function assertSignupGateRejects(email, expectedDetailCode, fn) {
  let error = null;
  try {
    fn();
  } catch (caught) {
    error = caught;
  }
  assert.ok(error, "expected signup gate rejection");
  assert.equal(error.code, ERROR_CODES.INVALID_ARGUMENTS);
  assert.equal(error.details && error.details.code, expectedDetailCode);
  assert.equal(error.message.includes(email), false);
  return error;
}

test("assertSignupEmailAllowed rejects email that was not temp-provisioned", () => {
  const email = "synthetic@example.com";
  assertSignupGateRejects(email, "auto_signup_email_not_temp_provisioned", () => {
    assertSignupEmailAllowed(email, { operatorIdentifiers: [] });
  });
});

test("assertSignupEmailAllowed rejects configured operator identifier before temp binding", () => {
  const previousIdentifiers = process.env.BOB_OPERATOR_IDENTIFIERS;
  const email = "v.mihalis.tmd+target@googlemail.com";
  process.env.BOB_OPERATOR_IDENTIFIERS = "vmihalis.tmd@gmail.com";

  try {
    const error = assertSignupGateRejects(email, "auto_signup_operator_identifier_rejected", () => {
      assertSignupEmailAllowed(email);
    });
    assert.match(error.message, /configured operator identifier/);
  } finally {
    if (previousIdentifiers == null) {
      delete process.env.BOB_OPERATOR_IDENTIFIERS;
    } else {
      process.env.BOB_OPERATOR_IDENTIFIERS = previousIdentifiers;
    }
  }
});

test("assertSignupEmailAllowed accepts a known temp mailbox with no operator match", async () => {
  const originalFetch = global.fetch;
  try {
    global.fetch = async (url) => {
      if (url.includes("mail.tm/domains")) {
        return { ok: true, json: async () => ({ "hydra:member": [{ domain: "test.tm" }] }) };
      }
      if (url.includes("mail.tm/accounts")) {
        return { ok: true, status: 201, json: async () => ({ id: "abc" }) };
      }
      if (url.includes("mail.tm/token")) {
        return { ok: true, json: async () => ({ token: "jwt123" }) };
      }
      return { ok: false, status: 500, text: async () => "" };
    };

    const created = JSON.parse(await tempEmailCreate("mail.tm"));
    assert.equal(created.success, true);
    assert.equal(tempMailboxIsKnown(created.email_address), true);
    assert.doesNotThrow(() => assertSignupEmailAllowed(created.email_address, {
      operatorIdentifiers: ["operator@example.com"],
    }));
  } finally {
    global.fetch = originalFetch;
  }
});
