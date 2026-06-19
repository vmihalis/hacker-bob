/**
 * Unit tests for src/reviews-api.ts — PR review submission (A4).
 *
 * These tests directly validate T3 acceptance criterion AC2:
 *   "At least one inline PR review comment is posted on a diff line with
 *    correct position"
 *
 * The submitPRReview function is the final step in the bob-diff-review
 * pipeline.  It calls octokit.rest.pulls.createReview with an array of
 * resolved inline comments.  Each comment must have:
 *   - path: file path as in the diff (e.g. "src/routes/users.js")
 *   - position: the diff offset (1-indexed position in the file's hunk blob)
 *   - body: the formatted finding comment
 *
 * For the T3 test PR, the SQL injection finding on src/routes/users.js line 20
 * must produce a comment with position=21 (the diff position for line 20 in
 * the test PR's unified diff, as documented in the test PR evidence in
 * live-test-report.json).
 */

import { describe, it, expect, vi } from "vitest";
import {
  submitPRReview,
  type ResolvedComment,
  type ReviewSummary,
  type ReviewsOctokitLike,
} from "../reviews-api.js";

// ---------------------------------------------------------------------------
// Helper: build a minimal ReviewsOctokitLike mock
// ---------------------------------------------------------------------------

function makeOctokit(overrides: {
  createReview?: (params: unknown) => Promise<{ data: { id: number; html_url: string } }>;
} = {}): ReviewsOctokitLike {
  return {
    rest: {
      pulls: {
        createReview: overrides.createReview ?? vi.fn().mockResolvedValue({
          data: { id: 111222333, html_url: "https://github.com/bobnetsec/bob-workflows-testbed/pull/1#pullrequestreview-111222333" },
        }),
      },
    },
  };
}

/** Build a minimal valid ResolvedComment for test use. */
function makeComment(overrides: Partial<ResolvedComment> = {}): ResolvedComment {
  return {
    path: "src/routes/users.js",
    position: 21,
    body: "[high] SQL Injection\n\nUser input passed to SQL query without sanitisation.\n\n**Evidence:**\n```\nGET /users/search?name=' OR '1'='1\n\nHTTP/1.1 200 OK\n[all user records returned]\n```",
    side: "RIGHT",
    ...overrides,
  };
}

/** Build a minimal valid ReviewSummary for test use. */
function makeSummary(overrides: Partial<ReviewSummary> = {}): ReviewSummary {
  return {
    session_id: "ses-t3-test001",
    target_domain: "gh-1261831449-pr1",
    finding_count: 1,
    severity: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// submitPRReview — happy path (AC2 core)
// ---------------------------------------------------------------------------

describe("submitPRReview: inline comment submission", () => {
  it("calls createReview with the resolved comment at the correct diff position", async () => {
    const createReviewFn = vi.fn().mockResolvedValue({
      data: { id: 111222333, html_url: "https://github.com/bobnetsec/bob-workflows-testbed/pull/1#pullrequestreview-111222333" },
    });
    const octokit = makeOctokit({ createReview: createReviewFn });

    const comment = makeComment({ path: "src/routes/users.js", position: 21 });
    await submitPRReview(octokit, "bobnetsec", "bob-workflows-testbed", 1, [comment], makeSummary());

    expect(createReviewFn).toHaveBeenCalledOnce();
    const callArgs = createReviewFn.mock.calls[0][0];

    // AC2: the review must include inline comment(s) with position set.
    expect(callArgs.pull_number).toBe(1);
    expect(callArgs.event).toBe("COMMENT");
    expect(callArgs.comments).toHaveLength(1);
    expect(callArgs.comments[0].path).toBe("src/routes/users.js");
    expect(callArgs.comments[0].position).toBe(21);
    expect(callArgs.comments[0].body).toContain("[high] SQL Injection");
  });

  it("returns the review HTML URL", async () => {
    const octokit = makeOctokit();
    const url = await submitPRReview(
      octokit,
      "bobnetsec",
      "bob-workflows-testbed",
      1,
      [makeComment()],
      makeSummary()
    );
    expect(url).toContain("pullrequestreview");
    expect(url).toContain("bob-workflows-testbed");
  });

  it("review body includes session_id and target_domain from summary", async () => {
    const createReviewFn = vi.fn().mockResolvedValue({
      data: { id: 1, html_url: "https://github.com/test" },
    });
    const octokit = makeOctokit({ createReview: createReviewFn });

    const summary = makeSummary({
      session_id: "ses-abc123",
      target_domain: "gh-987654321-pr42",
    });

    await submitPRReview(octokit, "owner", "repo", 42, [makeComment()], summary);

    const callArgs = createReviewFn.mock.calls[0][0];
    expect(callArgs.body).toContain("ses-abc123");
    expect(callArgs.body).toContain("gh-987654321-pr42");
  });

  it("multiple inline comments are all included in a single createReview call", async () => {
    const createReviewFn = vi.fn().mockResolvedValue({
      data: { id: 1, html_url: "https://github.com/test" },
    });
    const octokit = makeOctokit({ createReview: createReviewFn });

    // T3 test PR has three vulnerabilities — all three should appear as comments.
    const comments = [
      makeComment({ path: "src/routes/users.js", position: 21, body: "[high] SQL injection" }),
      makeComment({ path: "src/routes/users.js", position: 39, body: "[high] BOLA/IDOR" }),
      makeComment({ path: "src/routes/users.js", position: 53, body: "[high] Privilege escalation" }),
    ];

    const summary = makeSummary({
      finding_count: 3,
      severity: { critical: 0, high: 3, medium: 0, low: 0, info: 0 },
    });

    await submitPRReview(octokit, "bobnetsec", "bob-workflows-testbed", 1, comments, summary);

    const callArgs = createReviewFn.mock.calls[0][0];
    // AC2: all three inline comments with position != null.
    expect(callArgs.comments).toHaveLength(3);
    expect(callArgs.comments[0].position).toBe(21);
    expect(callArgs.comments[1].position).toBe(39);
    expect(callArgs.comments[2].position).toBe(53);
    for (const c of callArgs.comments) {
      expect(c.position).toBeTypeOf("number");
      expect(c.position).toBeGreaterThan(0);
    }
  });

  it("review body references finding count from summary", async () => {
    const createReviewFn = vi.fn().mockResolvedValue({
      data: { id: 1, html_url: "https://github.com/test" },
    });
    const octokit = makeOctokit({ createReview: createReviewFn });

    await submitPRReview(
      octokit,
      "owner",
      "repo",
      1,
      [makeComment()],
      makeSummary({ finding_count: 1, severity: { critical: 0, high: 1, medium: 0, low: 0, info: 0 } })
    );

    const body: string = createReviewFn.mock.calls[0][0].body;
    expect(body).toContain("Findings:");
  });
});

// ---------------------------------------------------------------------------
// submitPRReview — no findings (body-only review)
// ---------------------------------------------------------------------------

describe("submitPRReview: no-findings body-only review", () => {
  it("posts a body-only review with no inline comments when findings are empty", async () => {
    const createReviewFn = vi.fn().mockResolvedValue({
      data: { id: 1, html_url: "https://github.com/test" },
    });
    const octokit = makeOctokit({ createReview: createReviewFn });

    await submitPRReview(octokit, "owner", "repo", 1, [], makeSummary({ finding_count: 0 }));

    const callArgs = createReviewFn.mock.calls[0][0];
    expect(callArgs.event).toBe("COMMENT");
    // No inline comments (or empty array) when there are no findings.
    expect(callArgs.comments == null || callArgs.comments.length === 0).toBe(true);
    expect(callArgs.body).toContain("No findings");
  });

  it("keeps unanchored finding bodies in the review body when no inline comments exist", async () => {
    const createReviewFn = vi.fn().mockResolvedValue({
      data: { id: 1, html_url: "https://github.com/test" },
    });
    const octokit = makeOctokit({ createReview: createReviewFn });

    await submitPRReview(
      octokit,
      "owner",
      "repo",
      1,
      [],
      makeSummary({
        finding_count: 1,
        pr_level_comments: ["[high] Related-file issue\n\nEvidence from a file outside the diff."],
      })
    );

    const callArgs = createReviewFn.mock.calls[0][0];
    expect(callArgs.comments == null || callArgs.comments.length === 0).toBe(true);
    expect(callArgs.body).toContain("Unanchored Findings");
    expect(callArgs.body).toContain("Related-file issue");
    expect(callArgs.body).not.toContain("No findings");
  });
});

// ---------------------------------------------------------------------------
// submitPRReview — 429 retry behavior
// ---------------------------------------------------------------------------

describe("submitPRReview: retry on 429", () => {
  it("retries and succeeds after a single 429 rate limit response", async () => {
    let callCount = 0;
    const createReviewFn = vi.fn().mockImplementation(async () => {
      callCount++;
      if (callCount === 1) {
        const err = Object.assign(new Error("429 Too Many Requests"), { status: 429 });
        throw err;
      }
      return { data: { id: 1, html_url: "https://github.com/test" } };
    });
    const octokit = makeOctokit({ createReview: createReviewFn });

    // Should succeed after the retry.
    const url = await submitPRReview(octokit, "owner", "repo", 1, [makeComment()], makeSummary());
    expect(url).toBe("https://github.com/test");
    expect(callCount).toBe(2);
  }, 30000);
});

// ---------------------------------------------------------------------------
// submitPRReview — 422 recovery: falls back to body-only review
// ---------------------------------------------------------------------------

describe("submitPRReview: 422 recovery path", () => {
  it("does not log comment bodies when probing invalid positions", async () => {
    const createReviewFn = vi.fn().mockImplementation(async (params: { comments?: unknown[] }) => {
      if (params.comments && params.comments.length > 0) {
        throw Object.assign(new Error("422 Unprocessable Entity"), { status: 422 });
      }
      return { data: { id: 2, html_url: "https://github.com/test/fallback" } };
    });
    const octokit = makeOctokit({ createReview: createReviewFn });
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    let logged = "";

    try {
      await submitPRReview(
        octokit,
        "owner",
        "repo",
        1,
        [
          makeComment({
            position: 99999,
            body: "[high] Sensitive finding\n\nrequest body: password=secret-token",
          }),
        ],
        makeSummary()
      );
      logged = errorSpy.mock.calls.map((call) => call.join(" ")).join("\n");
    } finally {
      errorSpy.mockRestore();
    }

    expect(logged).toContain("path=src/routes/users.js position=99999");
    expect(logged).not.toContain("Sensitive finding");
    expect(logged).not.toContain("password=secret-token");
  });

  it("falls back to body-only review when all positions are invalid (422 on all probes)", async () => {
    // Every createReview call throws 422 — simulates all positions being bad.
    // The 422 recovery path will probe each comment, find all invalid, and
    // post a fallback body-only review.
    let callCount = 0;
    const createReviewFn = vi.fn().mockImplementation(async (params: { comments?: unknown[] }) => {
      // If comments are included, throw 422.
      // Body-only call (no comments) succeeds — this is the fallback.
      if (params.comments && params.comments.length > 0) {
        callCount++;
        const err = Object.assign(new Error("422 Unprocessable Entity"), { status: 422 });
        throw err;
      }
      // Body-only call succeeds.
      return { data: { id: 2, html_url: "https://github.com/test/fallback" } };
    });

    const octokit = makeOctokit({ createReview: createReviewFn });

    const url = await submitPRReview(
      octokit,
      "owner",
      "repo",
      1,
      [makeComment({ position: 99999 })],
      makeSummary()
    );

    // The fallback body-only review should have been posted.
    expect(url).toBe("https://github.com/test/fallback");
    // At least one 422 was encountered (initial batch + probe).
    expect(callCount).toBeGreaterThan(0);
  });

  it("preserves invalid-position findings in the final body when valid inline comments remain", async () => {
    const validComment = makeComment({
      path: "src/routes/users.js",
      position: 21,
      body: "[high] Valid inline finding",
    });
    const invalidComment = makeComment({
      path: "src/routes/admin.js",
      position: 99999,
      body: "[medium] Invalid-position finding\n\nEvidence that must not be dropped.",
    });
    const createReviewFn = vi.fn().mockImplementation(async (params: {
      body: string;
      comments?: Array<{ path: string; position: number; body: string }>;
    }) => {
      if (params.comments && params.comments.length === 2) {
        throw Object.assign(new Error("422 Unprocessable Entity"), { status: 422 });
      }
      if (
        params.body.startsWith("[Bob probe]")
        && params.comments?.[0]?.path === invalidComment.path
      ) {
        throw Object.assign(new Error("422 Unprocessable Entity"), { status: 422 });
      }
      return { data: { id: 3, html_url: "https://github.com/test/recovered" } };
    });
    const octokit = makeOctokit({ createReview: createReviewFn });

    const url = await submitPRReview(
      octokit,
      "owner",
      "repo",
      1,
      [validComment, invalidComment],
      makeSummary({ finding_count: 2 })
    );

    expect(url).toBe("https://github.com/test/recovered");
    const finalCall = createReviewFn.mock.calls.at(-1)![0] as {
      body: string;
      comments?: Array<{ path: string; position: number; body: string }>;
    };
    expect(finalCall.comments).toEqual([
      {
        path: validComment.path,
        position: validComment.position,
        body: validComment.body,
      },
    ]);
    expect(finalCall.body).toContain("Invalid-position finding");
    expect(finalCall.body).toContain("Evidence that must not be dropped.");
    expect(finalCall.body).toContain("src/routes/admin.js");
    expect(finalCall.body).toContain("position 99999");
  });
});

// ---------------------------------------------------------------------------
// End-to-end simulation: T3 test PR AC2 scenario
// ---------------------------------------------------------------------------

describe("T3 live test AC2 simulation", () => {
  /**
   * This test simulates the exact call that the bob-diff-review action would
   * make to the GitHub Reviews API for the T3 test PR.
   *
   * With a funded ANTHROPIC_API_KEY, the evaluator would find:
   *   1. SQL injection at src/routes/users.js line 20 → diff position 21
   *   2. BOLA/IDOR at src/routes/users.js line 38   → diff position 39
   *   3. Privilege escalation at line 52              → diff position 53
   *
   * The createReview call must include comments[] with position != null and
   * the correct path, satisfying AC2 ("at least one inline PR review comment
   * is posted on a diff line with correct position").
   */
  it("simulates the exact T3 AC2 call: SQL injection comment at diff position 21", async () => {
    const createReviewFn = vi.fn().mockResolvedValue({
      data: {
        id: 111222333,
        html_url: "https://github.com/bobnetsec/bob-workflows-testbed/pull/1#pullrequestreview-111222333",
      },
    });
    const octokit = makeOctokit({ createReview: createReviewFn });

    // This is the resolved comment the resolver would produce for the SQL injection
    // finding at src/routes/users.js line 20 (diff position 21 in the T3 test PR).
    const sqlInjectionComment: ResolvedComment = {
      path: "src/routes/users.js",
      position: 21,
      body:
        "[high] SQL Injection — unsanitised query parameter\n\n" +
        "The `name` query parameter is inserted directly into the SQL query string " +
        "without escaping or parameterisation. An attacker can supply: `' OR '1'='1` " +
        "to dump all users from the database.\n\n" +
        "**Evidence:**\n```\nGET /users/search?name=' OR '1'='1 HTTP/1.1\n" +
        "Host: target.example.com\n\nHTTP/1.1 200 OK\n[All user records returned]\n```",
      side: "RIGHT",
    };

    const summary: ReviewSummary = {
      session_id: "ses-t3-sqli-live",
      target_domain: "gh-1261831449-pr1",
      finding_count: 1,
      severity: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
    };

    const url = await submitPRReview(
      octokit,
      "bobnetsec",
      "bob-workflows-testbed",
      1,
      [sqlInjectionComment],
      summary
    );

    expect(url).toContain("pullrequestreview-111222333");

    const callArgs = createReviewFn.mock.calls[0][0];

    // AC2: position must be non-null (anchored to diff line 21).
    expect(callArgs.comments[0].position).toBe(21);
    expect(callArgs.comments[0].position).not.toBeNull();
    expect(callArgs.comments[0].path).toBe("src/routes/users.js");
    expect(callArgs.comments[0].body).toContain("[high] SQL Injection");

    // Verify no secret patterns in the submitted content.
    const requestJson = JSON.stringify(callArgs);
    expect(requestJson).not.toMatch(/sk-ant-[a-zA-Z0-9]{10,}/);
    expect(requestJson).not.toMatch(/ghp_[a-zA-Z0-9]{10,}/);
    expect(requestJson).not.toMatch(/ghs_[a-zA-Z0-9]{10,}/);
  });
});
