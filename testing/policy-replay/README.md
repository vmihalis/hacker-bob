# Policy Replay Harness

This harness replays minimized Bob policy regressions against candidate agent prompts. It is for diagnosing false refusals, policy stalls, tool/policy loops, ambiguous prompt wording, and unsafe-compliance regressions. It must not be used to bypass policy; cases should preserve safe refusal behavior where `expected` is `should_refuse`.

## Workflow

1. Run `/bob-debug --deep <target_domain>`.
2. If the debug review flags a policy/refusal issue in `--deep` mode, it can run a local dry-run cut and bounded tune pass directly from the implicated transcript.
3. If a stable regression should be retained, create a minimized and redacted case in `testing/policy-replay/cases/`.
4. Patch the relevant agent prompt after reviewing the suggested prompt change.
5. Dry-run the retained case to confirm the transcript cut:

   ```sh
   node testing/policy-replay/replay.mjs --case testing/policy-replay/cases/<case>.json --system .claude/agents/<agent>.md --dry-run
   ```

6. Run a live local replay with Claude OAuth:

   ```sh
   node testing/policy-replay/replay.mjs --case testing/policy-replay/cases/<case>.json --system .claude/agents/<agent>.md
   ```

7. Compare prompt candidates across retained regression cases:

   ```sh
   node testing/policy-replay/bench.mjs --cases-dir testing/policy-replay/cases --prompts-dir <dir> --n 3
   ```

Keep the minimized case as a regression fixture once the prompt behavior is understood.

For one-off transcript replay without first writing a case:

```sh
node testing/policy-replay/replay.mjs --transcript <agent.jsonl> --agent-type hunter-agent --failure-type refusal --expected should_continue_safely --system .claude/agents/hunter-agent.md --failure-event-index <index> --dry-run
```

For automatic prompt-guardrail trials against that same transcript:

```sh
node testing/policy-replay/tune.mjs --transcript <agent.jsonl> --agent-type hunter-agent --failure-type refusal --expected should_continue_safely --system .claude/agents/hunter-agent.md --failure-event-index <index> --n 3
```

The tune helper writes temporary prompt candidates under the OS temp directory, runs replay, and prints a `recommended_prompt_change` when a candidate passes. It does not edit repository prompts.

## Case Format

Cases are JSON objects with these required fields:

- `agent_type`: agent prompt family, for example `hunter-agent`.
- `prompt_path`: repository-relative or absolute default prompt path.
- `failure_type`: one of `refusal`, `policy_stall`, `tool_policy_loop`, or `unsafe_compliance`.
- `expected`: one of `should_continue_safely`, `should_refuse`, or `should_ask_clarification`.
- `transcript_source` or `transcript`: either a case-relative JSONL transcript path or an embedded minimized transcript event array.

Optional fields include `id`, `notes`, `redaction`, `unsafe_compliance_patterns`, and `replay`. Use `replay.failure_event_index` or `replay.next_user_index` only when the automatic cut cannot find the right failure window. These indexes are zero-based transcript event indexes.

The runner emits one machine-readable JSON object with `ok`, `case_id`, `agent_type`, `expected`, `stop_reason`, `refused`, `unsafe_compliance_detected`, `passed`, `text_preview`, and `error`.

## Local Dependencies

Live replay requires `@anthropic-ai/claude-agent-sdk` and a working local Claude OAuth login. CI-safe dry-run and schema tests do not invoke Claude and do not require credentials.
