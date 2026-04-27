# Deprecated refusal-replay prompt candidates

Prefer `testing/policy-replay/bench.mjs` with minimized cases in
`testing/policy-replay/cases/`. This directory is retained only for ad hoc
raw Anthropic API comparisons through the deprecated `replay-refusal.js` path.

Candidate hunter system prompts for `replay-refusal.js`. Each file is a
drop-in replacement for `.claude/agents/hunter-agent.md` (frontmatter optional
— the harness strips it).

To benchmark:

```sh
export ANTHROPIC_API_KEY=sk-...
scripts/bench-prompts.sh \
  ~/.claude/projects/-Users-memehalis-sec/<sess>/subagents/agent-<id>.jsonl \
  scripts/replay-prompts \
  5
```

That runs each `*.md` candidate 5 times against the given transcript and prints
a refusal-rate per file. The transcript is replayed in cached form on Anthropic's
side (same prefix, only system prompt changes), so trials are cheap.

To add a candidate, copy `.claude/agents/hunter-agent.md`, edit, save here.
