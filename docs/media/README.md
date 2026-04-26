# Media Capture Checklist

This directory is reserved for real, sanitized screenshots and short demos. Do not add mocked Claude Code screenshots.

## Required Captures

Capture these from a throwaway Claude Code workspace with no real credentials, tokens, customer data, target data, cookies, or private reports:

1. `doctor-ok.png`: successful `hacker-bob doctor /path/to/test-workspace` output.
2. `status-fresh.png`: `/bob:status` immediately after a fresh install and Claude Code restart.
3. `hunt-start.png`: `/bob:hunt` starting against a controlled lab target that the maintainer owns or is explicitly authorized to test.

## Sanitization

Before committing media, verify that the image does not show home directory names, usernames, API keys, cookies, account emails, private repository paths, real bug bounty targets, report contents, or session artifacts from `~/bounty-agent-sessions`.

## Capture Flow

Use a disposable project:

```bash
mkdir -p /tmp/hacker-bob-media-workspace
npx -y hacker-bob@latest install /tmp/hacker-bob-media-workspace
hacker-bob doctor /tmp/hacker-bob-media-workspace
cd /tmp/hacker-bob-media-workspace
claude --dangerously-skip-permissions --effort max
```

Warning: `--dangerously-skip-permissions` disables Claude Code permission prompts. Use it only in a disposable workspace for authorized media capture against a controlled lab target.

Then capture `/bob:status` and `/bob:hunt lab.example.test` from Claude Code. Use only a lab target that is owned by the maintainer or explicitly authorized for testing.
