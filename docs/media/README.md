# Media Capture Checklist

This directory is reserved for real, sanitized screenshots and short demos. Do not add mocked Claude Code screenshots.

## Required Captures

Capture these from a throwaway Claude Code workspace with no real credentials, tokens, customer data, target data, cookies, or private reports:

1. `doctor-ok.png`: successful `hacker-bob doctor /path/to/test-workspace` output.
2. `status-fresh.png`: `/bob-status` immediately after a fresh install and Claude Code restart.
3. `evaluate-start.png`: `/bob-evaluate` starting against a controlled lab target that the maintainer owns or is explicitly authorized to test.
4. `hacker-bob-demo.gif`: reproducible general installation demo generated from `hacker-bob-demo.tape`.
5. `hacker-bob-doctor-demo.gif`: reproducible install-health demo generated from `hacker-bob-doctor-demo.tape`.
6. `hacker-bob-receipts-demo.gif`: animated receipt-portfolio roll generated from `hacker-bob-receipts-demo.tape`.
7. `hacker-bob-receipts-demo.sh`: checked-in, human-readable CVE receipt source used by the animation.
8. `readme-hero.png`: current black-and-amber Hacker Bob artwork mirrored from `https://hackerbob.ai/og.png`.
9. `readme-footer.svg`: branded contribution, private-security-reporting, and license footer.
10. `readme-signal-deck.svg`: black-and-amber portfolio, adapter, and runtime status deck.
11. `readme-chapter-deploy.svg`: deploy chapter band for installation and host selection.
12. `readme-chapter-proof.svg`: proof chapter band for receipts and the evidence chain.
13. `readme-chapter-operate.svg`: operations chapter band for CI, safety, reference, and contribution.
14. `readme-community-header.svg`: branded Code of Conduct header.
15. `readme-contributing-header.svg`: branded contributor operations header.
16. `readme-security-header.svg`: branded private security reporting header.

## Sanitization

Before committing media, verify that the image does not show home directory names, usernames, API keys, cookies, account emails, private repository paths, real bug bounty targets, report contents, or session artifacts from `~/bounty-agent-sessions`.

## Capture Flow

Use a disposable project:

```bash
mkdir -p /tmp/hacker-bob-media-workspace
npm ci
node bin/hacker-bob.js install /tmp/hacker-bob-media-workspace
node bin/hacker-bob.js doctor /tmp/hacker-bob-media-workspace
cd /tmp/hacker-bob-media-workspace
claude --dangerously-skip-permissions --effort max
```

Warning: `--dangerously-skip-permissions` disables Claude Code permission prompts. Use it only in a disposable workspace for authorized media capture against a controlled lab target.

Then capture `/bob-status` and `/bob-evaluate lab.example.test` from Claude Code. Use only a lab target that is owned by the maintainer or explicitly authorized for testing.

## Rebuilding The VHS Demos

From the repository root:

```bash
vhs docs/media/hacker-bob-demo.tape
vhs docs/media/hacker-bob-doctor-demo.tape
vhs docs/media/hacker-bob-receipts-demo.tape
```

The install and doctor tapes use disposable workspaces under `/private/tmp`, exercise only the current checkout's local install and doctor commands, and remove their workspaces afterward. The receipt tape reads only the checked-in receipt source. None of the tapes run recon, signup flows, evaluations, or target scans.
