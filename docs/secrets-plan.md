# Secrets Plan — Anthropic and Bob Install Secrets

This document defines the secrets used to run the `bob-diff-review` GitHub
Action, their storage scope, minimum permission scopes, rotation policy, and the
injection pattern used inside the action.

---

## Secrets Overview

| Secret name             | Storage scope | Type                           | Minimum permissions                   |
|-------------------------|---------------|--------------------------------|---------------------------------------|
| `ANTHROPIC_OAUTH_TOKEN` | Org-level     | Claude OAuth token             | Claude Code access for diff review    |
| `ANTHROPIC_API_KEY`     | Org-level     | Anthropic API key fallback     | Sufficient credits; no extra scopes   |
| `BOB_INSTALL_TOKEN`     | Org-level     | GitHub App installation token  | `read:packages`, `contents:read`      |

These secrets are stored at the **organization level** in GitHub
(`Settings → Secrets and variables → Actions → Organization secrets`) and are
made available to all repositories in the `bobnetsec` organization that use
the `bob-diff-review` action.  Neither secret is duplicated at the repo level;
individual repos inherit them from the org. `ANTHROPIC_OAUTH_TOKEN` is the
recommended Claude auth path; `ANTHROPIC_API_KEY` is the pay-per-use fallback.
When both are configured, the runner injects only the OAuth token into the
Claude subprocess.

---

## ANTHROPIC_API_KEY

### Purpose

Passed to the `claude` headless runner so the Action can invoke the Claude API
on behalf of the workflow.  Without it the `claude --headless` subprocess
cannot authenticate and every run fails immediately.

### Storage and scope

- **Scope:** Organization-level secret (`bobnetsec` org).
- **Propagation:** Available to workflows triggered by internal (non-forked)
  PRs.  Do **not** propagate this secret to forked-PR workflows; treat any
  `pull_request` event from a fork as untrusted.

### Minimum permissions

An Anthropic API key carries no fine-grained permission model; the key grants
API access up to the associated account's quota and tier.  The key itself
should belong to a dedicated service account (not a personal account) to avoid
entanglement with human billing.

### Injection into the action

The calling workflow passes the key as an action input:

```yaml
- uses: bobnetsec/bob-workflows/packages/bob-diff-review@v1
  with:
    anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
    bob_install_token: ${{ secrets.BOB_INSTALL_TOKEN }}
```

Inside `action.yml` the input is mapped to an environment variable for the
`claude` subprocess:

```yaml
env:
  ANTHROPIC_API_KEY: ${{ inputs.anthropic_api_key }}
```

### Rotation policy

- **Frequency:** Rotate every 90 days or immediately on any suspected
  exposure.
- **Procedure:**
  1. Generate a new key in the Anthropic console under the service account.
  2. Update the `ANTHROPIC_API_KEY` org secret in GitHub.
  3. Revoke the old key in the Anthropic console.
  4. Verify the next scheduled workflow run succeeds before closing the
     rotation ticket.
- **Breach response:** Revoke the old key first, then rotate; the old key
  becomes invalid the moment it is revoked, so there is no window in which
  both keys are live.

### No-log guarantee

The value is never echoed in a `run:` step.  Any health-check or diagnostic
step that needs to confirm the key is _present_ (not its value) must use:

```bash
if [ -n "$ANTHROPIC_API_KEY" ]; then echo "ANTHROPIC_API_KEY present"; else echo "ANTHROPIC_API_KEY REDACTED or missing"; fi
```

GitHub Actions automatically masks secrets in log output, but the pattern
above adds a defense-in-depth layer so the check works even if the masking
layer is bypassed by an indirect expansion.

---

## BOB_INSTALL_TOKEN

### Purpose

Used to authenticate `npm install` (or `npm ci`) against the GitHub Packages
registry (`npm.pkg.github.com`) so the runner can download the private
`@bobnetsec/*` packages during the Action run.  The token is also used to
check out the private `bobnetsec/hacker-bob` repository on cache-miss runs.

### Preferred token type: GitHub App installation token

A **GitHub App installation token** is strongly preferred over a classic PAT
because:

- Tokens expire after one hour and are automatically refreshed per-run;
  there is no long-lived credential to rotate manually.
- Permissions are scoped to the App installation, not to a human account.
- The token cannot be used interactively, reducing the blast radius if
  intercepted.

If a classic PAT must be used as a fallback (e.g., during bootstrapping
before the App is installed):

- Create a fine-grained PAT scoped to the `bobnetsec` organization.
- Grant **only** `read:packages` and `contents:read`.
- Set an expiry of 90 days and rotate before expiry.

### Storage and scope

- **Scope:** Organization-level secret (`bobnetsec` org).
- **Propagation:** Same gate as `ANTHROPIC_API_KEY` — internal PRs only;
  never exposed to fork workflows.

### Minimum permissions

| Permission       | Level     | Reason                                              |
|------------------|-----------|-----------------------------------------------------|
| `read:packages`  | Required  | Allows `npm install` from `npm.pkg.github.com`      |
| `contents:read`  | Required  | Allows checking out `bobnetsec/hacker-bob` on miss  |

No write, admin, or pull-request permissions are needed.

### Injection into the action

```yaml
- uses: bobnetsec/bob-workflows/packages/bob-diff-review@v1
  with:
    anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
    bob_install_token: ${{ secrets.BOB_INSTALL_TOKEN }}
```

Inside `action.yml` the token is mapped for `npm` registry auth and for the
`cache-bob-workspace` sub-action:

```yaml
env:
  NODE_AUTH_TOKEN: ${{ inputs.bob_install_token }}
```

The `actions/setup-node` step must be configured with
`registry-url: https://npm.pkg.github.com` so Node sets
`NODE_AUTH_TOKEN` automatically for `npm ci` calls.

### Rotation policy

**GitHub App installation token (preferred):** No manual rotation required.
Tokens are issued per-run by the App and expire after one hour.  Monitor the
App installation in `bobnetsec` org settings to ensure the App has not been
uninstalled or had its permissions downgraded.

**Classic PAT (fallback):** Rotate every 90 days or immediately on suspected
exposure.
  1. Create a new fine-grained PAT with `read:packages` + `contents:read`.
  2. Update the `BOB_INSTALL_TOKEN` org secret.
  3. Verify a workflow run succeeds (`npm ci` completes without 401).
  4. Expire or revoke the old PAT.

### No-log guarantee

The token value is never echoed.  Any presence check must use:

```bash
if [ -n "$NODE_AUTH_TOKEN" ]; then echo "BOB_INSTALL_TOKEN present"; else echo "BOB_INSTALL_TOKEN REDACTED or missing"; fi
```

---

## PR / fork gating

Both secrets must be gated so they are never available in fork-triggered
workflows.  In any workflow that uses these secrets, add the following
guard on every job that reads them:

```yaml
if: >-
  github.event.pull_request.head.repo.full_name == github.repository
```

This ensures forked PRs skip the secret-consuming job entirely.  The same
guard is already applied in `brutalist-review.yml` with an additional
allowlist of trusted authors.

---

## Summary checklist

- [ ] `ANTHROPIC_API_KEY` created as org-level secret in `bobnetsec` GitHub org.
- [ ] `BOB_INSTALL_TOKEN` created as org-level secret (GitHub App token or
      90-day fine-grained PAT with `read:packages` + `contents:read`).
- [ ] Both secrets propagated to the repositories that run `bob-diff-review`.
- [ ] Workflows that consume the secrets gate on
      `head.repo.full_name == github.repository`.
- [ ] No `run:` step echoes a raw secret value; presence checks use the
      `if [ -n "$SECRET" ]; then echo present; fi` pattern.
- [ ] Rotation reminders set in the team calendar for PAT-based tokens.
