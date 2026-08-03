# ADR 0012 — GitHub Actions hardening baseline: SHA-pinned actions, `permissions: {}`, no `persist-credentials`

**Status:** accepted and in production, across every workflow in `.github/workflows/`.

## Context

GitHub Actions' defaults are permissive: actions are commonly referenced
by a floating tag (`@v4`) that can be repointed by the publisher at any
time, workflows inherit broad `GITHUB_TOKEN` permissions unless told
otherwise, and `actions/checkout` persists a Git credential in
`.git/config` by default — usable by any subsequent step, including a
malicious one. Every one of these defaults is a known, common supply-chain
foot-gun (a compromised or repointed action tag runs with the workflow's
full permissions on every consumer, instantly).

## Decision

Apply a stricter baseline everywhere, not just where an incident makes it
obviously necessary:

- **Every action pinned to a commit SHA**, never a tag —
  `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1`,
  with the version kept as a comment for readability. [Renovate](../../renovate.json5)
  keeps the digests current, since a SHA pin alone would otherwise never
  update.
- **`permissions: {}` at workflow level**, with each job declaring only
  the specific permissions it needs. Prevents inheriting the repository's
  default token permissions (which can be read-write) if `GITHUB_TOKEN`
  ever gets used by mistake.
- **`persist-credentials: false`** on every `actions/checkout` — the
  token doesn't stay written to `.git/config` after checkout, so a later
  step (including one from a compromised dependency) can't reuse it.
- **No `pull_request_target`, no `workflow_run`** anywhere — the two
  trigger types most commonly abused to run untrusted fork-PR code with
  trusted-repo secrets.
- **zizmor** audits the workflows themselves on every push, checking for
  exactly these classes of misconfiguration — including a real catch
  recorded in comments: zizmor 1.27.0 itself was once pulled from PyPI
  under a security advisory (GHSA-f42p-wjw5-97qh), found while
  reproducing the job locally.

## Consequences

- A malicious PR — including from a fork, which anyone can open on a
  public repo — cannot escalate through a workflow's permissions, cannot
  smuggle a credential out via a repointed action, and cannot borrow the
  checkout token for a later step.
- Cost is small but real: any action bump now goes through Renovate's
  weekly digest-update PR instead of updating silently; this is the
  entire point (an unreviewed silent update is what SHA pinning exists to
  prevent).
- This baseline is what makes [ADR 0011](0011-sem-token-cloudflare-no-github-actions.md)'s
  absence of a deploy credential meaningful — hardening a pipeline that
  holds no high-value secret is good hygiene; hardening one that *does*
  (once H3 closes and a deploy token exists) becomes load-bearing.
