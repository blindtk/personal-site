---
title: 'Homelab'
description: 'My personal infrastructure, segmented by role, automated and verified.'
tags: ['homelab', 'segmentation', 'automation', 'raspberry-pi']
order: 4
---

At home I run a small personal infrastructure made of a few Raspberry Pi and
a laptop. It is where I practise, in miniature, what I do at work: network
segmentation, controlled remote access, automation and verification. The
design and the decisions are documented in a repository of their own.

<svg class="diagram-homelab" viewBox="0 0 640 170" role="img" aria-label="Simplified homelab diagram: four segments by role (data, copies, experiments and administration) separated by a firewall">
  <rect class="diagram-boundary" x="20" y="20" width="600" height="130" rx="8"></rect>
  <text class="diagram-label" x="34" y="40">firewall · segments by role</text>
  <rect class="diagram-node" x="39" y="64" width="118" height="60" rx="6"></rect>
  <text class="diagram-node-title" x="98" y="98" text-anchor="middle">data</text>
  <rect class="diagram-node" x="187" y="64" width="118" height="60" rx="6"></rect>
  <text class="diagram-node-title" x="246" y="98" text-anchor="middle">copies</text>
  <rect class="diagram-node" x="335" y="64" width="118" height="60" rx="6"></rect>
  <text class="diagram-node-title" x="394" y="98" text-anchor="middle">experiments</text>
  <rect class="diagram-node diagram-node--prod" x="483" y="64" width="118" height="60" rx="6"></rect>
  <text class="diagram-node-title" x="542" y="98" text-anchor="middle">administration</text>
</svg>

## How I think about it

- **Separate by role.** Each machine has one job and lives in its own
  segment, so a compromise only reaches what that role allows.
- **Verify, don't assume.** Every network rule has a mechanism that enforces
  it and a test that confirms it, and that test runs automatically.
- **Configuration as code.** The machines are configured with versioned
  scripts, applied by CI.
- **Secrets out of the repository.** No secret goes into git, and a scanner
  makes sure of it.
- **Decisions on record.** Every choice has its own record, with the context
  and the reason, so that a year from now I can tell what I decided.
