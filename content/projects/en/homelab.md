---
title: 'Homelab'
description: 'My personal infrastructure, split by role, where every network rule has a test that checks it.'
tags: ['homelab', 'segmentation', 'raspberry-pi', 'gitops']
order: 4
---

At home I run a small personal infrastructure made of three Raspberry Pi and
a laptop. It is not a showcase of services. It is where I design and operate,
in miniature, what I do at work: segmentation, controlled remote access,
automation and verification. The design, the decisions and the state of each
part are documented in a repository of their own.

<svg class="diagram-homelab" viewBox="0 0 640 230" role="img" aria-label="Simplified homelab diagram: four segments (vault, copy, workshop and bench) separated by a firewall, with the vault unable to reach the copy">
  <defs>
    <marker id="homelab-arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path class="diagram-arrowhead" d="M0,0 L10,5 L0,10 z"></path>
    </marker>
  </defs>
  <rect class="diagram-boundary" x="20" y="24" width="600" height="182" rx="8"></rect>
  <text class="diagram-label" x="34" y="44">firewall · boundaries between segments</text>
  <rect class="diagram-node" x="39" y="76" width="118" height="64" rx="6"></rect>
  <text class="diagram-node-title" x="98" y="104" text-anchor="middle">vault</text>
  <text class="diagram-node-sub" x="98" y="120" text-anchor="middle">the irreplaceable</text>
  <rect class="diagram-node" x="187" y="76" width="118" height="64" rx="6"></rect>
  <text class="diagram-node-title" x="246" y="104" text-anchor="middle">copy</text>
  <text class="diagram-node-sub" x="246" y="120" text-anchor="middle">outlives the vault</text>
  <rect class="diagram-node" x="335" y="76" width="118" height="64" rx="6"></rect>
  <text class="diagram-node-title" x="394" y="104" text-anchor="middle">workshop</text>
  <text class="diagram-node-sub" x="394" y="120" text-anchor="middle">third-party code</text>
  <rect class="diagram-node diagram-node--prod" x="483" y="76" width="118" height="64" rx="6"></rect>
  <text class="diagram-node-title" x="542" y="104" text-anchor="middle">bench</text>
  <text class="diagram-node-sub" x="542" y="120" text-anchor="middle">admin · keys</text>
  <path class="diagram-edge diagram-edge--dashed" d="M157,112 L185,112"></path>
  <text class="diagram-caption" x="171" y="100" text-anchor="middle">✕</text>
  <text class="diagram-caption" x="39" y="170">✕ the vault never initiates connections to the copy</text>
  <text class="diagram-caption" x="39" y="188">remote access only through a mesh VPN</text>
</svg>

*Simplified diagram. It shows each segment's role and the rule that matters
most, not an inventory.*

## How it is organised

The home network is split into segments, each with its own role and kind of
risk.

| Segment | What it is for |
| --- | --- |
| Vault | Holds what cannot be lost or replaced. |
| Copy | Holds the copy that outlives the vault, and that the vault cannot reach. |
| Workshop | Runs code I did not write, such as CI, and the k3s experiments. Nothing here is irreplaceable. |
| Bench | Where I administer, where the lab of disposable virtual machines lives, and where the administration keys live, away from the servers. |

Every machine is mine, so the split is not about distrust. It is about what a
compromise would reach. Whatever runs third-party code sits in the segment I
can break without losing anything.

## What I decided, and why

- **A rule only counts if someone checks it.** Each boundary between
  segments has a mechanism that enforces it and a command that tests it, and
  the check runs every day. The test must also fail when the mechanism does
  not exist: a connection refused because nothing is listening proves no
  restriction at all, so I expect the connection to time out.
- **A faithful replica is not a backup.** A mirror of the repositories would
  copy a `push --force` that erased history too. So the replica does not
  delete what the original no longer has, and the real copy sits in another
  segment.
- **Nothing exposed.** Remote access to the machines goes through a mesh
  VPN, and the design plans nothing public.
- **Secrets out of git.** No secret goes into the repository, and a secret
  scanner has run in CI since the first commit.
- **Automatic security updates, manual reboots.** Security packages install
  themselves, but no machine reboots until I decide to.
- **State lives in one place.** A plan says what is done, half done,
  postponed and still to do, with the proof for each, and every decision has
  its own record. A line of documentation that does not match the machine is
  worse than none, so whatever describes what exists carries a date and how
  it was verified.

## Where it stands

Done: network segmentation and remote access, the vault segment with
automatic replicas of the repositories, the daily check of the boundaries and
the security updates. Under construction: the k3s cluster with GitOps (Flux)
in the workshop, one user per CI runner and the backups.
