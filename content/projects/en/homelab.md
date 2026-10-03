---
title: 'Homelab'
description: 'My home network with zero trust by default: Raspberry Pi, a deny-all firewall, a mesh VPN and my own CI.'
tags: ['homelab', 'zero-trust', 'k3s', 'tailscale']
order: 4
---

My homelab is a small home network made of three Raspberry Pi, a firewall, a
switch, access points and laptops. It is where I practise, in miniature, what
I do at work: network segmentation, controlled remote access, automation and
verification. The design and the decisions are documented in a repository of
their own.

<svg class="diagram-homelab" viewBox="0 0 640 170" role="img" aria-label="Simplified homelab diagram: four segments by role (data, copies, experiments and administration) separated by a firewall that denies all by default">
  <rect class="diagram-boundary" x="20" y="20" width="600" height="130" rx="8"></rect>
  <text class="diagram-label" x="34" y="40">firewall · deny all by default</text>
  <rect class="diagram-node" x="39" y="64" width="118" height="60" rx="6"></rect>
  <text class="diagram-node-title" x="98" y="98" text-anchor="middle">data</text>
  <rect class="diagram-node" x="187" y="64" width="118" height="60" rx="6"></rect>
  <text class="diagram-node-title" x="246" y="98" text-anchor="middle">copies</text>
  <rect class="diagram-node" x="335" y="64" width="118" height="60" rx="6"></rect>
  <text class="diagram-node-title" x="394" y="98" text-anchor="middle">experiments</text>
  <rect class="diagram-node diagram-node--prod" x="483" y="64" width="118" height="60" rx="6"></rect>
  <text class="diagram-node-title" x="542" y="98" text-anchor="middle">administration</text>
</svg>

## Zero trust by default

No machine trusts another just because it is on the same network. The
firewall denies all traffic between segments by default (deny all) and only
opens what each role needs, with an explicit rule. Remote access goes through
a mesh VPN instead of ports open to the Internet. Each Raspberry Pi has one
role and lives in its own segment, and the laptops are the administration.

## What it uses

- **Firewall, switch and access points.** The firewall enforces the
  boundaries between segments, and the switch and access points carry the
  VLANs to the machines.
- **Tailscale.** The mesh VPN for remote access, with permissions defined by
  ACL.
- **Docker.** Services run in containers, managed with Compose, each with its
  own user.
- **Vaultwarden.** The password manager, self-hosted and in a segment of its
  own, with no exposure to the Internet.
- **GitHub Actions runners.** My own CI, which also applies the configuration
  to the machines. It runs third-party code, such as workflow dependencies,
  so it sits in the segment I can break without losing anything.
- **k3s.** A lightweight Kubernetes for learning and testing, kept away from
  anything irreplaceable.

## How I keep it

- **Verify, don't assume.** Every network rule has a mechanism that enforces
  it and a test that confirms it, and that test runs automatically.
- **Configuration as code.** The machines are configured with versioned
  scripts, applied by CI.
- **Secrets out of the repository.** No secret goes into git, and a scanner
  makes sure of it.
- **Decisions on record.** Every choice has its own record, with the context
  and the reason, so that a year from now I can tell what I decided.
