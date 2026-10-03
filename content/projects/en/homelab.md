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

<svg class="diagram-homelab" viewBox="0 0 640 214" role="img" aria-label="Simplified homelab diagram: a firewall connecting four segments (data, copies, experiments and administration) and blocking everything by default">
  <rect class="diagram-node" x="40" y="20" width="560" height="44" rx="6"></rect>
  <text class="diagram-node-title" x="320" y="47" text-anchor="middle">firewall · deny all by default</text>
  <path class="diagram-edge" d="M80,64 L80,110"></path>
  <rect class="diagram-node" x="12" y="110" width="136" height="84" rx="6"></rect>
  <text class="diagram-node-title" x="80" y="146" text-anchor="middle">data</text>
  <text class="diagram-node-sub" x="80" y="164" text-anchor="middle">what must not be lost</text>
  <path class="diagram-edge" d="M240,64 L240,110"></path>
  <rect class="diagram-node" x="172" y="110" width="136" height="84" rx="6"></rect>
  <text class="diagram-node-title" x="240" y="146" text-anchor="middle">copies</text>
  <text class="diagram-node-sub" x="240" y="164" text-anchor="middle">a copy of what matters</text>
  <path class="diagram-edge" d="M400,64 L400,110"></path>
  <rect class="diagram-node" x="332" y="110" width="136" height="84" rx="6"></rect>
  <text class="diagram-node-title" x="400" y="146" text-anchor="middle">experiments</text>
  <text class="diagram-node-sub" x="400" y="164" text-anchor="middle">where I test and break</text>
  <path class="diagram-edge" d="M560,64 L560,110"></path>
  <rect class="diagram-node diagram-node--prod" x="492" y="110" width="136" height="84" rx="6"></rect>
  <text class="diagram-node-title" x="560" y="146" text-anchor="middle">administration</text>
  <text class="diagram-node-sub" x="560" y="164" text-anchor="middle">where I run everything</text>
</svg>

*The segments only talk through the firewall, which blocks anything without an explicit rule.*

## Zero trust by default

No machine trusts another just because it is on the same network. The
firewall denies all traffic between segments by default (deny all) and only
opens what each role needs, with an explicit rule. Each Raspberry Pi has one
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
  own.
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
