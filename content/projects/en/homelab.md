---
title: 'Homelab'
description: 'A k3s cluster on Raspberry Pi, at home — the ground where I test everything before it gets anywhere near production.'
tags: ['kubernetes', 'k3s', 'raspberry-pi', 'homelab']
order: 4
---

At home I run a [k3s](https://k3s.io/) cluster — the lightweight Kubernetes
distribution, built for modest hardware and ARM — on Raspberry Pi. It's the
same homelab I already mentioned on the [About](/en/about/) page: the guinea
pig for anything I want to try before it gets anywhere near production.

<svg class="diagram-homelab" viewBox="0 0 640 220" role="img" aria-label="Simplified homelab topology: a k3s cluster with a control-plane and agents, isolated from production">
  <defs>
    <marker id="homelab-arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path class="diagram-arrowhead" d="M0,0 L10,5 L0,10 z"></path>
    </marker>
  </defs>
  <rect class="diagram-boundary" x="20" y="24" width="380" height="168" rx="8"></rect>
  <text class="diagram-label" x="34" y="44">homelab</text>
  <rect class="diagram-node" x="165" y="76" width="110" height="46" rx="6"></rect>
  <text class="diagram-node-title" x="220" y="97" text-anchor="middle">control-plane</text>
  <text class="diagram-node-sub" x="220" y="111" text-anchor="middle">k3s server · Pi</text>
  <rect class="diagram-node" x="60" y="150" width="100" height="40" rx="6"></rect>
  <text class="diagram-node-title" x="110" y="172" text-anchor="middle">agent</text>
  <text class="diagram-node-sub" x="110" y="184" text-anchor="middle">k3s agent · Pi</text>
  <rect class="diagram-node" x="270" y="150" width="100" height="40" rx="6"></rect>
  <text class="diagram-node-title" x="320" y="172" text-anchor="middle">agent</text>
  <text class="diagram-node-sub" x="320" y="184" text-anchor="middle">k3s agent · Pi</text>
  <path class="diagram-edge" d="M192,122 L110,150"></path>
  <path class="diagram-edge" d="M248,122 L320,150"></path>
  <rect class="diagram-node diagram-node--prod" x="470" y="99" width="130" height="46" rx="6"></rect>
  <text class="diagram-node-title" x="535" y="120" text-anchor="middle">production</text>
  <text class="diagram-node-sub" x="535" y="134" text-anchor="middle">outside the homelab</text>
  <path class="diagram-edge diagram-edge--dashed" d="M400,122 L465,122"></path>
  <text class="diagram-caption" x="432" y="110" text-anchor="middle">test first</text>
</svg>

*Simplified, illustrative topology — the actual node count varies; what
matters here is the relationship between the cluster and production, not an
inventory.*

## What runs there

There's no fixed list — that's the nature of a testing ground: this site's
tools pass through before they reach someone else's browser, configs I want
to validate before taking them to work, and attack-infrastructure setups for
lab and CTF practice (the heatmap on [Attack](/en/attack/) maps that practice
to MITRE ATT&CK's *Acquire Infrastructure* technique, at the "occasional
experience / lab" level). The common thread is always the same: nothing
touches production without going through here first.

## Why k3s

A Raspberry Pi doesn't have the footprint for a "full" Kubernetes — k3s
exists exactly for this: the same Kubernetes API, with etcd, legacy
controllers, and unnecessary dependencies stripped out to fit low-power ARM
hardware. I get practice with the patterns that matter in production —
multi-node, scheduling, tolerating a lost node — in an environment cheap
enough to break for free.

## Technical decisions

- **A cluster, not a standalone Pi.** A single node only tests "does the
  container run"; several nodes test what actually fails in production —
  losing a node, scheduling under resource pressure, tolerating restarts.
- **Deliberate isolation from production.** The homelab has no access to
  anything that matters outside it; it's disposable by construction, so it
  can be torn down and rebuilt without ceremony.
- **No fixed public exposure.** There's no subdomain pointing at the homelab
  yet (see `docs/dns-tls.md` in this repo) — whether and when that makes
  sense gets decided without compromising the main domain's HSTS preload
  policy in the meantime.
