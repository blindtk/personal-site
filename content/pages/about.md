---
title: 'About me'
---

I'm **Daniel Malaco**, an **Information Security Engineer** in Porto, Portugal.
Since 2020 I have worked at Ascendi, where I design and run the security of
critical road infrastructure. The work covers the whole cycle: next-generation
firewalls, SIEM, endpoint protection, identity management, threat intelligence
and incident response. I design the control and I also analyse the event it
catches.

I came to security through networks. Between 2017 and 2020 I designed,
installed and commissioned IP networks on metro and rail projects: the Doha
Metro, the Santos VLT, and the Odense and Bergen light metros. In a transport
system a network failure is not just an inconvenience: the trains stop and
thousands of people are left waiting. That is where I learned to design for
redundancy, to document for whoever comes next, and to test everything in the
lab before touching production.

In 2020 I started looking at networks from the attacker's side. At Hardsecure
I deployed firewalls and ran internal penetration tests, looking for
vulnerabilities before someone else could exploit them. That way of thinking is
what I bring to defensive work today. I keep training it outside work too: I
took SANS SEC504, I follow the SANS DFIR and ransomware summits, and I have won
four CTFs, the first in Lisbon in 2022. The photos are at the end of this page.

I like building the tools I use. The ones on this site run in the browser, and
at home I run a homelab, segmented by role, where I try things
out before they get anywhere near production. The site itself is part of that:
it is static, bilingual, has no trackers, and how it is protected is explained
in [This site](/en/this-site/).

## Experience

Open each role for the detail.

<details>
<summary>Information Security Engineer · Ascendi <span>Nov 2020 → present</span></summary>

- **Context:** security of Ascendi's critical road infrastructure, in
  Portugal.
- **Role:** designing, deploying and operating the information security
  architecture; handling requests and incidents in ITSM.
- **Technologies:** NGFW, AV/EDR, vulnerability assessment, SIEM, IAM, WAF and
  email gateway (SEG).
- **Day to day:** keeping networks, systems and applications secure through
  policies and procedures, detecting threats and vulnerabilities, and putting
  in place the controls that mitigate them, based on monitoring and analysis of
  security events.
- **External reference:** Fortinet published a [case study on
  Ascendi](https://www.fortinet.com/customers/ascendi) that describes the
  security infrastructure I helped build. The article quotes the Head of IT
  and does not name me, but I was part of the team behind that work.

</details>

<details>
<summary>Cyber Security Engineer · Hardsecure <span>Feb 2020 → Sep 2020</span></summary>

- **Context:** next-generation firewall deployments and internal penetration
  tests.
- **Role:** installing, configuring and supporting NGFW.
- **Technologies:** NGFW, network scanning and enumeration.
- **Outcome:** vulnerabilities found in networks before they could be
  exploited.

</details>

<details>
<summary>Systems Engineer · Efacec <span>Jan 2019 → Feb 2020</span></summary>

**Odense Letbane** (Denmark)

- **Context:** the Odense light metro project.
- **Role:** design, installation and commissioning of the IP networks and
  security.
- **Method:** system requirements, design and installation documents, lab
  staging, test procedures and commissioning.
- **Outcome:** the IP network and security layer went from design to
  commissioning, with lab staging, testing and a documented handover to the
  operations team.

**Bergen D42** (Norway)

- **Context:** the Bergen light metro project, section D42.
- **Role:** design, installation and commissioning of the IP networks and
  security.
- **Method:** the same as Odense, from system requirements to commissioning.
- **Outcome:** design, installation and commissioning of section D42
  documented from the system requirements, ready for the line to enter
  service.

</details>

<details>
<summary>Junior Consultant · Altran / Network Engineer · Thales <span>Jan 2017 → Dec 2018</span></summary>

**Doha Metro** (Qatar)

- **Context:** the Doha Metro project, built from scratch.
- **Role:** design, installation and commissioning of the IP networks and the
  BBRS system, the mobile WiFi that travels with the trains.
- **Technologies:** IP networks, BBRS, rail and metro environments.

**VLT Santos** (Brazil)

- **Context:** the Santos VLT (light rail) project.
- **Role:** design, installation and commissioning of the IP networks and
  BBRS.
- **Outcome:** the same rail stack as Doha, adapted to an urban light-rail
  system.

</details>

## Education

- **MSc in Electrical and Computer Engineering** at FEUP (Faculty of
  Engineering, University of Porto), 2009 to 2016, specialising in
  Communication Networks and Services.

## Certifications

I hold certifications from Fortinet, SANS, Microsoft, CyberDefenders and
others. The full list, with the status of each one and independent
verification on Credly, is on **[Certifications](/en/certifications/)**.

## ATT&CK coverage

The **[ATT&CK heatmap](/en/attack/)** shows, tactic by tactic, the MITRE ATT&CK
techniques I cover on the defensive side and the tool or experience behind
each one.

## Skills

| Area | Detail |
| --- | --- |
| Perimeter | NGFW, WAF, Security Email Gateway (SEG) |
| Endpoint | Antivirus (AV), Endpoint Detection & Response (EDR) |
| Identity | IAM, Active Directory |
| Detection and response | SIEM, vulnerability assessment (VA), penetration testing |
| Resilience | Business Continuity Planning (BCP) |
| Languages | Python, Bash, PowerShell, Golang, C/C++ |
| Platforms | Linux, Windows, AWS, Azure, Rapid7 InsightVM, ServiceNow |

## Frameworks

I use these frameworks as working tools: to structure decisions, prioritise
controls and speak the same language as auditors, vendors and regulators. The
table says where each one comes into the work and at what depth.

| Framework | Where it comes into the work | Depth |
| --- | --- | --- |
| ISO 27001 | Basis for the security policies and procedures, and for organising technical controls by domain. | Reference |
| NIS2 | Regulatory context of the sector I work in, critical transport infrastructure. It shapes control and reporting priorities. | Context |
| CIS Controls & Benchmarks | Basis for hardening systems and network equipment, and for checking configurations. | Applied |
| CISA CPG | Point of comparison for prioritising baseline controls in critical infrastructure. | Reference |
| OWASP Top 10 | Common vocabulary for classifying what vulnerability assessments and internal tests find, and for tuning WAF rules. | Applied |
| MITRE ATT&CK | Mapping detection coverage and structuring incident analysis. The detail, technique by technique, is in the [heatmap](/en/attack/). | Applied |

*Applied* means in regular use in controls I operate. *Reference* means I
consult it during design and prioritisation, with no formal process attached.
*Context* is the sector's regulatory backdrop, not a programme I run. No row
implies certification, formal audit or declared compliance.
