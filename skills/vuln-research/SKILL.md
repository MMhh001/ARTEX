---
name: vuln-research
description: Evidence-driven source, version, and artifact vulnerability research with explicit false-positive elimination and reproducible validation.
license: Proprietary
compatibility: Requires local source or artifacts and standard shell/code-search tools.
---

# Vulnerability Research

Use this skill for authorized analysis of local source repositories, supplied versions, or task artifacts.

## Workflow

1. Establish the exact target, revision, build flags, default configuration, trust boundaries, and attacker capabilities.
2. Map externally reachable parsers, protocol handlers, import/export paths, authentication boundaries, plugin systems, update paths, and privileged operations.
3. Trace attacker-controlled data through validation and transformations into security-sensitive sinks.
4. Keep hypotheses explicit. For every candidate, record the entry point, control primitive, path constraints, sink, expected impact, and missing proof.
5. Seek disconfirming evidence before escalation: unreachable code, safe wrappers, canonicalization, permission checks, feature gates, test-only paths, and version mismatch.
6. Validate with the smallest safe local test or PoC. Prefer a regression test that fails before a fix and passes after it.
7. Report a finding only when reachability, attacker control, boundary violation or concrete security impact, affected versions, and reproducible evidence are established.

## Evidence quality

- Cite repository-relative file paths and symbols; include line numbers only after confirming they match the analyzed revision.
- Preserve commands, inputs, outputs, stack traces, logs, and generated test artifacts under the task working directory.
- Separate observed facts from inference.
- A crash is not automatically exploitable; an unsafe sink is not automatically reachable.
- Never claim a version is affected merely because similar code exists in another revision.

## Safety

- Work only on the authorized local material and explicitly scoped test systems.
- Use non-destructive payloads and synthetic data.
- Do not exfiltrate real secrets or use third-party systems to demonstrate impact.
