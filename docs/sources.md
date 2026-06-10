# Sources

This guard tracks conservative local checks from public OpenClaw advisory
material. It should be updated only with precise, reviewable indicators.

## OpenClaw Advisories

- GHSA-g55j-c2v4-pjcg: unauthenticated local RCE via WebSocket `config.apply`,
  fixed in `2026.1.20`.
  <https://advisories.gitlab.com/npm/openclaw/GHSA-g55j-c2v4-pjcg/>
- GHSA-g27f-9qjv-22pm: log poisoning / indirect prompt injection via WebSocket
  headers, fixed in `2026.2.13`.
  <https://advisories.gitlab.com/npm/openclaw/GHSA-g27f-9qjv-22pm/>
- GHSA-cv7m-c9jx-vg7q / CVE-2026-26329: browser upload path traversal allowing
  local file read, fixed in `2026.2.14`.
  <https://github.com/advisories/GHSA-cv7m-c9jx-vg7q>
- GHSA-m3mh-3mpg-37hw: local plugin/hook install-time command execution through
  `.npmrc` `git=` override, fixed in `2026.3.24`.
  <https://github.com/openclaw/openclaw/security/advisories/GHSA-m3mh-3mpg-37hw>

## Agent Phishing / Social-Trust Research

- Varonis Threat Labs, "Phishing for Lobsters: How We Tricked OpenClaw into
  Spilling Secrets" (2026-06-09): OpenClaw email-agent simulations leaked AWS,
  database, SSH, and CRM/customer-export data when plausible urgent or routine
  requests bypassed sender identity verification.
  <https://www.varonis.com/blog/openclaw-phishing>
- BleepingComputer, "OpenClaw AI agent found falling for phishing attacks,
  spills user data" (2026-06-09): summary of the Varonis OpenClaw phishing
  simulations and recommended controls.
  <https://www.bleepingcomputer.com/news/security/openclaw-ai-agent-found-falling-for-phishing-attacks-spills-user-data/>

## Triage Rules

- Prefer exact package names, affected ranges, fixed versions, paths, hashes,
  config keys, and service names.
- Do not add broad scary strings as findings.
- Keep remote-exposure checks local unless the operator explicitly asks for a
  scoped network assessment.
- For agent-phishing checks, prefer architecture/control signals such as inbox
  access, outbound-send capability, sensitive-data connectors, identity
  verification, first-time external recipient gating, and human approval.
- Do not add exploit logic.
