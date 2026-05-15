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

## Triage Rules

- Prefer exact package names, affected ranges, fixed versions, paths, hashes,
  config keys, and service names.
- Do not add broad scary strings as findings.
- Keep remote-exposure checks local unless the operator explicitly asks for a
  scoped network assessment.
- Do not add exploit logic.
