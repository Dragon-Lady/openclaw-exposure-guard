# OpenClaw Exposure Guard

Read-only checker for OpenClaw AI-agent server exposure, vulnerable versions,
risky configs, and credential-adjacent surfaces.

## Safety and Privacy

This tool does not save or collect user data.

- No telemetry.
- No registry calls.
- No package installation.
- No exploit tests.
- No cleanup or file removal.
- No secrets printed.
- No scan results uploaded or written unless you redirect command output yourself.

The guard reads local file names, package metadata, selected config text, and
local TCP listener metadata. Credential-adjacent files are reported by path only.

## Install-Free Use

```powershell
node .\bin\openclaw-exposure-guard.js C:\path\to\check
```

JSON output:

```powershell
node .\bin\openclaw-exposure-guard.js --json C:\path\to\check
```

## What It Checks

- Local `openclaw` package manifests and dependency specs.
- Known vulnerable OpenClaw versions from public advisories.
- OpenClaw skill or hook metadata files.
- Plugin/hook install-surface risks such as `.npmrc` `git=` overrides.
- Config patterns that appear to bind services publicly or disable auth.
- TCP listeners bound to all interfaces.
- Credential-adjacent file names, reported by path only.

## What It Does Not Do

This guard does not prove a host is clean. It only identifies the risks it knows
how to check locally.

It does not scan the internet, probe remote systems, exploit OpenClaw, revoke
tokens, remove files, or make cleanup decisions.

## Response Guidance

If this guard reports a high-risk OpenClaw finding:

1. Stop exposing the gateway/agent service publicly.
2. Preserve config, logs, package manifests, and installed skill/hook metadata.
3. Upgrade OpenClaw from a trusted source.
4. Review installed skills and hooks before re-enabling them.
5. Rotate credentials from a separate trusted environment if exposure or secret
   access is plausible.

## Sources

See [docs/sources.md](docs/sources.md).
