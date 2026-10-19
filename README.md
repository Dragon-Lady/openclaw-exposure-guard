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

Both regular file and directory targets are supported. Missing or unsupported
targets, unknown flags, and extra targets fail explicitly.

Exit codes: 0 means no medium/high/critical findings in a completed target scan,
1 means findings requiring review, and 2 means usage/runtime error or incomplete
target coverage (takes precedence over 1). This intentionally replaces the
earlier always-zero status for findings.

`coverage.complete` covers selected target files and traversed directories.
Unreadable inputs, malformed manifests, or candidates over the 1 MiB text limit
make it false; `coverage.errors` lists paths and reasons without file contents.
Excluded directory classes and unselected file types are outside that scope.
The optional host listener probe is separate: `coverage.listenerInspection`
reports `complete` or `unavailable`; an unavailable probe is not proof that no
listeners exist. It does not change target-file coverage or the exit status.

- Local `openclaw` package manifests and dependency specs.
- Known vulnerable OpenClaw versions from public advisories.
- OpenClaw skill or hook metadata files.
- Plugin/hook install-surface risks such as `.npmrc` `git=` overrides.
- Config patterns that appear to bind services publicly or disable auth.
- Email-agent policy patterns that combine inbox access, outbound-send
  capability, and sensitive-data access without clear identity, first-time
  external recipient, and human-approval gates.
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

## Unreleased advisory reconciliation

Six additional upstream advisories now retain their published affected ranges,
severity and feature conditions in `data/advisories.json`. Exact stable versions
are compared with those ranges; unresolved ranges and prereleases produce a
high-priority version-review finding, without asserting a vulnerable installation.
An npm `=X.Y.Z` pin is treated as exact; ranges are not guessed or truncated. The retry-endpoint advisory has no package specified
upstream, so it remains a product review lead. A gap between an affected range
and a stated patched release is not silently broadened into a new affected range.

This bounded catalog update is not a complete reconciliation of all OpenClaw
advisories, and no version is certified universally safe. Inventory does not
establish configuration, reachability or exploitation. Each record links its
upstream source; the six records were verified on 2026-10-19.

Simple complete stable dependency ranges (`^`, `~`, `>=`, `>`) whose lower bound
is outside every cataloged affected range receive medium version-review priority.
Overlapping, malformed, prerelease and unsupported compound specs retain high
review priority until resolved; neither rating proves an installed vulnerability.
