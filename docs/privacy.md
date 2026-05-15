# Privacy

OpenClaw Exposure Guard is a local, read-only checker.

It does not save, collect, upload, transmit, sell, or share user data. It has no
telemetry and does not contact a server while scanning.

The tool may read:

- local package manifests,
- OpenClaw-related config files,
- OpenClaw skill/hook metadata file names,
- selected local config text needed for exposure checks,
- local TCP listener metadata.

The tool does not print secret values. Credential-adjacent files are reported by
path only so operators can review them privately.

Scan output is printed to the terminal. The tool does not write scan reports to
disk unless the operator redirects output or saves it with another command.
