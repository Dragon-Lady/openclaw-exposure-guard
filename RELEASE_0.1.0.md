# v0.1.0

- Initial tagged release of the read-only exposure checker.
- Support explicit file targets and reject nonexistent or unsupported roots.
- Report malformed manifests, read failures, and inspection limits as incomplete coverage (exit 2).
- Report medium, high, and critical findings with exit 1.
- Track optional localhost listener-probe coverage separately.
- Add functional regressions and Node 18, 22, and 24 CI.

GitHub release only. npm publication remains pending. This checker reports known indicators and configuration risks, not a guarantee of safety.
