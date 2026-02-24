# v2 Tools

Tooling policy for this rewrite:
- Product control paths must be implemented as Go binaries.
- Use `cmd/installer` for host bootstrap/service install logic.
- Keep workflow glue minimal in GitHub Actions.
- Do not add ad-hoc Python/Bash control scripts for core runtime behavior.
