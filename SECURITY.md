# Security baseline

This repository uses a fail-closed security baseline.

- Never commit secrets, credentials, tokens, cookies, API keys, private keys, raw personal data, operational exports, database dumps, logs, or backups.
- Runtime secrets belong only in the deployment platform's secret/environment-variable store.
- Keep permissions least-privilege and repository-scoped.
- New network surfaces, external calls, parsers, file access, shell execution, or dynamic code execution require an explicit security review before release.
- The repository security audit must remain green on every push and pull request.
- Do not weaken or bypass the audit to make a build pass; update the baseline deliberately when the architecture changes.

This is the portable repository-level layer. Runtime HTTP hardening, deployment integrity manifests, health checks, ingress controls, and service-specific stress tests must be added when this repository gets an actual running service.
