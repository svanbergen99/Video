# Security baseline

This repository uses a deny-by-default internal media-service baseline.

- No secrets, credentials, tokens, private keys, database dumps, logs, archives or source maps belong in Git.
- No public frontend or static repository files are served.
- `GET`/`HEAD /healthz` is the only unauthenticated route. Every `/v1/*` route requires the internal service token.
- Large media uploads use short-lived presigned object-store URLs instead of accepting arbitrary multipart bodies through the API.
- Request targets are length-limited and reject encoded control characters, backslashes and traversal sequences.
- JSON request bodies are size-limited and ambiguous Content-Length plus Transfer-Encoding framing is rejected.
- Header, request, and keep-alive timeouts plus header/request-per-socket limits reduce application-layer connection exhaustion risk.
- FFmpeg and FFprobe run with fixed argument templates; user input is never passed through a shell.
- Object keys and video IDs are validated before storage access. Storage credentials are read only from runtime environment variables.
- CI runs static secret/dangerous-code checks plus live hostile-path, method, header, smuggling, Slowloris and recovery probes.

No application control is a guarantee against volumetric network DDoS; platform or edge protection is still required upstream.

## LCW repository standard — 2026-09-11

This repository is governed by the owner-approved LCW security standard.

- The human owner is the final authority.
- LCW is the independent guardian and emergency-control layer.
- Default deny applies to security-sensitive and privileged actions.
- Destructive, billing, permission, secret, authority-changing, or security-weakening actions require explicit owner approval.
- Operational agents may not grant themselves additional authority, bypass LCW, disable auditing, or modify the controls that constrain them.
- LCW enforcement credentials and control paths must remain outside operational-agent write authority.
- Security failures and unverifiable security state fail closed.
- Secrets must never be committed, logged, returned to clients, or included in model context.
- Because this repository is public, only explicitly public material may be committed; private media and production credentials remain prohibited.
- Production and security-sensitive changes require a reviewable pull request plus validated checks.
- Documentation is policy, not enforcement; controls must be implemented at repository, credential, deployment, network, storage, and tool layers where applicable.

### GitHub assurance boundary

For repositories operated under GitHub Free, the required target is to use all security controls technically available to the current account. Any `100%` assurance statement is explicitly scoped to that available-control set and is not an absolute-security claim.

Provider-level protections that are unavailable under the current plan are not considered active merely because they are documented. Until stronger provider-enforced controls are available and independently tested, the human owner remains the compensating control by personally reviewing and merging security-sensitive pull requests after successful CI.

If required CI or equivalent validation is absent or failing, the repository is below the LCW standard for security-sensitive deployment and must fail closed.
