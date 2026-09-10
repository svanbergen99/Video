# Security baseline

This repository starts from a deny-by-default collector baseline.

- No secrets, credentials, tokens, private keys, database dumps, logs, archives or source maps belong in Git.
- No public frontend is exposed. The baseline HTTP service exposes only `GET`/`HEAD /healthz`; every other path is rejected.
- Request targets are length-limited and reject encoded control characters, backslashes and traversal sequences.
- Header/request/keep-alive timeouts and header/request-per-socket limits reduce application-layer connection exhaustion risk.
- CI runs static secret/dangerous-code checks plus live hostile-path, method, header, smuggling, Slowloris and recovery probes on every change.
- Future collector endpoints must be explicitly allowlisted and must not return credentials, internal infrastructure details or unapproved data.
- Production deployments should remain private by default and add an external deployment integrity gate before exposure.

No control here is a guarantee against volumetric network DDoS; that requires platform/edge protection upstream of the application.
