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
