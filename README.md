# KCD Video / Visual Engine

Internal video pipeline for KCD. The active architecture uses Railway Storage Buckets as the durable hand-off points and deliberately does not require Redis or Postgres.

## Pipeline

```text
Engine1 -> Storage1 -> Beheer -> Storage2 -> Collega -> Storage3 -> ReCheck -> Engine1
```

- Storage1 contains Engine1 output, retry inputs and approved final video.
- Storage2 contains Beheer output.
- Storage3 contains Collega output and is the source for ReCheck.
- ReCheck performs technical validation. An approved item is copied to `final/` in Storage1. A retry is copied to `retry/` in Storage1 so Engine1 can improve it and start a new version.
- Every stage writes a JSON manifest next to the durable object-store workflow.

## Free processing stack

The service uses FFmpeg and FFprobe installed in the container. No paid media API is required. Uploads use short-lived S3-compatible presigned URLs so large videos do not need to pass through the API service during normal ingest.

## Required Railway variables

Set an `INTERNAL_API_TOKEN` on the Video service. Connect three Railway Storage Buckets and map their credentials to these names:

```text
STORAGE1_BUCKET
STORAGE1_ACCESS_KEY_ID
STORAGE1_SECRET_ACCESS_KEY
STORAGE1_ENDPOINT
STORAGE1_REGION
STORAGE1_URL_STYLE

STORAGE2_BUCKET
STORAGE2_ACCESS_KEY_ID
STORAGE2_SECRET_ACCESS_KEY
STORAGE2_ENDPOINT
STORAGE2_REGION
STORAGE2_URL_STYLE

STORAGE3_BUCKET
STORAGE3_ACCESS_KEY_ID
STORAGE3_SECRET_ACCESS_KEY
STORAGE3_ENDPOINT
STORAGE3_REGION
STORAGE3_URL_STYLE
```

`*_URL_STYLE` is optional and defaults to `virtual`. Railway buckets created with legacy path-style addressing can set it to `path`.

Optional quality thresholds:

```text
MIN_VIDEO_WIDTH=1280
MIN_VIDEO_HEIGHT=720
MIN_VIDEO_FPS=24
```

## API

All `/v1/*` endpoints require either `Authorization: Bearer <internal token>` or `x-kcd-internal-token`.

- `GET /healthz` - public liveness probe, 204.
- `GET /v1/capabilities` - storage/tool readiness without exposing credentials.
- `POST /v1/videos/create-upload` - creates a Storage1 presigned upload URL.
- `POST /v1/videos/confirm-stage` - verifies an uploaded stage object, probes it with FFprobe and stores a manifest.
- `POST /v1/videos/handoff` - creates a read URL for the current stage and an upload URL for the next stage.
- `POST /v1/videos/recheck` - technical QC of Storage3 and copy to Storage1 `final/` or `retry/`.

### Example: create an upload

```json
{
  "filename": "clip.mp4",
  "version": 1
}
```

After the client uploads to `upload_url`, confirm it with the returned `video_id`, `key` and version. Beheer and Collega follow the same pattern using the handoff endpoint.

## Security

The service remains deny-by-default. It does not expose a frontend or repository files, large uploads use presigned bucket URLs, API routes require a constant-time token check, JSON bodies are capped, hostile paths are rejected, and CI runs static and runtime hardening tests.
