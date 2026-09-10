import { randomUUID } from "node:crypto";
import { deepQc, generateSelfTestVideo, probeMedia, technicalQc } from "./media.mjs";
import { headObject, presignObject, putJson, putObject, storageConfig, streamCopy } from "./s3.mjs";

const ALLOWED_EXTENSIONS = new Set(["mp4", "mov", "mkv", "webm", "m4v", "avi"]);
const STAGE_NAMES = Object.freeze({ 1: "Engine1", 2: "Beheer", 3: "Collega" });

export function pipelineConfig(env = process.env) {
  return {
    1: storageConfig("STORAGE1", env),
    2: storageConfig("STORAGE2", env),
    3: storageConfig("STORAGE3", env)
  };
}

export function safeVideoId(value) {
  const text = String(value || "").trim();
  if (!/^[a-zA-Z0-9_-]{8,80}$/.test(text)) throw new Error("Invalid video_id");
  return text;
}

export function safeFilename(value) {
  const raw = String(value || "").trim();
  if (!raw || raw.length > 180 || raw.includes("/") || raw.includes("\\") || /[\u0000-\u001F\u007F]/.test(raw)) {
    throw new Error("Invalid filename");
  }
  const ext = raw.includes(".") ? raw.split(".").at(-1).toLowerCase() : "";
  if (!ALLOWED_EXTENSIONS.has(ext)) throw new Error("Unsupported video extension");
  return raw.replace(/[^a-zA-Z0-9._ -]/g, "_");
}

function stageNumber(value) {
  const stage = Number(value);
  if (![1, 2, 3].includes(stage)) throw new Error("stage must be 1, 2 or 3");
  return stage;
}

function assertStageKey(videoId, stage, key) {
  const clean = String(key || "");
  if (!clean.startsWith(`videos/${videoId}/stage${stage}/`) || clean.includes("..")) {
    throw new Error("Object key does not belong to requested video/stage");
  }
  return clean;
}

function versionNumber(value, fallback = 1) {
  const version = Number(value ?? fallback);
  if (!Number.isInteger(version) || version < 1 || version > 999999) throw new Error("Invalid version");
  return version;
}

function versionLabel(version) {
  return `v${String(version).padStart(4, "0")}`;
}

export function capabilities(env = process.env) {
  const storage = pipelineConfig(env);
  return {
    pipeline: "Engine1 -> Storage1 -> Beheer -> Storage2 -> Collega -> Storage3 -> ReCheck -> Engine1",
    redis: false,
    postgres: false,
    storage: {
      Storage1: storage[1].configured,
      Storage2: storage[2].configured,
      Storage3: storage[3].configured
    },
    limits: {
      maxJsonBytes: 64 * 1024,
      uploadViaPresignedUrl: true,
      uploadUrlExpirySeconds: 900
    }
  };
}

export async function storageReadiness(env = process.env) {
  const config = pipelineConfig(env);
  const checkedAt = new Date().toISOString();
  const result = {};
  for (const stage of [1, 2, 3]) {
    const name = `Storage${stage}`;
    const bucket = config[stage];
    if (!bucket.configured) {
      result[name] = { configured: false, reachable: false };
      continue;
    }
    try {
      const key = "_system/video-engine-health.json";
      await putJson(bucket, key, { service: "Video", storage: name, stage, checked_at: checkedAt });
      const head = await headObject(bucket, key);
      result[name] = { configured: true, reachable: true, contentType: head.contentType, contentLength: head.contentLength };
    } catch (error) {
      result[name] = { configured: true, reachable: false, error: String(error?.message || "storage_check_failed").slice(0, 180) };
    }
  }
  return result;
}

export async function createUpload(input, env = process.env) {
  const storage = pipelineConfig(env)[1];
  if (!storage.configured) throw new Error("Storage1 is not configured");
  const filename = safeFilename(input.filename);
  const videoId = input.video_id ? safeVideoId(input.video_id) : randomUUID();
  const version = versionNumber(input.version, 1);
  const key = `videos/${videoId}/stage1/${versionLabel(version)}/${filename}`;
  return {
    video_id: videoId,
    version,
    stage: 1,
    stage_name: STAGE_NAMES[1],
    key,
    upload_url: presignObject(storage, { method: "PUT", key, expiresSeconds: 900 }),
    expires_in_seconds: 900
  };
}

export async function confirmStage(input, env = process.env) {
  const stage = stageNumber(input.stage);
  const videoId = safeVideoId(input.video_id);
  const version = versionNumber(input.version);
  const key = assertStageKey(videoId, stage, input.key);
  const storage = pipelineConfig(env)[stage];
  if (!storage.configured) throw new Error(`Storage${stage} is not configured`);
  const object = await headObject(storage, key);
  const sourceUrl = presignObject(storage, { method: "GET", key, expiresSeconds: 900 });
  const metadata = await probeMedia(sourceUrl);
  const qc = technicalQc(metadata, null, env);
  const manifest = {
    schema_version: 1,
    video_id: videoId,
    version,
    stage,
    stage_name: STAGE_NAMES[stage],
    key,
    status: stage === 3 ? "ready_for_recheck" : "ready_for_next_stage",
    object,
    media: metadata,
    technical_qc: qc,
    actor: String(input.actor || STAGE_NAMES[stage]).slice(0, 80),
    feedback: String(input.feedback || "").slice(0, 4000),
    updated_at: new Date().toISOString()
  };
  const manifestKey = `manifests/${videoId}/${versionLabel(version)}-stage${stage}.json`;
  await putJson(storage, manifestKey, manifest);
  return { ...manifest, manifest_key: manifestKey };
}

export function handoff(input, env = process.env) {
  const fromStage = stageNumber(input.from_stage);
  if (fromStage === 3) throw new Error("Stage 3 hands off to ReCheck, not another production stage");
  const toStage = fromStage + 1;
  const videoId = safeVideoId(input.video_id);
  const sourceKey = assertStageKey(videoId, fromStage, input.source_key);
  const filename = safeFilename(input.output_filename || input.filename);
  const version = versionNumber(input.next_version, versionNumber(input.version, 1) + 1);
  const config = pipelineConfig(env);
  if (!config[fromStage].configured) throw new Error(`Storage${fromStage} is not configured`);
  if (!config[toStage].configured) throw new Error(`Storage${toStage} is not configured`);
  const targetKey = `videos/${videoId}/stage${toStage}/${versionLabel(version)}/${filename}`;
  return {
    video_id: videoId,
    from_stage: fromStage,
    to_stage: toStage,
    to_stage_name: STAGE_NAMES[toStage],
    source_key: sourceKey,
    target_key: targetKey,
    download_url: presignObject(config[fromStage], { method: "GET", key: sourceKey, expiresSeconds: 900 }),
    upload_url: presignObject(config[toStage], { method: "PUT", key: targetKey, expiresSeconds: 900 }),
    expires_in_seconds: 900
  };
}

export async function recheck(input, env = process.env) {
  const videoId = safeVideoId(input.video_id);
  const version = versionNumber(input.version);
  const key = assertStageKey(videoId, 3, input.key);
  const decision = String(input.decision || "").toLowerCase();
  if (!new Set(["approved", "retry"]).has(decision)) throw new Error("decision must be approved or retry");
  const config = pipelineConfig(env);
  if (!config[3].configured || !config[1].configured) throw new Error("Storage1 and Storage3 must be configured");
  await headObject(config[3], key);
  const sourceUrl = presignObject(config[3], { method: "GET", key, expiresSeconds: 900 });
  const metadata = await probeMedia(sourceUrl);
  const deep = input.deep_qc === true ? await deepQc(sourceUrl, metadata.durationSeconds) : null;
  const qc = technicalQc(metadata, deep, env);
  const effectiveDecision = decision === "approved" && qc.approved ? "approved" : "retry";
  const filename = safeFilename(input.output_filename || key.split("/").at(-1));
  const destinationKey = effectiveDecision === "approved"
    ? `videos/${videoId}/final/${versionLabel(version)}/${filename}`
    : `videos/${videoId}/retry/${versionLabel(version)}/${filename}`;
  const copied = await streamCopy(config[3], key, config[1], destinationKey);
  const report = {
    schema_version: 1,
    video_id: videoId,
    version,
    source_key: key,
    requested_decision: decision,
    decision: effectiveDecision,
    reason: String(input.reason || "").slice(0, 4000),
    media: metadata,
    deep_qc: deep,
    technical_qc: qc,
    destination: { storage: "Storage1", key: destinationKey, etag: copied.etag },
    next: effectiveDecision === "approved" ? "final" : "Engine1",
    rechecked_at: new Date().toISOString()
  };
  const reportKey = `manifests/${videoId}/${versionLabel(version)}-recheck.json`;
  await putJson(config[1], reportKey, report);
  return { ...report, manifest_key: reportKey };
}

export async function runPipelineSelfTest(env = process.env) {
  const selfEnv = {
    ...env,
    MIN_VIDEO_LONG_SIDE: "1280",
    MIN_VIDEO_SHORT_SIDE: "720",
    MIN_VIDEO_FPS: "24"
  };
  const config = pipelineConfig(selfEnv);
  if (![1, 2, 3].every((stage) => config[stage].configured)) throw new Error("All three storages are required for self-test");

  const videoId = `selftest-${Date.now()}`;
  const filename = "selftest.mp4";
  const video = await generateSelfTestVideo();

  const key1 = `videos/${videoId}/stage1/v0001/${filename}`;
  await putObject(config[1], key1, video, "video/mp4", 60_000);
  const stage1 = await confirmStage({ video_id: videoId, version: 1, stage: 1, key: key1, actor: "selftest" }, selfEnv);

  const h12 = handoff({ video_id: videoId, from_stage: 1, source_key: key1, filename, version: 1, next_version: 2 }, selfEnv);
  await streamCopy(config[1], key1, config[2], h12.target_key, 60_000);
  const stage2 = await confirmStage({ video_id: videoId, version: 2, stage: 2, key: h12.target_key, actor: "selftest" }, selfEnv);

  const h23 = handoff({ video_id: videoId, from_stage: 2, source_key: h12.target_key, filename, version: 2, next_version: 3 }, selfEnv);
  await streamCopy(config[2], h12.target_key, config[3], h23.target_key, 60_000);
  const stage3 = await confirmStage({ video_id: videoId, version: 3, stage: 3, key: h23.target_key, actor: "selftest" }, selfEnv);

  const final = await recheck({ video_id: videoId, version: 3, key: h23.target_key, decision: "approved", reason: "automated pipeline self-test" }, selfEnv);
  const passed = stage1.technical_qc.approved && stage2.technical_qc.approved && stage3.technical_qc.approved && final.decision === "approved";

  return {
    passed,
    video_id: videoId,
    generated_bytes: video.length,
    stage1: { key: stage1.key, approved: stage1.technical_qc.approved },
    stage2: { key: stage2.key, approved: stage2.technical_qc.approved },
    stage3: { key: stage3.key, approved: stage3.technical_qc.approved },
    final: { key: final.destination.key, decision: final.decision }
  };
}
