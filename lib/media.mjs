import { spawn } from "node:child_process";

const MAX_TOOL_OUTPUT = 2 * 1024 * 1024;
const MAX_SELFTEST_VIDEO_BYTES = 8 * 1024 * 1024;

function runTool(command, args, timeoutMs) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ["ignore", "pipe", "pipe"] });
    const stdout = [];
    const stderr = [];
    let bytes = 0;
    let settled = false;
    const timer = setTimeout(() => {
      if (!settled) child.kill("SIGKILL");
    }, timeoutMs);

    function append(target, chunk) {
      bytes += chunk.length;
      if (bytes > MAX_TOOL_OUTPUT) {
        child.kill("SIGKILL");
        return;
      }
      target.push(chunk);
    }

    child.stdout.on("data", (chunk) => append(stdout, chunk));
    child.stderr.on("data", (chunk) => append(stderr, chunk));
    child.once("error", (error) => {
      settled = true;
      clearTimeout(timer);
      reject(error);
    });
    child.once("close", (code, signal) => {
      settled = true;
      clearTimeout(timer);
      const output = Buffer.concat(stdout).toString("utf8");
      const errors = Buffer.concat(stderr).toString("utf8");
      if (bytes > MAX_TOOL_OUTPUT) return reject(new Error(`${command} output limit exceeded`));
      if (signal === "SIGKILL") return reject(new Error(`${command} timed out`));
      if (code !== 0) return reject(new Error(`${command} failed (${code}): ${errors.slice(-1200)}`));
      resolve({ stdout: output, stderr: errors });
    });
  });
}

function runToolBuffer(command, args, timeoutMs, maxBytes = MAX_SELFTEST_VIDEO_BYTES) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ["ignore", "pipe", "pipe"] });
    const stdout = [];
    const stderr = [];
    let outputBytes = 0;
    let settled = false;
    const timer = setTimeout(() => {
      if (!settled) child.kill("SIGKILL");
    }, timeoutMs);

    child.stdout.on("data", (chunk) => {
      outputBytes += chunk.length;
      if (outputBytes > maxBytes) child.kill("SIGKILL");
      else stdout.push(chunk);
    });
    child.stderr.on("data", (chunk) => {
      if (Buffer.concat(stderr).length < MAX_TOOL_OUTPUT) stderr.push(chunk);
    });
    child.once("error", (error) => {
      settled = true;
      clearTimeout(timer);
      reject(error);
    });
    child.once("close", (code, signal) => {
      settled = true;
      clearTimeout(timer);
      if (outputBytes > maxBytes) return reject(new Error(`${command} binary output limit exceeded`));
      if (signal === "SIGKILL") return reject(new Error(`${command} timed out`));
      const errors = Buffer.concat(stderr).toString("utf8");
      if (code !== 0) return reject(new Error(`${command} failed (${code}): ${errors.slice(-1200)}`));
      resolve(Buffer.concat(stdout));
    });
  });
}

function fraction(value) {
  if (!value || value === "0/0") return 0;
  const [a, b] = String(value).split("/").map(Number);
  if (Number.isFinite(a) && Number.isFinite(b) && b !== 0) return a / b;
  const direct = Number(value);
  return Number.isFinite(direct) ? direct : 0;
}

function parseDetections(stderr) {
  const black = [];
  const freezes = [];
  const silences = [];
  for (const line of stderr.split(/\r?\n/)) {
    const blackMatch = line.match(/black_start:([\d.]+)\s+black_end:([\d.]+)\s+black_duration:([\d.]+)/);
    if (blackMatch) black.push({ start: Number(blackMatch[1]), end: Number(blackMatch[2]), duration: Number(blackMatch[3]) });
    const freezeStart = line.match(/freeze_start:\s*([\d.]+)/);
    if (freezeStart) freezes.push({ start: Number(freezeStart[1]) });
    const freezeDuration = line.match(/freeze_duration:\s*([\d.]+)/);
    if (freezeDuration && freezes.length) freezes.at(-1).duration = Number(freezeDuration[1]);
    const silenceStart = line.match(/silence_start:\s*([\d.]+)/);
    if (silenceStart) silences.push({ start: Number(silenceStart[1]) });
    const silenceEnd = line.match(/silence_end:\s*([\d.]+)\s*\|\s*silence_duration:\s*([\d.]+)/);
    if (silenceEnd && silences.length) {
      silences.at(-1).end = Number(silenceEnd[1]);
      silences.at(-1).duration = Number(silenceEnd[2]);
    }
  }
  return { blackFrames: black, freezes, silences };
}

export async function probeMedia(url) {
  const { stdout } = await runTool("ffprobe", [
    "-v", "error",
    "-show_streams",
    "-show_format",
    "-of", "json",
    url
  ], 60_000);
  const raw = JSON.parse(stdout);
  const video = raw.streams?.find((stream) => stream.codec_type === "video") ?? null;
  const audio = raw.streams?.find((stream) => stream.codec_type === "audio") ?? null;
  const duration = Number(raw.format?.duration || video?.duration || 0);
  const fps = fraction(video?.avg_frame_rate || video?.r_frame_rate);
  const width = Number(video?.width || 0);
  const height = Number(video?.height || 0);
  return {
    durationSeconds: Number.isFinite(duration) ? duration : 0,
    sizeBytes: Number(raw.format?.size || 0) || 0,
    bitRate: Number(raw.format?.bit_rate || 0) || 0,
    formatName: raw.format?.format_name || null,
    video: video ? {
      codec: video.codec_name || null,
      width,
      height,
      orientation: height > width ? "portrait" : width > height ? "landscape" : "square",
      longSide: Math.max(width, height),
      shortSide: Math.min(width, height),
      fps: Number(fps.toFixed(3)),
      pixelFormat: video.pix_fmt || null,
      colorSpace: video.color_space || null,
      colorTransfer: video.color_transfer || null,
      colorPrimaries: video.color_primaries || null,
      hdr: ["smpte2084", "arib-std-b67"].includes(video.color_transfer || "")
    } : null,
    audio: audio ? {
      codec: audio.codec_name || null,
      channels: Number(audio.channels || 0),
      sampleRate: Number(audio.sample_rate || 0)
    } : null
  };
}

export async function deepQc(url, durationSeconds = 0) {
  const maxSeconds = Math.max(1, Math.min(Number(durationSeconds) || 120, 300));
  const args = [
    "-hide_banner", "-nostdin", "-v", "info",
    "-t", String(maxSeconds),
    "-i", url,
    "-vf", "blackdetect=d=0.5:pix_th=0.10,freezedetect=n=-60dB:d=2",
    "-af", "silencedetect=n=-50dB:d=2",
    "-f", "null", "-"
  ];
  const { stderr } = await runTool("ffmpeg", args, 300_000);
  return { scannedSeconds: maxSeconds, ...parseDetections(stderr) };
}

export function technicalQc(metadata, deep = null, env = process.env) {
  const minimumLongSide = Math.max(1, Number(env.MIN_VIDEO_LONG_SIDE || 1280));
  const minimumShortSide = Math.max(1, Number(env.MIN_VIDEO_SHORT_SIDE || 720));
  const minimumFps = Math.max(1, Number(env.MIN_VIDEO_FPS || 24));
  const errors = [];
  const warnings = [];
  if (!metadata.video) errors.push("no_video_stream");
  if (metadata.durationSeconds <= 0) errors.push("invalid_duration");
  if (metadata.video && metadata.video.longSide < minimumLongSide) errors.push("long_side_below_minimum");
  if (metadata.video && metadata.video.shortSide < minimumShortSide) errors.push("short_side_below_minimum");
  if (metadata.video && metadata.video.fps < minimumFps) errors.push("fps_below_minimum");
  if (!metadata.audio) warnings.push("no_audio_stream");
  if (deep?.blackFrames?.some((item) => item.duration >= 2)) warnings.push("long_black_segment");
  if (deep?.freezes?.some((item) => (item.duration || 0) >= 3)) warnings.push("long_freeze_segment");
  return {
    approved: errors.length === 0,
    requirements: { minimumLongSide, minimumShortSide, minimumFps },
    errors,
    warnings
  };
}

export async function generateSelfTestVideo() {
  return runToolBuffer("ffmpeg", [
    "-hide_banner", "-nostdin", "-loglevel", "error",
    "-f", "lavfi", "-i", "testsrc2=size=1280x720:rate=24:duration=1",
    "-f", "lavfi", "-i", "sine=frequency=1000:sample_rate=48000:duration=1",
    "-shortest",
    "-c:v", "libx264", "-preset", "ultrafast", "-crf", "35", "-pix_fmt", "yuv420p",
    "-c:a", "aac", "-b:a", "64k",
    "-movflags", "frag_keyframe+empty_moov",
    "-f", "mp4", "pipe:1"
  ], 60_000);
}

export async function mediaToolStatus() {
  const result = {};
  for (const tool of ["ffmpeg", "ffprobe"]) {
    try {
      const { stdout } = await runTool(tool, ["-version"], 5_000);
      result[tool] = { available: true, version: stdout.split(/\r?\n/, 1)[0].slice(0, 160) };
    } catch {
      result[tool] = { available: false, version: null };
    }
  }
  return result;
}
