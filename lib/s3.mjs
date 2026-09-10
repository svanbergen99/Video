import { createHash, createHmac } from "node:crypto";

const SERVICE = "s3";
const MAX_EXPIRY_SECONDS = 3600;

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function hmac(key, value) {
  return createHmac("sha256", key).update(value).digest();
}

function encodePath(path) {
  return path
    .split("/")
    .map((part) => encodeURIComponent(part).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`))
    .join("/");
}

function amzTimestamp(now = new Date()) {
  return now.toISOString().replace(/[:-]|\.\d{3}/g, "");
}

function dateStamp(amzDate) {
  return amzDate.slice(0, 8);
}

function sortedQuery(params) {
  return [...params.entries()]
    .sort(([aKey, aValue], [bKey, bValue]) => aKey.localeCompare(bKey) || aValue.localeCompare(bValue))
    .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`)
    .join("&");
}

function signingKey(secret, date, region) {
  const kDate = hmac(Buffer.from(`AWS4${secret}`, "utf8"), date);
  const kRegion = hmac(kDate, region);
  const kService = hmac(kRegion, SERVICE);
  return hmac(kService, "aws4_request");
}

function endpointFor(config, key) {
  const endpoint = new URL(config.endpoint);
  const encodedKey = encodePath(key.replace(/^\/+/, ""));
  const style = config.urlStyle === "path" ? "path" : "virtual";
  if (style === "path") {
    endpoint.pathname = `/${encodeURIComponent(config.bucket)}/${encodedKey}`;
  } else {
    endpoint.hostname = `${config.bucket}.${endpoint.hostname}`;
    endpoint.pathname = `/${encodedKey}`;
  }
  return endpoint;
}

export function storageConfig(prefix, env = process.env) {
  const get = (name) => String(env[`${prefix}_${name}`] ?? "").trim();
  const config = {
    bucket: get("BUCKET"),
    accessKeyId: get("ACCESS_KEY_ID"),
    secretAccessKey: get("SECRET_ACCESS_KEY"),
    endpoint: get("ENDPOINT"),
    region: get("REGION") || "auto",
    urlStyle: (get("URL_STYLE") || "virtual").toLowerCase()
  };
  const configured = Boolean(config.bucket && config.accessKeyId && config.secretAccessKey && config.endpoint);
  if (configured && !/^https:\/\//i.test(config.endpoint)) throw new Error(`${prefix}_ENDPOINT must use https`);
  if (!new Set(["virtual", "path"]).has(config.urlStyle)) throw new Error(`${prefix}_URL_STYLE must be virtual or path`);
  return { ...config, configured };
}

export function presignObject(config, { method = "GET", key, expiresSeconds = 900, now = new Date() } = {}) {
  if (!config?.configured) throw new Error("Storage is not configured");
  if (!key || typeof key !== "string") throw new Error("Object key is required");
  const expires = Math.min(Math.max(Number(expiresSeconds) || 900, 1), MAX_EXPIRY_SECONDS);
  const url = endpointFor(config, key);
  const amzDate = amzTimestamp(now);
  const shortDate = dateStamp(amzDate);
  const scope = `${shortDate}/${config.region}/${SERVICE}/aws4_request`;
  const params = new URLSearchParams(url.search);
  params.set("X-Amz-Algorithm", "AWS4-HMAC-SHA256");
  params.set("X-Amz-Credential", `${config.accessKeyId}/${scope}`);
  params.set("X-Amz-Date", amzDate);
  params.set("X-Amz-Expires", String(expires));
  params.set("X-Amz-SignedHeaders", "host");

  const canonicalQuery = sortedQuery(params);
  const canonicalRequest = [method.toUpperCase(), url.pathname, canonicalQuery, `host:${url.host}\n`, "host", "UNSIGNED-PAYLOAD"].join("\n");
  const stringToSign = ["AWS4-HMAC-SHA256", amzDate, scope, sha256(canonicalRequest)].join("\n");
  const signature = createHmac("sha256", signingKey(config.secretAccessKey, shortDate, config.region)).update(stringToSign).digest("hex");
  params.set("X-Amz-Signature", signature);
  url.search = sortedQuery(params);
  return url.toString();
}

export async function headObject(config, key) {
  const response = await fetch(presignObject(config, { method: "HEAD", key, expiresSeconds: 300 }), {
    method: "HEAD",
    redirect: "error",
    signal: AbortSignal.timeout(15_000)
  });
  if (!response.ok) throw new Error(`Object not available (${response.status})`);
  return {
    contentLength: Number(response.headers.get("content-length") || 0),
    contentType: response.headers.get("content-type") || "application/octet-stream",
    etag: response.headers.get("etag") || null
  };
}

export async function putObject(config, key, body, contentType = "application/octet-stream", timeoutMs = 120_000) {
  const response = await fetch(presignObject(config, { method: "PUT", key, expiresSeconds: 900 }), {
    method: "PUT",
    headers: { "content-type": contentType },
    body,
    redirect: "error",
    signal: AbortSignal.timeout(timeoutMs)
  });
  if (!response.ok) throw new Error(`Object upload failed (${response.status})`);
  return { key, etag: response.headers.get("etag") || null };
}

export async function putJson(config, key, value) {
  return putObject(config, key, JSON.stringify(value, null, 2), "application/json; charset=utf-8", 20_000);
}

export async function streamCopy(sourceConfig, sourceKey, targetConfig, targetKey, timeoutMs = 900_000) {
  const source = await fetch(presignObject(sourceConfig, { method: "GET", key: sourceKey, expiresSeconds: 1800 }), {
    method: "GET",
    redirect: "error",
    signal: AbortSignal.timeout(timeoutMs)
  });
  if (!source.ok || !source.body) throw new Error(`Source download failed (${source.status})`);
  const headers = {};
  const length = source.headers.get("content-length");
  const type = source.headers.get("content-type");
  if (length) headers["content-length"] = length;
  if (type) headers["content-type"] = type;

  const target = await fetch(presignObject(targetConfig, { method: "PUT", key: targetKey, expiresSeconds: 1800 }), {
    method: "PUT",
    headers,
    body: source.body,
    duplex: "half",
    redirect: "error",
    signal: AbortSignal.timeout(timeoutMs)
  });
  if (!target.ok) throw new Error(`Target upload failed (${target.status})`);
  return { key: targetKey, etag: target.headers.get("etag") || null };
}
