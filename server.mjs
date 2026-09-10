import { createServer } from "node:http";
import { timingSafeEqual } from "node:crypto";
import { capabilities, confirmStage, createUpload, handoff, recheck, storageReadiness } from "./lib/pipeline.mjs";
import { mediaToolStatus } from "./lib/media.mjs";

const PORT = Number.parseInt(process.env.PORT ?? "3000", 10);
if (!Number.isInteger(PORT) || PORT < 1 || PORT > 65535) throw new Error("Invalid PORT");

const CONTROL_CHARS = /[\u0000-\u001F\u007F]/;
const MAX_JSON_BYTES = 64 * 1024;
const SECURITY_HEADERS = Object.freeze({
  "Content-Security-Policy": "default-src 'none'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'none'",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
  "Referrer-Policy": "no-referrer",
  "Strict-Transport-Security": "max-age=31536000",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "X-Robots-Tag": "noindex, nofollow, noarchive",
  "Cache-Control": "no-store, max-age=0"
});

function applySecurityHeaders(response) {
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) response.setHeader(name, value);
}

function sendJson(response, statusCode, value, method = "GET") {
  const body = Buffer.from(JSON.stringify(value), "utf8");
  response.statusCode = statusCode;
  response.setHeader("Content-Type", "application/json; charset=utf-8");
  response.setHeader("Content-Length", String(body.byteLength));
  response.end(method === "HEAD" ? undefined : body);
}

function sendText(response, statusCode, text, method = "GET") {
  const body = Buffer.from(text, "utf8");
  response.statusCode = statusCode;
  response.setHeader("Content-Type", "text/plain; charset=utf-8");
  response.setHeader("Content-Length", String(body.byteLength));
  response.end(method === "HEAD" ? undefined : body);
}

function parsePath(requestTarget) {
  if (requestTarget.length > 2048) return { error: 414 };
  const queryIndex = requestTarget.indexOf("?");
  const rawPath = queryIndex === -1 ? requestTarget : requestTarget.slice(0, queryIndex);
  if (!rawPath.startsWith("/") || rawPath.includes("\\")) return { error: 400 };
  let pathname;
  try { pathname = decodeURIComponent(rawPath); } catch { return { error: 400 }; }
  if (!pathname.startsWith("/") || pathname.includes("\\") || CONTROL_CHARS.test(pathname) || pathname.includes("..")) return { error: 400 };
  return { pathname };
}

function hasRequestBodyHeaders(request) {
  const transferEncoding = request.headers["transfer-encoding"];
  const contentLength = request.headers["content-length"];
  if (transferEncoding !== undefined) return true;
  if (contentLength === undefined) return false;
  return contentLength !== "0";
}

function equalToken(a, b) {
  const left = Buffer.from(String(a || ""));
  const right = Buffer.from(String(b || ""));
  return left.length === right.length && left.length > 0 && timingSafeEqual(left, right);
}

function requireInternal(request, response) {
  const expected = String(process.env.INTERNAL_API_TOKEN || "");
  if (!expected) {
    sendJson(response, 503, { error: "service_not_configured" }, request.method);
    return false;
  }
  const authorization = String(request.headers.authorization || "");
  const bearer = authorization.startsWith("Bearer ") ? authorization.slice(7) : "";
  const alternate = String(request.headers["x-kcd-internal-token"] || "");
  if (!equalToken(bearer, expected) && !equalToken(alternate, expected)) {
    sendJson(response, 401, { error: "unauthorized" }, request.method);
    return false;
  }
  return true;
}

async function readJsonBody(request) {
  if (request.headers["transfer-encoding"] !== undefined && request.headers["content-length"] !== undefined) {
    const error = new Error("Ambiguous body framing");
    error.statusCode = 400;
    throw error;
  }
  const contentType = String(request.headers["content-type"] || "").split(";", 1)[0].trim().toLowerCase();
  if (contentType !== "application/json") {
    const error = new Error("Content-Type must be application/json");
    error.statusCode = 415;
    throw error;
  }
  const declared = Number(request.headers["content-length"] || 0);
  if (declared > MAX_JSON_BYTES) {
    const error = new Error("Request body too large");
    error.statusCode = 413;
    throw error;
  }
  const chunks = [];
  let total = 0;
  for await (const chunk of request) {
    total += chunk.length;
    if (total > MAX_JSON_BYTES) {
      const error = new Error("Request body too large");
      error.statusCode = 413;
      throw error;
    }
    chunks.push(chunk);
  }
  if (total === 0) return {};
  try { return JSON.parse(Buffer.concat(chunks).toString("utf8")); }
  catch {
    const error = new Error("Invalid JSON");
    error.statusCode = 400;
    throw error;
  }
}

async function route(request, response, pathname) {
  const method = request.method ?? "";
  if (pathname === "/healthz" && (method === "GET" || method === "HEAD")) {
    if (hasRequestBodyHeaders(request)) return sendText(response, 400, "Bad request\n", method);
    response.statusCode = 204;
    response.end();
    return;
  }

  const allowed = new Map([
    ["/v1/capabilities", "GET"],
    ["/v1/readiness", "GET"],
    ["/v1/videos/create-upload", "POST"],
    ["/v1/videos/confirm-stage", "POST"],
    ["/v1/videos/handoff", "POST"],
    ["/v1/videos/recheck", "POST"]
  ]);
  const expectedMethod = allowed.get(pathname);
  if (!expectedMethod) return sendText(response, 404, "Not found\n", method);
  if (method !== expectedMethod) {
    response.setHeader("Allow", expectedMethod);
    return sendText(response, 405, "Method not allowed\n", method);
  }
  if (!requireInternal(request, response)) return;

  if (method === "GET") {
    if (hasRequestBodyHeaders(request)) return sendText(response, 400, "Bad request\n", method);
    const tools = await mediaToolStatus();
    if (pathname === "/v1/readiness") {
      const storage = await storageReadiness();
      const ready = Object.values(storage).every((item) => item.configured && item.reachable)
        && Object.values(tools).every((item) => item.available);
      return sendJson(response, ready ? 200 : 503, { service: "Video", ready, tools, storage }, method);
    }
    return sendJson(response, 200, { service: "Video", version: "2.1.0", ...capabilities(), tools }, method);
  }

  const body = await readJsonBody(request);
  if (pathname === "/v1/videos/create-upload") return sendJson(response, 201, await createUpload(body), method);
  if (pathname === "/v1/videos/confirm-stage") return sendJson(response, 200, await confirmStage(body), method);
  if (pathname === "/v1/videos/handoff") return sendJson(response, 200, handoff(body), method);
  if (pathname === "/v1/videos/recheck") return sendJson(response, 200, await recheck(body), method);
}

export function createAppServer() {
  const server = createServer({
    maxHeaderSize: 8192,
    requestTimeout: 5000,
    headersTimeout: 4000,
    connectionsCheckingInterval: 1000,
    keepAliveTimeout: 5000
  }, (request, response) => {
    applySecurityHeaders(response);
    const parsed = parsePath(request.url ?? "/");
    if (parsed.error) return sendText(response, parsed.error, parsed.error === 414 ? "URI too long\n" : "Bad request\n", request.method);
    Promise.resolve(route(request, response, parsed.pathname)).catch((error) => {
      if (response.headersSent) return response.destroy();
      const status = Number.isInteger(error?.statusCode) ? error.statusCode : 400;
      const safeStatus = status >= 400 && status <= 599 ? status : 500;
      const message = safeStatus >= 500 ? "internal_error" : String(error?.message || "bad_request").slice(0, 300);
      sendJson(response, safeStatus, { error: message }, request.method);
    });
  });

  server.maxHeadersCount = 64;
  server.maxRequestsPerSocket = 100;
  server.on("connection", (socket) => {
    socket.setTimeout(5000, () => socket.destroy());
  });
  server.on("clientError", (_error, socket) => {
    if (socket.writable) socket.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
  });
  return server;
}

async function logStartupReadiness() {
  const tools = await mediaToolStatus();
  const storage = await storageReadiness();
  const ready = Object.values(storage).every((item) => item.configured && item.reachable)
    && Object.values(tools).every((item) => item.available);
  console.log(JSON.stringify({ event: "video_engine_readiness", ready, tools, storage }));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const server = createAppServer();
  server.listen(PORT, "0.0.0.0", () => {
    console.log(JSON.stringify({ event: "video_engine_started", port: PORT }));
    logStartupReadiness().catch((error) => {
      console.warn(JSON.stringify({ event: "video_engine_readiness_error", error: String(error?.message || "unknown").slice(0, 180) }));
    });
  });
}
