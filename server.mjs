import { createServer } from "node:http";

const PORT = Number.parseInt(process.env.PORT ?? "3000", 10);
if (!Number.isInteger(PORT) || PORT < 1 || PORT > 65535) {
  throw new Error("Invalid PORT");
}

const CONTROL_CHARS = /[\u0000-\u001F\u007F]/;
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
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
    response.setHeader(name, value);
  }
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
  try {
    pathname = decodeURIComponent(rawPath);
  } catch {
    return { error: 400 };
  }

  if (!pathname.startsWith("/") || pathname.includes("\\") || CONTROL_CHARS.test(pathname) || pathname.includes("..")) {
    return { error: 400 };
  }

  return { pathname };
}

function hasRequestBodyHeaders(request) {
  const transferEncoding = request.headers["transfer-encoding"];
  const contentLength = request.headers["content-length"];
  if (transferEncoding !== undefined) return true;
  if (contentLength === undefined) return false;
  return contentLength !== "0";
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

    const method = request.method ?? "";
    if (method !== "GET" && method !== "HEAD") {
      response.setHeader("Allow", "GET, HEAD");
      sendText(response, 405, "Method not allowed\n", method);
      return;
    }

    if (hasRequestBodyHeaders(request)) {
      sendText(response, 400, "Bad request\n", method);
      return;
    }

    const parsed = parsePath(request.url ?? "/");
    if (parsed.error) {
      sendText(response, parsed.error, parsed.error === 414 ? "URI too long\n" : "Bad request\n", method);
      return;
    }

    if (parsed.pathname === "/healthz") {
      response.statusCode = 204;
      response.end();
      return;
    }

    sendText(response, 404, "Not found\n", method);
  });

  server.maxHeadersCount = 64;
  server.maxRequestsPerSocket = 100;

  server.on("clientError", (_error, socket) => {
    if (!socket.writable) return;
    socket.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
  });

  return server;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const server = createAppServer();
  server.listen(PORT, "0.0.0.0");
}
