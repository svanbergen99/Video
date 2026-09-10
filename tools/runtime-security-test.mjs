import { request } from "node:http";
import { Socket } from "node:net";
import { createAppServer } from "../server.mjs";

const HOST = "127.0.0.1";
process.env.INTERNAL_API_TOKEN = "runtime-test-token-123456";

function httpRequest(port, path, { method = "GET", headers = {}, body = null } = {}) {
  return new Promise((resolve, reject) => {
    const finalHeaders = { ...headers };
    if (body !== null && finalHeaders["Content-Length"] === undefined) finalHeaders["Content-Length"] = String(Buffer.byteLength(body));
    const req = request({ host: HOST, port, path, method, headers: finalHeaders, agent: false }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks).toString("utf8") }));
    });
    req.setTimeout(5000, () => req.destroy(new Error("request timeout")));
    req.on("error", reject);
    if (body !== null) req.write(body);
    req.end();
  });
}

function rawRequest(port, payload, timeoutMs = 5000) {
  return new Promise((resolve) => {
    const socket = new Socket();
    let data = "";
    const timer = setTimeout(() => { socket.destroy(); resolve({ data, timedOut: true }); }, timeoutMs);
    socket.on("data", (chunk) => { data += chunk.toString("latin1"); });
    socket.on("error", () => {});
    socket.on("close", () => { clearTimeout(timer); resolve({ data, timedOut: false }); });
    socket.connect(port, HOST, () => socket.write(payload, "latin1"));
  });
}

function slowloris(port) {
  return new Promise((resolve) => {
    const socket = new Socket();
    let closed = false;
    const started = Date.now();
    const timer = setTimeout(() => { if (!closed) socket.destroy(); resolve({ closed, elapsed: Date.now() - started }); }, 8000);
    socket.on("data", () => {});
    socket.on("error", () => {});
    socket.on("close", () => { closed = true; clearTimeout(timer); resolve({ closed: true, elapsed: Date.now() - started }); });
    socket.connect(port, HOST, () => socket.write("GET /healthz HTTP/1.1\r\nHost: localhost\r\nX-Slow: ", "latin1"));
  });
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

const server = createAppServer();
await new Promise((resolve, reject) => { server.once("error", reject); server.listen(0, HOST, resolve); });
const address = server.address();
if (!address || typeof address === "string") throw new Error("Unable to resolve test port");
const port = address.port;

try {
  const health = await httpRequest(port, "/healthz");
  assert(health.status === 204, `healthz=${health.status}`);
  assert(!("set-cookie" in health.headers), "healthz must not set cookies");
  assert(!("access-control-allow-origin" in health.headers), "CORS must not be enabled by default");
  assert(health.headers["content-security-policy"]?.includes("default-src 'none'"), "missing restrictive CSP");
  assert(health.headers["x-content-type-options"] === "nosniff", "missing nosniff");

  const head = await httpRequest(port, "/healthz", { method: "HEAD" });
  assert(head.status === 204 && head.body === "", "HEAD /healthz failed");

  const unauthorized = await httpRequest(port, "/v1/capabilities");
  assert(unauthorized.status === 401, `unauthorized capabilities=${unauthorized.status}`);
  assert(!/runtime-test-token/.test(unauthorized.body), "auth failure leaked token");

  const capabilities = await httpRequest(port, "/v1/capabilities", { headers: { Authorization: "Bearer runtime-test-token-123456" } });
  assert(capabilities.status === 200, `authorized capabilities=${capabilities.status}`);
  assert(!/ACCESS_KEY|SECRET|runtime-test-token/.test(capabilities.body), "capabilities leaked credential material");

  const slow = [];
  for (let i = 0; i < 2; i += 1) slow.push(await slowloris(port));
  assert(slow.every((item) => item.closed), "one or more Slowloris sockets survived 8 seconds");
  assert(slow.every((item) => item.elapsed < 8000), "Slowloris timeout exceeded test budget");

  const browserSurface = ["/", "/index.html", "/app.js", "/styles.css", "/favicon.ico", "/debug", "/metrics"];
  for (const path of browserSurface) {
    const res = await httpRequest(port, path);
    assert(res.status === 404, `${path} unexpectedly exposed: ${res.status}`);
    assert(!/server\.mjs|package\.json|SECURITY\.md|BEGIN PRIVATE KEY/i.test(res.body), `${path} leaked internal content`);
  }

  const sensitivePaths = ["/.env", "/.git/config", "/server.mjs", "/package.json", "/SECURITY.md", "/tools/security-audit.mjs", "/admin", "/internal", "/console"];
  for (const path of sensitivePaths) {
    const res = await httpRequest(port, path);
    assert(res.status === 404, `${path} unexpectedly exposed: ${res.status}`);
  }

  const hostilePaths = [
    ["/%00", 400], ["/%09", 400], ["/%0a", 400], ["/%0d", 400], ["/%1f", 400], ["/%7f", 400],
    ["/%5c", 400], ["/%2e%2e/server.mjs", 400], ["/%", 400], [`/${"a".repeat(2049)}`, 414]
  ];
  for (const [path, expected] of hostilePaths) {
    const res = await httpRequest(port, path);
    assert(res.status === expected, `${path.slice(0, 64)}=${res.status}, expected ${expected}`);
  }

  for (const method of ["PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "PROPFIND"]) {
    const res = await httpRequest(port, "/healthz", { method });
    assert(res.status === 404 || res.status === 405, `${method}=${res.status}`);
  }

  const wrongMethod = await httpRequest(port, "/v1/capabilities", { method: "POST" });
  assert(wrongMethod.status === 405, `wrong method=${wrongMethod.status}`);

  const badJson = await httpRequest(port, "/v1/videos/create-upload", {
    method: "POST",
    headers: { Authorization: "Bearer runtime-test-token-123456", "Content-Type": "application/json" },
    body: "{"
  });
  assert(badJson.status === 400, `invalid json=${badJson.status}`);

  const bodyOnGet = await httpRequest(port, "/healthz", { headers: { "Content-Length": "10" } });
  assert(bodyOnGet.status === 400, `GET body header accepted: ${bodyOnGet.status}`);

  const oversized = await rawRequest(port, `GET /healthz HTTP/1.1\r\nHost: localhost\r\nX-Fill: ${"A".repeat(12000)}\r\n\r\n`);
  assert(/^HTTP\/1\.1 400 /m.test(oversized.data), "oversized header was not rejected");

  const smuggle = await rawRequest(port, "POST /v1/videos/create-upload HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer runtime-test-token-123456\r\nContent-Type: application/json\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n");
  assert(/^HTTP\/1\.1 400 /m.test(smuggle.data), "CL+TE malformed request was not rejected");

  const recovery = await Promise.all(Array.from({ length: 300 }, () => httpRequest(port, "/healthz")));
  assert(recovery.every((item) => item.status === 204), "recovery health burst failed");

  console.log("Runtime security test passed");
} finally {
  await new Promise((resolve) => server.close(resolve));
}
