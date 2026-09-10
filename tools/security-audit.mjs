import { readdir, readFile, stat, lstat } from "node:fs/promises";
import { join, relative } from "node:path";
import { spawn } from "node:child_process";

const ROOT = process.cwd();
const findings = [];
const MAX_BYTES = 512 * 1024;
const AUDIT_FILES = new Set(["tools/security-audit.mjs", "tools/runtime-security-test.mjs"]);

const forbiddenFilenamePatterns = [
  [/(^|\/)(?:\.env(?:\..+)?|id_rsa|id_ed25519|[^/]+\.(?:pem|key|p12|pfx|jks|keystore)|credentials?[^/]*\.(?:json|ya?ml|txt)|secrets?[^/]*\.(?:json|ya?ml|txt))$/i, "secret/credential filename"],
  [/\.(?:map|sql|sqlite3?|db|dump|bak|backup|log|zip|7z|rar|tar|tgz|gz)$/i, "export/archive/source-map filename"]
];

const sensitiveContentPatterns = [
  ["private key", /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/],
  ["AWS access key", /\bAKIA[0-9A-Z]{16}\b/],
  ["GitHub token", /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/],
  ["Slack token", /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/],
  ["Google API key", /\bAIza[0-9A-Za-z_-]{35}\b/],
  ["OpenAI-style secret key", /\bsk-[A-Za-z0-9_-]{20,}\b/],
  ["JWT-like token", /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/],
  ["hard-coded bearer token", /\bBearer\s+[A-Za-z0-9._~+\/-]{20,}\b/i],
  ["hard-coded secret assignment", /\b(?:password|passwd|secret|token|api[_-]?key|client[_-]?secret)\b\s*[:=]\s*["'`][^"'`\n]{8,}["'`]/i],
  ["basic-auth URL", /https?:\/\/[^/\s:@]+:[^/\s@]+@/i],
  ["database/queue credential URI", /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s"'`]+/i],
  ["private IPv4 address", /\b(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})\b/],
  ["internal/private hostname", /\b[a-z0-9-]+\.(?:internal|local)\b/i],
  ["source map reference", /sourceMappingURL\s*=/i]
];

const dangerousCodePatterns = [
  ["dynamic code execution", /\beval\s*\(|\bnew\s+Function\s*\(/],
  ["shell/process execution", /\b(?:child_process|execSync|spawnSync|execFileSync)\b/],
  ["HTML injection sink", /\.(?:innerHTML|outerHTML)\s*=|insertAdjacentHTML\s*\(/],
  ["TLS verification disabled", /NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0|rejectUnauthorized\s*:\s*false/i],
  ["insecure outbound HTTP", /\bhttp:\/\/(?!127\.0\.0\.1|localhost)/i]
];

async function walk(dir) {
  const output = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    if (entry.name === ".git" || entry.name === "node_modules") continue;
    const absolute = join(dir, entry.name);
    const info = await lstat(absolute);
    if (info.isSymbolicLink()) {
      findings.push(`${relative(ROOT, absolute)}: symlinks are forbidden`);
      continue;
    }
    if (entry.isDirectory()) output.push(...await walk(absolute));
    else if (entry.isFile()) output.push(absolute);
  }
  return output;
}

function isTextCandidate(path) {
  return /(?:^|\/)(?:[^/]+\.(?:js|mjs|cjs|json|md|txt|ya?ml|html|css|toml)|\.gitignore)$/i.test(path);
}

const requiredFragments = [
  "maxHeaderSize: 8192",
  "requestTimeout: 5000",
  "headersTimeout: 4000",
  "connectionsCheckingInterval: 1000",
  "keepAliveTimeout: 5000",
  "server.maxHeadersCount = 64",
  "server.maxRequestsPerSocket = 100",
  "const CONTROL_CHARS = /[\\u0000-\\u001F\\u007F]/;",
  "CONTROL_CHARS.test(pathname)",
  "parsed.pathname === \"/healthz\""
];

try {
  const serverText = await readFile(join(ROOT, "server.mjs"), "utf8");
  for (const fragment of requiredFragments) {
    if (!serverText.includes(fragment)) findings.push(`server.mjs: required hardening missing: ${fragment}`);
  }
  if (/readFile\s*\(|createReadStream\s*\(|serveStatic|express\.static|sendFile\s*\(/.test(serverText)) {
    findings.push("server.mjs: dynamic/static file-serving primitive is forbidden in collector baseline");
  }
} catch {
  findings.push("server.mjs: missing or unreadable");
}

const files = await walk(ROOT);
for (const absolutePath of files) {
  const path = relative(ROOT, absolutePath).replaceAll("\\", "/");
  for (const [pattern, label] of forbiddenFilenamePatterns) {
    if (pattern.test(path)) findings.push(`${path}: forbidden ${label}`);
  }
  if (!isTextCandidate(path) || AUDIT_FILES.has(path)) continue;
  const info = await stat(absolutePath);
  if (info.size > MAX_BYTES) {
    findings.push(`${path}: text file exceeds ${MAX_BYTES} byte limit`);
    continue;
  }
  const buffer = await readFile(absolutePath);
  if (buffer.includes(0)) {
    findings.push(`${path}: unexpected NUL/binary content`);
    continue;
  }
  const text = buffer.toString("utf8");
  for (const [label, pattern] of [...sensitiveContentPatterns, ...dangerousCodePatterns]) {
    if (pattern.test(text)) findings.push(`${path}: possible ${label}`);
  }
}

const packageJson = JSON.parse(await readFile(join(ROOT, "package.json"), "utf8"));
if (Object.keys(packageJson.dependencies ?? {}).length || Object.keys(packageJson.devDependencies ?? {}).length) {
  findings.push("package.json: zero-dependency baseline violated");
}
if (packageJson.type !== "module") findings.push("package.json: type must be module");
if (packageJson.scripts?.start !== "node server.mjs") findings.push("package.json: start script drifted");

if (findings.length) {
  console.error("SECURITY AUDIT FAILED");
  for (const finding of findings) console.error(`- ${finding}`);
  process.exit(1);
}

await new Promise((resolve, reject) => {
  const child = spawn(process.execPath, ["tools/runtime-security-test.mjs"], { cwd: ROOT, stdio: "inherit" });
  child.once("error", reject);
  child.once("exit", (code) => code === 0 ? resolve() : reject(new Error(`runtime security test exited ${code}`)));
});

console.log("Security audit passed");
