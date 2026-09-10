import { lstat, readFile, readdir } from "node:fs/promises";
import { relative, resolve } from "node:path";

const ROOT = resolve(".");
const MAX_FILE_BYTES = 5 * 1024 * 1024;
const SELF = "tools/security-audit.mjs";

const forbiddenFilenamePatterns = [
  [/(^|\/)(?:\.env(?:\..+)?|id_rsa|id_ed25519|[^/]+\.(?:pem|key|p12|pfx|jks|keystore)|credentials?[^/]*|secrets?[^/]*|service-account[^/]*)$/i, "secret/credential file"],
  [/\.(?:sql|sqlite3?|db|dump|csv|tsv|xlsx?|parquet|ndjson|log|zip|7z|rar|tar|tgz|gz|bak|backup)$/i, "data/export/archive file"],
  [/\.map$/i, "source map"],
  [/(^|\/)\.DS_Store$/i, "OS metadata"]
];

const sensitiveContentPatterns = [
  ["private key", /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/],
  ["AWS access key", /\bAKIA[0-9A-Z]{16}\b/],
  ["GitHub token", /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/],
  ["Slack token", /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/],
  ["Google API key", /\bAIza[0-9A-Za-z_-]{35}\b/],
  ["Stripe secret", /\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b/],
  ["OpenAI-style secret", /\bsk-[A-Za-z0-9_-]{20,}\b/],
  ["JWT-like token", /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/],
  ["hard-coded bearer token", /\bBearer\s+[A-Za-z0-9._~+\/-]{20,}\b/i],
  ["hard-coded secret assignment", /\b(?:password|passwd|secret|token|api[_-]?key|client[_-]?secret)\b\s*[:=]\s*["'`][^"'`\n]{8,}["'`]/i],
  ["basic-auth URL", /https?:\/\/[^/\s:@]+:[^/\s@]+@/i],
  ["database/queue credential URI", /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s"'`]+/i],
  ["Slack webhook", /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/_-]{20,}/i],
  ["Discord webhook", /https:\/\/(?:discord(?:app)?\.com)\/api\/webhooks\/[0-9]+\/[A-Za-z0-9._-]+/i],
  ["email address", /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i],
  ["private IPv4 address", /\b(?:127\.0\.0\.1|0\.0\.0\.0|10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})\b/],
  ["internal/private hostname", /\b(?:localhost|[a-z0-9-]+\.(?:internal|local)|[a-z0-9-]+\.railway\.internal)\b/i],
  ["Railway public hostname", /\b[a-z0-9-]+\.up\.railway\.app\b/i],
  ["infrastructure UUID", /\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/i]
];

const riskyCodePatterns = [
  ["dynamic code execution", /\beval\s*\(|\bnew\s+Function\s*\(/],
  ["child-process execution", /(?:node:)?child_process|from\s+["']child_process["']|require\s*\(\s*["']child_process["']\s*\)/],
  ["unsafe browser HTML sink", /\.(?:innerHTML|outerHTML)\s*=|insertAdjacentHTML\s*\(/],
  ["document.write", /\bdocument\.write\s*\(/],
  ["disabled TLS verification", /NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0|rejectUnauthorized\s*:\s*false|sslmode=disable/i],
  ["plain HTTP endpoint", /http:\/\/(?!127\.0\.0\.1(?::\d+)?(?:\/|$)|localhost(?::\d+)?(?:\/|$))/i]
];

const textExtensions = new Set([".c", ".cc", ".conf", ".cpp", ".css", ".go", ".h", ".hpp", ".html", ".ini", ".java", ".js", ".json", ".jsx", ".md", ".mjs", ".py", ".rb", ".rs", ".sh", ".toml", ".ts", ".tsx", ".txt", ".xml", ".yaml", ".yml"]);
function extension(path) { const slash = path.lastIndexOf("/"); const dot = path.lastIndexOf("."); return dot > slash ? path.slice(dot).toLowerCase() : ""; }
function isTextCandidate(path) { return path === ".gitignore" || path === "Dockerfile" || path === "Procfile" || textExtensions.has(extension(path)); }
async function walk(directory) {
  const output = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    if (entry.name === ".git" || entry.name === "node_modules") continue;
    const absolutePath = resolve(directory, entry.name);
    const path = relative(ROOT, absolutePath).replaceAll("\\", "/");
    const info = await lstat(absolutePath);
    if (info.isSymbolicLink()) output.push({ path, absolutePath, info, symlink: true });
    else if (info.isDirectory()) output.push(...await walk(absolutePath));
    else if (info.isFile()) output.push({ path, absolutePath, info, symlink: false });
  }
  return output;
}
const findings = [];
const files = await walk(ROOT);
for (const file of files) {
  const { path, absolutePath, info, symlink } = file;
  if (symlink) { findings.push(`${path}: symbolic links are forbidden in the hardened baseline`); continue; }
  if (info.size > MAX_FILE_BYTES) findings.push(`${path}: file exceeds ${MAX_FILE_BYTES} byte repository safety limit`);
  for (const [pattern, label] of forbiddenFilenamePatterns) if (pattern.test(path)) findings.push(`${path}: forbidden ${label}`);
  if (!isTextCandidate(path) || path === SELF) continue;
  const buffer = await readFile(absolutePath);
  if (buffer.includes(0)) { findings.push(`${path}: unexpected NUL/binary content in text file`); continue; }
  const text = buffer.toString("utf8");
  if (text.includes("\uFFFD")) findings.push(`${path}: invalid UTF-8 replacement character detected`);
  for (const [label, pattern] of sensitiveContentPatterns) if (pattern.test(text)) findings.push(`${path}: possible ${label}`);
  for (const [label, pattern] of riskyCodePatterns) if (pattern.test(text)) findings.push(`${path}: possible ${label}`);
}
if (findings.length) { console.error("SECURITY AUDIT FAILED"); for (const finding of findings) console.error(`- ${finding}`); process.exit(1); }
console.log(`Security audit passed: ${files.length} tracked working-tree files inspected.`);
