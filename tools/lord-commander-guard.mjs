import { readFile, readdir, lstat } from "node:fs/promises";
import { createHash } from "node:crypto";
import { join, relative } from "node:path";

const ROOT = process.cwd();
const findings = [];
const CRITICAL_CONTROLS = new Map([
  [".github/workflows/security-audit.yml", "ff8d3e2f54f7d7f7c7881a38c0158309ff044612"],
  ["tools/security-audit.mjs", "60934ea0159259170fcf01c2812b7612369636b1"],
  ["tools/runtime-security-test.mjs", "f60e2c4ff34909451d7f2d56373f8822f6c832aa"]
]);
const forbiddenNames = [
  /(^|\/)(?:\.env(?:\..+)?|id_rsa|id_ed25519)$/i,
  /\.(?:pem|key|p12|pfx|jks|keystore|sql|sqlite3?|db|dump|bak|backup|log|zip|7z|rar|tar|tgz|gz)$/i,
  /(^|\/)(?:credentials?|secrets?)[^/]*\.(?:json|ya?ml|txt)$/i
];

function blobId(buffer) {
  const header = Buffer.from(`blob ${buffer.length}\0`);
  return createHash("sha1").update(header).update(buffer).digest("hex");
}

for (const [path, expected] of CRITICAL_CONTROLS) {
  try {
    const data = await readFile(join(ROOT, path));
    if (blobId(data) !== expected) findings.push(`${path}: critical security control drifted`);
  } catch {
    findings.push(`${path}: critical security control missing or unreadable`);
  }
}

async function walk(dir) {
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    if (entry.name === ".git" || entry.name === "node_modules") continue;
    const absolute = join(dir, entry.name);
    const path = relative(ROOT, absolute).replaceAll("\\", "/");
    const info = await lstat(absolute);
    if (info.isSymbolicLink()) {
      findings.push(`${path}: symbolic links are forbidden`);
      continue;
    }
    if (entry.isDirectory()) await walk(absolute);
    else if (entry.isFile() && forbiddenNames.some((pattern) => pattern.test(path))) {
      findings.push(`${path}: forbidden credential/archive filename`);
    }
  }
}

await walk(ROOT);

if (findings.length) {
  console.error("LORD COMMANDER GUARD FAILED");
  for (const finding of [...new Set(findings)]) console.error(`- ${finding}`);
  process.exit(1);
}

console.log("Lord Commander guard passed: critical controls intact and repository structure clean.");
