import { readFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { extname } from "node:path";

const findings = [];
const MAX_TEXT_BYTES = 512 * 1024;
const CRITICAL_CONTROLS = new Map([
  [".github/workflows/security-audit.yml", "ff8d3e2f54f7d7f7c7881a38c0158309ff044612"],
  ["tools/security-audit.mjs", "60934ea0159259170fcf01c2812b7612369636b1"],
  ["tools/runtime-security-test.mjs", "f60e2c4ff34909451d7f2d56373f8822f6c832aa"]
]);
const SELF_FILES = new Set(["tools/lord-commander-guard.mjs"]);
const TEXT_EXTENSIONS = new Set([".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".json", ".html", ".css", ".md", ".yml", ".yaml", ".txt", ".toml", ".ini", ".sh", ".ps1"]);
const forbiddenNames = [/(^|\/)(?:\.env(?:\..+)?|id_rsa|id_ed25519)$/i,/\.(?:pem|key|p12|pfx|jks|keystore|sql|sqlite3?|db|dump|bak|backup|log|zip|7z|rar|tar|tgz|gz)$/i,/(^|\/)(?:credentials?|secrets?)[^/]*\.(?:json|ya?ml|txt)$/i];
const sensitivePatterns = [/-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/,/\bAKIA[0-9A-Z]{16}\b/,/\bgh[pousr]_[A-Za-z0-9_]{20,}\b/,/\bxox[baprs]-[A-Za-z0-9-]{10,}\b/,/\bAIza[0-9A-Za-z_-]{35}\b/,/\bsk-[A-Za-z0-9_-]{20,}\b/,/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/,/\bBearer\s+[A-Za-z0-9._~+\/-]{20,}\b/i,/\b(?:password|passwd|secret|token|api[_-]?key|client[_-]?secret)\b\s*[:=]\s*["'`][^"'`\n]{8,}["'`]/i,/\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s"'`]+/i,/NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0|rejectUnauthorized\s*:\s*false/i];
function git(...args){return execFileSync("git",args,{encoding:"utf8",maxBuffer:8*1024*1024}).trim();}
function lines(value){return value.split("\n").map((v)=>v.trim()).filter(Boolean);}
for(const [path,expected] of CRITICAL_CONTROLS){try{const actual=git("hash-object","--",path);if(actual!==expected)findings.push(`${path}: critical security control drifted`);}catch{findings.push(`${path}: critical security control missing or unreadable`);}}
const tags=lines(git("tag","--list"));if(tags.length)findings.push(`unexpected Git tags present: ${tags.join(", ")}`);
const tracked=lines(git("ls-files"));for(const path of tracked){if(forbiddenNames.some((p)=>p.test(path)))findings.push(`${path}: forbidden credential/archive filename`);if(SELF_FILES.has(path))continue;const name=path.split("/").pop()||"";if(!TEXT_EXTENSIONS.has(extname(name).toLowerCase())&&!name.startsWith(".git"))continue;const data=await readFile(path);if(data.length>MAX_TEXT_BYTES||data.includes(0))continue;const text=data.toString("utf8");for(const pattern of sensitivePatterns){if(pattern.test(text)){findings.push(`${path}: possible secret or unsafe credential material`);break;}}}
for(const row of lines(git("ls-files","-s"))){const match=row.match(/^(\d{6})\s+[0-9a-f]+\s+\d+\t(.+)$/);if(!match)continue;const[,mode,path]=match;if(mode!=="100644")findings.push(`${path}: unexpected Git file mode ${mode}`);}
if(findings.length){console.error("LORD COMMANDER GUARD FAILED");for(const finding of [...new Set(findings)])console.error(`- ${finding}`);process.exit(1);}console.log(`Lord Commander guard passed: ${tracked.length} tracked files checked; critical security controls intact.`);
