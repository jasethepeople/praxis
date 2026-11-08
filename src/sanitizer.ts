import { createHash } from "node:crypto";
import { sha256 } from "./canonical";

export const SANITIZER_VERSION = "praxis-sanitizer/1.0.0";
export const extractionModelSha = () => createHash("sha1").update("praxis-structured-miner/1.0.0").digest("hex");

const injectionPatterns = [
  /\bignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+instructions\b/i,
  /\b(?:system|developer)\s+prompt\b.{0,100}\b(?:reveal|print|show|override|ignore)\b/i,
  /\b(?:reveal|exfiltrate|print|dump)\s+(?:the\s+)?(?:secret|credential|api[ _-]?key|private key|token)s?\b/i,
  /\b(?:you are now|act as|roleplay as)\s+(?:the )?(?:system|developer|admin|root)\b/i,
  /\bdo not follow (?:the )?(?:user|developer|system)\b/i,
  /<\|(?:system|developer|assistant)\|>/i,
  /\bBEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY\b/i,
];

const redactions: Array<[RegExp, string]> = [
  [/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g, "[REDACTED_PRIVATE_KEY]"],
  [/\bBearer\s+[A-Za-z0-9._~+/-]{12,}={0,2}/gi, "Bearer [REDACTED]"],
  [/\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})\b/g, "[REDACTED_TOKEN]"],
  [/\bAKIA[0-9A-Z]{16}\b/g, "[REDACTED_AWS_KEY]"],
  [/((?:api[_ -]?key|access[_ -]?token|client[_ -]?secret|password|passwd|secret))\s*[:=]\s*[^\s,;]+/gi, "$1[REDACTED]"],
  [/(?<![\w.+-])[\w.+-]{1,64}@[\w.-]{1,190}\.[A-Za-z]{2,24}/g, "[REDACTED_EMAIL]"],
  [/(?<![A-Za-z0-9])(?:\/home|\/Users|\/root|\/etc|\/var|\/tmp)\/[^\s"'<>]+/g, "[REDACTED_PATH]"],
  [/\b[A-Za-z]:\\(?:Users|Documents and Settings|Windows|Program Files)\\[^\s"'<>]+/gi, "[REDACTED_PATH]"],
  [/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, "[REDACTED_JWT]"],
];

export interface SanitizedTrajectory {
  content: string;
  hash: string;
  flags: string[];
  quarantined: boolean;
  redacted: boolean;
}

export function sanitizeTrajectory(raw: string, maxBytes = 1_048_576): SanitizedTrajectory {
  if (typeof raw !== "string" || Buffer.byteLength(raw, "utf8") > maxBytes) throw new Error("Trajectory is missing or exceeds the configured size limit");
  const flags = new Set<string>();
  if (injectionPatterns.some((pattern) => pattern.test(raw))) flags.add("prompt_injection_detected");
  let content = raw.normalize("NFC").replace(/\u0000/g, "");
  let redacted = false;
  for (const [pattern, replacement] of redactions) {
    pattern.lastIndex = 0;
    const next = content.replace(pattern, (...args: unknown[]) => {
      redacted = true;
      if (replacement === "$1[REDACTED]") return `${String(args[1] ?? "sensitive field")}[REDACTED]`;
      return replacement;
    });
    content = next;
  }
  if (redacted) flags.add("sensitive_data_redacted");
  const hash = sha256(content);
  return {
    content,
    hash,
    flags: [...flags].sort(),
    quarantined: flags.has("prompt_injection_detected"),
    redacted,
  };
}
