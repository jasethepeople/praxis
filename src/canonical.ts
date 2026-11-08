import { createHash } from "node:crypto";

function canonical(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("Canonical JSON rejects non-finite numbers");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map((item) => canonical(item)).join(",")}]`;
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    const keys = Object.keys(record).sort();
    for (const key of keys) if (record[key] === undefined) throw new TypeError("Canonical JSON rejects undefined values");
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonical(record[key])}`).join(",")}}`;
  }
  throw new TypeError(`Canonical JSON cannot encode ${typeof value}`);
}

export function canonicalJson(value: unknown): string {
  return canonical(value);
}

export function sha256(value: string | Uint8Array): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

export function contractPayload(contract: object): Record<string, unknown> {
  const copy = structuredClone(contract) as Record<string, unknown>;
  delete copy.molts_event_hash;
  return copy;
}

export function contractHash(contract: object): string {
  return sha256(canonicalJson(contractPayload(contract)));
}
