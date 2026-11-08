import { randomBytes } from "node:crypto";

const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

export function newUlid(now = Date.now()): string {
  if (!Number.isSafeInteger(now) || now < 0 || now >= 2 ** 48) throw new RangeError("Invalid ULID timestamp");
  let value = (BigInt(now) << 80n) | BigInt(`0x${randomBytes(10).toString("hex")}`);
  let out = "";
  for (let i = 0; i < 26; i++) {
    out = alphabet[Number(value & 31n)] + out;
    value >>= 5n;
  }
  return out;
}

export function newSkillId(): string {
  return `skill_${newUlid()}`;
}

export function newEventId(): string {
  return `evt_${newUlid()}`;
}
