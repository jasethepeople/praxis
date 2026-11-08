import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  timingSafeEqual,
  verify,
  type KeyObject,
} from "node:crypto";
import { chmodSync, existsSync, lstatSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve, sep } from "node:path";
import { canonicalJson } from "./canonical";
import type { SignedEvent } from "./types";

export interface SigningIdentity {
  privateKey: KeyObject;
  publicKeyPem: string;
  fingerprint: string;
  sign(value: unknown): string;
}

export function constantTimeEqual(left: string, right: string): boolean {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

function publicPem(privateKey: KeyObject): string {
  return createPublicKey(privateKey).export({ type: "spki", format: "pem" }).toString();
}

function ensurePrivateDirectory(path: string): void {
  const absolute = resolve(path);
  const root = absolute.startsWith(sep) ? sep : "";
  let current = root;
  for (const part of absolute.split(sep).filter(Boolean)) {
    current = current ? join(current, part) : part;
    try {
      const stat = lstatSync(current);
      if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error("Signing key path contains a symlink or non-directory");
      if (current === absolute && (stat.mode & 0o077) !== 0) throw new Error("Signing key directory permissions must be 0700 or more restrictive");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      mkdirSync(current, { mode: 0o700 });
    }
  }
}

export function loadOrCreateSigningIdentity(path: string): SigningIdentity {
  ensurePrivateDirectory(dirname(path));
  if (!existsSync(path)) {
    const pair = generateKeyPairSync("ed25519", {
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });
    try {
      writeFileSync(path, pair.privateKey, { mode: 0o600, flag: "wx" });
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    }
    if (!existsSync(`${path}.pub.pem`)) {
      try {
        writeFileSync(`${path}.pub.pem`, pair.publicKey, { mode: 0o644, flag: "wx" });
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      }
    }
  }

  const privateStat = lstatSync(path);
  if (!privateStat.isFile() || privateStat.isSymbolicLink()) throw new Error(`Signing key must be a regular file: ${path}`);
  chmodSync(path, 0o600);
  const privateKey = createPrivateKey(readFileSync(path, "utf8"));
  if (privateKey.asymmetricKeyType !== "ed25519") throw new Error(`Signing key is not Ed25519: ${path}`);
  const derivedPublicPem = publicPem(privateKey);
  if (!existsSync(`${path}.pub.pem`)) writeFileSync(`${path}.pub.pem`, derivedPublicPem, { mode: 0o644, flag: "wx" });
  const publicStat = lstatSync(`${path}.pub.pem`);
  if (!publicStat.isFile() || publicStat.isSymbolicLink()) throw new Error("Signing public key must be a regular file");
  const publicKeyPem = readFileSync(`${path}.pub.pem`, "utf8");
  const publicKey = createPublicKey(publicKeyPem);
  if (publicKey.asymmetricKeyType !== "ed25519" || publicKey.export({ type: "spki", format: "der" }).compare(createPublicKey(privateKey).export({ type: "spki", format: "der" })) !== 0) {
    throw new Error("Signing key and public key do not match");
  }
  const fingerprint = `sha256:${createHash("sha256").update(publicKey.export({ type: "spki", format: "der" })).digest("hex")}`;
  return {
    privateKey,
    publicKeyPem,
    fingerprint,
    sign(value) {
      return `ed25519:${sign(null, Buffer.from(canonicalJson(value)), privateKey).toString("base64")}`;
    },
  };
}

export function readPublicKey(path: string | undefined): KeyObject | undefined {
  if (!path) return undefined;
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error(`Public key must be a regular file: ${path}`);
  const key = createPublicKey(readFileSync(path, "utf8"));
  if (key.asymmetricKeyType !== "ed25519") throw new Error(`Expected an Ed25519 public key: ${path}`);
  return key;
}

export function verifySignature(value: unknown, signature: string, publicKey: KeyObject | undefined): boolean {
  if (!publicKey || !/^ed25519:[A-Za-z0-9+/]{86}==$/.test(signature)) return false;
  try {
    const bytes = Buffer.from(signature.slice("ed25519:".length), "base64");
    return bytes.byteLength === 64 && verify(null, Buffer.from(canonicalJson(value)), publicKey, bytes);
  } catch {
    return false;
  }
}

export function eventSigningPayload(event: SignedEvent): Record<string, unknown> {
  return {
    event_type: event.event_type,
    event_id: event.event_id,
    timestamp: event.timestamp,
    payload: event.payload,
  };
}

export function signEvent(identity: SigningIdentity, event: Omit<SignedEvent, "signature" | "signer" | "prev_hash" | "event_hash">): SignedEvent {
  const signed = {
    event_type: event.event_type,
    event_id: event.event_id,
    timestamp: event.timestamp,
    payload: event.payload,
  };
  return { ...event, signature: identity.sign(signed), signer: identity.fingerprint };
}
