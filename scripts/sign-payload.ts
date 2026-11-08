import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  type KeyObject,
} from "node:crypto";
import { closeSync, constants, existsSync, fstatSync, lstatSync, openSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { canonicalJson } from "../src/canonical";
import { newUlid } from "../src/ids";

function fail(message: string): never {
  throw new Error(message);
}

function privateKey(path: string): KeyObject {
  const fullPath = resolve(path);
  const fd = openSync(fullPath, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile()) fail("Private key must be a regular file.");
    if ((stat.mode & 0o077) !== 0) fail("Private key permissions must be 0600 or stricter.");
    const key = createPrivateKey(readFileSync(fd));
    if (key.asymmetricKeyType !== "ed25519") fail("The key must be Ed25519.");
    return key;
  } finally {
    closeSync(fd);
  }

}

function keygen(approverId: string, path: string): void {
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,159}$/.test(approverId)) fail("Invalid approver id.");
  const fullPath = resolve(path);
  if (existsSync(fullPath)) fail("Refusing to overwrite an existing key.");
  const directoryStat = lstatSync(dirname(fullPath));
  if (!directoryStat.isDirectory() || directoryStat.isSymbolicLink() || (directoryStat.mode & 0o077) !== 0) fail("Key directory must exist, be a real directory, and have mode 0700 or stricter.");
  const { privateKey: secret, publicKey } = generateKeyPairSync("ed25519");
  const privatePem = secret.export({ type: "pkcs8", format: "pem" }).toString();
  const publicPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const fd = openSync(fullPath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600);
  try {
    writeFileSync(fd, privatePem, { encoding: "utf8" });
  } finally {
    closeSync(fd);
  }
  console.log(JSON.stringify({ approver_id: approverId, public_key_pem: publicPem }, null, 2));
}

function signFile(keyPath: string, payloadPath: string): void {
  const key = privateKey(keyPath);
  const payload = JSON.parse(readFileSync(resolve(payloadPath), "utf8"));
  if (payload === null || typeof payload !== "object" || Array.isArray(payload)) fail("Payload must be a JSON object.");
  if (Object.hasOwn(payload, "signature")) fail("Payload must not already contain a signature.");
  const signature = sign(null, Buffer.from(canonicalJson(payload)), key).toString("base64");
  const publicKeyPem = createPublicKey(key).export({ type: "spki", format: "pem" }).toString();
  console.log(JSON.stringify({ ...payload, signature, public_key_pem: publicKeyPem }, null, 2));
}

function signApproval(approverId: string, keyPath: string, contractHash: string, decision: string): void {
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,159}$/.test(approverId)) fail("Invalid approver id.");
  if (!/^sha256:[0-9a-f]{64}$/.test(contractHash)) fail("Invalid contract hash.");
  if (decision !== "approve" && decision !== "reject") fail("Decision must be approve or reject.");
  const payload = {
    approval_id: `approval_${newUlid()}`,
    contract_hash: contractHash,
    approver_id: approverId,
    decision,
    signed_at: new Date().toISOString(),
  };
  const key = privateKey(keyPath);
  const signature = sign(null, Buffer.from(canonicalJson(payload)), key).toString("base64");
  const publicKeyPem = createPublicKey(key).export({ type: "spki", format: "pem" }).toString();
  console.log(JSON.stringify({ ...payload, signature, public_key_pem: publicKeyPem }, null, 2));
}

try {
  const args = process.argv.slice(2);
  const usage = "Usage: bun scripts/sign-payload.ts --keygen APPROVER_ID PRIVATE_KEY_PATH | --approval APPROVER_ID PRIVATE_KEY_PATH CONTRACT_HASH approve|reject | --sign PRIVATE_KEY_PATH PAYLOAD_JSON";
  if (args[0] === "--help" || args[0] === "-h") console.log(usage);
  else if (args[0] === "--keygen" && args.length === 3) keygen(args[1], args[2]);
  else if (args[0] === "--sign" && args.length === 3) signFile(args[1], args[2]);
  else if (args[0] === "--approval" && args.length === 5) signApproval(args[1], args[2], args[3], args[4]);
  else fail(usage);
} catch (error) {
  const message = error instanceof Error ? error.message : "Signing failed.";
  console.error(message.slice(0, 400));
  process.exitCode = 1;
}
