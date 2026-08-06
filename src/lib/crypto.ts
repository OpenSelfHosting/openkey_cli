/** Shared crypto matching openkey_app / openkey_extension (Argon2id + AES-GCM). */

import { argon2id } from "hash-wasm";
import { gcm } from "@noble/ciphers/aes";
import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha2";
import { randomBytes } from "@noble/hashes/utils";

const enc = new TextEncoder();

export const KDF = {
  memory: 65536,
  iterations: 3,
  parallelism: 4,
  hashLength: 32,
} as const;

export function toB64Url(bytes: Uint8Array): string {
  let s = "";
  bytes.forEach((b) => (s += String.fromCharCode(b)));
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromB64Url(s: string): Uint8Array {
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const b64 = (s + pad).replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function generateSalt(length = 16): Uint8Array {
  return randomBytes(length);
}

export function generateVaultKey(): Uint8Array {
  return randomBytes(32);
}

export async function deriveMasterKey(
  email: string,
  masterPassword: string,
  salt: Uint8Array,
): Promise<Uint8Array> {
  const password = enc.encode(`${email.trim().toLowerCase()}:${masterPassword}`);
  const hash = await argon2id({
    password,
    salt,
    parallelism: KDF.parallelism,
    iterations: KDF.iterations,
    memorySize: KDF.memory,
    hashLength: KDF.hashLength,
    outputType: "binary",
  });
  return hash as Uint8Array;
}

export function deriveAuthHash(masterKey: Uint8Array): string {
  const digest = hmac(sha256, masterKey, enc.encode("openkey-auth"));
  return toB64Url(digest);
}

export function encryptBytes(key: Uint8Array, plaintext: Uint8Array): string {
  const nonce = randomBytes(12);
  const aes = gcm(key, nonce);
  const ciphertext = aes.encrypt(plaintext);
  const combined = new Uint8Array(nonce.length + ciphertext.length);
  combined.set(nonce, 0);
  combined.set(ciphertext, nonce.length);
  return toB64Url(combined);
}

export function decryptBytes(key: Uint8Array, ciphertextB64: string): Uint8Array {
  const combined = fromB64Url(ciphertextB64);
  if (combined.length < 28) throw new Error("Ciphertext too short");
  const nonce = combined.slice(0, 12);
  const data = combined.slice(12);
  const aes = gcm(key, nonce);
  return aes.decrypt(data);
}

export function encryptString(key: Uint8Array, plaintext: string): string {
  return encryptBytes(key, enc.encode(plaintext));
}

export function decryptString(key: Uint8Array, ciphertext: string): string {
  return new TextDecoder().decode(decryptBytes(key, ciphertext));
}

export async function wrapVaultKey(
  masterKey: Uint8Array,
  vaultKey: Uint8Array,
): Promise<string> {
  return encryptBytes(masterKey, vaultKey);
}

export async function unwrapVaultKey(
  masterKey: Uint8Array,
  wrapped: string,
): Promise<Uint8Array> {
  return decryptBytes(masterKey, wrapped);
}

const PW_LOWER = "abcdefghijklmnopqrstuvwxyz";
const PW_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const PW_DIGITS = "0123456789";
const PW_SYMBOLS = "!@#$%^&*()-_=+[]{}|;:,.<>?";
const PW_AMBIGUOUS = new Set("Il1O0o");

export type GeneratePasswordOpts = {
  length?: number;
  upper?: boolean;
  lower?: boolean;
  digits?: boolean;
  symbols?: boolean;
  avoidAmbiguous?: boolean;
};

/** Match openkey_app CryptoService.generatePassword options. */
export function generatePassword(opts: GeneratePasswordOpts | number = 20): string {
  const o = typeof opts === "number" ? { length: opts } : opts;
  const requested = o.length ?? 20;
  if (requested < 4 || requested > 64) {
    throw new Error("Password length must be between 4 and 64");
  }
  const length = requested;
  const avoid = !!o.avoidAmbiguous;
  const filter = (alphabet: string) =>
    avoid
      ? [...alphabet].filter((c) => !PW_AMBIGUOUS.has(c)).join("")
      : alphabet;

  const sets = [
    o.lower !== false ? filter(PW_LOWER) : "",
    o.upper !== false ? filter(PW_UPPER) : "",
    o.digits !== false ? filter(PW_DIGITS) : "",
    o.symbols !== false ? filter(PW_SYMBOLS) : "",
  ].filter((s) => s.length > 0);

  if (!sets.length || length < sets.length) {
    throw new Error("Invalid password generation options");
  }

  const pool = sets.join("");
  const chars: string[] = sets.map(
    (set) => set[randomBytes(1)[0]! % set.length]!,
  );
  const fill = randomBytes(length - sets.length);
  for (let i = 0; i < fill.length; i++) {
    chars.push(pool[fill[i]! % pool.length]!);
  }
  for (let i = chars.length - 1; i > 0; i--) {
    const j = randomBytes(1)[0]! % (i + 1);
    [chars[i], chars[j]] = [chars[j]!, chars[i]!];
  }
  return chars.join("");
}
