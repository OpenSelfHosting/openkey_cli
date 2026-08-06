/** TOTP helpers matching openkey_extension (HMAC-SHA1/256/512 + base32). */

import { hmac } from "@noble/hashes/hmac";
import { sha1 } from "@noble/hashes/sha1";
import { sha256, sha512 } from "@noble/hashes/sha2";

export type TotpConfig = {
  secret: string;
  period?: number;
  digits?: number;
  algorithm?: "SHA1" | "SHA256" | "SHA512" | string;
};

export function base32Decode(input: string): Uint8Array {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const cleaned = input.replace(/=+$/, "").replace(/\s+/g, "").toUpperCase();
  let bits = "";
  for (const c of cleaned) {
    const val = alphabet.indexOf(c);
    if (val < 0) continue;
    bits += val.toString(2).padStart(5, "0");
  }
  const bytes: number[] = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  return new Uint8Array(bytes);
}

function hotp(
  secret: Uint8Array,
  counter: number,
  digits: number,
  algo: string,
): string {
  const buf = new ArrayBuffer(8);
  const view = new DataView(buf);
  view.setUint32(0, 0);
  view.setUint32(4, counter >>> 0);
  const counterBytes = new Uint8Array(buf);
  const a = algo.toUpperCase();
  const hashFn = a === "SHA256" ? sha256 : a === "SHA512" ? sha512 : sha1;
  const digest = hmac(hashFn, secret, counterBytes);
  const offset = digest[digest.length - 1]! & 0x0f;
  const bin =
    ((digest[offset]! & 0x7f) << 24) |
    ((digest[offset + 1]! & 0xff) << 16) |
    ((digest[offset + 2]! & 0xff) << 8) |
    (digest[offset + 3]! & 0xff);
  const mod = 10 ** digits;
  return (bin % mod).toString().padStart(digits, "0");
}

export function generateTotp(config: TotpConfig, now = Date.now()): string {
  const period = config.period ?? 30;
  const digits = config.digits ?? 6;
  const algo = (config.algorithm ?? "SHA1").toString();
  const secret = base32Decode(config.secret);
  if (!secret.length) throw new Error("Invalid TOTP secret");
  const counter = Math.floor(now / 1000 / period);
  return hotp(secret, counter, digits, algo);
}

/** Seconds remaining in the current TOTP window. */
export function totpRemaining(period = 30, now = Date.now()): number {
  const p = period > 0 ? period : 30;
  return p - (Math.floor(now / 1000) % p);
}

export function parseOtpAuth(uri: string): TotpConfig | null {
  try {
    const url = new URL(uri);
    if (url.protocol !== "otpauth:") return null;
    const secret = url.searchParams.get("secret");
    if (!secret) return null;
    return {
      secret,
      period: Number(url.searchParams.get("period") ?? 30),
      digits: Number(url.searchParams.get("digits") ?? 6),
      algorithm: (url.searchParams.get("algorithm") ?? "SHA1").toUpperCase(),
    };
  } catch {
    return null;
  }
}

/** Normalize vault / bridge totp payloads (object, otpauth URI, or bare secret). */
export function normalizeTotp(raw: unknown): TotpConfig | null {
  if (raw == null) return null;
  if (typeof raw === "string") {
    const s = raw.trim();
    if (!s) return null;
    if (s.toLowerCase().startsWith("otpauth://")) return parseOtpAuth(s);
    return { secret: s.replace(/\s+/g, "") };
  }
  if (typeof raw === "object") {
    const o = raw as Record<string, unknown>;
    const secret = String(o.secret ?? "").trim();
    if (!secret) return null;
    return {
      secret: secret.replace(/\s+/g, ""),
      period: o.period != null ? Number(o.period) : 30,
      digits: o.digits != null ? Number(o.digits) : 6,
      algorithm: String(o.algorithm ?? "SHA1").toUpperCase(),
    };
  }
  return null;
}
