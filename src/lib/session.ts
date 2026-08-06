import { randomBytes } from "@noble/hashes/utils";
import {
  decryptString,
  encryptBytes,
  fromB64Url,
  toB64Url,
} from "./crypto.js";
import type { SessionPayload } from "./types.js";

const SESSION_ENV = "OPENKEY_SESSION";

export function encodeSession(payload: Omit<SessionPayload, "v">): string {
  const full: SessionPayload = { v: 1, ...payload };
  const key = randomBytes(32);
  const cipher = encryptBytes(key, new TextEncoder().encode(JSON.stringify(full)));
  const cipherBytes = fromB64Url(cipher);
  const combined = new Uint8Array(key.length + cipherBytes.length);
  combined.set(key, 0);
  combined.set(cipherBytes, key.length);
  return toB64Url(combined);
}

export function decodeSession(token: string): SessionPayload {
  const combined = fromB64Url(token);
  if (combined.length < 60) throw new Error("Invalid session token");
  const key = combined.slice(0, 32);
  const cipher = toB64Url(combined.slice(32));
  const json = decryptString(key, cipher);
  const payload = JSON.parse(json) as SessionPayload;
  if (payload.v !== 1 || !payload.vaultKeyB64 || !payload.email) {
    throw new Error("Invalid session token");
  }
  if (Date.now() > payload.expiresAt) {
    throw new Error("Session expired — run `openkey unlock` again");
  }
  return payload;
}

export function readSessionFromEnv(): SessionPayload | null {
  const raw = process.env[SESSION_ENV]?.trim();
  if (!raw) return null;
  try {
    return decodeSession(raw);
  } catch {
    return null;
  }
}

export function requireSession(): SessionPayload {
  const session = readSessionFromEnv();
  if (!session) {
    throw new Error(
      "Vault locked. Run `eval $(openkey unlock)` or set OPENKEY_SESSION.",
    );
  }
  return session;
}

export function vaultKeyFromSession(session: SessionPayload): Uint8Array {
  return fromB64Url(session.vaultKeyB64);
}

export function exportSessionShell(token: string): string {
  // Safe for eval: no secrets in cleartext beyond the opaque token
  const escaped = token.replace(/'/g, "'\\''");
  return `export ${SESSION_ENV}='${escaped}'`;
}

export { SESSION_ENV };
