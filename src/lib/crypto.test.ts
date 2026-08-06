import { describe, expect, it } from "vitest";
import {
  decryptString,
  deriveAuthHash,
  deriveMasterKey,
  encryptString,
  fromB64Url,
  generatePassword,
  generateSalt,
  generateVaultKey,
  toB64Url,
  unwrapVaultKey,
  wrapVaultKey,
} from "./crypto.js";
import { decodeSession, encodeSession } from "./session.js";
import { decryptItems } from "./vault.js";
import {
  ReservedCollections,
  normalizeSecretKind,
  type StoredEntry,
} from "./types.js";

describe("generatePassword", () => {
  it("respects length", () => {
    expect(generatePassword({ length: 24 }).length).toBe(24);
  });

  it("can generate digits-only", () => {
    const pw = generatePassword({
      length: 12,
      upper: false,
      lower: false,
      digits: true,
      symbols: false,
    });
    expect(pw).toMatch(/^\d+$/);
  });

  it("avoids ambiguous characters", () => {
    const ambiguous = /[Il1O0o]/;
    for (let i = 0; i < 20; i++) {
      const pw = generatePassword({
        length: 32,
        avoidAmbiguous: true,
      });
      expect(pw).not.toMatch(ambiguous);
    }
  });

  it("rejects invalid options", () => {
    expect(() =>
      generatePassword({
        length: 8,
        upper: false,
        lower: false,
        digits: false,
        symbols: false,
      }),
    ).toThrow();
    expect(() => generatePassword({ length: 3 })).toThrow();
  });
});

describe("crypto round-trip", () => {
  it("encrypts and decrypts strings", () => {
    const key = generateVaultKey();
    const cipher = encryptString(key, "hello openkey");
    expect(decryptString(key, cipher)).toBe("hello openkey");
  });

  it("wraps and unwraps vault key", async () => {
    const salt = generateSalt();
    const master = await deriveMasterKey("dev@example.com", "test-password-12", salt);
    const vault = generateVaultKey();
    const wrapped = await wrapVaultKey(master, vault);
    const unwrapped = await unwrapVaultKey(master, wrapped);
    expect(toB64Url(unwrapped)).toBe(toB64Url(vault));
    expect(deriveAuthHash(master).length).toBeGreaterThan(10);
  });
});

describe("session token", () => {
  it("round-trips session payload", () => {
    const token = encodeSession({
      email: "a@b.co",
      vaultKeyB64: toB64Url(generateVaultKey()),
      expiresAt: Date.now() + 60_000,
    });
    const decoded = decodeSession(token);
    expect(decoded.email).toBe("a@b.co");
    expect(decoded.v).toBe(1);
  });

  it("rejects expired sessions", () => {
    const token = encodeSession({
      email: "a@b.co",
      vaultKeyB64: toB64Url(generateVaultKey()),
      expiresAt: Date.now() - 1000,
    });
    expect(() => decodeSession(token)).toThrow(/expired/i);
  });
});

describe("secret payload decrypt", () => {
  it("decrypts secret entries from ciphertext", async () => {
    const key = generateVaultKey();
    const payload = {
      type: "secret",
      name: "GitHub PAT",
      kind: "apiToken",
      username: "",
      host: "github.com",
      publicKey: "",
      secret: "ghp_test_token",
      passphrase: "",
      notes: "",
    };
    const entry: StoredEntry = {
      uuid: "11111111-1111-1111-1111-111111111111",
      collectionUuid: ReservedCollections.secrets,
      encryptedPayload: encryptString(key, JSON.stringify(payload)),
      revision: 1,
      isDeleted: false,
      updatedAt: new Date().toISOString(),
    };
    const items = decryptItems(key, [entry]);
    expect(items).toHaveLength(1);
    const secret = items[0]!;
    expect(secret.kind).toBe("secret");
    if (secret.kind === "secret") {
      expect(secret.name).toBe("GitHub PAT");
      expect(secret.secret).toBe("ghp_test_token");
      expect(secret.secretKind).toBe("apiToken");
    }
  });
});

describe("normalizeSecretKind", () => {
  it("maps aliases", () => {
    expect(normalizeSecretKind("ssh")).toBe("sshKey");
    expect(normalizeSecretKind("api")).toBe("apiToken");
    expect(normalizeSecretKind(".env")).toBe("envSnippet");
    expect(normalizeSecretKind("xyz")).toBe("other");
  });
});

describe("b64url", () => {
  it("round-trips", () => {
    const bytes = fromB64Url(toB64Url(new Uint8Array([1, 2, 255, 0])));
    expect([...bytes]).toEqual([1, 2, 255, 0]);
  });
});
