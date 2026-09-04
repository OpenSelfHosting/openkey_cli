import { describe, expect, it } from "vitest";
import type { DecryptedLogin, DecryptedSecret } from "./types.js";
import {
  itemLabel,
  matchQuery,
  parseEnvBinding,
  resolveOneMatch,
  shellSingleQuote,
} from "./vault.js";

function secret(
  partial: Partial<DecryptedSecret> & { name: string; uuid: string },
): DecryptedSecret {
  return {
    kind: "secret",
    type: "secret",
    collectionUuid: "__dev_secrets__",
    revision: 1,
    secretKind: "apiToken",
    username: "",
    host: "",
    publicKey: "",
    secret: "x",
    passphrase: "",
    notes: "",
    device: "dev",
    ...partial,
  };
}

function login(
  partial: Partial<DecryptedLogin> & { title: string; uuid: string },
): DecryptedLogin {
  return {
    kind: "login",
    collectionUuid: null,
    revision: 1,
    username: "",
    password: "p",
    urls: [],
    notes: "",
    ...partial,
  };
}

describe("resolveOneMatch", () => {
  const items = [
    secret({ uuid: "aaaaaaaa-1111-1111-1111-111111111111", name: "GitHub PAT" }),
    secret({
      uuid: "bbbbbbbb-2222-2222-2222-222222222222",
      name: "GitHub Actions",
      host: "github.com",
    }),
    login({ uuid: "cccccccc-3333-3333-3333-333333333333", title: "GitHub" }),
  ];

  it("returns the sole substring match", () => {
    expect(resolveOneMatch(items, "Actions").name).toBe("GitHub Actions");
  });

  it("prefers exact label when substrings collide", () => {
    const hit = resolveOneMatch(items, "GitHub");
    expect(itemLabel(hit)).toBe("GitHub");
    expect(hit.kind).toBe("login");
  });

  it("prefers exact secret name", () => {
    expect(resolveOneMatch(items, "GitHub PAT").name).toBe("GitHub PAT");
  });

  it("prefers unique UUID prefix (≥4 chars)", () => {
    expect(resolveOneMatch(items, "bbbb").uuid.startsWith("bbbb")).toBe(true);
  });

  it("throws on empty / no match / still-ambiguous", () => {
    expect(() => resolveOneMatch(items, "")).toThrow(/Empty/);
    expect(() => resolveOneMatch(items, "nope")).toThrow(/No item/);
    const twins = [
      secret({ uuid: "1", name: "Token A", host: "api" }),
      secret({ uuid: "2", name: "Token B", host: "api" }),
    ];
    expect(() => resolveOneMatch(twins, "Token")).toThrow(/Ambiguous/);
  });
});

describe("matchQuery", () => {
  it("matches secret device and kind", () => {
    const items = [
      secret({
        uuid: "1",
        name: "x",
        device: "laptop",
        secretKind: "sshKey",
      }),
    ];
    expect(matchQuery(items, "laptop")).toHaveLength(1);
    expect(matchQuery(items, "ssh")).toHaveLength(1);
  });
});

describe("parseEnvBinding", () => {
  it("parses NAME and NAME=query", () => {
    expect(parseEnvBinding("DATABASE_URL")).toEqual({
      envName: "DATABASE_URL",
      query: "DATABASE_URL",
    });
    expect(parseEnvBinding("DB=my database")).toEqual({
      envName: "DB",
      query: "my database",
    });
  });

  it("sanitizes bare names with spaces", () => {
    expect(parseEnvBinding("GitHub PAT")).toEqual({
      envName: "GITHUB_PAT",
      query: "GitHub PAT",
    });
  });

  it("rejects bad env names", () => {
    expect(() => parseEnvBinding("9BAD=x")).toThrow(/Invalid environment/);
    expect(() => parseEnvBinding("OK=")).toThrow(/Missing query/);
  });
});

describe("shellSingleQuote", () => {
  it("escapes embedded single quotes", () => {
    expect(shellSingleQuote("a'b")).toBe(`'a'\\''b'`);
  });
});

describe("parseItemField / itemFieldValue", () => {
  it("parses field names", async () => {
    const { parseItemField, itemFieldValue } = await import("./vault.js");
    expect(parseItemField("username")).toBe("username");
    expect(parseItemField("TOTP")).toBe("totp");
    expect(() => parseItemField("nope")).toThrow(/Unknown field/);

    const entry = login({
      uuid: "1",
      title: "Ex",
      username: "u",
      password: "p",
      urls: ["https://ex.com"],
      totp: { secret: "JBSWY3DPEHPK3PXP" },
    });
    expect(itemFieldValue(entry, "username")).toBe("u");
    expect(itemFieldValue(entry, "url")).toBe("https://ex.com");
    expect(itemFieldValue(entry, "totp")).toMatch(/^\d{6}$/);
  });

  it("labels cards and crypto", () => {
    const card: import("./types.js").DecryptedCard = {
      kind: "card",
      type: "card",
      uuid: "c1",
      collectionUuid: "__wallets__",
      revision: 1,
      name: "Visa Gold",
      holder: "A",
      number: "4111",
      expiry: "12/28",
      cvc: "123",
      brand: "visa",
      notes: "",
      bank: "Acme Bank",
    };
    const wallet: import("./types.js").DecryptedCrypto = {
      kind: "crypto",
      type: "crypto",
      uuid: "w1",
      collectionUuid: "__crypto_wallets__",
      revision: 1,
      name: "Hot",
      network: "ethereum",
      address: "0xabc",
      privateKey: "pk",
      seedPhrase: "",
      notes: "",
      folder: "Cold",
    };
    expect(itemLabel(card)).toBe("Visa Gold");
    expect(itemLabel(wallet)).toBe("Hot");
    expect(matchQuery([card, wallet], "acme")).toEqual([card]);
    expect(matchQuery([card, wallet], "cold")).toEqual([wallet]);
  });
});
