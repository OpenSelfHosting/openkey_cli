import { describe, expect, it } from "vitest";
import {
  envKeyFromName,
  formatSecretsExport,
  listDevices,
} from "./export.js";
import type { DecryptedSecret } from "./types.js";

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
    secret: "token-value",
    passphrase: "",
    notes: "",
    device: "laptop",
    ...partial,
  };
}

describe("envKeyFromName", () => {
  it("normalizes names", () => {
    expect(envKeyFromName("GitHub PAT")).toBe("GITHUB_PAT");
    expect(envKeyFromName("9lives")).toBe("_9LIVES");
  });
});

describe("formatSecretsExport", () => {
  it("exports api tokens as KEY=value and env snippets as bodies", () => {
    const text = formatSecretsExport([
      secret({
        uuid: "1",
        name: "DATABASE_URL",
        secret: "postgres://x",
        device: "laptop",
      }),
      secret({
        uuid: "2",
        name: "app .env",
        secretKind: "envSnippet",
        secret: "FOO=1\nBAR=2\n",
        device: "laptop",
      }),
    ]);
    expect(text).toContain("DATABASE_URL=postgres://x");
    expect(text).toContain("FOO=1\nBAR=2");
    expect(text).toContain("# app .env");
  });

  it("filters by device and kind", () => {
    const secrets = [
      secret({ uuid: "1", name: "A", device: "a", secret: "aaa" }),
      secret({ uuid: "2", name: "B", device: "b", secret: "bbb" }),
    ];
    const text = formatSecretsExport(secrets, { device: "b" });
    expect(text).toContain("B=bbb");
    expect(text).not.toContain("A=aaa");
  });

  it("exports shell export lines", () => {
    const text = formatSecretsExport(
      [secret({ uuid: "1", name: "TOKEN", secret: "a'b" })],
      { format: "exports" },
    );
    expect(text).toContain("export TOKEN='a'\\''b'");
  });
});

describe("listDevices", () => {
  it("groups and counts", () => {
    const devices = listDevices([
      secret({ uuid: "1", name: "a", device: "x" }),
      secret({ uuid: "2", name: "b", device: "x" }),
      secret({ uuid: "3", name: "c", device: "" }),
    ]);
    expect(devices).toEqual([
      { device: "(ungrouped)", count: 1 },
      { device: "x", count: 2 },
    ]);
  });
});
