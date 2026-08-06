import { describe, expect, it } from "vitest";
import { mapBridgeSecret } from "./bridge.js";

describe("mapBridgeSecret", () => {
  it("maps native host payload", () => {
    const secret = mapBridgeSecret({
      uuid: "abc",
      name: "PAT",
      secretKind: "apiToken",
      host: "github.com",
      secret: "ghp_x",
      username: "",
      publicKey: "",
      passphrase: "",
      notes: "n",
      revision: 2,
    });
    expect(secret.kind).toBe("secret");
    expect(secret.name).toBe("PAT");
    expect(secret.secretKind).toBe("apiToken");
    expect(secret.secret).toBe("ghp_x");
    expect(secret.revision).toBe(2);
  });

  it("defaults missing fields and normalizes kind aliases", () => {
    const secret = mapBridgeSecret({
      name: "SSH",
      kind: "ssh_key",
    });
    expect(secret.uuid).toBe("");
    expect(secret.secretKind).toBe("sshKey");
    expect(secret.revision).toBe(1);
    expect(secret.host).toBe("");
    expect(secret.collectionUuid).toBe("__dev_secrets__");
  });

  it("prefers secretKind over kind when both present", () => {
    const secret = mapBridgeSecret({
      uuid: "1",
      name: "x",
      secretKind: "envSnippet",
      kind: "apiToken",
    });
    expect(secret.secretKind).toBe("envSnippet");
  });
});
