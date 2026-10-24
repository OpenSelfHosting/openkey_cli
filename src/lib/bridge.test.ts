import { afterEach, describe, expect, it } from "vitest";
import { createServer } from "node:net";
import { homedir } from "node:os";
import { join } from "node:path";
import {
  bridgeRequest,
  mapBridgeSecret,
  socketCandidates,
  usesLoopbackTcp,
} from "./bridge.js";

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

describe("usesLoopbackTcp", () => {
  const original = process.env.OPENKEY_NATIVE_PORT;

  afterEach(() => {
    if (original === undefined) delete process.env.OPENKEY_NATIVE_PORT;
    else process.env.OPENKEY_NATIVE_PORT = original;
  });

  it("uses Unix sockets on non-Windows when OPENKEY_NATIVE_PORT is unset", () => {
    delete process.env.OPENKEY_NATIVE_PORT;
    if (process.platform === "win32") return;
    expect(usesLoopbackTcp()).toBe(false);
  });

  it("uses TCP when OPENKEY_NATIVE_PORT is set (Termux)", () => {
    process.env.OPENKEY_NATIVE_PORT = "47830";
    expect(usesLoopbackTcp()).toBe(true);
  });
});

describe("socketCandidates", () => {
  const originalDataHome = process.env.XDG_DATA_HOME;
  const originalConfigHome = process.env.XDG_CONFIG_HOME;

  afterEach(() => {
    if (originalDataHome === undefined) delete process.env.XDG_DATA_HOME;
    else process.env.XDG_DATA_HOME = originalDataHome;

    if (originalConfigHome === undefined) delete process.env.XDG_CONFIG_HOME;
    else process.env.XDG_CONFIG_HOME = originalConfigHome;
  });

  it("includes config and data directories used by the desktop app", () => {
    const home = homedir();
    const dataHome = join(home, ".local", "share");
    const configHome = join(home, ".config");

    expect(socketCandidates()).toContain(join(dataHome, "openkey_app", "openkey-native.sock"));
    expect(socketCandidates()).toContain(join(configHome, "OpenKey", "openkey-native.sock"));
  });

  it("prefers XDG_CONFIG_HOME and XDG_DATA_HOME when present", () => {
    const configHome = "/tmp/openkey-config";
    const dataHome = "/tmp/openkey-data";
    process.env.XDG_CONFIG_HOME = configHome;
    process.env.XDG_DATA_HOME = dataHome;

    expect(socketCandidates()).toContain(join(configHome, "openkey_app", "openkey-native.sock"));
    expect(socketCandidates()).toContain(join(dataHome, "OpenKey", "openkey-native.sock"));
  });
});

describe("bridgeRequest", () => {
  it("reads a response when its header and payload arrive together", async () => {
    const originalPort = process.env.OPENKEY_NATIVE_PORT;
    const server = createServer((socket) => {
      socket.once("data", () => {
        const payload = Buffer.from(
          JSON.stringify({ ok: true, unlocked: true }),
          "utf8",
        );
        const header = Buffer.alloc(4);
        header.writeUInt32LE(payload.length, 0);
        socket.end(Buffer.concat([header, payload]));
      });
    });

    try {
      await new Promise<void>((resolve) => {
        server.listen(0, "127.0.0.1", resolve);
      });
      const address = server.address();
      if (!address || typeof address === "string") {
        throw new Error("Could not determine test bridge port");
      }
      process.env.OPENKEY_NATIVE_PORT = String(address.port);

      await expect(bridgeRequest({ type: "ping" })).resolves.toEqual({
        ok: true,
        unlocked: true,
      });
    } finally {
      if (originalPort === undefined) delete process.env.OPENKEY_NATIVE_PORT;
      else process.env.OPENKEY_NATIVE_PORT = originalPort;
      await new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      });
    }
  });
});
