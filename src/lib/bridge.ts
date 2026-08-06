/** Talk to the unlocked OpenKey desktop app over its local bridge socket. */

import { createConnection, type Socket } from "node:net";
import { existsSync, readFileSync } from "node:fs";
import { homedir, tmpdir, platform } from "node:os";
import { join } from "node:path";
import type { DecryptedSecret, SecretKindName } from "./types.js";
import { normalizeSecretKind, ReservedCollections } from "./types.js";
import { normalizeTotp } from "./totp.js";

export type BridgeResponse = {
  ok: boolean;
  unlocked?: boolean;
  error?: string;
  secrets?: Array<Record<string, unknown>>;
  secret?: Record<string, unknown>;
  entries?: Array<Record<string, unknown>>;
  entry?: Record<string, unknown> | null;
};

function socketCandidates(): string[] {
  const override = process.env.OPENKEY_NATIVE_SOCKET?.trim();
  if (override) return [override];

  const home = homedir();
  const runtime = process.env.XDG_RUNTIME_DIR?.trim();
  const tmp = process.env.TMPDIR?.trim() || tmpdir();
  const support = join(home, "Library", "Application Support");

  return [
    join(
      home,
      "Library",
      "Containers",
      "com.openselfhosting.openkey",
      "Data",
      "tmp",
      "openkey-native.sock",
    ),
    join(tmp, "openkey-native.sock"),
    join(tmp, "ok.sock"),
    "/tmp/openkey-native.sock",
    "/tmp/ok.sock",
    runtime ? join(runtime, "openkey-native.sock") : "",
    join(support, "com.openselfhosting.openkey", "openkey-native.sock"),
    join(support, "OpenKey", "openkey-native.sock"),
    join(support, "openkey_app", "openkey-native.sock"),
    join(home, ".local", "share", "OpenKey", "openkey-native.sock"),
    join(home, ".local", "share", "openkey_app", "openkey-native.sock"),
  ].filter(Boolean);
}

function resolveUnixSocket(): string | null {
  for (const path of socketCandidates()) {
    if (existsSync(path)) return path;
  }
  return null;
}

function windowsPort(): number | null {
  const override = process.env.OPENKEY_NATIVE_PORT?.trim();
  if (override) {
    const n = Number(override);
    return Number.isFinite(n) ? n : null;
  }
  const local = process.env.LOCALAPPDATA?.trim();
  if (!local) return null;
  const portFile = join(local, "OpenKey", "openkey-native.port");
  if (!existsSync(portFile)) return null;
  try {
    const n = Number(readFileSync(portFile, "utf8").trim());
    return Number.isFinite(n) ? n : null;
  } catch {
    return null;
  }
}

function readExact(socket: Socket, length: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let got = 0;
    const onData = (chunk: Buffer) => {
      chunks.push(chunk);
      got += chunk.length;
      if (got >= length) {
        cleanup();
        const buf = Buffer.concat(chunks);
        resolve(buf.subarray(0, length));
        if (buf.length > length) {
          socket.unshift(buf.subarray(length));
        }
      }
    };
    const onError = (err: Error) => {
      cleanup();
      reject(err);
    };
    const onClose = () => {
      cleanup();
      reject(new Error("Connection closed"));
    };
    const cleanup = () => {
      socket.off("data", onData);
      socket.off("error", onError);
      socket.off("close", onClose);
    };
    socket.on("data", onData);
    socket.on("error", onError);
    socket.on("close", onClose);
  });
}

async function requestOverSocket(
  connect: () => Socket,
  msg: Record<string, unknown>,
  timeoutMs = 2500,
): Promise<BridgeResponse> {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (value: BridgeResponse) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        socket.destroy();
      } catch {
        /* ignore */
      }
      resolve(value);
    };

    let socket: Socket;
    try {
      socket = connect();
    } catch (e) {
      resolve({ ok: false, error: String(e) });
      return;
    }

    const timer = setTimeout(() => {
      finish({ ok: false, error: "OpenKey app bridge timeout" });
    }, timeoutMs);

    socket.setTimeout(timeoutMs);
    socket.on("error", (err) => {
      finish({ ok: false, error: err.message });
    });
    socket.on("timeout", () => {
      finish({ ok: false, error: "OpenKey app bridge timeout" });
    });

    socket.on("connect", () => {
      void (async () => {
        try {
          const encoded = Buffer.from(JSON.stringify(msg), "utf8");
          const header = Buffer.alloc(4);
          header.writeUInt32LE(encoded.length, 0);
          socket.write(Buffer.concat([header, encoded]));

          const lenBuf = await readExact(socket, 4);
          const length = lenBuf.readUInt32LE(0);
          if (length <= 0 || length > 16 * 1024 * 1024) {
            finish({ ok: false, error: "Invalid response length" });
            return;
          }
          const payload = await readExact(socket, length);
          const data = JSON.parse(payload.toString("utf8")) as BridgeResponse;
          finish(data);
        } catch (e) {
          finish({
            ok: false,
            error: e instanceof Error ? e.message : String(e),
          });
        }
      })();
    });
  });
}

export async function bridgeRequest(
  msg: Record<string, unknown>,
  timeoutMs = 2500,
): Promise<BridgeResponse> {
  if (platform() === "win32") {
    const port = windowsPort();
    if (!port) {
      return {
        ok: false,
        error: "OpenKey desktop app is not running or the vault is locked",
      };
    }
    return requestOverSocket(
      () => createConnection({ host: "127.0.0.1", port }),
      msg,
      timeoutMs,
    );
  }

  const path = resolveUnixSocket();
  if (!path) {
    return {
      ok: false,
      error: "OpenKey desktop app is not running or the vault is locked",
    };
  }
  return requestOverSocket(() => createConnection(path), msg, timeoutMs);
}

export async function tryBridgePing(): Promise<boolean> {
  const res = await bridgeRequest({ type: "ping" });
  return res.ok === true && res.unlocked === true;
}

export function mapBridgeSecret(raw: Record<string, unknown>): DecryptedSecret {
  return {
    kind: "secret",
    type: "secret",
    uuid: String(raw.uuid ?? ""),
    collectionUuid:
      (raw.collectionUuid as string | null | undefined) ??
      ReservedCollections.secrets,
    revision: Number(raw.revision ?? 1),
    name: String(raw.name ?? ""),
    secretKind: normalizeSecretKind(
      String(raw.secretKind ?? raw.kind ?? "other"),
    ),
    username: String(raw.username ?? ""),
    host: String(raw.host ?? ""),
    publicKey: String(raw.publicKey ?? ""),
    secret: String(raw.secret ?? ""),
    passphrase: String(raw.passphrase ?? ""),
    notes: String(raw.notes ?? ""),
    device: String(raw.device ?? ""),
  };
}

export type BridgeCreateSecretInput = {
  name: string;
  kind?: SecretKindName | string;
  username?: string;
  host?: string;
  publicKey?: string;
  secret?: string;
  passphrase?: string;
  notes?: string;
  device?: string;
};

export async function bridgeListSecrets(): Promise<DecryptedSecret[]> {
  const res = await bridgeRequest({ type: "listSecrets" }, 5000);
  if (!res.ok) {
    throw new Error(res.error || "Failed to list secrets from OpenKey app");
  }
  return (res.secrets ?? []).map(mapBridgeSecret);
}

export async function bridgeCreateSecret(
  input: BridgeCreateSecretInput,
): Promise<DecryptedSecret> {
  const res = await bridgeRequest(
    {
      type: "createSecret",
      secret: {
        name: input.name,
        kind: input.kind ?? "apiToken",
        username: input.username ?? "",
        host: input.host ?? "",
        publicKey: input.publicKey ?? "",
        secret: input.secret ?? "",
        passphrase: input.passphrase ?? "",
        notes: input.notes ?? "",
        device: input.device ?? "",
      },
    },
    5000,
  );
  if (!res.ok || !res.secret) {
    throw new Error(res.error || "Failed to create secret in OpenKey app");
  }
  return mapBridgeSecret(res.secret);
}

export type BridgeUpdateSecretInput = BridgeCreateSecretInput & {
  uuid: string;
  /** Only keys present are sent; omitted fields keep existing values in the app. */
  patch?: Partial<{
    name: string;
    kind: string;
    username: string;
    host: string;
    publicKey: string;
    secret: string;
    passphrase: string;
    notes: string;
    device: string;
  }>;
};

export async function bridgeUpdateSecret(
  input: BridgeUpdateSecretInput,
): Promise<DecryptedSecret> {
  const patch = input.patch ?? {
    name: input.name,
    kind: input.kind ?? "apiToken",
    username: input.username ?? "",
    host: input.host ?? "",
    publicKey: input.publicKey ?? "",
    secret: input.secret ?? "",
    passphrase: input.passphrase ?? "",
    notes: input.notes ?? "",
    device: input.device ?? "",
  };
  const res = await bridgeRequest(
    {
      type: "updateSecret",
      uuid: input.uuid,
      secret: patch,
    },
    5000,
  );
  if (!res.ok || !res.secret) {
    throw new Error(res.error || "Failed to update secret in OpenKey app");
  }
  return mapBridgeSecret(res.secret);
}

export async function bridgeDeleteSecret(uuid: string): Promise<void> {
  const res = await bridgeRequest({ type: "deleteSecret", uuid }, 5000);
  if (!res.ok) {
    throw new Error(res.error || "Failed to delete secret in OpenKey app");
  }
}

export async function bridgeListLogins(): Promise<
  Array<{
    kind: "login";
    uuid: string;
    collectionUuid: string | null;
    revision: number;
    title: string;
    username: string;
    password: string;
    urls: string[];
    notes: string;
    totp?: {
      secret: string;
      period?: number;
      digits?: number;
      algorithm?: string;
    } | null;
  }>
> {
  const res = await bridgeRequest({ type: "listEntries" }, 5000);
  if (!res.ok) {
    throw new Error(res.error || "Failed to list logins from OpenKey app");
  }
  return (res.entries ?? []).map((e) => ({
    kind: "login" as const,
    uuid: String(e.uuid ?? ""),
    collectionUuid: (e.collectionUuid as string | null | undefined) ?? null,
    revision: Number(e.revision ?? 1),
    title: String(e.title ?? ""),
    username: String(e.username ?? ""),
    password: String(e.password ?? ""),
    urls: Array.isArray(e.urls) ? (e.urls as string[]) : [],
    notes: String(e.notes ?? ""),
    totp: normalizeTotp(e.totp),
  }));
}
