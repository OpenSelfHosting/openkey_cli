/** Talk to the unlocked OpenKey desktop app over its local bridge socket. */

import { createConnection, type Socket } from "node:net";
import { existsSync, readFileSync } from "node:fs";
import { homedir, tmpdir, platform } from "node:os";
import { dirname, join } from "node:path";
import type {
  DecryptedCard,
  DecryptedCrypto,
  DecryptedLogin,
  DecryptedSecret,
  SecretKindName,
} from "./types.js";
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
  cards?: Array<Record<string, unknown>>;
  wallets?: Array<Record<string, unknown>>;
};

export function socketCandidates(): string[] {
  const override = process.env.OPENKEY_NATIVE_SOCKET?.trim();
  if (override) return [override];

  const home = homedir();
  const runtime = process.env.XDG_RUNTIME_DIR?.trim();
  const tmp = process.env.TMPDIR?.trim() || tmpdir();
  const dataHome = process.env.XDG_DATA_HOME?.trim() || join(home, ".local", "share");
  const configHome = process.env.XDG_CONFIG_HOME?.trim() || join(home, ".config");
  const support = join(home, "Library", "Application Support");
  const flatpakData = join(home, ".var", "app", "com.openselfhosting.openkey", "data");
  const flatpakConfig = join(home, ".var", "app", "com.openselfhosting.openkey", "config");

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
    join(dataHome, "OpenKey", "openkey-native.sock"),
    join(dataHome, "openkey_app", "openkey-native.sock"),
    join(configHome, "OpenKey", "openkey-native.sock"),
    join(configHome, "openkey_app", "openkey-native.sock"),
    join(flatpakData, "openkey-native.sock"),
    join(flatpakConfig, "openkey-native.sock"),
    join(home, ".local", "share", "OpenKey", "openkey-native.sock"),
    join(home, ".local", "share", "openkey_app", "openkey-native.sock"),
    join(home, ".config", "OpenKey", "openkey-native.sock"),
    join(home, ".config", "openkey_app", "openkey-native.sock"),
  ].filter(Boolean);
}

function resolveUnixSocket(): string | null {
  for (const path of socketCandidates()) {
    if (existsSync(path)) return path;
  }
  return null;
}

function resolveBridgeToken(socketPath?: string): string | undefined {
  const override = process.env.OPENKEY_NATIVE_TOKEN?.trim();
  if (override) return override;

  const home = homedir();
  const dataHome = process.env.XDG_DATA_HOME?.trim() || join(home, ".local", "share");
  const configHome = process.env.XDG_CONFIG_HOME?.trim() || join(home, ".config");

  if (platform() === "win32") {
    const local = process.env.LOCALAPPDATA?.trim();
    if (local) {
      const tokenFile = join(local, "OpenKey", "openkey-native.token");
      if (existsSync(tokenFile)) {
        return readFileSync(tokenFile, "utf8").trim() || undefined;
      }
    }
  }

  const dirs = new Set<string>();
  if (socketPath) dirs.add(dirname(socketPath));
  for (const socketPath of socketCandidates()) {
    dirs.add(dirname(socketPath));
  }
  for (const dir of [
    join(dataHome, "OpenKey"),
    join(dataHome, "openkey_app"),
    join(configHome, "OpenKey"),
    join(configHome, "openkey_app"),
    join(home, ".local", "share", "OpenKey"),
    join(home, ".local", "share", "openkey_app"),
    join(home, ".config", "OpenKey"),
    join(home, ".config", "openkey_app"),
    join(home, ".var", "app", "com.openselfhosting.openkey", "data"),
    join(home, ".var", "app", "com.openselfhosting.openkey", "config"),
  ]) {
    dirs.add(dir);
  }

  for (const dir of dirs) {
    const tokenFile = join(dir, "openkey-native.token");
    if (existsSync(tokenFile)) {
      return readFileSync(tokenFile, "utf8").trim() || undefined;
    }
  }

  return undefined;
}

function withBridgeAuth(
  msg: Record<string, unknown>,
  token?: string,
): Record<string, unknown> {
  if (!token) return msg;
  return { ...msg, auth: token };
}

function loopbackPort(): number | null {
  const override = process.env.OPENKEY_NATIVE_PORT?.trim();
  if (override) {
    const n = Number(override);
    return Number.isFinite(n) ? n : null;
  }
  return windowsPort();
}

/** True when the CLI should speak loopback TCP (Windows, or Termux via env). */
export function usesLoopbackTcp(): boolean {
  return (
    platform() === "win32" || Boolean(process.env.OPENKEY_NATIVE_PORT?.trim())
  );
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
      const chunks: Buffer[] = [];
      let received = 0;
      const responseHeader = Buffer.alloc(4);
      let headerBytes = 0;
      let expectedLength: number | null = null;
      const onData = (chunk: Buffer) => {
        if (headerBytes < 4) {
          const copied = Math.min(4 - headerBytes, chunk.length);
          chunk.copy(responseHeader, headerBytes, 0, copied);
          headerBytes += copied;
        }
        chunks.push(chunk);
        received += chunk.length;

        if (expectedLength === null && headerBytes === 4) {
          expectedLength = responseHeader.readUInt32LE(0);
          if (expectedLength <= 0 || expectedLength > 16 * 1024 * 1024) {
            finish({ ok: false, error: "Invalid response length" });
            return;
          }
        }

        if (expectedLength !== null && received >= expectedLength + 4) {
          socket.off("data", onData);
          try {
            const frame = Buffer.concat(chunks, received);
            const data = JSON.parse(
              frame.subarray(4, expectedLength + 4).toString("utf8"),
            ) as BridgeResponse;
            finish(data);
          } catch (e) {
            finish({
              ok: false,
              error: e instanceof Error ? e.message : String(e),
            });
          }
        }
      };
      socket.on("data", onData);

      try {
        const encoded = Buffer.from(JSON.stringify(msg), "utf8");
        const header = Buffer.alloc(4);
        header.writeUInt32LE(encoded.length, 0);
        socket.write(Buffer.concat([header, encoded]));
      } catch (e) {
        finish({
          ok: false,
          error: e instanceof Error ? e.message : String(e),
        });
      }
    });
  });
}

export async function bridgeRequest(
  msg: Record<string, unknown>,
  timeoutMs = 2500,
): Promise<BridgeResponse> {
  if (usesLoopbackTcp()) {
    const port = loopbackPort();
    if (!port) {
      return {
        ok: false,
        error: "OpenKey app is not running or the vault is locked",
      };
    }
    const token = resolveBridgeToken();
    return requestOverSocket(
      () => createConnection({ host: "127.0.0.1", port }),
      withBridgeAuth(msg, token),
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
  const token = resolveBridgeToken(path);
  return requestOverSocket(
    () => createConnection(path),
    withBridgeAuth(msg, token),
    timeoutMs,
  );
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

export async function bridgeListLogins(): Promise<DecryptedLogin[]> {
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
    tags: Array.isArray(e.tags) ? (e.tags as string[]) : [],
    totp: normalizeTotp(e.totp),
  }));
}

export async function bridgeListCards(): Promise<DecryptedCard[]> {
  const res = await bridgeRequest({ type: "listCards" }, 5000);
  if (!res.ok) {
    throw new Error(res.error || "Failed to list cards from OpenKey app");
  }
  return (res.cards ?? []).map((c) => ({
    kind: "card" as const,
    type: "card" as const,
    uuid: String(c.uuid ?? ""),
    collectionUuid:
      (c.collectionUuid as string | null | undefined) ??
      ReservedCollections.wallets,
    revision: Number(c.revision ?? 1),
    name: String(c.name ?? ""),
    holder: String(c.holder ?? ""),
    number: String(c.number ?? ""),
    expiry: String(c.expiry ?? ""),
    cvc: String(c.cvc ?? ""),
    brand: String(c.brand ?? ""),
    notes: String(c.notes ?? ""),
    bank: String(c.bank ?? ""),
  }));
}

export async function bridgeListCrypto(): Promise<DecryptedCrypto[]> {
  const res = await bridgeRequest({ type: "listCrypto" }, 5000);
  if (!res.ok) {
    throw new Error(
      res.error || "Failed to list crypto wallets from OpenKey app",
    );
  }
  return (res.wallets ?? []).map((w) => ({
    kind: "crypto" as const,
    type: "crypto" as const,
    uuid: String(w.uuid ?? ""),
    collectionUuid:
      (w.collectionUuid as string | null | undefined) ??
      ReservedCollections.crypto,
    revision: Number(w.revision ?? 1),
    name: String(w.name ?? ""),
    network: String(w.network ?? ""),
    address: String(w.address ?? ""),
    privateKey: String(w.privateKey ?? ""),
    seedPhrase: String(w.seedPhrase ?? ""),
    notes: String(w.notes ?? ""),
    folder: String(w.folder ?? ""),
  }));
}
