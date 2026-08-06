import type { CliConfig, StoredCollection, StoredEntry } from "./types.js";
import { loadConfig, saveConfig } from "./store.js";

type TokenPair = {
  access_token: string;
  refresh_token: string;
  user_id: string;
};

type JsonValue = Record<string, unknown> | unknown[] | null;

async function rawRequest(
  cfg: CliConfig,
  method: string,
  path: string,
  body?: unknown,
  auth = false,
): Promise<{ ok: boolean; status: number; data: JsonValue }> {
  const root = cfg.serverUrl.replace(/\/$/, "");
  const headers: Record<string, string> = { Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (auth && cfg.accessToken) {
    headers.Authorization = `Bearer ${cfg.accessToken}`;
  }
  const res = await fetch(`${root}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (res.status === 204) return { ok: res.ok, status: res.status, data: {} };
  const text = await res.text();
  let data: JsonValue = {};
  if (text) {
    try {
      data = JSON.parse(text) as JsonValue;
    } catch {
      data = { detail: text };
    }
  }
  return { ok: res.ok, status: res.status, data };
}

async function tryRefresh(cfg: CliConfig): Promise<CliConfig | null> {
  if (!cfg.refreshToken) return null;
  const { ok, data } = await rawRequest(cfg, "POST", "/auth/refresh", {
    refresh_token: cfg.refreshToken,
  });
  if (!ok || !data || Array.isArray(data)) return null;
  return saveConfig({
    accessToken: data.access_token as string,
    refreshToken: data.refresh_token as string,
  });
}

async function request(
  cfg: CliConfig,
  method: string,
  path: string,
  body?: unknown,
  auth = false,
): Promise<JsonValue> {
  let current = cfg;
  let result = await rawRequest(current, method, path, body, auth);
  if (auth && result.status === 401) {
    const refreshed = await tryRefresh(current);
    if (refreshed) {
      current = refreshed;
      result = await rawRequest(current, method, path, body, auth);
    }
  }
  if (!result.ok) {
    const detailObj = result.data;
    const detail =
      (!Array.isArray(detailObj) && detailObj
        ? (detailObj.detail as string) || (detailObj.message as string)
        : null) || `HTTP ${result.status}`;
    throw new Error(typeof detail === "string" ? detail : `HTTP ${result.status}`);
  }
  return result.data;
}

function asRecord(data: JsonValue): Record<string, unknown> {
  if (data && !Array.isArray(data)) return data;
  return {};
}

function tokenPairFrom(data: Record<string, unknown>): TokenPair {
  return {
    access_token: data.access_token as string,
    refresh_token: data.refresh_token as string,
    user_id: String(data.user_id),
  };
}

export async function login(
  cfg: CliConfig,
  email: string,
  authHash: string,
): Promise<TokenPair> {
  const data = asRecord(
    await request(cfg, "POST", "/auth/login", { email, auth_hash: authHash }),
  );
  return tokenPairFrom(data);
}

export async function prelogin(
  cfg: CliConfig,
  email: string,
): Promise<{ salt: string; kdf_params: Record<string, unknown> }> {
  const data = asRecord(await request(cfg, "POST", "/auth/prelogin", { email }));
  return {
    salt: data.salt as string,
    kdf_params: (data.kdf_params as Record<string, unknown>) ?? {},
  };
}

export type MeResponse = {
  salt: string;
  encrypted_vault_key: string;
  kdf_params: Record<string, unknown>;
  email: string;
};

export async function fetchVaultMaterial(cfg: CliConfig): Promise<MeResponse> {
  const data = asRecord(await request(cfg, "GET", "/auth/me", undefined, true));
  return {
    salt: data.salt as string,
    encrypted_vault_key: data.encrypted_vault_key as string,
    kdf_params: (data.kdf_params as Record<string, unknown>) ?? {},
    email: data.email as string,
  };
}

function mapEntry(e: Record<string, unknown>): StoredEntry {
  return {
    uuid: e.uuid as string,
    collectionUuid: (e.collection_uuid as string) ?? null,
    encryptedPayload: e.encrypted_payload as string,
    revision: (e.revision as number) ?? 1,
    isDeleted: (e.is_deleted as boolean) ?? false,
    updatedAt: (e.updated_at as string) ?? new Date().toISOString(),
  };
}

function mapCollection(c: Record<string, unknown>): StoredCollection {
  return {
    uuid: c.uuid as string,
    encryptedName: c.encrypted_name as string,
    icon: (c.icon as string) ?? "material:folder",
    color: (c.color as number) ?? null,
    parentUuid: (c.parent_uuid as string) ?? null,
    sortOrder: (c.sort_order as number) ?? 0,
    revision: (c.revision as number) ?? 1,
    isDeleted: (c.is_deleted as boolean) ?? false,
    updatedAt: (c.updated_at as string) ?? new Date().toISOString(),
  };
}

export async function syncWith(
  cfg: CliConfig,
  push: {
    collections?: Array<{
      uuid: string;
      encrypted_name: string;
      icon?: string;
      color?: number | null;
      parent_uuid?: string | null;
      sort_order?: number;
      revision: number;
      is_deleted: boolean;
    }>;
    entries?: Array<{
      uuid: string;
      collection_uuid: string | null;
      encrypted_payload: string;
      revision: number;
      is_deleted: boolean;
    }>;
  },
): Promise<{
  entries: StoredEntry[];
  collections: StoredCollection[];
  serverRevision: number;
}> {
  const data = asRecord(
    await request(
      cfg,
      "POST",
      "/sync",
      {
        since_revision: cfg.serverRevision,
        collections: push.collections ?? [],
        entries: push.entries ?? [],
      },
      true,
    ),
  );
  const entries = ((data.entries as Record<string, unknown>[]) ?? []).map(mapEntry);
  const collections = ((data.collections as Record<string, unknown>[]) ?? []).map(
    mapCollection,
  );
  const serverRevision =
    typeof data.server_revision === "number" ? data.server_revision : cfg.serverRevision;
  return { entries, collections, serverRevision };
}

export async function syncPull(cfg: CliConfig) {
  return syncWith(cfg, { collections: [], entries: [] });
}

export async function syncPushEntries(cfg: CliConfig, entries: StoredEntry[]) {
  return syncWith(cfg, {
    entries: entries.map((e) => ({
      uuid: e.uuid,
      collection_uuid: e.collectionUuid,
      encrypted_payload: e.encryptedPayload,
      revision: e.revision,
      is_deleted: e.isDeleted,
    })),
  });
}

/** Ensure we have a fresh config with tokens (reload after refresh). */
export async function activeConfig(): Promise<CliConfig> {
  return loadConfig();
}
