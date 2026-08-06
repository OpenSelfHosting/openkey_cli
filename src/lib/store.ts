import { homedir } from "node:os";
import { join } from "node:path";
import { mkdir, readFile, writeFile, chmod } from "node:fs/promises";
import { existsSync } from "node:fs";
import {
  DEFAULT_CONFIG,
  type CliConfig,
  type StoredCollection,
  type StoredEntry,
} from "./types.js";

function configDir(): string {
  const xdg = process.env.XDG_CONFIG_HOME?.trim();
  if (xdg) return join(xdg, "openkey");
  if (process.platform === "darwin") {
    return join(homedir(), "Library", "Application Support", "OpenKey");
  }
  if (process.platform === "win32") {
    const appData = process.env.APPDATA?.trim() || join(homedir(), "AppData", "Roaming");
    return join(appData, "OpenKey");
  }
  return join(homedir(), ".config", "openkey");
}

export function configPath(): string {
  return join(configDir(), "config.json");
}

export async function loadConfig(): Promise<CliConfig> {
  const path = configPath();
  if (!existsSync(path)) return { ...DEFAULT_CONFIG, entries: [], collections: [] };
  try {
    const raw = await readFile(path, "utf8");
    const parsed = JSON.parse(raw) as Partial<CliConfig>;
    return {
      ...DEFAULT_CONFIG,
      ...parsed,
      entries: Array.isArray(parsed.entries) ? parsed.entries : [],
      collections: Array.isArray(parsed.collections) ? parsed.collections : [],
    };
  } catch {
    return { ...DEFAULT_CONFIG, entries: [], collections: [] };
  }
}

export async function saveConfig(patch: Partial<CliConfig>): Promise<CliConfig> {
  const current = await loadConfig();
  const next: CliConfig = {
    ...current,
    ...patch,
    entries: patch.entries ?? current.entries,
    collections: patch.collections ?? current.collections,
  };
  // Strip accidental unknown fields
  const dir = configDir();
  await mkdir(dir, { recursive: true });
  const path = configPath();
  await writeFile(path, JSON.stringify(next, null, 2), "utf8");
  try {
    await chmod(path, 0o600);
  } catch {
    /* Windows may not support chmod the same way */
  }
  return next;
}

export async function upsertEntries(incoming: StoredEntry[]): Promise<CliConfig> {
  const cfg = await loadConfig();
  const map = new Map(cfg.entries.map((e) => [e.uuid, e]));
  for (const e of incoming) {
    const prev = map.get(e.uuid);
    if (!prev || e.revision >= prev.revision) {
      map.set(e.uuid, e);
    }
  }
  const entries = [...map.values()].filter((e) => !e.isDeleted);
  return saveConfig({ entries });
}

export async function upsertCollections(
  incoming: StoredCollection[],
): Promise<CliConfig> {
  const cfg = await loadConfig();
  const map = new Map(cfg.collections.map((c) => [c.uuid, c]));
  for (const c of incoming) {
    const prev = map.get(c.uuid);
    if (!prev || c.revision >= prev.revision) {
      map.set(c.uuid, c);
    }
  }
  const collections = [...map.values()].filter((c) => !c.isDeleted);
  return saveConfig({ collections });
}

export async function clearAuth(): Promise<CliConfig> {
  return saveConfig({
    accessToken: undefined,
    refreshToken: undefined,
  });
}

export async function clearVaultMeta(): Promise<CliConfig> {
  return saveConfig({
    email: undefined,
    saltB64: undefined,
    wrappedVaultKey: undefined,
    kdfParams: undefined,
    accessToken: undefined,
    refreshToken: undefined,
    entries: [],
    collections: [],
    serverRevision: 0,
  });
}
