import { randomUUID } from "node:crypto";
import { decryptString, encryptString } from "./crypto.js";
import {
  ReservedCollections,
  isReservedCollection,
  normalizeSecretKind,
  type DecryptedCard,
  type DecryptedCrypto,
  type DecryptedLogin,
  type DecryptedSecret,
  type SecretKindName,
  type SecretPayload,
  type StoredEntry,
  type VaultItem,
} from "./types.js";
import { loadConfig, saveConfig, upsertEntries } from "./store.js";
import { syncPushEntries } from "./api.js";
import {
  readSessionFromEnv,
  requireSession,
  vaultKeyFromSession,
} from "./session.js";
import type { SessionPayload } from "./types.js";
import {
  bridgeCreateSecret,
  bridgeDeleteSecret,
  bridgeListCards,
  bridgeListCrypto,
  bridgeListLogins,
  bridgeListSecrets,
  bridgeUpdateSecret,
  tryBridgePing,
} from "./bridge.js";
import { normalizeTotp, generateTotp } from "./totp.js";
import { deviceName as defaultDeviceName } from "./discover.js";

export type VaultBackend = "native" | "session";

/**
 * Prefer the unlocked desktop OpenKey app (no server/login required).
 * Fall back to a CLI OPENKEY_SESSION (server / standalone vault).
 */
export async function resolveBackend(): Promise<VaultBackend> {
  if (await tryBridgePing()) return "native";
  if (readSessionFromEnv()) return "session";
  throw new Error(
    "No vault available. Unlock the OpenKey desktop app, or configure a server and run `eval $(openkey unlock)`.",
  );
}

export async function currentBackend(): Promise<VaultBackend | null> {
  if (await tryBridgePing()) return "native";
  if (readSessionFromEnv()) return "session";
  return null;
}

export function decryptItems(
  vaultKey: Uint8Array,
  entries: StoredEntry[],
): VaultItem[] {
  const out: VaultItem[] = [];
  for (const row of entries) {
    if (row.isDeleted) continue;
    try {
      const json = decryptString(vaultKey, row.encryptedPayload);
      const raw = JSON.parse(json) as Record<string, unknown>;
      const item = parseVaultItem(row, raw);
      if (item) out.push(item);
    } catch {
      /* skip undecryptable */
    }
  }
  return out;
}

function parseVaultItem(
  row: StoredEntry,
  raw: Record<string, unknown>,
): VaultItem | null {
  const type = raw.type?.toString();
  if (
    type === "secret" ||
    row.collectionUuid === ReservedCollections.secrets
  ) {
    return normalizeSecret(row, raw);
  }
  if (type === "card" || row.collectionUuid === ReservedCollections.wallets) {
    return normalizeCard(row, raw);
  }
  if (type === "crypto" || row.collectionUuid === ReservedCollections.crypto) {
    return normalizeCrypto(row, raw);
  }
  if (isReservedCollection(row.collectionUuid)) return null;
  return {
    kind: "login",
    uuid: row.uuid,
    collectionUuid: row.collectionUuid,
    revision: row.revision,
    title: String(raw.title ?? ""),
    username: String(raw.username ?? ""),
    password: String(raw.password ?? ""),
    urls: Array.isArray(raw.urls) ? (raw.urls as string[]) : [],
    notes: String(raw.notes ?? ""),
    tags: Array.isArray(raw.tags) ? (raw.tags as string[]) : [],
    totp: normalizeTotp(raw.totp),
  };
}

function normalizeCard(
  row: StoredEntry,
  raw: Record<string, unknown>,
): DecryptedCard {
  return {
    kind: "card",
    type: "card",
    uuid: row.uuid,
    collectionUuid: row.collectionUuid,
    revision: row.revision,
    name: String(raw.name ?? ""),
    holder: String(raw.holder ?? ""),
    number: String(raw.number ?? ""),
    expiry: String(raw.expiry ?? ""),
    cvc: String(raw.cvc ?? ""),
    brand: String(raw.brand ?? ""),
    notes: String(raw.notes ?? ""),
    bank: String(raw.bank ?? ""),
  };
}

function normalizeCrypto(
  row: StoredEntry,
  raw: Record<string, unknown>,
): DecryptedCrypto {
  return {
    kind: "crypto",
    type: "crypto",
    uuid: row.uuid,
    collectionUuid: row.collectionUuid,
    revision: row.revision,
    name: String(raw.name ?? ""),
    network: String(raw.network ?? ""),
    address: String(raw.address ?? ""),
    privateKey: String(raw.privateKey ?? ""),
    seedPhrase: String(raw.seedPhrase ?? ""),
    notes: String(raw.notes ?? ""),
    folder: String(raw.folder ?? ""),
  };
}

function normalizeSecret(
  row: StoredEntry,
  raw: Record<string, unknown>,
): DecryptedSecret {
  return {
    kind: "secret",
    type: "secret",
    uuid: row.uuid,
    collectionUuid: row.collectionUuid,
    revision: row.revision,
    name: String(raw.name ?? ""),
    secretKind: normalizeSecretKind(
      (raw.kind as string) ?? (raw.secretKind as string),
    ),
    username: String(raw.username ?? ""),
    host: String(raw.host ?? ""),
    publicKey: String(raw.publicKey ?? ""),
    secret: String(raw.secret ?? raw.privateKey ?? raw.token ?? ""),
    passphrase: String(raw.passphrase ?? ""),
    notes: String(raw.notes ?? ""),
    device: String(raw.device ?? ""),
  };
}

export async function listDecryptedItems(
  session?: SessionPayload,
): Promise<VaultItem[]> {
  const backend = session ? "session" : await resolveBackend();
  if (backend === "native") {
    const [secrets, logins, cards, cryptoWallets] = await Promise.all([
      bridgeListSecrets(),
      bridgeListLogins(),
      bridgeListCards(),
      bridgeListCrypto(),
    ]);
    return [...secrets, ...logins, ...cards, ...cryptoWallets];
  }
  const s = session ?? requireSession();
  const cfg = await loadConfig();
  return decryptItems(vaultKeyFromSession(s), cfg.entries);
}

export async function listSecrets(): Promise<DecryptedSecret[]> {
  const backend = await resolveBackend();
  if (backend === "native") return bridgeListSecrets();
  const items = await listDecryptedItems();
  return items.filter((i): i is DecryptedSecret => i.kind === "secret");
}

export async function listLogins(): Promise<DecryptedLogin[]> {
  const backend = await resolveBackend();
  if (backend === "native") return bridgeListLogins();
  const items = await listDecryptedItems();
  return items.filter((i): i is DecryptedLogin => i.kind === "login");
}

export async function listCards(): Promise<DecryptedCard[]> {
  const backend = await resolveBackend();
  if (backend === "native") return bridgeListCards();
  const items = await listDecryptedItems();
  return items.filter((i): i is DecryptedCard => i.kind === "card");
}

export async function listCrypto(): Promise<DecryptedCrypto[]> {
  const backend = await resolveBackend();
  if (backend === "native") return bridgeListCrypto();
  const items = await listDecryptedItems();
  return items.filter((i): i is DecryptedCrypto => i.kind === "crypto");
}

export type CreateSecretInput = {
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

export async function createSecret(
  input: CreateSecretInput,
): Promise<DecryptedSecret> {
  // Prefer desktop app when unlocked — no registration/server needed.
  if (await tryBridgePing()) {
    return bridgeCreateSecret(input);
  }

  // Optional standalone/server mode when OPENKEY_SESSION is set.
  const session = readSessionFromEnv();
  if (!session) {
    throw new Error(
      "Unlock the OpenKey desktop app to save secrets, or run `eval $(openkey unlock)` after logging into a server.",
    );
  }

  const key = vaultKeyFromSession(session);
  const kind = normalizeSecretKind(input.kind ?? "apiToken");
  const payload: SecretPayload = {
    type: "secret",
    name: input.name.trim(),
    kind,
    username: input.username ?? "",
    host: input.host ?? "",
    publicKey: input.publicKey ?? "",
    secret: input.secret ?? "",
    passphrase: input.passphrase ?? "",
    notes: input.notes ?? "",
    device: input.device?.trim() || undefined,
  };
  const uuid = randomUUID();
  const stored: StoredEntry = {
    uuid,
    collectionUuid: ReservedCollections.secrets,
    encryptedPayload: encryptString(key, JSON.stringify(payload)),
    revision: 1,
    isDeleted: false,
    updatedAt: new Date().toISOString(),
  };
  await upsertEntries([stored]);
  const cfg = await loadConfig();
  if (cfg.accessToken) {
    try {
      const pushed = await syncPushEntries(cfg, [stored]);
      await upsertEntries(pushed.entries);
      await saveConfig({ serverRevision: pushed.serverRevision });
    } catch {
      /* keep local; sync later */
    }
  }
  return normalizeSecret(stored, payload as unknown as Record<string, unknown>);
}

export type UpdateSecretPatch = {
  name?: string;
  kind?: SecretKindName | string;
  username?: string;
  host?: string;
  publicKey?: string;
  secret?: string;
  passphrase?: string;
  notes?: string;
  device?: string;
};

export async function updateSecret(
  uuid: string,
  patch: UpdateSecretPatch,
): Promise<DecryptedSecret> {
  const keys = Object.keys(patch).filter(
    (k) => patch[k as keyof UpdateSecretPatch] !== undefined,
  );
  if (!keys.length) {
    throw new Error("Nothing to update — pass at least one field");
  }

  if (await tryBridgePing()) {
    const body: Record<string, string> = {};
    if (patch.name !== undefined) body.name = patch.name;
    if (patch.kind !== undefined) body.kind = String(patch.kind);
    if (patch.username !== undefined) body.username = patch.username;
    if (patch.host !== undefined) body.host = patch.host;
    if (patch.publicKey !== undefined) body.publicKey = patch.publicKey;
    if (patch.secret !== undefined) body.secret = patch.secret;
    if (patch.passphrase !== undefined) body.passphrase = patch.passphrase;
    if (patch.notes !== undefined) body.notes = patch.notes;
    if (patch.device !== undefined) body.device = patch.device;
    return bridgeUpdateSecret({ uuid, name: body.name ?? "", patch: body });
  }

  const session = readSessionFromEnv();
  if (!session) {
    throw new Error(
      "Unlock the OpenKey desktop app to update secrets, or run `eval $(openkey unlock)` after logging into a server.",
    );
  }

  const key = vaultKeyFromSession(session);
  const cfg = await loadConfig();
  const existing = cfg.entries.find((e) => e.uuid === uuid && !e.isDeleted);
  if (!existing) throw new Error(`Secret not found: ${uuid}`);

  let current: Record<string, unknown>;
  try {
    current = JSON.parse(decryptString(key, existing.encryptedPayload)) as Record<
      string,
      unknown
    >;
  } catch {
    throw new Error("Could not decrypt secret for update");
  }

  const nextPayload: SecretPayload = {
    type: "secret",
    name: (patch.name ?? String(current.name ?? "")).trim(),
    kind: normalizeSecretKind(
      patch.kind ?? (current.kind as string) ?? (current.secretKind as string),
    ),
    username: patch.username ?? String(current.username ?? ""),
    host: patch.host ?? String(current.host ?? ""),
    publicKey: patch.publicKey ?? String(current.publicKey ?? ""),
    secret:
      patch.secret ??
      String(current.secret ?? current.privateKey ?? current.token ?? ""),
    passphrase: patch.passphrase ?? String(current.passphrase ?? ""),
    notes: patch.notes ?? String(current.notes ?? ""),
    device:
      patch.device !== undefined
        ? patch.device.trim() || undefined
        : String(current.device ?? "") || undefined,
  };
  if (!nextPayload.name) throw new Error("Name required");
  if (!(nextPayload.secret ?? "").trim()) throw new Error("Secret value required");

  const stored: StoredEntry = {
    ...existing,
    encryptedPayload: encryptString(key, JSON.stringify(nextPayload)),
    revision: existing.revision + 1,
    isDeleted: false,
    updatedAt: new Date().toISOString(),
  };
  await upsertEntries([stored]);
  const after = await loadConfig();
  if (after.accessToken) {
    try {
      const pushed = await syncPushEntries(after, [stored]);
      await upsertEntries(pushed.entries);
      await saveConfig({ serverRevision: pushed.serverRevision });
    } catch {
      /* keep local */
    }
  }
  return normalizeSecret(stored, nextPayload as unknown as Record<string, unknown>);
}

/**
 * Create or update a secret matched by name + device.
 * Returns `{ secret, created }` where created is true if a new record was made.
 */
export async function upsertSecret(
  input: CreateSecretInput,
): Promise<{ secret: DecryptedSecret; created: boolean }> {
  const device = (input.device?.trim() || defaultDeviceName()).toLowerCase();
  const name = input.name.trim().toLowerCase();
  if (!name) throw new Error("Name required");

  const existing = (await listSecrets()).find(
    (s) =>
      s.name.trim().toLowerCase() === name &&
      (s.device || "").trim().toLowerCase() === device,
  );

  if (!existing) {
    const secret = await createSecret({
      ...input,
      device: input.device?.trim() || defaultDeviceName(),
    });
    return { secret, created: true };
  }

  const secret = await updateSecret(existing.uuid, {
    name: input.name,
    kind: input.kind,
    username: input.username,
    host: input.host,
    publicKey: input.publicKey,
    secret: input.secret,
    passphrase: input.passphrase,
    notes: input.notes,
    device: input.device?.trim() || defaultDeviceName(),
  });
  return { secret, created: false };
}

export async function deleteSecret(uuid: string): Promise<void> {
  if (await tryBridgePing()) {
    await bridgeDeleteSecret(uuid);
    return;
  }

  requireSession();
  const cfg = await loadConfig();
  const existing = cfg.entries.find((e) => e.uuid === uuid && !e.isDeleted);
  if (!existing) throw new Error(`Secret not found: ${uuid}`);

  const tombstone: StoredEntry = {
    ...existing,
    revision: existing.revision + 1,
    isDeleted: true,
    updatedAt: new Date().toISOString(),
  };

  const withTombstone = cfg.entries.map((e) =>
    e.uuid === uuid ? tombstone : e,
  );
  await saveConfig({ entries: withTombstone });

  if (cfg.accessToken) {
    try {
      const pushed = await syncPushEntries(await loadConfig(), [tombstone]);
      await upsertEntries(pushed.entries);
      const after = await loadConfig();
      await saveConfig({
        serverRevision: pushed.serverRevision,
        entries: after.entries.filter((e) => !e.isDeleted),
      });
      return;
    } catch {
      /* fall through to local delete */
    }
  }

  await saveConfig({
    entries: withTombstone.filter((e) => !e.isDeleted),
  });
}

export function matchQuery<T extends VaultItem>(items: T[], query: string): T[] {
  const q = query.trim().toLowerCase();
  if (!q) return items;
  return items.filter((item) => {
    if (item.kind === "secret") {
      return (
        item.name.toLowerCase().includes(q) ||
        item.host.toLowerCase().includes(q) ||
        item.username.toLowerCase().includes(q) ||
        item.uuid.toLowerCase().startsWith(q) ||
        item.secretKind.toLowerCase().includes(q) ||
        item.device.toLowerCase().includes(q)
      );
    }
    if (item.kind === "card") {
      return (
        item.name.toLowerCase().includes(q) ||
        item.holder.toLowerCase().includes(q) ||
        item.bank.toLowerCase().includes(q) ||
        item.brand.toLowerCase().includes(q) ||
        item.uuid.toLowerCase().startsWith(q)
      );
    }
    if (item.kind === "crypto") {
      return (
        item.name.toLowerCase().includes(q) ||
        item.network.toLowerCase().includes(q) ||
        item.address.toLowerCase().includes(q) ||
        item.folder.toLowerCase().includes(q) ||
        item.uuid.toLowerCase().startsWith(q)
      );
    }
    return (
      item.title.toLowerCase().includes(q) ||
      item.username.toLowerCase().includes(q) ||
      item.urls.some((u) => u.toLowerCase().includes(q)) ||
      item.uuid.toLowerCase().startsWith(q)
    );
  });
}

/**
 * Resolve a single vault item from a query.
 * Prefers exact UUID / label / host matches when substring search is ambiguous.
 */
export function resolveOneMatch<T extends VaultItem>(
  items: T[],
  query: string,
  opts: { noun?: string } = {},
): T {
  const noun = opts.noun ?? "item";
  const q = query.trim();
  if (!q) throw new Error(`Empty query — provide a ${noun} name, host, or UUID`);

  const matches = matchQuery(items, q);
  if (!matches.length) throw new Error(`No ${noun} matching "${q}"`);
  if (matches.length === 1) return matches[0]!;

  const ql = q.toLowerCase();

  const byUuidExact = matches.filter((i) => i.uuid.toLowerCase() === ql);
  if (byUuidExact.length === 1) return byUuidExact[0]!;

  const byUuidPrefix = matches.filter((i) => i.uuid.toLowerCase().startsWith(ql));
  if (byUuidPrefix.length === 1 && ql.length >= 4) return byUuidPrefix[0]!;

  const byExactLabel = matches.filter(
    (i) => itemLabel(i).toLowerCase() === ql,
  );
  if (byExactLabel.length === 1) return byExactLabel[0]!;

  const byExactHost = matches.filter(
    (i) => i.kind === "secret" && i.host.toLowerCase() === ql,
  );
  if (byExactHost.length === 1) return byExactHost[0]!;

  throw new Error(
    `Ambiguous match (${matches.length}). Refine query:\n` +
      matches
        .map((i) => `  ${i.uuid.slice(0, 8)}  ${i.kind}  ${itemLabel(i)}`)
        .join("\n"),
  );
}

export function itemLabel(item: VaultItem): string {
  if (item.kind === "secret") return item.name || "Secret";
  if (item.kind === "card") return item.name || "Card";
  if (item.kind === "crypto") return item.name || "Wallet";
  return item.title || "Login";
}

export function itemSecretValue(item: VaultItem): string {
  if (item.kind === "secret") return item.secret;
  if (item.kind === "card") return item.number;
  if (item.kind === "crypto") return item.privateKey || item.seedPhrase;
  return item.password;
}

export type ItemField = "password" | "secret" | "username" | "url" | "totp" | "notes";

/** Resolve a printable field from a vault item (totp generates a live code). */
export function itemFieldValue(item: VaultItem, field: ItemField): string {
  if (field === "totp") {
    if (item.kind !== "login" || !item.totp?.secret) {
      throw new Error(`No TOTP on "${itemLabel(item)}"`);
    }
    return generateTotp(item.totp);
  }
  if (item.kind === "secret") {
    switch (field) {
      case "password":
      case "secret":
        return item.secret;
      case "username":
        return item.username;
      case "url":
        return item.host;
      case "notes":
        return item.notes;
      default:
        throw new Error(`Field "${field}" is not available on secrets`);
    }
  }
  if (item.kind === "card") {
    switch (field) {
      case "password":
      case "secret":
        return item.number;
      case "username":
        return item.holder;
      case "notes":
        return item.notes;
      default:
        throw new Error(`Field "${field}" is not available on cards`);
    }
  }
  if (item.kind === "crypto") {
    switch (field) {
      case "password":
      case "secret":
        return item.privateKey || item.seedPhrase;
      case "username":
        return item.address;
      case "url":
        return item.network;
      case "notes":
        return item.notes;
      default:
        throw new Error(`Field "${field}" is not available on crypto wallets`);
    }
  }
  switch (field) {
    case "password":
    case "secret":
      return item.password;
    case "username":
      return item.username;
    case "url":
      return item.urls[0] ?? "";
    case "notes":
      return item.notes;
    default:
      throw new Error(`Unknown field "${field}"`);
  }
}

/** Parse --field flag (password|username|url|totp|notes|secret). */
export function parseItemField(raw?: string): ItemField {
  const f = (raw ?? "password").trim().toLowerCase();
  if (
    f === "password" ||
    f === "secret" ||
    f === "username" ||
    f === "url" ||
    f === "totp" ||
    f === "notes"
  ) {
    return f;
  }
  throw new Error(
    `Unknown field "${raw}" (use password, username, url, totp, notes)`,
  );
}

/** Parse `NAME` or `NAME=query` bindings for env/run commands. */
export function parseEnvBinding(raw: string): { envName: string; query: string } {
  const trimmed = raw.trim();
  const eq = trimmed.indexOf("=");
  if (eq <= 0) {
    const name = trimmed.replace(/[^A-Za-z0-9_]/g, "_").replace(/^(\d)/, "_$1");
    if (!name) throw new Error(`Invalid env binding: "${raw}"`);
    return { envName: name.toUpperCase(), query: trimmed };
  }
  const envName = trimmed.slice(0, eq).trim();
  const query = trimmed.slice(eq + 1).trim();
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(envName)) {
    throw new Error(
      `Invalid environment variable name "${envName}" (use NAME or NAME=query)`,
    );
  }
  if (!query) throw new Error(`Missing query in binding "${raw}"`);
  return { envName, query };
}

/** Shell-safe single-quoted string for `eval $(openkey env …)`. */
export function shellSingleQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}
