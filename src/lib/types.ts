/** Types matching openkey_app / openkey_extension vault payloads. */

export type SecretKindName = "sshKey" | "apiToken" | "envSnippet" | "other";

export type SecretPayload = {
  type: "secret";
  name: string;
  kind: SecretKindName | string;
  username?: string;
  host?: string;
  publicKey?: string;
  secret?: string;
  passphrase?: string;
  notes?: string;
  /** Device / machine label for grouping inside Secrets. */
  device?: string;
};

export type EntryPayload = {
  type?: "login" | string;
  title: string;
  username: string;
  password: string;
  urls: string[];
  notes: string;
  tags?: string[];
};

export type StoredEntry = {
  uuid: string;
  collectionUuid: string | null;
  encryptedPayload: string;
  revision: number;
  isDeleted: boolean;
  updatedAt: string;
};

export type StoredCollection = {
  uuid: string;
  encryptedName: string;
  icon: string;
  color: number | null;
  parentUuid: string | null;
  sortOrder: number;
  revision: number;
  isDeleted: boolean;
  updatedAt: string;
};

export type DecryptedSecret = {
  kind: "secret";
  type: "secret";
  uuid: string;
  collectionUuid: string | null;
  revision: number;
  name: string;
  secretKind: SecretKindName;
  username: string;
  host: string;
  publicKey: string;
  secret: string;
  passphrase: string;
  notes: string;
  device: string;
};

export type DecryptedLogin = {
  kind: "login";
  uuid: string;
  collectionUuid: string | null;
  revision: number;
  title: string;
  username: string;
  password: string;
  urls: string[];
  notes: string;
  tags?: string[];
  totp?: {
    secret: string;
    period?: number;
    digits?: number;
    algorithm?: string;
  } | null;
};

export type DecryptedCard = {
  kind: "card";
  type: "card";
  uuid: string;
  collectionUuid: string | null;
  revision: number;
  name: string;
  holder: string;
  number: string;
  expiry: string;
  cvc: string;
  brand: string;
  notes: string;
  bank: string;
};

export type DecryptedCrypto = {
  kind: "crypto";
  type: "crypto";
  uuid: string;
  collectionUuid: string | null;
  revision: number;
  name: string;
  network: string;
  address: string;
  privateKey: string;
  seedPhrase: string;
  notes: string;
  folder: string;
};

export type VaultItem =
  | DecryptedSecret
  | DecryptedLogin
  | DecryptedCard
  | DecryptedCrypto;

export const ReservedCollections = {
  wallets: "__wallets__",
  crypto: "__crypto_wallets__",
  secrets: "__dev_secrets__",
} as const;

export function isReservedCollection(id: string | null | undefined): boolean {
  return (
    id === ReservedCollections.wallets ||
    id === ReservedCollections.crypto ||
    id === ReservedCollections.secrets
  );
}

export function normalizeSecretKind(name?: string | null): SecretKindName {
  const key = (name ?? "").toLowerCase().trim();
  if (key === "sshkey" || key === "ssh_key" || key === "ssh" || name === "sshKey") {
    return "sshKey";
  }
  if (
    key === "apitoken" ||
    key === "api_token" ||
    key === "api" ||
    key === "token" ||
    name === "apiToken"
  ) {
    return "apiToken";
  }
  if (
    key === "envsnippet" ||
    key === "env_snippet" ||
    key === "env" ||
    key === "dotenv" ||
    key === ".env" ||
    name === "envSnippet"
  ) {
    return "envSnippet";
  }
  return "other";
}

export function secretKindLabel(kind: SecretKindName): string {
  switch (kind) {
    case "sshKey":
      return "SSH key";
    case "apiToken":
      return "API token";
    case "envSnippet":
      return ".env";
    default:
      return "Secret";
  }
}

export function maskSecret(value: string): string {
  const v = value.trim();
  if (!v) return "—";
  if (v.length <= 8) return "••••••••";
  return `${v.slice(0, 4)}…${v.slice(-4)}`;
}

export type CliConfig = {
  serverUrl: string;
  email?: string;
  accessToken?: string;
  refreshToken?: string;
  saltB64?: string;
  wrappedVaultKey?: string;
  kdfParams?: Record<string, unknown>;
  lockMinutes: number;
  serverRevision: number;
  entries: StoredEntry[];
  collections: StoredCollection[];
};

export const DEFAULT_CONFIG: CliConfig = {
  serverUrl: "http://localhost:8000",
  lockMinutes: 15,
  serverRevision: 0,
  entries: [],
  collections: [],
};

export type SessionPayload = {
  v: 1;
  email: string;
  vaultKeyB64: string;
  expiresAt: number;
};
