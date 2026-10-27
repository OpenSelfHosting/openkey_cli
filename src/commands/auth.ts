import {
  deriveAuthHash,
  deriveMasterKey,
  fromB64Url,
  toB64Url,
  unwrapVaultKey,
} from "../lib/crypto.js";
import {
  fetchVaultMaterial,
  login,
  prelogin,
  syncPull,
} from "../lib/api.js";
import {
  clearAuth,
  clearVaultMeta,
  loadConfig,
  saveConfig,
  upsertCollections,
  upsertEntries,
} from "../lib/store.js";
import {
  SESSION_ENV,
  encodeSession,
  exportSessionShell,
  readSessionFromEnv,
} from "../lib/session.js";
import {
  isJsonMode,
  printJson,
  printLine,
  readEmail,
  readMasterPassword,
} from "../lib/output.js";

export async function cmdConfigSetServer(url: string): Promise<void> {
  const serverUrl = url.trim().replace(/\/$/, "");
  if (!/^https?:\/\//i.test(serverUrl)) {
    throw new Error("Server URL must start with http:// or https://");
  }
  await saveConfig({ serverUrl });
  if (isJsonMode()) printJson({ serverUrl });
  else printLine(`Server URL set to ${serverUrl}`);
}

export async function cmdConfigShow(): Promise<void> {
  const cfg = await loadConfig();
  const data = {
    serverUrl: cfg.serverUrl,
    email: cfg.email ?? null,
    loggedIn: !!cfg.accessToken,
    entriesCached: cfg.entries.length,
    lockMinutes: cfg.lockMinutes,
  };
  if (isJsonMode()) printJson(data);
  else {
    printLine(`server:  ${data.serverUrl}`);
    printLine(`email:   ${data.email ?? "(none)"}`);
    printLine(`logged:  ${data.loggedIn ? "yes" : "no"}`);
    printLine(`cached:  ${data.entriesCached} entries`);
    printLine(`lock:    ${data.lockMinutes} min`);
  }
}

export async function cmdLogin(opts: {
  email?: string;
  server?: string;
}): Promise<void> {
  if (opts.server) await cmdConfigSetServer(opts.server);
  const cfg = await loadConfig();
  if (!cfg.serverUrl?.trim()) {
    throw new Error("Set server first: openkey config set-server <url>");
  }
  const email = await readEmail(opts.email, cfg.email);
  const password = await readMasterPassword();

  const bootstrap = await prelogin(cfg, email);
  const saltB64 = bootstrap.salt;
  const kdfParams = bootstrap.kdf_params;

  const masterKey = await deriveMasterKey(
    email,
    password,
    fromB64Url(saltB64),
    kdfParams,
  );
  const authHash = deriveAuthHash(masterKey);
  const token = await login(cfg, email, authHash);
  let next = await saveConfig({
    email,
    accessToken: token.access_token,
    refreshToken: token.refresh_token,
    saltB64,
    kdfParams,
  });

  const material = await fetchVaultMaterial(next);
  const vaultMasterKey = await deriveMasterKey(
    email,
    password,
    fromB64Url(material.salt),
    material.kdf_params,
  );
  try {
    await unwrapVaultKey(vaultMasterKey, material.encrypted_vault_key);
  } catch {
    throw new Error(
      "Server accepted the password, but the vault key could not be decrypted.",
    );
  }
  next = await saveConfig({
    email: material.email,
    saltB64: material.salt,
    wrappedVaultKey: material.encrypted_vault_key,
    kdfParams: material.kdf_params,
  });

  const pulled = await syncPull(next);
  await upsertEntries(pulled.entries);
  await upsertCollections(pulled.collections);
  await saveConfig({ serverRevision: pulled.serverRevision });

  if (isJsonMode()) {
    printJson({ ok: true, email: material.email, entries: pulled.entries.length });
  } else {
    printLine(`Logged in as ${material.email} (${pulled.entries.length} entries synced)`);
    printLine("Next: eval $(openkey unlock)");
  }
}

export async function cmdLogout(): Promise<void> {
  await clearAuth();
  if (isJsonMode()) printJson({ ok: true });
  else printLine("Logged out (local vault cache kept). Use `openkey lock` to clear session.");
}

export async function cmdUnlock(opts: {
  email?: string;
  raw?: boolean;
}): Promise<void> {
  const cfg = await loadConfig();
  const email = await readEmail(opts.email, cfg.email);
  const password = await readMasterPassword();

  const cachedForEmail = cfg.email?.trim().toLowerCase() === email;
  let vaultKey: Uint8Array | null = null;
  if (cachedForEmail && cfg.saltB64 && cfg.wrappedVaultKey) {
    try {
      const cachedMasterKey = await deriveMasterKey(
        email,
        password,
        fromB64Url(cfg.saltB64),
        cfg.kdfParams,
      );
      vaultKey = await unwrapVaultKey(cachedMasterKey, cfg.wrappedVaultKey);
    } catch {
      // Cached metadata may be stale after a server-side password rotation.
    }
  }

  if (cfg.serverUrl?.trim()) {
    try {
      const bootstrap = await prelogin(cfg, email);
      const masterKey = await deriveMasterKey(
        email,
        password,
        fromB64Url(bootstrap.salt),
        bootstrap.kdf_params,
      );
      const authHash = deriveAuthHash(masterKey);
      const token = await login(cfg, email, authHash);
      let next = await saveConfig({
        email,
        accessToken: token.access_token,
        refreshToken: token.refresh_token,
        saltB64: bootstrap.salt,
        kdfParams: bootstrap.kdf_params,
      });
      const material = await fetchVaultMaterial(next);
      const materialMasterKey = await deriveMasterKey(
        email,
        password,
        fromB64Url(material.salt),
        material.kdf_params,
      );
      try {
        vaultKey = await unwrapVaultKey(
          materialMasterKey,
          material.encrypted_vault_key,
        );
      } catch {
        throw new Error(
          "Server accepted the password, but the vault key could not be decrypted.",
        );
      }
      next = await saveConfig({
        email: material.email,
        saltB64: material.salt,
        wrappedVaultKey: material.encrypted_vault_key,
        kdfParams: material.kdf_params,
      });
      const pulled = await syncPull(next);
      await upsertEntries(pulled.entries);
      await upsertCollections(pulled.collections);
      await saveConfig({ serverRevision: pulled.serverRevision });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.startsWith("Server accepted the password")) throw err;
      if (!vaultKey) {
        if (/invalid email or auth_hash|HTTP 401/i.test(msg)) {
          throw new Error(
            "The server rejected this email or password-derived key. Confirm the account was registered on this server with the same vault password.",
          );
        }
        throw new Error(
          msg,
        );
      }
    }
  } else if (!vaultKey) {
    throw new Error("No local vault meta — login first or set server URL");
  }

  if (!vaultKey) throw new Error("Could not unlock vault");

  const lockMinutes = cfg.lockMinutes || 15;
  const token = encodeSession({
    email,
    vaultKeyB64: toB64Url(vaultKey),
    expiresAt: Date.now() + lockMinutes * 60_000,
  });

  if (opts.raw || isJsonMode()) {
    if (isJsonMode()) {
      printJson({
        [SESSION_ENV]: token,
        expiresAt: Date.now() + lockMinutes * 60_000,
        email,
      });
    } else {
      console.log(token);
    }
    return;
  }

  // Print only the export line on stdout for `eval $(openkey unlock)`
  console.log(exportSessionShell(token));
}

export async function cmdLock(): Promise<void> {
  if (isJsonMode()) {
    printJson({ ok: true, hint: `unset ${SESSION_ENV}` });
  } else {
    console.log(`unset ${SESSION_ENV}`);
  }
}

export async function cmdStatus(): Promise<void> {
  const cfg = await loadConfig();
  const session = readSessionFromEnv();
  const { tryBridgePing } = await import("../lib/bridge.js");
  const bridge = await tryBridgePing();
  const path = (await import("../lib/store.js")).configPath();
  const data = {
    serverUrl: cfg.serverUrl,
    email: cfg.email ?? session?.email ?? null,
    loggedIn: !!cfg.accessToken,
    unlocked: bridge || !!session,
    mode: bridge ? "native" : session ? "session" : null,
    bridge,
    sessionExpiresAt: session?.expiresAt ?? null,
    entriesCached: cfg.entries.length,
    configPath: path,
  };
  if (isJsonMode()) printJson(data);
  else {
    printLine(`server:   ${data.serverUrl}`);
    printLine(`email:    ${data.email ?? "(none)"}`);
    printLine(`logged:   ${data.loggedIn ? "yes" : "no"}`);
    printLine(`bridge:   ${bridge ? "app unlocked (bridge)" : "unavailable"}`);
    printLine(
      `unlocked: ${data.unlocked ? `yes (${data.mode})` : "no"}`,
    );
    if (session) {
      const mins = Math.max(
        0,
        Math.round((session.expiresAt - Date.now()) / 60_000),
      );
      printLine(`session:  ~${mins} min left`);
    }
    printLine(`cached:   ${data.entriesCached} entries`);
    printLine(`config:   ${path}`);
    if (!data.unlocked) {
      printLine("");
      printLine(
        "Tip: unlock OpenKey (desktop or Android + Termux env),",
      );
      printLine("or configure a server and run: eval $(openkey unlock)");
    }
  }
}

export async function cmdForget(): Promise<void> {
  await clearVaultMeta();
  if (isJsonMode()) printJson({ ok: true });
  else printLine("Cleared local OpenKey CLI config and vault cache.");
}
