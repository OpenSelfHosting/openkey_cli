import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

import { cmdUnlock } from "./auth.js";
import {
  deriveAuthHash,
  deriveMasterKey,
  generateSalt,
  generateVaultKey,
  toB64Url,
  wrapVaultKey,
} from "../lib/crypto.js";
import { saveConfig } from "../lib/store.js";

const email = "test@example.com";
const password = "correct horse battery staple";
const serverKdfParams = {
  algorithm: "argon2id",
  memory: 8192,
  iterations: 1,
  parallelism: 1,
  hashLength: 32,
};

async function readJson(request: IncomingMessage): Promise<Record<string, unknown>> {
  let text = "";
  for await (const chunk of request) text += chunk;
  return JSON.parse(text) as Record<string, unknown>;
}

function respond(
  response: ServerResponse,
  body: Record<string, unknown>,
): void {
  response.statusCode = 200;
  response.setHeader("Content-Type", "application/json");
  response.end(JSON.stringify(body));
}

describe("cmdUnlock", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("uses fresh server KDF metadata when cached vault metadata is stale", async () => {
    const configRoot = await mkdtemp(join(tmpdir(), "openkey-cli-unlock-"));
    const previousEnv = {
      XDG_CONFIG_HOME: process.env.XDG_CONFIG_HOME,
      OPENKEY_EMAIL: process.env.OPENKEY_EMAIL,
      OPENKEY_PASSWORD: process.env.OPENKEY_PASSWORD,
    };
    const salt = generateSalt();
    const masterKey = await deriveMasterKey(
      email,
      password,
      salt,
      serverKdfParams,
    );
    const vaultKey = generateVaultKey();
    const wrapped = await wrapVaultKey(masterKey, vaultKey);
    const requestedPaths: string[] = [];
    const server = createServer(async (request, response) => {
      requestedPaths.push(request.url ?? "");
      if (request.method === "POST" && request.url === "/api/v1/auth/prelogin") {
        await readJson(request);
        respond(response, {
          salt: toB64Url(salt),
          kdf_params: serverKdfParams,
        });
      } else if (request.method === "POST" && request.url === "/api/v1/auth/login") {
        const body = await readJson(request);
        expect(body.auth_hash).toBe(deriveAuthHash(masterKey));
        respond(response, {
          access_token: "test-access",
          refresh_token: "test-refresh",
          user_id: "user-id",
        });
      } else if (request.method === "GET" && request.url === "/api/v1/auth/me") {
        respond(response, {
          email,
          salt: toB64Url(salt),
          kdf_params: serverKdfParams,
          encrypted_vault_key: wrapped,
        });
      } else if (request.method === "POST" && request.url === "/api/v1/sync") {
        respond(response, {
          entries: [],
          collections: [],
          server_revision: 0,
        });
      } else {
        response.statusCode = 404;
        response.end();
      }
    });

    try {
      await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
      const address = server.address();
      if (!address || typeof address === "string") throw new Error("No test server port");

      process.env.XDG_CONFIG_HOME = configRoot;
      process.env.OPENKEY_EMAIL = email;
      process.env.OPENKEY_PASSWORD = password;
      const staleSalt = generateSalt();
      const staleKey = await deriveMasterKey(email, "old password", staleSalt);
      await saveConfig({
        serverUrl: `http://127.0.0.1:${address.port}`,
        email,
        saltB64: toB64Url(staleSalt),
        wrappedVaultKey: await wrapVaultKey(staleKey, generateVaultKey()),
      });
      const log = vi.spyOn(console, "log").mockImplementation(() => {});

      await cmdUnlock({ email, raw: true });

      expect(log).toHaveBeenCalledOnce();
      expect(requestedPaths).toEqual([
        "/api/v1/auth/prelogin",
        "/api/v1/auth/login",
        "/api/v1/auth/me",
        "/api/v1/sync",
      ]);
    } finally {
      process.env.XDG_CONFIG_HOME = previousEnv.XDG_CONFIG_HOME;
      process.env.OPENKEY_EMAIL = previousEnv.OPENKEY_EMAIL;
      process.env.OPENKEY_PASSWORD = previousEnv.OPENKEY_PASSWORD;
      await new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      );
      await rm(configRoot, { recursive: true, force: true });
    }
  });
});
