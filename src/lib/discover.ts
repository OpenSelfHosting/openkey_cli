/** Discover local developer secrets (SSH, .env, API env vars, AWS creds). */

import { createHash } from "node:crypto";
import { readdir, readFile, stat } from "node:fs/promises";
import { existsSync } from "node:fs";
import { homedir, hostname } from "node:os";
import { basename, dirname, join, relative, resolve } from "node:path";
import type { CreateSecretInput } from "./vault.js";
import type { SecretKindName } from "./types.js";

export type DiscoveredSecret = CreateSecretInput & {
  source: string;
  fingerprint: string;
};

const SKIP_DIRS = new Set([
  "node_modules",
  ".git",
  ".svn",
  ".hg",
  "dist",
  "build",
  ".next",
  ".nuxt",
  "target",
  "vendor",
  "__pycache__",
  ".venv",
  "venv",
  ".turbo",
  "coverage",
  ".cache",
]);

const ENV_FILE_RE = /^\.env(\..+)?$/i;
const MAX_ENV_BYTES = 200_000;
const MAX_WALK_FILES = 2_000;

/** Well-known API / token environment variable names. */
const API_ENV_EXACT = new Set([
  "OPENAI_API_KEY",
  "ANTHROPIC_API_KEY",
  "GITHUB_TOKEN",
  "GH_TOKEN",
  "GITLAB_TOKEN",
  "NPM_TOKEN",
  "DIGITALOCEAN_ACCESS_TOKEN",
  "STRIPE_SECRET_KEY",
  "STRIPE_API_KEY",
  "TWILIO_AUTH_TOKEN",
  "SENDGRID_API_KEY",
  "CLOUDFLARE_API_TOKEN",
  "HF_TOKEN",
  "HUGGINGFACE_HUB_TOKEN",
  "VERCEL_TOKEN",
  "NETLIFY_AUTH_TOKEN",
  "SUPABASE_SERVICE_ROLE_KEY",
  "DATABASE_URL",
  "POSTGRES_PASSWORD",
  "MYSQL_PASSWORD",
  "REDIS_PASSWORD",
  "AWS_SECRET_ACCESS_KEY",
  "AWS_SESSION_TOKEN",
]);

const API_ENV_SUFFIX_RE =
  /(_API_KEY|_API_TOKEN|_ACCESS_TOKEN|_SECRET_KEY|_SECRET|_TOKEN|_PASSWORD|_PRIVATE_KEY)$/i;

const SKIP_ENV_NAMES = new Set([
  "PATH",
  "HOME",
  "USER",
  "SHELL",
  "TMPDIR",
  "TERM",
  "LANG",
  "PWD",
  "OLDPWD",
  "SSH_AUTH_SOCK",
  "OPENKEY_SESSION",
  "OPENKEY_PASSWORD",
]);

function fingerprint(value: string): string {
  return createHash("sha256").update(value.trim()).digest("hex").slice(0, 16);
}

function isPrivateKeyContent(text: string): boolean {
  return (
    text.includes("BEGIN OPENSSH PRIVATE KEY") ||
    text.includes("BEGIN RSA PRIVATE KEY") ||
    text.includes("BEGIN EC PRIVATE KEY") ||
    text.includes("BEGIN PRIVATE KEY") ||
    text.includes("BEGIN DSA PRIVATE KEY")
  );
}

export function deviceName(override?: string): string {
  if (override?.trim()) return override.trim();
  try {
    return hostname().split(".")[0] || hostname() || "this-device";
  } catch {
    return "this-device";
  }
}

export type DiscoverOptions = {
  device?: string;
  roots?: string[];
  depth?: number;
  ssh?: boolean;
  envFiles?: boolean;
  envVars?: boolean;
  aws?: boolean;
  gh?: boolean;
  docker?: boolean;
};

export async function discoverSecrets(
  opts: DiscoverOptions = {},
): Promise<DiscoveredSecret[]> {
  const device = deviceName(opts.device);
  const found: DiscoveredSecret[] = [];
  const seen = new Set<string>();

  const push = (item: Omit<DiscoveredSecret, "fingerprint" | "device"> & { device?: string }) => {
    const value = (item.secret ?? "").trim();
    if (!value) return;
    const fp = fingerprint(value);
    const key = `${item.kind}:${item.name}:${fp}`;
    if (seen.has(key)) return;
    seen.add(key);
    found.push({
      ...item,
      device,
      fingerprint: fp,
      secret: value,
    });
  };

  if (opts.ssh !== false) {
    for (const item of await scanSsh(device)) push(item);
  }
  if (opts.envVars !== false) {
    for (const item of scanEnvVars(device)) push(item);
  }
  if (opts.aws !== false) {
    for (const item of await scanAwsCredentials(device)) push(item);
  }
  if (opts.gh !== false) {
    for (const item of await scanGhHosts(device)) push(item);
  }
  if (opts.docker !== false) {
    for (const item of await scanDockerConfig(device)) push(item);
  }
  if (opts.envFiles !== false) {
    const roots = opts.roots?.length
      ? opts.roots.map((r) => resolve(r))
      : [process.cwd()];
    const depth = opts.depth ?? 4;
    for (const root of roots) {
      for (const item of await scanEnvFiles(root, depth, device)) push(item);
    }
  }

  return found;
}

async function scanSsh(device: string): Promise<DiscoveredSecret[]> {
  const sshDir = join(homedir(), ".ssh");
  if (!existsSync(sshDir)) return [];
  const out: DiscoveredSecret[] = [];
  let entries: string[];
  try {
    entries = await readdir(sshDir);
  } catch {
    return [];
  }

  const skip = new Set([
    "known_hosts",
    "known_hosts.old",
    "authorized_keys",
    "config",
    "config.d",
  ]);

  for (const name of entries) {
    if (name.startsWith(".") || name.endsWith(".pub") || skip.has(name)) {
      continue;
    }
    const path = join(sshDir, name);
    try {
      const st = await stat(path);
      if (!st.isFile() || st.size > 64_000) continue;
      const body = await readFile(path, "utf8");
      if (!isPrivateKeyContent(body)) continue;
      let publicKey = "";
      const pubPath = `${path}.pub`;
      if (existsSync(pubPath)) {
        publicKey = (await readFile(pubPath, "utf8")).trim();
      }
      out.push({
        name: `SSH · ${name}`,
        kind: "sshKey",
        host: path,
        publicKey,
        secret: body,
        notes: `Discovered from ${path}`,
        device,
        source: path,
        fingerprint: fingerprint(body),
      });
    } catch {
      /* skip unreadable */
    }
  }
  return out;
}

function scanEnvVars(device: string): DiscoveredSecret[] {
  const out: DiscoveredSecret[] = [];
  for (const [name, value] of Object.entries(process.env)) {
    if (!value || value.length < 8) continue;
    if (SKIP_ENV_NAMES.has(name)) continue;
    if (name.startsWith("npm_") || name.startsWith("npm_config_")) continue;
    const match =
      API_ENV_EXACT.has(name) ||
      (API_ENV_SUFFIX_RE.test(name) && !name.startsWith("TERM_"));
    if (!match) continue;
    // Skip paths that look like directories
    if (value.startsWith("/") && existsSync(value) && !value.includes("://")) {
      continue;
    }
    out.push({
      name: name,
      kind: "apiToken",
      host: name,
      secret: value,
      notes: `Discovered from environment variable ${name}`,
      device,
      source: `env:${name}`,
      fingerprint: fingerprint(value),
    });
  }
  return out;
}

async function scanAwsCredentials(device: string): Promise<DiscoveredSecret[]> {
  const path = join(homedir(), ".aws", "credentials");
  if (!existsSync(path)) return [];
  try {
    const text = await readFile(path, "utf8");
    const out: DiscoveredSecret[] = [];
    let profile = "default";
    let accessKey = "";
    let secretKey = "";
    const flush = () => {
      if (secretKey) {
        const body = accessKey
          ? `aws_access_key_id=${accessKey}\naws_secret_access_key=${secretKey}`
          : secretKey;
        out.push({
          name: `AWS · ${profile}`,
          kind: "apiToken",
          host: "aws",
          username: accessKey,
          secret: body,
          notes: `Discovered from ${path} [${profile}]`,
          device,
          source: `${path}#${profile}`,
          fingerprint: fingerprint(body),
        });
      }
      accessKey = "";
      secretKey = "";
    };
    for (const line of text.split(/\r?\n/)) {
      const header = line.match(/^\s*\[([^\]]+)\]\s*$/);
      if (header) {
        flush();
        profile = header[1]!.trim();
        continue;
      }
      const ak = line.match(/^\s*aws_access_key_id\s*=\s*(.+)\s*$/i);
      if (ak) {
        accessKey = ak[1]!.trim();
        continue;
      }
      const sk = line.match(/^\s*aws_secret_access_key\s*=\s*(.+)\s*$/i);
      if (sk) secretKey = sk[1]!.trim();
    }
    flush();
    return out;
  } catch {
    return [];
  }
}

/** GitHub CLI tokens from ~/.config/gh/hosts.yml (and XDG). */
async function scanGhHosts(device: string): Promise<DiscoveredSecret[]> {
  const candidates = [
    join(homedir(), ".config", "gh", "hosts.yml"),
    process.env.XDG_CONFIG_HOME
      ? join(process.env.XDG_CONFIG_HOME, "gh", "hosts.yml")
      : "",
  ].filter(Boolean);

  const out: DiscoveredSecret[] = [];
  for (const path of candidates) {
    if (!existsSync(path)) continue;
    try {
      const text = await readFile(path, "utf8");
      let host = "github.com";
      for (const line of text.split(/\r?\n/)) {
        const hostMatch = line.match(/^([^\s:#][^:]*):\s*$/);
        if (hostMatch) {
          host = hostMatch[1]!.trim();
          continue;
        }
        const tokenMatch = line.match(
          /^\s*(oauth_token|token)\s*:\s*["']?([^\s"']+)["']?\s*$/i,
        );
        if (tokenMatch) {
          const token = tokenMatch[2]!;
          if (token.length < 8) continue;
          out.push({
            name: `GitHub CLI · ${host}`,
            kind: "apiToken",
            host,
            username: "gh",
            secret: token,
            notes: `Discovered from ${path}`,
            device,
            source: `${path}#${host}`,
            fingerprint: fingerprint(token),
          });
        }
      }
    } catch {
      /* skip */
    }
  }
  return out;
}

/** Docker registry credentials from ~/.docker/config.json (decoded auth). */
async function scanDockerConfig(device: string): Promise<DiscoveredSecret[]> {
  const path = join(homedir(), ".docker", "config.json");
  if (!existsSync(path)) return [];
  try {
    const raw = JSON.parse(await readFile(path, "utf8")) as {
      auths?: Record<string, { auth?: string; username?: string; password?: string }>;
    };
    const out: DiscoveredSecret[] = [];
    for (const [registry, entry] of Object.entries(raw.auths ?? {})) {
      let username = entry.username ?? "";
      let password = entry.password ?? "";
      if (entry.auth) {
        try {
          const decoded = Buffer.from(entry.auth, "base64").toString("utf8");
          const idx = decoded.indexOf(":");
          if (idx >= 0) {
            username = decoded.slice(0, idx);
            password = decoded.slice(idx + 1);
          } else if (!password) {
            password = decoded;
          }
        } catch {
          /* keep raw fields */
        }
      }
      if (!password || password.length < 4) continue;
      out.push({
        name: `Docker · ${registry}`,
        kind: "apiToken",
        host: registry,
        username,
        secret: password,
        notes: `Discovered from ${path}`,
        device,
        source: `${path}#${registry}`,
        fingerprint: fingerprint(password),
      });
    }
    return out;
  } catch {
    return [];
  }
}

async function scanEnvFiles(
  root: string,
  maxDepth: number,
  device: string,
): Promise<DiscoveredSecret[]> {
  const out: DiscoveredSecret[] = [];
  let visited = 0;

  async function walk(dir: string, depth: number): Promise<void> {
    if (depth > maxDepth || visited > MAX_WALK_FILES) return;
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const ent of entries) {
      visited++;
      if (visited > MAX_WALK_FILES) return;
      const name = ent.name;
      if (ent.isDirectory()) {
        if (SKIP_DIRS.has(name) || name.startsWith(".")) continue;
        await walk(join(dir, name), depth + 1);
        continue;
      }
      if (!ent.isFile()) continue;
      if (!ENV_FILE_RE.test(name)) continue;
      // Skip example/sample templates
      if (/\.(example|sample|template)$/i.test(name)) continue;
      const path = join(dir, name);
      try {
        const st = await stat(path);
        if (st.size === 0 || st.size > MAX_ENV_BYTES) continue;
        const body = await readFile(path, "utf8");
        if (!body.trim()) continue;
        const rel = relative(root, path) || name;
        const project = basename(dirname(path));
        out.push({
          name: `${project} · ${name}`,
          kind: "envSnippet" as SecretKindName,
          host: path,
          secret: body,
          notes: `Discovered .env at ${path}`,
          device,
          source: path,
          fingerprint: fingerprint(body),
        });
        void rel;
      } catch {
        /* skip */
      }
    }
  }

  if (existsSync(root)) await walk(root, 0);
  return out;
}

/** Filter out candidates already present (same fingerprint or same name+device). */
export function filterNewSecrets(
  candidates: DiscoveredSecret[],
  existing: Array<{ name: string; secret: string; device?: string }>,
): DiscoveredSecret[] {
  const fps = new Set(
    existing.map((e) => fingerprint(e.secret || "")).filter(Boolean),
  );
  const names = new Set(
    existing.map(
      (e) => `${(e.device ?? "").toLowerCase()}::${e.name.toLowerCase()}`,
    ),
  );
  return candidates.filter((c) => {
    const fp = fingerprint(c.secret || "");
    if (fps.has(fp)) return false;
    const key = `${(c.device ?? "").toLowerCase()}::${c.name.toLowerCase()}`;
    if (names.has(key)) return false;
    return true;
  });
}
