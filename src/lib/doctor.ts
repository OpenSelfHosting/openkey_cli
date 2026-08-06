/** Local environment diagnostics for the OpenKey CLI. */

import { existsSync, statSync } from "node:fs";
import { platform } from "node:os";
import { configPath, loadConfig } from "./store.js";
import { tryBridgePing } from "./bridge.js";
import { readSessionFromEnv } from "./session.js";
import { packageVersion } from "./version.js";

export type DoctorCheck = {
  id: string;
  ok: boolean;
  detail: string;
};

export async function runDoctor(): Promise<{
  version: string;
  checks: DoctorCheck[];
  ok: boolean;
}> {
  const checks: DoctorCheck[] = [];
  const major = Number(process.versions.node.split(".")[0] ?? 0);
  checks.push({
    id: "node",
    ok: major >= 20,
    detail: `Node.js ${process.version} (need >= 20)`,
  });

  checks.push({
    id: "platform",
    ok: true,
    detail: `${platform()} ${process.arch}`,
  });

  const path = configPath();
  let configDetail = path;
  let configOk = true;
  if (!existsSync(path)) {
    configDetail = `${path} (missing — will be created on first save)`;
  } else {
    try {
      const st = statSync(path);
      const mode = (st.mode & 0o777).toString(8).padStart(3, "0");
      configDetail = `${path} (mode ${mode})`;
      if (platform() !== "win32" && (st.mode & 0o077) !== 0) {
        configOk = false;
        configDetail += " — should be 600";
      }
    } catch (e) {
      configOk = false;
      configDetail = `${path} (unreadable: ${e instanceof Error ? e.message : String(e)})`;
    }
  }
  checks.push({ id: "config", ok: configOk, detail: configDetail });

  const cfg = await loadConfig();
  checks.push({
    id: "server-url",
    ok: !!cfg.serverUrl?.trim(),
    detail: cfg.serverUrl?.trim() || "(not set)",
  });

  const bridge = await tryBridgePing();
  checks.push({
    id: "bridge",
    ok: bridge,
    detail: bridge
      ? "desktop app unlocked"
      : "unavailable (unlock OpenKey desktop, or use server session)",
  });

  const session = readSessionFromEnv();
  if (session) {
    const mins = Math.max(
      0,
      Math.round((session.expiresAt - Date.now()) / 60_000),
    );
    checks.push({
      id: "session",
      ok: true,
      detail: `OPENKEY_SESSION valid (~${mins} min left) for ${session.email}`,
    });
  } else {
    checks.push({
      id: "session",
      ok: false,
      detail: "OPENKEY_SESSION not set (optional if bridge works)",
    });
  }

  checks.push({
    id: "vault",
    ok: bridge || !!session,
    detail:
      bridge || session
        ? `ready via ${bridge ? "native" : "session"}`
        : "locked — unlock app or eval $(openkey unlock)",
  });

  if (cfg.serverUrl?.trim()) {
    const health = await probeServer(cfg.serverUrl);
    checks.push({
      id: "server",
      ok: health.ok,
      detail: health.detail,
    });
  } else {
    checks.push({
      id: "server",
      ok: true,
      detail: "skipped (no server URL)",
    });
  }

  checks.push({
    id: "logged-in",
    ok: !!cfg.accessToken,
    detail: cfg.accessToken
      ? `yes (${cfg.email ?? "unknown email"})`
      : "no (optional for bridge-only use)",
  });

  checks.push({
    id: "cache",
    ok: true,
    detail: `${cfg.entries.length} entries, ${cfg.collections.length} collections cached`,
  });

  const clip = await probeClipboard();
  checks.push({ id: "clipboard", ok: clip.ok, detail: clip.detail });

  // Bridge OR session is enough for vault. Server reachability is informational
  // unless the user relies on sync (still shown as !! when down).
  const hard = new Set(["node", "config", "vault"]);
  const ok = checks.filter((c) => hard.has(c.id)).every((c) => c.ok);

  return { version: packageVersion(), checks, ok };
}

async function probeServer(
  serverUrl: string,
): Promise<{ ok: boolean; detail: string }> {
  const root = serverUrl.replace(/\/$/, "");
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 3000);
  try {
    const res = await fetch(`${root}/health`, { signal: controller.signal });
    const text = await res.text();
    let status = "";
    try {
      const json = JSON.parse(text) as { status?: string; database?: string };
      status = json.status ?? "";
      if (json.database) status += ` db=${json.database}`;
    } catch {
      status = text.slice(0, 80);
    }
    return {
      ok: res.ok,
      detail: res.ok
        ? `${root}/health → ${status || res.status}`
        : `${root}/health → HTTP ${res.status}`,
    };
  } catch (e) {
    return {
      ok: false,
      detail: `${root}/health unreachable (${e instanceof Error ? e.message : String(e)})`,
    };
  } finally {
    clearTimeout(timer);
  }
}

async function probeClipboard(): Promise<{ ok: boolean; detail: string }> {
  const os = platform();
  if (os === "darwin") return { ok: true, detail: "pbcopy available" };
  if (os === "win32") return { ok: true, detail: "clip available" };
  const { spawnSync } = await import("node:child_process");
  for (const cmd of ["wl-copy", "xclip", "xsel"]) {
    const r = spawnSync("which", [cmd], { encoding: "utf8" });
    if (r.status === 0) return { ok: true, detail: `${cmd} available` };
  }
  return {
    ok: false,
    detail: "no clipboard tool (install wl-copy, xclip, or xsel)",
  };
}
