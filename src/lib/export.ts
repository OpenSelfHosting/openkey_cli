/** Format vault secrets as dotenv / KEY=value lines. */

import type { DecryptedSecret } from "./types.js";

export type ExportFormat = "dotenv" | "exports";

export type ExportOptions = {
  device?: string;
  kind?: string;
  /** Include only these UUIDs (optional). */
  uuids?: Set<string>;
  format?: ExportFormat;
};

/** Turn a secret display name into a shell/env identifier. */
export function envKeyFromName(name: string): string {
  const cleaned = name
    .trim()
    .replace(/[^A-Za-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .replace(/_+/g, "_");
  const base = cleaned || "SECRET";
  const withPrefix = /^[A-Za-z_]/.test(base) ? base : `_${base}`;
  return withPrefix.toUpperCase();
}

function escapeDotenvValue(value: string): string {
  if (/[\n\r"#\\$`]/.test(value) || value.includes(" ")) {
    return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n").replace(/\r/g, "\\r")}"`;
  }
  return value;
}

/**
 * Build export text from secrets.
 * - `envSnippet` secrets contribute their body as-is (one block per secret).
 * - other kinds become `NAME=value` (or `export NAME=...` for exports format).
 */
export function formatSecretsExport(
  secrets: DecryptedSecret[],
  opts: ExportOptions = {},
): string {
  const deviceFilter = opts.device?.trim().toLowerCase();
  const kindFilter = opts.kind?.trim().toLowerCase();
  const format = opts.format ?? "dotenv";

  const filtered = secrets.filter((s) => {
    if (opts.uuids && !opts.uuids.has(s.uuid)) return false;
    if (deviceFilter && (s.device || "").toLowerCase() !== deviceFilter) {
      return false;
    }
    if (kindFilter && s.secretKind.toLowerCase() !== kindFilter) return false;
    return !!(s.secret ?? "").trim();
  });

  const blocks: string[] = [];
  const usedKeys = new Set<string>();

  for (const s of filtered) {
    if (s.secretKind === "envSnippet") {
      const body = s.secret.replace(/\r\n/g, "\n").replace(/\s+$/, "");
      if (!body) continue;
      blocks.push(`# ${s.name || "env"}${s.device ? ` · ${s.device}` : ""}\n${body}`);
      continue;
    }

    let key = envKeyFromName(s.name || s.host || s.uuid.slice(0, 8));
    if (usedKeys.has(key)) {
      let n = 2;
      while (usedKeys.has(`${key}_${n}`)) n++;
      key = `${key}_${n}`;
    }
    usedKeys.add(key);

    if (format === "exports") {
      const escaped = s.secret.replace(/'/g, `'\\''`);
      blocks.push(`export ${key}='${escaped}'`);
    } else {
      blocks.push(`${key}=${escapeDotenvValue(s.secret)}`);
    }
  }

  return blocks.join("\n\n") + (blocks.length ? "\n" : "");
}

export function listDevices(secrets: DecryptedSecret[]): Array<{
  device: string;
  count: number;
}> {
  const map = new Map<string, number>();
  for (const s of secrets) {
    const d = s.device.trim() || "(ungrouped)";
    map.set(d, (map.get(d) ?? 0) + 1);
  }
  return [...map.entries()]
    .map(([device, count]) => ({ device, count }))
    .sort((a, b) => a.device.localeCompare(b.device));
}
