import type { Command } from "commander";
import { spawn } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import { saveConfig, loadConfig } from "../lib/store.js";
import {
  cmdConfigSetServer,
  cmdConfigShow,
  cmdForget,
  cmdLock,
  cmdLogin,
  cmdLogout,
  cmdStatus,
  cmdUnlock,
} from "./auth.js";
import {
  isJsonMode,
  printJson,
  printLine,
  printTable,
  prompt,
  readStdin,
} from "../lib/output.js";
import { syncPull, syncPushEntries } from "../lib/api.js";
import { upsertCollections, upsertEntries } from "../lib/store.js";
import { generatePassword } from "../lib/crypto.js";
import { copyToClipboard } from "../lib/clipboard.js";
import {
  createSecret,
  deleteSecret,
  itemFieldValue,
  itemLabel,
  itemSecretValue,
  listDecryptedItems,
  listLogins,
  listSecrets,
  matchQuery,
  parseEnvBinding,
  parseItemField,
  resolveOneMatch,
  shellSingleQuote,
  updateSecret,
  upsertSecret,
} from "../lib/vault.js";
import { generateTotp, totpRemaining } from "../lib/totp.js";
import { runDoctor } from "../lib/doctor.js";
import {
  maskSecret,
  secretKindLabel,
  normalizeSecretKind,
} from "../lib/types.js";
import {
  deviceName,
  discoverSecrets,
  filterNewSecrets,
} from "../lib/discover.js";
import {
  completionScript,
  type CompletionShell,
} from "../lib/completion.js";
import { formatSecretsExport, listDevices } from "../lib/export.js";
export function registerCommands(program: Command): void {
  const config = program.command("config").description("CLI configuration");
  config
    .command("set-server")
    .argument("<url>", "Self-hosted OpenKey server URL")
    .description("Set the sync server URL")
    .action(async (url: string) => {
      await cmdConfigSetServer(url);
    });
  config
    .command("show")
    .description("Show current config")
    .action(async () => {
      await cmdConfigShow();
    });
  config
    .command("set-lock")
    .argument("<minutes>", "Session lifetime in minutes")
    .description("Set unlock session duration")
    .action(async (minutes: string) => {
      const n = Math.max(1, Math.min(1440, Number(minutes) || 15));
      await saveConfig({ lockMinutes: n });
      if (isJsonMode()) printJson({ lockMinutes: n });
      else printLine(`Session lock set to ${n} minutes`);
    });

  program
    .command("login")
    .description("Optional: log in to a self-hosted OpenKey server")
    .option("-e, --email <email>", "Account email")
    .option("-s, --server <url>", "Server URL")
    .action(async (opts: { email?: string; server?: string }) => {
      await cmdLogin(opts);
    });

  program
    .command("logout")
    .description("Clear server access tokens")
    .action(async () => {
      await cmdLogout();
    });

  program
    .command("unlock")
    .description(
      "Optional: unlock server vault and print OPENKEY_SESSION export",
    )
    .option("-e, --email <email>", "Account email")
    .option("--raw", "Print session token only")
    .action(async (opts: { email?: string; raw?: boolean }) => {
      await cmdUnlock(opts);
    });

  program
    .command("lock")
    .description("Print shell command to clear OPENKEY_SESSION")
    .action(async () => {
      await cmdLock();
    });

  program
    .command("status")
    .description("Show desktop bridge / session / server status")
    .action(async () => {
      await cmdStatus();
    });

  program
    .command("forget")
    .description("Wipe local CLI config and cached ciphertext")
    .action(async () => {
      await cmdForget();
    });

  program
    .command("sync")
    .description("Pull ciphertext from the server (optionally push local cache)")
    .option("--push", "Also push local cached entries to the server")
    .action(async (opts: { push?: boolean }) => {
      const cfg = await loadConfig();
      if (!cfg.accessToken) throw new Error("Not logged in — run openkey login");

      let pushedCount = 0;
      if (opts.push && cfg.entries.length) {
        const pushed = await syncPushEntries(cfg, cfg.entries);
        await upsertEntries(pushed.entries);
        await upsertCollections(pushed.collections);
        await saveConfig({ serverRevision: pushed.serverRevision });
        pushedCount = cfg.entries.length;
      }

      const next = await loadConfig();
      const pulled = await syncPull(next);
      await upsertEntries(pulled.entries);
      await upsertCollections(pulled.collections);
      await saveConfig({ serverRevision: pulled.serverRevision });
      if (isJsonMode()) {
        printJson({
          pushed: pushedCount,
          entries: pulled.entries.length,
          collections: pulled.collections.length,
          serverRevision: pulled.serverRevision,
        });
      } else {
        if (opts.push) {
          printLine(`Pushed ${pushedCount} local entr${pushedCount === 1 ? "y" : "ies"}`);
        }
        printLine(
          `Synced ${pulled.entries.length} entries, ${pulled.collections.length} collections (rev ${pulled.serverRevision})`,
        );
      }
    });

  program
    .command("doctor")
    .description("Diagnose CLI, bridge, session, and server connectivity")
    .action(async () => {
      const report = await runDoctor();
      if (isJsonMode()) {
        printJson(report);
      } else {
        printLine(`openkey ${report.version}`);
        for (const c of report.checks) {
          printLine(`${c.ok ? "ok" : "!!"}  ${c.id.padEnd(12)} ${c.detail}`);
        }
        printLine("");
        printLine(report.ok ? "Doctor: ready" : "Doctor: issues found (see !! above)");
      }
      if (!report.ok) process.exitCode = 1;
    });

  program
    .command("gen")
    .description("Generate a password (offline — no login or app required)")
    .option("-l, --length <n>", "Length (4–64)", "20")
    .option("--no-upper", "Exclude uppercase")
    .option("--no-lower", "Exclude lowercase")
    .option("--no-digits", "Exclude digits")
    .option("--no-symbols", "Exclude symbols")
    .option("-a, --avoid-ambiguous", "Avoid Il1O0o")
    .option("-c, --copy", "Copy to clipboard")
    .action(
      async (opts: {
        length: string;
        upper?: boolean;
        lower?: boolean;
        digits?: boolean;
        symbols?: boolean;
        avoidAmbiguous?: boolean;
        copy?: boolean;
      }) => {
        const password = generatePassword({
          length: Number(opts.length) || 20,
          upper: opts.upper,
          lower: opts.lower,
          digits: opts.digits,
          symbols: opts.symbols,
          avoidAmbiguous: !!opts.avoidAmbiguous,
        });
        if (opts.copy) {
          await copyToClipboard(password);
          if (isJsonMode()) printJson({ copied: true, length: password.length });
          else printLine(`Copied ${password.length}-char password to clipboard`);
        } else if (isJsonMode()) {
          printJson({ password });
        } else {
          console.log(password);
        }
      },
    );

  const secret = program
    .command("secret")
    .description(
      "Manage developer secrets (uses unlocked desktop app; login optional)",
    );

  secret
    .command("list")
    .description("List secrets (values masked)")
    .option("-d, --device <name>", "Filter by device collection")
    .option("-k, --kind <kind>", "Filter by kind (sshKey|apiToken|envSnippet|other)")
    .action(async (opts: { device?: string; kind?: string }) => {
      let secrets = await listSecrets();
      if (opts.device?.trim()) {
        const d = opts.device.trim().toLowerCase();
        secrets = secrets.filter((s) => (s.device || "").toLowerCase() === d);
      }
      if (opts.kind?.trim()) {
        const k = normalizeSecretKind(opts.kind);
        secrets = secrets.filter((s) => s.secretKind === k);
      }
      if (isJsonMode()) {
        printJson(
          secrets.map((s) => ({
            uuid: s.uuid,
            name: s.name,
            kind: s.secretKind,
            device: s.device,
            host: s.host,
            username: s.username,
            secret: maskSecret(s.secret),
          })),
        );
        return;
      }
      if (!secrets.length) {
        printLine("No secrets. Add one with: openkey secret add --name ...");
        return;
      }
      printTable(
        ["UUID", "Name", "Kind", "Device", "Secret"],
        secrets.map((s) => [
          s.uuid.slice(0, 8),
          s.name || "—",
          secretKindLabel(s.secretKind),
          s.device || "—",
          maskSecret(s.secret),
        ]),
      );
    });

  secret
    .command("add")
    .description("Add a developer secret")
    .requiredOption("-n, --name <name>", "Display name")
    .option(
      "-k, --kind <kind>",
      "sshKey | apiToken | envSnippet | other",
      "apiToken",
    )
    .option("-s, --secret <value>", "Secret value / private key / token (use - for stdin)")
    .option("-f, --file <path>", "Read secret from file")
    .option("--stdin", "Read secret from stdin")
    .option("-u, --username <user>", "Username")
    .option("-H, --host <host>", "Host")
    .option("-d, --device <name>", "Device collection name (default: hostname)")
    .option("--public-key <key>", "SSH public key")
    .option("--public-key-file <path>", "Read public key from file")
    .option("--passphrase <pass>", "Key passphrase")
    .option("--notes <notes>", "Notes")
    .action(
      async (opts: {
        name: string;
        kind: string;
        secret?: string;
        file?: string;
        stdin?: boolean;
        username?: string;
        host?: string;
        device?: string;
        publicKey?: string;
        publicKeyFile?: string;
        passphrase?: string;
        notes?: string;
      }) => {
        let secretValue = opts.secret ?? "";
        if (opts.file) {
          secretValue = await readFile(opts.file, "utf8");
        } else if (opts.stdin || opts.secret === "-") {
          secretValue = await readStdin();
        }
        let publicKey = opts.publicKey ?? "";
        if (opts.publicKeyFile) {
          publicKey = (await readFile(opts.publicKeyFile, "utf8")).trim();
        }
        if (!secretValue.trim()) {
          throw new Error("Provide --secret, --file, or --stdin");
        }
        const created = await createSecret({
          name: opts.name,
          kind: normalizeSecretKind(opts.kind),
          secret: secretValue,
          username: opts.username,
          host: opts.host,
          publicKey,
          passphrase: opts.passphrase,
          notes: opts.notes,
          device: opts.device?.trim() || deviceName(),
        });
        if (isJsonMode()) {
          printJson({
            uuid: created.uuid,
            name: created.name,
            kind: created.secretKind,
            device: created.device,
          });
        } else {
          printLine(
            `Created secret ${created.uuid} (${created.name})` +
              (created.device ? ` · device ${created.device}` : ""),
          );
        }
      },
    );

  secret
    .command("set")
    .description("Create or update a secret matched by name + device")
    .requiredOption("-n, --name <name>", "Display name")
    .option(
      "-k, --kind <kind>",
      "sshKey | apiToken | envSnippet | other",
      "apiToken",
    )
    .option("-s, --secret <value>", "Secret value (use - for stdin)")
    .option("-f, --file <path>", "Read secret from file")
    .option("--stdin", "Read secret from stdin")
    .option("-u, --username <user>", "Username")
    .option("-H, --host <host>", "Host")
    .option("-d, --device <name>", "Device collection name (default: hostname)")
    .option("--public-key <key>", "SSH public key")
    .option("--public-key-file <path>", "Read public key from file")
    .option("--passphrase <pass>", "Key passphrase")
    .option("--notes <notes>", "Notes")
    .action(
      async (opts: {
        name: string;
        kind: string;
        secret?: string;
        file?: string;
        stdin?: boolean;
        username?: string;
        host?: string;
        device?: string;
        publicKey?: string;
        publicKeyFile?: string;
        passphrase?: string;
        notes?: string;
      }) => {
        let secretValue = opts.secret ?? "";
        if (opts.file) {
          secretValue = await readFile(opts.file, "utf8");
        } else if (opts.stdin || opts.secret === "-") {
          secretValue = await readStdin();
        }
        let publicKey = opts.publicKey ?? "";
        if (opts.publicKeyFile) {
          publicKey = (await readFile(opts.publicKeyFile, "utf8")).trim();
        }
        if (!secretValue.trim()) {
          throw new Error("Provide --secret, --file, or --stdin");
        }
        const { secret: saved, created } = await upsertSecret({
          name: opts.name,
          kind: normalizeSecretKind(opts.kind),
          secret: secretValue,
          username: opts.username,
          host: opts.host,
          publicKey,
          passphrase: opts.passphrase,
          notes: opts.notes,
          device: opts.device?.trim() || deviceName(),
        });
        if (isJsonMode()) {
          printJson({
            uuid: saved.uuid,
            name: saved.name,
            kind: saved.secretKind,
            device: saved.device,
            created,
          });
        } else {
          printLine(
            `${created ? "Created" : "Updated"} secret ${saved.uuid.slice(0, 8)} (${saved.name})` +
              (saved.device ? ` · device ${saved.device}` : ""),
          );
        }
      },
    );

  secret
    .command("get")
    .argument("<query>", "Name, host, or UUID prefix")
    .description("Print a secret value")
    .action(async (query: string) => {
      const s = resolveOneMatch(await listSecrets(), query, { noun: "secret" });
      if (isJsonMode()) {
        printJson({
          uuid: s.uuid,
          name: s.name,
          kind: s.secretKind,
          username: s.username,
          host: s.host,
          publicKey: s.publicKey,
          secret: s.secret,
          passphrase: s.passphrase,
          notes: s.notes,
        });
      } else {
        console.log(s.secret);
      }
    });

  secret
    .command("update")
    .argument("<query>", "Name, host, or UUID prefix")
    .description("Update fields on an existing secret")
    .option("-n, --name <name>", "New display name")
    .option("-k, --kind <kind>", "sshKey | apiToken | envSnippet | other")
    .option("-s, --secret <value>", "New secret value (use - for stdin)")
    .option("-f, --file <path>", "Read new secret from file")
    .option("--stdin", "Read new secret from stdin")
    .option("-u, --username <user>", "Username")
    .option("-H, --host <host>", "Host")
    .option("-d, --device <name>", "Device collection name")
    .option("--public-key <key>", "SSH public key")
    .option("--public-key-file <path>", "Read public key from file")
    .option("--passphrase <pass>", "Key passphrase")
    .option("--notes <notes>", "Notes")
    .action(
      async (
        query: string,
        opts: {
          name?: string;
          kind?: string;
          secret?: string;
          file?: string;
          stdin?: boolean;
          username?: string;
          host?: string;
          device?: string;
          publicKey?: string;
          publicKeyFile?: string;
          passphrase?: string;
          notes?: string;
        },
      ) => {
        const current = resolveOneMatch(await listSecrets(), query, {
          noun: "secret",
        });
        const patch: Parameters<typeof updateSecret>[1] = {};
        if (opts.name !== undefined) patch.name = opts.name;
        if (opts.kind !== undefined) patch.kind = normalizeSecretKind(opts.kind);
        if (opts.username !== undefined) patch.username = opts.username;
        if (opts.host !== undefined) patch.host = opts.host;
        if (opts.device !== undefined) patch.device = opts.device;
        if (opts.passphrase !== undefined) patch.passphrase = opts.passphrase;
        if (opts.notes !== undefined) patch.notes = opts.notes;

        if (opts.file) {
          patch.secret = await readFile(opts.file, "utf8");
        } else if (opts.stdin || opts.secret === "-") {
          patch.secret = await readStdin();
        } else if (opts.secret !== undefined) {
          patch.secret = opts.secret;
        }

        if (opts.publicKeyFile) {
          patch.publicKey = (await readFile(opts.publicKeyFile, "utf8")).trim();
        } else if (opts.publicKey !== undefined) {
          patch.publicKey = opts.publicKey;
        }

        const updated = await updateSecret(current.uuid, patch);
        if (isJsonMode()) {
          printJson({
            uuid: updated.uuid,
            name: updated.name,
            kind: updated.secretKind,
            device: updated.device,
            revision: updated.revision,
          });
        } else {
          printLine(`Updated secret ${updated.uuid.slice(0, 8)} (${updated.name})`);
        }
      },
    );

  secret
    .command("export")
    .description("Export secrets as .env / KEY=value (or shell exports)")
    .option("-d, --device <name>", "Only this device collection")
    .option(
      "-k, --kind <kind>",
      "Only this kind (sshKey|apiToken|envSnippet|other)",
    )
    .option("-o, --output <path>", "Write to file instead of stdout")
    .option(
      "--format <fmt>",
      "dotenv (default) | exports",
      "dotenv",
    )
    .action(
      async (opts: {
        device?: string;
        kind?: string;
        output?: string;
        format: string;
      }) => {
        const fmt = opts.format.trim().toLowerCase();
        if (fmt !== "dotenv" && fmt !== "exports") {
          throw new Error('Format must be "dotenv" or "exports"');
        }
        const secrets = await listSecrets();
        const text = formatSecretsExport(secrets, {
          device: opts.device,
          kind: opts.kind ? normalizeSecretKind(opts.kind) : undefined,
          format: fmt,
        });
        if (isJsonMode()) {
          printJson({
            device: opts.device ?? null,
            kind: opts.kind ? normalizeSecretKind(opts.kind) : null,
            format: fmt,
            bytes: Buffer.byteLength(text, "utf8"),
            text,
          });
          return;
        }
        if (opts.output) {
          await writeFile(opts.output, text, { mode: 0o600 });
          printLine(`Wrote ${opts.output} (${Buffer.byteLength(text, "utf8")} bytes)`);
        } else {
          process.stdout.write(text);
        }
      },
    );

  secret
    .command("devices")
    .description("List device collections and secret counts")
    .action(async () => {
      const secrets = await listSecrets();
      const devices = listDevices(secrets);
      if (isJsonMode()) {
        printJson(devices);
        return;
      }
      if (!devices.length) {
        printLine("No secrets / devices yet.");
        return;
      }
      printTable(
        ["Device", "Secrets"],
        devices.map((d) => [d.device, String(d.count)]),
      );
    });

  secret
    .command("copy")
    .argument("<query>", "Name, host, or UUID prefix")
    .description("Copy secret value to clipboard")
    .option(
      "--clear <seconds>",
      "Clear clipboard after N seconds (default: 45)",
      "45",
    )
    .option("--keep", "Do not auto-clear the clipboard")
    .action(
      async (
        query: string,
        opts: { clear: string; keep?: boolean },
      ) => {
        const s = resolveOneMatch(await listSecrets(), query, { noun: "secret" });
        if (!s.secret) throw new Error("Secret is empty");
        const clearAfterMs = opts.keep
          ? undefined
          : Math.max(0, Number(opts.clear) || 45) * 1000;
        await copyToClipboard(s.secret, { clearAfterMs });
        if (isJsonMode()) {
          printJson({
            copied: true,
            name: s.name,
            uuid: s.uuid,
            clearAfterMs: clearAfterMs ?? null,
          });
        } else {
          printLine(
            `Copied secret for "${s.name}" to clipboard` +
              (clearAfterMs
                ? ` (clears in ${Math.round(clearAfterMs / 1000)}s)`
                : ""),
          );
        }
      },
    );

  secret
    .command("rm")
    .argument("<query>", "Name, host, or UUID prefix")
    .description("Delete a secret")
    .option("-y, --yes", "Skip confirmation")
    .action(async (query: string, opts: { yes?: boolean }) => {
      const s = resolveOneMatch(await listSecrets(), query, { noun: "secret" });
      if (!opts.yes) {
        const answer = await prompt(
          `Delete "${s.name}" (${s.uuid.slice(0, 8)})? [y/N] `,
        );
        if (answer.trim().toLowerCase() !== "y") {
          printLine("Cancelled");
          return;
        }
      }
      await deleteSecret(s.uuid);
      if (isJsonMode()) printJson({ deleted: s.uuid });
      else printLine(`Deleted ${s.name}`);
    });

  program
    .command("discover")
    .description(
      "Scan this machine for SSH keys, .env files, and API tokens; save under a device collection",
    )
    .option("-d, --device <name>", "Device collection name (default: hostname)")
    .option(
      "-p, --path <dir>",
      "Project root(s) to scan for .env (repeatable)",
      (v: string, acc: string[]) => [...acc, v],
      [] as string[],
    )
    .option("--depth <n>", "Max directory depth for .env scan", "4")
    .option("--no-ssh", "Skip ~/.ssh")
    .option("--no-env-files", "Skip .env files")
    .option("--no-env-vars", "Skip process environment variables")
    .option("--no-aws", "Skip ~/.aws/credentials")
    .option("--no-gh", "Skip GitHub CLI hosts.yml tokens")
    .option("--no-docker", "Skip ~/.docker/config.json registry auth")
    .option("--dry-run", "List matches without saving")
    .option("-y, --yes", "Save all new secrets without prompting")
    .action(
      async (opts: {
        device?: string;
        path: string[];
        depth: string;
        ssh?: boolean;
        envFiles?: boolean;
        envVars?: boolean;
        aws?: boolean;
        gh?: boolean;
        docker?: boolean;
        dryRun?: boolean;
        yes?: boolean;
      }) => {
        const device = deviceName(opts.device);
        printLine(`Scanning for secrets → device collection "${device}"…`);
        const found = await discoverSecrets({
          device,
          roots: opts.path.length ? opts.path : undefined,
          depth: Number(opts.depth) || 4,
          ssh: opts.ssh,
          envFiles: opts.envFiles,
          envVars: opts.envVars,
          aws: opts.aws,
          gh: opts.gh,
          docker: opts.docker,
        });

        let existing: Array<{ name: string; secret: string; device?: string }> =
          [];
        try {
          existing = await listSecrets();
        } catch {
          /* vault locked / bridge down — still allow dry-run listing */
          if (!opts.dryRun) {
            throw new Error(
              "Unlock the OpenKey desktop app (or eval $(openkey unlock)) before saving discovered secrets.",
            );
          }
        }

        const neu = filterNewSecrets(found, existing);
        const skipped = found.length - neu.length;

        if (opts.dryRun) {
          if (isJsonMode()) {
            printJson({
              device,
              found: found.length,
              new: neu.length,
              skipped,
              dryRun: true,
              items: found.map((c) => ({
                name: c.name,
                kind: c.kind,
                source: c.source,
                device: c.device,
                preview: maskSecret(c.secret ?? ""),
              })),
            });
          } else if (!found.length) {
            printLine("No secrets found.");
          } else {
            printTable(
              ["Kind", "Name", "Source", "Preview"],
              found.map((c) => [
                String(c.kind ?? ""),
                c.name,
                c.source,
                maskSecret(c.secret ?? ""),
              ]),
            );
            if (skipped > 0) {
              printLine(`(${skipped} already in vault — skipped)`);
            }
            printLine(
              "Dry run — nothing saved. Re-run without --dry-run to import.",
            );
          }
          return;
        }

        if (!isJsonMode()) {
          if (!found.length) {
            printLine("No secrets found.");
            return;
          }
          printTable(
            ["Kind", "Name", "Source", "Preview"],
            neu.map((c) => [
              String(c.kind ?? ""),
              c.name,
              c.source,
              maskSecret(c.secret ?? ""),
            ]),
          );
          if (skipped > 0) {
            printLine(`(${skipped} already in vault — skipped)`);
          }
          if (!neu.length) {
            printLine("Nothing new to import.");
            return;
          }
        } else if (!neu.length) {
          printJson({
            device,
            found: found.length,
            new: 0,
            skipped,
            dryRun: false,
            saved: 0,
            items: [],
          });
          return;
        }

        if (!opts.yes && !isJsonMode()) {
          const answer = await prompt(
            `Import ${neu.length} secret(s) into device "${device}"? [y/N] `,
          );
          if (answer.trim().toLowerCase() !== "y") {
            printLine("Cancelled");
            return;
          }
        }

        let saved = 0;
        for (const item of neu) {
          await createSecret({
            name: item.name,
            kind: item.kind,
            secret: item.secret,
            username: item.username,
            host: item.host,
            publicKey: item.publicKey,
            passphrase: item.passphrase,
            notes: item.notes,
            device: item.device || device,
          });
          saved++;
        }
        if (isJsonMode()) {
          printJson({
            device,
            found: found.length,
            new: neu.length,
            skipped,
            dryRun: false,
            saved,
            items: neu.map((c) => ({
              name: c.name,
              kind: c.kind,
              source: c.source,
              device: c.device,
              preview: maskSecret(c.secret ?? ""),
            })),
          });
        } else {
          printLine(`Saved ${saved} secret(s) under device "${device}".`);
        }
      },
    );

  program
    .command("get")
    .argument("<query>", "Search secrets and logins")
    .description("Get password/secret for the best match")
    .option(
      "-f, --field <name>",
      "password | username | url | totp | notes (default: password)",
      "password",
    )
    .action(async (query: string, opts: { field: string }) => {
      const item = resolveOneMatch(await listDecryptedItems(), query);
      const field = parseItemField(opts.field);
      const value = itemFieldValue(item, field);
      if (isJsonMode()) {
        printJson({
          uuid: item.uuid,
          kind: item.kind,
          name: itemLabel(item),
          field,
          value,
        });
      } else {
        console.log(value);
      }
    });

  program
    .command("copy")
    .argument("<query>", "Search secrets and logins")
    .description("Copy password/secret for the best match")
    .option(
      "-f, --field <name>",
      "password | username | url | totp | notes (default: password)",
      "password",
    )
    .option(
      "--clear <seconds>",
      "Clear clipboard after N seconds (default: 45)",
      "45",
    )
    .option("--keep", "Do not auto-clear the clipboard")
    .action(
      async (
        query: string,
        opts: { field: string; clear: string; keep?: boolean },
      ) => {
        const item = resolveOneMatch(await listDecryptedItems(), query);
        const field = parseItemField(opts.field);
        const value = itemFieldValue(item, field);
        if (!value) throw new Error("Value is empty");
        const clearAfterMs = opts.keep
          ? undefined
          : Math.max(0, Number(opts.clear) || 45) * 1000;
        await copyToClipboard(value, { clearAfterMs });
        if (isJsonMode()) {
          printJson({
            copied: true,
            kind: item.kind,
            name: itemLabel(item),
            field,
            clearAfterMs: clearAfterMs ?? null,
          });
        } else {
          printLine(
            `Copied ${field} for ${item.kind} "${itemLabel(item)}" to clipboard` +
              (clearAfterMs
                ? ` (clears in ${Math.round(clearAfterMs / 1000)}s)`
                : ""),
          );
        }
      },
    );

  program
    .command("totp")
    .argument("<query>", "Login name, URL, or UUID prefix")
    .description("Print (or copy) a TOTP code for a login")
    .option("-c, --copy", "Copy code to clipboard")
    .option("-w, --watch", "Refresh the code live until Ctrl+C")
    .option(
      "--clear <seconds>",
      "Clear clipboard after N seconds when using --copy (default: 45)",
      "45",
    )
    .option("--keep", "Do not auto-clear the clipboard")
    .action(
      async (
        query: string,
        opts: { copy?: boolean; watch?: boolean; clear: string; keep?: boolean },
      ) => {
        const items = await listDecryptedItems();
        const withTotp = items.filter(
          (i) => i.kind === "login" && i.totp?.secret,
        );
        const item = resolveOneMatch(withTotp, query, {
          noun: "login with TOTP",
        });
        if (item.kind !== "login" || !item.totp?.secret) {
          throw new Error(`No TOTP on "${itemLabel(item)}"`);
        }
        const totpCfg = item.totp;

        if (opts.watch) {
          if (isJsonMode()) {
            throw new Error("--watch is for interactive terminals (omit --json)");
          }
          const period = totpCfg.period ?? 30;
          const draw = () => {
            const code = generateTotp(totpCfg);
            const left = totpRemaining(period);
            const barLen = 20;
            const filled = Math.round((left / period) * barLen);
            const bar = "█".repeat(filled) + "░".repeat(barLen - filled);
            process.stdout.write(
              `\r${itemLabel(item)}  ${code}  ${bar} ${String(left).padStart(2, " ")}s   `,
            );
          };
          draw();
          const timer = setInterval(draw, 250);
          await new Promise<void>((resolve) => {
            const stop = () => {
              clearInterval(timer);
              process.stdout.write("\n");
              resolve();
            };
            process.once("SIGINT", stop);
            process.once("SIGTERM", stop);
          });
          return;
        }

        const code = generateTotp(totpCfg);
        const remaining = totpRemaining(totpCfg.period ?? 30);
        if (opts.copy) {
          const clearAfterMs = opts.keep
            ? undefined
            : Math.max(0, Number(opts.clear) || 45) * 1000;
          await copyToClipboard(code, { clearAfterMs });
          if (isJsonMode()) {
            printJson({
              copied: true,
              code,
              remaining,
              name: itemLabel(item),
              uuid: item.uuid,
            });
          } else {
            printLine(
              `Copied TOTP for "${itemLabel(item)}" (${remaining}s left` +
                (clearAfterMs
                  ? `; clipboard clears in ${Math.round(clearAfterMs / 1000)}s`
                  : "") +
                ")",
            );
          }
          return;
        }
        if (isJsonMode()) {
          printJson({
            code,
            remaining,
            period: totpCfg.period ?? 30,
            name: itemLabel(item),
            uuid: item.uuid,
          });
        } else {
          console.log(code);
        }
      },
    );

  program
    .command("logins")
    .description("List login entries (passwords masked)")
    .action(async () => {
      const logins = await listLogins();
      if (isJsonMode()) {
        printJson(
          logins.map((l) => ({
            uuid: l.uuid,
            title: l.title,
            username: l.username,
            urls: l.urls,
            password: maskSecret(l.password),
            totp: !!l.totp?.secret,
          })),
        );
        return;
      }
      if (!logins.length) {
        printLine("No logins.");
        return;
      }
      printTable(
        ["UUID", "Title", "Username", "URL", "TOTP"],
        logins.map((l) => [
          l.uuid.slice(0, 8),
          l.title || "—",
          l.username || "—",
          l.urls[0] || "—",
          l.totp?.secret ? "yes" : "—",
        ]),
      );
    });

  program
    .command("search")
    .argument("<query>", "Search query")
    .description("Search secrets and logins (masked)")
    .action(async (query: string) => {
      const items = matchQuery(await listDecryptedItems(), query);
      if (isJsonMode()) {
        printJson(
          items.map((i) => ({
            uuid: i.uuid,
            kind: i.kind,
            name: itemLabel(i),
            preview: maskSecret(itemSecretValue(i)),
            totp: i.kind === "login" ? !!i.totp?.secret : false,
          })),
        );
        return;
      }
      if (!items.length) {
        printLine("No matches");
        return;
      }
      printTable(
        ["UUID", "Kind", "Name", "Preview", "TOTP"],
        items.map((i) => [
          i.uuid.slice(0, 8),
          i.kind,
          itemLabel(i),
          maskSecret(itemSecretValue(i)),
          i.kind === "login" && i.totp?.secret ? "yes" : "—",
        ]),
      );
    });

  program
    .command("env")
    .description(
      "Print shell exports for vault secrets (eval $(openkey env NAME …))",
    )
    .argument(
      "[bindings...]",
      "NAME or NAME=query (default: export matching secret name)",
    )
    .option(
      "-e, --export <binding>",
      "Repeatable NAME or NAME=query binding",
      (v: string, acc: string[]) => [...acc, v],
      [] as string[],
    )
    .option("--raw", "Print values only (one per line; single binding)")
    .action(
      async (
        bindings: string[],
        opts: { export: string[]; raw?: boolean },
      ) => {
        const all = [...opts.export, ...bindings];
        if (!all.length) {
          throw new Error(
            "Provide at least one NAME or NAME=query (e.g. openkey env DATABASE_URL)",
          );
        }
        const items = await listDecryptedItems();
        const resolved = all.map((raw) => {
          const { envName, query } = parseEnvBinding(raw);
          const item = resolveOneMatch(items, query);
          const value = itemSecretValue(item);
          if (!value) throw new Error(`Empty value for "${query}"`);
          return { envName, query, value, name: itemLabel(item), uuid: item.uuid };
        });

        if (isJsonMode()) {
          printJson(
            resolved.map((r) => ({
              env: r.envName,
              query: r.query,
              name: r.name,
              uuid: r.uuid,
              value: r.value,
            })),
          );
          return;
        }

        if (opts.raw) {
          if (resolved.length !== 1) {
            throw new Error("--raw requires exactly one binding");
          }
          console.log(resolved[0]!.value);
          return;
        }

        for (const r of resolved) {
          console.log(`export ${r.envName}=${shellSingleQuote(r.value)}`);
        }
      },
    );

  program
    .command("run")
    .description("Run a command with secrets injected into the environment")
    .option(
      "-e, --env <binding>",
      "NAME or NAME=query (repeatable)",
      (v: string, acc: string[]) => [...acc, v],
      [] as string[],
    )
    .allowExcessArguments(true)
    .action(async (opts: { env: string[] }) => {
      const dash = process.argv.indexOf("--");
      const argv = dash >= 0 ? process.argv.slice(dash + 1) : [];
      if (!argv.length) {
        throw new Error(
          "Usage: openkey run -e NAME[=query] … -- <command> [args…]",
        );
      }
      if (!opts.env.length) {
        throw new Error("Provide at least one -e/--env NAME or NAME=query");
      }

      const items = await listDecryptedItems();
      const env = { ...process.env };
      for (const raw of opts.env) {
        const { envName, query } = parseEnvBinding(raw);
        const item = resolveOneMatch(items, query);
        const value = itemSecretValue(item);
        if (!value) throw new Error(`Empty value for "${query}"`);
        env[envName] = value;
      }

      const code = await new Promise<number>((resolve, reject) => {
        const child = spawn(argv[0]!, argv.slice(1), {
          env,
          stdio: "inherit",
          shell: false,
        });
        child.on("error", reject);
        child.on("close", (c) => resolve(c ?? 1));
      });
      process.exitCode = code;
    });

  program
    .command("completion")
    .description("Print shell completion script (bash | zsh | fish)")
    .argument("[shell]", "bash, zsh, or fish", "bash")
    .action(async (shell: string) => {
      const s = shell.trim().toLowerCase();
      if (s !== "bash" && s !== "zsh" && s !== "fish") {
        throw new Error("Shell must be bash, zsh, or fish");
      }
      console.log(completionScript(s as CompletionShell));
    });
}
