import { createInterface } from "node:readline";
import { stdin as input, stdout as output, stderr } from "node:process";

let jsonMode = false;

export function setJsonMode(enabled: boolean): void {
  jsonMode = enabled;
}

export function isJsonMode(): boolean {
  return jsonMode;
}

export function printJson(data: unknown): void {
  console.log(JSON.stringify(data, null, 2));
}

export function printLine(msg: string): void {
  if (!jsonMode) console.log(msg);
}

export function printErr(msg: string): void {
  stderr.write(`${msg}\n`);
}

export function printTable(headers: string[], rows: string[][]): void {
  if (jsonMode) return;
  const widths = headers.map((h, i) =>
    Math.max(h.length, ...rows.map((r) => (r[i] ?? "").length)),
  );
  const fmt = (cols: string[]) =>
    cols.map((c, i) => c.padEnd(widths[i]!)).join("  ");
  console.log(fmt(headers));
  console.log(widths.map((w) => "-".repeat(w)).join("  "));
  for (const row of rows) console.log(fmt(row));
}

/** Read a line from stdin (hidden when hide=true on TTY). */
export async function prompt(
  question: string,
  opts: { hide?: boolean } = {},
): Promise<string> {
  if (opts.hide && input.isTTY) {
    return promptHidden(question);
  }
  const rl = createInterface({ input, output });
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer);
    });
  });
}

function promptHidden(question: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const stdin = input as NodeJS.ReadStream & {
      isRaw?: boolean;
      setRawMode?: (mode: boolean) => void;
    };
    stderr.write(question);
    const wasRaw = stdin.isRaw;
    stdin.setRawMode?.(true);
    stdin.resume();
    stdin.setEncoding("utf8");
    let value = "";
    const onData = (chunk: string) => {
      for (const ch of chunk) {
        if (ch === "\n" || ch === "\r" || ch === "\u0004") {
          cleanup();
          stderr.write("\n");
          resolve(value);
          return;
        }
        if (ch === "\u0003") {
          cleanup();
          reject(new Error("Cancelled"));
          return;
        }
        if (ch === "\u007f" || ch === "\b") {
          value = value.slice(0, -1);
          continue;
        }
        value += ch;
      }
    };
    const cleanup = () => {
      stdin.off("data", onData);
      stdin.setRawMode?.(wasRaw ?? false);
      stdin.pause();
    };
    stdin.on("data", onData);
  });
}

export async function readMasterPassword(): Promise<string> {
  const fromEnv = process.env.OPENKEY_PASSWORD?.trim();
  if (fromEnv) return fromEnv;
  const pw = await prompt("Master password: ", { hide: true });
  if (!pw) throw new Error("Master password required");
  return pw;
}

export async function readEmail(fallback?: string): Promise<string> {
  const fromEnv = process.env.OPENKEY_EMAIL?.trim();
  if (fromEnv) return fromEnv.toLowerCase();
  if (fallback?.trim()) return fallback.trim().toLowerCase();
  const email = (await prompt("Email: ")).trim().toLowerCase();
  if (!email.includes("@")) throw new Error("Enter a valid email");
  return email;
}

/** Read all of stdin (for `secret add --stdin` / `--secret -`). */
export async function readStdin(): Promise<string> {
  if (input.isTTY) {
    throw new Error("No piped stdin — use --secret, --file, or pipe a value");
  }
  const chunks: Buffer[] = [];
  for await (const chunk of input) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks).toString("utf8");
}
