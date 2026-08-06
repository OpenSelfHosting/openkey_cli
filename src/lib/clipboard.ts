import { spawn } from "node:child_process";
import { platform } from "node:os";

export type CopyOptions = {
  /** Clear the clipboard after this many ms (detached; default off). */
  clearAfterMs?: number;
};

/** Copy text to the system clipboard. */
export async function copyToClipboard(
  text: string,
  opts: CopyOptions = {},
): Promise<void> {
  const os = platform();
  if (os === "darwin") {
    await pipeTo("pbcopy", [], text);
  } else if (os === "win32") {
    await pipeTo("clip", [], text);
  } else {
    let copied = false;
    for (const [cmd, args] of [
      ["wl-copy", [] as string[]],
      ["xclip", ["-selection", "clipboard"]],
      ["xsel", ["--clipboard", "--input"]],
    ] as const) {
      try {
        await pipeTo(cmd, [...args], text);
        copied = true;
        break;
      } catch {
        /* try next */
      }
    }
    if (!copied) {
      throw new Error(
        "No clipboard tool found (install wl-copy, xclip, or xsel)",
      );
    }
  }

  const ms = opts.clearAfterMs;
  if (ms && ms > 0) {
    scheduleClipboardClear(ms);
  }
}

/** Best-effort clipboard wipe after `ms` without blocking the CLI. */
function scheduleClipboardClear(ms: number): void {
  const seconds = Math.max(1, Math.round(ms / 1000));
  const os = platform();
  let command: string;
  if (os === "darwin") {
    command = `sleep ${seconds}; printf '' | pbcopy`;
  } else if (os === "win32") {
    command = `timeout /t ${seconds} /nobreak >nul & echo.| clip`;
  } else {
    command = `sleep ${seconds}; (wl-copy --clear 2>/dev/null || printf '' | xclip -selection clipboard || printf '' | xsel --clipboard --input || true)`;
  }
  try {
    const child = spawn(command, {
      shell: true,
      detached: true,
      stdio: "ignore",
    });
    child.unref();
  } catch {
    /* ignore scheduler failures */
  }
}

function pipeTo(cmd: string, args: string[], text: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { stdio: ["pipe", "ignore", "pipe"] });
    let err = "";
    child.stderr?.on("data", (d: Buffer) => {
      err += d.toString();
    });
    child.on("error", reject);
    child.on("close", (code) => {
      if (code === 0) resolve();
      else reject(new Error(err.trim() || `${cmd} exited ${code}`));
    });
    child.stdin.write(text);
    child.stdin.end();
  });
}
