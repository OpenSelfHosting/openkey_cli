#!/usr/bin/env node
import { Command } from "commander";
import { registerCommands } from "./commands/index.js";
import { printErr, setJsonMode } from "./lib/output.js";
import { packageVersion } from "./lib/version.js";

const program = new Command();

program
  .name("openkey")
  .description(
    "OpenKey CLI — developer secrets, password generation, and vault sync",
  )
  .version(packageVersion())
  .option("--json", "Machine-readable JSON output")
  .exitOverride()
  .showHelpAfterError(false);

registerCommands(program);

program.hook("preAction", (thisCommand) => {
  const opts = thisCommand.optsWithGlobals() as { json?: boolean };
  if (opts.json) setJsonMode(true);
});

async function main(): Promise<void> {
  try {
    await program.parseAsync(process.argv);
  } catch (err) {
    // Commander uses exitOverride codes; rethrow help/version exits quietly
    if (
      err &&
      typeof err === "object" &&
      "code" in err &&
      (err as { code?: string }).code?.startsWith("commander.")
    ) {
      const code = (err as { code: string }).code;
      if (code === "commander.helpDisplayed" || code === "commander.versionDisplayed") {
        return;
      }
    }
    const msg = err instanceof Error ? err.message : String(err);
    printErr(`Error: ${msg}`);
    process.exitCode = 1;
  }
}

void main();
