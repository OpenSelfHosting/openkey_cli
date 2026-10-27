import { afterEach, describe, expect, it } from "vitest";

import { readEmail, readMasterPassword } from "./output.js";

const previousEmail = process.env.OPENKEY_EMAIL;
const previousPassword = process.env.OPENKEY_PASSWORD;

afterEach(() => {
  if (previousEmail === undefined) delete process.env.OPENKEY_EMAIL;
  else process.env.OPENKEY_EMAIL = previousEmail;
  if (previousPassword === undefined) delete process.env.OPENKEY_PASSWORD;
  else process.env.OPENKEY_PASSWORD = previousPassword;
});

describe("auth prompts", () => {
  it("prefers an explicitly supplied email over OPENKEY_EMAIL", async () => {
    process.env.OPENKEY_EMAIL = "other@example.com";

    await expect(
      readEmail(" Test@Example.com ", "config@example.com"),
    ).resolves.toBe("test@example.com");
  });

  it("uses OPENKEY_EMAIL before the configured fallback", async () => {
    process.env.OPENKEY_EMAIL = " ENV@Example.com ";

    await expect(readEmail(undefined, "config@example.com")).resolves.toBe(
      "env@example.com",
    );
  });

  it("preserves leading and trailing spaces in OPENKEY_PASSWORD", async () => {
    process.env.OPENKEY_PASSWORD = " password with spaces ";

    await expect(readMasterPassword()).resolves.toBe(" password with spaces ");
  });
});
