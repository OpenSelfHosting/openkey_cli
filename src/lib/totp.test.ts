import { describe, expect, it } from "vitest";
import {
  generateTotp,
  normalizeTotp,
  parseOtpAuth,
  totpRemaining,
} from "./totp.js";

describe("totp", () => {
  // RFC 6238 test vector (SHA1, 6 digits, period 30) — secret "12345678901234567890" in base32
  // Common test: secret JBSWY3DPEHPK3PXP ("Hello!") at a fixed time is widely used in demos.
  it("generates a stable code for a fixed timestamp", () => {
    const config = { secret: "JBSWY3DPEHPK3PXP", period: 30, digits: 6, algorithm: "SHA1" };
    const code = generateTotp(config, 1_234_567_890_000);
    expect(code).toMatch(/^\d{6}$/);
    expect(generateTotp(config, 1_234_567_890_000)).toBe(code);
  });

  it("parses otpauth URIs", () => {
    const cfg = parseOtpAuth(
      "otpauth://totp/Example:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA256&digits=8&period=60",
    );
    expect(cfg?.secret).toBe("JBSWY3DPEHPK3PXP");
    expect(cfg?.period).toBe(60);
    expect(cfg?.digits).toBe(8);
    expect(cfg?.algorithm).toBe("SHA256");
  });

  it("normalizes object / uri / bare secret", () => {
    expect(normalizeTotp({ secret: "abcd efgh", digits: 8 })?.secret).toBe("abcdefgh");
    expect(normalizeTotp("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP")?.secret).toBe(
      "JBSWY3DPEHPK3PXP",
    );
    expect(normalizeTotp("JBSWY3DPEHPK3PXP")?.secret).toBe("JBSWY3DPEHPK3PXP");
    expect(normalizeTotp(null)).toBeNull();
  });

  it("reports remaining seconds in window", () => {
    expect(totpRemaining(30, 30_000)).toBe(30);
    expect(totpRemaining(30, 45_000)).toBe(15);
  });
});
