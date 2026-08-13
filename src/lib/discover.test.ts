import { describe, expect, it } from "vitest";
import { mkdtemp, writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  deviceName,
  discoverSecrets,
  filterNewSecrets,
} from "./discover.js";

describe("discover", () => {
  it("returns a device name", () => {
    expect(deviceName("MyLaptop")).toBe("MyLaptop");
    expect(deviceName().length).toBeGreaterThan(0);
  });

  it("finds .env files under a project root", async () => {
    const root = await mkdtemp(join(tmpdir(), "openkey-discover-"));
    await writeFile(
      join(root, ".env"),
      "DATABASE_URL=postgres://u:p@localhost/db\nAPI_KEY=secret123456\n",
    );
    await mkdir(join(root, "apps"));
    await writeFile(join(root, "apps", ".env.local"), "TOKEN=abcdefghi123\n");
    await writeFile(join(root, ".env.example"), "TOKEN=placeholder\n");

    const found = await discoverSecrets({
      device: "test-device",
      roots: [root],
      depth: 3,
      ssh: false,
      envVars: false,
      aws: false,
      gh: false,
      docker: false,
      envFiles: true,
    });

    expect(found.some((f) => f.name.includes(".env") && !f.name.includes("example"))).toBe(
      true,
    );
    expect(found.every((f) => f.device === "test-device")).toBe(true);
    expect(found.every((f) => f.kind === "envSnippet")).toBe(true);
    // .env.example should be skipped
    expect(found.some((f) => f.source.endsWith(".env.example"))).toBe(false);
  });

  it("filters duplicates by fingerprint", () => {
    const candidates = [
      {
        name: "A",
        kind: "apiToken" as const,
        secret: "same-value-here",
        device: "d1",
        source: "x",
        fingerprint: "will-be-ignored",
      },
    ];
    // Recompute via filter using same secret content
    const withFp = candidates.map((c) => ({
      ...c,
      fingerprint: "x", // filter uses existing secret hash, not this
    }));
    // Use real discover fingerprint by importing through filterNewSecrets
    // which hashes existing.secret
    const neu = filterNewSecrets(
      [
        {
          name: "A",
          kind: "apiToken",
          secret: "unique-token-value",
          device: "d1",
          source: "env:A",
          fingerprint: "abc",
        },
        {
          name: "B",
          kind: "apiToken",
          secret: "dup-token-value",
          device: "d1",
          source: "env:B",
          fingerprint: "def",
        },
      ],
      [{ name: "Old", secret: "dup-token-value", device: "d1" }],
    );
    expect(neu).toHaveLength(1);
    expect(neu[0]!.name).toBe("A");
    void withFp;
  });

  it("returns empty when roots are missing", async () => {
    const found = await discoverSecrets({
      device: "test-device",
      roots: ["/tmp/openkey-definitely-missing-" + Date.now()],
      depth: 2,
      ssh: false,
      envVars: false,
      aws: false,
      gh: false,
      docker: false,
      envFiles: true,
    });
    expect(found).toEqual([]);
  });

  it("skips node_modules and empty env values", async () => {
    const root = await mkdtemp(join(tmpdir(), "openkey-discover-skip-"));
    await mkdir(join(root, "node_modules", "pkg"), { recursive: true });
    await writeFile(
      join(root, "node_modules", "pkg", ".env"),
      "SHOULD_NOT=see_this_secret_value\n",
    );
    await writeFile(join(root, ".env"), "EMPTY=\nOK_TOKEN=presentvalue123\n");

    const found = await discoverSecrets({
      device: "d",
      roots: [root],
      depth: 4,
      ssh: false,
      envVars: false,
      aws: false,
      gh: false,
      docker: false,
      envFiles: true,
    });

    expect(found.some((f) => f.secret.includes("see_this"))).toBe(false);
    expect(found.some((f) => f.secret.includes("presentvalue123"))).toBe(true);
  });

  it("discovers GitHub CLI and Docker registry credentials", async () => {
    const home = await mkdtemp(join(tmpdir(), "openkey-home-"));
    const prevHome = process.env.HOME;
    const prevXdg = process.env.XDG_CONFIG_HOME;
    process.env.HOME = home;
    delete process.env.XDG_CONFIG_HOME;

    try {
      await mkdir(join(home, ".config", "gh"), { recursive: true });
      await writeFile(
        join(home, ".config", "gh", "hosts.yml"),
        `github.com:\n  oauth_token: ghp_testtoken_abcdef123456\n  user: asim\n`,
      );
      await mkdir(join(home, ".docker"), { recursive: true });
      const auth = Buffer.from("user:s3cretpass").toString("base64");
      await writeFile(
        join(home, ".docker", "config.json"),
        JSON.stringify({ auths: { "ghcr.io": { auth } } }),
      );

      const found = await discoverSecrets({
        device: "dev",
        ssh: false,
        envVars: false,
        aws: false,
        envFiles: false,
        gh: true,
        docker: true,
      });

      expect(found.some((f) => f.name.includes("GitHub CLI") && f.secret.includes("ghp_"))).toBe(
        true,
      );
      expect(
        found.some((f) => f.name.includes("Docker") && f.secret === "s3cretpass"),
      ).toBe(true);
    } finally {
      if (prevHome === undefined) delete process.env.HOME;
      else process.env.HOME = prevHome;
      if (prevXdg === undefined) delete process.env.XDG_CONFIG_HOME;
      else process.env.XDG_CONFIG_HOME = prevXdg;
    }
  });
});
