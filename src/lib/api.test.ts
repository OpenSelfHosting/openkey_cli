import { afterEach, describe, expect, it, vi } from "vitest";

import { apiPathCandidates, prelogin } from "./api.js";
import { DEFAULT_CONFIG } from "./types.js";

describe("apiPathCandidates", () => {
  it("prefers the server's canonical unversioned routes", () => {
    expect(apiPathCandidates("/auth/prelogin")).toEqual([
      "/auth/prelogin",
      "/api/v1/auth/prelogin",
    ]);
  });

  it("keeps already versioned routes stable", () => {
    expect(apiPathCandidates("/api/v1/auth/me")).toEqual(["/api/v1/auth/me"]);
  });
});

describe("server network errors", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("includes the endpoint and underlying cause when fetch fails", async () => {
    const cause = Object.assign(new Error("connect ECONNREFUSED"), {
      code: "ECONNREFUSED",
    });
    vi.stubGlobal(
      "fetch",
      vi.fn().mockRejectedValue(
        Object.assign(new TypeError("fetch failed"), { cause }),
      ),
    );

    await expect(
      prelogin(
        { ...DEFAULT_CONFIG, serverUrl: "https://server.example" },
        "user@example.com",
      ),
    ).rejects.toThrow(
      "Could not reach OpenKey server at https://server.example/api/v1/auth/prelogin: connect ECONNREFUSED (ECONNREFUSED)",
    );
  });
});
