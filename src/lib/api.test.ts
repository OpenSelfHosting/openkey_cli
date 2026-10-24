import { describe, expect, it } from "vitest";

import { apiPathCandidates } from "./api.js";

describe("apiPathCandidates", () => {
  it("prefers versioned API routes for modern OpenKey servers", () => {
    expect(apiPathCandidates("/auth/prelogin")).toEqual([
      "/api/v1/auth/prelogin",
      "/auth/prelogin",
    ]);
  });

  it("keeps already versioned routes stable", () => {
    expect(apiPathCandidates("/api/v1/auth/me")).toEqual(["/api/v1/auth/me"]);
  });
});
