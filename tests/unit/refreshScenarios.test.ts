import { describe, expect, it, vi } from "vitest";
import type { AuthenticationOutcome } from "../../src/authenticationOutcome.js";
import {
  runRejectedRefreshScenario,
  runValidRefreshScenario,
} from "../../src/refreshScenarios.js";

describe("non-rotating refresh scenario evidence", () => {
  it("records verified refresh without replacement refresh or token values", async () => {
    const refreshOutcome: AuthenticationOutcome = {
      kind: "authenticated",
      tokens: {
        accessToken: "new-access-secret",
        idToken: "new-id-secret",
      },
    };
    const evidence = await runValidRefreshScenario({
      authenticate: async () => ({
        kind: "authenticated",
        tokens: {
          accessToken: "old-access-secret",
          idToken: "old-id-secret",
          refreshToken: "refresh-secret-value",
        },
      }),
      refresh: async (token) => {
        expect(token).toBe("refresh-secret-value");
        return refreshOutcome;
      },
      verifiers: {
        access: {
          verify: vi
            .fn()
            .mockResolvedValueOnce({
              sub: "subject-1",
              username: "u",
              jti: "access-jti-1",
            })
            .mockResolvedValueOnce({
              sub: "subject-1",
              username: "u",
              jti: "access-jti-2",
            }),
        },
        id: {
          verify: vi
            .fn()
            .mockResolvedValueOnce({ sub: "subject-1", jti: "id-jti-1" })
            .mockResolvedValueOnce({ sub: "subject-1", jti: "id-jti-2" }),
        },
      },
      username: "user@example.com",
      password: "Password1!",
    });

    expect(evidence).toEqual({
      outcomeKind: "authenticated",
      accessVerified: true,
      idVerified: true,
      subjectMatches: true,
      tokensRenewed: true,
      refreshTokenReplaced: false,
    });
    const serialized = JSON.stringify(evidence);
    expect(serialized).not.toContain("refresh-secret-value");
    expect(serialized).not.toContain("new-access-secret");
    expect(serialized).not.toContain("Password1!");
  });

  it("records invalid-refresh-token rejection without leaking the refresh token", async () => {
    const evidence = await runRejectedRefreshScenario({
      refresh: async () => ({
        kind: "rejected",
        rejection: {
          reason: "invalid-refresh-token",
          diagnostic: {
            operation: "refresh-token",
            providerCode: "NotAuthorizedException",
          },
        },
      }),
      refreshToken: "opaque-refresh-secret",
    });

    expect(evidence).toEqual({
      outcomeKind: "rejected",
      rejectionReason: "invalid-refresh-token",
      accessVerified: null,
      idVerified: null,
      subjectMatches: null,
      tokensRenewed: null,
      refreshTokenReplaced: null,
      providerCode: "NotAuthorizedException",
    });
    expect(JSON.stringify(evidence)).not.toContain("opaque-refresh-secret");
  });

  it("marks subject continuity false when refreshed ID subject differs", async () => {
    const evidence = await runValidRefreshScenario({
      authenticate: async () => ({
        kind: "authenticated",
        tokens: {
          accessToken: "old-access",
          idToken: "old-id",
          refreshToken: "refresh",
        },
      }),
      refresh: async () => ({
        kind: "authenticated",
        tokens: {
          accessToken: "new-access",
          idToken: "new-id",
        },
      }),
      verifiers: {
        access: {
          verify: vi
            .fn()
            .mockResolvedValueOnce({
              sub: "subject-1",
              username: "u",
              jti: "a1",
            })
            .mockResolvedValueOnce({
              sub: "subject-1",
              username: "u",
              jti: "a2",
            }),
        },
        id: {
          verify: vi
            .fn()
            .mockResolvedValueOnce({ sub: "subject-1", jti: "i1" })
            .mockResolvedValueOnce({ sub: "subject-2", jti: "i2" }),
        },
      },
      username: "user@example.com",
      password: "Password1!",
    });

    expect(evidence.subjectMatches).toBe(false);
    expect(evidence.accessVerified).toBe(true);
    expect(evidence.idVerified).toBe(true);
  });
});
