import { describe, expect, it, vi } from "vitest";
import { FetchError } from "aws-jwt-verify/error";
import {
  OperationalAuthenticationFailure,
  type AuthenticationOutcome,
} from "../../src/authenticationOutcome.js";
import { wrapAccessTokenVerifier } from "../../src/jwtVerifier.js";
import {
  runRejectedPasswordScenario,
  runTokenVerificationScenario,
  runValidPermanentPasswordScenario,
  toPasswordScenarioEvidence,
  verifyQuietly,
} from "../../src/permanentPasswordScenarios.js";

describe("permanent password scenario evidence", () => {
  it("records authenticated success without embedding tokens or password", async () => {
    const outcome: AuthenticationOutcome = {
      kind: "authenticated",
      tokens: {
        accessToken: "access-secret-value",
        idToken: "id-secret-value",
        refreshToken: "refresh-secret-value",
      },
    };
    const evidence = await runValidPermanentPasswordScenario({
      authenticate: async () => outcome,
      verifiers: {
        access: {
          verify: vi.fn().mockResolvedValue({ sub: "sub", username: "u" }),
        },
        id: { verify: vi.fn().mockResolvedValue({ sub: "sub" }) },
      },
      username: "user@example.com",
      password: "Password1!",
    });

    expect(evidence).toEqual({
      outcomeKind: "authenticated",
      refreshTokenIssued: true,
      accessVerified: true,
      idVerified: true,
    });
    const serialized = JSON.stringify(evidence);
    expect(serialized).not.toContain("access-secret-value");
    expect(serialized).not.toContain("id-secret-value");
    expect(serialized).not.toContain("refresh-secret-value");
    expect(serialized).not.toContain("Password1!");
  });

  it("records invalid-credentials rejection without tokens", async () => {
    const evidence = await runRejectedPasswordScenario({
      authenticate: async () => ({
        kind: "rejected",
        rejection: {
          reason: "invalid-credentials",
          diagnostic: {
            operation: "initiate-auth",
            providerCode: "NotAuthorizedException",
          },
        },
      }),
      username: "missing@example.com",
      password: "Password1!",
    });

    expect(evidence).toEqual({
      outcomeKind: "rejected",
      rejectionReason: "invalid-credentials",
      refreshTokenIssued: false,
      accessVerified: null,
      idVerified: null,
      providerCode: "NotAuthorizedException",
    });
    expect(JSON.stringify(evidence)).not.toContain("Password1!");
  });

  it("builds rejection evidence without session fields", () => {
    const evidence = toPasswordScenarioEvidence({
      kind: "challenged",
      challenge: {
        type: "new-password-required",
        continuation: {
          session: "session-secret" as never,
          username: "user" as never,
          profileId: "user-pool-public" as never,
        },
        requiredAttributes: [],
      },
    });

    expect(evidence.outcomeKind).toBe("challenged");
    expect(JSON.stringify(evidence)).not.toContain("session-secret");
  });

  it("reports token verification matrix without returning raw tokens", async () => {
    const otherAccess = vi.fn(async () => {
      throw new Error("wrong client");
    });
    const otherId = vi.fn(async () => {
      throw new Error("wrong client");
    });

    const evidence = await runTokenVerificationScenario({
      tokens: {
        accessToken: "access.payload.sig",
        idToken: "id.payload.sig",
        refreshToken: "refresh-opaque",
      },
      issuing: {
        access: {
          verify: vi.fn(async (token: string) => {
            if (token === "access.payload.sig") {
              return { sub: "sub", username: "u" };
            }
            throw new Error("bad access");
          }),
        },
        id: {
          verify: vi.fn(async (token: string) => {
            if (token === "id.payload.sig") {
              return { sub: "sub" };
            }
            throw new Error("bad id");
          }),
        },
      },
      otherProfile: {
        access: { verify: otherAccess },
        id: { verify: otherId },
      },
    });

    expect(evidence).toEqual({
      accessVerifiesOnAccess: true,
      idVerifiesOnId: true,
      accessRejectedAsId: true,
      idRejectedAsAccess: true,
      tamperedAccessRejected: true,
      tamperedIdRejected: true,
      crossProfileAccessRejected: true,
      crossProfileIdRejected: true,
    });
    expect(otherAccess).toHaveBeenCalledWith("access.payload.sig");
    expect(otherId).toHaveBeenCalledWith("id.payload.sig");
    expect(JSON.stringify(evidence)).not.toContain("access.payload.sig");
    expect(JSON.stringify(evidence)).not.toContain("refresh-opaque");
  });

  it("does not treat wrapped JWKS FetchError as token rejection", async () => {
    const wrapped = wrapAccessTokenVerifier({
      async verify() {
        throw new FetchError("https://example.invalid/jwks", "network down");
      },
    });

    await expect(verifyQuietly(wrapped.verify("access-token"))).rejects.toBeInstanceOf(
      OperationalAuthenticationFailure,
    );
    await expect(verifyQuietly(wrapped.verify("access-token"))).rejects.toMatchObject({
      category: "network",
      operation: "verify-access-token",
      retryable: true,
    });
  });

  it("propagates operational JWKS failure from valid password scenario", async () => {
    await expect(
      runValidPermanentPasswordScenario({
        authenticate: async () => ({
          kind: "authenticated",
          tokens: {
            accessToken: "access-token",
            idToken: "id-token",
            refreshToken: "refresh-token",
          },
        }),
        verifiers: {
          access: wrapAccessTokenVerifier({
            async verify() {
              throw new FetchError(
                "https://example.invalid/jwks",
                "network down",
              );
            },
          }),
          id: { verify: vi.fn().mockResolvedValue({ sub: "sub" }) },
        },
        username: "user@example.com",
        password: "Password1!",
      }),
    ).rejects.toBeInstanceOf(OperationalAuthenticationFailure);
  });
});
