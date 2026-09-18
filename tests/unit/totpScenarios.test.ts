import { describe, expect, it, vi } from "vitest";
import type { AuthenticationOutcome } from "../../src/authenticationOutcome.js";
import {
  runTotpEnrollmentScenario,
  runTotpReusedCodeScenario,
  runTotpWrongEnrollmentScenario,
  runTotpWrongSignInScenario,
} from "../../src/totpScenarios.js";

const authenticated: AuthenticationOutcome = {
  kind: "authenticated",
  tokens: {
    accessToken: "access-secret",
    idToken: "id-secret",
    refreshToken: "refresh-secret",
  },
};

const softwareTokenChallenge: AuthenticationOutcome = {
  kind: "challenged",
  challenge: {
    type: "software-token-mfa",
    continuation: {
      session: "session-secret-value" as never,
      username: "canonical-user" as never,
      profileId: "user-pool-public" as never,
    },
  },
};

const fixedClock = {
  now: () => 1_700_000_010_000,
  sleep: async () => undefined,
};

describe("TOTP scenario evidence", () => {
  it("TP-1: enrolls, prefers MFA, challenges, then authenticates without leaking secrets", async () => {
    const authenticate = vi
      .fn()
      .mockResolvedValueOnce(authenticated)
      .mockResolvedValueOnce(softwareTokenChallenge);
    const associate = vi.fn().mockResolvedValue("JBSWY3DPEHPK3PXP");
    const verify = vi.fn().mockResolvedValue({ kind: "verified" });
    const prefer = vi.fn().mockResolvedValue(undefined);
    const respond = vi.fn().mockResolvedValue({
      kind: "authenticated",
      tokens: {
        accessToken: "mfa-access-secret",
        idToken: "mfa-id-secret",
        refreshToken: "mfa-refresh-secret",
      },
    });

    const evidence = await runTotpEnrollmentScenario({
      authenticate,
      associateSoftwareToken: associate,
      verifySoftwareToken: verify,
      setSoftwareTokenMfaPreferred: prefer,
      respondToSoftwareTokenMfa: respond,
      verifiers: {
        access: {
          verify: vi.fn().mockResolvedValue({ sub: "sub", username: "u" }),
        },
        id: { verify: vi.fn().mockResolvedValue({ sub: "sub" }) },
      },
      username: "user@example.com",
      password: "Password1!",
      clock: fixedClock,
    });

    expect(evidence).toEqual({
      enrollmentVerified: true,
      preferredMfaSet: true,
      challengeType: "software-token-mfa",
      mfaAuthenticated: true,
      accessVerified: true,
      idVerified: true,
    });
    const serialized = JSON.stringify(evidence);
    expect(serialized).not.toContain("JBSWY3DPEHPK3PXP");
    expect(serialized).not.toContain("access-secret");
    expect(serialized).not.toContain("session-secret-value");
    expect(serialized).not.toContain("Password1!");
    expect(prefer).toHaveBeenCalledWith("access-secret");
  });

  it("TP-2: wrong enrollment code is invalid-code without leaking code or token", async () => {
    const evidence = await runTotpWrongEnrollmentScenario({
      authenticate: async () => authenticated,
      associateSoftwareToken: async () => "JBSWY3DPEHPK3PXP",
      verifySoftwareToken: async (input) => {
        expect(input.code).not.toMatch(/^(\d)\1{5}$/);
        return {
          kind: "rejected",
          rejection: {
            reason: "invalid-code",
            diagnostic: {
              operation: "verify-software-token",
              providerCode: "CodeMismatchException",
            },
          },
        };
      },
      username: "user@example.com",
      password: "Password1!",
      clock: fixedClock,
    });

    expect(evidence).toEqual({
      outcomeKind: "rejected",
      rejectionReason: "invalid-code",
      providerCode: "CodeMismatchException",
    });
    expect(JSON.stringify(evidence)).not.toContain("JBSWY3DPEHPK3PXP");
    expect(JSON.stringify(evidence)).not.toContain("access-secret");
  });

  it("TP-3: wrong sign-in code rejects then recovers on a fresh session", async () => {
    const authenticate = vi
      .fn()
      .mockResolvedValueOnce(authenticated)
      .mockResolvedValueOnce(softwareTokenChallenge)
      .mockResolvedValueOnce({
        kind: "challenged",
        challenge: {
          type: "software-token-mfa",
          continuation: {
            session: "fresh-session-secret" as never,
            username: "canonical-user" as never,
            profileId: "user-pool-public" as never,
          },
        },
      });
    const respond = vi
      .fn()
      .mockResolvedValueOnce({
        kind: "rejected",
        rejection: {
          reason: "invalid-code",
          diagnostic: {
            operation: "respond-to-auth-challenge",
            providerCode: "CodeMismatchException",
          },
        },
      })
      .mockResolvedValueOnce({
        kind: "authenticated",
        tokens: {
          accessToken: "recovered-access",
          idToken: "recovered-id",
        },
      });

    const evidence = await runTotpWrongSignInScenario({
      authenticate,
      associateSoftwareToken: async () => "JBSWY3DPEHPK3PXP",
      verifySoftwareToken: async () => ({ kind: "verified" }),
      setSoftwareTokenMfaPreferred: async () => undefined,
      respondToSoftwareTokenMfa: respond,
      verifiers: {
        access: { verify: vi.fn().mockResolvedValue({ sub: "sub" }) },
        id: { verify: vi.fn().mockResolvedValue({ sub: "sub" }) },
      },
      username: "user@example.com",
      password: "Password1!",
      clock: fixedClock,
    });

    expect(evidence).toEqual({
      wrongCodeRejected: true,
      wrongCodeReason: "invalid-code",
      recovered: true,
      accessVerified: true,
      idVerified: true,
      providerCode: "CodeMismatchException",
    });
    expect(JSON.stringify(evidence)).not.toContain("fresh-session-secret");
    expect(JSON.stringify(evidence)).not.toContain("JBSWY3DPEHPK3PXP");
  });

  it("reused enrollment/sign-in code is rejected as expired-code", async () => {
    const authenticate = vi
      .fn()
      .mockResolvedValueOnce(authenticated)
      .mockResolvedValueOnce(softwareTokenChallenge)
      .mockResolvedValueOnce({
        kind: "challenged",
        challenge: {
          type: "software-token-mfa",
          continuation: {
            session: "reuse-session-secret" as never,
            username: "canonical-user" as never,
            profileId: "user-pool-public" as never,
          },
        },
      });
    const respond = vi
      .fn()
      .mockResolvedValueOnce(authenticated)
      .mockResolvedValueOnce({
        kind: "rejected",
        rejection: {
          reason: "expired-code",
          diagnostic: {
            operation: "respond-to-auth-challenge",
            providerCode: "ExpiredCodeException",
          },
        },
      });

    const evidence = await runTotpReusedCodeScenario({
      authenticate,
      associateSoftwareToken: async () => "JBSWY3DPEHPK3PXP",
      verifySoftwareToken: async () => ({ kind: "verified" }),
      setSoftwareTokenMfaPreferred: async () => undefined,
      respondToSoftwareTokenMfa: respond,
      username: "user@example.com",
      password: "Password1!",
      clock: fixedClock,
    });

    expect(evidence).toEqual({
      reuseRejected: true,
      rejectionReason: "expired-code",
      providerCode: "ExpiredCodeException",
    });
    expect(JSON.stringify(evidence)).not.toContain("reuse-session-secret");
    expect(respond.mock.calls[0]?.[0].code).toBe(
      respond.mock.calls[1]?.[0].code,
    );
  });
});
