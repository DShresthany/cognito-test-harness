import { describe, expect, it, vi } from "vitest";
import type { AuthenticationOutcome } from "../../src/authenticationOutcome.js";
import {
  runInvalidChallengeSessionScenario,
  runPolicyViolatingThenRecoverScenario,
  runTemporaryPasswordChallengeScenario,
  runTemporaryPasswordCompletionScenario,
} from "../../src/temporaryPasswordScenarios.js";

const challenged: AuthenticationOutcome = {
  kind: "challenged",
  challenge: {
    type: "new-password-required",
    requiredAttributes: ["email"],
    continuation: {
      session: "session-secret-value" as never,
      username: "canonical-user" as never,
      profileId: "user-pool-public" as never,
    },
  },
};

describe("temporary password scenario evidence", () => {
  it("NP-1: records new-password-required without embedding the session", async () => {
    const evidence = await runTemporaryPasswordChallengeScenario({
      authenticate: async () => challenged,
      username: "user@example.com",
      temporaryPassword: "TempPassword1!",
    });

    expect(evidence).toEqual({
      outcomeKind: "challenged",
      challengeType: "new-password-required",
      requiredAttributes: ["email"],
    });
    expect(JSON.stringify(evidence)).not.toContain("session-secret-value");
    expect(JSON.stringify(evidence)).not.toContain("TempPassword1!");
  });

  it("NP-2: completes challenge, verifies tokens, rejects temp password, accepts new", async () => {
    const authenticate = vi
      .fn()
      .mockResolvedValueOnce(challenged)
      .mockResolvedValueOnce({
        kind: "rejected",
        rejection: {
          reason: "invalid-credentials",
          diagnostic: { operation: "initiate-auth" },
        },
      })
      .mockResolvedValueOnce({
        kind: "authenticated",
        tokens: {
          accessToken: "final-access",
          idToken: "final-id",
          refreshToken: "final-refresh",
        },
      });

    const evidence = await runTemporaryPasswordCompletionScenario({
      authenticate,
      respondToNewPassword: async (input) => {
        expect(input.session).toBe("session-secret-value");
        expect(input.username).toBe("canonical-user");
        expect(input.newPassword).toBe("NewPassword1!");
        return {
          kind: "authenticated",
          tokens: {
            accessToken: "access-secret",
            idToken: "id-secret",
            refreshToken: "refresh-secret",
          },
        };
      },
      verifiers: {
        access: {
          verify: vi.fn().mockResolvedValue({ sub: "sub", username: "u" }),
        },
        id: { verify: vi.fn().mockResolvedValue({ sub: "sub" }) },
      },
      username: "user@example.com",
      temporaryPassword: "TempPassword1!",
      newPassword: "NewPassword1!",
    });

    expect(evidence).toEqual({
      outcomeKind: "authenticated",
      challengeType: "new-password-required",
      accessVerified: true,
      idVerified: true,
      temporaryPasswordRejected: true,
      newPasswordAuthenticates: true,
      refreshTokenIssued: true,
    });
    const serialized = JSON.stringify(evidence);
    expect(serialized).not.toContain("session-secret-value");
    expect(serialized).not.toContain("access-secret");
    expect(serialized).not.toContain("NewPassword1!");
  });

  it("NP-3: policy violation then recovers with a fresh session", async () => {
    const secondChallenge: AuthenticationOutcome = {
      kind: "challenged",
      challenge: {
        type: "new-password-required",
        requiredAttributes: [],
        continuation: {
          session: "fresh-session-secret" as never,
          username: "canonical-user" as never,
          profileId: "user-pool-public" as never,
        },
      },
    };
    const authenticate = vi
      .fn()
      .mockResolvedValueOnce(challenged)
      .mockResolvedValueOnce(secondChallenge);
    const respond = vi
      .fn()
      .mockResolvedValueOnce({
        kind: "rejected",
        rejection: {
          reason: "password-policy-violation",
          diagnostic: {
            operation: "respond-to-auth-challenge",
            providerCode: "InvalidPasswordException",
          },
        },
      })
      .mockResolvedValueOnce({
        kind: "authenticated",
        tokens: {
          accessToken: "access",
          idToken: "id",
          refreshToken: "refresh",
        },
      });

    const evidence = await runPolicyViolatingThenRecoverScenario({
      authenticate,
      respondToNewPassword: respond,
      verifiers: {
        access: {
          verify: vi.fn().mockResolvedValue({ sub: "sub", username: "u" }),
        },
        id: { verify: vi.fn().mockResolvedValue({ sub: "sub" }) },
      },
      username: "user@example.com",
      temporaryPassword: "TempPassword1!",
      violatingPassword: "short",
      recoveringPassword: "RecoverPassword1!",
    });

    expect(evidence).toMatchObject({
      policyViolationReason: "password-policy-violation",
      recovered: true,
      accessVerified: true,
      idVerified: true,
    });
    expect(respond.mock.calls[0]?.[0]?.session).toBe("session-secret-value");
    expect(respond.mock.calls[1]?.[0]?.session).toBe("fresh-session-secret");
    expect(JSON.stringify(evidence)).not.toContain("fresh-session-secret");
  });

  it("NP-4: invalid session is rejected without session in evidence", async () => {
    const evidence = await runInvalidChallengeSessionScenario({
      respondToNewPassword: async () => ({
        kind: "rejected",
        rejection: {
          reason: "invalid-challenge-session",
          diagnostic: {
            operation: "respond-to-auth-challenge",
            providerCode: "NotAuthorizedException",
          },
        },
      }),
      session: "stale-or-consumed-session",
      username: "canonical-user",
      newPassword: "NewPassword1!",
    });

    expect(evidence).toEqual({
      outcomeKind: "rejected",
      rejectionReason: "invalid-challenge-session",
      providerCode: "NotAuthorizedException",
    });
    expect(JSON.stringify(evidence)).not.toContain("stale-or-consumed-session");
  });
});
