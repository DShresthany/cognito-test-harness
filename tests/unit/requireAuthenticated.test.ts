import { describe, expect, it } from "vitest";
import {
  requireAuthenticated,
  type AuthenticationOutcome,
} from "../../src/authenticationOutcome.js";

const authenticated: AuthenticationOutcome = {
  kind: "authenticated",
  tokens: {
    accessToken: "access-token",
    idToken: "id-token",
    refreshToken: "refresh-token",
  },
};

describe("requireAuthenticated", () => {
  it("returns the token set from an authenticated outcome", () => {
    expect(requireAuthenticated(authenticated)).toEqual({
      accessToken: "access-token",
      idToken: "id-token",
      refreshToken: "refresh-token",
    });
  });

  it("throws when the outcome is challenged or rejected", () => {
    const challenged: AuthenticationOutcome = {
      kind: "challenged",
      challenge: {
        type: "software-token-mfa",
        continuation: {
          session: "session" as never,
          username: "user@example.com" as never,
          profileId: "admin-confidential" as never,
        },
      },
    };
    const rejected: AuthenticationOutcome = {
      kind: "rejected",
      rejection: {
        reason: "invalid-credentials",
        diagnostic: { operation: "admin-initiate-auth" },
      },
    };

    expect(() => requireAuthenticated(challenged)).toThrow(
      /expected authenticated outcome, received challenged/,
    );
    expect(() => requireAuthenticated(rejected)).toThrow(
      /expected authenticated outcome, received rejected/,
    );
  });
});
