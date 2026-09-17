import { describe, expect, it, vi } from "vitest";
import { CognitoUserPoolAuthDriver } from "../../src/cognitoUserPoolAuthDriver.js";

const profile = {
  id: "user-pool-public" as const,
  userPoolId: "pool-id",
  clientId: "public-client-id",
};

describe("CognitoUserPoolAuthDriver", () => {
  it("returns authenticated with access, ID, and refresh tokens for valid credentials", async () => {
    const send = vi.fn().mockResolvedValue({
      AuthenticationResult: {
        AccessToken: "access-token",
        IdToken: "id-token",
        RefreshToken: "refresh-token",
      },
    });
    const driver = new CognitoUserPoolAuthDriver({ send }, profile);

    await expect(
      driver.authenticatePassword("user@example.com", "Password1!"),
    ).resolves.toEqual({
      kind: "authenticated",
      tokens: {
        accessToken: "access-token",
        idToken: "id-token",
        refreshToken: "refresh-token",
      },
    });

    const command = send.mock.calls[0]?.[0] as {
      input?: {
        AuthFlow?: string;
        ClientId?: string;
        AuthParameters?: Record<string, string>;
      };
    };
    expect(command.input?.AuthFlow).toBe("USER_PASSWORD_AUTH");
    expect(command.input?.ClientId).toBe("public-client-id");
    expect(command.input?.AuthParameters).toEqual({
      USERNAME: "user@example.com",
      PASSWORD: "Password1!",
    });
    expect(command.input?.AuthParameters?.SECRET_HASH).toBeUndefined();
  });

  it("rejects a wrong password as invalid-credentials", async () => {
    const send = vi.fn().mockRejectedValue(
      Object.assign(new Error("Not authorized"), {
        name: "NotAuthorizedException",
      }),
    );
    const driver = new CognitoUserPoolAuthDriver({ send }, profile);

    await expect(
      driver.authenticatePassword("user@example.com", "WrongPassword1!"),
    ).resolves.toMatchObject({
      kind: "rejected",
      rejection: { reason: "invalid-credentials" },
    });
  });

  it("rejects a nonexistent username as invalid-credentials", async () => {
    const send = vi.fn().mockRejectedValue(
      Object.assign(new Error("Not authorized"), {
        name: "NotAuthorizedException",
      }),
    );
    const driver = new CognitoUserPoolAuthDriver({ send }, profile);

    await expect(
      driver.authenticatePassword("missing@example.com", "Password1!"),
    ).resolves.toMatchObject({
      kind: "rejected",
      rejection: { reason: "invalid-credentials" },
    });
  });

  it("treats each password authentication as an independent protocol step", async () => {
    const send = vi
      .fn()
      .mockResolvedValueOnce({
        AuthenticationResult: {
          AccessToken: "access-token",
          IdToken: "id-token",
          RefreshToken: "refresh-token",
        },
      })
      .mockRejectedValueOnce(
        Object.assign(new Error("Not authorized"), {
          name: "NotAuthorizedException",
        }),
      );
    const driver = new CognitoUserPoolAuthDriver({ send }, profile);

    const first = await driver.authenticatePassword(
      "user@example.com",
      "Password1!",
    );
    const second = await driver.authenticatePassword(
      "user@example.com",
      "WrongPassword1!",
    );

    expect(first.kind).toBe("authenticated");
    expect(second).toMatchObject({
      kind: "rejected",
      rejection: { reason: "invalid-credentials" },
    });
    expect(send).toHaveBeenCalledTimes(2);
  });

  it("refreshes with REFRESH_TOKEN_AUTH and returns access and ID without a replacement refresh token", async () => {
    const send = vi.fn().mockResolvedValue({
      AuthenticationResult: {
        AccessToken: "new-access",
        IdToken: "new-id",
      },
    });
    const driver = new CognitoUserPoolAuthDriver({ send }, profile);

    await expect(driver.refresh("refresh-token")).resolves.toEqual({
      kind: "authenticated",
      tokens: {
        accessToken: "new-access",
        idToken: "new-id",
      },
    });

    const command = send.mock.calls[0]?.[0] as {
      input?: {
        AuthFlow?: string;
        ClientId?: string;
        AuthParameters?: Record<string, string>;
      };
    };
    expect(command.input?.AuthFlow).toBe("REFRESH_TOKEN_AUTH");
    expect(command.input?.ClientId).toBe("public-client-id");
    expect(command.input?.AuthParameters).toEqual({
      REFRESH_TOKEN: "refresh-token",
    });
  });

  it("rejects a malformed refresh token as invalid-refresh-token", async () => {
    const send = vi.fn().mockRejectedValue(
      Object.assign(new Error("Invalid Refresh Token"), {
        name: "NotAuthorizedException",
      }),
    );
    const driver = new CognitoUserPoolAuthDriver({ send }, profile);

    await expect(driver.refresh("not-a-refresh-token")).resolves.toMatchObject({
      kind: "rejected",
      rejection: { reason: "invalid-refresh-token" },
    });
  });

  it("continues NEW_PASSWORD_REQUIRED via public RespondToAuthChallenge without storing session", async () => {
    const send = vi.fn().mockResolvedValue({
      AuthenticationResult: {
        AccessToken: "access-token",
        IdToken: "id-token",
        RefreshToken: "refresh-token",
      },
    });
    const driver = new CognitoUserPoolAuthDriver({ send }, profile);

    await expect(
      driver.respondToNewPasswordChallenge({
        session: "opaque-session",
        username: "canonical-user",
        newPassword: "NewPassword1!",
      }),
    ).resolves.toEqual({
      kind: "authenticated",
      tokens: {
        accessToken: "access-token",
        idToken: "id-token",
        refreshToken: "refresh-token",
      },
    });

    const command = send.mock.calls[0]?.[0] as {
      input?: {
        ChallengeName?: string;
        ClientId?: string;
        Session?: string;
        ChallengeResponses?: Record<string, string>;
      };
    };
    expect(command.input?.ChallengeName).toBe("NEW_PASSWORD_REQUIRED");
    expect(command.input?.ClientId).toBe("public-client-id");
    expect(command.input?.Session).toBe("opaque-session");
    expect(command.input?.ChallengeResponses).toEqual({
      USERNAME: "canonical-user",
      NEW_PASSWORD: "NewPassword1!",
    });
    expect(driver).not.toHaveProperty("session");
  });

  it("rejects a policy-violating new password as password-policy-violation", async () => {
    const send = vi.fn().mockRejectedValue(
      Object.assign(new Error("Password does not conform"), {
        name: "InvalidPasswordException",
      }),
    );
    const driver = new CognitoUserPoolAuthDriver({ send }, profile);

    await expect(
      driver.respondToNewPasswordChallenge({
        session: "opaque-session",
        username: "canonical-user",
        newPassword: "short",
      }),
    ).resolves.toMatchObject({
      kind: "rejected",
      rejection: { reason: "password-policy-violation" },
    });
  });

  it("rejects an invalid challenge session as invalid-challenge-session", async () => {
    const send = vi.fn().mockRejectedValue(
      Object.assign(new Error("Invalid session for the user."), {
        name: "NotAuthorizedException",
      }),
    );
    const driver = new CognitoUserPoolAuthDriver({ send }, profile);

    await expect(
      driver.respondToNewPasswordChallenge({
        session: "stale-session",
        username: "canonical-user",
        newPassword: "NewPassword1!",
      }),
    ).resolves.toMatchObject({
      kind: "rejected",
      rejection: { reason: "invalid-challenge-session" },
    });
  });
});
