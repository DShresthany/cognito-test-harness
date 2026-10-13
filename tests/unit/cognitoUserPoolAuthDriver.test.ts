import { RefreshTokenReuseException } from "@aws-sdk/client-cognito-identity-provider";
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

  it("associates a software token and returns the Cognito secret without storing it", async () => {
    const send = vi.fn().mockResolvedValue({ SecretCode: "JBSWY3DPEHPK3PXP" });
    const driver = new CognitoUserPoolAuthDriver({ send }, profile);

    await expect(
      driver.associateSoftwareToken("access-token-value"),
    ).resolves.toBe("JBSWY3DPEHPK3PXP");

    const command = send.mock.calls[0]?.[0] as {
      input?: { AccessToken?: string };
    };
    expect(command.input?.AccessToken).toBe("access-token-value");
    expect(driver).not.toHaveProperty("secretCode");
    expect(driver).not.toHaveProperty("accessToken");
  });

  it("verifies a software token SUCCESS as verified without treating it as authenticated", async () => {
    const send = vi.fn().mockResolvedValue({ Status: "SUCCESS" });
    const driver = new CognitoUserPoolAuthDriver({ send }, profile);

    await expect(
      driver.verifySoftwareToken({
        accessToken: "access-token-value",
        code: "123456",
      }),
    ).resolves.toEqual({ kind: "verified" });

    const command = send.mock.calls[0]?.[0] as {
      input?: { AccessToken?: string; UserCode?: string };
    };
    expect(command.input?.AccessToken).toBe("access-token-value");
    expect(command.input?.UserCode).toBe("123456");
  });

  it("rejects a wrong enrollment code as invalid-code without leaking the code", async () => {
    const send = vi.fn().mockRejectedValue(
      Object.assign(new Error("Code mismatch"), {
        name: "CodeMismatchException",
      }),
    );
    const driver = new CognitoUserPoolAuthDriver({ send }, profile);

    const outcome = await driver.verifySoftwareToken({
      accessToken: "access-token-value",
      code: "000000",
    });
    expect(outcome).toMatchObject({
      kind: "rejected",
      rejection: { reason: "invalid-code" },
    });
    expect(JSON.stringify(outcome)).not.toContain("000000");
    expect(JSON.stringify(outcome)).not.toContain("access-token-value");
  });

  it("sets software-token MFA preferred via access token only", async () => {
    const send = vi.fn().mockResolvedValue({});
    const driver = new CognitoUserPoolAuthDriver({ send }, profile);

    await expect(
      driver.setSoftwareTokenMfaPreferred("access-token-value"),
    ).resolves.toBeUndefined();

    const command = send.mock.calls[0]?.[0] as {
      input?: {
        AccessToken?: string;
        SoftwareTokenMfaSettings?: { Enabled?: boolean; PreferredMfa?: boolean };
      };
    };
    expect(command.input?.AccessToken).toBe("access-token-value");
    expect(command.input?.SoftwareTokenMfaSettings).toEqual({
      Enabled: true,
      PreferredMfa: true,
    });
  });

  it("continues SOFTWARE_TOKEN_MFA and authenticates with a valid code", async () => {
    const send = vi.fn().mockResolvedValue({
      AuthenticationResult: {
        AccessToken: "access-token",
        IdToken: "id-token",
        RefreshToken: "refresh-token",
      },
    });
    const driver = new CognitoUserPoolAuthDriver({ send }, profile);

    await expect(
      driver.respondToSoftwareTokenMfa({
        session: "opaque-session",
        username: "canonical-user",
        code: "654321",
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
    expect(command.input?.ChallengeName).toBe("SOFTWARE_TOKEN_MFA");
    expect(command.input?.ClientId).toBe("public-client-id");
    expect(command.input?.Session).toBe("opaque-session");
    expect(command.input?.ChallengeResponses).toEqual({
      USERNAME: "canonical-user",
      SOFTWARE_TOKEN_MFA_CODE: "654321",
    });
  });

  it("rejects a wrong sign-in TOTP as invalid-code", async () => {
    const send = vi.fn().mockRejectedValue(
      Object.assign(new Error("Code mismatch"), {
        name: "CodeMismatchException",
      }),
    );
    const driver = new CognitoUserPoolAuthDriver({ send }, profile);

    await expect(
      driver.respondToSoftwareTokenMfa({
        session: "opaque-session",
        username: "canonical-user",
        code: "000000",
      }),
    ).resolves.toMatchObject({
      kind: "rejected",
      rejection: { reason: "invalid-code" },
    });
  });

  it("rotates a refresh token with GetTokensFromRefreshToken and returns the replacement", async () => {
    const send = vi.fn().mockResolvedValue({
      AuthenticationResult: {
        AccessToken: "rotated-access",
        IdToken: "rotated-id",
        RefreshToken: "replacement-refresh",
      },
    });
    const driver = new CognitoUserPoolAuthDriver(
      { send },
      {
        id: "refresh-rotating-public",
        userPoolId: "pool-id",
        clientId: "rotating-public-client-id",
      },
    );

    await expect(driver.rotateRefreshToken("consumed-refresh")).resolves.toEqual({
      kind: "authenticated",
      tokens: {
        accessToken: "rotated-access",
        idToken: "rotated-id",
        refreshToken: "replacement-refresh",
      },
    });

    const command = send.mock.calls[0]?.[0] as {
      input?: {
        ClientId?: string;
        RefreshToken?: string;
        ClientSecret?: string;
        AuthFlow?: string;
        AuthParameters?: Record<string, string>;
      };
    };
    expect(command.input).toEqual({
      ClientId: "rotating-public-client-id",
      RefreshToken: "consumed-refresh",
    });
    expect(command.input?.ClientSecret).toBeUndefined();
    expect(command.input?.AuthFlow).toBeUndefined();
    expect(command.input?.AuthParameters?.SECRET_HASH).toBeUndefined();
  });

  it("does not retry a reused refresh token", async () => {
    const send = vi.fn().mockRejectedValue(
      new RefreshTokenReuseException({
        message: "Refresh token has been used.",
        $metadata: { requestId: "req-reuse" },
      }),
    );
    const driver = new CognitoUserPoolAuthDriver({ send }, profile);

    await expect(driver.rotateRefreshToken("consumed-refresh")).resolves.toMatchObject({
      kind: "rejected",
      rejection: {
        reason: "invalid-refresh-token",
        diagnostic: { providerCode: "RefreshTokenReuseException" },
      },
    });
    expect(send).toHaveBeenCalledTimes(1);
  });

  it("revokes a refresh token for the public client without a client secret", async () => {
    const send = vi.fn().mockResolvedValue({});
    const driver = new CognitoUserPoolAuthDriver({ send }, profile);

    await expect(driver.revokeRefreshToken("refresh-token")).resolves.toEqual({
      kind: "revoked",
    });

    const command = send.mock.calls[0]?.[0] as {
      input?: { Token?: string; ClientId?: string; ClientSecret?: string };
    };
    expect(command.input).toEqual({
      Token: "refresh-token",
      ClientId: "public-client-id",
    });
    expect(command.input?.ClientSecret).toBeUndefined();
  });

  it("signs out globally with the access token", async () => {
    const send = vi.fn().mockResolvedValue({});
    const driver = new CognitoUserPoolAuthDriver({ send }, profile);

    await expect(driver.globalSignOut("access-token")).resolves.toEqual({
      kind: "signed-out",
    });

    const command = send.mock.calls[0]?.[0] as {
      input?: { AccessToken?: string };
    };
    expect(command.input).toEqual({ AccessToken: "access-token" });
  });

  it("rejects a reused sign-in TOTP as expired-code", async () => {
    const send = vi.fn().mockRejectedValue(
      Object.assign(new Error("Expired code"), {
        name: "ExpiredCodeException",
      }),
    );
    const driver = new CognitoUserPoolAuthDriver({ send }, profile);

    await expect(
      driver.respondToSoftwareTokenMfa({
        session: "opaque-session",
        username: "canonical-user",
        code: "123456",
      }),
    ).resolves.toMatchObject({
      kind: "rejected",
      rejection: { reason: "expired-code" },
    });
  });
});
