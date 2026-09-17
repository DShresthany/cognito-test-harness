import { describe, expect, it, vi } from "vitest";
import { CognitoAdminAuthDriver } from "../../src/cognitoAdminAuthDriver.js";

const profile = {
  id: "admin-confidential" as const,
  userPoolId: "pool-id",
  clientId: "client-id",
  clientSecret: "client-secret",
};

describe("CognitoAdminAuthDriver", () => {
  it("returns authenticated with access, ID, and refresh tokens for valid credentials", async () => {
    const send = vi.fn().mockResolvedValue({
      AuthenticationResult: {
        AccessToken: "access-token",
        IdToken: "id-token",
        RefreshToken: "refresh-token",
      },
    });
    const driver = new CognitoAdminAuthDriver({ send }, profile);

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
  });

  it("rejects a wrong password as invalid-credentials", async () => {
    const send = vi.fn().mockRejectedValue(
      Object.assign(new Error("Not authorized"), {
        name: "NotAuthorizedException",
      }),
    );
    const driver = new CognitoAdminAuthDriver({ send }, profile);

    await expect(
      driver.authenticatePassword("user@example.com", "WrongPassword1!"),
    ).resolves.toMatchObject({
      kind: "rejected",
      rejection: { reason: "invalid-credentials" },
    });
  });

  it("presents the injected confidential client proof on the protocol step", async () => {
    const send = vi.fn().mockResolvedValue({
      AuthenticationResult: {
        AccessToken: "access-token",
        IdToken: "id-token",
      },
    });
    const driver = new CognitoAdminAuthDriver(
      { send },
      {
        id: "admin-confidential",
        userPoolId: "pool-id",
        clientId: "1example23456789",
        clientSecret: "test-client-secret-value",
      },
    );

    await driver.authenticatePassword("alice@example.com", "Password1!");

    const command = send.mock.calls[0]?.[0] as {
      input?: { AuthParameters?: { SECRET_HASH?: string } };
    };
    expect(command.input?.AuthParameters?.SECRET_HASH).toBe(
      "t4HVCDtAiOpQ2KZ5rH6SH7Ap1y1WS66FZGCVvIq2cdg=",
    );
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
    const driver = new CognitoAdminAuthDriver({ send }, profile);

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
  });

  it("retries throttled admin initiate-auth until authentication succeeds", async () => {
    const send = vi
      .fn()
      .mockRejectedValueOnce(
        Object.assign(new Error("throttled"), {
          name: "TooManyRequestsException",
        }),
      )
      .mockResolvedValueOnce({
        AuthenticationResult: {
          AccessToken: "access-token",
          IdToken: "id-token",
          RefreshToken: "refresh-token",
        },
      });
    const driver = new CognitoAdminAuthDriver({ send }, profile, {
      sleep: async () => undefined,
    });

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
    expect(send).toHaveBeenCalledTimes(2);
  });

  it("throws when admin initiate-auth is throttled", async () => {
    const send = vi.fn().mockRejectedValue(
      Object.assign(new Error("throttled"), {
        name: "TooManyRequestsException",
      }),
    );
    const driver = new CognitoAdminAuthDriver({ send }, profile, {
      sleep: async () => undefined,
    });

    await expect(
      driver.authenticatePassword("user@example.com", "Password1!"),
    ).rejects.toMatchObject({
      name: "OperationalAuthenticationFailure",
      category: "throttled",
      retryable: true,
    });
    expect(send).toHaveBeenCalledTimes(3);
  });

  it("refreshes with REFRESH_TOKEN_AUTH and returns access and ID without a replacement refresh token", async () => {
    const send = vi.fn().mockResolvedValue({
      AuthenticationResult: {
        AccessToken: "new-access",
        IdToken: "new-id",
      },
    });
    const driver = new CognitoAdminAuthDriver({ send }, profile);

    await expect(
      driver.refresh("user@example.com", "refresh-token"),
    ).resolves.toEqual({
      kind: "authenticated",
      tokens: {
        accessToken: "new-access",
        idToken: "new-id",
      },
    });

    const command = send.mock.calls[0]?.[0] as {
      input?: {
        AuthFlow?: string;
        UserPoolId?: string;
        ClientId?: string;
        AuthParameters?: Record<string, string>;
      };
    };
    expect(command.input?.AuthFlow).toBe("REFRESH_TOKEN_AUTH");
    expect(command.input?.UserPoolId).toBe("pool-id");
    expect(command.input?.ClientId).toBe("client-id");
    expect(command.input?.AuthParameters?.REFRESH_TOKEN).toBe("refresh-token");
    expect(command.input?.AuthParameters?.USERNAME).toBe("user@example.com");
    expect(command.input?.AuthParameters?.SECRET_HASH).toBeDefined();
    expect(command.input?.AuthParameters?.PASSWORD).toBeUndefined();
  });

  it("rejects a malformed refresh token as invalid-refresh-token", async () => {
    const send = vi.fn().mockRejectedValue(
      Object.assign(new Error("Invalid Refresh Token"), {
        name: "NotAuthorizedException",
      }),
    );
    const driver = new CognitoAdminAuthDriver({ send }, profile);

    await expect(
      driver.refresh("user@example.com", "not-a-refresh-token"),
    ).resolves.toMatchObject({
      kind: "rejected",
      rejection: { reason: "invalid-refresh-token" },
    });
  });
});
