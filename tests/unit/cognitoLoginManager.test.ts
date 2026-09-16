import {
  AdminCreateUserCommand,
  AdminDeleteUserCommand,
  AdminInitiateAuthCommand,
  AdminSetUserPasswordCommand,
  CognitoIdentityProviderClient,
  UsernameExistsException,
} from "@aws-sdk/client-cognito-identity-provider";
import { describe, expect, it, vi } from "vitest";
import type { CognitoAuthResult } from "../../src/cognitoAuthResult.js";
import { CognitoLoginManager } from "../../src/cognitoLoginManager.js";

describe("CognitoLoginManager user ownership", () => {
  it("returns tokens without requiring persona metadata", async () => {
    const send = vi.fn().mockResolvedValue({
      AuthenticationResult: {
        AccessToken: "access-token",
        IdToken: "id-token",
        RefreshToken: "refresh-token",
      },
    });
    const client = { send } as unknown as CognitoIdentityProviderClient;
    const manager = new CognitoLoginManager(
      client,
      "pool-id",
      "client-id",
      "client-secret",
    );

    await expect(manager.login("user@example.com", "Password1!")).resolves.toEqual({
      accessToken: "access-token",
      idToken: "id-token",
      refreshToken: "refresh-token",
    });
  });

  it("uses a full UUID to isolate concurrent runs", () => {
    const client = { send: vi.fn() } as unknown as CognitoIdentityProviderClient;
    const manager = new CognitoLoginManager(
      client,
      "pool-id",
      "client-id",
      "client-secret",
    );

    expect(manager.runId).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    );
  });

  it("owns the provision-login-cleanup sequence and preserves diagnostics", async () => {
    const send = vi
      .fn()
      .mockResolvedValueOnce({ User: { Username: "created-user" } })
      .mockResolvedValueOnce({})
      .mockResolvedValueOnce({
        AuthenticationResult: {
          AccessToken: "access-token",
          IdToken: "id-token",
        },
      })
      .mockResolvedValueOnce({});
    const client = { send } as unknown as CognitoIdentityProviderClient;
    const manager = new CognitoLoginManager(
      client,
      "pool-id",
      "client-id",
      "client-secret",
    );

    const setupResults = await manager.setupUsers([
      { key: "smoke", emailPrefix: "harness-smoke" },
    ]);
    await manager.cleanup();

    expect(send.mock.calls[0]?.[0]).toBeInstanceOf(AdminCreateUserCommand);
    expect(send.mock.calls[1]?.[0]).toBeInstanceOf(AdminSetUserPasswordCommand);
    const loginCommand = send.mock.calls[2]?.[0];
    expect(loginCommand).toBeInstanceOf(AdminInitiateAuthCommand);
    expect(loginCommand.input.AuthParameters).toMatchObject({
      USERNAME: "created-user",
      SECRET_HASH: "//XDcy4Hg6hIX8lIOfi3PEWkB+US4X2IUsvbLFRHvzY=",
    });
    expect(send.mock.calls[3]?.[0]).toBeInstanceOf(AdminDeleteUserCommand);

    (setupResults as CognitoAuthResult[]).pop();
    expect(manager.getAuthResult("smoke").accessToken).toBe("access-token");
  });

  it("does not reset the password when the generated username already exists", async () => {
    const send = vi.fn().mockRejectedValue(
      new UsernameExistsException({
        $metadata: {},
        message: "User already exists",
      }),
    );
    const client = { send } as unknown as CognitoIdentityProviderClient;
    const manager = new CognitoLoginManager(
      client,
      "pool-id",
      "client-id",
      "client-secret",
    );

    await expect(
      manager.setupUsers([{ key: "smoke", emailPrefix: "harness-smoke" }]),
    ).rejects.toBeInstanceOf(UsernameExistsException);
    expect(send).toHaveBeenCalledTimes(1);
  });

  it("cleans up a created user when password assignment fails", async () => {
    const send = vi
      .fn()
      .mockResolvedValueOnce({ User: { Username: "created-user" } })
      .mockRejectedValueOnce(new Error("password assignment failed"))
      .mockResolvedValueOnce({});
    const client = { send } as unknown as CognitoIdentityProviderClient;
    const manager = new CognitoLoginManager(
      client,
      "pool-id",
      "client-id",
      "client-secret",
    );

    await expect(
      manager.setupUsers([{ key: "smoke", emailPrefix: "harness-smoke" }]),
    ).rejects.toThrow("password assignment failed");
    await manager.cleanup();

    expect(send).toHaveBeenCalledTimes(3);
    const cleanupCommand = send.mock.calls[2]?.[0];
    expect(cleanupCommand).toBeInstanceOf(AdminDeleteUserCommand);
    expect(cleanupCommand.input.Username).toBe("created-user");
  });
});
