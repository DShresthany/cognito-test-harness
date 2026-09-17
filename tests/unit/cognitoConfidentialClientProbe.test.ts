import { describe, expect, it, vi } from "vitest";
import {
  attemptRefreshWithInvalidSecretHash,
  attemptRefreshWithMissingSecretHash,
} from "../../src/cognitoConfidentialClientProbe.js";

const profile = {
  id: "admin-confidential" as const,
  userPoolId: "pool-id",
  clientId: "client-id",
  clientSecret: "client-secret",
};

describe("confidential refresh probes", () => {
  it("rejects refresh with an incorrect SECRET_HASH as invalid-refresh-token", async () => {
    const send = vi.fn().mockRejectedValue(
      Object.assign(new Error("Not authorized"), {
        name: "NotAuthorizedException",
      }),
    );

    const outcome = await attemptRefreshWithInvalidSecretHash(
      { send },
      profile,
      { subject: "subject-id", refreshToken: "refresh-secret" },
    );

    expect(outcome).toMatchObject({
      kind: "rejected",
      rejection: { reason: "invalid-refresh-token" },
    });
    expect(JSON.stringify(outcome)).not.toContain("refresh-secret");
    expect(JSON.stringify(outcome)).not.toContain("client-secret");
  });

  it("rejects refresh with a missing SECRET_HASH as invalid-refresh-token", async () => {
    const send = vi.fn().mockRejectedValue(
      Object.assign(new Error("Not authorized"), {
        name: "NotAuthorizedException",
      }),
    );

    const outcome = await attemptRefreshWithMissingSecretHash(
      { send },
      profile,
      { subject: "subject-id", refreshToken: "refresh-secret" },
    );

    expect(outcome).toMatchObject({
      kind: "rejected",
      rejection: { reason: "invalid-refresh-token" },
    });

    const command = send.mock.calls[0]?.[0] as {
      input?: {
        AuthFlow?: string;
        AuthParameters?: Record<string, string>;
      };
    };
    expect(command.input?.AuthFlow).toBe("REFRESH_TOKEN_AUTH");
    expect(command.input?.AuthParameters?.SECRET_HASH).toBeUndefined();
    expect(command.input?.AuthParameters?.USERNAME).toBeUndefined();
    expect(command.input?.AuthParameters?.REFRESH_TOKEN).toBe("refresh-secret");
  });
});
