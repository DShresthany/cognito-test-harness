import { describe, expect, it, vi } from "vitest";
import {
  finalizeScenario,
  ScenarioCleanupFailure,
  type ScenarioTokenHandles,
} from "../../src/scenarioFinalizer.js";

describe("scenario finalizer", () => {
  it("continues after a revoke failure, clears handles, and reports safe diagnostics", async () => {
    const handles: ScenarioTokenHandles = {
      refreshTokens: ["refresh-secret-a", "refresh-secret-b"],
      accessToken: "access-secret",
    };
    const attempts: string[] = [];
    const failure = await finalizeScenario(handles, {
      revokeRefreshToken: async (refreshToken) => {
        attempts.push(`revoke:${refreshToken}`);
        if (refreshToken === "refresh-secret-a") {
          throw new Error("revoke failed for refresh-secret-a");
        }
      },
      globalSignOut: async (accessToken) => {
        attempts.push(`sign-out:${accessToken}`);
      },
      deletePersona: async () => {
        attempts.push("delete");
        throw new Error("delete failed for access-secret");
      },
    }).catch((error: unknown) => error);

    expect(attempts).toEqual([
      "revoke:refresh-secret-a",
      "revoke:refresh-secret-b",
      "sign-out:access-secret",
      "delete",
    ]);
    expect(handles).toEqual({ refreshTokens: [] });
    expect(failure).toBeInstanceOf(ScenarioCleanupFailure);
    const cleanup = failure as ScenarioCleanupFailure;
    expect(cleanup.diagnostic).toEqual({
      revokeAttempted: 2,
      revokeFailed: 1,
      globalSignOutAttempted: true,
      globalSignOutFailed: false,
      personaDeleteFailed: true,
    });
    expect(JSON.stringify(cleanup.diagnostic)).not.toContain("refresh-secret-a");
    expect(cleanup.message).not.toContain("access-secret");
  });

  it("skips global sign-out when no access token remains", async () => {
    const handles: ScenarioTokenHandles = { refreshTokens: [] };
    const globalSignOut = vi.fn(async () => undefined);
    const deletePersona = vi.fn(async () => undefined);

    await finalizeScenario(handles, {
      revokeRefreshToken: async () => undefined,
      globalSignOut,
      deletePersona,
    });

    expect(globalSignOut).not.toHaveBeenCalled();
    expect(deletePersona).toHaveBeenCalledTimes(1);
  });
});
