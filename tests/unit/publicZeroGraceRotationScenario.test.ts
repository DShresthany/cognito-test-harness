import {
  AccessDeniedException,
  NotAuthorizedException,
  RefreshTokenReuseException,
} from "@aws-sdk/client-cognito-identity-provider";
import { describe, expect, it, vi } from "vitest";
import { ScenarioCleanupFailure } from "../../src/scenarioFinalizer.js";
import { createLineageFingerprinter } from "../../src/lineageFingerprint.js";
import { runPublicZeroGraceRotationScenario } from "../../src/publicZeroGraceRotationScenario.js";

const profile = {
  id: "refresh-rotating-public" as const,
  userPoolId: "pool-id",
  clientId: "rotating-public-client-id",
};

const salt = Buffer.from("lineage-salt-secret");

function cognitoException(
  name: string,
  message: string,
): Error {
  return Object.assign(new Error(message), { name });
}

describe("public zero-grace rotation scenario", () => {
  it("proves lineage through fingerprints and rejects reuse of the consumed refresh token", async () => {
    const rotationCalls: string[] = [];
    const revoked: string[] = [];
    let signedOut: string | undefined;
    const deletePersona = vi.fn(async () => undefined);
    const send = vi.fn(async (command: { input?: Record<string, unknown> }) => {
      const input = command.input ?? {};
      if (input.AuthFlow === "USER_PASSWORD_AUTH") {
        return {
          AuthenticationResult: {
            AccessToken: "initial-access-secret",
            IdToken: "initial-id-secret",
            RefreshToken: "initial-refresh-secret",
          },
        };
      }
      if (typeof input.RefreshToken === "string") {
        expect(input.ClientId).toBe(profile.clientId);
        expect(input.ClientSecret).toBeUndefined();
        rotationCalls.push(input.RefreshToken);
        if (rotationCalls.length === 1) {
          return {
            AuthenticationResult: {
              AccessToken: "rotated-access-secret",
              IdToken: "rotated-id-secret",
              RefreshToken: "replacement-refresh-secret",
            },
          };
        }
        throw new RefreshTokenReuseException({
          message: "Refresh token has been used.",
          $metadata: {},
        });
      }
      if (typeof input.Token === "string") {
        revoked.push(input.Token);
        if (input.Token === "initial-refresh-secret") {
          throw new NotAuthorizedException({
            message: "Invalid Refresh Token",
            $metadata: {},
          });
        }
        return {};
      }
      if (typeof input.AccessToken === "string") {
        signedOut = input.AccessToken;
        return {};
      }
      throw new Error("unexpected command");
    });

    const evidence = await runPublicZeroGraceRotationScenario({
      sender: { send },
      profile,
      verifiers: verifiers({
        initialAccess: {
          sub: "subject-1",
          username: "user",
          jti: "access-jti-initial",
          origin_jti: "origin-jti-value",
        },
        rotatedAccess: {
          sub: "subject-1",
          username: "user",
          jti: "access-jti-rotated",
          origin_jti: "origin-jti-value",
        },
        initialId: {
          sub: "subject-1",
          jti: "id-jti-initial",
          origin_jti: "origin-jti-value",
        },
        rotatedId: {
          sub: "subject-1",
          jti: "id-jti-rotated",
          origin_jti: "origin-jti-value",
        },
      }),
      username: "user@example.com",
      password: "Password1!",
      fingerprinter: createLineageFingerprinter(salt),
      deletePersona,
    });

    expect(rotationCalls).toEqual([
      "initial-refresh-secret",
      "initial-refresh-secret",
    ]);
    expect(revoked).toEqual([
      "initial-refresh-secret",
      "replacement-refresh-secret",
    ]);
    expect(signedOut).toBe("rotated-access-secret");
    expect(deletePersona).toHaveBeenCalledTimes(1);
    expect(evidence).toMatchObject({
      initialOutcomeKind: "authenticated",
      initialRefreshPresent: true,
      rotationOutcomeKind: "authenticated",
      replacementRefreshPresent: true,
      reuseOutcomeKind: "rejected",
      reuseRejectionReason: "invalid-refresh-token",
      reuseProviderCode: "RefreshTokenReuseException",
      accessVerified: true,
      idVerified: true,
      subjectMatches: true,
      originJtiFingerprintStable: true,
      jtiFingerprintsUnique: true,
    });
    expect(evidence.generations.map((generation) => generation.label)).toEqual([
      "initial",
      "rotated",
    ]);
    const origins = evidence.generations.flatMap((generation) => [
      generation.accessOriginJtiFingerprint,
      generation.idOriginJtiFingerprint,
    ]);
    expect(new Set(origins).size).toBe(1);
    expect(origins[0]).toEqual(expect.any(String));
    const jtis = evidence.generations.flatMap((generation) => [
      generation.accessJtiFingerprint,
      generation.idJtiFingerprint,
    ]);
    expect(new Set(jtis).size).toBe(4);
    expect(safeText(evidence)).not.toContain("origin-jti-value");
    expect(safeText(evidence)).not.toContain("access-jti-initial");
    expect(safeText(evidence)).not.toContain("lineage-salt-secret");
    expect(safeText(evidence)).not.toContain("initial-refresh-secret");
    expect(safeText(evidence)).not.toContain("replacement-refresh-secret");
    expect(safeText(evidence)).not.toContain("rotated-access-secret");
    expect(safeText(evidence)).not.toContain("Password1!");
  });

  it("fails cleanup when the current refresh token is rejected instead of revoked", async () => {
    const send = successfulSender({
      revoke(token) {
        throw new NotAuthorizedException({
          message: `Invalid Refresh Token ${token}`,
          $metadata: {},
        });
      },
    });

    const failure = await runPublicZeroGraceRotationScenario({
      sender: { send },
      profile,
      verifiers: verifiers(),
      username: "user@example.com",
      password: "Password1!",
      fingerprinter: createLineageFingerprinter(salt),
      deletePersona: async () => undefined,
    }).catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(ScenarioCleanupFailure);
    const cleanup = failure as ScenarioCleanupFailure;
    expect(cleanup.diagnostic.revokeFailed).toBe(1);
    expect(cleanup.diagnostic.revokeAttempted).toBe(2);
    expect(cleanup.message).not.toContain("replacement-refresh-secret");
  });

  it("records invalid-refresh-token when sign-in is rejected and still deletes the persona", async () => {
    const deletePersona = vi.fn(async () => undefined);
    const send = vi.fn(async () => {
      throw cognitoException("NotAuthorizedException", "Incorrect username or password.");
    });

    const evidence = await runPublicZeroGraceRotationScenario({
      sender: { send },
      profile,
      verifiers: verifiers(),
      username: "user@example.com",
      password: "Password1!",
      fingerprinter: createLineageFingerprinter(salt),
      deletePersona,
    });

    expect(evidence).toMatchObject({
      initialOutcomeKind: "rejected",
      initialRejectionReason: "invalid-credentials",
      rotationOutcomeKind: null,
      reuseOutcomeKind: null,
      originJtiFingerprintStable: null,
      generations: [],
    });
    expect(deletePersona).toHaveBeenCalledTimes(1);
    expect(safeText(evidence)).not.toContain("Password1!");
  });

  it("treats a missing origin_jti as failed lineage evidence", async () => {
    const send = successfulSender();
    const evidence = await runPublicZeroGraceRotationScenario({
      sender: { send },
      profile,
      verifiers: verifiers({
        initialAccess: {
          sub: "subject-1",
          username: "user",
          jti: "access-jti-initial",
        },
        rotatedAccess: {
          sub: "subject-1",
          username: "user",
          jti: "access-jti-rotated",
        },
        initialId: { sub: "subject-1", jti: "id-jti-initial" },
        rotatedId: { sub: "subject-1", jti: "id-jti-rotated" },
      }),
      username: "user@example.com",
      password: "Password1!",
      fingerprinter: createLineageFingerprinter(salt),
      deletePersona: async () => undefined,
    });

    expect(evidence.originJtiFingerprintStable).toBe(false);
    expect(evidence.jtiFingerprintsUnique).toBe(true);
    expect(evidence.subjectMatches).toBe(true);
    expect(evidence.accessVerified).toBe(true);
    expect(
      evidence.generations.every(
        (generation) =>
          generation.accessOriginJtiFingerprint === null &&
          generation.idOriginJtiFingerprint === null,
      ),
    ).toBe(true);
  });

  it("keeps the suite red when cleanup fails after tokens were issued", async () => {
    let revokeCount = 0;
    const send = vi.fn(async (command: { input?: Record<string, unknown> }) => {
      const input = command.input ?? {};
      if (input.AuthFlow === "USER_PASSWORD_AUTH") {
        return {
          AuthenticationResult: {
            AccessToken: "initial-access-secret",
            IdToken: "initial-id-secret",
            RefreshToken: "initial-refresh-secret",
          },
        };
      }
      if (typeof input.RefreshToken === "string") {
        if (!input.RefreshToken.includes("replacement")) {
          if (send.mock.calls.filter((call) => {
            const sent = call[0] as { input?: { RefreshToken?: string } };
            return typeof sent.input?.RefreshToken === "string";
          }).length === 1) {
            return {
              AuthenticationResult: {
                AccessToken: "rotated-access-secret",
                IdToken: "rotated-id-secret",
                RefreshToken: "replacement-refresh-secret",
              },
            };
          }
        }
        throw new RefreshTokenReuseException({
          message: "Refresh token has been used.",
          $metadata: {},
        });
      }
      if (typeof input.Token === "string") {
        revokeCount += 1;
        if (revokeCount === 2) {
          throw new AccessDeniedException({
            message: "not allowed to revoke replacement-refresh-secret",
            $metadata: {},
          });
        }
        return {};
      }
      if (typeof input.AccessToken === "string") {
        return {};
      }
      throw new Error("unexpected command");
    });
    const deletePersona = vi.fn(async () => {
      throw new Error("delete failed for initial-refresh-secret");
    });

    const failure = await runPublicZeroGraceRotationScenario({
      sender: { send },
      profile,
      verifiers: verifiers({
        initialAccess: {
          sub: "subject-1",
          username: "user",
          jti: "access-jti-initial",
          origin_jti: "origin-jti-value",
        },
        rotatedAccess: {
          sub: "subject-1",
          username: "user",
          jti: "access-jti-rotated",
          origin_jti: "origin-jti-value",
        },
        initialId: {
          sub: "subject-1",
          jti: "id-jti-initial",
          origin_jti: "origin-jti-value",
        },
        rotatedId: {
          sub: "subject-1",
          jti: "id-jti-rotated",
          origin_jti: "origin-jti-value",
        },
      }),
      username: "user@example.com",
      password: "Password1!",
      fingerprinter: createLineageFingerprinter(salt),
      deletePersona,
    }).catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(ScenarioCleanupFailure);
    const cleanup = failure as ScenarioCleanupFailure;
    expect(cleanup.diagnostic).toEqual({
      revokeAttempted: 2,
      revokeFailed: 1,
      globalSignOutAttempted: true,
      globalSignOutFailed: false,
      personaDeleteFailed: true,
    });
    expect(revokeCount).toBe(2);
    expect(deletePersona).toHaveBeenCalledTimes(1);
    expect(safeText(cleanup.diagnostic)).not.toContain("initial-refresh-secret");
    expect(safeText(cleanup.message)).not.toContain("initial-refresh-secret");
    expect(safeText(cleanup.message)).not.toContain("Password1!");
  });
});

function successfulSender(options?: {
  revoke?: (token: string) => void;
}) {
  let rotations = 0;
  return vi.fn(async (command: { input?: Record<string, unknown> }) => {
    const input = command.input ?? {};
    if (input.AuthFlow === "USER_PASSWORD_AUTH") {
      return {
        AuthenticationResult: {
          AccessToken: "initial-access-secret",
          IdToken: "initial-id-secret",
          RefreshToken: "initial-refresh-secret",
        },
      };
    }
    if (typeof input.RefreshToken === "string") {
      rotations += 1;
      if (rotations === 1) {
        return {
          AuthenticationResult: {
            AccessToken: "rotated-access-secret",
            IdToken: "rotated-id-secret",
            RefreshToken: "replacement-refresh-secret",
          },
        };
      }
      throw new RefreshTokenReuseException({
        message: "Refresh token has been used.",
        $metadata: {},
      });
    }
    if (typeof input.Token === "string") {
      options?.revoke?.(input.Token);
    }
    return {};
  });
}

function verifiers(
  claims: {
    initialAccess?: {
      sub: string;
      username: string;
      jti?: string;
      origin_jti?: string;
    };
    rotatedAccess?: {
      sub: string;
      username: string;
      jti?: string;
      origin_jti?: string;
    };
    initialId?: { sub: string; jti?: string; origin_jti?: string };
    rotatedId?: { sub: string; jti?: string; origin_jti?: string };
  } = {},
) {
  return {
    access: {
      verify: vi
        .fn()
        .mockResolvedValueOnce(
          claims.initialAccess ?? {
            sub: "subject-1",
            username: "user",
            jti: "access-jti-initial",
            origin_jti: "origin-jti-value",
          },
        )
        .mockResolvedValueOnce(
          claims.rotatedAccess ?? {
            sub: "subject-1",
            username: "user",
            jti: "access-jti-rotated",
            origin_jti: "origin-jti-value",
          },
        ),
    },
    id: {
      verify: vi
        .fn()
        .mockResolvedValueOnce(
          claims.initialId ?? {
            sub: "subject-1",
            jti: "id-jti-initial",
            origin_jti: "origin-jti-value",
          },
        )
        .mockResolvedValueOnce(
          claims.rotatedId ?? {
            sub: "subject-1",
            jti: "id-jti-rotated",
            origin_jti: "origin-jti-value",
          },
        ),
    },
  };
}

function safeText(value: unknown): string {
  return JSON.stringify(value);
}
