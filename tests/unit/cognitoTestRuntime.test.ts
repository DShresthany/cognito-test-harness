import { describe, expect, it, vi } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createCognitoTestRuntime } from "../../src/cognitoTestRuntime.js";
import { ManifestConfigurationFailure } from "../../src/authenticationProfileManifest.js";

const v2Document = {
  schemaVersion: 2,
  region: "us-east-1",
  userPoolId: "us-east-1_example",
  profiles: {
    "admin-confidential": {
      kind: "confidential" as const,
      clientId: "confidential-client-id",
      clientSecret: "confidential-client-secret",
    },
    "user-pool-public": {
      kind: "public" as const,
      clientId: "public-client-id",
    },
  },
};

function poolOk() {
  return {
    UserPool: {
      UsernameAttributes: ["email"],
      AutoVerifiedAttributes: ["email"],
      AdminCreateUserConfig: { AllowAdminCreateUserOnly: true },
      AccountRecoverySetting: {
        RecoveryMechanisms: [{ Name: "verified_email", Priority: 1 }],
      },
      Tier: "ESSENTIALS",
    },
  };
}

function mfaOk() {
  return {
    MfaConfiguration: "OPTIONAL",
    SoftwareTokenMfaConfiguration: { Enabled: true },
  };
}

function confidentialClientOk() {
  return {
    UserPoolClient: {
      ClientId: "confidential-client-id",
      ExplicitAuthFlows: [
        "ALLOW_ADMIN_USER_PASSWORD_AUTH",
        "ALLOW_REFRESH_TOKEN_AUTH",
      ],
      RefreshTokenValidity: 30,
      AccessTokenValidity: 1,
      IdTokenValidity: 1,
      AuthSessionValidity: 3,
      TokenValidityUnits: {
        AccessToken: "hours",
        IdToken: "hours",
        RefreshToken: "days",
      },
      EnableTokenRevocation: true,
      AllowedOAuthFlowsUserPoolClient: false,
      PreventUserExistenceErrors: "ENABLED",
    },
  };
}

function publicClientOk() {
  return {
    UserPoolClient: {
      ClientId: "public-client-id",
      ExplicitAuthFlows: [
        "ALLOW_USER_PASSWORD_AUTH",
        "ALLOW_REFRESH_TOKEN_AUTH",
      ],
      RefreshTokenValidity: 30,
      AccessTokenValidity: 1,
      IdTokenValidity: 1,
      AuthSessionValidity: 3,
      TokenValidityUnits: {
        AccessToken: "hours",
        IdToken: "hours",
        RefreshToken: "days",
      },
      EnableTokenRevocation: true,
      AllowedOAuthFlowsUserPoolClient: false,
      PreventUserExistenceErrors: "ENABLED",
    },
  };
}

describe("createCognitoTestRuntime", () => {
  it("creates a runtime after live preflight succeeds", async () => {
    const root = await mkdtemp(join(tmpdir(), "cognito-runtime-"));
    const configPath = join(root, "config.json");
    await writeFile(configPath, JSON.stringify(v2Document));

    const describeUserPool = vi.fn().mockResolvedValue(poolOk());
    const getUserPoolMfaConfig = vi.fn().mockResolvedValue(mfaOk());
    const describeUserPoolClient = vi
      .fn()
      .mockResolvedValueOnce(confidentialClientOk())
      .mockResolvedValueOnce(publicClientOk());

    try {
      const runtime = await createCognitoTestRuntime({
        configPath,
        describeUserPool,
        getUserPoolMfaConfig,
        describeUserPoolClient,
      });

      expect(runtime.manifest.userPoolId).toBe("us-east-1_example");
      expect(
        runtime.requireConfidentialProfile("admin-confidential").clientSecret,
      ).toBe("confidential-client-secret");
      expect(runtime.requirePublicProfile("user-pool-public").clientId).toBe(
        "public-client-id",
      );
      expect(describeUserPool).toHaveBeenCalledTimes(1);
      expect(getUserPoolMfaConfig).toHaveBeenCalledTimes(1);
      expect(describeUserPoolClient).toHaveBeenCalledTimes(2);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("fails runtime creation when a required client has drifted", async () => {
    const root = await mkdtemp(join(tmpdir(), "cognito-runtime-"));
    const configPath = join(root, "config.json");
    await writeFile(configPath, JSON.stringify(v2Document));

    const drifted = confidentialClientOk();
    drifted.UserPoolClient.ExplicitAuthFlows = ["ALLOW_USER_PASSWORD_AUTH"];

    try {
      await expect(
        createCognitoTestRuntime({
          configPath,
          describeUserPool: vi.fn().mockResolvedValue(poolOk()),
          getUserPoolMfaConfig: vi.fn().mockResolvedValue(mfaOk()),
          describeUserPoolClient: vi
            .fn()
            .mockResolvedValueOnce(drifted)
            .mockResolvedValueOnce(publicClientOk()),
        }),
      ).rejects.toMatchObject({
        name: "ManifestConfigurationFailure",
        retryable: false,
      });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("fails when a required profile is missing from the manifest", async () => {
    const root = await mkdtemp(join(tmpdir(), "cognito-runtime-"));
    const configPath = join(root, "config.json");
    await writeFile(
      configPath,
      JSON.stringify({
        schemaVersion: 2,
        region: "us-east-1",
        userPoolId: "us-east-1_example",
        profiles: {
          "admin-confidential": v2Document.profiles["admin-confidential"],
        },
      }),
    );

    try {
      await expect(
        createCognitoTestRuntime({
          configPath,
          describeUserPool: vi.fn().mockResolvedValue(poolOk()),
          getUserPoolMfaConfig: vi.fn().mockResolvedValue(mfaOk()),
          describeUserPoolClient: vi
            .fn()
            .mockResolvedValue(confidentialClientOk()),
        }),
      ).rejects.toBeInstanceOf(ManifestConfigurationFailure);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("tolerates PLUS and unknown higher feature tiers", async () => {
    const root = await mkdtemp(join(tmpdir(), "cognito-runtime-"));
    const configPath = join(root, "config.json");
    await writeFile(configPath, JSON.stringify(v2Document));
    const plusPool = poolOk();
    plusPool.UserPool.Tier = "PLUS";
    const futurePool = poolOk();
    futurePool.UserPool.Tier = "FUTURE_TIER";

    try {
      await createCognitoTestRuntime({
        configPath,
        describeUserPool: vi.fn().mockResolvedValue(plusPool),
        getUserPoolMfaConfig: vi.fn().mockResolvedValue(mfaOk()),
        describeUserPoolClient: vi
          .fn()
          .mockResolvedValueOnce(confidentialClientOk())
          .mockResolvedValueOnce(publicClientOk()),
      });
      await createCognitoTestRuntime({
        configPath,
        describeUserPool: vi.fn().mockResolvedValue(futurePool),
        getUserPoolMfaConfig: vi.fn().mockResolvedValue(mfaOk()),
        describeUserPoolClient: vi
          .fn()
          .mockResolvedValueOnce(confidentialClientOk())
          .mockResolvedValueOnce(publicClientOk()),
      });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("rejects known below-minimum feature tiers", async () => {
    const root = await mkdtemp(join(tmpdir(), "cognito-runtime-"));
    const configPath = join(root, "config.json");
    await writeFile(configPath, JSON.stringify(v2Document));
    const litePool = poolOk();
    litePool.UserPool.Tier = "LITE";

    try {
      await expect(
        createCognitoTestRuntime({
          configPath,
          describeUserPool: vi.fn().mockResolvedValue(litePool),
          getUserPoolMfaConfig: vi.fn().mockResolvedValue(mfaOk()),
          describeUserPoolClient: vi.fn(),
        }),
      ).rejects.toMatchObject({
        name: "ManifestConfigurationFailure",
        message: expect.stringContaining("userPool.Tier"),
      });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
