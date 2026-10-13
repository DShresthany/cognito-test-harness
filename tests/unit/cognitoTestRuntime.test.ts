import { describe, expect, it, vi } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createCognitoTestRuntime } from "../../src/cognitoTestRuntime.js";
import {
  REFRESH_ROTATING_PUBLIC_PROFILE_ID,
  ManifestConfigurationFailure,
} from "../../src/authenticationProfileManifest.js";
import { TOKEN_LIFECYCLE_SOAK_PROFILE_IDS } from "../../src/authenticationProfileExpectations.js";

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
      DeviceConfiguration: undefined as
        | {
            ChallengeRequiredOnNewDevice?: boolean;
            DeviceOnlyRememberedOnUserPrompt?: boolean;
          }
        | undefined,
    },
  };
}

function rotatingPublicClientOk() {
  return {
    UserPoolClient: {
      ClientId: "rotating-public-client-id",
      ExplicitAuthFlows: ["ALLOW_USER_PASSWORD_AUTH"],
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
      RefreshTokenRotation: {
        Feature: "ENABLED",
        RetryGracePeriodSeconds: 0,
      },
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

  it("tolerates Cognito/CDK minute-encoded token lifetimes equivalent to hours/days", async () => {
    const root = await mkdtemp(join(tmpdir(), "cognito-runtime-"));
    const configPath = join(root, "config.json");
    await writeFile(configPath, JSON.stringify(v2Document));

    const confidential = confidentialClientOk();
    confidential.UserPoolClient.AccessTokenValidity = 60;
    confidential.UserPoolClient.IdTokenValidity = 60;
    confidential.UserPoolClient.RefreshTokenValidity = 43200;
    confidential.UserPoolClient.TokenValidityUnits = {
      AccessToken: "minutes",
      IdToken: "minutes",
      RefreshToken: "minutes",
    };
    const publicClient = publicClientOk();
    publicClient.UserPoolClient.AccessTokenValidity = 60;
    publicClient.UserPoolClient.IdTokenValidity = 60;
    publicClient.UserPoolClient.RefreshTokenValidity = 43200;
    publicClient.UserPoolClient.TokenValidityUnits = {
      AccessToken: "minutes",
      IdToken: "minutes",
      RefreshToken: "minutes",
    };

    try {
      await createCognitoTestRuntime({
        configPath,
        describeUserPool: vi.fn().mockResolvedValue(poolOk()),
        getUserPoolMfaConfig: vi.fn().mockResolvedValue(mfaOk()),
        describeUserPoolClient: vi
          .fn()
          .mockResolvedValueOnce(confidential)
          .mockResolvedValueOnce(publicClient),
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

  it("leaves refresh-rotating-public unchecked unless a suite requires it", async () => {
    const root = await mkdtemp(join(tmpdir(), "cognito-runtime-"));
    const configPath = join(root, "config.json");
    await writeFile(
      configPath,
      JSON.stringify({
        ...v2Document,
        profiles: {
          ...v2Document.profiles,
          [REFRESH_ROTATING_PUBLIC_PROFILE_ID]: {
            kind: "public",
            clientId: "rotating-public-client-id",
          },
        },
      }),
    );
    const describeUserPoolClient = vi
      .fn()
      .mockResolvedValueOnce(confidentialClientOk())
      .mockResolvedValueOnce(publicClientOk());

    try {
      await createCognitoTestRuntime({
        configPath,
        describeUserPool: vi.fn().mockResolvedValue(poolOk()),
        getUserPoolMfaConfig: vi.fn().mockResolvedValue(mfaOk()),
        describeUserPoolClient,
      });
      expect(describeUserPoolClient).toHaveBeenCalledTimes(2);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("accepts refresh-rotating-public when rotation, grace, flows, and revocation match", async () => {
    const root = await mkdtemp(join(tmpdir(), "cognito-runtime-"));
    const configPath = join(root, "config.json");
    await writeFile(
      configPath,
      JSON.stringify({
        ...v2Document,
        profiles: {
          [REFRESH_ROTATING_PUBLIC_PROFILE_ID]: {
            kind: "public",
            clientId: "rotating-public-client-id",
          },
        },
      }),
    );

    try {
      const runtime = await createCognitoTestRuntime({
        configPath,
        requiredProfileIds: TOKEN_LIFECYCLE_SOAK_PROFILE_IDS,
        describeUserPool: vi.fn().mockResolvedValue(poolOk()),
        getUserPoolMfaConfig: vi.fn().mockResolvedValue(mfaOk()),
        describeUserPoolClient: vi.fn().mockResolvedValue(rotatingPublicClientOk()),
      });
      expect(
        runtime.requirePublicProfile(REFRESH_ROTATING_PUBLIC_PROFILE_ID).clientId,
      ).toBe("rotating-public-client-id");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("fails when refresh-rotating-public grace, rotation, or device tracking drifts", async () => {
    const cases = [
      {
        name: "grace",
        client: rotatingPublicClientOk(),
        pool: poolOk(),
        mutate(
          client: ReturnType<typeof rotatingPublicClientOk>,
          _pool?: ReturnType<typeof poolOk>,
        ) {
          client.UserPoolClient.RefreshTokenRotation.RetryGracePeriodSeconds = 10;
        },
      },
      {
        name: "rotation disabled",
        client: rotatingPublicClientOk(),
        pool: poolOk(),
        mutate(
          client: ReturnType<typeof rotatingPublicClientOk>,
          _pool?: ReturnType<typeof poolOk>,
        ) {
          client.UserPoolClient.RefreshTokenRotation.Feature = "DISABLED";
        },
      },
      {
        name: "refresh auth flow",
        client: rotatingPublicClientOk(),
        pool: poolOk(),
        mutate(
          client: ReturnType<typeof rotatingPublicClientOk>,
          _pool?: ReturnType<typeof poolOk>,
        ) {
          client.UserPoolClient.ExplicitAuthFlows = [
            "ALLOW_USER_PASSWORD_AUTH",
            "ALLOW_REFRESH_TOKEN_AUTH",
          ];
        },
      },
      {
        name: "revocation",
        client: rotatingPublicClientOk(),
        pool: poolOk(),
        mutate(
          client: ReturnType<typeof rotatingPublicClientOk>,
          _pool?: ReturnType<typeof poolOk>,
        ) {
          client.UserPoolClient.EnableTokenRevocation = false;
        },
      },
      {
        name: "device tracking",
        client: rotatingPublicClientOk(),
        pool: poolOk(),
        mutate(
          _client: ReturnType<typeof rotatingPublicClientOk>,
          pool: ReturnType<typeof poolOk>,
        ) {
          pool.UserPool.DeviceConfiguration = {
            ChallengeRequiredOnNewDevice: true,
            DeviceOnlyRememberedOnUserPrompt: true,
          };
        },
      },
    ];

    for (const testCase of cases) {
      testCase.mutate(testCase.client, testCase.pool);
      const root = await mkdtemp(join(tmpdir(), "cognito-runtime-"));
      const configPath = join(root, "config.json");
      await writeFile(
        configPath,
        JSON.stringify({
          ...v2Document,
          profiles: {
            [REFRESH_ROTATING_PUBLIC_PROFILE_ID]: {
              kind: "public",
              clientId: "rotating-public-client-id",
            },
          },
        }),
      );
      try {
        await expect(
          createCognitoTestRuntime({
            configPath,
            requiredProfileIds: TOKEN_LIFECYCLE_SOAK_PROFILE_IDS,
            describeUserPool: vi.fn().mockResolvedValue(testCase.pool),
            getUserPoolMfaConfig: vi.fn().mockResolvedValue(mfaOk()),
            describeUserPoolClient: vi.fn().mockResolvedValue(testCase.client),
          }),
        ).rejects.toBeInstanceOf(ManifestConfigurationFailure);
      } finally {
        await rm(root, { recursive: true, force: true });
      }
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
