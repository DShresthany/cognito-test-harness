import { access, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { createHarnessComposition } from "../../src/createHarnessComposition.js";

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

describe("createHarnessComposition", () => {
  it("wires runtime, confidential driver, fixtures, and HTTP stub without LoginManager", async () => {
    const root = await mkdtemp(join(tmpdir(), "harness-composition-"));
    const configPath = join(root, "config.json");
    await writeFile(configPath, JSON.stringify(v2Document));

    try {
      const send = vi.fn();
      const client = { send } as never;
      const composition = await createHarnessComposition({
        configPath,
        client,
        describer: {
          describeUserPool: async () => poolOk(),
          getUserPoolMfaConfig: async () => mfaOk(),
          describeUserPoolClient: async ({ clientId }) =>
            clientId === "confidential-client-id"
              ? confidentialClientOk()
              : publicClientOk(),
        },
      });

      expect(composition.profile).toEqual({
        id: "admin-confidential",
        userPoolId: "us-east-1_example",
        clientId: "confidential-client-id",
        clientSecret: "confidential-client-secret",
      });
      expect(composition.driver).toBeDefined();
      expect(composition.fixtures.runId).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      );
      expect(composition.app).toBeDefined();
      expect(composition).not.toHaveProperty("authResults");
      expect(composition).not.toHaveProperty("credentials");
      expect(composition).not.toHaveProperty("fromEnv");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

describe("LoginManager deletion contract", () => {
  it("removes CognitoLoginManager and cognitoAuthResult source modules", async () => {
    await expect(
      access(resolve(process.cwd(), "src/cognitoLoginManager.ts")),
    ).rejects.toMatchObject({ code: "ENOENT" });
    await expect(
      access(resolve(process.cwd(), "src/cognitoAuthResult.ts")),
    ).rejects.toMatchObject({ code: "ENOENT" });
  });
});
