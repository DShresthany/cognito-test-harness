import { readFile } from "node:fs/promises";
import {
  ADMIN_CONFIDENTIAL_PROFILE_ID,
  USER_POOL_PUBLIC_PROFILE_ID,
  loadAuthenticationProfileManifest,
  ManifestConfigurationFailure,
  type AuthenticationProfileManifest,
  type ConfidentialProfileRecord,
  type PublicProfileRecord,
} from "./authenticationProfileManifest.js";
import {
  EXPECTED_ADMIN_CONFIDENTIAL_CLIENT,
  EXPECTED_POOL_CONTRACT,
  EXPECTED_USER_POOL_PUBLIC_CLIENT,
  FIRST_RELEASE_REQUIRED_PROFILE_IDS,
  type ExpectedClientContract,
} from "./authenticationProfileExpectations.js";

export type DescribeUserPoolResult = {
  UserPool?: {
    UsernameAttributes?: string[];
    AutoVerifiedAttributes?: string[];
    AdminCreateUserConfig?: { AllowAdminCreateUserOnly?: boolean };
    AccountRecoverySetting?: {
      RecoveryMechanisms?: Array<{ Name?: string }>;
    };
    Tier?: string;
  };
};

export type GetUserPoolMfaConfigResult = {
  MfaConfiguration?: string;
  SoftwareTokenMfaConfiguration?: { Enabled?: boolean };
};

export type DescribeUserPoolClientResult = {
  UserPoolClient?: {
    ClientId?: string;
    ClientSecret?: string;
    ExplicitAuthFlows?: string[];
    RefreshTokenValidity?: number;
    AccessTokenValidity?: number;
    IdTokenValidity?: number;
    AuthSessionValidity?: number;
    TokenValidityUnits?: {
      AccessToken?: string;
      IdToken?: string;
      RefreshToken?: string;
    };
    EnableTokenRevocation?: boolean;
    AllowedOAuthFlowsUserPoolClient?: boolean;
    PreventUserExistenceErrors?: string;
    RefreshTokenRotation?: { Feature?: string };
  };
};

export type CognitoCapabilityDescriber = {
  describeUserPool(input: {
    userPoolId: string;
  }): Promise<DescribeUserPoolResult>;
  getUserPoolMfaConfig(input: {
    userPoolId: string;
  }): Promise<GetUserPoolMfaConfigResult>;
  describeUserPoolClient(input: {
    userPoolId: string;
    clientId: string;
  }): Promise<DescribeUserPoolClientResult>;
};

export type CreateCognitoTestRuntimeInput = CognitoCapabilityDescriber & {
  configPath: string;
  requiredProfileIds?: ReadonlyArray<string>;
};

export type CognitoTestRuntime = {
  manifest: AuthenticationProfileManifest;
  requireConfidentialProfile(id: string): ConfidentialProfileRecord & {
    id: typeof ADMIN_CONFIDENTIAL_PROFILE_ID;
    userPoolId: string;
    region: string;
  };
  requirePublicProfile(id: string): PublicProfileRecord & {
    id: typeof USER_POOL_PUBLIC_PROFILE_ID;
    userPoolId: string;
    region: string;
  };
};

export async function createCognitoTestRuntime(
  input: CreateCognitoTestRuntimeInput,
): Promise<CognitoTestRuntime> {
  const rawText = await readFile(input.configPath, "utf8");
  let rawDocument: unknown;
  try {
    rawDocument = JSON.parse(rawText);
  } catch {
    throw new ManifestConfigurationFailure(
      "authentication profile manifest: config file must be JSON",
    );
  }

  const manifest = loadAuthenticationProfileManifest(rawDocument);
  const requiredProfileIds =
    input.requiredProfileIds ?? FIRST_RELEASE_REQUIRED_PROFILE_IDS;

  for (const profileId of requiredProfileIds) {
    if (!(profileId in manifest.profiles)) {
      throw new ManifestConfigurationFailure(
        `authentication profile manifest: missing required profile at profiles.${profileId}`,
      );
    }
  }

  await assertPoolContract(input, manifest.userPoolId);
  await assertMfaContract(input, manifest.userPoolId);

  for (const profileId of requiredProfileIds) {
    const profile = manifest.profiles[profileId]!;
    const described = await input.describeUserPoolClient({
      userPoolId: manifest.userPoolId,
      clientId: profile.clientId,
    });
    assertClientContract(profileId, profile.kind, described);
  }

  return {
    manifest,
    requireConfidentialProfile(id) {
      const profile = manifest.profiles[id];
      if (!profile || profile.kind !== "confidential") {
        throw new ManifestConfigurationFailure(
          `authentication profile manifest: confidential profile required at profiles.${id}`,
        );
      }
      if (id !== ADMIN_CONFIDENTIAL_PROFILE_ID) {
        throw new ManifestConfigurationFailure(
          `authentication profile manifest: unsupported confidential profile id at profiles.${id}`,
        );
      }
      return {
        id: ADMIN_CONFIDENTIAL_PROFILE_ID,
        userPoolId: manifest.userPoolId,
        region: manifest.region,
        ...profile,
      };
    },
    requirePublicProfile(id) {
      const profile = manifest.profiles[id];
      if (!profile || profile.kind !== "public") {
        throw new ManifestConfigurationFailure(
          `authentication profile manifest: public profile required at profiles.${id}`,
        );
      }
      if (id !== USER_POOL_PUBLIC_PROFILE_ID) {
        throw new ManifestConfigurationFailure(
          `authentication profile manifest: unsupported public profile id at profiles.${id}`,
        );
      }
      return {
        id: USER_POOL_PUBLIC_PROFILE_ID,
        userPoolId: manifest.userPoolId,
        region: manifest.region,
        ...profile,
      };
    },
  };
}

async function assertPoolContract(
  describer: CognitoCapabilityDescriber,
  userPoolId: string,
): Promise<void> {
  const described = await describer.describeUserPool({ userPoolId });
  const pool = described.UserPool;
  if (!pool) {
    throw drift("userPool", "missing UserPool payload");
  }

  if (!pool.UsernameAttributes?.includes("email")) {
    throw drift("userPool.UsernameAttributes", "expected email");
  }
  if (!pool.AutoVerifiedAttributes?.includes("email")) {
    throw drift("userPool.AutoVerifiedAttributes", "expected email");
  }
  if (pool.AdminCreateUserConfig?.AllowAdminCreateUserOnly !== true) {
    throw drift(
      "userPool.AdminCreateUserConfig.AllowAdminCreateUserOnly",
      "expected true",
    );
  }
  const recoveryNames =
    pool.AccountRecoverySetting?.RecoveryMechanisms?.map(
      (mechanism) => mechanism.Name,
    ) ?? [];
  if (!recoveryNames.includes("verified_email")) {
    throw drift(
      "userPool.AccountRecoverySetting.RecoveryMechanisms",
      "expected verified_email",
    );
  }
  // Essentials-or-higher: reject only known below-minimum tiers; tolerate PLUS and future higher tiers.
  if (pool.Tier === "LITE") {
    throw drift("userPool.Tier", "feature tier below minimum");
  }
}

async function assertMfaContract(
  describer: CognitoCapabilityDescriber,
  userPoolId: string,
): Promise<void> {
  const described = await describer.getUserPoolMfaConfig({ userPoolId });
  if (described.MfaConfiguration !== EXPECTED_POOL_CONTRACT.mfaConfiguration) {
    throw drift("userPool.MfaConfiguration", "expected OPTIONAL");
  }
  if (described.SoftwareTokenMfaConfiguration?.Enabled !== true) {
    throw drift(
      "userPool.SoftwareTokenMfaConfiguration.Enabled",
      "expected true",
    );
  }
}

function assertClientContract(
  profileId: string,
  kind: "confidential" | "public",
  described: DescribeUserPoolClientResult,
): void {
  const client = described.UserPoolClient;
  if (!client) {
    throw drift(`profiles.${profileId}`, "missing UserPoolClient payload");
  }

  const expected =
    kind === "confidential"
      ? EXPECTED_ADMIN_CONFIDENTIAL_CLIENT
      : EXPECTED_USER_POOL_PUBLIC_CLIENT;

  assertAuthFlows(profileId, client.ExplicitAuthFlows ?? [], expected);

  if (client.EnableTokenRevocation !== expected.enableTokenRevocation) {
    throw drift(
      `profiles.${profileId}.EnableTokenRevocation`,
      "token revocation drift",
    );
  }
  if (
    (client.AllowedOAuthFlowsUserPoolClient ?? false) !== expected.oauthEnabled
  ) {
    throw drift(
      `profiles.${profileId}.AllowedOAuthFlowsUserPoolClient`,
      "oauth drift",
    );
  }
  if (
    client.PreventUserExistenceErrors !== expected.preventUserExistenceErrors
  ) {
    throw drift(
      `profiles.${profileId}.PreventUserExistenceErrors`,
      "existence-error drift",
    );
  }
  if (
    (client.RefreshTokenRotation?.Feature ?? "DISABLED") === "ENABLED" &&
    !expected.refreshTokenRotationEnabled
  ) {
    throw drift(
      `profiles.${profileId}.RefreshTokenRotation`,
      "rotation must stay disabled",
    );
  }

  assertDuration(
    `profiles.${profileId}.AccessTokenValidity`,
    client.AccessTokenValidity,
    client.TokenValidityUnits?.AccessToken,
    expected.accessTokenValidityHours,
    "hours",
  );
  assertDuration(
    `profiles.${profileId}.IdTokenValidity`,
    client.IdTokenValidity,
    client.TokenValidityUnits?.IdToken,
    expected.idTokenValidityHours,
    "hours",
  );
  assertDuration(
    `profiles.${profileId}.RefreshTokenValidity`,
    client.RefreshTokenValidity,
    client.TokenValidityUnits?.RefreshToken,
    expected.refreshTokenValidityDays,
    "days",
  );
  if (client.AuthSessionValidity !== expected.authSessionValidityMinutes) {
    throw drift(
      `profiles.${profileId}.AuthSessionValidity`,
      "challenge session drift",
    );
  }

  if (kind === "public" && client.ClientSecret) {
    throw drift(
      `profiles.${profileId}.ClientSecret`,
      "public profile must not have a client secret",
    );
  }
}

function assertAuthFlows(
  profileId: string,
  actualFlows: string[],
  expected: ExpectedClientContract,
): void {
  for (const flow of expected.requiredAuthFlows) {
    if (!actualFlows.includes(flow)) {
      throw drift(
        `profiles.${profileId}.ExplicitAuthFlows`,
        `missing required flow`,
      );
    }
  }
  for (const flow of expected.forbiddenAuthFlows) {
    if (actualFlows.includes(flow)) {
      throw drift(
        `profiles.${profileId}.ExplicitAuthFlows`,
        `forbidden flow present`,
      );
    }
  }
}

function assertDuration(
  path: string,
  value: number | undefined,
  unit: string | undefined,
  expectedValue: number,
  expectedUnit: "hours" | "days",
): void {
  if (value === undefined) {
    throw drift(path, "token lifetime drift");
  }
  const actualMinutes = toMinutes(value, unit ?? expectedUnit);
  const expectedMinutes = toMinutes(expectedValue, expectedUnit);
  if (actualMinutes !== expectedMinutes) {
    throw drift(path, "token lifetime drift");
  }
}

/** Cognito/CDK often report the same lifetime as minutes instead of hours/days. */
function toMinutes(value: number, unit: string): number {
  switch (unit) {
    case "minutes":
      return value;
    case "hours":
      return value * 60;
    case "days":
      return value * 24 * 60;
    default:
      throw drift("TokenValidityUnits", `unsupported unit ${unit}`);
  }
}

function drift(path: string, _reason: string): ManifestConfigurationFailure {
  return new ManifestConfigurationFailure(
    `authentication profile manifest: live capability drift at ${path}`,
  );
}
