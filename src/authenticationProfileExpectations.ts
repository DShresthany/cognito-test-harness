import {
  ADMIN_CONFIDENTIAL_PROFILE_ID,
  REFRESH_ROTATING_PUBLIC_PROFILE_ID,
  USER_POOL_PUBLIC_PROFILE_ID,
  type AuthenticationProfileId,
} from "./authenticationProfileManifest.js";

export type ExpectedPoolContract = {
  usernameAttributesIncludeEmail: true;
  autoVerifiedAttributesIncludeEmail: true;
  adminCreateUserOnly: true;
  accountRecoveryIncludesVerifiedEmail: true;
  mfaConfiguration: "OPTIONAL";
  softwareTokenMfaEnabled: true;
  deviceTrackingDisabled: true;
  /** Accepted feature tiers (Essentials-or-higher). */
  minimumFeatureTier: ReadonlyArray<"ESSENTIALS" | "PLUS">;
};

type ExpectedClientContractBase = {
  requiredAuthFlows: ReadonlyArray<string>;
  forbiddenAuthFlows: ReadonlyArray<string>;
  refreshTokenValidityDays: 30;
  accessTokenValidityHours: 1;
  idTokenValidityHours: 1;
  authSessionValidityMinutes: 3;
  enableTokenRevocation: true;
  oauthEnabled: false;
  preventUserExistenceErrors: "ENABLED";
};

export type ExpectedClientContract = ExpectedClientContractBase &
  (
    | { refreshTokenRotationEnabled: false }
    | {
        refreshTokenRotationEnabled: true;
        refreshTokenRotationGracePeriodSeconds: number;
      }
  );

export const FIRST_RELEASE_REQUIRED_PROFILE_IDS = [
  ADMIN_CONFIDENTIAL_PROFILE_ID,
  USER_POOL_PUBLIC_PROFILE_ID,
] as const satisfies ReadonlyArray<AuthenticationProfileId>;

export const EXPECTED_POOL_CONTRACT: ExpectedPoolContract = {
  usernameAttributesIncludeEmail: true,
  autoVerifiedAttributesIncludeEmail: true,
  adminCreateUserOnly: true,
  accountRecoveryIncludesVerifiedEmail: true,
  mfaConfiguration: "OPTIONAL",
  softwareTokenMfaEnabled: true,
  deviceTrackingDisabled: true,
  minimumFeatureTier: ["ESSENTIALS", "PLUS"],
};

export const EXPECTED_ADMIN_CONFIDENTIAL_CLIENT: ExpectedClientContract = {
  requiredAuthFlows: [
    "ALLOW_ADMIN_USER_PASSWORD_AUTH",
    "ALLOW_REFRESH_TOKEN_AUTH",
  ],
  forbiddenAuthFlows: [
    "ALLOW_USER_PASSWORD_AUTH",
    "ALLOW_USER_SRP_AUTH",
    "ALLOW_USER_AUTH",
    "ALLOW_CUSTOM_AUTH",
  ],
  refreshTokenValidityDays: 30,
  accessTokenValidityHours: 1,
  idTokenValidityHours: 1,
  authSessionValidityMinutes: 3,
  enableTokenRevocation: true,
  oauthEnabled: false,
  preventUserExistenceErrors: "ENABLED",
  refreshTokenRotationEnabled: false,
};

export const EXPECTED_USER_POOL_PUBLIC_CLIENT: ExpectedClientContract = {
  requiredAuthFlows: [
    "ALLOW_USER_PASSWORD_AUTH",
    "ALLOW_REFRESH_TOKEN_AUTH",
  ],
  forbiddenAuthFlows: [
    "ALLOW_ADMIN_USER_PASSWORD_AUTH",
    "ALLOW_USER_SRP_AUTH",
    "ALLOW_USER_AUTH",
    "ALLOW_CUSTOM_AUTH",
  ],
  refreshTokenValidityDays: 30,
  accessTokenValidityHours: 1,
  idTokenValidityHours: 1,
  authSessionValidityMinutes: 3,
  enableTokenRevocation: true,
  oauthEnabled: false,
  preventUserExistenceErrors: "ENABLED",
  refreshTokenRotationEnabled: false,
};

export const TOKEN_LIFECYCLE_SOAK_PROFILE_IDS = [
  REFRESH_ROTATING_PUBLIC_PROFILE_ID,
] as const satisfies ReadonlyArray<AuthenticationProfileId>;

export const EXPECTED_REFRESH_ROTATING_PUBLIC_CLIENT: ExpectedClientContract = {
  requiredAuthFlows: ["ALLOW_USER_PASSWORD_AUTH"],
  forbiddenAuthFlows: [
    "ALLOW_REFRESH_TOKEN_AUTH",
    "ALLOW_ADMIN_USER_PASSWORD_AUTH",
    "ALLOW_USER_SRP_AUTH",
    "ALLOW_USER_AUTH",
    "ALLOW_CUSTOM_AUTH",
  ],
  refreshTokenValidityDays: 30,
  accessTokenValidityHours: 1,
  idTokenValidityHours: 1,
  authSessionValidityMinutes: 3,
  enableTokenRevocation: true,
  oauthEnabled: false,
  preventUserExistenceErrors: "ENABLED",
  refreshTokenRotationEnabled: true,
  refreshTokenRotationGracePeriodSeconds: 0,
};
