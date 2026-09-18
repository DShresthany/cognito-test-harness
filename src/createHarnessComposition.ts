import type { CognitoIdentityProviderClient } from "@aws-sdk/client-cognito-identity-provider";
import { createApp, type HttpAuthenticationStubDependencies } from "./app.js";
import {
  CognitoAdminAuthDriver,
  type ConfidentialAdminAuthProfile,
} from "./cognitoAdminAuthDriver.js";
import { createCognitoClient } from "./cognitoAuth.js";
import {
  createAwsCapabilityDescriber,
  resolveCognitoConfigPath,
} from "./cognitoConfigPaths.js";
import {
  createCognitoTestRuntime,
  type CognitoCapabilityDescriber,
  type CognitoTestRuntime,
} from "./cognitoTestRuntime.js";
import {
  CognitoUserFixtureManager,
  createCognitoFixtureCommands,
} from "./cognitoUserFixtureManager.js";
import { createAccessTokenVerifierPort } from "./jwtVerifier.js";

export type HarnessComposition = {
  client: CognitoIdentityProviderClient;
  runtime: CognitoTestRuntime;
  profile: ConfidentialAdminAuthProfile;
  driver: CognitoAdminAuthDriver;
  fixtures: CognitoUserFixtureManager;
  app: ReturnType<typeof createApp>;
};

export type CreateHarnessCompositionInput = {
  configPath?: string;
  client?: CognitoIdentityProviderClient;
  describer?: CognitoCapabilityDescriber;
  reportDiagnostic?: HttpAuthenticationStubDependencies["reportDiagnostic"];
};

/**
 * Single composition root for live harness wiring.
 * Builds runtime (manifest + preflight), confidential admin driver, fixtures, and HTTP stub.
 */
export async function createHarnessComposition(
  input: CreateHarnessCompositionInput = {},
): Promise<HarnessComposition> {
  const client = input.client ?? createCognitoClient();
  const describer =
    input.describer ?? createAwsCapabilityDescriber(client);
  const runtime = await createCognitoTestRuntime({
    configPath: input.configPath ?? resolveCognitoConfigPath(),
    ...describer,
  });
  const confidential = runtime.requireConfidentialProfile("admin-confidential");
  const profile: ConfidentialAdminAuthProfile = {
    id: confidential.id,
    userPoolId: confidential.userPoolId,
    clientId: confidential.clientId,
    clientSecret: confidential.clientSecret,
  };
  const driver = new CognitoAdminAuthDriver(client, profile);
  const fixtures = new CognitoUserFixtureManager(
    createCognitoFixtureCommands(client, profile.userPoolId),
  );
  const app = createApp({
    authenticatePassword: {
      authenticate: (username, password) =>
        driver.authenticatePassword(username, password),
    },
    verifyAccessToken: createAccessTokenVerifierPort({
      userPoolId: profile.userPoolId,
      clientId: profile.clientId,
    }),
    reportDiagnostic: input.reportDiagnostic ?? { report() {} },
  });

  return { client, runtime, profile, driver, fixtures, app };
}
