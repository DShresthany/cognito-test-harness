import { serve } from "@hono/node-server";
import { config } from "dotenv";
import { createApp } from "./app.js";
import { createCognitoClient } from "./cognitoAuth.js";
import { CognitoAdminAuthDriver } from "./cognitoAdminAuthDriver.js";
import {
  createAwsCapabilityDescriber,
  resolveCognitoConfigPath,
} from "./cognitoConfigPaths.js";
import { createCognitoTestRuntime } from "./cognitoTestRuntime.js";
import { createAccessTokenVerifierPort } from "./jwtVerifier.js";

config();

const client = createCognitoClient();
const runtime = await createCognitoTestRuntime({
  configPath: resolveCognitoConfigPath(),
  ...createAwsCapabilityDescriber(client),
});
const profile = runtime.requireConfidentialProfile("admin-confidential");
const driver = new CognitoAdminAuthDriver(client, {
  id: profile.id,
  userPoolId: profile.userPoolId,
  clientId: profile.clientId,
  clientSecret: profile.clientSecret,
});

serve({
  fetch: createApp({
    authenticatePassword: {
      authenticate: (username, password) =>
        driver.authenticatePassword(username, password),
    },
    verifyAccessToken: createAccessTokenVerifierPort({
      userPoolId: profile.userPoolId,
      clientId: profile.clientId,
    }),
    reportDiagnostic: {
      report(diagnostic) {
        console.log(JSON.stringify(diagnostic));
      },
    },
  }).fetch,
  port: 3000,
});

console.log("listening on http://localhost:3000");
