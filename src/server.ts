import { serve } from "@hono/node-server";
import { config } from "dotenv";
import { createApp } from "./app.js";
import { createCognitoClient, required } from "./cognitoAuth.js";
import { CognitoAdminAuthDriver } from "./cognitoAdminAuthDriver.js";
import { createAccessTokenVerifierPort } from "./jwtVerifier.js";

config();

const driver = new CognitoAdminAuthDriver(createCognitoClient(), {
  id: "admin-confidential",
  userPoolId: required("COGNITO_USER_POOL_ID"),
  clientId: required("COGNITO_CLIENT_ID"),
  clientSecret: required("COGNITO_CLIENT_SECRET"),
});

serve({
  fetch: createApp({
    authenticatePassword: {
      authenticate: (username, password) =>
        driver.authenticatePassword(username, password),
    },
    verifyAccessToken: createAccessTokenVerifierPort(),
    reportDiagnostic: {
      report(diagnostic) {
        console.log(JSON.stringify(diagnostic));
      },
    },
  }).fetch,
  port: 3000,
});

console.log("listening on http://localhost:3000");
