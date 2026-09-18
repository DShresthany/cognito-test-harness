#!/usr/bin/env npx tsx
/**
 * Validate materialized manifest + live Cognito Describe preflight.
 * Does not create personas.
 */
import { createCognitoClient } from "../src/cognitoAuth.js";
import {
  createAwsCapabilityDescriber,
  resolveCognitoConfigPath,
} from "../src/cognitoConfigPaths.js";
import { createCognitoTestRuntime } from "../src/cognitoTestRuntime.js";

async function main(): Promise<void> {
  const client = createCognitoClient();
  const runtime = await createCognitoTestRuntime({
    configPath: resolveCognitoConfigPath(),
    ...createAwsCapabilityDescriber(client),
  });
  runtime.requireConfidentialProfile("admin-confidential");
  runtime.requirePublicProfile("user-pool-public");
  console.log(
    "Preflight OK: manifest validated and live Cognito contract matches expectations (no users created)",
  );
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(message);
  process.exitCode = 1;
});
