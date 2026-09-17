#!/usr/bin/env npx tsx
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { materializeAuthenticationProfileConfig } from "../src/materializeAuthenticationProfileConfig.js";

async function main(): Promise<void> {
  const root = resolve(process.cwd());
  const configPath =
    process.env.COGNITO_CONFIG_PATH ?? resolve(root, ".cognito/config.json");
  const envPath = process.env.COGNITO_ENV_PATH ?? resolve(root, ".env");
  const awsProfile = process.env.AWS_PROFILE;

  const rawText = readFileSync(0, "utf8");
  let rawDocument: unknown;
  try {
    rawDocument = JSON.parse(rawText);
  } catch {
    throw new Error("authentication profile manifest: input must be JSON");
  }

  await materializeAuthenticationProfileConfig({
    rawDocument,
    configPath,
    envPath,
    ...(awsProfile ? { awsProfile } : {}),
  });

  console.log(
    `Wrote owner-only Cognito config to ${configPath} (secret values not logged)`,
  );
  console.log(`Wrote bootstrap env to ${envPath} (secret values not logged)`);
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(message);
  process.exitCode = 1;
});
