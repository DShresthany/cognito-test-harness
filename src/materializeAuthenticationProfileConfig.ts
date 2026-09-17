import { chmod, mkdir, rename, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import {
  loadAuthenticationProfileManifest,
  type AuthenticationProfileManifest,
} from "./authenticationProfileManifest.js";

export type MaterializeAuthenticationProfileConfigInput = {
  rawDocument: unknown;
  configPath: string;
  envPath: string;
  awsProfile?: string;
};

export type MaterializeAuthenticationProfileConfigResult = {
  configPath: string;
  manifest: AuthenticationProfileManifest;
};

export async function materializeAuthenticationProfileConfig(
  input: MaterializeAuthenticationProfileConfigInput,
): Promise<MaterializeAuthenticationProfileConfigResult> {
  const manifest = loadAuthenticationProfileManifest(input.rawDocument);
  const configDirectory = dirname(input.configPath);
  await mkdir(configDirectory, { recursive: true, mode: 0o700 });

  const temporaryPath = join(
    configDirectory,
    `.config.${process.pid}.${Date.now()}.tmp.json`,
  );
  const serialized = `${JSON.stringify(manifest, null, 2)}\n`;
  await writeFile(temporaryPath, serialized, { mode: 0o600 });
  await chmod(temporaryPath, 0o600);
  await rename(temporaryPath, input.configPath);
  await chmod(input.configPath, 0o600);

  const envLines = [
    ...(input.awsProfile ? [`AWS_PROFILE=${input.awsProfile}`] : []),
    `AWS_REGION=${manifest.region}`,
    `COGNITO_CONFIG_PATH=${input.configPath}`,
  ];
  await writeFile(input.envPath, `${envLines.join("\n")}\n`, { mode: 0o600 });
  await chmod(input.envPath, 0o600);

  return {
    configPath: input.configPath,
    manifest,
  };
}
