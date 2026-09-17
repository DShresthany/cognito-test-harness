import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { materializeAuthenticationProfileConfig } from "../../src/materializeAuthenticationProfileConfig.js";

const v2Document = {
  schemaVersion: 2,
  region: "us-east-1",
  userPoolId: "us-east-1_example",
  profiles: {
    "admin-confidential": {
      kind: "confidential",
      clientId: "confidential-client-id",
      clientSecret: "confidential-client-secret",
    },
    "user-pool-public": {
      kind: "public",
      clientId: "public-client-id",
    },
  },
};

describe("materializeAuthenticationProfileConfig", () => {
  it("writes an owner-only config file and bootstrap env without client secrets", async () => {
    const root = await mkdtemp(join(tmpdir(), "cognito-materialize-"));
    const configPath = join(root, ".cognito", "config.json");
    const envPath = join(root, ".env");

    try {
      const result = await materializeAuthenticationProfileConfig({
        rawDocument: v2Document,
        configPath,
        envPath,
        awsProfile: "cognito-dev",
      });

      expect(result.configPath).toBe(configPath);
      const written = JSON.parse(await readFile(configPath, "utf8"));
      expect(written.profiles["admin-confidential"].clientSecret).toBe(
        "confidential-client-secret",
      );

      const envText = await readFile(envPath, "utf8");
      expect(envText).toContain("AWS_PROFILE=cognito-dev");
      expect(envText).toContain("AWS_REGION=us-east-1");
      expect(envText).toContain(`COGNITO_CONFIG_PATH=${configPath}`);
      expect(envText).not.toContain("COGNITO_CLIENT_SECRET");
      expect(envText).not.toContain("confidential-client-secret");
      expect(envText).not.toContain("COGNITO_USER_POOL_ID");
      expect(envText).not.toContain("COGNITO_CLIENT_ID");
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it("rejects invalid documents before replacing an existing config file", async () => {
    const root = await mkdtemp(join(tmpdir(), "cognito-materialize-"));
    const configPath = join(root, ".cognito", "config.json");
    const envPath = join(root, ".env");

    try {
      await materializeAuthenticationProfileConfig({
        rawDocument: v2Document,
        configPath,
        envPath,
      });
      const before = await readFile(configPath, "utf8");

      await expect(
        materializeAuthenticationProfileConfig({
          rawDocument: { schemaVersion: 99 },
          configPath,
          envPath,
        }),
      ).rejects.toThrow(/unsupported schemaVersion/);

      expect(await readFile(configPath, "utf8")).toBe(before);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
