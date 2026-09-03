import { config } from "dotenv";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { CognitoLoginManager } from "../src/cognitoLoginManager.js";
import { loadTestUsers } from "../src/loadTestUsers.js";

config();

describe("YAML provision + login", () => {
  const users = loadTestUsers();
  const manager = CognitoLoginManager.fromEnv();

  beforeAll(async () => {
    await manager.setupUsers(users);
  }, 90_000);

  afterAll(async () => {
    await manager.cleanup();
  }, 90_000);

  it.each(users.map((user) => [user.key] as const))(
    "logs in YAML user %s",
    (key) => {
      const auth = manager.getAuthResult(key);
      expect(auth.email).toContain(manager.runId);
      expect(auth.username).toBeTruthy();
      expect(auth.accessToken).toBeTruthy();
      expect(auth.idToken).toBeTruthy();
    }
  );
});
