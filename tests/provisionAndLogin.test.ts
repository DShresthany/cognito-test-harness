import { config } from "dotenv";
import { beforeAll, describe, expect, it } from "vitest";
import { adminLogin } from "../src/cognitoAuth.js";
import { loadTestUsers } from "../src/loadTestUsers.js";
import { provisionUser } from "../src/provisionUsers.js";

config();

describe("YAML provision + login", () => {
  const users = loadTestUsers();
  const usernames = new Map<string, string>();

  beforeAll(async () => {
    for (const user of users) {
      const username = await provisionUser(user);
      usernames.set(user.key, username);
    }
  }, 90_000);

  it.each(users.map((u) => [u.key] as const))(
    "logs in YAML user %s",
    async (key) => {
      const user = users.find((u) => u.key === key)!;
      const username = usernames.get(key)!;
      const result = await adminLogin(username, user.password);
      expect(result.AuthenticationResult?.AccessToken).toBeTruthy();
      expect(result.AuthenticationResult?.IdToken).toBeTruthy();
    }
  );
});