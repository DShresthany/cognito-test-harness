import { config } from "dotenv";
import { describe, expect, it } from "vitest";
import { CognitoLoginManager } from "../src/cognitoLoginManager.js";

config();

describe("CognitoLoginManager.loginUser (seed user)", () => {
  const manager = CognitoLoginManager.fromEnv();

  it("returns tokens for a valid user", async () => {
    const username = process.env.COGNITO_TEST_USERNAME!;
    const password = process.env.COGNITO_TEST_PASSWORD!;
    const email = process.env.COGNITO_TEST_EMAIL ?? username;

    const result = await manager.loginUser(username, password, {
      key: "seed",
      email,
    });

    expect(result.accessToken).toBeTruthy();
    expect(result.idToken).toBeTruthy();
  });

  it("rejects an incorrect password", async () => {
    const username = process.env.COGNITO_TEST_USERNAME!;
    const email = process.env.COGNITO_TEST_EMAIL ?? username;

    await expect(
      manager.loginUser(username, "WrongPassword123!", {
        key: "seed",
        email,
      })
    ).rejects.toMatchObject({
      name: "NotAuthorizedException",
    });
  });
});
