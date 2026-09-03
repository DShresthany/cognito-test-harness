import { config } from "dotenv";
import { describe, expect, it } from "vitest";
import { adminLogin } from "../src/cognitoAuth.js";

config();

describe("adminLogin", () => {
  it("returns tokens for a valid user", async () => {
    const username = process.env.COGNITO_TEST_USERNAME!;
    const password = process.env.COGNITO_TEST_PASSWORD!;
    const result = await adminLogin(username, password);
    expect(result.AuthenticationResult?.AccessToken).toBeTruthy();
    expect(result.AuthenticationResult?.IdToken).toBeTruthy();
  });

  it("rejects an incorrect password", async () => {
    const username = process.env.COGNITO_TEST_USERNAME!;
    await expect(adminLogin(username, "WrongPassword123!")).rejects.toMatchObject({
      name: "NotAuthorizedException",
    });
  });
});