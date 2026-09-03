import { describe, expect, it } from "vitest";
import { randomPassword } from "../src/randomPassword.js";

describe("randomPassword", () => {
  it("meets Cognito complexity rules", () => {
    const password = randomPassword();
    expect(password.length).toBeGreaterThanOrEqual(8);
    expect(password).toMatch(/[a-z]/);
    expect(password).toMatch(/[A-Z]/);
    expect(password).toMatch(/[0-9]/);
    expect(password).toMatch(/[!@#$%^&*()\-_=+]/);
  });
});
