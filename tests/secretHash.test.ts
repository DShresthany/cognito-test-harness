import { describe, expect, it } from "vitest";
import { createHmac } from "node:crypto";
import { getSecretHash } from "../src/secretHash.js";

describe("getSecretHash", () => {
  it("matches Node HMAC-SHA256 Base64 for username + clientId", () => {
    const username = "user-uuid";
    const clientId = "client-id";
    const clientSecret = "client-secret";
    const expected = createHmac("sha256", clientSecret)
      .update(username + clientId)
      .digest("base64");
    expect(getSecretHash(username, clientId, clientSecret)).toBe(expected);
  });
});