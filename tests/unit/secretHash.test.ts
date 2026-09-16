import { describe, expect, it } from "vitest";
import { getSecretHash } from "../../src/secretHash.js";

describe("getSecretHash", () => {
  // Frozen Cognito-style vector: Base64(HMAC-SHA256(secret, username + clientId)).
  // Computed once offline; do not re-derive expected with the same algorithm in-test.
  const username = "alice@example.com";
  const clientId = "1example23456789";
  const clientSecret = "test-client-secret-value";
  const knownHash = "t4HVCDtAiOpQ2KZ5rH6SH7Ap1y1WS66FZGCVvIq2cdg=";

  it("matches the known HMAC-SHA256 Base64 vector for username + clientId", () => {
    expect(getSecretHash(username, clientId, clientSecret)).toBe(knownHash);
  });

  it("does not match when message order is clientId + username", () => {
    const wrongOrder = getSecretHash(clientId, username, clientSecret);
    expect(wrongOrder).not.toBe(knownHash);
    expect(wrongOrder).toBe("/Fcqk2YZJf65ieLsHID65rgnFTIbxmqebLGLJIQftMU=");
  });
});
