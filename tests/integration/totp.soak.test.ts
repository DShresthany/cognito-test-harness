import { config } from "dotenv";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createCognitoClient } from "../../src/cognitoAuth.js";
import {
  createAwsCapabilityDescriber,
  resolveCognitoConfigPath,
} from "../../src/cognitoConfigPaths.js";
import { createCognitoTestRuntime } from "../../src/cognitoTestRuntime.js";
import {
  CognitoUserFixtureManager,
  createCognitoFixtureCommands,
} from "../../src/cognitoUserFixtureManager.js";
import {
  CognitoUserPoolAuthDriver,
  type PublicUserPoolAuthProfile,
} from "../../src/cognitoUserPoolAuthDriver.js";
import { createProfileTokenVerifiers } from "../../src/jwtVerifier.js";
import {
  runTotpEnrollmentScenario,
  runTotpReusedCodeScenario,
  runTotpWrongEnrollmentScenario,
  runTotpWrongSignInScenario,
} from "../../src/totpScenarios.js";

config();

let client: ReturnType<typeof createCognitoClient>;
let publicProfile: PublicUserPoolAuthProfile;
let publicDriver: CognitoUserPoolAuthDriver;
let fixtures: CognitoUserFixtureManager;
let publicVerifiers: ReturnType<typeof createProfileTokenVerifiers>;

beforeAll(async () => {
  client = createCognitoClient();
  const runtime = await createCognitoTestRuntime({
    configPath: resolveCognitoConfigPath(),
    ...createAwsCapabilityDescriber(client),
  });
  const publicRecord = runtime.requirePublicProfile("user-pool-public");
  publicProfile = {
    id: publicRecord.id,
    userPoolId: publicRecord.userPoolId,
    clientId: publicRecord.clientId,
  };
  publicDriver = new CognitoUserPoolAuthDriver(client, publicProfile);
  fixtures = new CognitoUserFixtureManager(
    createCognitoFixtureCommands(client, publicProfile.userPoolId),
  );
  publicVerifiers = createProfileTokenVerifiers({
    userPoolId: publicProfile.userPoolId,
    clientId: publicProfile.clientId,
  });
}, 90_000);

afterAll(async () => {
  await fixtures?.cleanup();
}, 90_000);

describe("TP deterministic TOTP soak (public profile)", () => {
  it("TP-1: enroll + prefer MFA, then software-token-mfa continuation authenticates", async () => {
    const persona = await fixtures.provision(
      { key: "tp1", emailPrefix: "harness-tp1" },
      { kind: "permanent-password" },
    );

    const evidence = await runTotpEnrollmentScenario({
      authenticate: (username, password) =>
        publicDriver.authenticatePassword(username, password),
      associateSoftwareToken: (accessToken) =>
        publicDriver.associateSoftwareToken(accessToken),
      verifySoftwareToken: (input) => publicDriver.verifySoftwareToken(input),
      setSoftwareTokenMfaPreferred: (accessToken) =>
        publicDriver.setSoftwareTokenMfaPreferred(accessToken),
      respondToSoftwareTokenMfa: (input) =>
        publicDriver.respondToSoftwareTokenMfa(input),
      verifiers: publicVerifiers,
      username: persona.username,
      password: persona.password,
    });

    expect(evidence).toEqual({
      enrollmentVerified: true,
      preferredMfaSet: true,
      challengeType: "software-token-mfa",
      mfaAuthenticated: true,
      accessVerified: true,
      idVerified: true,
    });
    expect(JSON.stringify(evidence)).not.toContain(persona.password);
  }, 120_000);

  it("TP-2: incorrect enrollment code is invalid-code without leaking secrets", async () => {
    const persona = await fixtures.provision(
      { key: "tp2", emailPrefix: "harness-tp2" },
      { kind: "permanent-password" },
    );

    const evidence = await runTotpWrongEnrollmentScenario({
      authenticate: (username, password) =>
        publicDriver.authenticatePassword(username, password),
      associateSoftwareToken: (accessToken) =>
        publicDriver.associateSoftwareToken(accessToken),
      verifySoftwareToken: (input) => publicDriver.verifySoftwareToken(input),
      username: persona.username,
      password: persona.password,
    });

    expect(evidence).toMatchObject({
      outcomeKind: "rejected",
      rejectionReason: "invalid-code",
    });
    expect(JSON.stringify(evidence)).not.toContain(persona.password);
  }, 120_000);

  it("TP-3: incorrect sign-in TOTP is invalid-code; fresh session recovers", async () => {
    const persona = await fixtures.provision(
      { key: "tp3", emailPrefix: "harness-tp3" },
      { kind: "permanent-password" },
    );

    const evidence = await runTotpWrongSignInScenario({
      authenticate: (username, password) =>
        publicDriver.authenticatePassword(username, password),
      associateSoftwareToken: (accessToken) =>
        publicDriver.associateSoftwareToken(accessToken),
      verifySoftwareToken: (input) => publicDriver.verifySoftwareToken(input),
      setSoftwareTokenMfaPreferred: (accessToken) =>
        publicDriver.setSoftwareTokenMfaPreferred(accessToken),
      respondToSoftwareTokenMfa: (input) =>
        publicDriver.respondToSoftwareTokenMfa(input),
      verifiers: publicVerifiers,
      username: persona.username,
      password: persona.password,
    });

    expect(evidence).toMatchObject({
      wrongCodeRejected: true,
      wrongCodeReason: "invalid-code",
      recovered: true,
      accessVerified: true,
      idVerified: true,
    });
  }, 180_000);

  it("reused sign-in TOTP is rejected as expired-code or invalid-code", async () => {
    const persona = await fixtures.provision(
      { key: "tp-reuse", emailPrefix: "harness-tp-reuse" },
      { kind: "permanent-password" },
    );

    const evidence = await runTotpReusedCodeScenario({
      authenticate: (username, password) =>
        publicDriver.authenticatePassword(username, password),
      associateSoftwareToken: (accessToken) =>
        publicDriver.associateSoftwareToken(accessToken),
      verifySoftwareToken: (input) => publicDriver.verifySoftwareToken(input),
      setSoftwareTokenMfaPreferred: (accessToken) =>
        publicDriver.setSoftwareTokenMfaPreferred(accessToken),
      respondToSoftwareTokenMfa: (input) =>
        publicDriver.respondToSoftwareTokenMfa(input),
      username: persona.username,
      password: persona.password,
    });

    expect(evidence.reuseRejected).toBe(true);
    expect(["expired-code", "invalid-code"]).toContain(evidence.rejectionReason);
    expect(JSON.stringify(evidence)).not.toContain(persona.password);
  }, 180_000);
});
