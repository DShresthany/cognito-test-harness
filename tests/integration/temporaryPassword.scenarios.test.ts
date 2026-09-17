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
import { randomPassword } from "../../src/randomPassword.js";
import {
  runInvalidChallengeSessionScenario,
  runPolicyViolatingThenRecoverScenario,
  runTemporaryPasswordChallengeScenario,
  runTemporaryPasswordCompletionScenario,
} from "../../src/temporaryPasswordScenarios.js";

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

describe("NP temporary-password / NEW_PASSWORD_REQUIRED scenarios", () => {
  it("NP-1: temporary-password persona first public auth is new-password-required", async () => {
    const persona = await fixtures.provision(
      { key: "np1", emailPrefix: "harness-np1" },
      { kind: "temporary-password" },
    );

    const evidence = await runTemporaryPasswordChallengeScenario({
      authenticate: (username, password) =>
        publicDriver.authenticatePassword(username, password),
      username: persona.username,
      temporaryPassword: persona.password,
    });

    expect(evidence).toMatchObject({
      outcomeKind: "challenged",
      challengeType: "new-password-required",
    });
    expect(Array.isArray(evidence.requiredAttributes)).toBe(true);
    expect(JSON.stringify(evidence)).not.toContain(persona.password);
  }, 60_000);

  it("NP-2: policy-compliant continuation authenticates; temp rejected; new works", async () => {
    const persona = await fixtures.provision(
      { key: "np2", emailPrefix: "harness-np2" },
      { kind: "temporary-password" },
    );
    const newPassword = randomPassword();

    const evidence = await runTemporaryPasswordCompletionScenario({
      authenticate: (username, password) =>
        publicDriver.authenticatePassword(username, password),
      respondToNewPassword: (challenge) =>
        publicDriver.respondToNewPasswordChallenge(challenge),
      verifiers: publicVerifiers,
      username: persona.username,
      temporaryPassword: persona.password,
      newPassword,
    });

    expect(evidence).toEqual({
      outcomeKind: "authenticated",
      challengeType: "new-password-required",
      accessVerified: true,
      idVerified: true,
      temporaryPasswordRejected: true,
      newPasswordAuthenticates: true,
      refreshTokenIssued: true,
    });
    expect(JSON.stringify(evidence)).not.toContain(newPassword);
    expect(JSON.stringify(evidence)).not.toContain(persona.password);
  }, 90_000);

  it("NP-3: policy-violating password then recover with a fresh session", async () => {
    const persona = await fixtures.provision(
      { key: "np3", emailPrefix: "harness-np3" },
      { kind: "temporary-password" },
    );

    const evidence = await runPolicyViolatingThenRecoverScenario({
      authenticate: (username, password) =>
        publicDriver.authenticatePassword(username, password),
      respondToNewPassword: (challenge) =>
        publicDriver.respondToNewPasswordChallenge(challenge),
      verifiers: publicVerifiers,
      username: persona.username,
      temporaryPassword: persona.password,
      violatingPassword: "short",
      recoveringPassword: randomPassword(),
    });

    expect(evidence).toMatchObject({
      policyViolationReason: "password-policy-violation",
      recovered: true,
      accessVerified: true,
      idVerified: true,
    });
  }, 90_000);

  it("NP-4: invalid or consumed session is invalid-challenge-session without session leakage", async () => {
    const persona = await fixtures.provision(
      { key: "np4", emailPrefix: "harness-np4" },
      { kind: "temporary-password" },
    );
    const first = await publicDriver.authenticatePassword(
      persona.username,
      persona.password,
    );
    expect(first.kind).toBe("challenged");
    if (first.kind !== "challenged") {
      return;
    }
    expect(first.challenge.type).toBe("new-password-required");
    if (first.challenge.type !== "new-password-required") {
      return;
    }

    const session = first.challenge.continuation.session;
    const challengeUsername = first.challenge.continuation.username;
    const newPassword = randomPassword();

    const completed = await publicDriver.respondToNewPasswordChallenge({
      session,
      username: challengeUsername,
      newPassword,
    });
    expect(completed.kind).toBe("authenticated");

    const reused = await runInvalidChallengeSessionScenario({
      respondToNewPassword: (challenge) =>
        publicDriver.respondToNewPasswordChallenge(challenge),
      session,
      username: challengeUsername,
      newPassword: randomPassword(),
    });
    const garbage = await runInvalidChallengeSessionScenario({
      respondToNewPassword: (challenge) =>
        publicDriver.respondToNewPasswordChallenge(challenge),
      session: "not-a-real-challenge-session",
      username: challengeUsername,
      newPassword: randomPassword(),
    });

    expect(reused).toMatchObject({
      outcomeKind: "rejected",
      rejectionReason: "invalid-challenge-session",
    });
    expect(garbage).toMatchObject({
      outcomeKind: "rejected",
      rejectionReason: "invalid-challenge-session",
    });
    expect(JSON.stringify(reused)).not.toContain(session);
    expect(JSON.stringify(garbage)).not.toContain(
      "not-a-real-challenge-session",
    );
  }, 90_000);
});
