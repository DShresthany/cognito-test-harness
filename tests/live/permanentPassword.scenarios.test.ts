import { config } from "dotenv";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { requireAuthenticated } from "../../src/authenticationOutcome.js";
import {
  CognitoAdminAuthDriver,
  type ConfidentialAdminAuthProfile,
} from "../../src/cognitoAdminAuthDriver.js";
import { createCognitoClient } from "../../src/cognitoAuth.js";
import {
  attemptLoginWithInvalidSecretHash,
  attemptLoginWithMissingSecretHash,
} from "../../src/cognitoConfidentialClientProbe.js";
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
  runRejectedPasswordScenario,
  runTokenVerificationScenario,
  runValidPermanentPasswordScenario,
} from "../../src/permanentPasswordScenarios.js";

config();

let client: ReturnType<typeof createCognitoClient>;
let confidential: ConfidentialAdminAuthProfile;
let publicProfile: PublicUserPoolAuthProfile;
let adminDriver: CognitoAdminAuthDriver;
let publicDriver: CognitoUserPoolAuthDriver;
let fixtures: CognitoUserFixtureManager;
let adminVerifiers: ReturnType<typeof createProfileTokenVerifiers>;
let publicVerifiers: ReturnType<typeof createProfileTokenVerifiers>;

beforeAll(async () => {
  client = createCognitoClient();
  const runtime = await createCognitoTestRuntime({
    configPath: resolveCognitoConfigPath(),
    ...createAwsCapabilityDescriber(client),
  });
  const confidentialRecord = runtime.requireConfidentialProfile(
    "admin-confidential",
  );
  const publicRecord = runtime.requirePublicProfile("user-pool-public");
  confidential = {
    id: confidentialRecord.id,
    userPoolId: confidentialRecord.userPoolId,
    clientId: confidentialRecord.clientId,
    clientSecret: confidentialRecord.clientSecret,
  };
  publicProfile = {
    id: publicRecord.id,
    userPoolId: publicRecord.userPoolId,
    clientId: publicRecord.clientId,
  };
  adminDriver = new CognitoAdminAuthDriver(client, confidential);
  publicDriver = new CognitoUserPoolAuthDriver(client, publicProfile);
  fixtures = new CognitoUserFixtureManager(
    createCognitoFixtureCommands(client, confidential.userPoolId),
  );
  adminVerifiers = createProfileTokenVerifiers({
    userPoolId: confidential.userPoolId,
    clientId: confidential.clientId,
  });
  publicVerifiers = createProfileTokenVerifiers({
    userPoolId: publicProfile.userPoolId,
    clientId: publicProfile.clientId,
  });
}, 90_000);

afterAll(async () => {
  await fixtures?.cleanup();
}, 90_000);

describe("PA permanent password scenarios", () => {
  it("PA-1: admin confidential valid credentials authenticate and verify", async () => {
    const persona = await fixtures.provision(
      { key: "pa1", emailPrefix: "harness-pa1" },
      { kind: "permanent-password" },
    );

    const evidence = await runValidPermanentPasswordScenario({
      authenticate: (username, password) =>
        adminDriver.authenticatePassword(username, password),
      verifiers: adminVerifiers,
      username: persona.username,
      password: persona.password,
    });

    expect(evidence).toEqual({
      outcomeKind: "authenticated",
      refreshTokenIssued: true,
      accessVerified: true,
      idVerified: true,
    });
  }, 60_000);

  it("PA-2: public valid credentials authenticate and verify", async () => {
    const persona = await fixtures.provision(
      { key: "pa2", emailPrefix: "harness-pa2" },
      { kind: "permanent-password" },
    );

    const evidence = await runValidPermanentPasswordScenario({
      authenticate: (username, password) =>
        publicDriver.authenticatePassword(username, password),
      verifiers: publicVerifiers,
      username: persona.username,
      password: persona.password,
    });

    expect(evidence).toEqual({
      outcomeKind: "authenticated",
      refreshTokenIssued: true,
      accessVerified: true,
      idVerified: true,
    });
  }, 60_000);

  it("PA-3: wrong password is invalid-credentials on both surfaces", async () => {
    const persona = await fixtures.provision(
      { key: "pa3", emailPrefix: "harness-pa3" },
      { kind: "permanent-password" },
    );

    const adminEvidence = await runRejectedPasswordScenario({
      authenticate: (username, password) =>
        adminDriver.authenticatePassword(username, password),
      username: persona.username,
      password: `${persona.password}-wrong`,
    });
    const publicEvidence = await runRejectedPasswordScenario({
      authenticate: (username, password) =>
        publicDriver.authenticatePassword(username, password),
      username: persona.username,
      password: `${persona.password}-wrong`,
    });

    expect(adminEvidence).toMatchObject({
      outcomeKind: "rejected",
      rejectionReason: "invalid-credentials",
      refreshTokenIssued: false,
    });
    expect(publicEvidence).toMatchObject({
      outcomeKind: "rejected",
      rejectionReason: "invalid-credentials",
      refreshTokenIssued: false,
    });
  }, 60_000);

  it("PA-4: public nonexistent username matches wrong-password privacy", async () => {
    const persona = await fixtures.provision(
      { key: "pa4", emailPrefix: "harness-pa4" },
      { kind: "permanent-password" },
    );
    const publicWrongPassword = await runRejectedPasswordScenario({
      authenticate: (username, password) =>
        publicDriver.authenticatePassword(username, password),
      username: persona.username,
      password: `${persona.password}-wrong`,
    });
    const publicMissing = await runRejectedPasswordScenario({
      authenticate: (username, password) =>
        publicDriver.authenticatePassword(username, password),
      username: `missing+${fixtures.runId}@example.com`,
      password: "Password1!",
    });
    const adminMissing = await runRejectedPasswordScenario({
      authenticate: (username, password) =>
        adminDriver.authenticatePassword(username, password),
      username: `missing+${fixtures.runId}@example.com`,
      password: "Password1!",
    });

    expect(publicMissing.rejectionReason).toBe("invalid-credentials");
    expect(publicWrongPassword.rejectionReason).toBe("invalid-credentials");
    expect(publicMissing.outcomeKind).toBe(publicWrongPassword.outcomeKind);
    expect(publicMissing.refreshTokenIssued).toBe(false);
    expect(adminMissing.rejectionReason).toBe("invalid-credentials");
  }, 60_000);

  it("PA-5: missing or incorrect confidential proof is invalid-credentials", async () => {
    const persona = await fixtures.provision(
      { key: "pa5", emailPrefix: "harness-pa5" },
      { kind: "permanent-password" },
    );
    const credentials = {
      username: persona.username,
      password: persona.password,
    };

    const invalidProof = await runRejectedPasswordScenario({
      authenticate: async () =>
        attemptLoginWithInvalidSecretHash(client, confidential, credentials),
      username: persona.username,
      password: persona.password,
    });
    const missingProof = await runRejectedPasswordScenario({
      authenticate: async () =>
        attemptLoginWithMissingSecretHash(client, confidential, credentials),
      username: persona.username,
      password: persona.password,
    });

    expect(invalidProof).toMatchObject({
      outcomeKind: "rejected",
      rejectionReason: "invalid-credentials",
      refreshTokenIssued: false,
    });
    expect(missingProof).toMatchObject({
      outcomeKind: "rejected",
      rejectionReason: "invalid-credentials",
      refreshTokenIssued: false,
    });
    expect(invalidProof.providerCode).toBeTruthy();
    expect(JSON.stringify(invalidProof)).not.toContain(confidential.clientSecret);
    expect(JSON.stringify(missingProof)).not.toContain(confidential.clientSecret);
  }, 60_000);
});

describe("TV profile JWT checks", () => {
  it("TV-1..TV-4: admin and public profile binding, token_use, and tamper checks", async () => {
    const adminPersona = await fixtures.provision(
      { key: "tv-admin", emailPrefix: "harness-tv-admin" },
      { kind: "permanent-password" },
    );
    const publicPersona = await fixtures.provision(
      { key: "tv-public", emailPrefix: "harness-tv-public" },
      { kind: "permanent-password" },
    );
    const adminTokens = requireAuthenticated(
      await adminDriver.authenticatePassword(
        adminPersona.username,
        adminPersona.password,
      ),
    );
    const publicTokens = requireAuthenticated(
      await publicDriver.authenticatePassword(
        publicPersona.username,
        publicPersona.password,
      ),
    );

    const adminEvidence = await runTokenVerificationScenario({
      tokens: adminTokens,
      issuing: adminVerifiers,
      otherProfile: publicVerifiers,
    });
    const publicEvidence = await runTokenVerificationScenario({
      tokens: publicTokens,
      issuing: publicVerifiers,
      otherProfile: adminVerifiers,
    });

    const expected = {
      accessVerifiesOnAccess: true,
      idVerifiesOnId: true,
      accessRejectedAsId: true,
      idRejectedAsAccess: true,
      tamperedAccessRejected: true,
      tamperedIdRejected: true,
      crossProfileAccessRejected: true,
      crossProfileIdRejected: true,
    };
    expect(adminEvidence).toEqual(expected);
    expect(publicEvidence).toEqual(expected);
    expect(JSON.stringify(adminEvidence)).not.toContain(adminTokens.accessToken);
    expect(JSON.stringify(publicEvidence)).not.toContain(publicTokens.idToken);
  }, 90_000);
});
