import { config } from "dotenv";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { requireAuthenticated } from "../../src/authenticationOutcome.js";
import {
  CognitoAdminAuthDriver,
  type ConfidentialAdminAuthProfile,
} from "../../src/cognitoAdminAuthDriver.js";
import { createCognitoClient } from "../../src/cognitoAuth.js";
import {
  attemptRefreshWithInvalidSecretHash,
  attemptRefreshWithMissingSecretHash,
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
  runRejectedRefreshScenario,
  runValidRefreshScenario,
} from "../../src/refreshScenarios.js";

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

describe("RF non-rotating refresh scenarios", () => {
  it("RF-1: confidential refresh returns verifying tokens without replacement refresh", async () => {
    const persona = await fixtures.provision(
      { key: "rf1", emailPrefix: "harness-rf1" },
      { kind: "permanent-password" },
    );

    const evidence = await runValidRefreshScenario({
      authenticate: (username, password) =>
        adminDriver.authenticatePassword(username, password),
      refresh: (refreshToken) =>
        adminDriver.refresh(persona.username, refreshToken),
      verifiers: adminVerifiers,
      username: persona.username,
      password: persona.password,
    });

    expect(evidence).toEqual({
      outcomeKind: "authenticated",
      accessVerified: true,
      idVerified: true,
      subjectMatches: true,
      tokensRenewed: true,
      refreshTokenReplaced: false,
    });
  }, 60_000);

  it("RF-2: public refresh returns verifying tokens without replacement refresh", async () => {
    const persona = await fixtures.provision(
      { key: "rf2", emailPrefix: "harness-rf2" },
      { kind: "permanent-password" },
    );

    const evidence = await runValidRefreshScenario({
      authenticate: (username, password) =>
        publicDriver.authenticatePassword(username, password),
      refresh: (refreshToken) => publicDriver.refresh(refreshToken),
      verifiers: publicVerifiers,
      username: persona.username,
      password: persona.password,
    });

    expect(evidence).toEqual({
      outcomeKind: "authenticated",
      accessVerified: true,
      idVerified: true,
      subjectMatches: true,
      tokensRenewed: true,
      refreshTokenReplaced: false,
    });
  }, 60_000);

  it("RF-3: malformed refresh token is invalid-refresh-token", async () => {
    const adminEvidence = await runRejectedRefreshScenario({
      refresh: (token) => adminDriver.refresh("anyone@example.com", token),
      refreshToken: "not-a-real-refresh-token",
    });
    const publicEvidence = await runRejectedRefreshScenario({
      refresh: (token) => publicDriver.refresh(token),
      refreshToken: "not-a-real-refresh-token",
    });

    expect(adminEvidence).toMatchObject({
      outcomeKind: "rejected",
      rejectionReason: "invalid-refresh-token",
      refreshTokenReplaced: null,
    });
    expect(publicEvidence).toMatchObject({
      outcomeKind: "rejected",
      rejectionReason: "invalid-refresh-token",
      refreshTokenReplaced: null,
    });
    expect(JSON.stringify(adminEvidence)).not.toContain(
      "not-a-real-refresh-token",
    );
  }, 60_000);

  it("RF-4: refresh presented to the wrong client is invalid-refresh-token", async () => {
    const persona = await fixtures.provision(
      { key: "rf4", emailPrefix: "harness-rf4" },
      { kind: "permanent-password" },
    );
    const tokens = requireAuthenticated(
      await adminDriver.authenticatePassword(persona.username, persona.password),
    );
    expect(tokens.refreshToken).toBeTruthy();

    const evidence = await runRejectedRefreshScenario({
      refresh: (token) => publicDriver.refresh(token),
      refreshToken: tokens.refreshToken!,
    });

    expect(evidence).toMatchObject({
      outcomeKind: "rejected",
      rejectionReason: "invalid-refresh-token",
    });
    expect(JSON.stringify(evidence)).not.toContain(tokens.refreshToken);
  }, 60_000);

  it("RF-5: missing or incorrect confidential refresh proof is invalid-refresh-token", async () => {
    const persona = await fixtures.provision(
      { key: "rf5", emailPrefix: "harness-rf5" },
      { kind: "permanent-password" },
    );
    const tokens = requireAuthenticated(
      await adminDriver.authenticatePassword(persona.username, persona.password),
    );
    expect(tokens.refreshToken).toBeTruthy();
    const credentials = {
      username: persona.username,
      refreshToken: tokens.refreshToken!,
    };

    const invalidProof = await runRejectedRefreshScenario({
      refresh: async () =>
        attemptRefreshWithInvalidSecretHash(client, confidential, credentials),
      refreshToken: credentials.refreshToken,
    });
    const missingProof = await runRejectedRefreshScenario({
      refresh: async () =>
        attemptRefreshWithMissingSecretHash(client, confidential, credentials),
      refreshToken: credentials.refreshToken,
    });

    expect(invalidProof).toMatchObject({
      outcomeKind: "rejected",
      rejectionReason: "invalid-refresh-token",
    });
    expect(missingProof).toMatchObject({
      outcomeKind: "rejected",
      rejectionReason: "invalid-refresh-token",
    });
    expect(invalidProof.providerCode).toBeTruthy();
    expect(JSON.stringify(invalidProof)).not.toContain(confidential.clientSecret);
    expect(JSON.stringify(missingProof)).not.toContain(confidential.clientSecret);
    expect(JSON.stringify(invalidProof)).not.toContain(credentials.refreshToken);
    expect(JSON.stringify(missingProof)).not.toContain(credentials.refreshToken);
  }, 60_000);
});
