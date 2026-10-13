import type { CognitoIdentityProviderClient } from "@aws-sdk/client-cognito-identity-provider";
import { config } from "dotenv";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { TOKEN_LIFECYCLE_SOAK_PROFILE_IDS } from "../../src/authenticationProfileExpectations.js";
import { REFRESH_ROTATING_PUBLIC_PROFILE_ID } from "../../src/authenticationProfileManifest.js";
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
import type { PublicUserPoolAuthProfile } from "../../src/cognitoUserPoolAuthDriver.js";
import {
  createProfileTokenVerifiers,
  type ProfileTokenVerifiers,
} from "../../src/jwtVerifier.js";
import {
  createLineageFingerprinter,
  type LineageFingerprinter,
} from "../../src/lineageFingerprint.js";
import { runPublicZeroGraceRotationScenario } from "../../src/publicZeroGraceRotationScenario.js";

config();

let client: CognitoIdentityProviderClient;
let profile: PublicUserPoolAuthProfile;
let fixtures: CognitoUserFixtureManager;
let verifiers: ProfileTokenVerifiers;
let fingerprinter: LineageFingerprinter;

beforeAll(async () => {
  client = createCognitoClient();
  const runtime = await createCognitoTestRuntime({
    configPath: resolveCognitoConfigPath(),
    requiredProfileIds: TOKEN_LIFECYCLE_SOAK_PROFILE_IDS,
    ...createAwsCapabilityDescriber(client),
  });
  const record = runtime.requirePublicProfile(REFRESH_ROTATING_PUBLIC_PROFILE_ID);
  profile = {
    id: record.id,
    userPoolId: record.userPoolId,
    clientId: record.clientId,
  };
  fixtures = new CognitoUserFixtureManager(
    createCognitoFixtureCommands(client, record.userPoolId),
  );
  verifiers = createProfileTokenVerifiers({
    userPoolId: record.userPoolId,
    clientId: record.clientId,
  });
  fingerprinter = createLineageFingerprinter();
}, 90_000);

afterAll(async () => {
  await fixtures?.cleanup();
}, 90_000);

describe("public zero-grace rotation soak", () => {
  it("rotates refresh-rotating-public and rejects the consumed refresh token", async () => {
    const persona = await fixtures.provision(
      { key: "rot1", emailPrefix: "harness-rot1" },
      { kind: "permanent-password" },
    );

    const evidence = await runPublicZeroGraceRotationScenario({
      sender: client,
      profile,
      verifiers,
      username: persona.username,
      password: persona.password,
      fingerprinter,
      deletePersona: () => fixtures.cleanup(),
    });

    expect(evidence).toMatchObject({
      initialOutcomeKind: "authenticated",
      initialRefreshPresent: true,
      rotationOutcomeKind: "authenticated",
      replacementRefreshPresent: true,
      reuseOutcomeKind: "rejected",
      reuseRejectionReason: "invalid-refresh-token",
      accessVerified: true,
      idVerified: true,
      subjectMatches: true,
      originJtiFingerprintStable: true,
      jtiFingerprintsUnique: true,
    });
    expect(evidence.generations.map((generation) => generation.label)).toEqual([
      "initial",
      "rotated",
    ]);
    const origins = evidence.generations.flatMap((generation) => [
      generation.accessOriginJtiFingerprint,
      generation.idOriginJtiFingerprint,
    ]);
    expect(origins.every((fingerprint) => fingerprint && fingerprint === origins[0])).toBe(
      true,
    );
    const jtis = evidence.generations.flatMap((generation) => [
      generation.accessJtiFingerprint,
      generation.idJtiFingerprint,
    ]);
    expect(new Set(jtis).size).toBe(jtis.length);
    const serialized = JSON.stringify(evidence);
    expect(serialized).not.toContain(persona.password);
    expect(serialized).not.toContain(persona.username);
    expect(serialized).not.toContain(profile.clientId);
  }, 60_000);
});
