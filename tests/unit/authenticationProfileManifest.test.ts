import { describe, expect, it } from "vitest";
import {
  loadAuthenticationProfileManifest,
  ManifestConfigurationFailure,
} from "../../src/authenticationProfileManifest.js";

const v2Document = {
  schemaVersion: 2,
  region: "us-east-1",
  userPoolId: "us-east-1_example",
  profiles: {
    "admin-confidential": {
      kind: "confidential",
      clientId: "confidential-client-id",
      clientSecret: "confidential-client-secret",
    },
    "user-pool-public": {
      kind: "public",
      clientId: "public-client-id",
    },
  },
};

describe("loadAuthenticationProfileManifest", () => {
  it("loads a schema version 2 document with discriminated profiles", () => {
    const manifest = loadAuthenticationProfileManifest(v2Document);

    expect(manifest).toEqual({
      schemaVersion: 2,
      region: "us-east-1",
      userPoolId: "us-east-1_example",
      profiles: {
        "admin-confidential": {
          kind: "confidential",
          clientId: "confidential-client-id",
          clientSecret: "confidential-client-secret",
        },
        "user-pool-public": {
          kind: "public",
          clientId: "public-client-id",
        },
      },
    });
  });

  it("rejects a public profile that includes a client secret without leaking the value", () => {
    const raw = {
      ...v2Document,
      profiles: {
        ...v2Document.profiles,
        "user-pool-public": {
          kind: "public",
          clientId: "public-client-id",
          clientSecret: "must-not-appear",
        },
      },
    };

    expect(() => loadAuthenticationProfileManifest(raw)).toThrow(
      ManifestConfigurationFailure,
    );
    try {
      loadAuthenticationProfileManifest(raw);
    } catch (error) {
      expect(error).toBeInstanceOf(ManifestConfigurationFailure);
      const failure = error as ManifestConfigurationFailure;
      expect(failure.retryable).toBe(false);
      expect(failure.message).toContain("profiles.user-pool-public");
      expect(failure.message).not.toContain("must-not-appear");
    }
  });

  it("rejects a confidential profile missing a client secret", () => {
    const raw = {
      ...v2Document,
      profiles: {
        "admin-confidential": {
          kind: "confidential",
          clientId: "confidential-client-id",
        },
      },
    };

    expect(() => loadAuthenticationProfileManifest(raw)).toThrow(
      ManifestConfigurationFailure,
    );
  });

  it("rejects unsupported schema versions as non-retryable failures", () => {
    expect(() =>
      loadAuthenticationProfileManifest({
        schemaVersion: 99,
        region: "us-east-1",
        userPoolId: "us-east-1_example",
        profiles: {},
      }),
    ).toThrow(/unsupported schemaVersion/);
  });

  it("maps legacy flat fields into a temporary schema version 2 confidential profile", () => {
    const manifest = loadAuthenticationProfileManifest({
      region: "us-east-1",
      userPoolId: "us-east-1_example",
      clientId: "legacy-client-id",
      clientSecret: "legacy-client-secret",
    });

    expect(manifest).toEqual({
      schemaVersion: 2,
      region: "us-east-1",
      userPoolId: "us-east-1_example",
      profiles: {
        "admin-confidential": {
          kind: "confidential",
          clientId: "legacy-client-id",
          clientSecret: "legacy-client-secret",
        },
      },
    });
  });

  it("tolerates unrelated top-level metadata on schema version 2", () => {
    const manifest = loadAuthenticationProfileManifest({
      ...v2Document,
      futureNote: "ignored",
    });

    expect(manifest.schemaVersion).toBe(2);
    expect(manifest.profiles["user-pool-public"]).toEqual({
      kind: "public",
      clientId: "public-client-id",
    });
  });

  it("tolerates unrelated additive metadata on profile records", () => {
    const manifest = loadAuthenticationProfileManifest({
      ...v2Document,
      profiles: {
        ...v2Document.profiles,
        "user-pool-public": {
          kind: "public",
          clientId: "public-client-id",
          futureFlag: true,
        },
      },
    });

    expect(manifest.profiles["user-pool-public"]).toEqual({
      kind: "public",
      clientId: "public-client-id",
    });
  });
});
