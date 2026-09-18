import { z } from "zod";

export const ADMIN_CONFIDENTIAL_PROFILE_ID = "admin-confidential" as const;
export const USER_POOL_PUBLIC_PROFILE_ID = "user-pool-public" as const;

export type AuthenticationProfileId =
  | typeof ADMIN_CONFIDENTIAL_PROFILE_ID
  | typeof USER_POOL_PUBLIC_PROFILE_ID;

export type ConfidentialProfileRecord = {
  kind: "confidential";
  clientId: string;
  clientSecret: string;
};

export type PublicProfileRecord = {
  kind: "public";
  clientId: string;
};

export type AuthenticationProfileRecord =
  | ConfidentialProfileRecord
  | PublicProfileRecord;

export type AuthenticationProfileManifest = {
  schemaVersion: 2;
  region: string;
  userPoolId: string;
  profiles: Record<string, AuthenticationProfileRecord>;
};

export class ManifestConfigurationFailure extends Error {
  readonly name = "ManifestConfigurationFailure";
  readonly retryable = false;

  constructor(message: string) {
    super(message);
  }
}

const confidentialProfileSchema = z
  .object({
    kind: z.literal("confidential"),
    clientId: z.string().min(1),
    clientSecret: z.string().min(1),
  })
  .passthrough();

const publicProfileSchema = z
  .object({
    kind: z.literal("public"),
    clientId: z.string().min(1),
  })
  .passthrough()
  .superRefine((value, context) => {
    if ("clientSecret" in value) {
      context.addIssue({
        code: "custom",
        path: ["clientSecret"],
        message: "public profile must not include clientSecret",
      });
    }
  });

const profileRecordSchema = z.discriminatedUnion("kind", [
  confidentialProfileSchema,
  publicProfileSchema,
]);

const schemaVersion2Schema = z
  .object({
    schemaVersion: z.literal(2),
    region: z.string().min(1),
    userPoolId: z.string().min(1),
    profiles: z.record(z.string(), profileRecordSchema),
  })
  .passthrough();

export function loadAuthenticationProfileManifest(
  raw: unknown,
): AuthenticationProfileManifest {
  if (raw === null || typeof raw !== "object") {
    throw new ManifestConfigurationFailure(
      "authentication profile manifest: document must be an object",
    );
  }

  const document = raw as Record<string, unknown>;
  if (!("schemaVersion" in document)) {
    throw new ManifestConfigurationFailure(
      "authentication profile manifest: schemaVersion 2 is required (legacy flat secrets are no longer accepted)",
    );
  }

  return parseSchemaVersion2(document);
}

function parseSchemaVersion2(
  document: Record<string, unknown>,
): AuthenticationProfileManifest {
  const version = document.schemaVersion;
  if (version !== 2) {
    throw new ManifestConfigurationFailure(
      `authentication profile manifest: unsupported schemaVersion at schemaVersion`,
    );
  }

  const parsed = schemaVersion2Schema.safeParse(document);
  if (!parsed.success) {
    throw toConfigurationFailure(parsed.error);
  }

  const profiles: Record<string, AuthenticationProfileRecord> = {};
  for (const [profileId, profile] of Object.entries(parsed.data.profiles)) {
    switch (profile.kind) {
      case "confidential":
        profiles[profileId] = {
          kind: "confidential",
          clientId: profile.clientId,
          clientSecret: profile.clientSecret,
        };
        break;
      case "public":
        profiles[profileId] = {
          kind: "public",
          clientId: profile.clientId,
        };
        break;
      default: {
        const _exhaustive: never = profile;
        throw new ManifestConfigurationFailure(
          `authentication profile manifest: unsupported profile kind at profiles.${profileId}`,
        );
        void _exhaustive;
      }
    }
  }

  return {
    schemaVersion: 2,
    region: parsed.data.region,
    userPoolId: parsed.data.userPoolId,
    profiles,
  };
}

function toConfigurationFailure(
  error: z.ZodError,
): ManifestConfigurationFailure {
  const path =
    error.issues[0]?.path.join(".") || "authentication profile manifest";
  return new ManifestConfigurationFailure(
    `authentication profile manifest: invalid configuration at ${path}`,
  );
}
