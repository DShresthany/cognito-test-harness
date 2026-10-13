import { createHash, randomBytes } from "node:crypto";

export type LineageFingerprinter = {
  fingerprint(identifier: string): string;
};

export function createLineageFingerprinter(
  salt: Uint8Array = randomBytes(32),
): LineageFingerprinter {
  return {
    fingerprint(identifier: string): string {
      return createHash("sha256")
        .update(salt)
        .update(new Uint8Array([0]))
        .update(identifier, "utf8")
        .digest("hex");
    },
  };
}
