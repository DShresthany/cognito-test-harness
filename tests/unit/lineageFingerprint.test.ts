import { describe, expect, it } from "vitest";
import { createLineageFingerprinter } from "../../src/lineageFingerprint.js";

describe("lineage fingerprints", () => {
  it("compares salted hashes for equality and hides the identifier and salt", () => {
    const salt = Buffer.from("lineage-salt-secret");
    const fingerprinter = createLineageFingerprinter(salt);
    const origin = "origin-jti-value";

    const first = fingerprinter.fingerprint(origin);
    const second = fingerprinter.fingerprint(origin);
    const other = fingerprinter.fingerprint("other-jti-value");

    expect(first).toBe(second);
    expect(first).not.toBe(other);
    expect(first).not.toContain(origin);
    expect(first).not.toContain("lineage-salt-secret");
    expect(JSON.stringify(fingerprinter)).not.toContain("lineage-salt-secret");
    expect(JSON.stringify(fingerprinter)).not.toContain(origin);
  });

  it("uses a different in-memory salt for each fingerprinter", () => {
    const identifier = "origin-jti-value";
    const first = createLineageFingerprinter(Buffer.from("salt-a")).fingerprint(
      identifier,
    );
    const second = createLineageFingerprinter(Buffer.from("salt-b")).fingerprint(
      identifier,
    );

    expect(first).not.toBe(second);
  });
});
