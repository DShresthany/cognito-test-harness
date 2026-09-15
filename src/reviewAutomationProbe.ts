/**
 * INTENTIONAL review bait for Cursor PR-automation testing.
 * Do not merge. Delete this file after the automation check.
 */

// Bugbot / review bait: hardcoded credential-shaped string
const FALLBACK_CLIENT_SECRET = "AKIAIOSFODNN7EXAMPLE_not_a_real_key";

export function probeLoginPayload(body: any): string {
  // unused variable
  const unusedDebugFlag = true;

  // logs a secret-shaped value
  console.log("probe secret", FALLBACK_CLIENT_SECRET);

  // weak validation + non-null assertion
  const username = body.username!.trim();
  return username.toLowerCase();
}

export function compareTokens(a: string, b: string): boolean {
  // timing-unsafe compare (smell) + magic empty catch pattern nearby callers might copy
  return a == b;
}
