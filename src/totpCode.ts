import * as OTPAuth from "otpauth";

export const TOTP_PERIOD_SECONDS = 30;
export const TOTP_DIGITS = 6;
export const TOTP_ALGORITHM = "SHA1";
/** Wait for next step if fewer than this many ms remain in the current window. */
export const TOTP_MIN_REMAINDER_MS = 5_000;

export type TotpClock = {
  now(): number;
  sleep(ms: number): Promise<void>;
};

const defaultClock: TotpClock = {
  now: () => Date.now(),
  sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
};

export function createSoftwareTotp(secretBase32: string): OTPAuth.TOTP {
  return new OTPAuth.TOTP({
    issuer: "cognito-test-harness",
    label: "soak",
    algorithm: TOTP_ALGORITHM,
    digits: TOTP_DIGITS,
    period: TOTP_PERIOD_SECONDS,
    secret: OTPAuth.Secret.fromBase32(secretBase32),
  });
}

export function generateTotpCode(
  secretBase32: string,
  clock: TotpClock = defaultClock,
): string {
  const resolved = clock ?? defaultClock;
  return createSoftwareTotp(secretBase32).generate({
    timestamp: resolved.now(),
  });
}

export function alterTotpCode(code: string): string {
  const first = code[0] === "0" ? "1" : "0";
  return `${first}${code.slice(1)}`;
}

export function stepRemainderMs(
  timestamp: number,
  periodSeconds: number = TOTP_PERIOD_SECONDS,
): number {
  const periodMs = periodSeconds * 1_000;
  return periodMs - (timestamp % periodMs);
}

/** If fewer than `minimumMs` remain in the step, wait until the next step (+1s). */
export async function waitForMinimumStepRemainder(
  clock: TotpClock = defaultClock,
  minimumMs: number = TOTP_MIN_REMAINDER_MS,
): Promise<void> {
  const resolved = clock ?? defaultClock;
  const threshold = minimumMs ?? TOTP_MIN_REMAINDER_MS;
  const remainder = stepRemainderMs(resolved.now());
  if (remainder < threshold) {
    await resolved.sleep(remainder + 1_000);
  }
}

/** After enrollment, wait until the next TOTP step before MFA sign-in. */
export async function waitForNextTotpStep(
  clock: TotpClock = defaultClock,
): Promise<void> {
  const resolved = clock ?? defaultClock;
  await resolved.sleep(stepRemainderMs(resolved.now()) + 250);
}
