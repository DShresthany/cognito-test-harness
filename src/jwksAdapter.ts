import {
  OperationalAuthenticationFailure,
} from "./authenticationOutcome.js";

export type Jwk = {
  kid?: string;
  kty: string;
  n?: string;
  e?: string;
};

export type Jwks = {
  keys: readonly Jwk[];
};

export class UnknownSigningKeyFailure extends Error {
  readonly retryable = false as const;

  constructor() {
    super("unknown signing key");
    this.name = "UnknownSigningKeyFailure";
  }
}

export type JwksAdapter = {
  resolveKey(kid: string): Promise<Jwk>;
};

export function createJwksAdapter(deps: {
  fetchJwks: (jwksUri: string) => Promise<Jwks>;
  jwksUri: string;
}): JwksAdapter {
  let cache: Jwks | undefined;

  return {
    async resolveKey(kid: string): Promise<Jwk> {
      const cached = findKey(cache, kid);
      if (cached) {
        return cached;
      }

      try {
        cache = await deps.fetchJwks(deps.jwksUri);
      } catch (error) {
        throw new OperationalAuthenticationFailure({
          category: "network",
          operation: "verify-access-token",
          retryable: true,
          cause: error,
        });
      }

      const refreshed = findKey(cache, kid);
      if (refreshed) {
        return refreshed;
      }

      throw new UnknownSigningKeyFailure();
    },
  };
}

function findKey(jwks: Jwks | undefined, kid: string): Jwk | undefined {
  return jwks?.keys.find((key) => key.kid === kid);
}
