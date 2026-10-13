export type ScenarioTokenHandles = {
  refreshTokens: string[];
  accessToken?: string;
};

export type ScenarioCleanupDiagnostic = {
  revokeAttempted: number;
  revokeFailed: number;
  globalSignOutAttempted: boolean;
  globalSignOutFailed: boolean;
  personaDeleteFailed: boolean;
};

export class ScenarioCleanupFailure extends Error {
  readonly diagnostic: ScenarioCleanupDiagnostic;

  constructor(diagnostic: ScenarioCleanupDiagnostic) {
    super(
      `scenario cleanup failed: revokeFailed=${diagnostic.revokeFailed} revokeAttempted=${diagnostic.revokeAttempted} globalSignOutFailed=${diagnostic.globalSignOutFailed} personaDeleteFailed=${diagnostic.personaDeleteFailed}`,
    );
    this.name = "ScenarioCleanupFailure";
    this.diagnostic = diagnostic;
  }
}

export async function finalizeScenario(
  handles: ScenarioTokenHandles,
  cleanup: {
    revokeRefreshToken: (refreshToken: string) => Promise<void>;
    globalSignOut: (accessToken: string) => Promise<void>;
    deletePersona: () => Promise<void>;
  },
): Promise<void> {
  const refreshTokens = [...handles.refreshTokens];
  const accessToken = handles.accessToken;
  const diagnostic: ScenarioCleanupDiagnostic = {
    revokeAttempted: 0,
    revokeFailed: 0,
    globalSignOutAttempted: false,
    globalSignOutFailed: false,
    personaDeleteFailed: false,
  };

  for (const refreshToken of refreshTokens) {
    diagnostic.revokeAttempted += 1;
    try {
      await cleanup.revokeRefreshToken(refreshToken);
    } catch {
      diagnostic.revokeFailed += 1;
    }
  }

  if (accessToken !== undefined) {
    diagnostic.globalSignOutAttempted = true;
    try {
      await cleanup.globalSignOut(accessToken);
    } catch {
      diagnostic.globalSignOutFailed = true;
    }
  }

  try {
    await cleanup.deletePersona();
  } catch {
    diagnostic.personaDeleteFailed = true;
  }

  handles.refreshTokens.length = 0;
  handles.accessToken = undefined;

  if (
    diagnostic.revokeFailed > 0 ||
    diagnostic.globalSignOutFailed ||
    diagnostic.personaDeleteFailed
  ) {
    throw new ScenarioCleanupFailure(diagnostic);
  }
}
