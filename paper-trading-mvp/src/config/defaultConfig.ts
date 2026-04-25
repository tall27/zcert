export interface AppConfig {
  scanner: {
    minLiquidity: number;
    maxSpread: number;
    minHoursToResolution: number;
    maxHoursToResolution: number;
    categoryAllowList: string[];
    categoryBlockList: string[];
    minEstimatedEdge: number;
  };
  research: {
    minConfidence: number;
    passEdge: number;
  };
  walletIntel: {
    minTradesForTrust: number;
    topN: number;
  };
  strategy: {
    fullPositionExposure: number;
    halfPositionExposure: number;
  };
  risk: {
    cappedKellyFraction: number;
    maxPositionSize: number;
    maxDailyLoss: number;
    maxOpenPositions: number;
  };
  exits: {
    targetRoi: number;
    stopRoi: number;
    staleThesisHours: number;
    maxHoldingHours: number;
  };
  engine: {
    startingBankroll: number;
    artifactsDir: string;
  };
}

export const defaultConfig: AppConfig = {
  scanner: {
    minLiquidity: 20000,
    maxSpread: 0.06,
    minHoursToResolution: 4,
    maxHoursToResolution: 30000,
    categoryAllowList: ['politics', 'sports', 'crypto', 'macro'],
    categoryBlockList: ['other'],
    minEstimatedEdge: 0.005
  },
  research: {
    minConfidence: 0.5,
    passEdge: 0.01
  },
  walletIntel: {
    minTradesForTrust: 8,
    topN: 5
  },
  strategy: {
    fullPositionExposure: 1,
    halfPositionExposure: 0.5
  },
  risk: {
    cappedKellyFraction: 0.5,
    maxPositionSize: 400,
    maxDailyLoss: 800,
    maxOpenPositions: 8
  },
  exits: {
    targetRoi: 0.25,
    stopRoi: -0.12,
    staleThesisHours: 24,
    maxHoldingHours: 36
  },
  engine: {
    startingBankroll: 10000,
    artifactsDir: 'artifacts'
  }
};

export const mergeConfig = (base: AppConfig, override: Partial<AppConfig>): AppConfig => ({
  ...base,
  ...override,
  scanner: { ...base.scanner, ...(override.scanner ?? {}) },
  research: { ...base.research, ...(override.research ?? {}) },
  walletIntel: { ...base.walletIntel, ...(override.walletIntel ?? {}) },
  strategy: { ...base.strategy, ...(override.strategy ?? {}) },
  risk: { ...base.risk, ...(override.risk ?? {}) },
  exits: { ...base.exits, ...(override.exits ?? {}) },
  engine: { ...base.engine, ...(override.engine ?? {}) }
});
