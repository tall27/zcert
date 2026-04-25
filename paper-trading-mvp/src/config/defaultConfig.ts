export const defaultConfig = {
  scanner: {
    minLiquidity: 20000,
    maxSpread: 0.06,
    minHoursToResolution: 4,
    maxHoursToResolution: 30000,
    categoryAllowList: ['politics', 'sports', 'crypto', 'macro'] as const,
    categoryBlockList: ['other'] as const,
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
    startingBankroll: 10000
  }
};

export type AppConfig = typeof defaultConfig;
