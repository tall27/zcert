export type MarketSourceType = 'sample' | 'polymarket';

export interface AppConfig {
  marketSource: MarketSourceType;
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
    minTrades: number;
    minRealizedPnl: number;
    minConfidenceScore: number;
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
  guardrails: {
    minLiquidity: number;
    maxSpread: number;
    minEdgeAfterSpread: number;
    minWalletSampleSize: number;
    minHoursToResolution: number;
    maxPriceStaleMinutes: number;
  };
  polymarket: {
    apiBase: string;
    limit: number;
    tradeHistoryEndpoint?: string;
  };
}

export const defaultConfig: AppConfig = {
  marketSource: 'sample',
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
    minTrades: 2,
    minRealizedPnl: -1000000,
    minConfidenceScore: 0.2,
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
  },
  guardrails: {
    minLiquidity: 20000,
    maxSpread: 0.06,
    minEdgeAfterSpread: 0.005,
    minWalletSampleSize: 2,
    minHoursToResolution: 4,
    maxPriceStaleMinutes: 180
  },
  polymarket: {
    apiBase: 'https://gamma-api.polymarket.com',
    limit: 200
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
  engine: { ...base.engine, ...(override.engine ?? {}) },
  guardrails: { ...base.guardrails, ...(override.guardrails ?? {}) },
  polymarket: { ...base.polymarket, ...(override.polymarket ?? {}) }
});
