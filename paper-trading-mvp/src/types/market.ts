export type MarketCategory = 'politics' | 'sports' | 'crypto' | 'macro' | 'other';

export interface Market {
  id: string;
  question: string;
  category: MarketCategory;
  currentPrice: number;
  spread: number;
  liquidity: number;
  volume24h: number;
  resolutionAt: string;
  lastPriceUpdatedAt?: string;
}

export interface ScoredMarket extends Market {
  estimatedProbability: number;
  estimatedEdge: number;
  scannerPass: boolean;
  scannerReasons: string[];
}
