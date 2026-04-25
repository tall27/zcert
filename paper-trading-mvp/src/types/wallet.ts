import { MarketCategory } from './market';

export interface WalletTrade {
  wallet: string;
  marketId: string;
  category: MarketCategory;
  stake: number;
  payout: number;
  timestamp: string;
}

export interface WalletScore {
  wallet: string;
  numberOfTrades: number;
  winRate: number;
  realizedProfit: number;
  maxDrawdown: number;
  categoryConsistency: number;
  trustedSample: boolean;
  rankScore: number;
}
