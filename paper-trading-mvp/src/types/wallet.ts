import { HistoricalTrade } from './trade';

export type WalletTrade = HistoricalTrade;

export interface WalletScore {
  wallet: string;
  totalTrades: number;
  winRate: number;
  realizedPnl: number;
  roi: number;
  averageTradeSize: number;
  maxDrawdown: number;
  categoryConcentration: number;
  confidenceScore: number;
  trustedSample: boolean;
  rankScore: number;
}
