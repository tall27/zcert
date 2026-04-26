import path from 'node:path';
import { Market } from '../types/market';
import { WalletTrade } from '../types/wallet';
import { writeJson } from '../utils/io';

export interface DataQualityReport {
  criticalIssues: string[];
  warnings: string[];
  stats: {
    marketCount: number;
    tradeCount: number;
    unmatchedMarkets: number;
    unmatchedTrades: number;
  };
}

export const analyzeDataQuality = (markets: Market[], trades: WalletTrade[]): DataQualityReport => {
  const criticalIssues: string[] = [];
  const warnings: string[] = [];

  const marketIds = markets.map((m) => m.id);
  const duplicateMarketIds = marketIds.filter((id, idx) => marketIds.indexOf(id) !== idx);
  if (duplicateMarketIds.length > 0) criticalIssues.push(`duplicate_market_ids:${Array.from(new Set(duplicateMarketIds)).join(',')}`);

  const tradeKeys = trades.map((t) => `${t.wallet}|${t.marketId}|${t.timestamp}|${t.stake}|${t.payout}`);
  const duplicateTrades = tradeKeys.filter((k, idx) => tradeKeys.indexOf(k) !== idx);
  if (duplicateTrades.length > 0) warnings.push(`duplicate_trades:${duplicateTrades.length}`);

  const missingTimestamps = trades.filter((t) => !t.timestamp || Number.isNaN(new Date(t.timestamp).getTime())).length;
  if (missingTimestamps > 0) criticalIssues.push(`missing_or_invalid_timestamps:${missingTimestamps}`);

  const futureTimestamps = trades.filter((t) => new Date(t.timestamp).getTime() > Date.now()).length;
  if (futureTimestamps > 0) warnings.push(`future_timestamps:${futureTimestamps}`);

  const negativePrices = markets.filter((m) => m.currentPrice < 0).length;
  if (negativePrices > 0) criticalIssues.push(`negative_prices:${negativePrices}`);

  const outsideRangePrices = markets.filter((m) => m.currentPrice > 1 || m.currentPrice < 0).length;
  if (outsideRangePrices > 0) criticalIssues.push(`prices_outside_0_1:${outsideRangePrices}`);

  const missingLiquidity = markets.filter((m) => !Number.isFinite(m.liquidity) || m.liquidity <= 0).length;
  if (missingLiquidity > 0) warnings.push(`missing_or_invalid_liquidity:${missingLiquidity}`);

  const sizes = trades.map((t) => t.stake).filter((n) => Number.isFinite(n));
  const median = sizes.length === 0 ? 0 : [...sizes].sort((a, b) => a - b)[Math.floor(sizes.length / 2)];
  const outliers = sizes.filter((s) => median > 0 && s > median * 10).length;
  if (outliers > 0) warnings.push(`extreme_trade_size_outliers:${outliers}`);

  const tradeMarketSet = new Set(trades.map((t) => t.marketId));
  const marketsWithoutTrades = markets.filter((m) => !tradeMarketSet.has(m.id)).length;
  if (marketsWithoutTrades > 0) warnings.push(`markets_with_no_matching_trades:${marketsWithoutTrades}`);

  const marketSet = new Set(markets.map((m) => m.id));
  const tradesWithoutMarkets = trades.filter((t) => !marketSet.has(t.marketId)).length;
  if (tradesWithoutMarkets > 0) warnings.push(`trades_with_no_matching_market:${tradesWithoutMarkets}`);

  return {
    criticalIssues,
    warnings,
    stats: {
      marketCount: markets.length,
      tradeCount: trades.length,
      unmatchedMarkets: marketsWithoutTrades,
      unmatchedTrades: tradesWithoutMarkets
    }
  };
};

export const persistDataQualityReport = (report: DataQualityReport, artifactsDir: string): void => {
  writeJson(path.resolve(process.cwd(), artifactsDir, 'data_quality_report.json'), report);
};
