import path from 'node:path';
import { AppConfig } from '../config/defaultConfig';
import { WalletScore, WalletTrade } from '../types/wallet';
import { writeJson } from '../utils/io';

const computeDrawdown = (profits: number[]): number => {
  let peak = 0;
  let equity = 0;
  let maxDrawdown = 0;
  for (const p of profits) {
    equity += p;
    peak = Math.max(peak, equity);
    maxDrawdown = Math.max(maxDrawdown, peak - equity);
  }
  return maxDrawdown;
};

export const rankWallets = (trades: WalletTrade[], config: AppConfig): WalletScore[] => {
  const grouped = new Map<string, WalletTrade[]>();
  for (const trade of trades) {
    const arr = grouped.get(trade.wallet) ?? [];
    arr.push(trade);
    grouped.set(trade.wallet, arr);
  }

  const scores: WalletScore[] = Array.from(grouped.entries()).map(([wallet, walletTrades]) => {
    const totalTrades = walletTrades.length;
    const profits = walletTrades.map((t) => t.payout - t.stake);
    const wins = profits.filter((p) => p > 0).length;
    const winRate = totalTrades ? wins / totalTrades : 0;
    const realizedPnl = profits.reduce((a, b) => a + b, 0);
    const totalStake = walletTrades.reduce((sum, t) => sum + t.stake, 0);
    const roi = totalStake > 0 ? realizedPnl / totalStake : 0;
    const averageTradeSize = totalTrades > 0 ? totalStake / totalTrades : 0;
    const maxDrawdown = computeDrawdown(profits);

    const catCounts = new Map<string, number>();
    for (const t of walletTrades) catCounts.set(t.category, (catCounts.get(t.category) ?? 0) + 1);
    const largestCategory = Math.max(...Array.from(catCounts.values()));
    const categoryConcentration = largestCategory / totalTrades;

    const sampleSizeScore = Math.min(1, totalTrades / Math.max(1, config.walletIntel.minTradesForTrust));
    const confidenceScore = Math.max(0, Math.min(1, sampleSizeScore * (0.6 + winRate * 0.4)));
    const trustedSample = sampleSizeScore >= 1;

    const rankScore =
      winRate * 25 + roi * 30 + realizedPnl / 25 + confidenceScore * 20 - maxDrawdown / 25 - categoryConcentration * 2;

    return {
      wallet,
      totalTrades,
      winRate,
      realizedPnl,
      roi,
      averageTradeSize,
      maxDrawdown,
      categoryConcentration,
      confidenceScore,
      trustedSample,
      rankScore
    };
  });

  const filtered = scores.filter(
    (s) =>
      s.totalTrades >= config.walletIntel.minTrades &&
      s.realizedPnl >= config.walletIntel.minRealizedPnl &&
      s.confidenceScore >= config.walletIntel.minConfidenceScore
  );

  const sorted = filtered.sort((a, b) => b.rankScore - a.rankScore).slice(0, config.walletIntel.topN);
  const outputPath = path.resolve(process.cwd(), config.engine.artifactsDir, 'wallet_rankings.json');
  writeJson(outputPath, sorted);
  return sorted;
};
