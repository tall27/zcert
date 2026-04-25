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
    const numberOfTrades = walletTrades.length;
    const profits = walletTrades.map((t) => t.payout - t.stake);
    const wins = profits.filter((p) => p > 0).length;
    const winRate = numberOfTrades ? wins / numberOfTrades : 0;
    const realizedProfit = profits.reduce((a, b) => a + b, 0);
    const maxDrawdown = computeDrawdown(profits);

    const catCounts = new Map<string, number>();
    for (const t of walletTrades) catCounts.set(t.category, (catCounts.get(t.category) ?? 0) + 1);
    const largestCategory = Math.max(...Array.from(catCounts.values()));
    const categoryConsistency = largestCategory / numberOfTrades;

    const trustedSample = numberOfTrades >= config.walletIntel.minTradesForTrust;
    const samplePenalty = trustedSample ? 1 : Math.max(0.3, numberOfTrades / config.walletIntel.minTradesForTrust);

    const rankScore =
      (winRate * 40 + realizedProfit / 20 + categoryConsistency * 20 - maxDrawdown / 25) * samplePenalty;

    return {
      wallet,
      numberOfTrades,
      winRate,
      realizedProfit,
      maxDrawdown,
      categoryConsistency,
      trustedSample,
      rankScore
    };
  });

  const sorted = scores.sort((a, b) => b.rankScore - a.rankScore).slice(0, config.walletIntel.topN);
  const outputPath = path.resolve(process.cwd(), config.engine.artifactsDir, 'top_wallets.json');
  writeJson(outputPath, sorted);
  return sorted;
};
