import path from 'node:path';
import { AppConfig } from '../config/defaultConfig';
import { Market, ScoredMarket } from '../types/market';
import { writeJson } from '../utils/io';

const estimateProbability = (market: Market): number => {
  const liquiditySignal = Math.min(0.15, market.liquidity / 1_000_000);
  const volumeSignal = Math.min(0.08, market.volume24h / 1_000_000);
  return Math.max(0.01, Math.min(0.99, market.currentPrice + liquiditySignal - volumeSignal / 2));
};

export const runScanner = (markets: Market[], config: AppConfig): ScoredMarket[] => {
  if (markets.length === 0) throw new Error('Scanner received no markets to evaluate.');

  const now = Date.now();
  const results = markets.map((market) => {
    const estimatedProbability = estimateProbability(market);
    const estimatedEdge = Math.abs(estimatedProbability - market.currentPrice);
    const hoursToResolution = (new Date(market.resolutionAt).getTime() - now) / (1000 * 60 * 60);

    const checks: Array<[boolean, string]> = [
      [market.liquidity >= config.scanner.minLiquidity, 'insufficient_liquidity'],
      [market.spread <= config.scanner.maxSpread, 'spread_too_wide'],
      [hoursToResolution >= config.scanner.minHoursToResolution, 'too_close_to_resolution'],
      [hoursToResolution <= config.scanner.maxHoursToResolution, 'too_far_to_resolution'],
      [config.scanner.categoryAllowList.includes(market.category), 'not_in_allow_list'],
      [!config.scanner.categoryBlockList.includes(market.category), 'in_block_list'],
      [estimatedEdge >= config.scanner.minEstimatedEdge, 'edge_too_small']
    ];

    const scannerReasons = checks.filter(([pass]) => !pass).map(([, reason]) => reason);

    return {
      ...market,
      estimatedProbability,
      estimatedEdge,
      scannerPass: scannerReasons.length === 0,
      scannerReasons
    };
  });

  const queue = results.filter((m) => m.scannerPass);
  const queuePath = path.resolve(process.cwd(), config.engine.artifactsDir, 'scanner_queue.json');
  writeJson(queuePath, queue);

  return results;
};
