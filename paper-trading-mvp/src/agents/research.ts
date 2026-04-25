import fs from 'node:fs';
import path from 'node:path';
import { AppConfig } from '../config/defaultConfig';
import { ScoredMarket } from '../types/market';
import { ResearchReport } from '../types/signal';

const confidenceFromEdge = (edge: number): number => Math.max(0.5, Math.min(0.9, 0.5 + edge * 2));

export const runResearch = (config: AppConfig): ResearchReport[] => {
  const queuePath = path.resolve(process.cwd(), 'data', 'scanner_queue.json');
  const queued = JSON.parse(fs.readFileSync(queuePath, 'utf-8')) as ScoredMarket[];

  const reports = queued.map((market) => {
    const confidence = confidenceFromEdge(market.estimatedEdge);
    const riskFlags = [
      ...(market.spread > config.scanner.maxSpread * 0.8 ? ['wider_spread_watch'] : []),
      ...(market.liquidity < config.scanner.minLiquidity * 1.25 ? ['borderline_liquidity'] : [])
    ];

    const pass = market.estimatedEdge >= config.research.passEdge && confidence >= config.research.minConfidence;

    return {
      market_id: market.id,
      question: market.question,
      current_price: market.currentPrice,
      estimated_probability: market.estimatedProbability,
      edge: market.estimatedEdge,
      confidence,
      reasoning_summary:
        'Deterministic placeholder model: combines market price with liquidity/volume signals and simple risk checks.',
      risk_flags: riskFlags,
      pass
    };
  });

  const outputPath = path.resolve(process.cwd(), 'data', 'research_output.json');
  fs.writeFileSync(outputPath, JSON.stringify(reports, null, 2));

  return reports;
};
