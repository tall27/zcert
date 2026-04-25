import test from 'node:test';
import assert from 'node:assert/strict';
import { buildStrategyDecisions } from '../src/agents/strategy';
import { defaultConfig } from '../src/config/defaultConfig';
import { ScoredMarket } from '../src/types/market';

const scanned: ScoredMarket[] = [
  {
    id: 'fx_market_1',
    question: 'Will event A happen?',
    category: 'politics',
    currentPrice: 0.4,
    spread: 0.02,
    liquidity: 60000,
    volume24h: 20000,
    resolutionAt: '2026-12-31T00:00:00Z',
    estimatedProbability: 0.5,
    estimatedEdge: 0.1,
    scannerPass: true,
    scannerReasons: []
  }
];

test('strategy uses consensus to produce full exposure', () => {
  const decisions = buildStrategyDecisions(
    scanned,
    [
      {
        market_id: 'fx_market_1',
        question: 'Will event A happen?',
        current_price: 0.4,
        estimated_probability: 0.52,
        edge: 0.12,
        confidence: 0.7,
        reasoning_summary: 'test',
        risk_flags: [],
        pass: true
      }
    ],
    [{ wallet: 'x', totalTrades: 10, winRate: 0.7, realizedPnl: 100, roi: 0.2, averageTradeSize: 50, maxDrawdown: 10, categoryConcentration: 0.8, confidenceScore: 0.9, trustedSample: true, rankScore: 9 }],
    defaultConfig
  );

  assert.equal(decisions[0].direction, 'yes');
  assert.equal(decisions[0].desiredExposure, 1);
});
