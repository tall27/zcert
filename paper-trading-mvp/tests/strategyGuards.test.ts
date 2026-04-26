import test from 'node:test';
import assert from 'node:assert/strict';
import { defaultConfig, mergeConfig } from '../src/config/defaultConfig';
import { evaluateStrategyGuards } from '../src/validation/strategyGuards';

const baseMarket = {
  id: 'g1',
  question: 'q',
  category: 'politics' as const,
  currentPrice: 0.4,
  spread: 0.02,
  liquidity: 50000,
  volume24h: 10000,
  resolutionAt: new Date(Date.now() + 48 * 3600_000).toISOString(),
  estimatedProbability: 0.5,
  estimatedEdge: 0.1,
  scannerPass: true,
  scannerReasons: [] as string[]
};

const decision = {
  marketId: 'g1',
  direction: 'yes' as const,
  strategy: 'convergence' as const,
  consensusCount: 2,
  confidence: 0.8,
  desiredExposure: 1,
  rationale: 'x'
};

const walletScores = [{ wallet: 'w', totalTrades: 5, winRate: 0.6, realizedPnl: 10, roi: 0.1, averageTradeSize: 50, maxDrawdown: 5, categoryConcentration: 0.7, confidenceScore: 0.8, trustedSample: true, rankScore: 1 }];

test('spread rejection', () => {
  const market = { ...baseMarket, spread: 0.5 };
  const out = evaluateStrategyGuards(market, decision, 100, walletScores, defaultConfig);
  assert.equal(out.allowed, false);
  assert.ok(out.reasons.includes('spread_above_maximum'));
});

test('liquidity rejection', () => {
  const market = { ...baseMarket, liquidity: 10 };
  const out = evaluateStrategyGuards(market, decision, 100, walletScores, defaultConfig);
  assert.ok(out.reasons.includes('liquidity_below_minimum'));
});

test('stale data rejection', () => {
  const market = { ...baseMarket, lastPriceUpdatedAt: new Date(Date.now() - 10 * 3600_000).toISOString() };
  const out = evaluateStrategyGuards(market, decision, 100, walletScores, defaultConfig);
  assert.ok(out.reasons.includes('stale_price_data'));
});

test('slippage removing edge rejection', () => {
  const cfg = mergeConfig(defaultConfig, { guardrails: { ...defaultConfig.guardrails, minEdgeAfterSpread: 0.0001 } });
  const market = { ...baseMarket, liquidity: 100, estimatedEdge: 0.01, spread: 0.009 };
  const out = evaluateStrategyGuards(market, decision, 500, walletScores, cfg);
  assert.ok(out.reasons.includes('slippage_removes_edge'));
});
