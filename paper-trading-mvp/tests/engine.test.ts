import test from 'node:test';
import assert from 'node:assert/strict';
import { runPaperEngine } from '../src/paper/engine';
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

test('paper engine runs and computes metrics', () => {
  const out = runPaperEngine(
    [{ marketId: 'fx_market_1', direction: 'yes', strategy: 'convergence', consensusCount: 3, confidence: 0.9, desiredExposure: 1, rationale: 'ok' }],
    scanned,
    defaultConfig
  );

  assert.equal(out.ledger.trades.length, 1);
  assert.equal(typeof out.metrics.finalBankroll, 'number');
});
