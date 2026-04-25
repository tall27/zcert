import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeDataQuality } from '../src/validation/dataQuality';

const baseMarket = {
  id: 'm1',
  question: 'q',
  category: 'politics' as const,
  currentPrice: 0.5,
  spread: 0.02,
  liquidity: 1000,
  volume24h: 100,
  resolutionAt: '2026-12-31T00:00:00Z'
};

const baseTrade = {
  wallet: 'w1',
  marketId: 'm1',
  category: 'politics' as const,
  stake: 100,
  payout: 120,
  timestamp: '2026-01-01T00:00:00Z'
};

test('duplicate market IDs', () => {
  const r = analyzeDataQuality([{ ...baseMarket }, { ...baseMarket }], [{ ...baseTrade }]);
  assert.match(r.criticalIssues.join(','), /duplicate_market_ids/);
});

test('duplicate trades', () => {
  const r = analyzeDataQuality([{ ...baseMarket }], [{ ...baseTrade }, { ...baseTrade }]);
  assert.match(r.warnings.join(','), /duplicate_trades/);
});

test('missing timestamps', () => {
  const r = analyzeDataQuality([{ ...baseMarket }], [{ ...baseTrade, timestamp: '' }]);
  assert.match(r.criticalIssues.join(','), /missing_or_invalid_timestamps/);
});

test('future timestamps', () => {
  const future = new Date(Date.now() + 86_400_000).toISOString();
  const r = analyzeDataQuality([{ ...baseMarket }], [{ ...baseTrade, timestamp: future }]);
  assert.match(r.warnings.join(','), /future_timestamps/);
});

test('negative/out-of-range prices', () => {
  const r = analyzeDataQuality([{ ...baseMarket, currentPrice: -0.1 }], [{ ...baseTrade }]);
  assert.match(r.criticalIssues.join(','), /negative_prices/);
});

test('missing liquidity', () => {
  const r = analyzeDataQuality([{ ...baseMarket, liquidity: 0 }], [{ ...baseTrade }]);
  assert.match(r.warnings.join(','), /missing_or_invalid_liquidity/);
});

test('extreme outlier trade sizes', () => {
  const r = analyzeDataQuality([{ ...baseMarket }], [{ ...baseTrade, stake: 10 }, { ...baseTrade, wallet: 'w2', stake: 12 }, { ...baseTrade, wallet: 'w3', stake: 5000 }]);
  assert.match(r.warnings.join(','), /extreme_trade_size_outliers/);
});

test('markets with no matching trades and trades with no matching market', () => {
  const r = analyzeDataQuality([{ ...baseMarket, id: 'm2' }], [{ ...baseTrade, marketId: 'mX' }]);
  assert.match(r.warnings.join(','), /markets_with_no_matching_trades/);
  assert.match(r.warnings.join(','), /trades_with_no_matching_market/);
});
