import test from 'node:test';
import assert from 'node:assert/strict';
import { mergeConfig, defaultConfig } from '../src/config/defaultConfig';
import { runBacktest } from '../src/backtest/engine';
import { calculateMaxDrawdown } from '../src/backtest/metrics';

const market = {
  id: 'bt_m1',
  question: 'Will test event happen?',
  category: 'politics' as const,
  currentPrice: 0.4,
  spread: 0.02,
  liquidity: 50000,
  volume24h: 10000,
  resolutionAt: '2026-12-31T00:00:00Z'
};

const cfg = mergeConfig(defaultConfig, {
  walletIntel: {
    ...defaultConfig.walletIntel,
    minTrades: 1,
    minConfidenceScore: 0,
    minRealizedPnl: -1_000_000
  }
});

test('backtest profitable replay', () => {
  const trades = [
    { wallet: '0xw', marketId: 'bt_m1', category: 'politics' as const, stake: 100, payout: 180, timestamp: '2026-01-01T00:00:00Z' },
    { wallet: '0xw', marketId: 'bt_m1', category: 'politics' as const, stake: 100, payout: 160, timestamp: '2026-01-02T00:00:00Z' }
  ];

  const result = runBacktest([market], trades, cfg);
  assert.equal(result.summary.totalTrades > 0, true);
  assert.equal(result.summary.realizedPnl > 0, true);
  assert.equal(typeof result.trainSummary.roi, 'number');
  assert.equal(typeof result.testSummary.roi, 'number');
});

test('backtest losing replay', () => {
  const trades = [
    { wallet: '0xw', marketId: 'bt_m1', category: 'politics' as const, stake: 100, payout: 20, timestamp: '2026-01-01T00:00:00Z' },
    { wallet: '0xw', marketId: 'bt_m1', category: 'politics' as const, stake: 100, payout: 50, timestamp: '2026-01-02T00:00:00Z' }
  ];

  const result = runBacktest([market], trades, cfg);
  assert.equal(result.summary.totalTrades > 0, true);
  assert.equal(result.summary.realizedPnl < 0, true);
});

test('backtest no-trade replay', () => {
  const blockedMarket = { ...market, id: 'bt_m2', category: 'other' as const };
  const trades = [
    { wallet: '0xw', marketId: 'bt_m2', category: 'other' as const, stake: 100, payout: 180, timestamp: '2026-01-01T00:00:00Z' }
  ];

  const result = runBacktest([blockedMarket], trades, cfg);
  assert.equal(result.summary.totalTrades, 0);
});

test('drawdown calculation', () => {
  const dd = calculateMaxDrawdown([100, 120, 90, 130, 110]);
  assert.equal(dd, 30);
});

test('backtest rejects malformed historical data', () => {
  const badTrades = [
    { wallet: '0xw', marketId: 'bt_m1', category: 'politics' as const, stake: 100, payout: 120, timestamp: 'not-a-date' }
  ];

  assert.throws(() => runBacktest([market], badTrades, cfg), /Malformed historical trade/);
});
