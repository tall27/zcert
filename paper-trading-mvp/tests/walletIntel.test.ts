import test from 'node:test';
import assert from 'node:assert/strict';
import trades from './fixtures/trades.fixture.json';
import { WalletTrade } from '../src/types/wallet';
import { rankWallets } from '../src/agents/walletIntel';
import { defaultConfig, mergeConfig } from '../src/config/defaultConfig';

test('wallet intel ranks wallets with expanded metrics and filters', () => {
  const cfg = mergeConfig(defaultConfig, {
    walletIntel: {
      ...defaultConfig.walletIntel,
      minTrades: 1,
      minConfidenceScore: 0,
      minRealizedPnl: -1000
    }
  });

  const ranked = rankWallets(trades as WalletTrade[], cfg);
  assert.equal(ranked.length > 0, true);
  assert.equal(ranked[0].wallet, '0x1');
  assert.equal(typeof ranked[0].roi, 'number');
  assert.equal(typeof ranked[0].averageTradeSize, 'number');
  assert.equal(typeof ranked[0].categoryConcentration, 'number');
  assert.equal(typeof ranked[0].confidenceScore, 'number');
});
