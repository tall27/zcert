import test from 'node:test';
import assert from 'node:assert/strict';
import trades from './fixtures/trades.fixture.json';
import { WalletTrade } from '../src/types/wallet';
import { rankWallets } from '../src/agents/walletIntel';
import { defaultConfig } from '../src/config/defaultConfig';

test('wallet intel ranks wallets and applies trust sample penalty', () => {
  const ranked = rankWallets(trades as WalletTrade[], defaultConfig);
  assert.equal(ranked.length > 0, true);
  assert.equal(ranked[0].wallet, '0x1');
  assert.equal(ranked[0].trustedSample, false);
});
