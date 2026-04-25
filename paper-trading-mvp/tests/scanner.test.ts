import test from 'node:test';
import assert from 'node:assert/strict';
import markets from './fixtures/markets.fixture.json';
import { Market } from '../src/types/market';
import { runScanner } from '../src/agents/scanner';
import { defaultConfig } from '../src/config/defaultConfig';

test('scanner filters and produces survivors', () => {
  const scanned = runScanner(markets as Market[], defaultConfig);
  assert.equal(scanned.length, 2);
  assert.equal(scanned.filter((m) => m.scannerPass).length, 1);
  assert.equal(scanned.find((m) => m.id === 'fx_market_2')?.scannerPass, false);
});
