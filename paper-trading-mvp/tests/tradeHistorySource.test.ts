import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import assert from 'node:assert/strict';
import { defaultConfig } from '../src/config/defaultConfig';
import { __private__, loadTradeHistory } from '../src/data/polymarketTradeHistorySource';

test('csv parser ingests valid rows', () => {
  const csv = [
    'wallet,marketId,category,stake,payout,timestamp',
    '0xabc,mkt1,politics,100,150,2026-01-01T00:00:00Z',
    '0xabc,mkt2,crypto,200,0,2026-01-02T00:00:00Z'
  ].join('\n');

  const parsed = __private__.parseCsvTrades(csv);
  assert.equal(parsed.length, 2);
  assert.equal(parsed[0].wallet, '0xabc');
});

test('csv parser rejects malformed row', () => {
  const csv = [
    'wallet,marketId,category,stake,payout,timestamp',
    '0xabc,mkt1,politics,100,150'
  ].join('\n');

  assert.throws(() => __private__.parseCsvTrades(csv), /Malformed CSV row/);
});

test('json parser loads from local file', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'trade-json-'));
  const file = path.join(tmp, 'trades.json');
  fs.writeFileSync(
    file,
    JSON.stringify([
      { wallet: '0x1', marketId: 'm1', category: 'politics', stake: 50, payout: 80, timestamp: '2026-01-01T00:00:00Z' }
    ])
  );

  const trades = loadTradeHistory('json', file, defaultConfig);
  assert.equal(trades.length, 1);
});

test('csv parser loads from local file', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'trade-csv-'));
  const file = path.join(tmp, 'trades.csv');
  fs.writeFileSync(file, 'wallet,marketId,category,stake,payout,timestamp\n0x1,m1,politics,50,80,2026-01-01T00:00:00Z\n');

  const trades = loadTradeHistory('csv', file, defaultConfig);
  assert.equal(trades.length, 1);
});
