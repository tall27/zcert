import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import assert from 'node:assert/strict';
import { importAndNormalize } from '../src/import/importer';

test('importer normalizes market and trade json files', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'importer-'));

  const rawMarkets = [
    { id: 'm1', question: 'Q1', category: 'politics', bestBid: 0.45, bestAsk: 0.48, liquidity: 10000, volume: 50000, endDate: '2024-11-01T00:00:00Z' }
  ];
  const rawTrades = [
    { maker: '0xabc', market_id: 'm1', category: 'politics', usd_amount: 50, price: 0.5, timestamp: '2024-10-01T00:00:00Z' }
  ];

  const marketsIn = path.join(tmp, 'markets.json');
  const tradesIn = path.join(tmp, 'trades.json');
  const marketsOut = path.join(tmp, 'real_markets.json');
  const tradesOut = path.join(tmp, 'real_trades.json');

  fs.writeFileSync(marketsIn, JSON.stringify(rawMarkets));
  fs.writeFileSync(tradesIn, JSON.stringify(rawTrades));

  const marketsResult = importAndNormalize(marketsIn, 'markets', marketsOut);
  const tradesResult = importAndNormalize(tradesIn, 'trades', tradesOut);

  assert.equal(marketsResult.count, 1);
  assert.equal(tradesResult.count, 1);

  const normalizedMarkets = JSON.parse(fs.readFileSync(marketsOut, 'utf-8')) as Array<Record<string, unknown>>;
  const normalizedTrades = JSON.parse(fs.readFileSync(tradesOut, 'utf-8')) as Array<Record<string, unknown>>;

  assert.equal(normalizedMarkets[0].id, 'm1');
  assert.equal(normalizedTrades[0].marketId, 'm1');
});
