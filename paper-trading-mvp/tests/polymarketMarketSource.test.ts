import test from 'node:test';
import assert from 'node:assert/strict';
import { defaultConfig } from '../src/config/defaultConfig';
import { loadPolymarketMarkets } from '../src/data/polymarketMarketSource';

test('polymarket source normalizes active markets', async () => {
  const fakeFetch = async () =>
    ({
      ok: true,
      status: 200,
      json: async () => [
        {
          id: '123',
          question: 'Will X happen?',
          active: true,
          closed: false,
          endDate: '2026-12-01T00:00:00Z',
          liquidity: '10000',
          volume: '2500',
          bestBid: '0.44',
          bestAsk: '0.48',
          outcomePrices: '[0.46,0.54]',
          category: 'politics'
        }
      ]
    }) as Response;

  const markets = await loadPolymarketMarkets(defaultConfig, fakeFetch as typeof fetch);
  assert.equal(markets.length, 1);
  assert.equal(markets[0].id, '123');
  assert.equal(markets[0].currentPrice, 0.46);
});

test('polymarket source throws on network failure', async () => {
  const fakeFetch = async () => {
    throw new Error('down');
  };
  await assert.rejects(() => loadPolymarketMarkets(defaultConfig, fakeFetch as typeof fetch), /network/);
});

test('polymarket source throws on malformed payload and empty list', async () => {
  const malformedFetch = async () => ({ ok: true, status: 200, json: async () => ({}) }) as Response;
  await assert.rejects(() => loadPolymarketMarkets(defaultConfig, malformedFetch as typeof fetch), /expected an array/);

  const emptyFetch = async () => ({ ok: true, status: 200, json: async () => [] }) as Response;
  await assert.rejects(() => loadPolymarketMarkets(defaultConfig, emptyFetch as typeof fetch), /no active markets/);
});
