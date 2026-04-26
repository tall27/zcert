import test from 'node:test';
import assert from 'node:assert/strict';
import { simulateExit } from '../src/agents/exit';
import { defaultConfig } from '../src/config/defaultConfig';

test('exit simulation produces deterministic reason and pnl', () => {
  const result = simulateExit(
    {
      id: 'sim_fx_market_1_1',
      marketId: 'fx_market_1',
      question: 'q',
      direction: 'yes',
      entryPrice: 0.4,
      positionSize: 100,
      quantity: 250,
      openedAt: '2026-01-01T00:00:00Z',
      maxHoldingMinutes: 60
    },
    defaultConfig
  );

  assert.equal(typeof result.pnl, 'number');
  assert.ok(result.exitReason.length > 0);
});
