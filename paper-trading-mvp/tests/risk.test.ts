import test from 'node:test';
import assert from 'node:assert/strict';
import { sizeDecision } from '../src/agents/risk';
import { defaultConfig } from '../src/config/defaultConfig';

test('risk blocks when max daily loss is hit', () => {
  const sized = sizeDecision(
    { marketId: 'm1', direction: 'yes', strategy: 'convergence', consensusCount: 2, confidence: 0.8, desiredExposure: 1, rationale: 'x' },
    10000,
    0.1,
    -999,
    0,
    defaultConfig
  );

  assert.equal(sized.allowed, false);
  assert.equal(sized.rejectionReason, 'max_daily_loss_hit');
});
