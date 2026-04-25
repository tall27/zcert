import test from 'node:test';
import assert from 'node:assert/strict';
import { parseCliArgs } from '../src/utils/cli';

test('cli parses source polymarket', () => {
  const parsed = parseCliArgs(['--source', 'polymarket']);
  assert.equal(parsed.source, 'polymarket');
});

test('cli rejects unsupported source', () => {
  assert.throws(() => parseCliArgs(['--source', 'foo']), /Unsupported source/);
});
