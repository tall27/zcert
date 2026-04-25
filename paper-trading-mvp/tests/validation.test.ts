import test from 'node:test';
import assert from 'node:assert/strict';
import { validateMarkets } from '../src/utils/validation';

test('validation fails clearly on malformed market json', () => {
  assert.throws(() => validateMarkets([{ id: 'bad' }]), /Invalid string for field 'markets\[0\]\.resolutionAt'/);
});
