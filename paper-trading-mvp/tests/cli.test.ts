import test from 'node:test';
import assert from 'node:assert/strict';
import { parseCliArgs } from '../src/utils/cli';

test('cli parses source polymarket and trade source csv', () => {
  const parsed = parseCliArgs(['--mode','backtest','--source', 'polymarket', '--trade-source', 'csv', '--trade-file', './fills.csv', '--llm', 'on']);
  assert.equal(parsed.mode, 'backtest');
  assert.equal(parsed.source, 'polymarket');
  assert.equal(parsed.tradeSource, 'csv');
  assert.equal(parsed.tradeFile, './fills.csv');
  assert.equal(parsed.llm, 'on');
});

test('cli rejects unsupported source', () => {
  assert.throws(() => parseCliArgs(['--source', 'foo']), /Unsupported source/);
});

test('cli rejects unsupported trade source', () => {
  assert.throws(() => parseCliArgs(['--trade-source', 'foo']), /Unsupported trade source/);
});


test('cli rejects unsupported mode', () => {
  assert.throws(() => parseCliArgs(['--mode', 'live']), /Unsupported mode/);
});


test('cli rejects unsupported llm flag', () => {
  assert.throws(() => parseCliArgs(['--llm', 'maybe']), /Unsupported --llm value/);
});
