import test from 'node:test';
import assert from 'node:assert/strict';
import { parseCliArgs } from '../src/utils/cli';

test('cli parses source polymarket and trade source csv', () => {
  const parsed = parseCliArgs(['--mode','backtest','--source', 'polymarket', '--trade-source', 'csv', '--trade-file', './fills.csv', '--llm', 'on', '--strict-data', 'off']);
  assert.equal(parsed.mode, 'backtest');
  assert.equal(parsed.source, 'polymarket');
  assert.equal(parsed.tradeSource, 'csv');
  assert.equal(parsed.tradeFile, './fills.csv');
  assert.equal(parsed.llm, 'on');
  assert.equal(parsed.strictData, 'off');
});

test('cli parses import mode flags', () => {
  const parsed = parseCliArgs(['--mode','import','--input','./raw.json','--input-type','markets','--output','./out.json']);
  assert.equal(parsed.mode, 'import');
  assert.equal(parsed.input, './raw.json');
  assert.equal(parsed.inputType, 'markets');
  assert.equal(parsed.output, './out.json');
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


test('cli rejects unsupported strict-data flag', () => {
  assert.throws(() => parseCliArgs(['--strict-data', 'maybe']), /Unsupported --strict-data value/);
});

test('cli rejects unsupported input-type flag', () => {
  assert.throws(() => parseCliArgs(['--input-type', 'bad']), /Unsupported --input-type value/);
});
