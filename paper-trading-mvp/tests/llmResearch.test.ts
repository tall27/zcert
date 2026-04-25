import test from 'node:test';
import assert from 'node:assert/strict';
import { runLlmResearch } from '../src/agents/llmResearch';
import { mergeConfig, defaultConfig } from '../src/config/defaultConfig';
import { buildStrategyDecisions } from '../src/agents/strategy';
import { runPaperEngine } from '../src/paper/engine';
import { ScoredMarket } from '../src/types/market';

const market: ScoredMarket = {
  id: 'm1',
  question: 'Q',
  category: 'politics',
  currentPrice: 0.4,
  spread: 0.02,
  liquidity: 50000,
  volume24h: 10000,
  resolutionAt: new Date(Date.now() + 48 * 3600_000).toISOString(),
  estimatedProbability: 0.5,
  estimatedEdge: 0.1,
  scannerPass: true,
  scannerReasons: []
};

test('llm valid response parses', async () => {
  process.env.OPENAI_API_KEY = 'x';
  const cfg = mergeConfig(defaultConfig, { llm: { ...defaultConfig.llm, enabled: true, provider: 'openai' } });
  const fakeFetch = async () => ({
    ok: true,
    status: 200,
    json: async () => ({
      choices: [{ message: { content: JSON.stringify([{ marketId: 'm1', estimatedProbability: 0.6, confidence: 0.7, reasoningSummary: 'ok', riskFlags: ['x'], pass: true }]) } }]
    })
  }) as Response;

  const out = await runLlmResearch([market], cfg, fakeFetch as typeof fetch);
  assert.equal(out.length, 1);
  assert.equal(out[0].marketId, 'm1');
});

test('llm malformed json falls back', async () => {
  process.env.OPENAI_API_KEY = 'x';
  const cfg = mergeConfig(defaultConfig, { llm: { ...defaultConfig.llm, enabled: true, provider: 'openai' } });
  const fakeFetch = async () => ({ ok: true, status: 200, json: async () => ({ choices: [{ message: { content: 'not-json' } }] }) }) as Response;
  const out = await runLlmResearch([market], cfg, fakeFetch as typeof fetch);
  assert.equal(out.length, 0);
});

test('llm timeout/failure falls back', async () => {
  process.env.OPENAI_API_KEY = 'x';
  const cfg = mergeConfig(defaultConfig, { llm: { ...defaultConfig.llm, enabled: true, provider: 'openai', timeoutMs: 1 } });
  const hangingFetch = async () => await new Promise<Response>(() => undefined);
  const out = await runLlmResearch([market], cfg, hangingFetch as typeof fetch);
  assert.equal(out.length, 0);
});

test('llm pass cannot bypass guardrails', () => {
  const lowLiquidityMarket = { ...market, liquidity: 10 };
  const wallets = [{ wallet: 'w', totalTrades: 5, winRate: 0.6, realizedPnl: 10, roi: 0.1, averageTradeSize: 50, maxDrawdown: 5, categoryConcentration: 0.8, confidenceScore: 0.9, trustedSample: true, rankScore: 1 }];
  const research = [{ market_id: 'm1', question: 'Q', current_price: 0.4, estimated_probability: 0.6, edge: 0.2, confidence: 0.8, reasoning_summary: 'r', risk_flags: [], pass: true }];
  const llm = [{ marketId: 'm1', estimatedProbability: 0.7, confidence: 0.9, reasoningSummary: 'llm', riskFlags: [], pass: true }];

  const decisions = buildStrategyDecisions([lowLiquidityMarket], research, wallets, defaultConfig, llm);
  const out = runPaperEngine(decisions, [lowLiquidityMarket], wallets, defaultConfig);
  assert.equal(out.ledger.trades.length, 0);
  assert.equal(out.rejections.length > 0, true);
});
