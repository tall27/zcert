import path from 'node:path';
import { AppConfig } from '../config/defaultConfig';
import { ScoredMarket } from '../types/market';
import { LlmResearchReport } from '../types/signal';
import { writeJson } from '../utils/io';

const validateLlmReports = (input: unknown): LlmResearchReport[] => {
  if (!Array.isArray(input)) throw new Error('LLM response must be a JSON array.');
  return input.map((item, idx) => {
    if (typeof item !== 'object' || item === null) throw new Error(`LLM response item ${idx} must be an object.`);
    const obj = item as Record<string, unknown>;
    if (typeof obj.marketId !== 'string') throw new Error(`LLM response item ${idx} missing marketId.`);
    if (typeof obj.estimatedProbability !== 'number') throw new Error(`LLM response item ${idx} missing estimatedProbability.`);
    if (typeof obj.confidence !== 'number') throw new Error(`LLM response item ${idx} missing confidence.`);
    if (typeof obj.reasoningSummary !== 'string') throw new Error(`LLM response item ${idx} missing reasoningSummary.`);
    if (!Array.isArray(obj.riskFlags)) throw new Error(`LLM response item ${idx} missing riskFlags.`);
    if (typeof obj.pass !== 'boolean') throw new Error(`LLM response item ${idx} missing pass.`);

    return {
      marketId: obj.marketId,
      estimatedProbability: obj.estimatedProbability,
      confidence: obj.confidence,
      reasoningSummary: obj.reasoningSummary,
      riskFlags: obj.riskFlags.map(String),
      pass: obj.pass
    };
  });
};

const withTimeout = async <T>(promise: Promise<T>, ms: number): Promise<T> => {
  return await Promise.race([
    promise,
    new Promise<T>((_, reject) => setTimeout(() => reject(new Error('LLM request timeout.')), ms))
  ]);
};

const extractText = (provider: AppConfig['llm']['provider'], payload: unknown): string => {
  const obj = payload as Record<string, unknown>;
  if (provider === 'openai') {
    const choices = obj.choices as Array<{ message?: { content?: string } }> | undefined;
    return choices?.[0]?.message?.content ?? '';
  }
  if (provider === 'anthropic') {
    const content = obj.content as Array<{ text?: string }> | undefined;
    return content?.[0]?.text ?? '';
  }
  return '';
};

export const runLlmResearch = async (
  markets: ScoredMarket[],
  config: AppConfig,
  fetchImpl: typeof fetch = fetch
): Promise<LlmResearchReport[]> => {
  const artifactPath = path.resolve(process.cwd(), config.engine.artifactsDir, 'llm_research.json');

  if (!config.llm.enabled || config.llm.provider === 'none') {
    writeJson(artifactPath, []);
    return [];
  }

  const key = config.llm.provider === 'openai' ? process.env.OPENAI_API_KEY : process.env.ANTHROPIC_API_KEY;
  if (!key) {
    console.warn('[llm] Missing API key. Falling back to deterministic research.');
    writeJson(artifactPath, []);
    return [];
  }

  const selected = markets.slice(0, config.llm.maxMarketsPerRun);
  const prompt = `Return ONLY strict JSON array with fields: marketId, estimatedProbability, confidence, reasoningSummary, riskFlags, pass for markets: ${JSON.stringify(selected.map((m) => ({ id: m.id, question: m.question, price: m.currentPrice, edge: m.estimatedEdge })))}.`;

  try {
    const req =
      config.llm.provider === 'openai'
        ? fetchImpl('https://api.openai.com/v1/chat/completions', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              Authorization: `Bearer ${key}`
            },
            body: JSON.stringify({ model: config.llm.model, messages: [{ role: 'user', content: prompt }] })
          })
        : fetchImpl('https://api.anthropic.com/v1/messages', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'x-api-key': key,
              'anthropic-version': '2023-06-01'
            },
            body: JSON.stringify({ model: config.llm.model, max_tokens: 1024, messages: [{ role: 'user', content: prompt }] })
          });

    const response = await withTimeout(req, config.llm.timeoutMs);
    if (!response.ok) throw new Error(`LLM request failed with status ${response.status}.`);

    const payload = await response.json();
    const text = extractText(config.llm.provider, payload);
    const parsed = JSON.parse(text) as unknown;
    const reports = validateLlmReports(parsed);
    writeJson(artifactPath, reports);
    return reports;
  } catch (error) {
    console.warn(`[llm] ${String((error as Error).message)} Falling back to deterministic research.`);
    writeJson(artifactPath, []);
    return [];
  }
};

export const __private__ = {
  validateLlmReports,
  extractText
};
