import { AppConfig } from '../config/defaultConfig';
import { Market } from '../types/market';

interface RawPolymarketMarket {
  id?: string;
  question?: string;
  active?: boolean;
  closed?: boolean;
  endDate?: string;
  liquidity?: number | string;
  volume?: number | string;
  bestBid?: number | string;
  bestAsk?: number | string;
  outcomePrices?: string | number[];
  category?: string;
}

const parseNumber = (value: unknown, fallback = 0): number => {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string') {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return fallback;
};

const parseOutcomePrices = (value: unknown): number[] => {
  if (Array.isArray(value)) return value.map((v) => parseNumber(v, 0));
  if (typeof value === 'string') {
    try {
      const parsed = JSON.parse(value) as unknown;
      return Array.isArray(parsed) ? parsed.map((v) => parseNumber(v, 0)) : [];
    } catch {
      return [];
    }
  }
  return [];
};

const normalizeMarket = (raw: RawPolymarketMarket): Market | null => {
  if (!raw.id || !raw.question) return null;
  if (raw.closed || raw.active === false) return null;

  const prices = parseOutcomePrices(raw.outcomePrices);
  const currentPrice = prices.length > 0 ? Math.min(0.99, Math.max(0.01, prices[0])) : 0.5;

  const bestBid = parseNumber(raw.bestBid, currentPrice - 0.02);
  const bestAsk = parseNumber(raw.bestAsk, currentPrice + 0.02);
  const spread = Math.max(0, Math.min(0.5, bestAsk - bestBid));

  return {
    id: String(raw.id),
    question: String(raw.question),
    category: (raw.category ?? 'other') as Market['category'],
    currentPrice,
    spread,
    liquidity: parseNumber(raw.liquidity, 0),
    volume24h: parseNumber(raw.volume, 0),
    resolutionAt: raw.endDate && !Number.isNaN(new Date(raw.endDate).getTime()) ? raw.endDate : new Date(Date.now() + 7 * 86400000).toISOString()
  };
};

export const loadPolymarketMarkets = async (
  config: AppConfig,
  fetchImpl: typeof fetch = fetch
): Promise<Market[]> => {
  const endpoint = `${config.polymarket.apiBase}/markets?active=true&closed=false&limit=${config.polymarket.limit}`;

  let response: Response;
  try {
    response = await fetchImpl(endpoint);
  } catch (error) {
    throw new Error(`Polymarket market fetch failed (network): ${(error as Error).message}`);
  }

  if (!response.ok) {
    throw new Error(`Polymarket market fetch failed with status ${response.status}.`);
  }

  let payload: unknown;
  try {
    payload = await response.json();
  } catch (error) {
    throw new Error(`Polymarket market fetch returned invalid JSON: ${(error as Error).message}`);
  }

  if (!Array.isArray(payload)) {
    throw new Error('Polymarket response malformed: expected an array of markets.');
  }

  const normalized = payload
    .map((item) => normalizeMarket(item as RawPolymarketMarket))
    .filter((m): m is Market => m !== null);

  if (normalized.length === 0) {
    throw new Error('Polymarket response contained no active markets after normalization.');
  }

  return normalized;
};
