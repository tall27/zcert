import { Market } from '../types/market';
import { WalletTrade } from '../types/wallet';

const isObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const assertNumber = (value: unknown, field: string): number => {
  if (typeof value !== 'number' || Number.isNaN(value) || !Number.isFinite(value)) {
    throw new Error(`Invalid number for field '${field}'.`);
  }
  return value;
};

const assertString = (value: unknown, field: string): string => {
  if (typeof value !== 'string' || value.trim() === '') {
    throw new Error(`Invalid string for field '${field}'.`);
  }
  return value;
};

export const validateMarkets = (input: unknown): Market[] => {
  if (!Array.isArray(input)) throw new Error('Markets JSON must be an array.');
  if (input.length === 0) throw new Error('Markets JSON is empty.');

  return input.map((item, idx) => {
    if (!isObject(item)) throw new Error(`Market at index ${idx} must be an object.`);
    const resolutionAt = assertString(item.resolutionAt, `markets[${idx}].resolutionAt`);
    if (Number.isNaN(new Date(resolutionAt).getTime())) {
      throw new Error(`Invalid date for markets[${idx}].resolutionAt.`);
    }

    return {
      id: assertString(item.id, `markets[${idx}].id`),
      question: assertString(item.question, `markets[${idx}].question`),
      category: assertString(item.category, `markets[${idx}].category`) as Market['category'],
      currentPrice: assertNumber(item.currentPrice, `markets[${idx}].currentPrice`),
      spread: assertNumber(item.spread, `markets[${idx}].spread`),
      liquidity: assertNumber(item.liquidity, `markets[${idx}].liquidity`),
      volume24h: assertNumber(item.volume24h, `markets[${idx}].volume24h`),
      resolutionAt
    };
  });
};

export const validateWalletTrades = (input: unknown): WalletTrade[] => {
  if (!Array.isArray(input)) throw new Error('Trades JSON must be an array.');
  return input.map((item, idx) => {
    if (!isObject(item)) throw new Error(`Trade at index ${idx} must be an object.`);
    const timestamp = assertString(item.timestamp, `trades[${idx}].timestamp`);
    if (Number.isNaN(new Date(timestamp).getTime())) {
      throw new Error(`Invalid date for trades[${idx}].timestamp.`);
    }

    return {
      wallet: assertString(item.wallet, `trades[${idx}].wallet`),
      marketId: assertString(item.marketId, `trades[${idx}].marketId`),
      category: assertString(item.category, `trades[${idx}].category`) as WalletTrade['category'],
      stake: assertNumber(item.stake, `trades[${idx}].stake`),
      payout: assertNumber(item.payout, `trades[${idx}].payout`),
      timestamp
    };
  });
};
