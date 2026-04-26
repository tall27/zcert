import path from 'node:path';
import { Market } from '../types/market';
import { readJson } from '../utils/io';
import { validateMarkets } from '../utils/validation';

export const loadMarkets = (customPath?: string): Market[] => {
  const filePath = customPath ? path.resolve(customPath) : path.resolve(process.cwd(), 'data', 'sample_markets.json');
  return validateMarkets(readJson(filePath));
};
