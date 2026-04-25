import fs from 'node:fs';
import path from 'node:path';
import { Market } from '../types/market';

export const loadMarkets = (): Market[] => {
  const filePath = path.resolve(process.cwd(), 'data', 'sample_markets.json');
  return JSON.parse(fs.readFileSync(filePath, 'utf-8')) as Market[];
};
