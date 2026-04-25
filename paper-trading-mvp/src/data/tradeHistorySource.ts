import fs from 'node:fs';
import path from 'node:path';
import { WalletTrade } from '../types/wallet';

export const loadWalletTrades = (): WalletTrade[] => {
  const filePath = path.resolve(process.cwd(), 'data', 'sample_trades.json');
  return JSON.parse(fs.readFileSync(filePath, 'utf-8')) as WalletTrade[];
};
