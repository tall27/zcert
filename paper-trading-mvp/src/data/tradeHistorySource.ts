import path from 'node:path';
import { WalletTrade } from '../types/wallet';
import { readJson } from '../utils/io';
import { validateWalletTrades } from '../utils/validation';

export const loadWalletTrades = (customPath?: string): WalletTrade[] => {
  const filePath = customPath ? path.resolve(customPath) : path.resolve(process.cwd(), 'data', 'sample_trades.json');
  return validateWalletTrades(readJson(filePath));
};
