import { AppConfig, defaultConfig } from '../config/defaultConfig';
import { WalletTrade } from '../types/wallet';
import { loadTradeHistory } from './polymarketTradeHistorySource';

export const loadWalletTrades = (customPath?: string, config: AppConfig = defaultConfig): WalletTrade[] =>
  loadTradeHistory(customPath ? 'json' : 'sample', customPath, config);
