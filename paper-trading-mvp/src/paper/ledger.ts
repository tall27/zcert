import path from 'node:path';
import { ClosedTrade, PaperMetrics } from '../types/trade';
import { writeJson } from '../utils/io';

export interface LedgerState {
  bankroll: number;
  trades: ClosedTrade[];
  equityCurve: number[];
}

export const initLedger = (startingBankroll: number): LedgerState => ({
  bankroll: startingBankroll,
  trades: [],
  equityCurve: [startingBankroll]
});

export const recordClosedTrade = (ledger: LedgerState, trade: ClosedTrade): void => {
  ledger.trades.push(trade);
  ledger.bankroll += trade.pnl;
  ledger.equityCurve.push(ledger.bankroll);
};

export const computeMetrics = (ledger: LedgerState, startingBankroll: number): PaperMetrics => {
  const wins = ledger.trades.filter((t) => t.pnl > 0).length;
  const totalPnl = ledger.bankroll - startingBankroll;
  const winRate = ledger.trades.length ? wins / ledger.trades.length : 0;

  let peak = ledger.equityCurve[0] ?? startingBankroll;
  let maxDrawdown = 0;
  for (const equity of ledger.equityCurve) {
    peak = Math.max(peak, equity);
    maxDrawdown = Math.max(maxDrawdown, peak - equity);
  }

  const returns = ledger.trades.map((t) => t.roi);
  const meanReturn = returns.length ? returns.reduce((a, b) => a + b, 0) / returns.length : 0;
  const variance =
    returns.length > 1
      ? returns.reduce((sum, r) => sum + (r - meanReturn) ** 2, 0) / (returns.length - 1)
      : 0;
  const std = Math.sqrt(variance);
  const sharpeLike = std === 0 ? 0 : (meanReturn / std) * Math.sqrt(Math.max(1, returns.length));

  return {
    finalBankroll: ledger.bankroll,
    totalPnl,
    winRate,
    maxDrawdown,
    sharpeLike
  };
};

export const persistLedger = (ledger: LedgerState, artifactsDir: string): void => {
  const outputPath = path.resolve(process.cwd(), artifactsDir, 'paper_ledger.json');
  writeJson(outputPath, ledger);
};
