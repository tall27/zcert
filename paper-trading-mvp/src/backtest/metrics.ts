export interface BacktestTradeResult {
  marketId: string;
  direction: 'yes' | 'no';
  entryTime: string;
  exitTime: string;
  holdingMs: number;
  pnl: number;
  roi: number;
}

export interface BacktestSummary {
  totalTrades: number;
  winRate: number;
  realizedPnl: number;
  roi: number;
  maxDrawdown: number;
  averageHoldingTimeHours: number;
  profitFactor: number;
  sharpeLike: number;
  endingBankroll: number;
}

export const calculateMaxDrawdown = (equityCurve: number[]): number => {
  if (equityCurve.length === 0) return 0;
  let peak = equityCurve[0];
  let maxDrawdown = 0;
  for (const value of equityCurve) {
    peak = Math.max(peak, value);
    maxDrawdown = Math.max(maxDrawdown, peak - value);
  }
  return maxDrawdown;
};

export const calculateBacktestMetrics = (
  trades: BacktestTradeResult[],
  startingBankroll: number,
  endingBankroll: number,
  equityCurve: number[]
): BacktestSummary => {
  const totalTrades = trades.length;
  const wins = trades.filter((t) => t.pnl > 0);
  const losses = trades.filter((t) => t.pnl < 0);
  const realizedPnl = endingBankroll - startingBankroll;
  const roi = startingBankroll > 0 ? realizedPnl / startingBankroll : 0;
  const winRate = totalTrades > 0 ? wins.length / totalTrades : 0;
  const averageHoldingTimeHours =
    totalTrades > 0 ? trades.reduce((sum, t) => sum + t.holdingMs, 0) / totalTrades / 3_600_000 : 0;

  const grossProfit = wins.reduce((sum, t) => sum + t.pnl, 0);
  const grossLoss = Math.abs(losses.reduce((sum, t) => sum + t.pnl, 0));
  const profitFactor = grossLoss === 0 ? (grossProfit > 0 ? Number.POSITIVE_INFINITY : 0) : grossProfit / grossLoss;

  const returns = trades.map((t) => t.roi);
  const mean = returns.length ? returns.reduce((a, b) => a + b, 0) / returns.length : 0;
  const variance =
    returns.length > 1 ? returns.reduce((sum, r) => sum + (r - mean) ** 2, 0) / (returns.length - 1) : 0;
  const std = Math.sqrt(variance);
  const sharpeLike = std === 0 ? 0 : (mean / std) * Math.sqrt(Math.max(1, returns.length));

  return {
    totalTrades,
    winRate,
    realizedPnl,
    roi,
    maxDrawdown: calculateMaxDrawdown(equityCurve),
    averageHoldingTimeHours,
    profitFactor,
    sharpeLike,
    endingBankroll
  };
};
