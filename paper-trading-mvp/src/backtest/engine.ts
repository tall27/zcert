import path from 'node:path';
import { runScanner } from '../agents/scanner';
import { runResearch } from '../agents/research';
import { buildStrategyDecisions } from '../agents/strategy';
import { rankWallets } from '../agents/walletIntel';
import { AppConfig } from '../config/defaultConfig';
import { Market } from '../types/market';
import { WalletTrade } from '../types/wallet';
import { writeJson } from '../utils/io';
import { BacktestTradeResult, calculateBacktestMetrics } from './metrics';

const assertHistoricalData = (markets: Market[], trades: WalletTrade[]): void => {
  if (markets.length === 0) throw new Error('Backtest requires at least one historical market.');
  if (trades.length === 0) throw new Error('Backtest requires at least one historical trade/fill.');
  for (const trade of trades) {
    if (!Number.isFinite(trade.stake) || !Number.isFinite(trade.payout)) {
      throw new Error('Malformed historical trade: invalid stake or payout value.');
    }
    if (Number.isNaN(new Date(trade.timestamp).getTime())) {
      throw new Error('Malformed historical trade: invalid timestamp.');
    }
  }
};

export const runBacktest = (markets: Market[], trades: WalletTrade[], config: AppConfig) => {
  assertHistoricalData(markets, trades);

  const scanned = runScanner(markets, config);
  const research = runResearch(config);
  const walletScores = rankWallets(trades, config);
  const decisions = buildStrategyDecisions(scanned, research, walletScores, config);

  let bankroll = config.engine.startingBankroll;
  const equityCurve = [bankroll];
  const tradeResults: BacktestTradeResult[] = [];

  for (const decision of decisions) {
    if (decision.direction === 'none') continue;
    const market = scanned.find((m) => m.id === decision.marketId);
    if (!market) continue;

    const related = trades
      .filter((t) => t.marketId === market.id)
      .sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());

    if (related.length === 0) continue;

    const totalStake = related.reduce((sum, t) => sum + t.stake, 0);
    const totalPayout = related.reduce((sum, t) => sum + t.payout, 0);
    const marketReturn = totalStake > 0 ? (totalPayout - totalStake) / totalStake : 0;

    const positionSize = Math.min(config.risk.maxPositionSize, bankroll * 0.05);
    if (positionSize <= 0) continue;

    const signedReturn = decision.direction === 'yes' ? marketReturn : -marketReturn;
    const pnl = positionSize * signedReturn;
    const roi = positionSize > 0 ? pnl / positionSize : 0;

    bankroll += pnl;
    equityCurve.push(bankroll);

    const entryTime = related[0].timestamp;
    const exitTime = related[related.length - 1].timestamp;
    const holdingMs = Math.max(0, new Date(exitTime).getTime() - new Date(entryTime).getTime());

    tradeResults.push({
      marketId: market.id,
      direction: decision.direction,
      entryTime,
      exitTime,
      holdingMs,
      pnl,
      roi
    });
  }

  const summary = calculateBacktestMetrics(
    tradeResults,
    config.engine.startingBankroll,
    bankroll,
    equityCurve
  );

  const artifact = {
    mode: 'backtest',
    source: config.marketSource,
    tradeCountInput: trades.length,
    scannedMarkets: scanned.length,
    decisionCount: decisions.length,
    tradeResults,
    summary
  };

  writeJson(path.resolve(process.cwd(), config.engine.artifactsDir, 'backtest_summary.json'), artifact);
  return artifact;
};
