import path from 'node:path';
import { runScanner } from '../agents/scanner';
import { runResearch } from '../agents/research';
import { buildStrategyDecisions } from '../agents/strategy';
import { rankWallets } from '../agents/walletIntel';
import { AppConfig } from '../config/defaultConfig';
import { ScoredMarket } from '../types/market';
import { WalletTrade } from '../types/wallet';
import { writeJson } from '../utils/io';
import { evaluateStrategyGuards } from '../validation/strategyGuards';
import { BacktestTradeResult, calculateBacktestMetrics } from './metrics';

const assertHistoricalData = (markets: ScoredMarket[] | any[], trades: WalletTrade[]): void => {
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

const splitTrainTest = (trades: BacktestTradeResult[]) => {
  const sorted = [...trades].sort((a, b) => new Date(a.entryTime).getTime() - new Date(b.entryTime).getTime());
  const splitIdx = Math.max(1, Math.floor(sorted.length * 0.7));
  return {
    train: sorted.slice(0, splitIdx),
    test: sorted.slice(splitIdx)
  };
};

export const runBacktest = (markets: any[], trades: WalletTrade[], config: AppConfig) => {
  assertHistoricalData(markets, trades);

  const scanned = runScanner(markets, config);
  const research = runResearch(config);
  const walletScores = rankWallets(trades, config);
  const decisions = buildStrategyDecisions(scanned, research, walletScores, config);

  let bankroll = config.engine.startingBankroll;
  const equityCurve = [bankroll];
  const tradeResults: BacktestTradeResult[] = [];
  const rejections: Array<{ marketId: string; reasons: string[] }> = [];

  for (const decision of decisions) {
    if (decision.direction === 'none') continue;
    const market = scanned.find((m) => m.id === decision.marketId);
    if (!market) continue;

    const related = trades
      .filter((t) => t.marketId === market.id)
      .sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());

    if (related.length === 0) continue;

    const positionSize = Math.min(config.risk.maxPositionSize, bankroll * 0.05);
    const guard = evaluateStrategyGuards(market, decision, positionSize, walletScores, config);
    if (!guard.allowed) {
      rejections.push({ marketId: market.id, reasons: guard.reasons });
      continue;
    }

    const totalStake = related.reduce((sum, t) => sum + t.stake, 0);
    const totalPayout = related.reduce((sum, t) => sum + t.payout, 0);
    const marketReturn = totalStake > 0 ? (totalPayout - totalStake) / totalStake : 0;
    if (positionSize <= 0) continue;

    const signedReturn = decision.direction === 'yes' ? marketReturn : -marketReturn;
    const pnl = positionSize * signedReturn;
    const roi = positionSize > 0 ? pnl / positionSize : 0;

    bankroll += pnl;
    equityCurve.push(bankroll);

    const entryTime = related[0].timestamp;
    const exitTime = related[related.length - 1].timestamp;
    const holdingMs = Math.max(0, new Date(exitTime).getTime() - new Date(entryTime).getTime());

    tradeResults.push({ marketId: market.id, direction: decision.direction, entryTime, exitTime, holdingMs, pnl, roi });
  }

  const summary = calculateBacktestMetrics(tradeResults, config.engine.startingBankroll, bankroll, equityCurve);
  const { train, test } = splitTrainTest(tradeResults);
  const trainSummary = calculateBacktestMetrics(train, config.engine.startingBankroll, config.engine.startingBankroll + train.reduce((s, t) => s + t.pnl, 0), [config.engine.startingBankroll, config.engine.startingBankroll + train.reduce((s, t) => s + t.pnl, 0)]);
  const testStart = config.engine.startingBankroll + train.reduce((s, t) => s + t.pnl, 0);
  const testSummary = calculateBacktestMetrics(test, testStart, testStart + test.reduce((s, t) => s + t.pnl, 0), [testStart, testStart + test.reduce((s, t) => s + t.pnl, 0)]);

  const overfitWarning = trainSummary.roi > 0.1 && testSummary.roi < 0.02;

  const artifact = {
    mode: 'backtest',
    source: config.marketSource,
    tradeCountInput: trades.length,
    scannedMarkets: scanned.length,
    decisionCount: decisions.length,
    tradeResults,
    summary,
    trainSummary,
    testSummary,
    overfitWarning
  };

  writeJson(path.resolve(process.cwd(), config.engine.artifactsDir, 'backtest_summary.json'), artifact);
  writeJson(path.resolve(process.cwd(), config.engine.artifactsDir, 'backtest_train_summary.json'), trainSummary);
  writeJson(path.resolve(process.cwd(), config.engine.artifactsDir, 'backtest_test_summary.json'), testSummary);
  writeJson(path.resolve(process.cwd(), config.engine.artifactsDir, 'guardrail_rejections.json'), rejections);

  return artifact;
};
