import path from 'node:path';
import { sizeDecision } from '../agents/risk';
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

interface NearMiss {
  marketId: string;
  question: string;
  failedStage: string;
  failedReason: string;
  liquidity: number;
  spread: number;
  edge: number;
  edgeAfterSlippage: number;
  timeToResolutionHours: number;
  walletSignal: number;
}

interface PipelineDiagnostics {
  generatedAt: string;
  funnel: {
    marketsLoaded: number;
    scannerPassed: number;
    researchPassed: number;
    walletSignalsAvailable: number;
    strategyCandidates: number;
    riskApproved: number;
    guardrailApproved: number;
    executedTrades: number;
  };
  rejectionCountsByStage: Record<string, number>;
  rejectionReasonsByStage: Record<string, Record<string, number>>;
  topBlockers: Array<{ stage: string; reason: string; count: number }>;
  nearMissCandidates: NearMiss[];
}

const incrementReason = (obj: Record<string, number>, reason: string): void => {
  obj[reason] = (obj[reason] ?? 0) + 1;
};

export const runBacktest = (markets: any[], trades: WalletTrade[], config: AppConfig) => {
  assertHistoricalData(markets, trades);

  const scanned = runScanner(markets, config);
  const research = runResearch(config);
  const researchByMarket = new Map(research.map((r) => [r.market_id, r]));
  const walletScores = rankWallets(trades, config);
  const decisions = buildStrategyDecisions(scanned, research, walletScores, config);

  let bankroll = config.engine.startingBankroll;
  const equityCurve = [bankroll];
  const tradeResults: BacktestTradeResult[] = [];
  const rejections: Array<{ marketId: string; reasons: string[] }> = [];

  const stageRejected: Record<string, number> = {
    scanner: 0,
    research: 0,
    strategy: 0,
    risk: 0,
    guardrail: 0,
    execution: 0
  };
  const stageReasons: Record<string, Record<string, number>> = {
    scanner: {},
    research: {},
    strategy: {},
    risk: {},
    guardrail: {},
    execution: {}
  };

  const nearMissCandidates: NearMiss[] = [];

  const scannerPassed = scanned.filter((m) => m.scannerPass);
  const researchPassedSet = new Set(research.filter((r) => r.pass).map((r) => r.market_id));
  const strategyCandidates = decisions.filter((d) => d.direction !== 'none');

  let riskApproved = 0;
  let guardrailApproved = 0;

  for (const market of scanned) {
    const decision = decisions.find((d) => d.marketId === market.id);
    const researchReport = researchByMarket.get(market.id);
    const timeToResolutionHours = (new Date(market.resolutionAt).getTime() - Date.now()) / 3_600_000;
    const walletSignal = walletScores.length > 0 ? Math.max(...walletScores.map((w) => w.confidenceScore)) : 0;

    const addNearMiss = (failedStage: string, failedReason: string, edgeAfterSlippage = market.estimatedEdge): void => {
      nearMissCandidates.push({
        marketId: market.id,
        question: market.question,
        failedStage,
        failedReason,
        liquidity: market.liquidity,
        spread: market.spread,
        edge: market.estimatedEdge,
        edgeAfterSlippage,
        timeToResolutionHours,
        walletSignal
      });
    };

    if (!market.scannerPass) {
      stageRejected.scanner += 1;
      market.scannerReasons.forEach((reason) => incrementReason(stageReasons.scanner, reason));
      addNearMiss('scanner', market.scannerReasons[0] ?? 'scanner_rejected');
      continue;
    }

    if (!researchReport || !researchReport.pass) {
      stageRejected.research += 1;
      const reason = !researchReport ? 'missing_research_report' : 'research_confidence_or_edge_below_threshold';
      incrementReason(stageReasons.research, reason);
      addNearMiss('research', reason);
      continue;
    }

    if (!decision || decision.direction === 'none') {
      stageRejected.strategy += 1;
      const reason = decision?.rationale ?? 'no_strategy_decision';
      incrementReason(stageReasons.strategy, reason);
      addNearMiss('strategy', reason);
      continue;
    }

    const sized = sizeDecision(decision, bankroll, market.estimatedEdge, 0, tradeResults.length, config);
    if (!sized.allowed || sized.sizeUsd <= 0) {
      stageRejected.risk += 1;
      const reason = sized.rejectionReason ?? 'risk_rejected';
      incrementReason(stageReasons.risk, reason);
      addNearMiss('risk', reason);
      continue;
    }
    riskApproved += 1;

    const guard = evaluateStrategyGuards(market, decision, sized.sizeUsd, walletScores, config);
    if (!guard.allowed) {
      stageRejected.guardrail += 1;
      guard.reasons.forEach((reason) => incrementReason(stageReasons.guardrail, reason));
      addNearMiss('guardrail', guard.reasons[0] ?? 'guardrail_rejected', guard.slippage.edgeAfterSlippage);
      rejections.push({ marketId: market.id, reasons: guard.reasons });
      continue;
    }
    guardrailApproved += 1;

    const related = trades
      .filter((t) => t.marketId === market.id)
      .sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());

    if (related.length === 0) {
      stageRejected.execution += 1;
      incrementReason(stageReasons.execution, 'no_related_trades_for_market');
      addNearMiss('execution', 'no_related_trades_for_market', guard.slippage.edgeAfterSlippage);
      continue;
    }

    const totalStake = related.reduce((sum, t) => sum + t.stake, 0);
    const totalPayout = related.reduce((sum, t) => sum + t.payout, 0);
    const marketReturn = totalStake > 0 ? (totalPayout - totalStake) / totalStake : 0;

    const signedReturn = decision.direction === 'yes' ? marketReturn : -marketReturn;
    const pnl = sized.sizeUsd * signedReturn;
    const roi = sized.sizeUsd > 0 ? pnl / sized.sizeUsd : 0;

    bankroll += pnl;
    equityCurve.push(bankroll);

    const entryTime = related[0].timestamp;
    const exitTime = related[related.length - 1].timestamp;
    const holdingMs = Math.max(0, new Date(exitTime).getTime() - new Date(entryTime).getTime());

    tradeResults.push({ marketId: market.id, direction: decision.direction, entryTime, exitTime, holdingMs, pnl, roi });
  }

  const summary = calculateBacktestMetrics(tradeResults, config.engine.startingBankroll, bankroll, equityCurve);
  const { train, test } = splitTrainTest(tradeResults);
  const trainSummary = calculateBacktestMetrics(
    train,
    config.engine.startingBankroll,
    config.engine.startingBankroll + train.reduce((s, t) => s + t.pnl, 0),
    [config.engine.startingBankroll, config.engine.startingBankroll + train.reduce((s, t) => s + t.pnl, 0)]
  );
  const testStart = config.engine.startingBankroll + train.reduce((s, t) => s + t.pnl, 0);
  const testSummary = calculateBacktestMetrics(
    test,
    testStart,
    testStart + test.reduce((s, t) => s + t.pnl, 0),
    [testStart, testStart + test.reduce((s, t) => s + t.pnl, 0)]
  );

  const overfitWarning = trainSummary.roi > 0.1 && testSummary.roi < 0.02;

  const topBlockers = Object.entries(stageReasons)
    .flatMap(([stage, reasons]) => Object.entries(reasons).map(([reason, count]) => ({ stage, reason, count })))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);

  const pipelineDiagnostics: PipelineDiagnostics = {
    generatedAt: new Date().toISOString(),
    funnel: {
      marketsLoaded: markets.length,
      scannerPassed: scannerPassed.length,
      researchPassed: researchPassedSet.size,
      walletSignalsAvailable: walletScores.length,
      strategyCandidates: strategyCandidates.length,
      riskApproved,
      guardrailApproved,
      executedTrades: tradeResults.length
    },
    rejectionCountsByStage: stageRejected,
    rejectionReasonsByStage: stageReasons,
    topBlockers,
    nearMissCandidates: nearMissCandidates.sort((a, b) => b.edgeAfterSlippage - a.edgeAfterSlippage).slice(0, 20)
  };

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
    overfitWarning,
    pipelineDiagnostics
  };

  writeJson(path.resolve(process.cwd(), config.engine.artifactsDir, 'backtest_summary.json'), artifact);
  writeJson(path.resolve(process.cwd(), config.engine.artifactsDir, 'backtest_train_summary.json'), trainSummary);
  writeJson(path.resolve(process.cwd(), config.engine.artifactsDir, 'backtest_test_summary.json'), testSummary);
  writeJson(path.resolve(process.cwd(), config.engine.artifactsDir, 'guardrail_rejections.json'), rejections);
  writeJson(path.resolve(process.cwd(), config.engine.artifactsDir, 'pipeline_diagnostics.json'), pipelineDiagnostics);

  return artifact;
};
