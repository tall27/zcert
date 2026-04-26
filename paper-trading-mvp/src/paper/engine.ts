import path from 'node:path';
import { simulateExit } from '../agents/exit';
import { sizeDecision } from '../agents/risk';
import { AppConfig } from '../config/defaultConfig';
import { ScoredMarket } from '../types/market';
import { StrategyDecision } from '../types/signal';
import { SimulatedTrade } from '../types/trade';
import { WalletScore } from '../types/wallet';
import { writeJson } from '../utils/io';
import { evaluateStrategyGuards } from '../validation/strategyGuards';
import { computeMetrics, initLedger, persistLedger, recordClosedTrade } from './ledger';

export const runPaperEngine = (
  decisions: StrategyDecision[],
  scannedMarkets: ScoredMarket[],
  walletScores: WalletScore[],
  config: AppConfig
) => {
  const ledger = initLedger(config.engine.startingBankroll);
  const rejections: Array<{ marketId: string; reasons: string[] }> = [];

  if (decisions.length === 0) {
    persistLedger(ledger, config.engine.artifactsDir);
    writeJson(path.resolve(process.cwd(), config.engine.artifactsDir, 'guardrail_rejections.json'), rejections);
    return { ledger, metrics: computeMetrics(ledger, config.engine.startingBankroll), rejections };
  }

  for (const decision of decisions) {
    const market = scannedMarkets.find((m) => m.id === decision.marketId);
    if (!market) continue;

    const sized = sizeDecision(
      decision,
      ledger.bankroll,
      market.estimatedEdge,
      ledger.bankroll - config.engine.startingBankroll,
      0,
      config
    );

    if (!sized.allowed || sized.sizeUsd <= 0 || (sized.direction !== 'yes' && sized.direction !== 'no')) continue;

    const guard = evaluateStrategyGuards(market, decision, sized.sizeUsd, walletScores, config);
    if (!guard.allowed) {
      rejections.push({ marketId: market.id, reasons: guard.reasons });
      continue;
    }

    const trade: SimulatedTrade = {
      id: `sim_${market.id}_${ledger.trades.length + 1}`,
      marketId: market.id,
      question: market.question,
      direction: sized.direction,
      entryPrice: market.currentPrice,
      positionSize: sized.sizeUsd,
      quantity: sized.sizeUsd / Math.max(0.01, market.currentPrice),
      openedAt: new Date().toISOString(),
      maxHoldingMinutes: config.exits.maxHoldingHours * 60
    };

    const closed = simulateExit(trade, config);
    recordClosedTrade(ledger, closed);
  }

  persistLedger(ledger, config.engine.artifactsDir);
  writeJson(path.resolve(process.cwd(), config.engine.artifactsDir, 'guardrail_rejections.json'), rejections);
  const metrics = computeMetrics(ledger, config.engine.startingBankroll);
  return { ledger, metrics, rejections };
};
