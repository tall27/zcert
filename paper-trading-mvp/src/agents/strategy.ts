import { AppConfig } from '../config/defaultConfig';
import { ScoredMarket } from '../types/market';
import { LlmResearchReport, ResearchReport, StrategyDecision } from '../types/signal';
import { WalletScore } from '../types/wallet';

const walletDirectionalBias = (wallets: WalletScore[]): 'yes' | 'no' | 'none' => {
  if (!wallets.length) return 'none';
  const avgWinRate = wallets.reduce((sum, w) => sum + w.winRate, 0) / wallets.length;
  if (avgWinRate >= 0.55) return 'yes';
  if (avgWinRate <= 0.45) return 'no';
  return 'none';
};

export const buildStrategyDecisions = (
  scanned: ScoredMarket[],
  researchReports: ResearchReport[],
  wallets: WalletScore[],
  config: AppConfig,
  llmReports: LlmResearchReport[] = []
): StrategyDecision[] => {
  const researchByMarket = new Map(researchReports.map((r) => [r.market_id, r]));
  const llmByMarket = new Map(llmReports.map((r) => [r.marketId, r]));
  const walletBias = walletDirectionalBias(wallets);

  return scanned
    .filter((m) => m.scannerPass)
    .map((market) => {
      const report = researchByMarket.get(market.id);
      const llm = llmByMarket.get(market.id);
      const scannerSignal = market.estimatedProbability > market.currentPrice ? 'yes' : 'no';
      const researchSignal = report && report.pass ? (report.estimated_probability > report.current_price ? 'yes' : 'no') : 'none';
      const llmSignal = llm && llm.pass ? (llm.estimatedProbability > market.currentPrice ? 'yes' : 'no') : 'none';

      const signals = [scannerSignal, researchSignal, walletBias, llmSignal].filter((s) => s !== 'none');
      const yesVotes = signals.filter((s) => s === 'yes').length;
      const noVotes = signals.filter((s) => s === 'no').length;
      const consensusCount = Math.max(yesVotes, noVotes);

      if (signals.length === 0 || (yesVotes > 0 && noVotes > 0 && consensusCount < 2)) {
        return {
          marketId: market.id,
          direction: 'none',
          strategy: 'none',
          consensusCount,
          confidence: 0,
          desiredExposure: 0,
          rationale: 'Disagreement among scanner/research/wallet/llm signals.'
        } satisfies StrategyDecision;
      }

      if (consensusCount === 1) {
        const direction = yesVotes === 1 ? 'yes' : 'no';
        return {
          marketId: market.id,
          direction,
          strategy: 'copy_trade_placeholder',
          consensusCount,
          confidence: 0.55,
          desiredExposure: config.strategy.halfPositionExposure,
          rationale: `Single-signal ${direction.toUpperCase()} bias: half exposure.`
        } satisfies StrategyDecision;
      }

      const direction = yesVotes > noVotes ? 'yes' : 'no';
      return {
        marketId: market.id,
        direction,
        strategy: 'convergence',
        consensusCount,
        confidence: 0.5 + consensusCount * 0.12,
        desiredExposure: config.strategy.fullPositionExposure,
        rationale: `Consensus ${consensusCount}/4 with ${direction.toUpperCase()} bias.`
      } satisfies StrategyDecision;
    });
};
