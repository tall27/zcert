import { AppConfig } from '../config/defaultConfig';
import { ScoredMarket } from '../types/market';
import { ResearchReport, StrategyDecision } from '../types/signal';
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
  config: AppConfig
): StrategyDecision[] => {
  const researchByMarket = new Map(researchReports.map((r) => [r.market_id, r]));
  const walletBias = walletDirectionalBias(wallets);

  return scanned
    .filter((m) => m.scannerPass)
    .map((market) => {
      const report = researchByMarket.get(market.id);
      const scannerSignal = market.estimatedProbability > market.currentPrice ? 'yes' : 'no';
      const researchSignal = report && report.pass ? (report.estimated_probability > report.current_price ? 'yes' : 'no') : 'none';

      const signals = [scannerSignal, researchSignal, walletBias].filter((s) => s !== 'none');
      const yesVotes = signals.filter((s) => s === 'yes').length;
      const noVotes = signals.filter((s) => s === 'no').length;
      const consensusCount = Math.max(yesVotes, noVotes);

      if (consensusCount < 2) {
        return {
          marketId: market.id,
          direction: 'none',
          strategy: 'none',
          consensusCount,
          confidence: 0,
          desiredExposure: 0,
          rationale: 'Insufficient agreement among scanner/research/wallet signals.'
        } satisfies StrategyDecision;
      }

      const direction = yesVotes > noVotes ? 'yes' : 'no';
      const desiredExposure =
        consensusCount >= 2 ? config.strategy.fullPositionExposure : config.strategy.halfPositionExposure;

      return {
        marketId: market.id,
        direction,
        strategy: 'convergence',
        consensusCount,
        confidence: 0.5 + consensusCount * 0.15,
        desiredExposure,
        rationale: `Consensus ${consensusCount}/3 with ${direction.toUpperCase()} bias.`
      } satisfies StrategyDecision;
    });
};
