import { AppConfig } from '../config/defaultConfig';
import { StrategyDecision } from '../types/signal';

export interface SizedDecision extends StrategyDecision {
  sizeUsd: number;
  allowed: boolean;
  rejectionReason?: string;
}

export const sizeDecision = (
  decision: StrategyDecision,
  bankroll: number,
  estimatedEdge: number,
  dailyPnl: number,
  openPositions: number,
  config: AppConfig
): SizedDecision => {
  if (!Number.isFinite(bankroll) || bankroll <= 0) {
    throw new Error('Invalid bankroll for risk sizing.');
  }
  if (!Number.isFinite(estimatedEdge)) {
    throw new Error('Invalid estimated edge for risk sizing.');
  }

  if (decision.direction === 'none' || decision.desiredExposure <= 0) {
    return { ...decision, sizeUsd: 0, allowed: false, rejectionReason: 'no_trade_signal' };
  }

  if (dailyPnl <= -config.risk.maxDailyLoss) {
    return { ...decision, sizeUsd: 0, allowed: false, rejectionReason: 'max_daily_loss_hit' };
  }

  if (openPositions >= config.risk.maxOpenPositions) {
    return { ...decision, sizeUsd: 0, allowed: false, rejectionReason: 'max_open_positions_hit' };
  }

  const rawKelly = estimatedEdge / Math.max(0.2, 1 - estimatedEdge);
  const fStar = Math.max(0, Math.min(rawKelly * config.risk.cappedKellyFraction, 0.25));
  if (fStar <= 0) {
    return { ...decision, sizeUsd: 0, allowed: false, rejectionReason: 'f_star_non_positive' };
  }

  const sizeUsd = Math.min(bankroll * fStar * decision.desiredExposure, config.risk.maxPositionSize, bankroll * 0.2);

  return {
    ...decision,
    sizeUsd,
    allowed: sizeUsd > 0,
    rejectionReason: sizeUsd > 0 ? undefined : 'size_below_zero'
  };
};
