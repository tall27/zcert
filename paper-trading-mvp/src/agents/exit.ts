import { AppConfig } from '../config/defaultConfig';
import { ClosedTrade, SimulatedTrade } from '../types/trade';

const deterministicExitPrice = (trade: SimulatedTrade): number => {
  // Deterministic pseudo-simulation from trade id characters.
  const charScore = Array.from(trade.id).reduce((sum, c) => sum + c.charCodeAt(0), 0);
  const drift = ((charScore % 15) - 7) / 100;
  return Math.max(0.01, Math.min(0.99, trade.entryPrice + drift));
};

export const simulateExit = (trade: SimulatedTrade, config: AppConfig): ClosedTrade => {
  const exitPrice = deterministicExitPrice(trade);
  const pnl = (exitPrice - trade.entryPrice) * trade.quantity * (trade.direction === 'yes' ? 1 : -1);
  const roi = trade.positionSize === 0 ? 0 : pnl / trade.positionSize;

  const exitReason =
    roi >= config.exits.targetRoi
      ? 'target_hit'
      : roi <= config.exits.stopRoi
        ? 'stop_loss'
        : Math.abs(roi) < 0.02
          ? 'stale_thesis'
          : roi > 0.15
            ? 'volume_spike_placeholder'
            : 'max_holding_time';

  return {
    ...trade,
    exitPrice,
    closedAt: new Date(Date.now() + trade.maxHoldingMinutes * 60_000).toISOString(),
    pnl,
    roi,
    exitReason
  };
};
