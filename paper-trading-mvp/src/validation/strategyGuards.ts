import { AppConfig } from '../config/defaultConfig';
import { ScoredMarket } from '../types/market';
import { StrategyDecision } from '../types/signal';
import { WalletScore } from '../types/wallet';

export interface SlippageEstimate {
  estimatedSlippage: number;
  edgeAfterSlippage: number;
}

export interface GuardrailResult {
  allowed: boolean;
  reasons: string[];
  slippage: SlippageEstimate;
}

export const estimateSlippage = (liquidity: number, spread: number, tradeSize: number): SlippageEstimate => {
  const depthFactor = tradeSize / Math.max(1, liquidity);
  const estimatedSlippage = Math.min(0.2, depthFactor * 0.5 + spread * 0.25);
  return {
    estimatedSlippage,
    edgeAfterSlippage: 0
  };
};

export const evaluateStrategyGuards = (
  market: ScoredMarket,
  decision: StrategyDecision,
  tradeSize: number,
  walletScores: WalletScore[],
  config: AppConfig
): GuardrailResult => {
  const reasons: string[] = [];

  if (market.liquidity < config.guardrails.minLiquidity) reasons.push('liquidity_below_minimum');
  if (market.spread > config.guardrails.maxSpread) reasons.push('spread_above_maximum');

  const now = Date.now();
  const hoursToResolution = (new Date(market.resolutionAt).getTime() - now) / 3_600_000;
  if (hoursToResolution < config.guardrails.minHoursToResolution) reasons.push('too_close_to_resolution');

  const lastUpdatedAt = market.lastPriceUpdatedAt ? new Date(market.lastPriceUpdatedAt).getTime() : now;
  const staleMinutes = (now - lastUpdatedAt) / 60_000;
  if (staleMinutes > config.guardrails.maxPriceStaleMinutes) reasons.push('stale_price_data');

  const bestWalletSample = walletScores.length > 0 ? Math.max(...walletScores.map((w) => w.totalTrades)) : 0;
  if (bestWalletSample < config.guardrails.minWalletSampleSize) reasons.push('wallet_sample_too_small');

  const edgeAfterSpread = market.estimatedEdge - market.spread;
  if (edgeAfterSpread < config.guardrails.minEdgeAfterSpread) reasons.push('edge_after_spread_too_small');

  const slip = estimateSlippage(market.liquidity, market.spread, tradeSize);
  slip.edgeAfterSlippage = edgeAfterSpread - slip.estimatedSlippage;
  if (slip.edgeAfterSlippage <= 0) reasons.push('slippage_removes_edge');

  if (decision.direction === 'none') reasons.push('no_trade_signal');

  return {
    allowed: reasons.length === 0,
    reasons,
    slippage: slip
  };
};
