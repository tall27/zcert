export type SignalDirection = 'yes' | 'no' | 'none';

export interface ResearchReport {
  market_id: string;
  question: string;
  current_price: number;
  estimated_probability: number;
  edge: number;
  confidence: number;
  reasoning_summary: string;
  risk_flags: string[];
  pass: boolean;
}

export interface StrategyDecision {
  marketId: string;
  direction: SignalDirection;
  strategy: 'convergence' | 'arbitrage_placeholder' | 'copy_trade_placeholder' | 'none';
  consensusCount: number;
  confidence: number;
  desiredExposure: number;
  rationale: string;
}
