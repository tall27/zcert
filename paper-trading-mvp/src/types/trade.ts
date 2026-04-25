export interface SimulatedTrade {
  id: string;
  marketId: string;
  question: string;
  direction: 'yes' | 'no';
  entryPrice: number;
  positionSize: number;
  quantity: number;
  openedAt: string;
  maxHoldingMinutes: number;
}

export interface ClosedTrade extends SimulatedTrade {
  exitPrice: number;
  closedAt: string;
  pnl: number;
  roi: number;
  exitReason: 'target_hit' | 'stop_loss' | 'stale_thesis' | 'volume_spike_placeholder' | 'max_holding_time';
}

export interface PaperMetrics {
  finalBankroll: number;
  totalPnl: number;
  winRate: number;
  maxDrawdown: number;
  sharpeLike: number;
}
