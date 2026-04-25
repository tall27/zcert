import fs from 'node:fs';
import path from 'node:path';
import { runResearch } from './agents/research';
import { runScanner } from './agents/scanner';
import { buildStrategyDecisions } from './agents/strategy';
import { rankWallets } from './agents/walletIntel';
import { defaultConfig } from './config/defaultConfig';
import { loadMarkets } from './data/marketSource';
import { loadWalletTrades } from './data/tradeHistorySource';
import { runPaperEngine } from './paper/engine';

const main = (): void => {
  const config = defaultConfig;

  const markets = loadMarkets();
  const scanned = runScanner(markets, config);
  const survived = scanned.filter((m) => m.scannerPass);

  const research = runResearch(config);
  const wallets = rankWallets(loadWalletTrades(), config);
  const decisions = buildStrategyDecisions(scanned, research, wallets, config);
  const { ledger, metrics } = runPaperEngine(decisions, scanned, config);

  const summary = {
    scanned_markets: scanned.length,
    scanner_survivors: survived.length,
    selected_candidates: decisions.filter((d) => d.direction !== 'none').length,
    simulated_trades: ledger.trades.length,
    final_bankroll: metrics.finalBankroll,
    win_rate: metrics.winRate,
    drawdown: metrics.maxDrawdown,
    sharpe_like: metrics.sharpeLike
  };

  const summaryPath = path.resolve(process.cwd(), 'data', 'run_summary.json');
  fs.writeFileSync(summaryPath, JSON.stringify(summary, null, 2));

  console.log('--- Scanner Survivors ---');
  console.table(survived.map((m) => ({ id: m.id, edge: m.estimatedEdge.toFixed(4), price: m.currentPrice })));

  console.log('\n--- Strategy Candidates ---');
  console.table(decisions.map((d) => ({ market: d.marketId, direction: d.direction, rationale: d.rationale })));

  console.log('\n--- Simulated Trades ---');
  console.table(
    ledger.trades.map((t) => ({ market: t.marketId, pnl: t.pnl.toFixed(2), roi: t.roi.toFixed(4), exit: t.exitReason }))
  );

  console.log('\n--- Metrics ---');
  console.log(summary);
  console.log(`Ledger saved to ${path.resolve(process.cwd(), 'data', 'paper_ledger.json')}`);
};

main();
