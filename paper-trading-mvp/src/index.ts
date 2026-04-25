import path from 'node:path';
import { runResearch } from './agents/research';
import { runScanner } from './agents/scanner';
import { buildStrategyDecisions } from './agents/strategy';
import { rankWallets } from './agents/walletIntel';
import { AppConfig, defaultConfig, mergeConfig } from './config/defaultConfig';
import { loadMarkets } from './data/marketSource';
import { loadWalletTrades } from './data/tradeHistorySource';
import { runPaperEngine } from './paper/engine';
import { parseCliArgs } from './utils/cli';
import { readJson, writeJson } from './utils/io';

const loadConfig = (configPath?: string): AppConfig => {
  if (!configPath) return defaultConfig;
  const override = readJson(path.resolve(configPath)) as Partial<AppConfig>;
  return mergeConfig(defaultConfig, override);
};

const main = (): void => {
  try {
    const args = parseCliArgs(process.argv.slice(2));
    const baseConfig = loadConfig(args.configPath);
    const config = args.bankroll
      ? mergeConfig(baseConfig, { engine: { ...baseConfig.engine, startingBankroll: args.bankroll } })
      : baseConfig;

    if (!Number.isFinite(config.engine.startingBankroll) || config.engine.startingBankroll <= 0) {
      throw new Error('startingBankroll must be a positive number.');
    }

    const markets = loadMarkets(args.marketsPath);
    const scanned = runScanner(markets, config);
    const survived = scanned.filter((m) => m.scannerPass);

    const research = runResearch(config);
    const wallets = rankWallets(loadWalletTrades(args.tradesPath), config);
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
      sharpe_like: metrics.sharpeLike,
      note: ledger.trades.length === 0 ? 'No surviving trades were executed.' : 'Simulation completed.'
    };

    const summaryPath = path.resolve(process.cwd(), config.engine.artifactsDir, 'run_summary.json');
    writeJson(summaryPath, summary);

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
    console.log(`Artifacts written to ${path.resolve(process.cwd(), config.engine.artifactsDir)}`);
  } catch (error) {
    console.error(`Pipeline failed: ${(error as Error).message}`);
    process.exit(1);
  }
};

main();
