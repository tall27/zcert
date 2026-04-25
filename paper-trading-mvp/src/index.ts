import path from 'node:path';
import { runBacktest } from './backtest/engine';
import { runLlmResearch } from './agents/llmResearch';
import { runResearch } from './agents/research';
import { runScanner } from './agents/scanner';
import { buildStrategyDecisions } from './agents/strategy';
import { rankWallets } from './agents/walletIntel';
import { AppConfig, defaultConfig, mergeConfig } from './config/defaultConfig';
import { loadMarkets } from './data/marketSource';
import { loadPolymarketMarkets } from './data/polymarketMarketSource';
import { TradeSourceType, loadTradeHistory } from './data/polymarketTradeHistorySource';
import { runPaperEngine } from './paper/engine';
import { parseCliArgs } from './utils/cli';
import { readJson, writeJson } from './utils/io';

const loadConfig = (configPath?: string): AppConfig => {
  if (!configPath) return defaultConfig;
  const override = readJson(path.resolve(configPath)) as Partial<AppConfig>;
  return mergeConfig(defaultConfig, override);
};

const resolveMarkets = async (config: AppConfig, marketsPath?: string) => {
  if (config.marketSource === 'sample') return loadMarkets(marketsPath);
  if (config.marketSource === 'polymarket') return loadPolymarketMarkets(config);
  throw new Error(`Unsupported source '${String(config.marketSource)}'.`);
};

const main = async (): Promise<void> => {
  try {
    const args = parseCliArgs(process.argv.slice(2));
    const mode = args.mode ?? 'paper';
    const baseConfig = loadConfig(args.configPath);

    let config = args.bankroll
      ? mergeConfig(baseConfig, { engine: { ...baseConfig.engine, startingBankroll: args.bankroll } })
      : baseConfig;

    if (args.source) config = mergeConfig(config, { marketSource: args.source });
    if (args.llm) config = mergeConfig(config, { llm: { ...config.llm, enabled: args.llm === 'on' } });

    if (!Number.isFinite(config.engine.startingBankroll) || config.engine.startingBankroll <= 0) {
      throw new Error('startingBankroll must be a positive number.');
    }

    const tradeSource: TradeSourceType = args.tradeSource ?? 'sample';
    const markets = await resolveMarkets(config, args.marketsPath);
    const tradeHistory = loadTradeHistory(tradeSource, args.tradeFile, config);

    if (mode === 'backtest') {
      const result = runBacktest(markets, tradeHistory, config);
      console.log('--- Backtest Summary ---');
      console.log(result.summary);
      console.log(`Artifacts written to ${path.resolve(process.cwd(), config.engine.artifactsDir)}`);
      return;
    }

    const scanned = runScanner(markets, config);
    const survived = scanned.filter((m) => m.scannerPass);

    const research = runResearch(config);
    const llmReports = await runLlmResearch(survived, config);
    const wallets = rankWallets(tradeHistory, config);
    const decisions = buildStrategyDecisions(scanned, research, wallets, config, llmReports);
    const { ledger, metrics } = runPaperEngine(decisions, scanned, wallets, config);

    const summary = {
      mode,
      source: config.marketSource,
      trade_source: tradeSource,
      llm_enabled: config.llm.enabled,
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

    writeJson(path.resolve(process.cwd(), config.engine.artifactsDir, 'run_summary.json'), summary);

    console.log('--- Scanner Survivors ---');
    console.table(survived.map((m) => ({ id: m.id, edge: m.estimatedEdge.toFixed(4), price: m.currentPrice })));

    console.log('\n--- Wallet Rankings ---');
    console.table(wallets.map((w) => ({ wallet: w.wallet, trades: w.totalTrades, pnl: w.realizedPnl.toFixed(2), confidence: w.confidenceScore.toFixed(2) })));

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

void main();
