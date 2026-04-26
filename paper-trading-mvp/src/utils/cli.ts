import { MarketSourceType } from '../config/defaultConfig';
import { TradeSourceType } from '../data/polymarketTradeHistorySource';

export type RunMode = 'paper' | 'backtest' | 'import';

export interface CliArgs {
  marketsPath?: string;
  bankroll?: number;
  configPath?: string;
  source?: MarketSourceType;
  tradeSource?: TradeSourceType;
  tradeFile?: string;
  mode?: RunMode;
  llm?: 'on' | 'off';
  strictData?: 'on' | 'off';
  input?: string;
  inputType?: 'markets' | 'trades' | 'fills';
  output?: string;
}

export const parseCliArgs = (argv: string[]): CliArgs => {
  const args: CliArgs = {};

  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    const next = argv[i + 1];

    if (token === '--markets') args.marketsPath = next;
    if (token === '--trade-file') args.tradeFile = next;
    if (token === '--config') args.configPath = next;
    if (token === '--strict-data') {
      if (next !== 'on' && next !== 'off') throw new Error(`Unsupported --strict-data value '${next}'. Use 'on' or 'off'.`);
      args.strictData = next;
    }
    if (token === '--llm') {
      if (next !== 'on' && next !== 'off') throw new Error(`Unsupported --llm value '${next}'. Use 'on' or 'off'.`);
      args.llm = next;
    }
    if (token === '--mode') {
      if (next !== 'paper' && next !== 'backtest' && next !== 'import') {
        throw new Error(`Unsupported mode '${next}'. Use 'paper', 'backtest', or 'import'.`);
      }
      args.mode = next;
    }
    if (token === '--source') {
      if (next !== 'sample' && next !== 'polymarket') {
        throw new Error(`Unsupported source '${next}'. Use 'sample' or 'polymarket'.`);
      }
      args.source = next;
    }
    if (token === '--trade-source') {
      if (next !== 'sample' && next !== 'csv' && next !== 'json' && next !== 'fills') {
        throw new Error(`Unsupported trade source '${next}'. Use 'sample', 'csv', 'json', or 'fills'.`);
      }
      args.tradeSource = next;
    }

    if (token === '--input') args.input = next;
    if (token === '--output') args.output = next;
    if (token === '--input-type') {
      if (next !== 'markets' && next !== 'trades' && next !== 'fills') {
        throw new Error(`Unsupported --input-type value '${next}'. Use 'markets', 'trades', or 'fills'.`);
      }
      args.inputType = next;
    }

    if (token === '--bankroll') {
      const parsed = Number(next);
      if (!Number.isFinite(parsed) || parsed <= 0) {
        throw new Error(`Invalid --bankroll value '${next}'. Must be a positive number.`);
      }
      args.bankroll = parsed;
    }
  }

  return args;
};
