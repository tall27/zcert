import { MarketSourceType } from '../config/defaultConfig';

export interface CliArgs {
  marketsPath?: string;
  tradesPath?: string;
  bankroll?: number;
  configPath?: string;
  source?: MarketSourceType;
}

export const parseCliArgs = (argv: string[]): CliArgs => {
  const args: CliArgs = {};

  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    const next = argv[i + 1];

    if (token === '--markets') args.marketsPath = next;
    if (token === '--trades') args.tradesPath = next;
    if (token === '--config') args.configPath = next;
    if (token === '--source') {
      if (next !== 'sample' && next !== 'polymarket') {
        throw new Error(`Unsupported source '${next}'. Use 'sample' or 'polymarket'.`);
      }
      args.source = next;
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
