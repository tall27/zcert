import fs from 'node:fs';
import path from 'node:path';
import { Market } from '../types/market';
import { WalletTrade } from '../types/wallet';
import { writeJson } from '../utils/io';
import { validateMarkets, validateWalletTrades } from '../utils/validation';

export type ImportInputType = 'markets' | 'trades' | 'fills';

const parseNumber = (value: unknown, fallback = 0): number => {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string') {
    const parsed = Number(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return fallback;
};

const parseJsonFile = (inputPath: string): unknown[] => {
  const raw = JSON.parse(fs.readFileSync(inputPath, 'utf-8')) as unknown;
  if (!Array.isArray(raw)) throw new Error('Import input JSON must be an array of objects.');
  return raw;
};

const parseCsvLine = (line: string): string[] => {
  const out: string[] = [];
  let cell = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i += 1) {
    const c = line[i];
    if (c === '"') {
      inQuotes = !inQuotes;
      continue;
    }
    if (c === ',' && !inQuotes) {
      out.push(cell.trim());
      cell = '';
      continue;
    }
    cell += c;
  }
  out.push(cell.trim());
  return out;
};

const parseCsvFile = (inputPath: string): Record<string, string>[] => {
  const lines = fs.readFileSync(inputPath, 'utf-8').split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  if (lines.length < 2) throw new Error('CSV input must include a header and at least one data row.');
  const headers = parseCsvLine(lines[0]);
  return lines.slice(1).map((line, idx) => {
    const cells = parseCsvLine(line);
    if (cells.length !== headers.length) {
      throw new Error(`Malformed CSV row ${idx + 2}: expected ${headers.length} columns, got ${cells.length}.`);
    }
    return headers.reduce<Record<string, string>>((acc, h, i) => {
      acc[h] = cells[i] ?? '';
      return acc;
    }, {});
  });
};

const normalizeCategory = (value: unknown): Market['category'] => {
  const raw = String(value ?? 'other').toLowerCase();
  if (raw.includes('politic')) return 'politics';
  if (raw.includes('sport')) return 'sports';
  if (raw.includes('crypto') || raw.includes('bitcoin') || raw.includes('eth')) return 'crypto';
  if (raw.includes('macro') || raw.includes('econom')) return 'macro';
  return 'other';
};

const asMarkets = (rows: unknown[]): Market[] => {
  const mapped = rows.map((raw) => {
    const row = raw as Record<string, unknown>;
    const bid = parseNumber(row.bestBid ?? row.best_bid, 0.48);
    const ask = parseNumber(row.bestAsk ?? row.best_ask, 0.52);
    const currentPrice = parseNumber(
      row.currentPrice ?? row.current_price ?? row.price ?? row.lastPrice ?? row.last_price,
      parseNumber(row.yes_price, 0.5)
    );
    const spread = parseNumber(row.spread, Math.max(0, ask - bid));
    return {
      id: String(row.id ?? row.marketId ?? row.market_id ?? row.condition_id ?? ''),
      question: String(row.question ?? row.title ?? row.market_question ?? ''),
      category: normalizeCategory(row.category),
      currentPrice: Math.min(0.99, Math.max(0.01, currentPrice || 0.5)),
      spread: Math.max(0, Math.min(0.5, spread)),
      liquidity: parseNumber(row.liquidity ?? row.liquidityNum ?? row.totalLiquidity ?? row.volume ?? row.volumeNum, 1),
      volume24h: parseNumber(row.volume24h ?? row.volume_24h ?? row.volume ?? row.usd_volume, 0),
      resolutionAt: String(row.resolutionAt ?? row.endDate ?? row.closeTime ?? row.closedTime ?? row.resolution_time ?? new Date().toISOString()),
      lastPriceUpdatedAt: String(row.lastPriceUpdatedAt ?? row.updatedAt ?? row.last_updated_at ?? new Date().toISOString())
    } satisfies Market;
  });
  return validateMarkets(mapped);
};

const asTrades = (rows: unknown[]): WalletTrade[] => {
  const mapped = rows.map((raw) => {
    const row = raw as Record<string, unknown>;
    const stake = parseNumber(row.stake ?? row.usd_amount ?? row.notional ?? row.amount ?? row.size, 0);
    const price = parseNumber(row.price ?? row.yes_price ?? row.avg_price, 0.5);
    const payout = parseNumber(row.payout, stake * (price > 0 ? 1 / Math.max(0.01, price) : 1));

    return {
      wallet: String(row.wallet ?? row.maker ?? row.taker ?? row.account ?? 'unknown_wallet'),
      marketId: String(row.marketId ?? row.market_id ?? row.id ?? row.condition_id ?? ''),
      category: normalizeCategory(row.category),
      stake,
      payout,
      timestamp: String(row.timestamp ?? row.createdAt ?? row.created_at ?? row.time ?? new Date().toISOString())
    } satisfies WalletTrade;
  });

  return validateWalletTrades(mapped);
};

export const importAndNormalize = (inputPath: string, inputType: ImportInputType, outputPath: string) => {
  const resolvedInput = path.resolve(inputPath);
  if (!fs.existsSync(resolvedInput)) throw new Error(`Import input does not exist: ${resolvedInput}`);

  const rows = resolvedInput.endsWith('.csv') ? parseCsvFile(resolvedInput) : parseJsonFile(resolvedInput);

  if (inputType === 'markets') {
    const markets = asMarkets(rows);
    writeJson(path.resolve(outputPath), markets);
    return { count: markets.length, outputType: 'markets' as const };
  }

  const trades = asTrades(rows);
  writeJson(path.resolve(outputPath), trades);
  return { count: trades.length, outputType: 'trades' as const };
};
