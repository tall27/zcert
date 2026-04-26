import fs from 'node:fs';
import path from 'node:path';
import { AppConfig } from '../config/defaultConfig';
import { WalletTrade } from '../types/wallet';
import { readJson } from '../utils/io';
import { validateWalletTrades } from '../utils/validation';

export type TradeSourceType = 'sample' | 'csv' | 'json' | 'fills';

const parseCsvLine = (line: string): string[] => {
  const cells: string[] = [];
  let current = '';
  let inQuotes = false;

  for (let i = 0; i < line.length; i += 1) {
    const char = line[i];
    if (char === '"') {
      inQuotes = !inQuotes;
      continue;
    }
    if (char === ',' && !inQuotes) {
      cells.push(current.trim());
      current = '';
      continue;
    }
    current += char;
  }
  cells.push(current.trim());
  return cells;
};

const parseCsvTrades = (csv: string): WalletTrade[] => {
  const lines = csv.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  if (lines.length < 2) throw new Error('CSV trade file must contain a header and at least one row.');

  const headers = parseCsvLine(lines[0]);
  const required = ['wallet', 'marketId', 'category', 'stake', 'payout', 'timestamp'];
  for (const field of required) {
    if (!headers.includes(field)) throw new Error(`CSV trade file missing required header '${field}'.`);
  }

  const rows = lines.slice(1).map((line, idx) => {
    const values = parseCsvLine(line);
    if (values.length !== headers.length) {
      throw new Error(`Malformed CSV row ${idx + 2}: column count mismatch.`);
    }
    const row: Record<string, string> = {};
    headers.forEach((header, i) => {
      row[header] = values[i] ?? '';
    });
    return row;
  });

  return validateWalletTrades(
    rows.map((row) => ({
      wallet: row.wallet,
      marketId: row.marketId,
      category: row.category,
      stake: Number(row.stake),
      payout: Number(row.payout),
      timestamp: row.timestamp
    }))
  );
};

export const loadPolymarketTradeHistoryFromApi = async (
  config: AppConfig,
  fetchImpl: typeof fetch = fetch
): Promise<WalletTrade[]> => {
  if (!config.polymarket.tradeHistoryEndpoint) {
    throw new Error('No tradeHistoryEndpoint configured for Polymarket read-only API adapter.');
  }

  const endpoint = config.polymarket.tradeHistoryEndpoint;
  let response: Response;
  try {
    response = await fetchImpl(endpoint);
  } catch (error) {
    throw new Error(`Trade history fetch failed (network): ${(error as Error).message}`);
  }

  if (!response.ok) throw new Error(`Trade history fetch failed with status ${response.status}.`);

  const payload = await response.json();
  if (!Array.isArray(payload)) throw new Error('Trade history API response malformed: expected array.');
  return validateWalletTrades(payload);
};

export const loadTradeHistory = (
  source: TradeSourceType,
  filePath: string | undefined,
  config: AppConfig
): WalletTrade[] => {
  if (source === 'sample') {
    const samplePath = filePath ? path.resolve(filePath) : path.resolve(process.cwd(), 'data', 'sample_trades.json');
    return validateWalletTrades(readJson(samplePath));
  }

  if (!filePath) throw new Error(`--trade-file is required when --trade-source is '${source}'.`);

  const resolved = path.resolve(filePath);
  if (!fs.existsSync(resolved)) throw new Error(`Trade file does not exist: ${resolved}`);

  if (source === 'json') {
    return validateWalletTrades(readJson(resolved));
  }

  if (source === 'csv' || source === 'fills') {
    const raw = fs.readFileSync(resolved, 'utf-8');
    return parseCsvTrades(raw);
  }

  throw new Error(`Unsupported trade source '${source}'.`);
};

export const __private__ = {
  parseCsvLine,
  parseCsvTrades
};
