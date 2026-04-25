# Paper Trading MVP (Prediction Market Multi-Agent)

A CLI-first TypeScript MVP for **simulated** prediction-market research and paper trading.

## What it does
- Scans local market data with configurable filters.
- Produces structured research reports.
- Ranks wallets from sample fills/trades.
- Combines signals with strategy consensus logic.
- Applies capped Kelly sizing + hard risk controls.
- Simulates exits and records reasons.
- Writes an auditable trade ledger and summary metrics.

## What it does **not** do
- No real trading.
- No private keys.
- No live exchange connectors.

## Quickstart
```bash
npm install
npm run dev
```

## Key output files
- `data/scanner_queue.json`
- `data/research_output.json`
- `data/top_wallets.json`
- `data/paper_ledger.json`
- `data/run_summary.json`

## Config
Edit `src/config/defaultConfig.ts` to tune scanner, strategy, risk, and exit behavior.

## Pipeline command behavior
`npm run dev` runs the full pipeline end-to-end and prints:
- scanned markets
- selected candidates
- simulated trades
- final bankroll
- win rate
- drawdown
