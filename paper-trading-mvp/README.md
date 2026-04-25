# Paper Trading MVP (Prediction Market Multi-Agent)

CLI-first TypeScript MVP for **offline simulated** prediction-market research and execution.

## Safety boundaries
- No live trading
- No private keys
- No wallet signing
- No real order placement

## Install
```bash
cd paper-trading-mvp
npm install
```

## Run full simulation
```bash
npm run dev
```

## Market source modes
Sample/offline mode (default):
```bash
npm run dev -- --source sample
```

Live read-only Polymarket market data mode:
```bash
npm run dev -- --source polymarket
```

> Warning: polymarket mode is **read-only market data**. This project does **not** place orders, sign wallets, or execute live trades.

## Historical trade ingestion modes
Use sample trade history (default):
```bash
npm run dev -- --trade-source sample
```

Load local CSV fills:
```bash
npm run dev -- --trade-source csv --trade-file ./data/sample_trades.csv
```

Load local JSON fills:
```bash
npm run dev -- --trade-source json --trade-file ./data/sample_trades.json
```

## Run with flags
```bash
npm run dev -- --markets ./data/sample_markets.json --trade-source sample --bankroll 12000
npm run dev -- --config ./config.override.json
```

### Supported CLI flags
- `--markets <path>` custom markets JSON
- `--bankroll <number>` override starting bankroll
- `--config <path>` JSON config override
- `--source <sample|polymarket>` market data source selector
- `--trade-source <sample|csv|json>` historical trade source selector
- `--trade-file <path>` required for `csv`/`json` trade source

## Quality checks
```bash
npm run typecheck
npm test
npm run lint
```

## Expected output artifacts
All generated files go to `/artifacts`:
- `artifacts/scanner_queue.json`
- `artifacts/research_output.json`
- `artifacts/wallet_rankings.json`
- `artifacts/paper_ledger.json`
- `artifacts/run_summary.json`

## Error handling
The CLI fails clearly for:
- missing input files
- malformed JSON
- malformed CSV rows
- invalid numeric inputs (including bankroll)
- empty markets input

## Config
Default thresholds live in `src/config/defaultConfig.ts`.
