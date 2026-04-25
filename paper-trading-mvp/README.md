# Paper Trading MVP (Prediction Market Multi-Agent)

CLI-first TypeScript MVP for **offline simulated** prediction-market research and execution.

## Safety boundaries
- No live trading
- No private keys
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

## Run with flags
```bash
npm run dev -- --markets ./data/sample_markets.json --trades ./data/sample_trades.json --bankroll 12000
npm run dev -- --config ./config.override.json
```

### Supported CLI flags
- `--markets <path>` custom markets JSON
- `--trades <path>` custom trade history JSON
- `--bankroll <number>` override starting bankroll
- `--config <path>` JSON config override
- `--source <sample|polymarket>` market data source selector

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
- `artifacts/top_wallets.json`
- `artifacts/paper_ledger.json`
- `artifacts/run_summary.json`

## Example console output
```text
--- Scanner Survivors ---
(index) id                  edge      price
0       mkt_us_election...  0.0625    0.54

--- Strategy Candidates ---
(index) market                 direction rationale
0       mkt_us_election_2028   yes       Consensus 3/3 with YES bias.

--- Simulated Trades ---
(index) market                 pnl     roi      exit
0       mkt_us_election_2028   30.86   0.0926   max_holding_time

--- Metrics ---
{ scanned_markets: 5, simulated_trades: 3, final_bankroll: 10030.82 }
Artifacts written to /workspace/zcert/paper-trading-mvp/artifacts
```

## Error handling
The CLI fails clearly for:
- missing input files
- malformed JSON
- invalid numeric inputs (including bankroll)
- empty markets input

## Config
Default thresholds live in `src/config/defaultConfig.ts`.
