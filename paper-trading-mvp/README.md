# Paper Trading MVP (Prediction Market Multi-Agent)

CLI-first TypeScript MVP for paper simulation and historical backtesting.

## Safety boundaries
- No live trading
- No private keys
- No wallet signing
- No order placement

## Install
```bash
cd paper-trading-mvp
npm install
```

## Modes
Paper mode (default):
```bash
npm run dev -- --mode paper
```

Backtest mode:
```bash
npm run dev -- --mode backtest
```

## Market source modes
```bash
npm run dev -- --mode paper --source sample
npm run dev -- --mode paper --source polymarket
```

> `--source polymarket` is read-only market data only.

## Historical trade ingestion modes
```bash
npm run dev -- --mode paper --trade-source sample
npm run dev -- --mode paper --trade-source csv --trade-file ./data/sample_trades.csv
npm run dev -- --mode paper --trade-source json --trade-file ./data/sample_trades.json
```

Backtest with deterministic fixture-style local data:
```bash
npm run dev -- --mode backtest --source sample --trade-source json --trade-file ./data/sample_trades.json
```

## CLI flags
- `--mode <paper|backtest>`
- `--source <sample|polymarket>`
- `--markets <path>`
- `--trade-source <sample|csv|json>`
- `--trade-file <path>`
- `--bankroll <number>`
- `--config <path>`
- `--llm <on|off>` (default off)



## Optional LLM research
Enable optional LLM enrichment (never required):
```bash
npm run dev -- --mode paper --llm on
```

- LLM adds at most one extra strategy signal.
- LLM cannot bypass scanner, risk sizing, strategy guardrails, or backtest rules.
- If API key is missing, provider fails, response is malformed, or timeout occurs, the system logs a warning and continues with deterministic research.
- LLM artifacts are persisted to `artifacts/llm_research.json`.

## Strategy guardrails
Before simulated execution, strategy decisions are gated by validation checks:
- minimum liquidity
- maximum spread
- minimum edge after spread
- minimum wallet signal sample size
- reject near-resolution markets
- reject stale price data
- reject trades where slippage removes edge

A simple slippage model estimates impact from trade size vs liquidity, then computes `edgeAfterSlippage`.
Rejected candidates are written to `artifacts/guardrail_rejections.json`.

## Backtest output
Backtest writes `artifacts/backtest_summary.json` and prints metrics including:
- total trades
- win rate
- realized PnL
- ROI
- max drawdown
- average holding time
- profit factor
- sharpe-like score

## Quality checks
```bash
npm run typecheck
npm test
npm run lint
```

## Artifacts
- `artifacts/run_summary.json`
- `artifacts/wallet_rankings.json`
- `artifacts/paper_ledger.json`
- `artifacts/backtest_summary.json`
- `artifacts/backtest_train_summary.json`
- `artifacts/backtest_test_summary.json`
- `artifacts/guardrail_rejections.json`

- `artifacts/report.md`
- `artifacts/report.html`
