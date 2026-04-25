# Architecture Overview

This MVP is a CLI-first, file-backed paper-trading workflow inspired by a multi-agent prediction market system.

## Flow
1. Scanner reads market JSON, applies filtering/scoring, and writes `artifacts/scanner_queue.json`.
2. Research reads scanner queue and writes `artifacts/research_output.json`.
3. Wallet Intelligence ranks wallets from trade history and writes `artifacts/top_wallets.json`.
4. Strategy combines scanner/research/wallet signals with consensus logic.
5. Risk/Sizing applies capped Kelly + hard risk limits.
6. Exit simulates deterministic exits and assigns exit reason.
7. Paper Engine updates bankroll, writes `artifacts/paper_ledger.json`, and computes metrics.
8. Entry point writes `artifacts/run_summary.json`.

## Input validation and safety
- Runtime JSON validation for market/trade inputs.
- Clear error messages for malformed data and invalid numeric inputs.
- No live trading, private keys, or order routing.
