# Architecture Overview

This MVP implements a CLI-first, file-backed paper-trading pipeline inspired by a multi-agent prediction market workflow.

## Flow
1. **Scanner Agent** reads `data/sample_markets.json`, applies filter gates, and writes `data/scanner_queue.json`.
2. **Research Agent** reads scanner queue and emits structured reports to `data/research_output.json`.
3. **Wallet Intelligence Agent** ranks wallets from `data/sample_trades.json` and writes `data/top_wallets.json`.
4. **Strategy Agent** combines scanner + research + wallet signals into consensus decisions.
5. **Risk/Sizing Agent** applies capped Kelly and hard risk limits.
6. **Exit Agent** deterministically simulates exits and labels each exit reason.
7. **Paper Engine** updates bankroll, persists `data/paper_ledger.json`, and computes metrics.

## Persistence
- JSON-only persistence for auditability and zero external dependencies.
- Every step creates artifact files to trace decisions.

## Safety Constraints
- No live keys.
- No real API order routing.
- No private key handling.
