import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildReportArtifacts } from '../src/reporting/reportBuilder';

test('report builder generates markdown and html', () => {
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'report-'));
  const artifacts = path.join(tmpRoot, 'artifacts');
  fs.mkdirSync(artifacts, { recursive: true });

  fs.writeFileSync(path.join(artifacts, 'run_summary.json'), JSON.stringify({ source: 'sample', final_bankroll: 10100, win_rate: 0.6, drawdown: 20, sharpe_like: 1.2, llm_enabled: false }));
  fs.writeFileSync(path.join(artifacts, 'paper_ledger.json'), JSON.stringify({ bankroll: 10100, trades: [{ marketId: 'm1', pnl: 10, roi: 0.1 }] }));
  fs.writeFileSync(path.join(artifacts, 'guardrail_rejections.json'), JSON.stringify([{ marketId: 'm2', reasons: ['spread_above_maximum'] }]));
  fs.writeFileSync(path.join(artifacts, 'llm_research.json'), JSON.stringify([]));
  fs.writeFileSync(path.join(artifacts, 'data_quality_report.json'), JSON.stringify({ criticalIssues: ['duplicate_market_ids:m1'], warnings: ['future_timestamps:1'] }));
  fs.writeFileSync(path.join(artifacts, 'backtest_train_summary.json'), JSON.stringify({ roi: 0.1, winRate: 0.5 }));
  fs.writeFileSync(path.join(artifacts, 'backtest_test_summary.json'), JSON.stringify({ roi: 0.02, winRate: 0.45 }));
  fs.writeFileSync(path.join(artifacts, 'pipeline_diagnostics.json'), JSON.stringify({ funnel: { marketsLoaded: 10, scannerPassed: 4, researchPassed: 3, walletSignalsAvailable: 2, strategyCandidates: 2, riskApproved: 1, guardrailApproved: 1, executedTrades: 1 }, topBlockers: [{ stage: 'scanner', reason: 'too_close_to_resolution', count: 6 }], nearMissCandidates: [{ marketId: 'm3', failedStage: 'scanner', failedReason: 'too_close_to_resolution', edge: 0.02, edgeAfterSlippage: 0.01, liquidity: 1000, spread: 0.1, timeToResolutionHours: -5, walletSignal: 0.2 }] }));

  const cwd = process.cwd();
  process.chdir(tmpRoot);
  try {
    const out = buildReportArtifacts({ mode: 'paper', artifactsDir: 'artifacts' });
    assert.equal(fs.existsSync(out.mdPath), true);
    assert.equal(fs.existsSync(out.htmlPath), true);
    const md = fs.readFileSync(out.mdPath, 'utf-8');
    assert.match(md, /Run mode:\*\* paper/);
    assert.match(md, /Rejected trades by guardrail reason/);
    assert.match(md, /Data quality diagnostics/);
    assert.match(md, /Reality Check/);
    assert.match(md, /Pipeline Diagnostics/);
    assert.match(md, /Biggest blockers/);
    assert.match(md, /Near-miss opportunities/);
  } finally {
    process.chdir(cwd);
  }
});
