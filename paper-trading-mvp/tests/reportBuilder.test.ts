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
  } finally {
    process.chdir(cwd);
  }
});
