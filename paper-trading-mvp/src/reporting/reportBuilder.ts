import fs from 'node:fs';
import path from 'node:path';

interface BuildReportInput {
  mode: 'paper' | 'backtest';
  artifactsDir: string;
}

const safeRead = <T>(filePath: string, fallback: T): T => {
  if (!fs.existsSync(filePath)) return fallback;
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf-8')) as T;
  } catch {
    return fallback;
  }
};

const toPct = (n: number): string => `${(n * 100).toFixed(2)}%`;

export const buildReportArtifacts = ({ mode, artifactsDir }: BuildReportInput): { mdPath: string; htmlPath: string } => {
  const dir = path.resolve(process.cwd(), artifactsDir);
  const runSummary = safeRead<Record<string, unknown>>(path.join(dir, 'run_summary.json'), {});
  const backtestSummary = safeRead<Record<string, unknown>>(path.join(dir, 'backtest_summary.json'), {});
  const trainSummary = safeRead<Record<string, unknown>>(path.join(dir, 'backtest_train_summary.json'), {});
  const testSummary = safeRead<Record<string, unknown>>(path.join(dir, 'backtest_test_summary.json'), {});
  const guardRejections = safeRead<Array<{ marketId: string; reasons: string[] }>>(path.join(dir, 'guardrail_rejections.json'), []);
  const llmResearch = safeRead<Array<Record<string, unknown>>>(path.join(dir, 'llm_research.json'), []);
  const ledger = safeRead<{ trades?: Array<Record<string, unknown>>; bankroll?: number }>(path.join(dir, 'paper_ledger.json'), {});
  const dataQuality = safeRead<{ criticalIssues?: string[]; warnings?: string[] }>(path.join(dir, 'data_quality_report.json'), {});

  const topAcceptedTrades =
    mode === 'backtest'
      ? (backtestSummary.tradeResults as Array<Record<string, unknown>> | undefined)?.slice(0, 5) ?? []
      : (ledger.trades ?? []).slice(0, 5);

  const finalBankroll =
    mode === 'backtest'
      ? Number((backtestSummary.summary as Record<string, unknown> | undefined)?.endingBankroll ?? 0)
      : Number(runSummary.final_bankroll ?? ledger.bankroll ?? 0);

  const roi =
    mode === 'backtest'
      ? Number((backtestSummary.summary as Record<string, unknown> | undefined)?.roi ?? 0)
      : finalBankroll > 0 ? (finalBankroll - 10000) / 10000 : 0;

  const winRate =
    mode === 'backtest'
      ? Number((backtestSummary.summary as Record<string, unknown> | undefined)?.winRate ?? 0)
      : Number(runSummary.win_rate ?? 0);

  const maxDrawdown =
    mode === 'backtest'
      ? Number((backtestSummary.summary as Record<string, unknown> | undefined)?.maxDrawdown ?? 0)
      : Number(runSummary.drawdown ?? 0);

  const profitFactor =
    mode === 'backtest'
      ? Number((backtestSummary.summary as Record<string, unknown> | undefined)?.profitFactor ?? 0)
      : 0;

  const sharpeLike =
    mode === 'backtest'
      ? Number((backtestSummary.summary as Record<string, unknown> | undefined)?.sharpeLike ?? 0)
      : Number(runSummary.sharpe_like ?? 0);

  const source = String(runSummary.source ?? backtestSummary.source ?? 'unknown');

  const rejectionByReason = guardRejections.reduce<Record<string, number>>((acc, row) => {
    row.reasons.forEach((r) => {
      acc[r] = (acc[r] ?? 0) + 1;
    });
    return acc;
  }, {});

  const trainVsTest = {
    trainRoi: Number(trainSummary.roi ?? 0),
    testRoi: Number(testSummary.roi ?? 0),
    trainWinRate: Number(trainSummary.winRate ?? 0),
    testWinRate: Number(testSummary.winRate ?? 0)
  };

  const md = `# Run Report

- **Run mode:** ${mode}
- **Source:** ${source}
- **Final bankroll:** ${finalBankroll.toFixed(2)}
- **ROI:** ${toPct(roi)}
- **Win rate:** ${toPct(winRate)}
- **Max drawdown:** ${maxDrawdown.toFixed(2)}
- **Profit factor:** ${profitFactor.toFixed(4)}
- **Sharpe-like score:** ${sharpeLike.toFixed(4)}

## Top accepted trades

${topAcceptedTrades.map((t) => `- ${JSON.stringify(t)}`).join('\n') || '- none'}

## Rejected trades by guardrail reason

${Object.entries(rejectionByReason).map(([k, v]) => `- ${k}: ${v}`).join('\n') || '- none'}

## Train vs Test comparison

- train ROI: ${toPct(trainVsTest.trainRoi)}
- test ROI: ${toPct(trainVsTest.testRoi)}
- train win rate: ${toPct(trainVsTest.trainWinRate)}
- test win rate: ${toPct(trainVsTest.testWinRate)}

## LLM research summary

- enabled: ${String(runSummary.llm_enabled ?? false)}
- llm reports generated: ${llmResearch.length}

## Data quality diagnostics

- critical issues: ${(dataQuality.criticalIssues ?? []).join(', ') || 'none'}
- warnings: ${(dataQuality.warnings ?? []).join(', ') || 'none'}
`;

  const htmlRows = topAcceptedTrades
    .map((t) => `<tr><td>${String(t.marketId ?? t.id ?? '')}</td><td>${String(t.pnl ?? '')}</td><td>${String(t.roi ?? '')}</td></tr>`)
    .join('');

  const html = `<!doctype html><html><head><meta charset="utf-8"><title>Run Report</title></head><body>
<h1>Run Report</h1>
<table border="1"><tr><th>Metric</th><th>Value</th></tr>
<tr><td>Run mode</td><td>${mode}</td></tr>
<tr><td>Source</td><td>${source}</td></tr>
<tr><td>Final bankroll</td><td>${finalBankroll.toFixed(2)}</td></tr>
<tr><td>ROI</td><td>${toPct(roi)}</td></tr>
<tr><td>Win rate</td><td>${toPct(winRate)}</td></tr>
<tr><td>Max drawdown</td><td>${maxDrawdown.toFixed(2)}</td></tr>
<tr><td>Profit factor</td><td>${profitFactor.toFixed(4)}</td></tr>
<tr><td>Sharpe-like</td><td>${sharpeLike.toFixed(4)}</td></tr>
</table>
<h2>Top accepted trades</h2>
<table border="1"><tr><th>Market</th><th>PnL</th><th>ROI</th></tr>${htmlRows}</table>
<h2>Rejected by guardrail</h2>
<ul>${Object.entries(rejectionByReason).map(([k, v]) => `<li>${k}: ${v}</li>`).join('') || '<li>none</li>'}</ul>
<h2>Train vs Test</h2>
<table border="1"><tr><th>Split</th><th>ROI</th><th>Win Rate</th></tr>
<tr><td>Train</td><td>${toPct(trainVsTest.trainRoi)}</td><td>${toPct(trainVsTest.trainWinRate)}</td></tr>
<tr><td>Test</td><td>${toPct(trainVsTest.testRoi)}</td><td>${toPct(trainVsTest.testWinRate)}</td></tr>
</table>
<h2>LLM Summary</h2><p>Enabled: ${String(runSummary.llm_enabled ?? false)}, Reports: ${llmResearch.length}</p>
<h2>Data Quality</h2><p>Critical: ${(dataQuality.criticalIssues ?? []).join(', ') || 'none'}</p><p>Warnings: ${(dataQuality.warnings ?? []).join(', ') || 'none'}</p>
</body></html>`;

  const mdPath = path.join(dir, 'report.md');
  const htmlPath = path.join(dir, 'report.html');
  fs.writeFileSync(mdPath, md);
  fs.writeFileSync(htmlPath, html);

  return { mdPath, htmlPath };
};
